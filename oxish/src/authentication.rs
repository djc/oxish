use core::{
    ffi::c_char,
    fmt,
    future::poll_fn,
    ops::{ControlFlow, Deref},
    time::Duration,
};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    borrow::Cow,
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, Read},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    str,
};

use libc::{_SC_GETPW_R_SIZE_MAX, ERANGE, getpwnam_r, getpwuid_r, sysconf};
use proto::{
    Disconnect, DisconnectReason, IncomingPacket, MessageType, ProtoError, WriteState,
    auth::{
        AuthorizedKey, Method, ServiceAccept, ServiceRequest, SignatureData, UserAuthPkOk,
        UserAuthRequest,
    },
    crypto::{CryptoError, CryptoProvider, Digest},
    named::{MethodName, PublicKeyAlgorithm, ServiceName},
};
use rustix::fs::{Mode, OFlags, openat};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::spawn_blocking,
    time::timeout,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{Connection, Error, receive, send};

#[instrument(name = "authentication", skip(session_id, conn, store, provider), fields(addr = %conn.addr))]
pub(crate) async fn authenticate<T: AsyncRead + AsyncWrite + Unpin>(
    session_id: &Digest,
    conn: &mut Connection<T>,
    store: &dyn UserStore,
    provider: &dyn CryptoProvider,
) -> anyhow::Result<User> {
    let mut state = AuthenticationState::default();
    let future = async {
        loop {
            let packet = receive(&mut conn.stream, &mut conn.read).await?;
            let handled = state
                .handle(packet, session_id, &mut conn.write, store, provider)
                .await;

            let sent = poll_fn(|cx| send(&mut conn.stream, &mut conn.write, cx)).await;
            match (handled, sent) {
                (Ok(AuthenticationState::Complete(user)), Ok(())) => return Ok(user),
                (Ok(next), Ok(())) => state = next,
                (Err(error), _) | (_, Err(error)) => return Err(error),
            }
        }
    };

    let (error, disconnect) = match timeout(Duration::from_secs(60), future).await {
        Ok(Ok(user)) => return Ok(user),
        Ok(Err(error)) => {
            let disconnect = match &error {
                Error::Auth(AuthError::TooManyAttempts) => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description: "too many authentication attempts",
                },
                Error::InvalidState(description) => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description,
                },
                Error::InvalidUsername => Disconnect {
                    reason_code: DisconnectReason::IllegalUserName,
                    description: "invalid username",
                },
                Error::Proto(ProtoError::ServiceNotAvailable(description)) => Disconnect {
                    reason_code: DisconnectReason::ServiceNotAvailable,
                    description,
                },
                _ => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description: "authentication failed",
                },
            };

            (error, disconnect)
        }
        Err(_) => (
            Error::Io(io::Error::from(io::ErrorKind::TimedOut)),
            Disconnect {
                reason_code: DisconnectReason::ByApplication,
                description: "authentication timed out",
            },
        ),
    };

    let _ = timeout(Duration::from_secs(1), conn.send(&disconnect)).await;
    Err(error.into())
}

#[derive(Default)]
enum AuthenticationState {
    #[default]
    AwaitServiceRequest,
    AwaitAuthRequest {
        cached: Option<CachedUser>,
        attempts: u8,
    },
    Complete(User),
}

impl AuthenticationState {
    pub(crate) async fn handle(
        self,
        packet: IncomingPacket<'_>,
        session_id: &Digest,
        write: &mut WriteState,
        store: &dyn UserStore,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, Error> {
        match (self, packet.message_type) {
            (state, MessageType::Ignore | MessageType::Debug) => Ok(state),
            (_, MessageType::Disconnect) => Err(AuthError::Canceled.into()),
            (Self::AwaitServiceRequest, MessageType::ServiceRequest) => {
                match ServiceRequest::try_from(packet)?.service_name {
                    ServiceName::UserAuth => {
                        write.encode(&ServiceAccept {
                            service_name: ServiceName::UserAuth,
                        })?;
                        Ok(Self::AwaitAuthRequest {
                            cached: None,
                            attempts: 6,
                        })
                    }
                    service_name => {
                        error!(?service_name, "unsupported service requested");
                        Err(ProtoError::ServiceNotAvailable(
                            "only user authentication service is supported",
                        )
                        .into())
                    }
                }
            }
            (
                Self::AwaitAuthRequest {
                    mut cached,
                    mut attempts,
                },
                MessageType::UserAuthRequest,
            ) => {
                attempts -= 1;
                if attempts == 0 {
                    error!("too many authentication attempts");
                    return Err(AuthError::TooManyAttempts.into());
                }

                let user_auth_request = UserAuthRequest::try_from(packet)?;
                debug!(?user_auth_request, "received user auth request");
                if user_auth_request.service_name != ServiceName::Connection {
                    error!(
                        service_name = ?user_auth_request.service_name,
                        "unsupported service requested"
                    );

                    return Err(ProtoError::ServiceNotAvailable(
                        "only connection service is supported",
                    )
                    .into());
                }

                let Method::PublicKey(public_key) = user_auth_request.method else {
                    warn!(
                        method = ?user_auth_request.method,
                        "unsupported authentication method requested"
                    );
                    write.send_auth_failed(SUPPORTED_METHODS)?;
                    return Ok(Self::AwaitAuthRequest { cached, attempts });
                };

                let user = match &mut cached {
                    Some(user) if &*user.data.name == user_auth_request.user_name => user,
                    _ => {
                        let Ok(name) = Username::try_from(user_auth_request.user_name.to_owned())
                        else {
                            write.send_auth_failed(SUPPORTED_METHODS)?;
                            return Ok(Self::AwaitAuthRequest { cached, attempts });
                        };

                        let Some(user) = store.lookup(name) else {
                            write.send_auth_failed(SUPPORTED_METHODS)?;
                            return Ok(Self::AwaitAuthRequest { cached, attempts });
                        };

                        let keys = store.keys(&user, provider);
                        cached.insert(CachedUser { data: user, keys })
                    }
                };

                let authorized_key = user.keys.iter().find(|key| key.matches(&public_key));
                let (sig, authorized_key) = match (public_key.signature, authorized_key) {
                    // Signature, authorized key => verify signature
                    (Some(sig), Some(key)) if &sig.algorithm == key.algorithm() => {
                        (sig, key.clone())
                    }
                    // Signature, no authorized key => verify signature against fake key
                    (Some(sig), None) => (
                        sig,
                        match fake_key(&public_key.algorithm, provider) {
                            Ok(key) => key,
                            Err(_) => {
                                warn!(algorithm = ?public_key.algorithm, "unsupported public key algorithm");
                                write.send_auth_failed(SUPPORTED_METHODS)?;
                                return Ok(Self::AwaitAuthRequest { cached, attempts });
                            }
                        },
                    ),
                    // Signature, authorized key but mismatched algorithms => fail authentication without verifying signature
                    (Some(_), Some(_)) => {
                        warn!(
                            algorithm = ?public_key.algorithm,
                            "mismatched signature algorithm in authentication request"
                        );
                        write.send_auth_failed(SUPPORTED_METHODS)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                    // No signature, authorized key => send pk-ok and wait for signature
                    (None, Some(_)) => {
                        let pk_ok = UserAuthPkOk {
                            algorithm: public_key.algorithm.to_owned(),
                            key_blob: Cow::Owned(public_key.key_blob.to_vec()),
                        };
                        debug!(ok = ?pk_ok, "sending pk-ok for user");
                        write.encode(&pk_ok)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                    // No signature, no authorized key => fail authentication
                    (None, None) => {
                        write.send_auth_failed(SUPPORTED_METHODS)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                };

                let message = SignatureData {
                    session_id: session_id.as_ref(),
                    user_name: &user.data.name,
                    service_name: user_auth_request.service_name,
                    algorithm: public_key.algorithm,
                    public_key: public_key.key_blob,
                }
                .encode();

                let signature = match sig.encode() {
                    Ok(signature) => signature,
                    Err(error) => {
                        debug!(%error, "failed to encode signature");
                        write.send_auth_failed(SUPPORTED_METHODS)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                };

                match spawn_blocking(move || authorized_key.verify(message, signature)).await {
                    Ok(Ok(())) => {
                        let Some(user) = cached else {
                            return Err(ProtoError::Unreachable("must have cached user").into());
                        };

                        info!(user = %user.data.name, "authentication successful");
                        write.encode(&MessageType::UserAuthSuccess)?;
                        Ok(Self::Complete(user.data))
                    }
                    _ => {
                        write.send_auth_failed(SUPPORTED_METHODS)?;
                        Ok(Self::AwaitAuthRequest { cached, attempts })
                    }
                }
            }
            (_, _) => {
                error!(
                    message_type = ?packet.message_type,
                    "unexpected packet received during authentication"
                );
                Err(Error::InvalidState(
                    "unexpected packet received during authentication",
                ))
            }
        }
    }
}

/// Build a fake key for the given `algorithm` to mitigate timing attacks
///
/// We want to execute a signature verification even when the user does not have a matching
/// authorized key, so we build a fake key for the requested algorithm and verify the
/// signature against it. This ensures that the response time is consistent regardless of
/// whether the user has a matching authorized key.
fn fake_key(
    algorithm: &PublicKeyAlgorithm<'_>,
    provider: &dyn CryptoProvider,
) -> Result<AuthorizedKey, CryptoError> {
    AuthorizedKey::from_str(
        match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE4MlZd759Tv7GElTKPf1D0FCmDWB9LEkkWyaP3E8T0H/fKyFnA0e0yBm/XpkG9erfxrcgMkAu1CM3e19g9bZWg=",
            PublicKeyAlgorithm::Ed25519 => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDX+GNCeikghR3A2bLB0KmlovqxdC+BUHAfYhYGcUJxA",
            _ => return Err(CryptoError::UnknownAlgorithm),
        },
        provider,
    )
    .ok_or(CryptoError::KeyRejected)
}

/// Default [`UserStore`] implementation
///
/// Uses the system database when running as root, and a single-user store otherwise.
pub struct DefaultStore(());

impl DefaultStore {
    /// Construct a new [`DefaultStore`] from the current process's effective UID
    #[expect(clippy::new_ret_no_self)]
    pub fn new(provider: &dyn CryptoProvider) -> Result<Box<dyn UserStore>, Error> {
        // SAFETY: `geteuid()` takes no arguments, cannot fail and has no preconditions.
        Ok(match unsafe { libc::geteuid() } {
            0 => {
                debug!("using system user store");
                Box::new(SystemStore) as Box<dyn UserStore>
            }
            uid => {
                debug!(uid, "using single-user store");
                let data = User::lookup(UserLookup::Id(uid))?;
                let keys = data.authorized_keys(provider);
                Box::new(SingleUser(CachedUser { data, keys }))
            }
        })
    }
}

/// User store backed by the system database
struct SystemStore;

impl UserStore for SystemStore {
    fn lookup(&self, name: Username) -> Option<User> {
        match User::lookup(UserLookup::Name(name)) {
            Ok(user) => Some(user),
            Err(error) => {
                error!(%error, "failed to get user information");
                None
            }
        }
    }

    fn keys(&self, user: &User, provider: &dyn CryptoProvider) -> Vec<AuthorizedKey> {
        user.authorized_keys(provider)
    }

    fn drop_privileges(&self) -> bool {
        true
    }
}

/// User store that only contains a single user
pub(crate) struct SingleUser(CachedUser);

impl SingleUser {
    #[cfg(test)]
    pub(crate) fn with_keys(data: User, keys: Vec<AuthorizedKey>) -> Self {
        Self(CachedUser { data, keys })
    }
}

impl UserStore for SingleUser {
    fn lookup(&self, name: Username) -> Option<User> {
        match self.0.data.name == name {
            true => Some(self.0.data.clone()),
            false => {
                warn!(
                    requested = %name,
                    authorized = %self.0.data.name,
                    "requested user does not match authorized user",
                );
                None
            }
        }
    }

    fn keys(&self, _: &User, _: &dyn CryptoProvider) -> Vec<AuthorizedKey> {
        self.0.keys.clone()
    }

    fn drop_privileges(&self) -> bool {
        false
    }
}

/// A user store resolves a username to a `User` type containing data used for authentication
pub trait UserStore: Send + Sync + 'static {
    /// Lookup a user by name, returning `None` if the user does not exist or cannot be retrieved
    fn lookup(&self, name: Username) -> Option<User>;

    /// Lookup the authorized keys for a user
    fn keys(&self, user: &User, provider: &dyn CryptoProvider) -> Vec<AuthorizedKey>;

    /// Whether the user store should set the UID of the process to the authenticated user
    fn drop_privileges(&self) -> bool;
}

struct CachedUser {
    data: User,
    keys: Vec<AuthorizedKey>,
}

/// User data as retrieved from the system database
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct User {
    /// The user's name
    pub name: Username,
    /// The user's UID
    pub id: u32,
    /// The user's GID
    pub gid: u32,
    /// The user's home directory
    pub home_dir: PathBuf,
    /// The user's shell
    pub shell: PathBuf,
}

impl User {
    fn lookup(by: UserLookup) -> Result<Self, Error> {
        /// Upper bound on the buffer used to hold the passwd entry
        const MAX_BUF_LEN: usize = 1_048_576;

        // SAFETY: `sysconf()` only reads its integer argument and has no other preconditions.
        let buf_len = match unsafe { sysconf(_SC_GETPW_R_SIZE_MAX) } {
            -1 => 1024,
            n => (n as usize).clamp(1024, MAX_BUF_LEN),
        };

        let c_name = match &by {
            UserLookup::Name(name) => {
                Some(CString::new(&**name).map_err(|_| Error::InvalidUsername)?)
            }
            UserLookup::Id(_) => None,
        };

        let mut buf = vec![0u8; buf_len];
        // SAFETY: `passwd` is a plain C struct of integers and pointers, for which
        // all-zeros (including null pointers) is a valid bit pattern.
        let mut pwd = unsafe { core::mem::zeroed() };
        let mut result = core::ptr::null_mut();

        // A passwd entry can exceed the initial buffer size (a long GECOS field is
        // enough); `ERANGE` means the buffer was too small, so grow it and try again,
        // up to a cap (like the `getgrouplist()` loop in `server.rs`).
        let ret = loop {
            let ret = match (&by, &c_name) {
                (UserLookup::Name(_), Some(c_name)) => unsafe {
                    // SAFETY: `c_name` is a valid null-terminated C string, `pwd` and `result` are
                    // valid for writes, and the buffer pointer and length describe the live
                    // allocation in `buf`.
                    getpwnam_r(
                        c_name.as_ptr(),
                        &mut pwd,
                        buf.as_mut_ptr().cast::<c_char>(),
                        buf.len(),
                        &mut result,
                    )
                },
                (UserLookup::Id(id), _) => unsafe {
                    // SAFETY: `pwd` and `result` are valid for writes, and the buffer pointer
                    // and length describe the live allocation in `buf`.
                    getpwuid_r(
                        *id,
                        &mut pwd,
                        buf.as_mut_ptr().cast::<c_char>(),
                        buf.len(),
                        &mut result,
                    )
                },
                (UserLookup::Name(_), None) => {
                    unreachable!("`c_name` is set for lookups by name")
                }
            };

            if ret != ERANGE || buf.len() >= MAX_BUF_LEN {
                break ret;
            }

            buf.resize(Ord::min(buf.len() * 2, MAX_BUF_LEN), 0);
        };

        let name = match by {
            UserLookup::Name(name) => name,
            UserLookup::Id(_) => match (ret, result.is_null(), pwd.pw_name.is_null()) {
                // SAFETY: `ret` is 0 and `result` is non-null, so the `pwd.pw_name` points to a
                // null-terminated C string stored in `buf`, which is still alive.
                (0, false, false) => Username::try_from(unsafe { CStr::from_ptr(pwd.pw_name) })?,
                _ => Username::nobody(),
            },
        };

        let id = match (ret, result.is_null()) {
            (0, false) => pwd.pw_uid,
            _ => u32::MAX,
        };

        if id == 0 {
            return Err(Error::InvalidState("refusing to authenticate root user"));
        }

        let gid = match (ret, result.is_null()) {
            (0, false) => pwd.pw_gid,
            _ => u32::MAX,
        };

        let (home_dir, shell) = if ret != 0 {
            let error = io::Error::from_raw_os_error(ret);
            debug!(%error, %name, "failed to get user information");
            (Self::FAKE_HOME, Self::DEFAULT_SHELL)
        } else if result.is_null() {
            debug!(%name, "user not found");
            (Self::FAKE_HOME, Self::DEFAULT_SHELL)
        } else {
            // POSIX does not promise these values will be non-null
            debug!(%name, "found home dir");
            (
                match pwd.pw_dir.cast_const() {
                    home_dir if !home_dir.is_null() => home_dir,
                    _ => Self::FAKE_HOME,
                },
                match pwd.pw_shell.cast_const() {
                    shell if !shell.is_null() => shell,
                    _ => Self::DEFAULT_SHELL,
                },
            )
        };

        // SAFETY: if `ret` is 0 (signifying success) and `result` is non-null, `pwd.pw_dir`
        // and `pwd.pw_shell` were populated by the `getpw` call and the `pwd` struct and `buf`
        // are still alive, so the pointers are valid; otherwise, `home_dir` and `shell` are set
        // to static strings. In either case, both are valid pointers to null-terminated C strings.
        let home_dir = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(home_dir) }.to_bytes(),
        ));

        // An empty `pw_shell` means the system default shell.
        // SAFETY: `shell` is a valid pointer to a null-terminated C string,
        // per the same reasoning as for `home_dir` above.
        let shell = match unsafe { CStr::from_ptr(shell) }.to_bytes() {
            b"" => PathBuf::from(OsStr::from_bytes(
                // SAFETY: `DEFAULT_SHELL` points to a static null-terminated C string literal.
                unsafe { CStr::from_ptr(Self::DEFAULT_SHELL) }.to_bytes(),
            )),
            bytes => PathBuf::from(OsStr::from_bytes(bytes)),
        };

        Ok(Self {
            name,
            id,
            gid,
            home_dir,
            shell,
        })
    }

    /// Read and parse the `authorized_keys` file for a user
    ///
    /// This is pretty finicky because we need to check that
    ///
    /// - None of the path components have group or other write permissions
    /// - Each of the path components are owned by root or the target user
    /// - Avoid TOCTOU issues when opening each path component
    fn authorized_keys(&self, provider: &dyn CryptoProvider) -> Vec<AuthorizedKey> {
        let home_dir = &self.home_dir;
        let home = match File::open(home_dir) {
            Ok(file) => file,
            Err(error) => {
                warn!(%error, ?home_dir, "failed to open home directory");
                return Vec::new();
            }
        };

        match check_permissions(&home, self.id, "home directory") {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(()) => {
                warn!(?home_dir, "bad permissions on home directory");
                return Vec::new();
            }
        };

        let result = openat(
            &home,
            ".ssh",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let ssh_dir = match result {
            Ok(fd) => File::from(fd),
            Err(error) => {
                warn!(%error, ?home_dir, "failed to open .ssh directory");
                return Vec::new();
            }
        };

        match check_permissions(&ssh_dir, self.id, ".ssh directory") {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(()) => {
                warn!(?home_dir, "bad permissions on .ssh directory");
                return Vec::new();
            }
        };

        let result = openat(
            &ssh_dir,
            "authorized_keys",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let mut key_file = match result {
            Ok(fd) => File::from(fd),
            Err(error) => {
                warn!(%error, ?home_dir, "failed to open authorized keys file");
                return Vec::new();
            }
        };

        match check_permissions(&key_file, self.id, "authorized keys file") {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(()) => {
                warn!(?home_dir, "bad permissions on authorized keys file");
                return Vec::new();
            }
        };

        let mut contents = String::new();
        if let Err(error) = key_file.read_to_string(&mut contents) {
            warn!(%error, ?home_dir, "failed to read authorized keys file");
            return Vec::new();
        };

        let mut keys = Vec::new();
        for (line, key) in contents.lines().enumerate() {
            match AuthorizedKey::from_str(key, provider) {
                Some(key) => keys.push(key),
                None => debug!(line = line + 1, "no valid authorized key found on line"),
            }
        }

        keys
    }

    const FAKE_HOME: *const c_char = c"/var/empty".as_ptr().cast::<c_char>();
    const DEFAULT_SHELL: *const c_char = c"/bin/sh".as_ptr().cast::<c_char>();
}

/// A validated username
///
/// Must be valid UTF-8 without any ASCII control characters or slashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Username(String);

impl Username {
    fn nobody() -> Self {
        Self("nobody".to_owned())
    }
}

impl TryFrom<&CStr> for Username {
    type Error = Error;

    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        let Ok(name) = value.to_str() else {
            return Err(Error::InvalidUsername);
        };

        Self::try_from(name.to_owned())
    }
}

impl TryFrom<String> for Username {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.chars().any(|c| c.is_control() || c == '/') {
            true => Err(Error::InvalidUsername),
            false => Ok(Self(value)),
        }
    }
}

impl Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
enum UserLookup {
    Name(Username),
    Id(u32),
}

fn check_permissions(file: &File, uid: u32, level: &str) -> ControlFlow<()> {
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            warn!(%error, level, "failed to get metadata");
            return ControlFlow::Break(());
        }
    };

    match meta.mode() & 0o022 == 0 && (meta.uid() == 0 || meta.uid() == uid) {
        true => ControlFlow::Continue(()),
        false => ControlFlow::Break(()),
    }
}

/// Errors that can occur during authentication
#[derive(Debug, Error)]
pub enum AuthError {
    /// The client canceled the authentication process
    #[error("canceled by the client")]
    Canceled,
    /// Too many authentication attempts for a single connection
    #[error("too many authentication attempts")]
    TooManyAttempts,
}

const SUPPORTED_METHODS: &[MethodName<'_>] = &[MethodName::PublicKey];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_PROVIDER;

    #[test]
    fn parse_fake_keys() {
        fake_key(&PublicKeyAlgorithm::EcdsaSha2Nistp256, DEFAULT_PROVIDER).unwrap();
        fake_key(&PublicKeyAlgorithm::Ed25519, DEFAULT_PROVIDER).unwrap();
    }
}
