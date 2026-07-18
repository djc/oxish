use core::{ffi::c_char, fmt, ops::ControlFlow};
#[cfg(target_vendor = "apple")]
use std::os::darwin::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(all(unix, not(target_vendor = "apple"), not(target_os = "linux")))]
use std::os::unix::fs::MetadataExt;
use std::{
    borrow::Cow,
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    str,
    sync::Arc,
};

use libc::{getpwnam_r, sysconf, _SC_GETPW_R_SIZE_MAX, O_DIRECTORY, O_RDONLY};
use proto::{
    crypto::{CryptoProvider, SigningKey, VerifyingKey},
    Decode, Decoded, Disconnect, DisconnectReason, EcdhKeyExchangeInit, EcdhKeyExchangeReply,
    ExtInfo, ExtensionId, ExtensionName, KeyExchangeInit, MessageType, Method, Named,
    OutgoingNameList, ProtoError, PublicKeyAlgorithm, ServiceAccept, ServiceName, ServiceRequest,
    Signature, SignatureData, UserAuthPkOk, UserAuthRequest,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::spawn_blocking,
};
use tracing::{debug, error, info, warn};

use crate::{receive, Error, IoStream};

pub(crate) enum Auth {
    /// Look up the requested user in the system database and read their
    /// `authorized_keys` file.
    System,
    /// Authorize against a fixed set of keys, ignoring the system database.
    #[cfg(test)]
    Fixed(User),
}

impl Auth {
    pub(crate) async fn authenticate<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut IoStream<T>,
        host_key: &dyn SigningKey,
        provider: &dyn CryptoProvider,
    ) -> Result<User, ()> {
        let exchange = match io.identify().await {
            Ok(exchange) => exchange,
            Err(error) => {
                error!(%error, "failed to identify client");
                return Err(());
            }
        };

        // Receive and send key exchange init packets

        let packet = receive(&mut io.stream, &mut io.read).await?;
        let (key_exchange_init, mut exchange, negotiated) = match KeyExchangeInit::peer(
            packet,
            exchange,
            vec![host_key.algorithm()],
            [ExtensionId::StrictKexServer].into_iter(),
            provider,
        ) {
            Ok(result) => result,
            Err(error) => {
                error!(%error, "failed to read key exchange init");
                return Err(());
            }
        };

        io.send_handshake(&key_exchange_init, Some(&mut exchange))
            .await?;

        // Perform ECDH key exchange

        let packet = receive(&mut io.stream, &mut io.read).await?;
        let ecdh_key_exchange_init = match EcdhKeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                error!(%error, "failed to read ecdh key exchange init");
                return Err(());
            }
        };

        let result = EcdhKeyExchangeReply::new(
            ecdh_key_exchange_init,
            &negotiated,
            exchange,
            host_key,
            provider,
        );

        let (key_exchange_reply, session_id, keys) = match result {
            Ok(out) => out,
            Err(error) => {
                error!(%error, "failed to complete ecdh key exchange");
                return Err(());
            }
        };

        io.send(&key_exchange_reply).await?;

        // Exchange new keys packets and install new keys

        io.update_keys(keys, negotiated.strict_key_exchange, provider)
            .await?;
        if negotiated.want_extension_info {
            let ext_info = ExtInfo {
                extensions: vec![(
                    ExtensionName::ServerSigAlgs,
                    &OutgoingNameList(&[PublicKeyAlgorithm::EcdsaSha2Nistp256]),
                )],
            };
            io.send(&ext_info).await?;
        }

        io.send(&MessageType::Ignore).await?;

        // Handle authentication

        let packet = receive(&mut io.stream, &mut io.read).await?;
        let service_request = match ServiceRequest::try_from(packet) {
            Ok(req) => req,
            Err(error) => {
                error!(%error, "failed to read service request");
                return Err(());
            }
        };

        if service_request.service_name != ServiceName::UserAuth {
            error!(
                service_name = ?service_request.service_name,
                "unsupported service requested"
            );

            let disconnect = Disconnect {
                reason_code: DisconnectReason::ServiceNotAvailable,
                description: "only user authentication service is supported",
            };

            io.send(&disconnect).await?;
            return Err(());
        }

        let service_accept = ServiceAccept {
            service_name: ServiceName::UserAuth,
        };
        io.send(&service_accept).await?;

        let mut cached_user = None::<User>;
        loop {
            let packet = receive(&mut io.stream, &mut io.read).await?;
            let user_auth_request = match UserAuthRequest::try_from(packet) {
                Ok(req) => req,
                Err(error) => {
                    error!(%error, "failed to read user auth request");
                    return Err(());
                }
            };

            debug!(?user_auth_request, "received user auth request");
            if user_auth_request.service_name != ServiceName::Connection {
                error!(
                    service_name = ?user_auth_request.service_name,
                    "unsupported service requested"
                );

                let disconnect = Disconnect {
                    reason_code: DisconnectReason::ServiceNotAvailable,
                    description: "only connection service is supported",
                };
                io.send(&disconnect).await?;
                return Err(());
            }

            let Method::PublicKey(public_key) = user_auth_request.method else {
                warn!(
                    method = ?user_auth_request.method,
                    "unsupported authentication method requested"
                );
                io.send_auth_failed().await?;
                continue;
            };

            if public_key.algorithm != PublicKeyAlgorithm::EcdsaSha2Nistp256 {
                warn!(algorithm = ?public_key.algorithm, "unsupported public key algorithm");
                io.send_auth_failed().await?;
                continue;
            }

            let user = match (&mut cached_user, self) {
                (Some(user), _) if user.name == user_auth_request.user_name => user,
                (_, auth) => match auth.resolve(user_auth_request.user_name, provider) {
                    Some(user) => cached_user.insert(user),
                    None => {
                        io.send_auth_failed().await?;
                        continue;
                    }
                },
            };

            let authorized_key = user.authorized_keys.iter().find(|key| {
                key.algorithm == public_key.algorithm && key.blob.as_slice() == public_key.key_blob
            });

            let (sig, authorized_key) = match (public_key.signature, authorized_key) {
                // Signature, authorized key => verify signature
                (Some(sig), Some(key)) if sig.algorithm == key.algorithm => (sig, key.clone()),
                // Signature, no authorized key => verify signature against fake key
                (Some(sig), None) => (sig, AuthorizedKey::fake(provider)),
                // Signature, authorized key but mismatched algorithms => fail authentication without verifying signature
                (Some(_), Some(_)) => {
                    warn!(
                        algorithm = ?public_key.algorithm,
                        "mismatched signature algorithm in authentication request"
                    );
                    io.send_auth_failed().await?;
                    continue;
                }
                // No signature, authorized key => send pk-ok and wait for signature
                (None, Some(_)) => {
                    let pk_ok = UserAuthPkOk {
                        algorithm: public_key.algorithm.to_owned(),
                        key_blob: Cow::Owned(public_key.key_blob.to_vec()),
                    };
                    debug!(ok = ?pk_ok, "sending pk-ok for user");
                    io.send(&pk_ok).await?;
                    continue;
                }
                // No signature, no authorized key => fail authentication
                (None, None) => {
                    io.send_auth_failed().await?;
                    continue;
                }
            };

            let message = SignatureData {
                session_id: session_id.as_ref(),
                user_name: &user.name,
                service_name: user_auth_request.service_name,
                algorithm: public_key.algorithm,
                public_key: public_key.key_blob,
            };

            match authorized_key.verify(message, sig).await {
                Ok(()) => {
                    let Some(user) = cached_user else {
                        return Err(());
                    };

                    info!(user = %user.name, "authentication successful");
                    io.send(&MessageType::UserAuthSuccess).await?;
                    break Ok(user);
                }
                _ => {
                    io.send_auth_failed().await?;
                    continue;
                }
            }
        }
    }

    pub(crate) fn resolve(&self, name: &str, provider: &dyn CryptoProvider) -> Option<User> {
        match self {
            Self::System => match User::from_system(name, provider) {
                Ok(new) => Some(new),
                Err(error) => {
                    error!(%error, "failed to get user information");
                    None
                }
            },
            #[cfg(test)]
            Self::Fixed(user) => match user.name == name {
                true => Some(user.clone()),
                false => {
                    warn!(
                        requested_user = %name,
                        authorized_user = %user.name,
                        "requested user does not match authorized user",
                    );
                    None
                }
            },
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct User {
    name: String,
    #[expect(dead_code)]
    id: u32,
    #[expect(dead_code)]
    home_dir: PathBuf,
    /// Cached authorized keys for the user
    ///
    /// Since finding the authorized keys can be somewhat expensive, prefer to cache them
    /// here so we can reuse them across attempts for the same user.
    authorized_keys: Vec<AuthorizedKey>,
}

impl User {
    fn from_system(name: &str, provider: &dyn CryptoProvider) -> Result<Self, Error> {
        let c_name = CString::new(name).map_err(|_| Error::InvalidUsername)?;
        let buf_len = match unsafe { sysconf(_SC_GETPW_R_SIZE_MAX) } {
            -1 => 1024,
            n => Ord::min(n as usize, 1_048_576),
        };

        let mut buf = vec![0u8; buf_len];
        let mut pwd = unsafe { core::mem::zeroed() };
        let mut result = core::ptr::null_mut();

        let ret = unsafe {
            getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast::<c_char>(),
                buf_len,
                &mut result,
            )
        };

        let home_dir = if ret != 0 {
            let error = io::Error::from_raw_os_error(ret);
            debug!(%error, %name, "failed to get user information");
            Self::FAKE_HOME
        } else if result.is_null() {
            debug!(%name, "user not found");
            Self::FAKE_HOME
        } else {
            debug!(user = %name, "found home dir");
            pwd.pw_dir
        };

        // SAFETY: if `ret` is 0 (signifying success) and `result` is non-null, `pwd.pw_dir`
        // was populated by `getpwnam_r`, the `pwd` struct and `buf` are still alive, so the
        // pointer is valid; otherwise, `home_dir` is set to a static string. In either case,
        // `home_dir` is a valid pointer to a null-terminated C string.
        let home_dir = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(home_dir) }.to_bytes(),
        ));

        let id = match (ret, result.is_null()) {
            (0, false) => pwd.pw_uid,
            _ => u32::MAX,
        };

        Ok(Self {
            name: name.to_owned(),
            id,
            authorized_keys: authorized_keys(&home_dir, id, provider),
            home_dir,
        })
    }

    /// Create a new user with the given name and home directory
    ///
    /// This is primarily intended for testing.
    #[cfg(test)]
    pub(crate) fn new(
        name: String,
        id: u32,
        home_dir: PathBuf,
        authorized_keys: Vec<AuthorizedKey>,
    ) -> Self {
        Self {
            name,
            id,
            home_dir,
            authorized_keys,
        }
    }

    const FAKE_HOME: *const c_char = c"/var/empty".as_ptr().cast::<c_char>();
}

/// Read and parse the `authorized_keys` file for a user
///
/// This is pretty finicky because we need to check that
///
/// - None of the path components have group or other write permissions
/// - Each of the path components are owned by root or the target user
/// - Avoid TOCTOU issues when opening each path component
fn authorized_keys(home_dir: &Path, uid: u32, provider: &dyn CryptoProvider) -> Vec<AuthorizedKey> {
    let home = match File::open(home_dir) {
        Ok(file) => file,
        Err(error) => {
            warn!(%error, ?home_dir, "failed to open home directory");
            return Vec::new();
        }
    };

    match check_permissions(&home, uid, "home directory") {
        ControlFlow::Continue(()) => {}
        ControlFlow::Break(()) => {
            warn!(?home_dir, "bad permissions on home directory");
            return Vec::new();
        }
    };

    let ssh_dir = match open_in_dir(&home, ".ssh", O_DIRECTORY) {
        Ok(file) => file,
        Err(error) => {
            warn!(%error, ?home_dir, "failed to open .ssh directory");
            return Vec::new();
        }
    };

    match check_permissions(&ssh_dir, uid, ".ssh directory") {
        ControlFlow::Continue(()) => {}
        ControlFlow::Break(()) => {
            warn!(?home_dir, "bad permissions on .ssh directory");
            return Vec::new();
        }
    };

    let mut key_file = match open_in_dir(&ssh_dir, "authorized_keys", O_RDONLY) {
        Ok(file) => file,
        Err(error) => {
            warn!(%error, ?home_dir, "failed to open authorized keys file");
            return Vec::new();
        }
    };

    match check_permissions(&key_file, uid, "authorized keys file") {
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
            Ok(Some(key)) => keys.push(key),
            Ok(None) => continue,
            Err(()) => debug!(line = line + 1, "skipping invalid authorized keys line"),
        }
    }

    keys
}

fn open_in_dir(dir: &File, name: &str, flags: libc::c_int) -> Result<File, io::Error> {
    let c_name = CString::new(name)?;
    match unsafe { libc::openat(dir.as_raw_fd(), c_name.as_ptr(), flags) } {
        -1 => Err(io::Error::last_os_error()),
        fd => Ok(unsafe { File::from_raw_fd(fd) }),
    }
}

fn check_permissions(file: &File, uid: u32, level: &str) -> ControlFlow<()> {
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            warn!(%error, level, "failed to get metadata");
            return ControlFlow::Break(());
        }
    };

    match meta.st_mode() & 0o022 == 0 && (meta.st_uid() == 0 || meta.st_uid() == uid) {
        true => ControlFlow::Continue(()),
        false => ControlFlow::Break(()),
    }
}

#[derive(Clone)]
pub(crate) struct AuthorizedKey {
    algorithm: PublicKeyAlgorithm<'static>,
    blob: Vec<u8>,
    key: Arc<dyn VerifyingKey>,
}

impl AuthorizedKey {
    fn fake(provider: &dyn CryptoProvider) -> Self {
        Self {
            algorithm: PublicKeyAlgorithm::EcdsaSha2Nistp256,
            blob: Vec::new(),
            key: provider
                .verifying_key(&Self::FAKE_KEY[..], &PublicKeyAlgorithm::EcdsaSha2Nistp256)
                .expect("fake key uses a supported algorithm"),
        }
    }

    pub(crate) fn from_str(s: &str, provider: &dyn CryptoProvider) -> Result<Option<Self>, ()> {
        let key = match s.split_once('#') {
            Some((contents, _)) => contents,
            None => s,
        }
        .trim();

        if key.is_empty() {
            return Ok(None);
        }

        let mut parts = key.split_whitespace();
        let Some(alg) = parts.next() else {
            debug!("missing algorithm");
            return Err(());
        };

        // TODO: support options before key type
        let algorithm = PublicKeyAlgorithm::typed(alg);
        let Some(key_data) = parts.next() else {
            debug!("missing key data");
            return Err(());
        };

        let Ok(blob) = data_encoding::BASE64.decode(key_data.as_bytes()) else {
            debug!("invalid base64 key data");
            return Err(());
        };

        let next = match <&[u8]>::decode(&blob) {
            // Unused `key_type` field, should match `alg`
            Ok(Decoded { next, .. }) => next,
            Err(error) => {
                debug!(%error, "invalid key type");
                return Err(());
            }
        };

        let next = match <&[u8]>::decode(next) {
            // Unused `curve_name` field
            Ok(Decoded { next, .. }) => next,
            Err(error) => {
                debug!(%error, "invalid curve name");
                return Err(());
            }
        };

        let q = match <&[u8]>::decode(next) {
            // TODO: what does the trailing data mean?
            Ok(Decoded { value: q, .. }) => q,
            Err(error) => {
                debug!(%error, "invalid public key data");
                return Err(());
            }
        };

        Ok(Some(Self {
            algorithm: algorithm.to_owned(),
            key: provider.verifying_key(q, &algorithm).map_err(|_| ())?,
            blob,
        }))
    }

    async fn verify(
        &self,
        message: SignatureData<'_>,
        signature: Signature<'_>,
    ) -> Result<(), ProtoError> {
        match &self.algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let Decoded {
                    value: r,
                    next: rest,
                } = <&[u8]>::decode(signature.signature_blob)?;

                let Decoded { value: s, next } = <&[u8]>::decode(rest)?;
                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "extra data after ECDSA signature components",
                    ));
                }

                let mut fixed = [0u8; 64];
                if mpint_to_fixed(r, &mut fixed[..64 / 2]).is_none() {
                    return Err(ProtoError::InvalidPacket(
                        "failure to decode r in ECDSA signature",
                    ));
                }

                if mpint_to_fixed(s, &mut fixed[64 / 2..]).is_none() {
                    return Err(ProtoError::InvalidPacket(
                        "failure to decode s in ECDSA signature",
                    ));
                }

                let encoded = message.encode();
                let key = self.key.clone();
                spawn_blocking(move || {
                    key.verify(&encoded, &fixed)
                        .map_err(|_| ProtoError::InvalidPacket("invalid signature"))
                })
                .await
                .map_err(|_| ProtoError::InvalidPacket("signature verification task failed"))?
            }
            algorithm => {
                warn!(
                    ?algorithm,
                    "unsupported public key algorithm for verification"
                );
                Err(ProtoError::InvalidPacket(
                    "unsupported public key algorithm for verification",
                ))
            }
        }
    }

    /// A random key used to mitigate timing attacks during authentication.
    ///
    /// When no matching authorized key is found, we still perform signature
    /// verification against this key so the response time is consistent.
    const FAKE_KEY: [u8; 65] = [
        4, 78, 12, 149, 151, 123, 231, 212, 239, 236, 97, 37, 76, 163, 223, 212, 61, 5, 10, 96,
        214, 7, 210, 196, 146, 69, 178, 104, 253, 196, 241, 61, 7, 253, 242, 178, 22, 112, 52, 123,
        76, 129, 155, 245, 233, 144, 111, 94, 173, 252, 107, 114, 3, 36, 2, 237, 66, 51, 119, 181,
        246, 15, 91, 101, 104,
    ];
}

impl fmt::Debug for AuthorizedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Convert an SSH mpint to a fixed-width big-endian representation
fn mpint_to_fixed(mpint: &[u8], out: &mut [u8]) -> Option<()> {
    let data = match mpint.split_first() {
        Some((&0, rest)) if !rest.is_empty() => rest,
        _ => mpint,
    };

    if data.len() > out.len() {
        return None;
    }

    let offset = out.len() - data.len();
    out[offset..].copy_from_slice(data);
    Some(())
}
