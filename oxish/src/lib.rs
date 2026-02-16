use core::{ffi::c_char, fmt, future, net::SocketAddr, ops::ControlFlow};
#[cfg(target_vendor = "apple")]
use std::os::darwin::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(all(unix, not(target_vendor = "apple"), not(target_os = "linux")))]
use std::os::unix::fs::MetadataExt;
use std::{
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

use aws_lc_rs::signature::{self, Ed25519KeyPair, UnparsedPublicKey};
use libc::{getpwnam_r, sysconf, O_DIRECTORY, O_RDONLY, _SC_GETPW_R_SIZE_MAX};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, instrument, warn};

mod connections;
use connections::{Channels, IncomingChannelMessage};
mod key_exchange;
use key_exchange::{EcdhKeyExchangeInit, KeyExchange, RawKeySet};
mod messages;
use messages::{
    Completion, Decode, Decoded, Disconnect, DisconnectReason, Encode, Identification,
    KeyExchangeInit, MessageType, Method, MethodName, Named, NewKeys, ServiceAccept, ServiceName,
    ServiceRequest, UserAuthFailure, UserAuthRequest, PROTOCOL,
};
mod proto;
use proto::{AesCtrReadKeys, AesCtrWriteKeys, HandshakeHash, ReadState, WriteState};

use crate::messages::{ExtensionName, KeyExchangeAlgorithm, OutgoingNameList, PublicKeyAlgorithm};
mod terminal;

/// A single SSH connection
pub struct Connection<T> {
    stream: T,
    context: ConnectionContext,
    read: ReadState,
    write: WriteState,
    channels: Channels,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Create a new [`Connection`]
    pub fn new(stream: T, addr: SocketAddr, host_key: Arc<Ed25519KeyPair>) -> Self {
        Self {
            stream,
            context: ConnectionContext { addr, host_key },
            read: ReadState::default(),
            write: WriteState::default(),
            channels: Channels::default(),
        }
    }

    /// Drive the connection forward
    #[instrument(name = "connection", skip(self), fields(addr = %self.context.addr))]
    pub async fn run(mut self) -> Result<(), ()> {
        let mut exchange = HandshakeHash::default();
        let state = VersionExchange::default();
        let state = match state.advance(&mut exchange, &mut self).await {
            Ok(state) => state,
            Err(error) => {
                error!(%error, "failed to complete version exchange");
                return Err(());
            }
        };

        // Receive and send key exchange init packets

        let packet = self.read.packet(&mut self.stream).await?;
        exchange.update(&((packet.payload.len() + 1) as u32).to_be_bytes());
        exchange.update(&[u8::from(packet.message_type)]);
        exchange.update(packet.payload);
        let peer_key_exchange_init = match KeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                error!(%error, "failed to read key exchange init");
                return Err(());
            }
        };

        debug!(key_exchange_init = %Pretty(&peer_key_exchange_init), "received key exchange init");
        let want_extension_info = peer_key_exchange_init
            .key_exchange_algorithms
            .contains(&KeyExchangeAlgorithm::ExtInfoC);
        let Ok((key_exchange_init, state)) = state.advance(peer_key_exchange_init, &self.context)
        else {
            return Err(());
        };

        self.send(&key_exchange_init, Some(&mut exchange)).await?;

        // Perform ECDH key exchange

        let packet = self.read.packet(&mut self.stream).await?;
        let ecdh_key_exchange_init = match EcdhKeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                error!(%error, "failed to read ecdh key exchange init");
                return Err(());
            }
        };

        let Ok((key_exchange_reply, keys)) =
            state.advance(ecdh_key_exchange_init, exchange, &self.context)
        else {
            return Err(());
        };

        self.send(&key_exchange_reply, None).await?;

        // Exchange new keys packets and install new keys

        self.update_keys(keys).await?;

        if want_extension_info {
            let ext_info = messages::ExtInfo {
                extensions: vec![(
                    ExtensionName::ServerSigAlgs,
                    &OutgoingNameList(&[PublicKeyAlgorithm::EcdsaSha2Nistp256]),
                )],
            };
            self.send(&ext_info, None).await?;
        }

        self.send(&MessageType::Ignore, None).await?;

        // Handle authentication

        let packet = self.read.packet(&mut self.stream).await?;
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

            self.send(&disconnect, None).await?;
            return Err(());
        }

        let service_accept = ServiceAccept {
            service_name: ServiceName::UserAuth,
        };
        self.send(&service_accept, None).await?;

        let mut cached_user = None::<User>;
        let user_auth_request = loop {
            let packet = self.read.packet(&mut self.stream).await?;
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
                self.send(&disconnect, None).await?;
                return Err(());
            }

            let Method::PublicKey(public_key) = &user_auth_request.method else {
                warn!(
                    method = ?user_auth_request.method,
                    "unsupported authentication method requested"
                );

                let failure = UserAuthFailure {
                    can_continue: &[MethodName::PublicKey],
                    partial_success: false,
                };
                self.send(&failure, None).await?;
                continue;
            };

            if public_key.algorithm != PublicKeyAlgorithm::EcdsaSha2Nistp256 {
                warn!(algorithm = ?public_key.algorithm, "unsupported public key algorithm");
                self.send(
                    &UserAuthFailure {
                        can_continue: &[MethodName::PublicKey],
                        partial_success: false,
                    },
                    None,
                )
                .await?;
                continue;
            }

            let user = match &mut cached_user {
                Some(user) if user.name == user_auth_request.user_name => user,
                _ => match User::new(user_auth_request.user_name) {
                    Ok(new) => cached_user.insert(new),
                    Err(error) => {
                        error!(%error, "failed to get user information");
                        self.send(
                            &UserAuthFailure {
                                can_continue: &[MethodName::PublicKey],
                                partial_success: false,
                            },
                            None,
                        )
                        .await?;
                        continue;
                    }
                },
            };

            let _authorized_keys = dbg!(&*user.authorized_keys);
            debug!(?public_key, "received public key authentication request");
            break user_auth_request;
        };

        #[expect(unused_variables)]
        let user = user_auth_request.user_name.to_owned();
        self.send(&MessageType::UserAuthSuccess, None).await?;

        // Main loop for handling channel messages

        loop {
            tokio::select! {
                result = self.read.packet(&mut self.stream) => {
                    let packet = result?;
                    if packet.message_type == MessageType::Disconnect {
                        match Disconnect::try_from(packet) {
                            Ok(disconnect) => info!(?disconnect, "received disconnect packet, closing connection"),
                            Err(error) => warn!(%error, "failed to read disconnect packet"),
                        }
                        return Err(());
                    }

                    let channel_message = match IncomingChannelMessage::try_from(packet) {
                        Ok(req) => req,
                        Err(error) => {
                            error!(%error, "failed to read channel message");
                            return Err(());
                        }
                    };

                    debug!(message = %Pretty(&channel_message), "handling channel message");
                    let outgoing = match channel_message {
                        IncomingChannelMessage::Open(open) => Some(self.channels.open(open)),
                        IncomingChannelMessage::Request(request) => match self.channels.request(request) {
                            Ok(outgoing) => outgoing,
                            Err(error) => {
                                error!(%error, "failed to handle channel request");
                                return Err(());
                            }
                        }
                        IncomingChannelMessage::Data(data) => match self.channels.data(&data) {
                            Ok(Some((session, data))) => {
                                if let Err(error) = session.write(data).await {
                                    error!(%error, "failed to write data to session");
                                    return Err(());
                                }
                                None
                            }
                            Ok(None) => None,
                            Err(error) => {
                                error!(%error, "failed to handle channel data");
                                return Err(());
                            }
                        }
                        IncomingChannelMessage::Eof(eof) => {
                            if let Err(error) = self.channels.eof(&eof) {
                                error!(%error, "failed to handle channel eof");
                                return Err(());
                            }
                            None
                        }
                        IncomingChannelMessage::Close(close) => self.channels.close(&close),
                    };

                    if let Some(outgoing) = outgoing {
                        debug!(outgoing = %Pretty(&outgoing), "sending channel message");
                        self.send(&outgoing, None).await?;
                    }
                }
                result = self.channels.poll_terminals() => {
                    match result {
                        Ok(Some(outgoing)) => {
                            debug!(outgoing = %Pretty(&outgoing), "sending channel message from session");
                            self.send(&outgoing, None).await?;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            error!(%error, "failed to poll sessions");
                            return Err(());
                        }
                    }
                }
            }
        }
    }

    async fn update_keys(&mut self, keys: RawKeySet) -> Result<(), ()> {
        let packet = self.read.packet(&mut self.stream).await?;
        if let Err(error) = NewKeys::try_from(packet) {
            error!(%error, "failed to read new keys packet");
            return Err(());
        }

        self.send(&NewKeys, None).await?;
        let RawKeySet {
            client_to_server,
            server_to_client,
        } = keys;

        // Cipher and MAC algorithms are negotiated during key exchange.
        // Currently this hard codes AES-128-CTR and HMAC-SHA256.
        self.read.decryption_key = Some(AesCtrReadKeys::new(client_to_server));
        self.write.keys = Some(AesCtrWriteKeys::new(server_to_client));
        Ok(())
    }

    async fn send(
        &mut self,
        payload: &impl Encode,
        exchange_hash: Option<&mut HandshakeHash>,
    ) -> Result<(), ()> {
        if let Err(error) = self.write.handle_packet(payload, exchange_hash) {
            error!(%error, ?payload, "failed to encode packet");
            return Err(());
        }

        let future = future::poll_fn(|cx| self.write.poll_write_to(cx, &mut self.stream));
        if let Err(error) = future.await {
            error!(%error, ?payload, "failed to write packet to stream");
            return Err(());
        }

        Ok(())
    }
}

struct ConnectionContext {
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
}

#[derive(Debug)]
struct User {
    name: String,
    #[expect(dead_code)]
    id: u32,
    #[expect(dead_code)]
    home_dir: PathBuf,
    authorized_keys: Vec<AuthorizedKey>,
}

impl User {
    fn new(name: &str) -> Result<Self, Error> {
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
            authorized_keys: authorized_keys(&home_dir, id),
            home_dir,
        })
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
fn authorized_keys(home_dir: &Path, uid: u32) -> Vec<AuthorizedKey> {
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
        let line = line + 1;
        let key = match key.split_once('#') {
            Some((contents, _)) => contents,
            None => key,
        }
        .trim();

        let mut parts = key.split_whitespace();
        let Some(alg) = parts.next() else {
            debug!(line, "missing algorithm");
            continue;
        };

        // TODO: support options before key type
        let alg = match PublicKeyAlgorithm::typed(alg) {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => &signature::ECDSA_P256_SHA256_FIXED,
            algorithm => {
                warn!(
                    ?algorithm,
                    line, "unsupported public key algorithm in authorized keys file"
                );
                continue;
            }
        };

        let Some(key_data) = parts.next() else {
            debug!(line, "missing key data");
            continue;
        };

        let Ok(blob) = data_encoding::BASE64.decode(key_data.as_bytes()) else {
            debug!(line, "invalid base64 key data");
            continue;
        };

        let next = match <&[u8]>::decode(&blob) {
            // Unused `key_type` field, should match `alg`
            Ok(Decoded { next, .. }) => next,
            Err(error) => {
                debug!(%error, line, "invalid key type");
                continue;
            }
        };

        let next = match <&[u8]>::decode(next) {
            // Unused `curve_name` field
            Ok(Decoded { next, .. }) => next,
            Err(error) => {
                debug!(%error, line, "invalid curve name");
                continue;
            }
        };

        let q = match <&[u8]>::decode(next) {
            // TODO: what does the trailing data mean?
            Ok(Decoded { value: q, .. }) => q,
            Err(error) => {
                debug!(%error, line, "invalid public key data");
                continue;
            }
        };

        keys.push(AuthorizedKey {
            key: UnparsedPublicKey::new(alg, Box::from(q)),
            blob,
        });
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

struct AuthorizedKey {
    #[expect(dead_code)]
    blob: Vec<u8>,
    key: UnparsedPublicKey<Box<[u8]>>,
}

impl fmt::Debug for AuthorizedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedKey")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct VersionExchange(());

impl VersionExchange {
    async fn advance(
        &self,
        exchange: &mut HandshakeHash,
        conn: &mut Connection<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> Result<KeyExchange, Error> {
        // TODO: enforce timeout if this is taking too long
        let (buf, Decoded { value: ident, next }) = loop {
            let bytes = conn.read.buffer(&mut conn.stream).await?;
            match Identification::decode(bytes) {
                Ok(Completion::Complete(decoded)) => break (bytes, decoded),
                Ok(Completion::Incomplete(_length)) => continue,
                Err(error) => return Err(error),
            }
        };

        debug!(addr = %conn.context.addr, ?ident, "received identification");
        if ident.protocol != PROTOCOL {
            warn!(addr = %conn.context.addr, ?ident, "unsupported protocol version");
            return Err(IdentificationError::UnsupportedVersion(ident.protocol.to_owned()).into());
        }

        let rest = next.len();
        let v_c_len = buf.len() - rest - 2;
        if let Some(v_c) = buf.get(..v_c_len) {
            exchange.prefixed(v_c);
        }

        let ident = Identification {
            protocol: PROTOCOL,
            software: SOFTWARE,
            comments: "",
        };

        let server_ident_bytes = conn.write.encoded(&ident);
        if let Err(error) = conn.stream.write_all(server_ident_bytes).await {
            warn!(addr = %conn.context.addr, %error, "failed to send version exchange");
            return Err(error.into());
        }

        let v_s_len = server_ident_bytes.len() - 2;
        if let Some(v_s) = server_ident_bytes.get(..v_s_len) {
            exchange.prefixed(v_s);
        }

        let last_length = buf.len() - rest;
        conn.read.set_last_length(last_length);
        Ok(KeyExchange::default())
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("failed to parse identification: {0}")]
    Identification(#[from] IdentificationError),
    #[error("invalid user name")]
    InvalidUsername,
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("incomplete message: {0:?}")]
    Incomplete(Option<usize>),
    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),
    #[error("no common {0} algorithms")]
    NoCommonAlgorithm(&'static str),
    #[error("invalid mac for packet")]
    InvalidMac,
    #[error("unreachable code: {0}")]
    Unreachable(&'static str),
}

#[derive(Debug, Error)]
enum IdentificationError {
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    #[error("No SSH prefix")]
    NoSsh,
    #[error("No version found")]
    NoVersion,
    #[error("Identification too long")]
    TooLong,
    #[error("Unsupported protocol version")]
    UnsupportedVersion(String),
}

struct Pretty<T>(T);

impl<T: fmt::Debug> fmt::Display for Pretty<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", &self.0)
    }
}

const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
