use core::{
    fmt, future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use std::{borrow::Cow, io, str, sync::Arc, task::ready};

use proto::{
    crypto::{CryptoError, CryptoProvider, HandshakeBuffer, HandshakeHash, SigningKey},
    Completion, Decoded, Disconnect, DisconnectReason, EcdhKeyExchange, EcdhKeyExchangeInit,
    Encode, EncryptionAlgorithm, ExtInfo, ExtensionId, ExtensionName, Identification,
    IdentificationError, IncomingPacket, KeyExchange, KeyExchangeInit, KeySourceSet, MessageType,
    Method, MethodName, NewKeys, OutgoingNameList, ProtoError, PublicKeyAlgorithm, ReadState,
    ServiceAccept, ServiceName, ServiceRequest, SignatureData, UserAuthFailure, UserAuthPkOk,
    UserAuthRequest, WriteState, PROTOCOL,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, instrument, trace, warn};

mod authentication;
use authentication::{Auth, AuthorizedKey, User};
mod connections;
use connections::{Channels, IncomingChannelMessage, TerminalsFuture};

mod terminal;
#[cfg(test)]
mod tests;

/// A single SSH connection
pub struct Connection<T> {
    stream: T,
    addr: SocketAddr,
    host_key: Arc<dyn SigningKey>,
    auth: Auth,
    provider: &'static dyn CryptoProvider,
    read: ReadState,
    write: WriteState,
    channels: Channels,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Create a new [`Connection`]
    pub fn new(
        stream: T,
        addr: SocketAddr,
        host_key: Arc<dyn SigningKey>,
        provider: &'static dyn CryptoProvider,
    ) -> Self {
        Self {
            stream,
            addr,
            host_key,
            auth: Auth::System,
            provider,
            read: ReadState::default(),
            write: WriteState::new(provider.secure_random()),
            channels: Channels::default(),
        }
    }

    /// Use a fixed set of authorized keys for authentication
    ///
    /// By default, we find the `authorized_keys` file from the user's `.ssh` directory.
    #[cfg(test)]
    pub(crate) fn for_user(mut self, user: User) -> Self {
        self.auth = Auth::Fixed(user);
        self
    }

    /// Drive the connection forward
    #[instrument(name = "connection", skip(self), fields(addr = %self.addr))]
    pub async fn run(mut self) -> Result<(), ()> {
        let mut exchange = HandshakeBuffer::default();
        let state = VersionExchange::default();
        let state = match state.advance(&mut exchange, &mut self).await {
            Ok(state) => state,
            Err(error) => {
                error!(%error, "failed to complete version exchange");
                return Err(());
            }
        };

        // Receive and send key exchange init packets

        let packet = receive(&mut self.stream, &mut self.read).await?;
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
        let want_extension_info = peer_key_exchange_init.has_extension(ExtensionId::ExtInfoC);
        let strict_key_exchange =
            peer_key_exchange_init.has_extension(ExtensionId::StrictKexClient);

        let (algorithms, key_exchange_init) = match state.advance(
            peer_key_exchange_init,
            vec![self.host_key.algorithm()],
            [ExtensionId::StrictKexServer].into_iter(),
            &*self.provider,
        ) {
            Ok(result) => result,
            Err(error) => {
                error!(%error, "failed to advance key exchange");
                return Err(());
            }
        };

        let state = EcdhKeyExchange {
            session_id: None,
            key_exchange: algorithms.key_exchange,
        };

        let hash = match self.provider.hash(&algorithms.key_exchange) {
            Ok(hash) => hash,
            Err(error) => {
                error!(%error, algorithm = ?algorithms.key_exchange, "failed to find hash implementation for key exchange algorithm");
                return Err(());
            }
        };

        let mut exchange = exchange.hash(hash);
        self.send_handshake(&key_exchange_init, Some(&mut exchange))
            .await?;

        // Perform ECDH key exchange

        let packet = receive(&mut self.stream, &mut self.read).await?;
        let ecdh_key_exchange_init = match EcdhKeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                error!(%error, "failed to read ecdh key exchange init");
                return Err(());
            }
        };

        let result = state.advance(
            ecdh_key_exchange_init,
            exchange,
            &*self.host_key,
            &*self.provider,
        );
        let (key_exchange_reply, session_id, keys) = match result {
            Ok(out) => out,
            Err(error) => {
                error!(%error, "failed to complete ecdh key exchange");
                return Err(());
            }
        };

        self.send(&key_exchange_reply).await?;

        // Exchange new keys packets and install new keys

        self.update_keys(keys, strict_key_exchange).await?;

        if want_extension_info {
            let ext_info = ExtInfo {
                extensions: vec![(
                    ExtensionName::ServerSigAlgs,
                    &OutgoingNameList(&[PublicKeyAlgorithm::EcdsaSha2Nistp256]),
                )],
            };
            self.send(&ext_info).await?;
        }

        self.send(&MessageType::Ignore).await?;

        // Handle authentication

        let packet = receive(&mut self.stream, &mut self.read).await?;
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

            self.send(&disconnect).await?;
            return Err(());
        }

        let service_accept = ServiceAccept {
            service_name: ServiceName::UserAuth,
        };
        self.send(&service_accept).await?;

        let mut cached_user = None::<User>;
        let _user = loop {
            let packet = receive(&mut self.stream, &mut self.read).await?;
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
                self.send(&disconnect).await?;
                return Err(());
            }

            let Method::PublicKey(public_key) = user_auth_request.method else {
                warn!(
                    method = ?user_auth_request.method,
                    "unsupported authentication method requested"
                );
                self.send_auth_failed().await?;
                continue;
            };

            if public_key.algorithm != PublicKeyAlgorithm::EcdsaSha2Nistp256 {
                warn!(algorithm = ?public_key.algorithm, "unsupported public key algorithm");
                self.send_auth_failed().await?;
                continue;
            }

            let user = match (&mut cached_user, &self.auth) {
                (Some(user), _) if user.name == user_auth_request.user_name => user,
                (_, auth) => match auth.resolve(user_auth_request.user_name, self.provider) {
                    Some(user) => cached_user.insert(user),
                    None => {
                        self.send_auth_failed().await?;
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
                (Some(sig), None) => (sig, AuthorizedKey::fake(self.provider)),
                // Signature, authorized key but mismatched algorithms => fail authentication without verifying signature
                (Some(_), Some(_)) => {
                    warn!(
                        algorithm = ?public_key.algorithm,
                        "mismatched signature algorithm in authentication request"
                    );
                    self.send_auth_failed().await?;
                    continue;
                }
                // No signature, authorized key => send pk-ok and wait for signature
                (None, Some(_)) => {
                    let pk_ok = UserAuthPkOk {
                        algorithm: public_key.algorithm.to_owned(),
                        key_blob: Cow::Owned(public_key.key_blob.to_vec()),
                    };
                    debug!(ok = ?pk_ok, "sending pk-ok for user");
                    self.send(&pk_ok).await?;
                    continue;
                }
                // No signature, no authorized key => fail authentication
                (None, None) => {
                    self.send_auth_failed().await?;
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
                    info!(user = %user.name, "authentication successful");
                    self.send(&MessageType::UserAuthSuccess).await?;
                    break user;
                }
                _ => {
                    self.send_auth_failed().await?;
                    continue;
                }
            }
        };

        // Main loop for handling channel messages
        loop {
            tokio::select! {
                result = receive(&mut self.stream, &mut self.read) => {
                    let packet = result?;
                    if packet.message_type == MessageType::Disconnect {
                        match Disconnect::try_from(packet) {
                            Ok(disconnect) => info!(?disconnect, "received disconnect packet, closing connection"),
                            Err(error) => warn!(%error, "failed to read disconnect packet"),
                        }
                        return Ok(());
                    }

                    let channel_message = match IncomingChannelMessage::try_from(packet) {
                        Ok(req) => req,
                        Err(error) => {
                            error!(%error, "failed to read channel message");
                            return Err(());
                        }
                    };

                    debug!(message = %Pretty(&channel_message), "handling channel message");
                    let mut encoder = Encoder::new(&mut self.write);
                    let result = match channel_message {
                        IncomingChannelMessage::Open(open) => self.channels.open(open, &mut encoder),
                        IncomingChannelMessage::Request(request) => self.channels.request(request, &mut encoder),
                        IncomingChannelMessage::Data(data) => match self.channels.data(&data) {
                            Ok(Some((session, data))) => match session.write(data).await {
                                Ok(_) => Ok(()),
                                Err(error) => Err(error.into()),
                            },
                            Ok(None) => Ok(()),
                            Err(error) => Err(error.into()),
                        }
                        IncomingChannelMessage::Eof(eof) => self.channels.eof(&eof).map_err(Into::into),
                        IncomingChannelMessage::Close(close) => self.channels.close(&close, &mut encoder),
                    };

                    if let Err(error) = result {
                        error!(%error, "failed to handle channel message");
                        return Err(());
                    }

                    encoder.flush(&mut self.stream).await?;
                }
                result = TerminalsFuture::new(self.channels.channels_mut()) => {
                    match result {
                        Ok(Some(outgoing)) => {
                            debug!(outgoing = %Pretty(&outgoing), "sending channel message from session");
                            self.send(&outgoing).await?;
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

    async fn update_keys(&mut self, keys: KeySourceSet, strict: bool) -> Result<(), ()> {
        let packet = receive(&mut self.stream, &mut self.read).await?;
        if let Err(error) = NewKeys::try_from(packet) {
            error!(%error, "failed to read new keys packet");
            return Err(());
        }

        // Under strict key exchange the sequence numbers are reset to zero once
        // NEWKEYS crosses in each direction, so the first encrypted packet after
        // NEWKEYS uses sequence number zero.
        if strict {
            self.read.reset_sequence_number();
        }

        self.send(&NewKeys).await?;
        if strict {
            self.write.reset_sequence_number();
        }
        let KeySourceSet {
            client_to_server,
            server_to_client,
        } = keys;

        // The cipher is negotiated during key exchange; currently this hard codes
        // aes128-gcm@openssh.com, an AEAD that also provides integrity protection.
        let results = (
            self.provider
                .opening_key(client_to_server, &EncryptionAlgorithm::Aes128Gcm),
            self.provider
                .sealing_key(server_to_client, &EncryptionAlgorithm::Aes128Gcm),
        );
        match results {
            (Ok(opener), Ok(sealer)) => {
                self.read.opener = Some(opener);
                self.write.sealer = Some(sealer);
                Ok(())
            }
            (Err(error), _) | (_, Err(error)) => {
                error!(%error, "failed to create opening or sealing key");
                Err(())
            }
        }
    }

    async fn send_auth_failed(&mut self) -> Result<(), ()> {
        self.send(&UserAuthFailure {
            can_continue: &[MethodName::PublicKey],
            partial_success: false,
        })
        .await
    }

    async fn send(&mut self, payload: &impl Encode) -> Result<(), ()> {
        self.send_handshake(payload, None).await
    }

    async fn send_handshake(
        &mut self,
        payload: &impl Encode,
        exchange_hash: Option<&mut HandshakeHash>,
    ) -> Result<(), ()> {
        if let Err(error) = self.write.handle_packet(payload, exchange_hash) {
            error!(%error, ?payload, "failed to encode packet");
            return Err(());
        }

        let future = future::poll_fn(|cx| send(&mut self.stream, &mut self.write, cx));
        if let Err(error) = future.await {
            error!(%error, ?payload, "failed to write packet to stream");
            return Err(());
        }

        Ok(())
    }
}

pub(crate) async fn receive<'a>(
    stream: &mut (impl AsyncRead + Unpin),
    state: &'a mut ReadState,
) -> Result<IncomingPacket<'a>, ()> {
    loop {
        let (sequence_number, packet_length) = match state.poll_packet() {
            Ok(Completion::Complete((sequence_number, packet_length))) => {
                (sequence_number, packet_length)
            }
            Ok(Completion::Incomplete(_amount)) | Err(ProtoError::Incomplete(_amount)) => {
                if let Err(error) = buffer(stream, state).await {
                    error!(%error, "failed to buffer from stream");
                    return Err(());
                }
                continue;
            }
            Err(error) => {
                error!(%error, "failed to decrypt packet");
                return Err(());
            }
        };

        if packet_length.0 > 64 * 1024 {
            error!(packet_length = packet_length.0, "packet too large");
            return Err(());
        }

        match state.decode_packet(sequence_number, packet_length) {
            Ok(packet) => return Ok(packet),
            Err(error) => {
                error!(%error, "failed to decode packet");
                return Err(());
            }
        }
    }
}

pub(crate) struct Encoder<'a> {
    write: &'a mut WriteState,
    pub(crate) buffered: bool,
}

impl Encoder<'_> {
    pub(crate) fn new(write: &mut WriteState) -> Encoder<'_> {
        Encoder {
            write,
            buffered: false,
        }
    }

    pub(crate) fn enqueue(&mut self, payload: &impl Encode) -> Result<(), Error> {
        self.buffered = true;
        self.write.handle_packet(payload, None).map_err(|error| {
            error!(%error, ?payload, "failed to encode packet");
            Error::from(error)
        })
    }

    pub(crate) async fn flush(self, stream: &mut (impl AsyncWrite + Unpin)) -> Result<(), ()> {
        if !self.buffered {
            return Ok(());
        }

        future::poll_fn(|cx| send(stream, self.write, cx))
            .await
            .map_err(|error| {
                error!(%error, "failed to write queued packets to stream");
            })
    }
}

pub(crate) fn send(
    stream: &mut (impl AsyncWrite + Unpin),
    state: &mut WriteState,
    cx: &mut Context<'_>,
) -> Poll<Result<(), Error>> {
    state.written(ready!(Pin::new(stream).poll_write(cx, state.buffered()))?);
    Poll::Ready(Ok(()))
}

#[derive(Default)]
struct VersionExchange(());

impl VersionExchange {
    async fn advance(
        &self,
        exchange: &mut HandshakeBuffer,
        conn: &mut Connection<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> Result<KeyExchange, Error> {
        // TODO: enforce timeout if this is taking too long
        let (buf, Decoded { value: ident, next }) = loop {
            let bytes = buffer(&mut conn.stream, &mut conn.read).await?;
            match Identification::decode(bytes) {
                Ok(Completion::Complete(decoded)) => break (bytes, decoded),
                Ok(Completion::Incomplete(_length)) => continue,
                Err(error) => return Err(error.into()),
            }
        };

        debug!(?ident, "received identification");
        if ident.protocol != PROTOCOL {
            warn!(?ident, "unsupported protocol version");
            return Err(ProtoError::from(IdentificationError::UnsupportedVersion(
                ident.protocol.to_owned(),
            ))
            .into());
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
            warn!(%error, "failed to send version exchange");
            return Err(error.into());
        }

        let v_s_len = server_ident_bytes.len() - 2;
        if let Some(v_s) = server_ident_bytes.get(..v_s_len) {
            exchange.prefixed(v_s);
        }

        // The ident was written to the stream directly, so drop it from the outgoing buffer
        conn.write.clear();

        let last_length = buf.len() - rest;
        conn.read.set_last_length(last_length);
        Ok(KeyExchange::default())
    }
}

pub(crate) async fn buffer<'a>(
    stream: &mut (impl AsyncRead + Unpin),
    state: &'a mut ReadState,
) -> Result<&'a [u8], Error> {
    let read = stream.read_buf(&mut state.buf).await?;
    trace!(read, "read from stream");
    match read {
        0 => Err(Error::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "EOF",
        ))),
        _ => Ok(&state.buf),
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("invalid user name")]
    InvalidUsername,
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("proto: {0}")]
    Proto(#[from] ProtoError),
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Proto(ProtoError::Crypto(error))
    }
}

struct Pretty<T>(T);

impl<T: fmt::Debug> fmt::Display for Pretty<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
