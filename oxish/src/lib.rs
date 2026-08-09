//! OxiSH: a modern, memory-safe SSH server implementation

#![warn(missing_docs)]

use core::{
    fmt, future,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};
use std::{io, str, task::ready};

use anyhow::Context as _;
use proto::{
    Completion, Decode, Decoded, Encode, Identification, IdentificationError, Ignore,
    IncomingPacket, PROTOCOL, ProtoError, ReadState, WriteState,
    auth::UserAuthFailure,
    crypto::{
        CryptoError, CryptoProvider, Digest, HandshakeBuffer, HandshakeHash, KeyLengths,
        KeySourceSide,
    },
    key_exchange::{
        EcdhKeyExchangeInit, HostKeys, Identities, KeyExchange, KeySourceSet, NewKeys, Rekey,
        ServerHostKey, SessionHostKey, StrictKeyExchange,
    },
    named::{EncryptionAlgorithm, ExtensionId, MethodName},
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, trace, warn};

/// Default cryptography provider, as determined based on the enabled features
#[cfg(any(feature = "aws-lc", feature = "aws-lc-fips"))]
pub use aws_lc::DEFAULT_PROVIDER;
/// Default cryptography provider, as determined based on the enabled features
#[cfg(all(
    feature = "graviola",
    not(feature = "aws-lc"),
    not(feature = "aws-lc-fips")
))]
pub use graviola::DEFAULT_PROVIDER;
#[cfg(all(
    not(feature = "aws-lc"),
    not(feature = "aws-lc-fips"),
    not(feature = "graviola")
))]
compile_error!("no crypto providers enabled -- enable at least one to fix this error");

mod authentication;
pub use authentication::{AuthError, DefaultStore, User, UserStore, Username};
mod session;
pub use session::Session;
mod server;
pub use server::{Config, Server};

#[cfg(test)]
mod tests;

/// Core connection state and logic for an SSH session
struct Connection<T> {
    stream: T,
    addr: SocketAddr,
    read: ReadState,
    write: WriteState,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Perform the SSH handshake and key exchange, returning the session ID
    async fn exchange_keys<'h>(
        &mut self,
        host_keys: &'h HostKeys,
        provider: &dyn CryptoProvider,
    ) -> anyhow::Result<(
        Identities,
        ServerHostKey<'h>,
        Option<StrictKeyExchange>,
        Digest,
        KeySourceSet,
    )> {
        let (exchange, identities) = self.identify().await.context("identification failed")?;

        // Receive and send key exchange init packets

        let packet = receive(&mut self.stream, &mut self.read).await?;
        let (mut kx, strict_kx, ext_info) = KeyExchange::start(
            packet,
            exchange,
            host_keys.algorithms().collect(),
            [ExtensionId::StrictKexServer].into_iter(),
            provider,
        )?;

        self.send_handshake(&kx.local, Some(&mut kx.exchange))
            .await?;

        // Perform ECDH key exchange

        let packet = receive(&mut self.stream, &mut self.read).await?;
        let ecdh_key_exchange_init = EcdhKeyExchangeInit::try_from(packet)?;
        let (host_key, key_exchange_reply, session_id, keys) = kx
            .complete(ecdh_key_exchange_init, host_keys, provider)
            .context("key exchange failed")?;

        self.send(&key_exchange_reply).await?;
        self.update_keys(&keys, strict_kx.as_ref(), provider)
            .await?;

        if let Some(ext_info) = ext_info {
            self.send(&ext_info).await?;
        }

        self.send(&Ignore::default()).await?;
        Ok((identities, host_key, strict_kx, session_id, keys))
    }

    /// Complete a client-initiated rekey after its `SSH_MSG_KEXINIT` has been parsed
    async fn rekey(
        &mut self,
        mut kx: KeyExchange,
        rekey: &Rekey,
        provider: &dyn CryptoProvider,
    ) -> Result<(), Error> {
        debug!("starting client-initiated rekey");

        self.send_handshake(&kx.local, Some(&mut kx.exchange))
            .await?;

        let packet = receive(&mut self.stream, &mut self.read).await?;
        let ecdh_key_exchange_init = EcdhKeyExchangeInit::try_from(packet)?;
        let (key_exchange_reply, keys) = rekey.complete(
            ecdh_key_exchange_init,
            &kx.negotiated,
            kx.exchange,
            provider,
        )?;

        self.send(&key_exchange_reply).await?;
        self.update_keys(&keys, rekey.strict_key_exchange(), provider)
            .await?;

        debug!("completed client-initiated rekey");
        Ok(())
    }

    async fn update_keys(
        &mut self,
        keys: &KeySourceSet,
        strict_kx: Option<&StrictKeyExchange>,
        provider: &dyn CryptoProvider,
    ) -> Result<(), Error> {
        let packet = receive(&mut self.stream, &mut self.read).await?;
        NewKeys::try_from(packet)?;

        // Under strict key exchange the sequence numbers are reset to zero once NEWKEYS crosses in
        // each direction, so the first encrypted packet after NEWKEYS uses sequence number zero.
        self.read.reset_sequence_number(strict_kx);

        self.send(&NewKeys).await?;
        self.write.reset_sequence_number(strict_kx);

        self.read.opener = Some(provider.opening_key(0, &keys.client_to_server)?);
        self.write.sealer = Some(provider.sealing_key(0, &keys.server_to_client)?);
        Ok(())
    }

    async fn identify(&mut self) -> Result<(HandshakeBuffer, Identities), Error> {
        let (buf, Decoded { value: ident, next }) = loop {
            let bytes = buffer(&mut self.stream, &mut self.read).await?;
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

        let mut identities = Identities {
            client: Vec::new(),
            server: Vec::new(),
        };

        let mut exchange = HandshakeBuffer::default();
        let rest = next.len();
        let v_c_len = buf.len() - rest - 2;
        if let Some(v_c) = buf.get(..v_c_len) {
            exchange.prefixed(v_c);
            identities.client = v_c.to_vec();
        }

        let last_length = buf.len() - rest;
        self.read.set_last_length(last_length);

        let ident = Identification {
            protocol: PROTOCOL,
            software: SOFTWARE,
            comments: "",
        };

        let server_ident_bytes = self.write.encoded(&ident);
        if let Err(error) = self.stream.write_all(server_ident_bytes).await {
            warn!(%error, "failed to send version exchange");
            return Err(error.into());
        }

        let v_s_len = server_ident_bytes.len() - 2;
        if let Some(v_s) = server_ident_bytes.get(..v_s_len) {
            exchange.prefixed(v_s);
            identities.server = v_s.to_vec();
        }

        // The ident was written to the stream directly, so drop it from the outgoing buffer
        self.write.clear();
        Ok((exchange, identities))
    }

    async fn send_auth_failed(&mut self) -> Result<(), Error> {
        self.send(&UserAuthFailure {
            can_continue: &[MethodName::PublicKey],
            partial_success: false,
        })
        .await
    }

    async fn send(&mut self, payload: &impl Encode) -> Result<(), Error> {
        self.send_handshake(payload, None).await
    }

    async fn send_handshake(
        &mut self,
        payload: &impl Encode,
        exchange_hash: Option<&mut HandshakeHash>,
    ) -> Result<(), Error> {
        self.write
            .handle_packet(payload, exchange_hash)
            .inspect_err(|error| {
                error!(%error, "failed to encode packet");
            })?;

        future::poll_fn(|cx| send(&mut self.stream, &mut self.write, cx)).await
    }
}

/// The state needed to resume an authenticated connection in a session process
struct SessionState<H> {
    addr: SocketAddr,
    host_key: H,
    identities: Identities,
    strict_kx: Option<StrictKeyExchange>,
    session_id: Digest,
    read: SideState,
    write: SideState,
    /// Residual inbound bytes already drained from the socket (pipelined packets)
    read_buf: Vec<u8>,
}

impl Encode for SessionState<ServerHostKey<'_>> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self {
            addr,
            host_key,
            identities,
            strict_kx,
            session_id,
            read,
            write,
            read_buf,
        } = self;

        addr.to_string().as_bytes().encode(buf);
        host_key.encode(buf);
        identities.encode(buf);
        strict_kx.encode(buf);
        session_id.as_ref().encode(buf);
        read.encode(buf);
        write.encode(buf);
        read_buf.encode(buf);
    }
}

impl SessionState<SessionHostKey> {
    fn decode<'a>(
        bytes: &'a [u8],
        provider: &dyn CryptoProvider,
    ) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: addr, next } = <&[u8]>::decode(bytes)?;
        let Ok(addr) = str::from_utf8(addr) else {
            return Err(ProtoError::InvalidPacket("invalid UTF-8 in peer address"));
        };

        let Ok(addr) = SocketAddr::from_str(addr) else {
            return Err(ProtoError::InvalidPacket("invalid peer address"));
        };

        let Decoded {
            value: host_key,
            next,
        } = SessionHostKey::decode(next, provider)?;

        let Decoded {
            value: identities,
            next,
        } = Identities::decode(next)?;

        let Decoded {
            value: strict_kx,
            next,
        } = Option::<StrictKeyExchange>::decode(next)?;

        let Decoded {
            value: session_id,
            next,
        } = <&[u8]>::decode(next)?;

        let Decoded { value: read, next } = SideState::decode(next)?;
        let Decoded { value: write, next } = SideState::decode(next)?;
        let Decoded {
            value: read_buf,
            next,
        } = <&[u8]>::decode(next)?;

        Ok(Decoded {
            value: Self {
                addr,
                host_key,
                identities,
                strict_kx,
                session_id: Digest::new(session_id),
                read,
                write,
                read_buf: read_buf.to_vec(),
            },
            next,
        })
    }
}

impl<H> fmt::Debug for SessionState<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("addr", &self.addr)
            .field("read", &self.read)
            .field("write", &self.write)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct SideState {
    source: KeySourceSide,
    counter: u64,
    sequence_number: u32,
}

impl Encode for SideState {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self {
            source:
                KeySourceSide {
                    algorithm,
                    encryption_key,
                    initial_iv,
                },
            counter,
            sequence_number,
        } = self;

        algorithm.encode(buf);
        encryption_key.encode(buf);
        initial_iv.encode(buf);
        counter.encode(buf);
        sequence_number.encode(buf);
    }
}

impl Decode<'_> for SideState {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded {
            value: algorithm,
            next,
        } = EncryptionAlgorithm::decode(bytes)?;

        let Some(KeyLengths { key_len, iv_len }) = algorithm.lengths() else {
            return Err(ProtoError::InvalidPacket(
                "unsupported encryption algorithm",
            ));
        };

        let Decoded {
            value: encryption_key,
            next,
        } = <&[u8]>::decode(next)?;
        if encryption_key.len() != key_len {
            return Err(ProtoError::InvalidPacket("invalid encryption key length"));
        }

        let Decoded {
            value: initial_iv,
            next,
        } = <&[u8]>::decode(next)?;
        if initial_iv.len() != iv_len {
            return Err(ProtoError::InvalidPacket("invalid IV length"));
        }

        let Decoded {
            value: counter,
            next,
        } = u64::decode(next)?;

        let Decoded {
            value: sequence_number,
            next,
        } = u32::decode(next)?;

        Ok(Decoded {
            value: Self {
                source: KeySourceSide {
                    algorithm: algorithm.to_owned(),
                    initial_iv: initial_iv.to_owned(),
                    encryption_key: encryption_key.to_owned(),
                },
                counter,
                sequence_number,
            },
            next,
        })
    }
}

async fn receive<'a>(
    stream: &mut (impl AsyncRead + Unpin),
    state: &'a mut ReadState,
) -> Result<IncomingPacket<'a>, Error> {
    loop {
        // `PacketLength` enforces a reasonable maximum packet length.
        let (sequence_number, packet_length) = match state.poll_packet() {
            Ok(Completion::Complete((sequence_number, packet_length))) => {
                (sequence_number, packet_length)
            }
            Ok(Completion::Incomplete(_amount)) | Err(ProtoError::Incomplete(_amount)) => {
                buffer(stream, state).await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };

        return Ok(state.decode_packet(sequence_number, packet_length)?);
    }
}

fn send(
    stream: &mut (impl AsyncWrite + Unpin),
    state: &mut WriteState,
    cx: &mut Context<'_>,
) -> Poll<Result<(), Error>> {
    while !state.buffered().is_empty() {
        state.written(ready!(
            Pin::new(&mut *stream).poll_write(cx, state.buffered())
        ))?;
    }

    Pin::new(stream).poll_flush(cx).map_err(Error::from)
}

async fn buffer<'a>(
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

/// Error type for SSH connections
#[derive(Debug, Error)]
pub enum Error {
    /// Authentication errors
    #[error("authentication error: {0}")]
    Auth(#[from] AuthError),
    /// Invalid state encountered during SSH session
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
    /// Invalid username provided during authentication
    #[error("invalid user name")]
    InvalidUsername,
    /// I/O errors
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// Protocol errors
    #[error("proto: {0}")]
    Proto(#[from] ProtoError),
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Proto(ProtoError::Crypto(error))
    }
}

const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
