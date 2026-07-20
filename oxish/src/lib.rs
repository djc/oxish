use core::{
    fmt, future,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};
use std::{io, str, sync::Arc, task::ready};

use anyhow::Context as _;
use proto::{
    Completion, Decode, Decoded, EcdhKeyExchangeInit, EcdhKeyExchangeReply, Encode,
    EncryptionAlgorithm, ExtensionId, Identification, IdentificationError, Ignore, IncomingPacket,
    KeyExchange, KeySourceSet, MethodName, NewKeys, PROTOCOL, ProtoError, ReadState,
    UserAuthFailure, WriteState,
    crypto::{
        CryptoError, CryptoProvider, Digest, HandshakeBuffer, HandshakeHash, KeyLengths,
        KeySourceSide, SigningKey,
    },
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, trace, warn};

#[cfg(feature = "aws-lc")]
pub use aws_lc::DEFAULT_PROVIDER;
#[cfg(all(feature = "graviola", not(feature = "aws-lc")))]
pub use graviola::DEFAULT_PROVIDER;
#[cfg(all(not(feature = "aws-lc"), not(feature = "graviola")))]
compile_error!("no crypto providers enabled -- enable at least one to fix this error");

mod authentication;
pub use authentication::{Auth, User};
mod session;
pub use session::Session;
mod server;
pub use server::Server;

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
    async fn exchange_keys(
        &mut self,
        host_keys: &[Arc<dyn SigningKey>],
        provider: &dyn CryptoProvider,
    ) -> anyhow::Result<(Digest, KeySourceSet)> {
        let exchange = self.identify().await.context("identification failed")?;

        // Receive and send key exchange init packets

        let packet = receive(&mut self.stream, &mut self.read).await?;
        let mut kx = KeyExchange::start(
            packet,
            exchange,
            host_keys
                .iter()
                .map(|key| key.algorithm())
                .collect::<Vec<_>>(),
            [ExtensionId::StrictKexServer].into_iter(),
            provider,
        )?;

        self.send_handshake(&kx.local, Some(&mut kx.exchange))
            .await?;

        // Perform ECDH key exchange

        let packet = receive(&mut self.stream, &mut self.read).await?;
        let ecdh_key_exchange_init = EcdhKeyExchangeInit::try_from(packet)?;
        let (key_exchange_reply, session_id, keys) = EcdhKeyExchangeReply::new(
            ecdh_key_exchange_init,
            &kx.negotiated,
            kx.exchange,
            host_keys,
            provider,
        )?;

        self.send(&key_exchange_reply).await?;

        // Exchange new keys packets and install new keys

        self.update_keys(&keys, kx.negotiated.strict_key_exchange, provider)
            .await?;
        if kx.negotiated.want_extension_info {
            self.send(&kx.ext_info).await?;
        }

        self.send(&Ignore::default()).await?;
        Ok((session_id, keys))
    }

    async fn update_keys(
        &mut self,
        keys: &KeySourceSet,
        strict: bool,
        provider: &dyn CryptoProvider,
    ) -> Result<(), Error> {
        let packet = receive(&mut self.stream, &mut self.read).await?;
        NewKeys::try_from(packet)?;

        // Under strict key exchange the sequence numbers are reset to zero once NEWKEYS crosses in
        // each direction, so the first encrypted packet after NEWKEYS uses sequence number zero.
        if strict {
            self.read.reset_sequence_number();
        }

        self.send(&NewKeys).await?;
        if strict {
            self.write.reset_sequence_number();
        }

        self.read.opener = Some(provider.opening_key(0, &keys.client_to_server)?);
        self.write.sealer = Some(provider.sealing_key(0, &keys.server_to_client)?);
        Ok(())
    }

    async fn identify(&mut self) -> Result<HandshakeBuffer, Error> {
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

        let mut exchange = HandshakeBuffer::default();
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

        let server_ident_bytes = self.write.encoded(&ident);
        if let Err(error) = self.stream.write_all(server_ident_bytes).await {
            warn!(%error, "failed to send version exchange");
            return Err(error.into());
        }

        let v_s_len = server_ident_bytes.len() - 2;
        if let Some(v_s) = server_ident_bytes.get(..v_s_len) {
            exchange.prefixed(v_s);
        }

        // The ident was written to the stream directly, so drop it from the outgoing buffer
        self.write.clear();

        let last_length = buf.len() - rest;
        self.read.set_last_length(last_length);
        Ok(exchange)
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
struct SessionState {
    addr: SocketAddr,
    read: SideState,
    write: SideState,
    /// Residual inbound bytes already drained from the socket (pipelined packets)
    read_buf: Vec<u8>,
}

impl SessionState {
    /// Construct a [`SessionState`] from a [`Connection`] and its [`KeySourceSet`]
    ///
    /// Fails if no keys were installed or the write buffer still holds unflushed bytes.
    pub(crate) fn from_connection<T>(
        conn: Connection<T>,
        keys: KeySourceSet,
    ) -> Result<(Self, T), Error> {
        let Connection {
            stream,
            addr,
            mut read,
            write,
        } = conn;

        if !write.buffered().is_empty() {
            return Err(Error::InvalidState("unflushed bytes in write buffer"));
        }

        // Compact the bytes of the last decoded packet, which are still at the front of
        // the buffer (they are usually dropped at the start of the next `poll_packet()`).
        if read.last_length > 0 {
            read.buf.copy_within(read.last_length.., 0);
            read.buf.truncate(read.buf.len() - read.last_length);
            read.last_length = 0;
        }

        Ok((
            Self {
                addr,
                read: SideState {
                    source: keys.client_to_server,
                    counter: read.opener.as_ref().map_or(0, |opener| opener.counter()),
                    sequence_number: read.sequence_number,
                },
                write: SideState {
                    source: keys.server_to_client,
                    counter: write.sealer.as_ref().map_or(0, |sealer| sealer.counter()),
                    sequence_number: write.sequence_number,
                },
                read_buf: read.buf,
            },
            stream,
        ))
    }
}

impl Encode for SessionState {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.addr.to_string().as_bytes().encode(buf);
        self.read.encode(buf);
        self.write.encode(buf);
        self.read_buf.encode(buf);
    }
}

impl Decode<'_> for SessionState {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value: addr, next } = <&[u8]>::decode(bytes)?;
        let Ok(addr) = str::from_utf8(addr) else {
            return Err(ProtoError::InvalidPacket("invalid UTF-8 in peer address"));
        };

        let Ok(addr) = SocketAddr::from_str(addr) else {
            return Err(ProtoError::InvalidPacket("invalid peer address"));
        };

        let Decoded { value: read, next } = SideState::decode(next)?;
        let Decoded { value: write, next } = SideState::decode(next)?;
        let Decoded {
            value: read_buf,
            next,
        } = <&[u8]>::decode(next)?;

        Ok(Decoded {
            value: Self {
                addr,
                read,
                write,
                read_buf: read_buf.to_vec(),
            },
            next,
        })
    }
}

impl fmt::Debug for SessionState {
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
        self.source.algorithm.encode(buf);
        self.source.encryption_key.encode(buf);
        self.source.initial_iv.encode(buf);
        self.counter.encode(buf);
        self.sequence_number.encode(buf);
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

        if packet_length.0 > 64 * 1024 {
            return Err(Error::Proto(ProtoError::InvalidPacket("packet too large")));
        }

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

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
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

const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
