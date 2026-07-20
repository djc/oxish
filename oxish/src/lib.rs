use core::{
    future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use std::{io, path::PathBuf, str, sync::Arc, task::ready};

use anyhow::Context as _;
use proto::{
    Completion, Decoded, EcdhKeyExchangeInit, EcdhKeyExchangeReply, Encode, ExtensionId,
    Identification, IdentificationError, Ignore, IncomingPacket, KeyExchange, KeySourceSet,
    MethodName, NewKeys, PROTOCOL, ProtoError, ReadState, UserAuthFailure, WriteState,
    crypto::{CryptoError, CryptoProvider, Digest, HandshakeBuffer, HandshakeHash, SigningKey},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::{debug, error, instrument, trace, warn};

#[cfg(feature = "aws-lc")]
pub use aws_lc::DEFAULT_PROVIDER;
#[cfg(all(feature = "graviola", not(feature = "aws-lc")))]
pub use graviola::DEFAULT_PROVIDER;
#[cfg(all(not(feature = "aws-lc"), not(feature = "graviola")))]
compile_error!("no crypto providers enabled -- enable at least one to fix this error");

mod authentication;
pub use authentication::{Auth, User};
mod session;
pub use session::{Session, SessionState};

pub struct Server {
    provider: &'static dyn CryptoProvider,
    host_keys: Vec<Arc<dyn SigningKey>>,
    session: PathBuf,
    auth: Auth,
}

impl Server {
    pub fn new(
        auth: Auth,
        host_keys: Vec<Arc<dyn SigningKey>>,
        session: PathBuf,
        provider: &'static dyn CryptoProvider,
    ) -> anyhow::Result<Self> {
        if host_keys.is_empty() {
            return Err(anyhow::anyhow!("no host keys configured"));
        }

        Ok(Self {
            provider,
            host_keys,
            session,
            auth,
        })
    }

    pub async fn accept(&self, stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        let (mut conn, session_id, keys) = Connection::accept(stream, addr, self)
            .await
            .context("key exchange failed")?;

        let user = self
            .auth
            .authenticate(session_id, &mut conn, self.provider)
            .await
            .context("authentication failed")?;

        let (state, stream) = SessionState::from_connection(conn, keys)?;
        let mut child = state
            .spawn(stream, user, self)
            .await
            .context("failed to spawn session process")?;

        match child.wait().await {
            Ok(status) if status.success() => {
                debug!(%addr, %status, "session process exited");
                Ok(())
            }
            Ok(status) => Err(anyhow::anyhow!("session process exited with {status}")),
            Err(error) => Err(error).context("failed to wait for session process"),
        }
    }
}

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
    /// Create a new [`Connection`] and perform key exchange
    #[instrument(name = "handshake", skip(stream, addr, server), fields(addr = %addr))]
    async fn accept(
        stream: T,
        addr: SocketAddr,
        server: &Server,
    ) -> anyhow::Result<(Self, Digest, KeySourceSet)> {
        let mut new = Self {
            stream,
            addr,
            read: ReadState::default(),
            write: WriteState::new(server.provider.secure_random()),
        };

        let future = new.exchange_keys(&server.host_keys, server.provider);
        match timeout(Duration::from_secs(30), future).await {
            Ok(result) => result.map(|(session_id, keys)| (new, session_id, keys)),
            Err(_) => Err(anyhow::anyhow!("key exchange timed out")),
        }
    }

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
