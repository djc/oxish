use core::{
    future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use std::{io, str, sync::Arc, task::ready};

use proto::{
    Completion, Decoded, EcdhKeyExchangeInit, EcdhKeyExchangeReply, Encode, ExtensionId,
    Identification, IdentificationError, Ignore, IncomingPacket, KeyExchange, KeySourceSet,
    MethodName, NewKeys, PROTOCOL, ProtoError, ReadState, UserAuthFailure, WriteState,
    crypto::{CryptoError, CryptoProvider, Digest, HandshakeBuffer, HandshakeHash, SigningKey},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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

#[cfg(test)]
mod tests;

/// Core connection state and logic for an SSH session
pub struct Connection<T> {
    stream: T,
    addr: SocketAddr,
    read: ReadState,
    write: WriteState,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Create a new [`Connection`] and perform key exchange
    #[instrument(name = "handshake", skip(stream, addr, host_keys, provider), fields(addr = %addr))]
    pub async fn accept(
        stream: T,
        addr: SocketAddr,
        host_keys: &[Arc<dyn SigningKey>],
        provider: &dyn CryptoProvider,
    ) -> Result<(Self, Digest, KeySourceSet), ()> {
        let mut new = Self {
            stream,
            addr,
            read: ReadState::default(),
            write: WriteState::new(provider.secure_random()),
        };

        let future = new.exchange_keys(host_keys, provider);
        match timeout(Duration::from_secs(30), future).await {
            Ok(Ok((session_id, keys))) => Ok((new, session_id, keys)),
            Ok(Err(())) => Err(()),
            Err(_) => {
                error!("key exchange timed out");
                Err(())
            }
        }
    }

    /// Perform the SSH handshake and key exchange, returning the session ID
    async fn exchange_keys(
        &mut self,
        host_keys: &[Arc<dyn SigningKey>],
        provider: &dyn CryptoProvider,
    ) -> Result<(Digest, KeySourceSet), ()> {
        if host_keys.is_empty() {
            error!("no host keys configured");
            return Err(());
        }

        let exchange = match self.identify().await {
            Ok(exchange) => exchange,
            Err(error) => {
                error!(%error, "failed to identify client");
                return Err(());
            }
        };

        // Receive and send key exchange init packets

        let packet = receive(&mut self.stream, &mut self.read).await?;
        let mut kx = match KeyExchange::start(
            packet,
            exchange,
            host_keys
                .iter()
                .map(|key| key.algorithm())
                .collect::<Vec<_>>(),
            [ExtensionId::StrictKexServer].into_iter(),
            provider,
        ) {
            Ok(result) => result,
            Err(error) => {
                error!(%error, "failed to read key exchange init");
                return Err(());
            }
        };

        self.send_handshake(&kx.local, Some(&mut kx.exchange))
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

        let result = EcdhKeyExchangeReply::new(
            ecdh_key_exchange_init,
            &kx.negotiated,
            kx.exchange,
            host_keys,
            provider,
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
    ) -> Result<(), ()> {
        let packet = receive(&mut self.stream, &mut self.read).await?;
        if let Err(error) = NewKeys::try_from(packet) {
            error!(%error, "failed to read new keys packet");
            return Err(());
        }

        // Under strict key exchange the sequence numbers are reset to zero once NEWKEYS crosses in
        // each direction, so the first encrypted packet after NEWKEYS uses sequence number zero.
        if strict {
            self.read.reset_sequence_number();
        }

        self.send(&NewKeys).await?;
        if strict {
            self.write.reset_sequence_number();
        }

        let results = (
            provider.opening_key(0, &keys.client_to_server),
            provider.sealing_key(0, &keys.server_to_client),
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

pub(crate) fn send(
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
