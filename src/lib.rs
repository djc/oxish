use core::net::SocketAddr;
use std::{io, str, sync::Arc};

use aws_lc_rs::signature::Ed25519KeyPair;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, warn};

mod key_exchange;
use key_exchange::KeyExchange;
mod proto;
use proto::{AesCtrWriteKeys, Completion, Decoded, MessageType, ReadState, WriteState};

use crate::{
    key_exchange::{EcdhKeyExchangeInit, KeyExchangeInit, NewKeys},
    proto::{AesCtrReadKeys, HandshakeHash},
};

/// A single SSH connection
pub struct Connection<T> {
    stream: T,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
    read: ReadState,
    write: WriteState,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Create a new [`Connection`]
    pub fn new(stream: T, addr: SocketAddr, host_key: Arc<Ed25519KeyPair>) -> anyhow::Result<Self> {
        Ok(Self {
            stream,
            addr,
            host_key,
            read: ReadState::default(),
            write: WriteState::default(),
        })
    }

    /// Drive the connection forward
    pub async fn run(mut self) {
        let mut exchange = HandshakeHash::default();
        let state = VersionExchange::default();
        let state = match state.advance(&mut exchange, &mut self).await {
            Ok(state) => state,
            Err(error) => {
                error!(addr = %self.addr, %error, "failed to complete version exchange");
                return;
            }
        };

        let packet = match self.read.packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet");
                return;
            }
        };
        exchange.prefixed(packet.payload);
        let peer_key_exchange_init = match KeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read key exchange init");
                return;
            }
        };

        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
        };

        let Ok((key_exchange_init, state)) = state.advance(peer_key_exchange_init, &mut cx) else {
            return;
        };

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &key_exchange_init, Some(&mut exchange))
            .await
        {
            warn!(addr = %self.addr, %error, "failed to send key exchange init packet");
            return;
        }

        let packet = match self.read.packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet");
                return;
            }
        };
        let Ok(ecdh_key_exchange_init) = EcdhKeyExchangeInit::try_from(packet) else {
            return;
        };

        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
        };

        let Ok((key_exchange_reply, keys)) =
            state.advance(ecdh_key_exchange_init, exchange, &mut cx)
        else {
            return;
        };

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &key_exchange_reply, None)
            .await
        {
            warn!(addr = %self.addr, %error, "failed to send key exchange init packet");
            return;
        }

        let packet = match self.read.packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet");
                return;
            }
        };
        let Ok(NewKeys) = NewKeys::try_from(packet) else {
            return;
        };

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &NewKeys, None)
            .await
        {
            warn!(addr = %self.addr, %error, "failed to send newkeys packet");
            return;
        }

        // Cipher and MAC algorithms are negotiated during key exchange.
        // Currently this hard codes AES-128-CTR and HMAC-SHA256.
        self.read.decryption_key = Some(AesCtrReadKeys::new(keys.client_to_server));
        self.write.keys = Some(AesCtrWriteKeys::new(keys.server_to_client));

        self.write
            .write_packet(&mut self.stream, &MessageType::Ignore, None)
            .await
            .unwrap();

        todo!();
    }
}

struct ConnectionContext<'a> {
    addr: SocketAddr,
    host_key: &'a Ed25519KeyPair,
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

        debug!(addr = %conn.addr, ?ident, "received identification");
        if ident.protocol != PROTOCOL {
            warn!(addr = %conn.addr, ?ident, "unsupported protocol version");
            return Err(IdentificationError::UnsupportedVersion(ident.protocol.to_owned()).into());
        }

        let rest = next.len();
        let v_c_len = buf.len() - rest - 2;
        if let Some(v_c) = buf.get(..v_c_len) {
            exchange.prefixed(v_c);
        }

        let ident = Identification::outgoing();
        let server_ident_bytes = ident.encode();
        if let Err(error) = conn.stream.write_all(&server_ident_bytes).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
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

#[derive(Debug)]
struct Identification<'a> {
    protocol: &'a str,
    software: &'a str,
    comments: &'a str,
}

impl Identification<'_> {
    fn outgoing() -> Self {
        Self {
            protocol: PROTOCOL,
            software: SOFTWARE,
            comments: "",
        }
    }
}

impl<'a> Identification<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Completion<Decoded<'a, Self>>, Error> {
        let Ok(message) = str::from_utf8(bytes) else {
            return Err(IdentificationError::InvalidUtf8.into());
        };

        let Some((message, next)) = message.split_once("\r\n") else {
            // The maximum length is 255 bytes including CRLF. message excludes
            // the CRLF, so subtract 2.
            return match message.len() > 255 - 2 {
                true => Err(IdentificationError::TooLong.into()),
                false => Ok(Completion::Incomplete(None)),
            };
        };

        let Some(rest) = message.strip_prefix("SSH-") else {
            return Err(IdentificationError::NoSsh.into());
        };

        let Some((protocol, rest)) = rest.split_once('-') else {
            return Err(IdentificationError::NoVersion.into());
        };

        let (software, comments) = match rest.split_once(' ') {
            Some((software, comments)) => (software, comments),
            None => (rest, ""),
        };

        let out = Self {
            protocol,
            software,
            comments,
        };

        Ok(Completion::Complete(Decoded {
            value: out,
            next: next.as_bytes(),
        }))
    }
}

impl Identification<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(b"SSH-");
        buf.extend_from_slice(self.protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(self.software.as_bytes());
        if !self.comments.is_empty() {
            buf.push(b' ');
            buf.extend_from_slice(self.comments.as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("failed to get random bytes")]
    FailedRandomBytes,
    #[error("failed to parse identification: {0}")]
    Identification(#[from] IdentificationError),
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

const PROTOCOL: &str = "2.0";
const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
