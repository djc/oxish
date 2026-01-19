use core::net::SocketAddr;
use std::{io, str, sync::Arc};

use aws_lc_rs::signature::Ed25519KeyPair;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, warn};

mod key_exchange;
use key_exchange::KeyExchange;
mod proto;
use proto::{Completion, Decoded, Encode, ReadState};

use crate::{
    key_exchange::{EcdhKeyExchangeInit, KeyExchangeInit},
    proto::HandshakeHash,
};

/// A single SSH connection
pub struct Connection<T> {
    stream: T,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
    read: ReadState,
    write_buf: Vec<u8>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Create a new [`Connection`]
    pub fn new(stream: T, addr: SocketAddr, host_key: Arc<Ed25519KeyPair>) -> anyhow::Result<Self> {
        Ok(Self {
            stream,
            addr,
            host_key,
            read: ReadState::default(),
            write_buf: Vec::with_capacity(16_384),
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

        let future = self
            .read
            .packet::<KeyExchangeInit<'_>>(&mut self.stream, self.addr);
        let (peer_key_exchange_init, rest) = match future.await {
            Ok(packeted) => packeted.hash(&mut exchange),
            Err(error) => {
                error!(addr = %self.addr, %error, "failed to read key exchange init");
                return;
            }
        };

        self.write_buf.clear();
        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
            write_buf: &mut self.write_buf,
        };

        let Ok((packet, state)) = state.advance(peer_key_exchange_init, &mut exchange, &mut cx)
        else {
            return;
        };

        if let Err(error) = self.stream.write_all(&packet).await {
            error!(addr = %self.addr, %error, "failed to send ECDH key exchange reply");
            return;
        }

        self.read.used = self.read.buf.len() - rest;

        let future = self
            .read
            .packet::<EcdhKeyExchangeInit<'_>>(&mut self.stream, self.addr);
        let ecdh_key_exchange_init = match future.await {
            Ok(packet) => packet.into_inner(),
            Err(_) => return,
        };

        self.write_buf.clear();
        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
            write_buf: &mut self.write_buf,
        };

        let Ok((packet, _keys)) = state.advance(ecdh_key_exchange_init, exchange, &mut cx) else {
            return;
        };

        if let Err(error) = self.stream.write_all(&packet).await {
            error!(addr = %self.addr, %error, "failed to send ECDH key exchange reply");
            return;
        }

        todo!();
    }
}

struct ConnectionContext<'a> {
    addr: SocketAddr,
    host_key: &'a Ed25519KeyPair,
    write_buf: &'a mut Vec<u8>,
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
        let Decoded { value: ident, next } = loop {
            let bytes = conn.read.buffer(&mut conn.stream).await?;
            match Identification::decode(bytes) {
                Ok(Completion::Complete(decoded)) => break decoded,
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
        let v_c_len = conn.read.buf.len() - rest - 2;
        if let Some(v_c) = conn.read.buf.get(..v_c_len) {
            exchange.prefixed(v_c);
        }

        let ident = Identification::outgoing();
        ident.encode(&mut conn.write_buf);
        if let Err(error) = conn.stream.write_all(&conn.write_buf).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(error.into());
        }

        let v_s_len = conn.write_buf.len() - 2;
        if let Some(v_s) = conn.write_buf.get(..v_s_len) {
            exchange.prefixed(v_s);
        }

        conn.read.used = conn.read.buf.len() - rest;
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

impl Encode for Identification<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"SSH-");
        buf.extend_from_slice(self.protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(self.software.as_bytes());
        if !self.comments.is_empty() {
            buf.push(b' ');
            buf.extend_from_slice(self.comments.as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
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
