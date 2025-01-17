use std::{io, net::SocketAddr, str};

use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{debug, error, warn};

mod key_exchange;
use key_exchange::{KeyExchange, KeyExchangeInit};
mod proto;
use proto::{Decode, Decoded, Encode, Packet, StreamState};

/// A single SSH connection
pub struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
}

impl Connection {
    /// Create a new [`Connection`]
    pub fn new(stream: TcpStream, addr: SocketAddr) -> anyhow::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self { stream, addr })
    }

    /// Drive the connection forward
    pub async fn run(self) {
        let Self { mut stream, addr } = self;
        let mut write_buf = Vec::with_capacity(16_384);
        let ident = Identification::outgoing();
        ident.encode(&mut write_buf);
        if let Err(error) = stream.write_all(&write_buf).await {
            warn!(%addr, %error, "failed to send version exchange");
            return;
        }
        write_buf.clear();

        let state = VersionExchange;
        let mut read_buf = Vec::with_capacity(16_384);
        let (ident, rest) = match state.read(&mut stream, &mut read_buf).await {
            Ok((ident, rest)) => {
                debug!(%addr, ?ident, "received identification");
                (ident, rest)
            }
            Err(error) => {
                warn!(%addr, %error, "failed to read version exchange");
                return;
            }
        };

        if ident.protocol != PROTOCOL {
            warn!(%addr, ?ident, "unsupported protocol version");
            return;
        }

        if rest > 0 {
            let start = read_buf.len() - rest;
            read_buf.copy_within(start.., 0);
        }
        read_buf.truncate(rest);

        let state = KeyExchange;
        let key_exchange_init = match KeyExchangeInit::new() {
            Ok(kex_init) => kex_init,
            Err(error) => {
                error!(%addr, %error, "failed to create key exchange init");
                return;
            }
        };

        if let Err(error) = Packet::encode(&key_exchange_init, &mut write_buf) {
            warn!(%addr, %error, "failed to encode key exchange init");
            return;
        }

        if let Err(error) = stream.write_all(&write_buf).await {
            warn!(%addr, %error, "failed to send version exchange");
            return;
        }
        write_buf.clear();

        let (peer_key_exchange_init, rest) = match state.read(&mut stream, &mut read_buf).await {
            Ok((key_exchange_init, rest)) => {
                debug!(%addr, "received key exchange init");
                (key_exchange_init, rest)
            }
            Err(error) => {
                warn!(%addr, %error, "failed to read key exchange init");
                return;
            }
        };

        todo!();
    }
}

struct VersionExchange;

impl<'a> StreamState<'a> for VersionExchange {
    type Input = Identification<'a>;
    type Output = Identification<'a>;
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

impl<'a> Decode<'a> for Identification<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let message = match str::from_utf8(bytes) {
            Ok(message) => message,
            Err(_) => return Err(IdentificationError::InvalidUtf8.into()),
        };

        let Some((message, next)) = message.split_once("\r\n") else {
            return Err(match message.len() > 256 {
                true => IdentificationError::TooLong.into(),
                false => Error::Incomplete(None),
            });
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

        Ok(Decoded {
            value: out,
            next: next.as_bytes(),
        })
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
}

const PROTOCOL: &str = "2.0";
const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
