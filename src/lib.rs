use std::{io, net::SocketAddr, str};

use aws_lc_rs::digest;
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{debug, warn};

mod key_exchange;
use key_exchange::KeyExchange;
mod proto;
use proto::{read, Decode, Decoded, Encode};

/// A single SSH connection
pub struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl Connection {
    /// Create a new [`Connection`]
    pub fn new(stream: TcpStream, addr: SocketAddr) -> anyhow::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            addr,
            read_buf: Vec::with_capacity(16_384),
            write_buf: Vec::with_capacity(16_384),
        })
    }

    /// Drive the connection forward
    pub async fn run(mut self) {
        let mut exchange = digest::Context::new(&digest::SHA256);
        let state = VersionExchange::default();
        let Ok(state) = state.advance(&mut exchange, &mut self).await else {
            return;
        };

        let Ok(state) = state.advance(&mut exchange, &mut self).await else {
            return;
        };

        let Ok(()) = state.advance(exchange, &mut self).await else {
            return;
        };

        todo!();
    }
}

#[derive(Default)]
struct VersionExchange(());

impl VersionExchange {
    async fn advance(
        &self,
        exchange: &mut digest::Context,
        conn: &mut Connection,
    ) -> Result<KeyExchange, ()> {
        let ident = Identification::outgoing();
        ident.encode(&mut conn.write_buf);
        if let Err(error) = conn.stream.write_all(&conn.write_buf).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        let (ident, rest) =
            match read::<Identification<'_>>(&mut conn.stream, &mut conn.read_buf).await {
                Ok(Decoded { value: ident, next }) => {
                    debug!(addr = %conn.addr, ?ident, "received identification");
                    (ident, next.len())
                }
                Err(error) => {
                    warn!(addr = %conn.addr, %error, "failed to read version exchange");
                    return Err(());
                }
            };

        if ident.protocol != PROTOCOL {
            warn!(addr = %conn.addr, ?ident, "unsupported protocol version");
            return Err(());
        }

        let v_c_len = conn.read_buf.len() - rest - 2;
        if let Some(v_c) = conn.read_buf.get(..v_c_len) {
            exchange.update(&(v_c.len() as u32).to_be_bytes());
            exchange.update(v_c);
        }

        let v_s_len = conn.write_buf.len() - 2;
        if let Some(v_s) = conn.write_buf.get(..v_s_len) {
            exchange.update(&(v_s.len() as u32).to_be_bytes());
            exchange.update(v_s);
        }

        if rest > 0 {
            let start = conn.read_buf.len() - rest;
            conn.read_buf.copy_within(start.., 0);
        }
        conn.read_buf.truncate(rest);

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

impl<'a> Decode<'a> for Identification<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Ok(message) = str::from_utf8(bytes) else {
            return Err(IdentificationError::InvalidUtf8.into());
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
}

const PROTOCOL: &str = "2.0";
const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
