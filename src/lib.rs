use core::net::SocketAddr;
use std::{io, str, sync::Arc};

use aws_lc_rs::{digest, signature::Ed25519KeyPair};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp, TcpStream},
};
use tracing::{debug, warn};

mod key_exchange;
use key_exchange::KeyExchange;
mod proto;
use proto::{DecryptingReader, Encode};

/// A single SSH connection
pub struct Connection {
    stream_read: DecryptingReader<tcp::OwnedReadHalf>,
    stream_write: tcp::OwnedWriteHalf,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
    write_buf: Vec<u8>,
}

impl Connection {
    /// Create a new [`Connection`]
    pub fn new(
        stream: TcpStream,
        addr: SocketAddr,
        host_key: Arc<Ed25519KeyPair>,
    ) -> anyhow::Result<Self> {
        stream.set_nodelay(true)?;

        let (stream_read, stream_write) = stream.into_split();

        Ok(Self {
            stream_read: DecryptingReader::new(stream_read),
            stream_write,
            addr,
            host_key,
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
        let ident_bytes = match Identification::read_from_stream(&mut conn.stream_read).await {
            Ok(ident_bytes) => ident_bytes,
            Err(error) => {
                warn!(addr = %conn.addr, %error, "failed to read version exchange");
                return Err(());
            }
        };
        let ident = match Identification::decode(&ident_bytes) {
            Ok(ident) => {
                debug!(addr = %conn.addr, ?ident, "received identification");
                ident
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

        let v_c = &ident_bytes;
        exchange.update(&(v_c.len() as u32).to_be_bytes());
        exchange.update(v_c);

        let ident = Identification::outgoing();
        ident.encode(&mut conn.write_buf);
        if let Err(error) = conn.stream_write.write_all(&conn.write_buf).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        let v_s_len = conn.write_buf.len() - 2;
        if let Some(v_s) = conn.write_buf.get(..v_s_len) {
            exchange.update(&(v_s.len() as u32).to_be_bytes());
            exchange.update(v_s);
        }

        Ok(KeyExchange::for_new_session())
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
    /// Read the identification string as raw bytes with the CRLF stripped off.
    async fn read_from_stream(
        stream: &mut DecryptingReader<impl AsyncReadExt + Unpin>,
    ) -> Result<Vec<u8>, Error> {
        let mut data = vec![];
        loop {
            data.push(stream.read_u8_cleartext().await?);
            if data.len() > 255 {
                return Err(IdentificationError::TooLong.into());
            }
            if let Some((_, b"\r\n")) = data.split_last_chunk::<2>() {
                data.pop().unwrap();
                data.pop().unwrap();
                break;
            }
        }
        debug!(bytes = data.len(), "read from stream");
        Ok(data)
    }

    fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let Ok(message) = str::from_utf8(bytes) else {
            return Err(IdentificationError::InvalidUtf8.into());
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

        Ok(Self {
            protocol,
            software,
            comments,
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
