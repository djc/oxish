use core::net::SocketAddr;
use std::{io, str, sync::Arc};

use aws_lc_rs::{digest, signature::Ed25519KeyPair};
use thiserror::Error;
use tokio::{
    io::AsyncReadExt,
    net::{tcp, TcpStream},
};
use tracing::{debug, warn};

pub mod auth;
mod buffered_stream;
pub use buffered_stream::{buffered_stream, BufferedStream};
pub mod connection;
mod key_exchange;
use key_exchange::KeyExchange;
pub mod proto;
use proto::{Encode, EncryptingWriter, Packet, ReadState};
pub mod service;

/// A low level ssh transport layer protocol connection
pub struct SshTransportConnection {
    stream_read: tcp::OwnedReadHalf,
    stream_write: EncryptingWriter<tcp::OwnedWriteHalf>,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
    read: ReadState,
}

impl SshTransportConnection {
    /// Create a new [`Connection`] and do the initial key exchange
    pub async fn connect(
        stream: TcpStream,
        addr: SocketAddr,
        host_key: Arc<Ed25519KeyPair>,
    ) -> Result<Self, ()> {
        if let Err(error) = stream.set_nodelay(true) {
            warn!(addr = %addr, %error, "failed to set nodelay");
            return Err(());
        }

        let (stream_read, stream_write) = stream.into_split();

        let mut connection = Self {
            stream_read,
            stream_write: EncryptingWriter::new(stream_write),
            addr,
            host_key,
            read: ReadState::default(),
        };

        let mut exchange = digest::Context::new(&digest::SHA256);
        let state = VersionExchange::default();
        let state = state.advance(&mut exchange, &mut connection).await?;
        let state = state.advance(&mut exchange, &mut connection).await?;
        state.advance(exchange, &mut connection).await?;

        Ok(connection)
    }

    pub(crate) async fn recv_packet(&mut self) -> Result<Packet<'_>, Error> {
        self.read.read_packet(&mut self.stream_read).await
    }

    pub(crate) async fn send_packet(
        &mut self,
        payload: &(impl Encode + ?Sized),
    ) -> Result<(), Error> {
        self.stream_write.write_packet(payload, |_| {}).await
    }
}

#[derive(Default)]
struct VersionExchange(());

impl VersionExchange {
    async fn advance(
        &self,
        exchange: &mut digest::Context,
        conn: &mut SshTransportConnection,
    ) -> Result<KeyExchange, ()> {
        let ident_bytes =
            match Identification::read_from_stream(&mut conn.read, &mut conn.stream_read).await {
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
        let server_ident_bytes = ident.encode();
        if let Err(error) = conn
            .stream_write
            .write_raw_cleartext(&server_ident_bytes)
            .await
        {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        let v_s_len = server_ident_bytes.len() - 2;
        if let Some(v_s) = server_ident_bytes.get(..v_s_len) {
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
        read: &mut ReadState,
        stream: &mut (impl AsyncReadExt + Unpin),
    ) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(256);
        let mut ident = vec![];
        loop {
            if buf.is_empty() && stream.read_buf(&mut buf).await? == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF",
                )));
            }
            ident.push(buf.remove(0));
            if ident.len() > 255 {
                return Err(IdentificationError::TooLong.into());
            }
            if let Some((_, b"\r\n")) = ident.split_last_chunk::<2>() {
                ident.pop().unwrap();
                ident.pop().unwrap();
                break;
            }
        }
        debug!(bytes = ident.len(), "read from stream");

        // Give all data we read but isn't part of the identification string to the ReadState.
        read.incoming_buf().extend(buf);

        Ok(ident)
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
}

const PROTOCOL: &str = "2.0";
const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
