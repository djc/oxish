use core::{net::SocketAddr, ops::Deref};
use std::{io, str, sync::Arc};

use aws_lc_rs::{digest, signature::Ed25519KeyPair};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, error, warn};

mod key_exchange;
use key_exchange::KeyExchange;
mod proto;
use proto::{read, Decode, Decoded, Encode};

use crate::{key_exchange::EcdhKeyExchangeInit, proto::Packet};

/// A single SSH connection
pub struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
    read: ReadState,
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
        let mut exchange = digest::Context::new(&digest::SHA256);
        let state = VersionExchange::default();
        let Ok(state) = state.advance(&mut exchange, &mut self).await else {
            return;
        };

        let Ok(state) = state.advance(&mut exchange, &mut self).await else {
            return;
        };

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

struct ReadState {
    buf: Vec<u8>,
}

impl ReadState {
    async fn packet<'a, T: TryFrom<Packet<'a>, Error = Error> + 'a>(
        &'a mut self,
        stream: &mut (impl AsyncRead + Unpin),
        addr: SocketAddr,
    ) -> Result<Packeted<'a, T>, Error> {
        let (packet, _rest) = match read::<Packet<'_>>(stream, &mut self.buf).await {
            Ok(Decoded {
                value: packet,
                next,
            }) => (packet, next.len()),
            Err(error) => {
                error!(%addr, %error, "failed to read packet");
                return Err(error);
            }
        };

        let payload = packet.payload;
        match T::try_from(packet) {
            Ok(decoded) => Ok(Packeted { payload, decoded }),
            Err(error) => {
                error!(%addr, %error, "failed to parse packet");
                Err(error)
            }
        }
    }
}

impl Default for ReadState {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(16_384),
        }
    }
}

struct Packeted<'a, T: 'a> {
    #[expect(dead_code)]
    payload: &'a [u8],
    decoded: T,
}

impl<'a, T> Packeted<'a, T> {
    fn into_inner(self) -> T {
        self.decoded
    }
}

impl<T> Deref for Packeted<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.decoded
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
        exchange: &mut digest::Context,
        conn: &mut Connection,
    ) -> Result<KeyExchange, ()> {
        let (ident, rest) =
            match read::<Identification<'_>>(&mut conn.stream, &mut conn.read.buf).await {
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

        let v_c_len = conn.read.buf.len() - rest - 2;
        if let Some(v_c) = conn.read.buf.get(..v_c_len) {
            exchange.update(&(v_c.len() as u32).to_be_bytes());
            exchange.update(v_c);
        }

        let ident = Identification::outgoing();
        ident.encode(&mut conn.write_buf);
        if let Err(error) = conn.stream.write_all(&conn.write_buf).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        let v_s_len = conn.write_buf.len() - 2;
        if let Some(v_s) = conn.write_buf.get(..v_s_len) {
            exchange.update(&(v_s.len() as u32).to_be_bytes());
            exchange.update(v_s);
        }

        if rest > 0 {
            let start = conn.read.buf.len() - rest;
            conn.read.buf.copy_within(start.., 0);
        }
        conn.read.buf.truncate(rest);

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
