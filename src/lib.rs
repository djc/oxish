use std::{io, net::SocketAddr, str};

use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{debug, error, warn};

mod key_exchange;
use key_exchange::{
    Algorithms, EcdhKeyExchange, KeyExchange, KeyExchangeAlgorithm, KeyExchangeInit,
};
mod proto;
use proto::{Decode, Decoded, Encode, Packet, StreamState};

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
        let ident = Identification::outgoing();
        ident.encode(&mut self.write_buf);
        if let Err(error) = self.stream.write_all(&self.write_buf).await {
            warn!(addr = %self.addr, %error, "failed to send version exchange");
            return;
        }
        self.write_buf.clear();

        let state = VersionExchange;
        let (ident, rest) = match state.read(&mut self.stream, &mut self.read_buf).await {
            Ok((ident, rest)) => {
                debug!(addr = %self.addr, ?ident, "received identification");
                (ident, rest)
            }
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read version exchange");
                return;
            }
        };

        if ident.protocol != PROTOCOL {
            warn!(addr = %self.addr, ?ident, "unsupported protocol version");
            return;
        }

        if rest > 0 {
            let start = self.read_buf.len() - rest;
            self.read_buf.copy_within(start.., 0);
        }
        self.read_buf.truncate(rest);

        let state = KeyExchange;
        let key_exchange_init = match KeyExchangeInit::new() {
            Ok(kex_init) => kex_init,
            Err(error) => {
                error!(addr = %self.addr, %error, "failed to create key exchange init");
                return;
            }
        };

        if let Err(error) = Packet::encode(&key_exchange_init, &mut self.write_buf) {
            warn!(addr = %self.addr, %error, "failed to encode key exchange init");
            return;
        }

        if let Err(error) = self.stream.write_all(&self.write_buf).await {
            warn!(addr = %self.addr, %error, "failed to send version exchange");
            return;
        }
        self.write_buf.clear();

        let (peer_key_exchange_init, rest) =
            match state.read(&mut self.stream, &mut self.read_buf).await {
                Ok((key_exchange_init, rest)) => {
                    debug!(addr = %self.addr, "received key exchange init");
                    (key_exchange_init, rest)
                }
                Err(error) => {
                    warn!(addr = %self.addr, %error, "failed to read key exchange init");
                    return;
                }
            };

        let algorithms = match Algorithms::choose(peer_key_exchange_init, key_exchange_init) {
            Ok(algorithms) => {
                debug!(addr = %self.addr, ?algorithms, "chosen algorithms");
                algorithms
            }
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to choose algorithms");
                return;
            }
        };

        if algorithms.key_exchange != KeyExchangeAlgorithm::Curve25519Sha256 {
            warn!(addr = %self.addr, algorithm = ?algorithms.key_exchange, "unsupported key exchange algorithm");
            return;
        }

        if rest > 0 {
            let start = self.read_buf.len() - rest;
            self.read_buf.copy_within(start.., 0);
        }
        self.read_buf.truncate(rest);

        let state = EcdhKeyExchange;
        let (_ecdh_key_exchange_start, _rest) =
            match state.read(&mut self.stream, &mut self.read_buf).await {
                Ok((ecdh_key_exchange_start, rest)) => {
                    debug!(addr = %self.addr, "received ECDH key exchange start");
                    dbg!(&ecdh_key_exchange_start);
                    (ecdh_key_exchange_start, rest)
                }
                Err(error) => {
                    warn!(addr = %self.addr, %error, "failed to read ECDH key exchange start");
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
