use std::{
    future::Future,
    io, iter,
    net::{Ipv4Addr, SocketAddr},
    str,
};

use aws_lc_rs::rand;
use clap::Parser;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, args.port));
    let listener = TcpListener::bind(addr).await?;
    debug!(%addr, "Listening for connections");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!(%addr, "Accepted connection");
                let conn = Connection::new(stream, addr)?;
                tokio::spawn(conn.run());
            }
            Err(error) => {
                warn!(%error, "Failed to accept connection");
                continue;
            }
        }
    }
}

struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
}

impl Connection {
    fn new(stream: TcpStream, addr: SocketAddr) -> anyhow::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self { stream, addr })
    }

    async fn run(self) {
        let Self { mut stream, addr } = self;
        let mut write_buf = Vec::with_capacity(16_384);
        let ident = Identification::outgoing();
        ident.encode(&mut write_buf);
        if let Err(error) = stream.write_all(&write_buf).await {
            warn!(%addr, %error, "Failed to send version exchange");
            return;
        }
        write_buf.clear();

        let state = VersionExchange;
        let mut read_buf = Vec::with_capacity(16_384);
        let (ident, rest) = match state.read(&mut stream, &mut read_buf).await {
            Ok((ident, rest)) => {
                debug!(%addr, ?ident, "Received identification");
                (ident, rest)
            }
            Err(error) => {
                warn!(%addr, %error, "Failed to read version exchange");
                return;
            }
        };

        if ident.protocol != PROTOCOL {
            warn!(%addr, ?ident, "Unsupported protocol version");
            return;
        }

        let start = read_buf.len() - rest;
        read_buf.copy_within(start.., 0);
        read_buf.truncate(rest);

        let state = KeyExchange;
        let kex_init = match KeyExchangeInit::new() {
            Ok(kex_init) => kex_init,
            Err(error) => {
                error!(%addr, %error, "failed to create key exchange init");
                return;
            }
        };

        if let Err(error) = Packet::encode(&kex_init, &mut write_buf) {
            error!(%addr, %error, "Failed to encode key exchange init");
            return;
        }

        if let Err(error) = stream.write_all(&write_buf).await {
            warn!(%addr, %error, "Failed to send version exchange");
            return;
        }
        write_buf.clear();

        let _key_exchange_init = match state.read(&mut stream, &mut read_buf).await {
            Ok(key_exchange_init) => {
                debug!(%addr, "Received key exchange init");
                dbg!(&key_exchange_init);
                key_exchange_init
            }
            Err(error) => {
                warn!(%addr, %error, "Failed to read key exchange init");
                return;
            }
        };

        todo!();
    }
}

struct KeyExchange;

impl<'a> StreamState<'a> for KeyExchange {
    type Input = KeyExchangeInit<'a>;
    type Output = KeyExchangeInit<'a>;
}

#[derive(Debug)]
struct KeyExchangeInit<'a> {
    cookie: [u8; 16],
    key_exchange_algorithms: Vec<KeyExchangeAlgorithm<'a>>,
    server_host_key_algorithms: Vec<PublicKeyAlgorithm<'a>>,
    encryption_algorithms_client_to_server: Vec<EncryptionAlgorithm<'a>>,
    encryption_algorithms_server_to_client: Vec<EncryptionAlgorithm<'a>>,
    mac_algorithms_client_to_server: Vec<MacAlgorithm<'a>>,
    mac_algorithms_server_to_client: Vec<MacAlgorithm<'a>>,
    compression_algorithms_client_to_server: Vec<CompressionAlgorithm<'a>>,
    compression_algorithms_server_to_client: Vec<CompressionAlgorithm<'a>>,
    languages_client_to_server: Vec<Language<'a>>,
    languages_server_to_client: Vec<Language<'a>>,
    first_kex_packet_follows: bool,
    extended: u32,
}

impl KeyExchangeInit<'static> {
    fn new() -> Result<Self, Error> {
        let mut cookie = [0; 16];
        if rand::fill(&mut cookie).is_err() {
            return Err(Error::FailedRandomBytes);
        };

        Ok(Self {
            cookie,
            key_exchange_algorithms: vec![KeyExchangeAlgorithm::Curve25519Sha256],
            server_host_key_algorithms: vec![PublicKeyAlgorithm::Ed25519],
            encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::Aes128Ctr],
            encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::Aes128Ctr],
            mac_algorithms_client_to_server: vec![MacAlgorithm::HmacSha2256],
            mac_algorithms_server_to_client: vec![MacAlgorithm::HmacSha2256],
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::None],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::None],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            extended: 0,
        })
    }
}

impl<'a> Decode<'a> for KeyExchangeInit<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded {
            value: packet,
            next: next_packet,
        } = Packet::decode(bytes)?;

        let Decoded {
            value: r#type,
            next,
        } = MessageType::decode(packet.payload)?;
        if r#type != MessageType::KeyExchangeInit {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: cookie,
            next,
        } = <[u8; 16]>::decode(next)?;

        let Decoded {
            value: key_exchange_algorithms,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: server_host_key_algorithms,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: encryption_algorithms_client_to_server,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: encryption_algorithms_server_to_client,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: mac_algorithms_client_to_server,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: mac_algorithms_server_to_client,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: compression_algorithms_client_to_server,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: compression_algorithms_server_to_client,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: languages_client_to_server,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: languages_server_to_client,
            next,
        } = Vec::decode(next)?;

        let Decoded {
            value: first_kex_packet_follows,
            next,
        } = u8::decode(next)?;

        let Decoded {
            value: extended,
            next,
        } = u32::decode(next)?;

        let value = Self {
            cookie,
            key_exchange_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows: first_kex_packet_follows != 0,
            extended,
        };

        if !next.is_empty() {
            debug!(bytes = ?next, "unexpected trailing bytes");
            return Err(Error::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Decoded {
            value,
            next: next_packet,
        })
    }
}

impl Encode for KeyExchangeInit<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::KeyExchangeInit.encode(buf);
        buf.extend_from_slice(&self.cookie);
        self.key_exchange_algorithms.encode(buf);
        self.server_host_key_algorithms.encode(buf);
        self.encryption_algorithms_client_to_server.encode(buf);
        self.encryption_algorithms_server_to_client.encode(buf);
        self.mac_algorithms_client_to_server.encode(buf);
        self.mac_algorithms_server_to_client.encode(buf);
        self.compression_algorithms_client_to_server.encode(buf);
        self.compression_algorithms_server_to_client.encode(buf);
        self.languages_client_to_server.encode(buf);
        self.languages_server_to_client.encode(buf);
        buf.push(if self.first_kex_packet_follows { 1 } else { 0 });
        buf.extend_from_slice(&self.extended.to_be_bytes());
    }
}

impl<T: Encode> Encode for [T] {
    fn encode(&self, buf: &mut Vec<u8>) {
        let offset = buf.len();
        buf.extend_from_slice(&[0, 0, 0, 0]);
        let mut first = true;
        for name in self {
            match first {
                true => first = false,
                false => buf.push(b','),
            }

            name.encode(buf);
        }

        let len = (buf.len() - offset - 4) as u32;
        if let Some(slice) = buf.get_mut(offset..offset + 4) {
            slice.copy_from_slice(&len.to_be_bytes());
        }
    }
}

impl<'a, T: From<&'a str>> Decode<'a> for Vec<T> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value: len, next } = u32::decode(bytes)?;

        let Some(list) = next.get(..len as usize) else {
            return Err(Error::Incomplete(Some(len as usize - next.len())));
        };

        let Some(next) = next.get(len as usize..) else {
            return Err(Error::Unreachable("unable to extract rest after name list"));
        };

        let mut value = Self::new();
        if list.is_empty() {
            return Ok(Decoded { value, next });
        }

        for name in list.split(|&b| b == b',') {
            match str::from_utf8(name) {
                Ok(name) => value.push(T::from(name)),
                Err(_) => return Err(Error::InvalidPacket("invalid name")),
            }
        }

        Ok(Decoded { value, next })
    }
}

#[derive(Debug)]
enum KeyExchangeAlgorithm<'a> {
    /// curve25519-sha256 (<https://www.rfc-editor.org/rfc/rfc8731>)
    Curve25519Sha256,
    Unknown(&'a str),
}

impl Encode for KeyExchangeAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Curve25519Sha256 => buf.extend_from_slice(b"curve25519-sha256"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for KeyExchangeAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "curve25519-sha256" => Self::Curve25519Sha256,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug)]
enum PublicKeyAlgorithm<'a> {
    /// sh-ed25519 (<https://www.rfc-editor.org/rfc/rfc8709>)
    Ed25519,
    Unknown(&'a str),
}

impl Encode for PublicKeyAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Ed25519 => buf.extend_from_slice(b"ssh-ed25519"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for PublicKeyAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "ssh-ed25519" => Self::Ed25519,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug)]
enum EncryptionAlgorithm<'a> {
    /// aes128-ctr (<https://www.rfc-editor.org/rfc/rfc4344#section-4>)
    Aes128Ctr,
    Unknown(&'a str),
}

impl Encode for EncryptionAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Aes128Ctr => buf.extend_from_slice(b"aes128-ctr"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for EncryptionAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "aes128-ctr" => Self::Aes128Ctr,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug)]
enum MacAlgorithm<'a> {
    /// hmac-sha2-256 (<https://www.rfc-editor.org/rfc/rfc6668#section-2>)
    HmacSha2256,
    Unknown(&'a str),
}

impl Encode for MacAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::HmacSha2256 => buf.extend_from_slice(b"hmac-sha2-256"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for MacAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "hmac-sha2-256" => Self::HmacSha2256,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug)]
enum CompressionAlgorithm<'a> {
    None,
    Unknown(&'a str),
}

impl Encode for CompressionAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::None => buf.extend_from_slice(b"none"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for CompressionAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "none" => Self::None,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug)]
enum Language<'a> {
    Unknown(&'a str),
}

impl Encode for Language<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for Language<'a> {
    fn from(value: &'a str) -> Self {
        Self::Unknown(value)
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

trait StreamState<'a> {
    type Input: Encode;
    type Output: Decode<'a>;

    fn read(
        &self,
        stream: &'a mut TcpStream,
        buf: &'a mut Vec<u8>,
    ) -> impl Future<Output = Result<(Self::Output, usize), Error>> + 'a {
        async move {
            let len = stream.read_buf(buf).await?;
            debug!(bytes = len, "read from stream");
            let decoded = Self::Output::decode(buf)?;
            Ok((decoded.value, decoded.next.len()))
        }
    }
}

trait Encode {
    fn encode(&self, buf: &mut Vec<u8>);
}

trait Decode<'a>: Sized {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error>;
}

struct Decoded<'a, T> {
    value: T,
    next: &'a [u8],
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageType {
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,
    KeyExchangeInit,
    NewKeys,
    Unknown(u8),
}

impl Encode for MessageType {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Disconnect => buf.push(1),
            Self::Ignore => buf.push(2),
            Self::Unimplemented => buf.push(3),
            Self::Debug => buf.push(4),
            Self::ServiceRequest => buf.push(5),
            Self::ServiceAccept => buf.push(6),
            Self::KeyExchangeInit => buf.push(20),
            Self::NewKeys => buf.push(21),
            Self::Unknown(value) => buf.push(*value),
        }
    }
}

impl<'a> Decode<'a> for MessageType {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = u8::decode(bytes)?;
        Ok(Decoded {
            value: Self::from(value),
            next,
        })
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Disconnect,
            2 => Self::Ignore,
            3 => Self::Unimplemented,
            4 => Self::Debug,
            5 => Self::ServiceRequest,
            6 => Self::ServiceAccept,
            20 => Self::KeyExchangeInit,
            21 => Self::NewKeys,
            value => Self::Unknown(value),
        }
    }
}

struct Packet<'a> {
    payload: &'a [u8],
}

impl Packet<'_> {
    fn encode(payload: &impl Encode, buf: &mut Vec<u8>) -> Result<(), Error> {
        // <https://www.rfc-editor.org/rfc/rfc4253#section-6>
        //
        // Note that the length of the concatenation of 'packet_length',
        // 'padding_length', 'payload', and 'random padding' MUST be a multiple
        // of the cipher block size or 8, whichever is larger.  This constraint
        // MUST be enforced, even when using stream ciphers.  Note that the
        // 'packet_length' field is also encrypted, and processing it requires
        // special care when sending or receiving packets.  Also note that the
        // insertion of variable amounts of 'random padding' may help thwart
        // traffic analysis.
        //
        // The minimum size of a packet is 16 (or the cipher block size,
        // whichever is larger) bytes (plus 'mac').  Implementations SHOULD
        // decrypt the length after receiving the first 8 (or cipher block size,
        // whichever is larger) bytes of a packet.

        let start = buf.len();
        buf.extend_from_slice(&[0, 0, 0, 0]); // packet_length
        buf.push(0); // padding_length

        payload.encode(buf); // payload

        let min_padding = 8 - (buf.len() - start) % 8;
        let padding_len = match min_padding < 4 {
            true => min_padding + 8,
            false => min_padding,
        };

        buf[4] = padding_len as u8;

        let padding_start = buf.len();
        buf.extend(iter::repeat(0).take(padding_len)); // padding
        if let Some(padding) = buf.get_mut(padding_start..) {
            if rand::fill(padding).is_err() {
                return Err(Error::Unreachable("failed to get random padding"));
            }
        }

        buf.extend_from_slice(&[]); // mac

        let packet_len = (buf.len() - start - 4) as u32;
        buf[start..start + 4].copy_from_slice(&packet_len.to_be_bytes());

        Ok(())
    }
}

impl<'a> Decode<'a> for Packet<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded {
            value: packet_length,
            next,
        } = PacketLength::decode(bytes)?;

        let Decoded {
            value: padding_length,
            next,
        } = PaddingLength::decode(next)?;

        let payload_len = (packet_length.inner - 1 - padding_length.inner as u32) as usize;
        let Some(payload) = next.get(..payload_len) else {
            return Err(Error::Incomplete(Some(payload_len - next.len())));
        };

        let Some(next) = next.get(payload_len..) else {
            return Err(Error::Unreachable(
                "unable to extract rest after fixed-length slice",
            ));
        };

        let Some(_) = next.get(..padding_length.inner as usize) else {
            return Err(Error::Incomplete(Some(
                padding_length.inner as usize - next.len(),
            )));
        };

        // No MAC support yet

        Ok(Decoded {
            value: Self { payload },
            next,
        })
    }
}

struct PacketLength {
    inner: u32,
}

impl Decode<'_> for PacketLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<Self>, Error> {
        let Decoded { value, next } = u32::decode(bytes)?;
        if value > 256 * 1024 {
            return Err(Error::InvalidPacket("packet too large"));
        }

        Ok(Decoded {
            value: Self { inner: value },
            next,
        })
    }
}

struct PaddingLength {
    inner: u8,
}

impl Decode<'_> for PaddingLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<Self>, Error> {
        let Decoded { value, next } = u8::decode(bytes)?;
        if value < 4 {
            return Err(Error::InvalidPacket("padding too short"));
        }

        Ok(Decoded {
            value: Self { inner: value },
            next,
        })
    }
}

impl Decode<'_> for u32 {
    fn decode(bytes: &[u8]) -> Result<Decoded<Self>, Error> {
        <[u8; 4]>::decode(bytes).map(|decoded| Decoded {
            value: Self::from_be_bytes(decoded.value),
            next: decoded.next,
        })
    }
}

impl<'a, const N: usize> Decode<'a> for [u8; N] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Some(inner) = bytes.get(..N) else {
            return Err(Error::Incomplete(Some(N - bytes.len())));
        };

        let Some(next) = bytes.get(N..) else {
            return Err(Error::Unreachable(
                "unable to extract rest after fixed-length slice",
            ));
        };

        let Ok(value) = <[u8; N]>::try_from(inner) else {
            return Err(Error::Unreachable("fixed-length slice converts to array"));
        };

        Ok(Decoded { value, next })
    }
}

impl<'a> Decode<'a> for u8 {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Some(&inner) = bytes.first() else {
            return Err(Error::Incomplete(Some(1)));
        };

        let Some(next) = bytes.get(1..) else {
            return Err(Error::Unreachable("unable to extract rest after u8"));
        };

        Ok(Decoded { value: inner, next })
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    port: u16,
}

const PROTOCOL: &str = "2.0";
const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
