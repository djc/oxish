use std::str;

use aws_lc_rs::rand;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, warn};

use crate::{
    proto::{Decode, Decoded, Encode, MessageType, Packet, StreamState},
    Connection, Error,
};

pub(crate) struct EcdhKeyExchange(());

impl EcdhKeyExchange {
    pub(crate) async fn advance(&self, conn: &mut Connection) -> Result<(), ()> {
        let (_ecdh_key_exchange_start, _rest) =
            match self.read(&mut conn.stream, &mut conn.read_buf).await {
                Ok((ecdh_key_exchange_start, rest)) => {
                    debug!(addr = %conn.addr, "received ECDH key exchange start");
                    (ecdh_key_exchange_start, rest)
                }
                Err(error) => {
                    warn!(addr = %conn.addr, %error, "failed to read ECDH key exchange start");
                    return Err(());
                }
            };

        Ok(())
    }
}

impl<'a> StreamState<'a> for EcdhKeyExchange {
    type Input = EcdhKeyExchangeReply<'a>;
    type Output = EcdhKeyExchangeInit<'a>;
}

#[derive(Debug)]
pub(crate) struct EcdhKeyExchangeInit<'a> {
    /// Also known as `Q_C` (<https://www.rfc-editor.org/rfc/rfc5656#section-4>)
    #[allow(dead_code)]
    client_ephemeral_public_key: &'a [u8],
}

impl<'a> Decode<'a> for EcdhKeyExchangeInit<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded {
            value: packet,
            next: next_packet,
        } = Packet::decode(bytes)?;

        let Decoded {
            value: r#type,
            next,
        } = MessageType::decode(packet.payload)?;
        if r#type != MessageType::KeyExchangeEcdhInit {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: client_ephemeral_public_key,
            next,
        } = <&[u8]>::decode(next)?;

        if !next.is_empty() {
            debug!(bytes = ?next, "unexpected trailing bytes");
            return Err(Error::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Decoded {
            value: Self {
                client_ephemeral_public_key,
            },
            next: next_packet,
        })
    }
}

#[derive(Debug)]
pub(crate) struct EcdhKeyExchangeReply<'a> {
    server_public_host_key: &'a [u8],
    server_ephemeral_public_key: &'a [u8],
    exchange_hash_signature: &'a [u8],
}

impl Encode for EcdhKeyExchangeReply<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::KeyExchangeEcdhReply.encode(buf);
        self.server_public_host_key.encode(buf);
        self.server_ephemeral_public_key.encode(buf);
        self.exchange_hash_signature.encode(buf);
    }
}

#[derive(Debug)]
struct Algorithms {
    key_exchange: KeyExchangeAlgorithm<'static>,
}

impl Algorithms {
    fn choose(
        client: KeyExchangeInit<'_>,
        server: KeyExchangeInit<'static>,
    ) -> Result<Self, Error> {
        let key_exchange = client
            .key_exchange_algorithms
            .iter()
            .find_map(|&client| {
                server
                    .key_exchange_algorithms
                    .iter()
                    .find(|&&server_alg| server_alg == client)
            })
            .ok_or(Error::NoCommonAlgorithm("key exchange"))?;

        Ok(Self {
            key_exchange: *key_exchange,
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct KeyExchange(());

impl KeyExchange {
    pub(crate) async fn advance(&self, conn: &mut Connection) -> Result<EcdhKeyExchange, ()> {
        let key_exchange_init = match KeyExchangeInit::new() {
            Ok(kex_init) => kex_init,
            Err(error) => {
                error!(addr = %conn.addr, %error, "failed to create key exchange init");
                return Err(());
            }
        };

        conn.write_buf.clear();
        if let Err(error) = Packet::encode(&key_exchange_init, &mut conn.write_buf) {
            warn!(addr = %conn.addr, %error, "failed to encode key exchange init");
            return Err(());
        }

        if let Err(error) = conn.stream.write_all(&conn.write_buf).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        let (peer_key_exchange_init, rest) =
            match self.read(&mut conn.stream, &mut conn.read_buf).await {
                Ok((key_exchange_init, rest)) => {
                    debug!(addr = %conn.addr, "received key exchange init");
                    (key_exchange_init, rest)
                }
                Err(error) => {
                    warn!(addr = %conn.addr, %error, "failed to read key exchange init");
                    return Err(());
                }
            };

        let algorithms = match Algorithms::choose(peer_key_exchange_init, key_exchange_init) {
            Ok(algorithms) => {
                debug!(addr = %conn.addr, ?algorithms, "chosen algorithms");
                algorithms
            }
            Err(error) => {
                warn!(addr = %conn.addr, %error, "failed to choose algorithms");
                return Err(());
            }
        };

        if algorithms.key_exchange != KeyExchangeAlgorithm::Curve25519Sha256 {
            warn!(addr = %conn.addr, algorithm = ?algorithms.key_exchange, "unsupported key exchange algorithm");
            return Err(());
        }

        if rest > 0 {
            let start = conn.read_buf.len() - rest;
            conn.read_buf.copy_within(start.., 0);
        }
        conn.read_buf.truncate(rest);

        Ok(EcdhKeyExchange(()))
    }
}

impl<'a> StreamState<'a> for KeyExchange {
    type Input = KeyExchangeInit<'a>;
    type Output = KeyExchangeInit<'a>;
}

#[derive(Debug)]
pub(crate) struct KeyExchangeInit<'a> {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicKeyAlgorithm<'a> {
    /// ssh-ed25519 (<https://www.rfc-editor.org/rfc/rfc8709>)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
