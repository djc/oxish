use std::str;

use aws_lc_rs::{
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    digest,
    rand::{self, SystemRandom},
    signature::KeyPair,
};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, warn};

use crate::{
    proto::{read, with_mpint_bytes, Decode, Decoded, Encode, MessageType, Packet},
    Connection, Error,
};

pub(crate) struct EcdhKeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<digest::Digest>,
}

impl EcdhKeyExchange {
    pub(crate) async fn advance(
        self,
        mut exchange: digest::Context,
        conn: &mut Connection,
    ) -> Result<(), ()> {
        let (packet, _rest) = match read::<Packet<'_>>(&mut conn.stream, &mut conn.read_buf).await {
            Ok(Decoded {
                value: packet,
                next,
            }) => (packet, next.len()),
            Err(error) => {
                warn!(addr = %conn.addr, %error, "failed to read packet");
                return Err(());
            }
        };

        let ecdh_key_exchange_init = match EcdhKeyExchangeInit::try_from(packet) {
            Ok(ecdh_key_exchange_init) => {
                debug!(addr = %conn.addr, "received ECDH key exchange start");
                ecdh_key_exchange_init
            }
            Err(error) => {
                warn!(addr = %conn.addr, %error, "failed to read ECDH key exchange start");
                return Err(());
            }
        };

        // Write the server's public host key (`K_S`) to the exchange hash

        let mut host_key_buf = Vec::with_capacity(128);
        TaggedPublicKey {
            algorithm: PublicKeyAlgorithm::Ed25519,
            key: conn.host_key.public_key().as_ref(),
        }
        .encode(&mut host_key_buf);
        exchange.update(&host_key_buf);

        // Write the client's ephemeral public key (`Q_C`) to the exchange hash

        exchange.update(
            &(ecdh_key_exchange_init.client_ephemeral_public_key.len() as u32).to_be_bytes(),
        );
        exchange.update(ecdh_key_exchange_init.client_ephemeral_public_key);

        let random = SystemRandom::new();
        let Ok(kx_private_key) = EphemeralPrivateKey::generate(&X25519, &random) else {
            warn!(addr = %conn.addr, "failed to generate key exchange private key");
            return Err(());
        };

        let Ok(kx_public_key) = kx_private_key.compute_public_key() else {
            warn!(addr = %conn.addr, "failed to compute key exchange public key");
            return Err(());
        };

        let client_kx_public_key =
            UnparsedPublicKey::new(&X25519, ecdh_key_exchange_init.client_ephemeral_public_key);

        exchange.update(&(kx_public_key.as_ref().len() as u32).to_be_bytes());
        exchange.update(kx_public_key.as_ref());
        let Ok(shared_secret) = agreement::agree_ephemeral(
            kx_private_key,
            client_kx_public_key,
            aws_lc_rs::error::Unspecified,
            |shared_secret| Ok(shared_secret.to_vec()),
        ) else {
            warn!(addr = %conn.addr, "key exchange failed");
            return Err(());
        };

        with_mpint_bytes(&shared_secret, |bytes| exchange.update(bytes));

        let exchange_hash = exchange.finish();
        let signature = conn.host_key.sign(exchange_hash.as_ref());
        let key_exchange_reply = EcdhKeyExchangeReply {
            server_public_host_key: TaggedPublicKey {
                algorithm: PublicKeyAlgorithm::Ed25519,
                key: conn.host_key.public_key().as_ref(),
            },
            server_ephemeral_public_key: kx_public_key.as_ref(),
            exchange_hash_signature: TaggedSignature {
                algorithm: PublicKeyAlgorithm::Ed25519,
                signature: signature.as_ref(),
            },
        };

        conn.write_buf.clear();
        let Ok(packet) = Packet::builder(&mut conn.write_buf)
            .with_payload(&key_exchange_reply)
            .without_mac()
        else {
            error!(addr = %conn.addr, "failed to build key exchange init packet");
            return Err(());
        };

        if let Err(error) = conn.stream.write_all(packet).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        // FIXME wait for and send newkey packet

        // The first exchange hash is used as session id.
        let session_id = self.session_id.as_ref().unwrap_or(&exchange_hash);

        RawKeySet::derive(shared_secret, exchange_hash, session_id);

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct EcdhKeyExchangeInit<'a> {
    /// Also known as `Q_C` (<https://www.rfc-editor.org/rfc/rfc5656#section-4>)
    client_ephemeral_public_key: &'a [u8],
}

impl<'a> TryFrom<Packet<'a>> for EcdhKeyExchangeInit<'a> {
    type Error = Error;

    fn try_from(packet: Packet<'a>) -> Result<Self, Error> {
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

        Ok(Self {
            client_ephemeral_public_key,
        })
    }
}

#[derive(Debug)]
pub(crate) struct EcdhKeyExchangeReply<'a> {
    server_public_host_key: TaggedPublicKey<'a>,
    server_ephemeral_public_key: &'a [u8],
    exchange_hash_signature: TaggedSignature<'a>,
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
struct TaggedPublicKey<'a> {
    algorithm: PublicKeyAlgorithm<'a>,
    key: &'a [u8],
}

impl Encode for TaggedPublicKey<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend([0; 4]);
        self.algorithm.as_str().as_bytes().encode(buf);
        self.key.encode(buf);
        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

#[derive(Debug)]
struct TaggedSignature<'a> {
    algorithm: PublicKeyAlgorithm<'a>,
    signature: &'a [u8],
}

impl Encode for TaggedSignature<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend([0; 4]);
        self.algorithm.as_str().as_bytes().encode(buf);
        self.signature.encode(buf);
        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

#[derive(Debug)]
pub(crate) struct KeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<digest::Digest>,
}

impl KeyExchange {
    pub(crate) fn for_new_session() -> Self {
        Self { session_id: None }
    }

    pub(crate) async fn advance(
        self,
        exchange: &mut digest::Context,
        conn: &mut Connection,
    ) -> Result<EcdhKeyExchange, ()> {
        let (packet, rest) = match read::<Packet<'_>>(&mut conn.stream, &mut conn.read_buf).await {
            Ok(Decoded {
                value: packet,
                next,
            }) => (packet, next.len()),
            Err(error) => {
                warn!(addr = %conn.addr, %error, "failed to read packet");
                return Err(());
            }
        };

        exchange.update(&(packet.payload.len() as u32).to_be_bytes());
        exchange.update(packet.payload);

        let peer_key_exchange_init = match KeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                warn!(addr = %conn.addr, %error, "failed to read key exchange init");
                return Err(());
            }
        };

        let key_exchange_init = match KeyExchangeInit::new() {
            Ok(kex_init) => kex_init,
            Err(error) => {
                error!(addr = %conn.addr, %error, "failed to create key exchange init");
                return Err(());
            }
        };

        conn.write_buf.clear();
        let builder = Packet::builder(&mut conn.write_buf).with_payload(&key_exchange_init);

        if let Ok(kex_init_payload) = builder.payload() {
            exchange.update(&(kex_init_payload.len() as u32).to_be_bytes());
            exchange.update(kex_init_payload);
        };

        let Ok(packet) = builder.without_mac() else {
            error!(addr = %conn.addr, "failed to build key exchange init packet");
            return Err(());
        };

        if let Err(error) = conn.stream.write_all(packet).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

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

        Ok(EcdhKeyExchange {
            session_id: self.session_id,
        })
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

impl<'a> TryFrom<Packet<'a>> for KeyExchangeInit<'a> {
    type Error = Error;

    fn try_from(packet: Packet<'a>) -> Result<Self, Self::Error> {
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

        Ok(value)
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

/// The raw hashes from which we will derive the crypto keys.
#[expect(dead_code)] // FIXME implement encryption/decryption and MAC
struct RawKeySet {
    client_to_server: RawKeys,
    server_to_client: RawKeys,
}

impl RawKeySet {
    fn derive(
        shared_secret: Vec<u8>,
        exchange_hash: digest::Digest,
        session_id: &digest::Digest,
    ) -> Self {
        let compute_key = |key: &str| {
            let mut context = digest::Context::new(&digest::SHA256);
            with_mpint_bytes(&shared_secret, |bytes| context.update(bytes));
            context.update(exchange_hash.as_ref());
            context.update(key.as_bytes());
            context.update(session_id.as_ref());
            context.finish()
        };

        Self {
            client_to_server: RawKeys {
                initial_iv: compute_key("A"),
                encryption_key: compute_key("C"),
                integrity_key: compute_key("E"),
            },
            server_to_client: RawKeys {
                initial_iv: compute_key("B"),
                encryption_key: compute_key("D"),
                integrity_key: compute_key("F"),
            },
        }
    }
}

#[expect(dead_code)] // FIXME implement encryption/decryption and MAC
struct RawKeys {
    initial_iv: digest::Digest,
    encryption_key: digest::Digest,
    integrity_key: digest::Digest,
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

impl<'a> PublicKeyAlgorithm<'a> {
    fn as_str(&self) -> &'a str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::Unknown(name) => name,
        }
    }
}

impl Encode for PublicKeyAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_str().as_bytes());
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
