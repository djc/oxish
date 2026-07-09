use core::fmt;
use std::borrow::Cow;

use tracing::debug;

use crate::{
    crypto::{
        CryptoError, CryptoProvider, Digest, HandshakeHash, KeyDerivation, KeySourceSide,
        SigningKey,
    },
    named::{
        CompressionAlgorithm, EncryptionAlgorithm, ExtensionId, IncomingNameList,
        KeyExchangeAlgorithmOrExtensionId, Language, MacAlgorithm, OutgoingNameList,
    },
    Decode, Decoded, Encode, IncomingPacket, KeyExchangeAlgorithm, MessageType, ProtoError,
    PublicKeyAlgorithm,
};

pub struct EcdhKeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<Digest>,
    /// The negotiated key exchange algorithm, which also determines the hash.
    key_exchange: KeyExchangeAlgorithm<'static>,
}

impl EcdhKeyExchange {
    pub fn advance(
        self,
        ecdh_key_exchange_init: EcdhKeyExchangeInit<'_>,
        mut exchange: HandshakeHash,
        host_key: &dyn SigningKey,
        provider: &dyn CryptoProvider,
    ) -> Result<(EcdhKeyExchangeReply, Digest, KeySourceSet), CryptoError> {
        // Write the server's public host key (`K_S`) to the exchange hash

        let mut host_key_buf = Vec::with_capacity(128);
        TaggedPublicKey {
            algorithm: host_key.algorithm(),
            key: Cow::Owned(host_key.public_key().to_owned()),
        }
        .encode(&mut host_key_buf);
        exchange.update(&host_key_buf);

        // Write the client's ephemeral public key (`Q_C`) to the exchange hash

        exchange.prefixed(ecdh_key_exchange_init.client_ephemeral_public_key);

        let key_exchange = provider.key_exchange(&self.key_exchange)?;
        let kx = key_exchange.start()?;
        let completed = kx.complete(ecdh_key_exchange_init.client_ephemeral_public_key)?;

        // Write the server's reply public value (`Q_S` / `S_REPLY`) to the exchange hash
        exchange.prefixed(&completed.public_key);
        let secret_bytes = completed.shared_secret.secret_bytes();
        let mut shared_secret = Vec::with_capacity(secret_bytes.len() + 4);
        secret_bytes.encode(&mut shared_secret);
        exchange.update(&shared_secret);

        let exchange_hash = exchange.finish();
        let signature = host_key.sign(exchange_hash.as_ref());
        let key_exchange_reply = EcdhKeyExchangeReply {
            server_public_host_key: TaggedPublicKey {
                algorithm: host_key.algorithm(),
                key: Cow::Owned(host_key.public_key().to_owned()),
            },
            server_ephemeral_public_key: completed.public_key,
            exchange_hash_signature: TaggedSignature {
                algorithm: host_key.algorithm(),
                signature,
            },
        };

        // The first exchange hash is used as session id.
        let session_id = self.session_id.unwrap_or(exchange_hash);
        let derivation = KeyDerivation {
            hash: provider.hash(&self.key_exchange)?,
            shared_secret,
            exchange_hash,
            session_id,
        };

        Ok((
            key_exchange_reply,
            session_id,
            KeySourceSet {
                client_to_server: KeySourceSide::client_to_server(&derivation),
                server_to_client: KeySourceSide::server_to_client(&derivation),
            },
        ))
    }
}

#[derive(Debug, Default)]
pub struct KeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<Digest>,
}

impl KeyExchange {
    pub fn advance<'out>(
        self,
        peer_key_exchange_init: KeyExchangeInit<'_>,
        extensions: impl Iterator<Item = ExtensionId<'static>>,
        provider: &dyn CryptoProvider,
    ) -> Result<(KeyExchangeInit<'out>, EcdhKeyExchange), ProtoError> {
        let mut cookie = [0; 16];
        provider.secure_random().fill(&mut cookie)?;
        let key_exchange_init = KeyExchangeInit::new(cookie, extensions)?;

        let algorithms = Algorithms::choose(peer_key_exchange_init, &key_exchange_init)?;
        if algorithms.key_exchange != KeyExchangeAlgorithm::Mlkem768X25519Sha256 {
            return Err(CryptoError::UnknownAlgorithm.into());
        }

        Ok((
            key_exchange_init,
            EcdhKeyExchange {
                session_id: self.session_id,
                key_exchange: algorithms.key_exchange,
            },
        ))
    }
}

#[derive(Debug)]
pub struct KeyExchangeInit<'a> {
    cookie: [u8; 16],
    pub(crate) key_exchange_algorithms: Vec<KeyExchangeAlgorithmOrExtensionId<'a>>,
    pub(crate) server_host_key_algorithms: Vec<PublicKeyAlgorithm<'a>>,
    pub(crate) encryption_algorithms_client_to_server: Vec<EncryptionAlgorithm<'a>>,
    pub(crate) encryption_algorithms_server_to_client: Vec<EncryptionAlgorithm<'a>>,
    pub(crate) mac_algorithms_client_to_server: Vec<MacAlgorithm<'a>>,
    pub(crate) mac_algorithms_server_to_client: Vec<MacAlgorithm<'a>>,
    pub(crate) compression_algorithms_client_to_server: Vec<CompressionAlgorithm<'a>>,
    pub(crate) compression_algorithms_server_to_client: Vec<CompressionAlgorithm<'a>>,
    pub(crate) languages_client_to_server: Vec<Language<'a>>,
    pub(crate) languages_server_to_client: Vec<Language<'a>>,
    first_kex_packet_follows: bool,
    extended: u32,
}

impl KeyExchangeInit<'static> {
    pub fn new(
        cookie: [u8; 16],
        extensions: impl Iterator<Item = ExtensionId<'static>>,
    ) -> Result<Self, ProtoError> {
        let mut key_exchange_algorithms = vec![KeyExchangeAlgorithmOrExtensionId::KeyExchange(
            KeyExchangeAlgorithm::Mlkem768X25519Sha256,
        )];

        key_exchange_algorithms
            .extend(extensions.map(KeyExchangeAlgorithmOrExtensionId::Extension));

        Ok(Self {
            cookie,
            key_exchange_algorithms,
            server_host_key_algorithms: vec![PublicKeyAlgorithm::Ed25519],
            encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::Aes128Gcm],
            encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::Aes128Gcm],
            mac_algorithms_client_to_server: vec![MacAlgorithm::None],
            mac_algorithms_server_to_client: vec![MacAlgorithm::None],
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::None],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::None],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            extended: 0,
        })
    }
}

impl<'a> KeyExchangeInit<'a> {
    pub fn has_extension(&self, extension: ExtensionId<'_>) -> bool {
        self.key_exchange_algorithms
            .iter()
            .any(|alg| matches!(alg, KeyExchangeAlgorithmOrExtensionId::Extension(ext) if *ext == extension))
    }
}

impl<'a> TryFrom<IncomingPacket<'a>> for KeyExchangeInit<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::KeyExchangeInit {
            return Err(ProtoError::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: cookie,
            next,
        } = <[u8; 16]>::decode(packet.payload)?;

        let Decoded {
            value: key_exchange_algorithms,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: server_host_key_algorithms,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: encryption_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: encryption_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: mac_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: mac_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: compression_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: compression_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: languages_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: languages_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

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
            key_exchange_algorithms: key_exchange_algorithms.0,
            server_host_key_algorithms: server_host_key_algorithms.0,
            encryption_algorithms_client_to_server: encryption_algorithms_client_to_server.0,
            encryption_algorithms_server_to_client: encryption_algorithms_server_to_client.0,
            mac_algorithms_client_to_server: mac_algorithms_client_to_server.0,
            mac_algorithms_server_to_client: mac_algorithms_server_to_client.0,
            compression_algorithms_client_to_server: compression_algorithms_client_to_server.0,
            compression_algorithms_server_to_client: compression_algorithms_server_to_client.0,
            languages_client_to_server: languages_client_to_server.0,
            languages_server_to_client: languages_server_to_client.0,
            first_kex_packet_follows: first_kex_packet_follows != 0,
            extended,
        };

        if !next.is_empty() {
            debug!(bytes = ?next, "unexpected trailing bytes");
            return Err(ProtoError::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(value)
    }
}

impl Encode for KeyExchangeInit<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::KeyExchangeInit.encode(buf);
        buf.extend_from_slice(&self.cookie);
        OutgoingNameList(&self.key_exchange_algorithms).encode(buf);
        OutgoingNameList(&self.server_host_key_algorithms).encode(buf);
        OutgoingNameList(&self.encryption_algorithms_client_to_server).encode(buf);
        OutgoingNameList(&self.encryption_algorithms_server_to_client).encode(buf);
        OutgoingNameList(&self.mac_algorithms_client_to_server).encode(buf);
        OutgoingNameList(&self.mac_algorithms_server_to_client).encode(buf);
        OutgoingNameList(&self.compression_algorithms_client_to_server).encode(buf);
        OutgoingNameList(&self.compression_algorithms_server_to_client).encode(buf);
        OutgoingNameList(&self.languages_client_to_server).encode(buf);
        OutgoingNameList(&self.languages_server_to_client).encode(buf);
        buf.push(if self.first_kex_packet_follows { 1 } else { 0 });
        buf.extend_from_slice(&self.extended.to_be_bytes());
    }
}

#[derive(Debug)]
pub struct EcdhKeyExchangeInit<'a> {
    /// Also known as `Q_C` (<https://www.rfc-editor.org/rfc/rfc5656#section-4>)
    client_ephemeral_public_key: &'a [u8],
}

impl<'a> TryFrom<IncomingPacket<'a>> for EcdhKeyExchangeInit<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::KeyExchangeEcdhInit {
            return Err(ProtoError::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: client_ephemeral_public_key,
            next,
        } = <&[u8]>::decode(packet.payload)?;

        if !next.is_empty() {
            debug!(bytes = ?next, "unexpected trailing bytes");
            return Err(ProtoError::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Self {
            client_ephemeral_public_key,
        })
    }
}

#[derive(Debug)]
pub struct EcdhKeyExchangeReply {
    server_public_host_key: TaggedPublicKey<'static>,
    server_ephemeral_public_key: Vec<u8>,
    exchange_hash_signature: TaggedSignature<'static>,
}

impl Encode for EcdhKeyExchangeReply {
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
    key: Cow<'a, [u8]>,
}

impl Encode for TaggedPublicKey<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend([0; 4]);
        self.algorithm.encode(buf);
        self.key.encode(buf);
        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

struct TaggedSignature<'a> {
    algorithm: PublicKeyAlgorithm<'a>,
    signature: Vec<u8>,
}

impl Encode for TaggedSignature<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend([0; 4]);
        self.algorithm.encode(buf);
        self.signature.as_slice().encode(buf);
        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

impl fmt::Debug for TaggedSignature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaggedSignature")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Algorithms {
    key_exchange: KeyExchangeAlgorithm<'static>,
}

impl Algorithms {
    fn choose(
        client: KeyExchangeInit<'_>,
        server: &KeyExchangeInit<'static>,
    ) -> Result<Self, ProtoError> {
        let key_exchange = client
            .key_exchange_algorithms
            .iter()
            .find_map(|&client| {
                server
                    .key_exchange_algorithms
                    .iter()
                    .find_map(|&server_alg| match (client, server_alg) {
                        (
                            KeyExchangeAlgorithmOrExtensionId::KeyExchange(client_alg),
                            KeyExchangeAlgorithmOrExtensionId::KeyExchange(server_alg),
                        ) if client_alg == server_alg => Some(server_alg),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm("key exchange"))?;

        Ok(Self { key_exchange })
    }
}

/// The raw hashes from which we will derive the crypto keys.
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-7.2>
pub struct KeySourceSet {
    pub client_to_server: KeySourceSide,
    pub server_to_client: KeySourceSide,
}
