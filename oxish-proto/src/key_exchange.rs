use core::fmt;
use std::borrow::Cow;

use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    Decode, Decoded, Encode, IncomingPacket, MessageType, Pretty, ProtoError, PublicKeyAlgorithm,
    crypto::{
        CryptoError, CryptoProvider, Digest, HandshakeBuffer, HandshakeHash, KeyDerivation,
        KeySourceSide, SharedSecret, SigningKey,
    },
    named::{
        CompressionAlgorithm, EncryptionAlgorithm, ExtensionId, ExtensionName, IncomingNameList,
        KeyExchangeAlgorithm, KeyExchangeAlgorithmOrExtensionId, Language, MacAlgorithm,
        OutgoingNameList,
    },
};

/// Output from the initial key exchange phase
pub struct KeyExchange {
    /// Our own `SSH_MSG_KEXINIT` message, to be sent to the peer
    pub local: KeyExchangeInit<'static>,
    /// The in-progress exchange hash computation
    pub exchange: HandshakeHash,
    /// The negotiated algorithms
    pub negotiated: Negotiated,
    /// Our `SSH_MSG_EXT_INFO` message, to be sent if the peer supports it
    pub ext_info: ExtInfo<'static>,
}

impl KeyExchange {
    /// Process the peer's `SSH_MSG_KEXINIT` and negotiate algorithms
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.1> for the negotiation procedure.
    pub fn start(
        packet: IncomingPacket<'_>,
        mut exchange: HandshakeBuffer,
        server_host_key_algorithms: Vec<PublicKeyAlgorithm<'static>>,
        extensions: impl Iterator<Item = ExtensionId<'static>>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, ProtoError> {
        exchange.update(&((packet.payload.len() + 1) as u32).to_be_bytes());
        exchange.update(&[u8::from(packet.message_type)]);
        exchange.update(packet.payload);

        let peer_key_exchange_init = KeyExchangeInit::try_from(packet)?;
        debug!(key_exchange_init = %Pretty(&peer_key_exchange_init), "received key exchange init");

        let mut cookie = [0; 16];
        provider.secure_random().fill(&mut cookie)?;
        let supported = provider.supported_algorithms();
        let mut key_exchange_algorithms = supported
            .key_exchange
            .iter()
            .map(|&alg| KeyExchangeAlgorithmOrExtensionId::KeyExchange(alg))
            .collect::<Vec<_>>();
        key_exchange_algorithms
            .extend(extensions.map(KeyExchangeAlgorithmOrExtensionId::Extension));

        let ext_info = ExtInfo {
            extensions: vec![(
                ExtensionName::ServerSigAlgs,
                Box::new(OutgoingNameList(supported.public_key)),
            )],
        };

        let local = KeyExchangeInit {
            cookie,
            key_exchange_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server: supported.encryption.to_owned(),
            encryption_algorithms_server_to_client: supported.encryption.to_owned(),
            mac_algorithms_client_to_server: supported.mac.to_owned(),
            mac_algorithms_server_to_client: supported.mac.to_owned(),
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::None],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::None],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            extended: 0,
        };

        let negotiated = Negotiated::choose(peer_key_exchange_init, &local)?;
        Ok(Self {
            local,
            exchange: exchange.hash(provider.hash(&negotiated.key_exchange)?),
            negotiated,
            ext_info,
        })
    }
}

/// The `SSH_MSG_KEXINIT` message
///
/// Lists the algorithms each side supports, in preference order
/// (<https://www.rfc-editor.org/rfc/rfc4253#section-7.1>).
#[derive(Debug)]
pub struct KeyExchangeInit<'a> {
    cookie: [u8; 16],
    key_exchange_algorithms: Vec<KeyExchangeAlgorithmOrExtensionId<'a>>,
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

impl<'a> KeyExchangeInit<'a> {
    fn has_extension(&self, extension: ExtensionId<'_>) -> bool {
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

/// The `SSH_MSG_KEX_ECDH_INIT` message
///
/// Carries the client's ephemeral public key (<https://www.rfc-editor.org/rfc/rfc5656#section-4>).
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

/// The `SSH_MSG_KEX_ECDH_REPLY` message
///
/// Carries the server's host key, its ephemeral public key and its signature over the exchange hash
/// (<https://www.rfc-editor.org/rfc/rfc5656#section-4>).
#[derive(Debug)]
pub struct EcdhKeyExchangeReply {
    server_public_host_key: TaggedPublicKey<'static>,
    server_ephemeral_public_key: Vec<u8>,
    exchange_hash_signature: TaggedSignature<'static>,
}

impl EcdhKeyExchangeReply {
    /// Complete the key exchange started by the client's `SSH_MSG_KEX_ECDH_INIT`
    ///
    /// Returns the reply message, the exchange hash and the derived key material
    /// (<https://www.rfc-editor.org/rfc/rfc4253#section-7.2>).
    pub fn new<'h>(
        ecdh_key_exchange_init: EcdhKeyExchangeInit<'_>,
        negotiated: &Negotiated,
        exchange: HandshakeHash,
        session_id: Option<Digest>,
        host_key: &ServerHostKey<'h>,
        provider: &dyn CryptoProvider,
    ) -> Result<(Self, Digest, KeySourceSet), CryptoError> {
        let KeyExchangeOutput {
            shared_secret,
            exchange_hash,
            reply: key_exchange_reply,
        } = host_key.sign(
            exchange,
            ecdh_key_exchange_init.client_ephemeral_public_key,
            negotiated,
            provider,
        )?;

        // The first exchange hash is used as session id.
        let derivation = KeyDerivation {
            hash: provider.hash(&negotiated.key_exchange)?,
            shared_secret,
            exchange_hash: exchange_hash.clone(),
            session_id: session_id.unwrap_or_else(|| exchange_hash.clone()),
        };

        Ok((
            key_exchange_reply,
            exchange_hash,
            KeySourceSet {
                client_to_server: KeySourceSide::client_to_server(
                    &derivation,
                    negotiated.encryption_client_to_server.clone(),
                )?,
                server_to_client: KeySourceSide::server_to_client(
                    &derivation,
                    negotiated.encryption_server_to_client.clone(),
                )?,
            },
        ))
    }
}

impl Encode for EcdhKeyExchangeReply {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::KeyExchangeEcdhReply.encode(buf);
        self.server_public_host_key.encode(buf);
        self.server_ephemeral_public_key.encode(buf);
        self.exchange_hash_signature.encode(buf);
    }
}

/// The server's host keys, used to authenticate the key exchange
#[expect(clippy::type_complexity)]
pub struct HostKeys(Vec<(Zeroizing<Vec<u8>>, Box<dyn SigningKey>)>);

impl HostKeys {
    /// Create a new set of host keys from the given PKCS#8 private keys
    ///
    /// `pkcs8` must have more than 0 and less than 16 elements.
    pub fn new(
        pkcs8: impl Iterator<Item = Zeroizing<Vec<u8>>>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, ProtoError> {
        let mut keys = Vec::new();
        for pkcs8 in pkcs8 {
            if keys.len() >= Self::MAX_KEYS {
                return Err(ProtoError::TooManyHostKeys);
            }

            let signing_key = provider.signing_key_from_pkcs8(&pkcs8)?;
            keys.push((pkcs8, signing_key));
        }

        if keys.is_empty() {
            return Err(ProtoError::NoHostKeys);
        }

        Ok(Self(keys))
    }

    /// Select the host key matching the negotiated algorithm
    pub fn key<'a>(&'a self, negotiated: &Negotiated) -> Result<ServerHostKey<'a>, CryptoError> {
        let mut iter = self.0.iter();
        match iter.find(|(_, key)| key.algorithm() == negotiated.server_host_key) {
            Some((pkcs8, key)) => Ok(ServerHostKey {
                pkcs8,
                key: key.as_ref(),
            }),
            None => Err(CryptoError::UnknownAlgorithm),
        }
    }

    /// The public key algorithms of the held host keys
    pub fn algorithms(&self) -> impl Iterator<Item = PublicKeyAlgorithm<'static>> + '_ {
        self.0.iter().map(|(_, key)| key.algorithm())
    }

    const MAX_KEYS: usize = 16;
}

/// A borrowed single host key, used to sign the key exchange output
pub struct ServerHostKey<'a> {
    pkcs8: &'a Zeroizing<Vec<u8>>,
    key: &'a dyn SigningKey,
}

impl ServerHostKey<'_> {
    fn sign(
        &self,
        exchange: HandshakeHash,
        client_ephemeral_public_key: &[u8],
        negotiated: &Negotiated,
        provider: &dyn CryptoProvider,
    ) -> Result<KeyExchangeOutput, CryptoError> {
        KeyExchangeOutput::new(
            exchange,
            client_ephemeral_public_key,
            negotiated,
            self.key,
            provider,
        )
    }
}

impl Encode for ServerHostKey<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.pkcs8.encode(buf);
    }
}

#[doc(hidden)] // for testing
impl<'a> From<(&'a Zeroizing<Vec<u8>>, &'a dyn SigningKey)> for ServerHostKey<'a> {
    fn from((pkcs8, key): (&'a Zeroizing<Vec<u8>>, &'a dyn SigningKey)) -> Self {
        Self { pkcs8, key }
    }
}

/// A single host key, used to sign rekeying exchanges
#[expect(dead_code)]
pub struct SessionHostKey(Box<dyn SigningKey>);

impl SessionHostKey {
    /// Decode a host key from encoded PKCS#8 bytes
    pub fn decode<'a>(
        buf: &'a [u8],
        provider: &dyn CryptoProvider,
    ) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: pkcs8, next } = <&[u8]>::decode(buf)?;
        Ok(Decoded {
            value: Self(provider.signing_key_from_pkcs8(pkcs8)?),
            next,
        })
    }
}

struct KeyExchangeOutput {
    shared_secret: SharedSecret,
    exchange_hash: Digest,
    reply: EcdhKeyExchangeReply,
}

impl KeyExchangeOutput {
    fn new(
        mut exchange: HandshakeHash,
        client_ephemeral_public_key: &[u8],
        negotiated: &Negotiated,
        host_key: &dyn SigningKey,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, CryptoError> {
        // Write the server's public host key (`K_S`) to the exchange hash

        let mut host_key_buf = Vec::with_capacity(128);
        TaggedPublicKey {
            algorithm: host_key.algorithm(),
            key: Cow::Owned(host_key.public_key().to_owned()),
        }
        .encode(&mut host_key_buf);
        exchange.update(&host_key_buf);

        // Write the client's ephemeral public key (`Q_C`) to the exchange hash

        exchange.prefixed(client_ephemeral_public_key);

        let key_exchange = provider.key_exchange(&negotiated.key_exchange)?;
        let kx = key_exchange.start()?;
        let completed = kx.complete(client_ephemeral_public_key)?;

        // Write the server's reply public value (`Q_S` / `S_REPLY`) to the exchange hash
        exchange.prefixed(&completed.public_key);
        let secret_bytes = completed.shared_secret.secret_bytes();
        let mut shared_secret = Vec::with_capacity(secret_bytes.len() + 4);
        secret_bytes.encode(&mut shared_secret);
        exchange.update(&shared_secret);

        let exchange_hash = exchange.finish();
        Ok(Self {
            shared_secret: SharedSecret::from(shared_secret),
            reply: EcdhKeyExchangeReply {
                server_public_host_key: TaggedPublicKey {
                    algorithm: host_key.algorithm(),
                    key: Cow::Owned(host_key.public_key().to_owned()),
                },
                server_ephemeral_public_key: completed.public_key,
                exchange_hash_signature: TaggedSignature {
                    algorithm: host_key.algorithm(),
                    signature: host_key.sign(exchange_hash.as_ref()),
                },
            },
            exchange_hash,
        })
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

        // RFC 5656 section 3.1: an ECDSA public key blob carries the curve
        // identifier between the algorithm name and the point `Q`.
        if matches!(self.algorithm, PublicKeyAlgorithm::EcdsaSha2Nistp256) {
            "nistp256".as_bytes().encode(buf);
        }

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

        match self.algorithm {
            // RFC 5656 section 3.1.2: the ECDSA signature blob is the pair of
            // integers `r` and `s`, each encoded as an mpint. The signing key
            // hands us the fixed-length `r || s` form, which we split in half.
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let blob_start = buf.len();
                buf.extend([0; 4]);
                let (r, s) = self.signature.split_at(self.signature.len() / 2);
                encode_mpint(r, buf);
                encode_mpint(s, buf);
                let blob_len = (buf.len() - blob_start - 4) as u32;
                if let Some(dst) = buf.get_mut(blob_start..blob_start + 4) {
                    dst.copy_from_slice(&blob_len.to_be_bytes());
                }
            }
            PublicKeyAlgorithm::Ed25519 => self.signature.as_slice().encode(buf),
            PublicKeyAlgorithm::Unknown(_) => {
                unreachable!("unknown algorithm should not be used for signing")
            }
        }

        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

/// Append `value` to `buf` as an SSH mpint (RFC 4251 section 5)
///
/// Leading zero bytes are stripped, and a single zero byte is prepended when the
/// most significant bit is set so the value is interpreted as positive.
fn encode_mpint(value: &[u8], buf: &mut Vec<u8>) {
    let trimmed = match value.iter().position(|&b| b != 0) {
        Some(first) => &value[first..],
        None => &[],
    };

    let pad = matches!(trimmed.first(), Some(&b) if b & 0x80 != 0);
    let len = trimmed.len() + usize::from(pad);
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    if pad {
        buf.push(0);
    }
    buf.extend_from_slice(trimmed);
}

impl fmt::Debug for TaggedSignature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaggedSignature")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// The algorithms negotiated from the client's and server's `SSH_MSG_KEXINIT`
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.1> for the negotiation procedure.
#[derive(Debug)]
pub struct Negotiated {
    key_exchange: KeyExchangeAlgorithm<'static>,
    server_host_key: PublicKeyAlgorithm<'static>,
    encryption_client_to_server: EncryptionAlgorithm<'static>,
    encryption_server_to_client: EncryptionAlgorithm<'static>,
    /// Whether the client requested `SSH_MSG_EXT_INFO` via `ext-info-c` (RFC 8308)
    pub want_extension_info: bool,
    /// Whether the client requested strict key exchange via `kex-strict-c-v00@openssh.com`
    pub strict_key_exchange: bool,
}

impl Negotiated {
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

        let server_host_key = client
            .server_host_key_algorithms
            .iter()
            .find_map(|client| {
                server
                    .server_host_key_algorithms
                    .iter()
                    .find_map(|server| match (client, server) {
                        (client, server) if client == server => Some(server.clone()),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm("host key"))?;

        let encryption_client_to_server = client
            .encryption_algorithms_client_to_server
            .iter()
            .find_map(|client| {
                server
                    .encryption_algorithms_client_to_server
                    .iter()
                    .find_map(|server| match (client, server) {
                        (client, server) if client == server => Some(server.clone()),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm(
                "encryption (client to server)",
            ))?;

        let encryption_server_to_client = client
            .encryption_algorithms_server_to_client
            .iter()
            .find_map(|client| {
                server
                    .encryption_algorithms_server_to_client
                    .iter()
                    .find_map(|server| match (client, server) {
                        (client, server) if client == server => Some(server.clone()),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm(
                "encryption (server to client)",
            ))?;

        Ok(Self {
            key_exchange,
            server_host_key,
            encryption_client_to_server,
            encryption_server_to_client,
            want_extension_info: client.has_extension(ExtensionId::ExtInfoC),
            strict_key_exchange: client.has_extension(ExtensionId::StrictKexClient),
        })
    }
}

/// The `SSH_MSG_NEWKEYS` message
///
/// Signals that all following packets use the newly negotiated keys and algorithms.
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.3>.
#[derive(Debug)]
pub struct NewKeys;

impl<'a> TryFrom<IncomingPacket<'a>> for NewKeys {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::NewKeys {
            return Err(ProtoError::InvalidPacket("unexpected message type"));
        }

        if !packet.payload.is_empty() {
            debug!(bytes = ?packet.payload, "unexpected trailing bytes");
            return Err(ProtoError::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Self)
    }
}

impl Encode for NewKeys {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::NewKeys.encode(buf);
    }
}

/// Identities from the connection's initial setup
///
/// Used to derive the session id and the exchange hash for rekeying.
#[derive(Debug)]
pub struct Identities {
    /// Client identity
    pub client: Vec<u8>,
    /// Server identity
    pub server: Vec<u8>,
}

impl Encode for Identities {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.client.encode(buf);
        self.server.encode(buf);
    }
}

impl Decode<'_> for Identities {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded {
            value: client,
            next,
        } = <&[u8]>::decode(bytes)?;
        let Decoded {
            value: server,
            next,
        } = <&[u8]>::decode(next)?;

        Ok(Decoded {
            value: Self {
                client: client.to_vec(),
                server: server.to_vec(),
            },
            next,
        })
    }
}

/// The `SSH_MSG_EXT_INFO` message
///
/// Carries protocol extensions such as `server-sig-algs`
///
/// See <https://www.rfc-editor.org/rfc/rfc8308#section-2.3>.
pub struct ExtInfo<'a> {
    extensions: Vec<(ExtensionName<'a>, Box<dyn Encode + 'a>)>,
}

impl Encode for ExtInfo<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::ExtInfo.encode(buf);
        (self.extensions.len() as u32).encode(buf);
        for (name, value) in &self.extensions {
            name.encode(buf);
            value.encode(buf);
        }
    }
}

/// The raw hashes from which we will derive the crypto keys.
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.2>.
pub struct KeySourceSet {
    /// Key material for the client-to-server direction
    pub client_to_server: KeySourceSide,
    /// Key material for the server-to-client direction
    pub server_to_client: KeySourceSide,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_string(bytes: &[u8]) -> (&[u8], &[u8]) {
        let Decoded { value, next } = <&[u8]>::decode(bytes).unwrap();
        (value, next)
    }

    #[test]
    fn mpint_encoding() {
        // Leading zero bytes are stripped.
        let mut buf = Vec::new();
        encode_mpint(&[0x00, 0x00, 0x05, 0x06], &mut buf);
        assert_eq!(buf, [0, 0, 0, 2, 0x05, 0x06]);

        // A set most significant bit forces a leading zero byte.
        buf.clear();
        encode_mpint(&[0x80, 0x01], &mut buf);
        assert_eq!(buf, [0, 0, 0, 3, 0x00, 0x80, 0x01]);

        // An all-zero value encodes as a zero-length mpint.
        buf.clear();
        encode_mpint(&[0x00, 0x00], &mut buf);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn ecdsa_signature_framing() {
        // `r` has its top bit set (needs padding); `s` has leading zeros (stripped).
        let mut signature = [0x11u8; 64];
        signature[0] = 0x80;
        signature[32] = 0x00;
        signature[33] = 0x00;
        signature[34] = 0x05;

        let tagged = TaggedSignature {
            algorithm: PublicKeyAlgorithm::EcdsaSha2Nistp256,
            signature: signature.to_vec(),
        };

        let mut buf = Vec::new();
        tagged.encode(&mut buf);

        // The whole thing is wrapped in a single string.
        let (inner, next) = decode_string(&buf);
        assert!(next.is_empty());

        let (name, next) = decode_string(inner);
        assert_eq!(name, b"ecdsa-sha2-nistp256");

        // RFC 5656 section 3.1.2: the signature blob is `mpint r || mpint s`.
        let (blob, next) = decode_string(next);
        assert!(next.is_empty());

        let (r, next) = decode_string(blob);
        let (s, next) = decode_string(next);
        assert!(next.is_empty());

        let mut expected_r = vec![0x00, 0x80];
        expected_r.extend([0x11; 31]);
        assert_eq!(r, expected_r);

        let mut expected_s = vec![0x05];
        expected_s.extend([0x11; 29]);
        assert_eq!(s, expected_s);
    }

    #[test]
    fn ecdsa_public_key_framing() {
        // A stand-in uncompressed point: the marker byte plus 64 coordinate bytes.
        let mut point = vec![0x04];
        point.extend([0x42; 64]);

        let tagged = TaggedPublicKey {
            algorithm: PublicKeyAlgorithm::EcdsaSha2Nistp256,
            key: Cow::Borrowed(&point),
        };

        let mut buf = Vec::new();
        tagged.encode(&mut buf);

        // RFC 5656 section 3.1: `ecdsa-sha2-nistp256 || nistp256 || Q`.
        let (inner, next) = decode_string(&buf);
        assert!(next.is_empty());

        let (name, next) = decode_string(inner);
        assert_eq!(name, b"ecdsa-sha2-nistp256");

        let (curve, next) = decode_string(next);
        assert_eq!(curve, b"nistp256");

        let (q, next) = decode_string(next);
        assert_eq!(q, point.as_slice());
        assert!(next.is_empty());
    }

    #[test]
    fn ed25519_public_key_framing() {
        // Ed25519 keys carry no curve identifier (RFC 8709 section 4).
        let key = [0x07u8; 32];
        let tagged = TaggedPublicKey {
            algorithm: PublicKeyAlgorithm::Ed25519,
            key: Cow::Borrowed(&key),
        };

        let mut buf = Vec::new();
        tagged.encode(&mut buf);

        let (inner, next) = decode_string(&buf);
        assert!(next.is_empty());

        let (name, next) = decode_string(inner);
        assert_eq!(name, b"ssh-ed25519");

        let (value, next) = decode_string(next);
        assert_eq!(value, key);
        assert!(next.is_empty());
    }
}
