use core::fmt;
use std::borrow::Cow;

use tracing::debug;

use crate::{
    Decode, Decoded, Encode, ExtInfo, IncomingPacket, KeyExchangeAlgorithm, MessageType, Pretty,
    ProtoError, PublicKeyAlgorithm,
    crypto::{
        CryptoError, CryptoProvider, Digest, HandshakeBuffer, HandshakeHash, KeyDerivation,
        KeySourceSide, SharedSecret, SigningKey,
    },
    named::{
        CompressionAlgorithm, EncryptionAlgorithm, ExtensionId, ExtensionName, IncomingNameList,
        KeyExchangeAlgorithmOrExtensionId, Language, MacAlgorithm, OutgoingNameList,
    },
};

/// Output from the initial key exchange phase
pub struct KeyExchange {
    pub local: KeyExchangeInit<'static>,
    pub exchange: HandshakeHash,
    pub negotiated: Negotiated,
    pub ext_info: ExtInfo<'static>,
}

impl KeyExchange {
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

impl EcdhKeyExchangeReply {
    /// Complete an ECDH key exchange and derive fresh key material
    ///
    /// `session_id` carries the session identifier from an earlier exchange when this is a
    /// rekey; pass `None` for the initial exchange, where the exchange hash doubles as the
    /// session identifier (RFC 4253 section 7.2).
    pub fn new(
        ecdh_key_exchange_init: EcdhKeyExchangeInit<'_>,
        negotiated: &Negotiated,
        exchange: HandshakeHash,
        host_keys: &HostKeys,
        provider: &dyn CryptoProvider,
        session_id: Option<Digest>,
    ) -> Result<(Self, Digest, KeySourceSet), CryptoError> {
        let KeyExchangeOutput {
            shared_secret,
            exchange_hash,
            reply: key_exchange_reply,
        } = host_keys.sign(
            exchange,
            ecdh_key_exchange_init.client_ephemeral_public_key,
            negotiated,
            provider,
        )?;

        // The first exchange hash doubles as the session id; a rekey keeps the original one.
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

pub struct HostKeys(Vec<Box<dyn SigningKey>>);

impl HostKeys {
    fn sign(
        &self,
        mut exchange: HandshakeHash,
        client_ephemeral_public_key: &[u8],
        negotiated: &Negotiated,
        provider: &dyn CryptoProvider,
    ) -> Result<KeyExchangeOutput, CryptoError> {
        let host_key = self
            .0
            .iter()
            .find(|key| key.algorithm() == negotiated.server_host_key)
            .ok_or(CryptoError::UnknownAlgorithm)?;

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
        Ok(KeyExchangeOutput {
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

    pub fn algorithms(&self) -> impl Iterator<Item = PublicKeyAlgorithm<'static>> + '_ {
        self.0.iter().map(|key| key.algorithm())
    }
}

impl TryFrom<Vec<Box<dyn SigningKey>>> for HostKeys {
    type Error = ProtoError;

    fn try_from(host_keys: Vec<Box<dyn SigningKey>>) -> Result<Self, Self::Error> {
        if host_keys.is_empty() {
            return Err(ProtoError::NoHostKeys);
        }

        Ok(Self(host_keys))
    }
}

struct KeyExchangeOutput {
    shared_secret: SharedSecret,
    exchange_hash: Digest,
    reply: EcdhKeyExchangeReply,
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

#[derive(Debug)]
pub struct Negotiated {
    pub key_exchange: KeyExchangeAlgorithm<'static>,
    pub server_host_key: PublicKeyAlgorithm<'static>,
    pub encryption_client_to_server: EncryptionAlgorithm<'static>,
    pub encryption_server_to_client: EncryptionAlgorithm<'static>,
    pub want_extension_info: bool,
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

/// The raw hashes from which we will derive the crypto keys.
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-7.2>
pub struct KeySourceSet {
    pub client_to_server: KeySourceSide,
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
