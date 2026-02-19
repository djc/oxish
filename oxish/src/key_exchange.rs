use core::fmt;
use std::{borrow::Cow, sync::Arc};

use aws_lc_rs::{
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    digest,
    rand::{self, SystemRandom},
    signature::{KeyPair, Signature},
};
use tracing::{debug, error, warn};

use crate::{
    messages::{
        Decode, Decoded, Encode, IncomingPacket, KeyExchangeAlgorithm, KeyExchangeInit,
        MessageType, ProtoError, PublicKeyAlgorithm,
    },
    proto::HandshakeHash,
    ConnectionContext,
};

pub(crate) struct EcdhKeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<digest::Digest>,
}

impl EcdhKeyExchange {
    pub(crate) fn advance(
        self,
        ecdh_key_exchange_init: EcdhKeyExchangeInit<'_>,
        mut exchange: HandshakeHash,
        cx: &ConnectionContext,
    ) -> Result<(EcdhKeyExchangeReply, digest::Digest, RawKeySet), ()> {
        // Write the server's public host key (`K_S`) to the exchange hash

        let mut host_key_buf = Vec::with_capacity(128);
        TaggedPublicKey {
            algorithm: PublicKeyAlgorithm::Ed25519,
            key: Cow::Owned(cx.host_key.public_key().as_ref().to_owned()),
        }
        .encode(&mut host_key_buf);
        exchange.update(&host_key_buf);

        // Write the client's ephemeral public key (`Q_C`) to the exchange hash

        exchange.prefixed(ecdh_key_exchange_init.client_ephemeral_public_key);

        let random = SystemRandom::new();
        let Ok(kx_private_key) = EphemeralPrivateKey::generate(&X25519, &random) else {
            warn!(addr = %cx.addr, "failed to generate key exchange private key");
            return Err(());
        };

        let Ok(kx_public_key) = kx_private_key.compute_public_key() else {
            warn!(addr = %cx.addr, "failed to compute key exchange public key");
            return Err(());
        };

        let client_kx_public_key =
            UnparsedPublicKey::new(&X25519, ecdh_key_exchange_init.client_ephemeral_public_key);

        exchange.prefixed(kx_public_key.as_ref());
        let Ok(shared_secret) = agreement::agree_ephemeral(
            kx_private_key,
            client_kx_public_key,
            aws_lc_rs::error::Unspecified,
            |shared_secret| Ok(shared_secret.to_vec()),
        ) else {
            warn!(addr = %cx.addr, "key exchange failed");
            return Err(());
        };

        with_mpint_bytes(&shared_secret, |bytes| exchange.update(bytes));

        let exchange_hash = exchange.finish();
        let signature = cx.host_key.sign(exchange_hash.as_ref());
        let key_exchange_reply = EcdhKeyExchangeReply {
            server_public_host_key: TaggedPublicKey {
                algorithm: PublicKeyAlgorithm::Ed25519,
                key: Cow::Owned(cx.host_key.public_key().as_ref().to_owned()),
            },
            server_ephemeral_public_key: kx_public_key.as_ref().to_owned(),
            exchange_hash_signature: TaggedSignature {
                algorithm: PublicKeyAlgorithm::Ed25519,
                signature,
            },
        };

        // The first exchange hash is used as session id.
        let session_id = self.session_id.unwrap_or(exchange_hash);
        let derivation = KeyDerivation {
            shared_secret,
            exchange_hash,
            session_id: Arc::new(session_id),
        };

        Ok((
            key_exchange_reply,
            session_id,
            RawKeySet {
                client_to_server: RawKeys::client_to_server(&derivation),
                server_to_client: RawKeys::server_to_client(&derivation),
            },
        ))
    }
}

#[derive(Debug)]
pub(crate) struct EcdhKeyExchangeInit<'a> {
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
pub(crate) struct EcdhKeyExchangeReply {
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
    signature: Signature,
}

impl Encode for TaggedSignature<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend([0; 4]);
        self.algorithm.encode(buf);
        self.signature.as_ref().encode(buf);
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

#[derive(Debug, Default)]
pub(crate) struct KeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<digest::Digest>,
}

impl KeyExchange {
    pub(crate) fn advance<'out>(
        self,
        peer_key_exchange_init: KeyExchangeInit<'_>,
        cx: &ConnectionContext,
    ) -> Result<(KeyExchangeInit<'out>, EcdhKeyExchange), ()> {
        let mut cookie = [0; 16];
        if rand::fill(&mut cookie).is_err() {
            error!("failed to generate key exchange cookie");
            return Err(());
        };

        let key_exchange_init = match KeyExchangeInit::new(cookie) {
            Ok(kex_init) => kex_init,
            Err(error) => {
                error!(addr = %cx.addr, %error, "failed to create key exchange init");
                return Err(());
            }
        };

        let algorithms = match Algorithms::choose(peer_key_exchange_init, &key_exchange_init) {
            Ok(algorithms) => {
                debug!(addr = %cx.addr, ?algorithms, "chosen algorithms");
                algorithms
            }
            Err(error) => {
                warn!(addr = %cx.addr, %error, "failed to choose algorithms");
                return Err(());
            }
        };

        if algorithms.key_exchange != KeyExchangeAlgorithm::Curve25519Sha256 {
            warn!(addr = %cx.addr, algorithm = ?algorithms.key_exchange, "unsupported key exchange algorithm");
            return Err(());
        }

        Ok((
            key_exchange_init,
            EcdhKeyExchange {
                session_id: self.session_id,
            },
        ))
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
                    .find(|&&server_alg| server_alg == client)
            })
            .ok_or(ProtoError::NoCommonAlgorithm("key exchange"))?;

        Ok(Self {
            key_exchange: *key_exchange,
        })
    }
}

/// The raw hashes from which we will derive the crypto keys.
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-7.2>
pub(crate) struct RawKeySet {
    pub(crate) client_to_server: RawKeys,
    pub(crate) server_to_client: RawKeys,
}

pub(crate) struct RawKeys {
    pub(crate) initial_iv: Key,
    pub(crate) encryption_key: Key,
    pub(crate) integrity_key: Key,
}

impl RawKeys {
    fn client_to_server(derivation: &KeyDerivation) -> Self {
        Self {
            initial_iv: derivation.key(KeyInput::InitialIvClientToServer),
            encryption_key: derivation.key(KeyInput::EncryptionKeyClientToServer),
            integrity_key: derivation.key(KeyInput::IntegrityKeyClientToServer),
        }
    }

    fn server_to_client(derivation: &KeyDerivation) -> Self {
        Self {
            initial_iv: derivation.key(KeyInput::InitialIvServerToClient),
            encryption_key: derivation.key(KeyInput::EncryptionKeyServerToClient),
            integrity_key: derivation.key(KeyInput::IntegrityKeyServerToClient),
        }
    }
}

struct KeyDerivation {
    shared_secret: Vec<u8>,
    exchange_hash: digest::Digest,
    session_id: Arc<digest::Digest>,
}

impl KeyDerivation {
    fn key(&self, input: KeyInput) -> Key {
        let mut base = digest::Context::new(&digest::SHA256);
        with_mpint_bytes(&self.shared_secret, |bytes| base.update(bytes));
        base.update(self.exchange_hash.as_ref());

        Key {
            base,
            session_id: self.session_id.clone(),
            input,
        }
    }
}

pub(crate) struct Key {
    base: digest::Context,
    session_id: Arc<digest::Digest>,
    input: KeyInput,
}

impl Key {
    pub(crate) fn derive<const N: usize>(self) -> [u8; N] {
        let block_len = digest::SHA256.output_len();

        let mut key = [0; N];

        if block_len < N {
            let mut context = self.base.clone();
            context.update(&[u8::from(self.input)]);
            context.update((*self.session_id).as_ref());
            key[0..block_len].copy_from_slice(context.finish().as_ref());

            let mut i = block_len;
            while i < 64 {
                let mut context = self.base.clone();
                context.update(&key[..i]);
                key[i..i + block_len].copy_from_slice(context.finish().as_ref());
                i += block_len;
            }
        } else {
            let mut context = self.base;
            context.update(&[u8::from(self.input)]);
            context.update((*self.session_id).as_ref());
            key[..N].copy_from_slice(&context.finish().as_ref()[..N]);
        }

        key
    }
}

enum KeyInput {
    InitialIvClientToServer,
    InitialIvServerToClient,
    EncryptionKeyClientToServer,
    EncryptionKeyServerToClient,
    IntegrityKeyClientToServer,
    IntegrityKeyServerToClient,
}

impl From<KeyInput> for u8 {
    fn from(value: KeyInput) -> Self {
        match value {
            KeyInput::InitialIvClientToServer => b'A',
            KeyInput::InitialIvServerToClient => b'B',
            KeyInput::EncryptionKeyClientToServer => b'C',
            KeyInput::EncryptionKeyServerToClient => b'D',
            KeyInput::IntegrityKeyClientToServer => b'E',
            KeyInput::IntegrityKeyServerToClient => b'F',
        }
    }
}

/// The mpint data type is defined in RFC4251 section 5.
///
/// Remove leading zeros, and prepend a zero byte if the first byte has its
/// most significant bit set.
fn with_mpint_bytes(int: &[u8], mut f: impl FnMut(&[u8])) {
    let leading_zeros = int.iter().take_while(|&&b| b == 0).count();
    // This slice indexing is safe as leading_zeros can be no larger than the length of int
    let int = &int[leading_zeros..];
    let prepend = matches!(int.first(), Some(&b) if b & 0x80 != 0);
    let len = int.len() + if prepend { 1 } else { 0 };
    f(&(len as u32).to_be_bytes());
    if prepend {
        f(&[0]);
    }
    f(int);
}
