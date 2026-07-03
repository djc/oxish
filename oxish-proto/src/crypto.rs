use core::{error::Error as StdError, fmt};
use std::sync::Arc;

use crate::{
    named::{EncryptionAlgorithm, KeyExchangeAlgorithm, PublicKeyAlgorithm},
    with_mpint_bytes,
};

/// A bundle of cryptographic algorithm implementations
pub trait CryptoProvider: Send + Sync {
    /// Generate a fresh signing key
    ///
    /// Returns the key together with its PKCS#8 serialization, so the caller can
    /// persist it and load it again later with [`Self::signing_key_from_pkcs8()`].
    fn generate_signing_key(
        &self,
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<(Arc<dyn SigningKey>, Vec<u8>), CryptoError>;

    /// Load a signing key from its PKCS#8 serialization
    fn signing_key_from_pkcs8(&self, pkcs8: &[u8]) -> Result<Arc<dyn SigningKey>, CryptoError>;

    /// Build a public key that can verify signatures for `algorithm`
    ///
    /// `key` is the raw public key material. Returns `Err` if the algorithm is not supported.
    fn verifying_key(
        &self,
        key: &[u8],
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<Arc<dyn VerifyingKey>, CryptoError>;

    /// Build a decryption state from `key` and `iv`
    fn opening_key(
        &self,
        source: KeySourceSide,
        algorithm: &EncryptionAlgorithm<'_>,
    ) -> Result<Box<dyn OpeningKey>, CryptoError>;

    /// Build an encryption state from `key` and `iv`
    fn sealing_key(
        &self,
        source: KeySourceSide,
        algorithm: &EncryptionAlgorithm<'_>,
    ) -> Result<Box<dyn SealingKey>, CryptoError>;

    /// The key exchange group
    ///
    /// Returns `Err` if the algorithm is not supported.
    fn key_exchange(
        &self,
        algorithm: &KeyExchangeAlgorithm<'_>,
    ) -> Result<&'static dyn KeyExchange, CryptoError>;

    /// The hash function used for the exchange hash and key derivation
    ///
    /// Returns `Err` if the algorithm is not supported.
    fn hash(&self, algorithm: &KeyExchangeAlgorithm<'_>) -> Result<&'static dyn Hash, CryptoError>;

    /// A source of cryptographically secure random bytes
    fn secure_random(&self) -> &'static dyn SecureRandom;
}

/// An in-progress decryption, produced by [`CryptoProvider::opening_key()`]
pub trait OpeningKey: Send + Sync {
    /// Verify and decrypt a packet in place
    ///
    /// `data` is the `packet_length` field (4 bytes) followed by the ciphertext. On
    /// success the ciphertext portion is decrypted in place; returns `Err` if the tag
    /// does not verify.
    fn open_in_place(
        &mut self,
        sequence_number: u32,
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError>;

    /// Recover the 4-byte `packet_length` field
    ///
    /// For ciphers that transmit the length in cleartext (like AES-GCM) this returns
    /// `encrypted` unchanged; ciphers that encrypt the length override this.
    fn decrypt_packet_length(&mut self, seq: u32, encrypted: [u8; 4]) -> [u8; 4];

    /// The length in bytes of the authentication tag
    fn tag_len(&self) -> usize;
}

/// An in-progress encryption, produced by [`CryptoProvider::sealing_key()`]
pub trait SealingKey: Send + Sync {
    /// Encrypt a packet in place and write its authentication tag
    ///
    /// `data` is the `packet_length` field (4 bytes) followed by the plaintext
    /// (`padding_length`, `payload` and `padding`). The plaintext portion is encrypted
    /// in place and `tag` is filled with the authentication tag.
    fn seal_in_place(
        &mut self,
        seq: u32,
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// The length in bytes of the block size for this cipher
    fn block_len(&self) -> usize;

    /// The length in bytes of the authentication tag
    fn tag_len(&self) -> usize;
}

pub struct KeySourceSide {
    pub initial_iv: KeySource,
    pub encryption_key: KeySource,
}

impl KeySourceSide {
    pub fn client_to_server(derivation: &KeyDerivation) -> Self {
        Self {
            initial_iv: derivation.key(KeyInput::InitialIvClientToServer),
            encryption_key: derivation.key(KeyInput::EncryptionKeyClientToServer),
        }
    }

    pub fn server_to_client(derivation: &KeyDerivation) -> Self {
        Self {
            initial_iv: derivation.key(KeyInput::InitialIvServerToClient),
            encryption_key: derivation.key(KeyInput::EncryptionKeyServerToClient),
        }
    }
}

pub struct KeyDerivation {
    pub hash: &'static dyn Hash,
    pub shared_secret: Vec<u8>,
    pub exchange_hash: Digest,
    pub session_id: Digest,
}

impl KeyDerivation {
    fn key(&self, input: KeyInput) -> KeySource {
        let mut base = self.hash.start();
        with_mpint_bytes(&self.shared_secret, |bytes| base.update(bytes));
        base.update(self.exchange_hash.as_ref());

        KeySource {
            base,
            block_len: self.hash.output_len(),
            session_id: self.session_id,
            input,
        }
    }
}

pub struct KeySource {
    base: Box<dyn HashContext>,
    block_len: usize,
    session_id: Digest,
    input: KeyInput,
}

impl KeySource {
    pub fn derive<const N: usize>(self) -> [u8; N] {
        let block_len = self.block_len;

        let mut key = [0; N];

        if block_len < N {
            let mut context = self.base.fork();
            context.update(&[u8::from(self.input)]);
            context.update(self.session_id.as_ref());
            key[0..block_len].copy_from_slice(context.finish().as_ref());

            let mut i = block_len;
            while i < 64 {
                let mut context = self.base.fork();
                context.update(&key[..i]);
                key[i..i + block_len].copy_from_slice(context.finish().as_ref());
                i += block_len;
            }
        } else {
            let mut context = self.base;
            context.update(&[u8::from(self.input)]);
            context.update(self.session_id.as_ref());
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
}

impl From<KeyInput> for u8 {
    fn from(value: KeyInput) -> Self {
        match value {
            KeyInput::InitialIvClientToServer => b'A',
            KeyInput::InitialIvServerToClient => b'B',
            KeyInput::EncryptionKeyClientToServer => b'C',
            KeyInput::EncryptionKeyServerToClient => b'D',
        }
    }
}

/// A cryptographic hash function
pub trait Hash: Send + Sync {
    /// Start an incremental hash computation
    fn start(&self) -> Box<dyn HashContext>;

    /// The length in bytes of this hash function's output
    fn output_len(&self) -> usize;
}

/// An in-progress incremental hash computation
pub trait HashContext: Send + Sync {
    /// Add `data` to the computation
    fn update(&mut self, data: &[u8]);

    /// Clone the computation, producing another context with the same prefix
    fn fork(&self) -> Box<dyn HashContext>;

    /// Finish the computation, consuming it and returning the digest
    fn finish(self: Box<Self>) -> Digest;
}

/// A hash output, stored inline
#[derive(Clone, Copy, Debug)]
pub struct Digest {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl Digest {
    /// Build a `Digest` from a slice of no more than [`Self::MAX_LEN`] bytes
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= Self::MAX_LEN);
        let mut buf = [0; Self::MAX_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Self {
            buf,
            used: bytes.len(),
        }
    }

    /// Maximum supported digest size: enough for SHA-512
    pub const MAX_LEN: usize = 64;
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A key exchange group
pub trait KeyExchange: Send + Sync {
    /// Start an ephemeral key exchange, generating our ephemeral key pair
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, CryptoError>;
}

/// An in-progress key exchange, produced by [`KeyExchange::start`]
pub trait ActiveKeyExchange: Send {
    /// Our ephemeral public key, to be sent to the peer
    fn public_key(&self) -> &[u8];

    /// Complete the exchange using the peer's public key, returning the shared secret
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// A key pair that can sign messages
pub trait SigningKey: Send + Sync {
    /// Sign `message`, returning the raw signature
    fn sign(&self, message: &[u8]) -> Vec<u8>;

    /// The raw public key material
    fn public_key(&self) -> &[u8];

    /// The public key algorithm of this key
    fn algorithm(&self) -> PublicKeyAlgorithm<'static>;
}

/// A public key that can verify signatures
pub trait VerifyingKey: Send + Sync {
    /// Verify that `signature` is a valid signature over `message`
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// A source of cryptographically secure randomness.
pub trait SecureRandom: Send + Sync {
    /// Fill `buf` with random bytes
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError>;
}

/// An error returned by a cryptographic operation
#[derive(Clone, Copy, Debug)]
pub enum CryptoError {
    DecryptionFailed,
    EncryptionFailed,
    InvalidLength,
    KeyAgreementFailed,
    KeyGenerationFailed,
    KeyRejected,
    NonceOverflow,
    NoRandomness,
    UnknownAlgorithm,
    Unspecified,
    VerificationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::InvalidLength => write!(f, "invalid length"),
            Self::KeyAgreementFailed => write!(f, "key agreement failed"),
            Self::KeyGenerationFailed => write!(f, "key generation failed"),
            Self::KeyRejected => write!(f, "key rejected"),
            Self::NonceOverflow => write!(f, "nonce overflow"),
            Self::NoRandomness => write!(f, "no randomness available"),
            Self::UnknownAlgorithm => write!(f, "unknown algorithm"),
            Self::Unspecified => write!(f, "unspecified error"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl StdError for CryptoError {}
