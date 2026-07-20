use core::{error::Error as StdError, fmt};
use std::sync::Arc;

use crate::{
    MacAlgorithm,
    named::{EncryptionAlgorithm, KeyExchangeAlgorithm, PublicKeyAlgorithm},
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
    ) -> Result<(Box<dyn SigningKey>, Vec<u8>), CryptoError>;

    /// Load a signing key from its PKCS#8 serialization
    fn signing_key_from_pkcs8(&self, pkcs8: &[u8]) -> Result<Box<dyn SigningKey>, CryptoError>;

    /// Build a public key that can verify signatures for `algorithm`
    ///
    /// `key` is the raw public key material. Returns `Err` if the algorithm is not supported.
    fn verifying_key(
        &self,
        key: &[u8],
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<Arc<dyn VerifyingKey>, CryptoError>;

    /// Build a decryption state from key `source` material and initial `counter`
    fn opening_key(
        &self,
        counter: u64,
        source: &KeySourceSide,
    ) -> Result<Box<dyn OpeningKey>, CryptoError>;

    /// Build an encryption state from key `source` material and initial `counter`
    fn sealing_key(
        &self,
        counter: u64,
        source: &KeySourceSide,
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

    /// Algorithms supported by this provider
    fn supported_algorithms(&self) -> SupportedAlgorithms;

    /// A source of cryptographically secure random bytes
    fn secure_random(&self) -> &'static dyn SecureRandom;
}

pub struct SupportedAlgorithms {
    pub key_exchange: &'static [KeyExchangeAlgorithm<'static>],
    pub public_key: &'static [PublicKeyAlgorithm<'static>],
    pub encryption: &'static [EncryptionAlgorithm<'static>],
    pub mac: &'static [MacAlgorithm<'static>],
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

    /// Number of times the key has been used to open a packet
    fn counter(&self) -> u64;

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

    /// Number of times the key has been used to seal a packet
    fn counter(&self) -> u64;

    /// The length in bytes of the block size for this cipher
    fn block_len(&self) -> usize;

    /// The length in bytes of the authentication tag
    fn tag_len(&self) -> usize;
}

pub struct KeySourceSide {
    pub algorithm: EncryptionAlgorithm<'static>,
    pub initial_iv: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

impl KeySourceSide {
    pub(crate) fn client_to_server(
        derivation: &KeyDerivation,
        algorithm: EncryptionAlgorithm<'static>,
    ) -> Result<Self, CryptoError> {
        let Some(KeyLengths { key_len, iv_len }) = algorithm.lengths() else {
            return Err(CryptoError::UnknownAlgorithm);
        };

        Ok(Self {
            algorithm,
            initial_iv: derivation
                .key(KeyInput::InitialIvClientToServer)
                .derive(iv_len),
            encryption_key: derivation
                .key(KeyInput::EncryptionKeyClientToServer)
                .derive(key_len),
        })
    }

    pub(crate) fn server_to_client(
        derivation: &KeyDerivation,
        algorithm: EncryptionAlgorithm<'static>,
    ) -> Result<Self, CryptoError> {
        let Some(KeyLengths { key_len, iv_len }) = algorithm.lengths() else {
            return Err(CryptoError::UnknownAlgorithm);
        };

        Ok(Self {
            algorithm,
            initial_iv: derivation
                .key(KeyInput::InitialIvServerToClient)
                .derive(iv_len),
            encryption_key: derivation
                .key(KeyInput::EncryptionKeyServerToClient)
                .derive(key_len),
        })
    }
}

impl fmt::Debug for KeySourceSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            algorithm,
            initial_iv: _,
            encryption_key: _,
        } = self;

        f.debug_struct("KeySourceSide")
            .field("algorithm", algorithm)
            .finish_non_exhaustive()
    }
}

pub struct KeyLengths {
    pub key_len: usize,
    pub iv_len: usize,
}

pub(crate) struct KeyDerivation {
    pub(crate) hash: &'static dyn Hash,
    /// The shared secret `K`, encoded exactly as fed into the exchange hash
    pub(crate) shared_secret: SharedSecret,
    pub(crate) exchange_hash: Digest,
    pub(crate) session_id: Digest,
}

impl KeyDerivation {
    fn key(&self, input: KeyInput) -> KeySource {
        let mut base = self.hash.start();
        base.update(self.shared_secret.secret_bytes());
        base.update(self.exchange_hash.as_ref());

        KeySource {
            base,
            block_len: self.hash.output_len(),
            session_id: self.session_id,
            input,
        }
    }
}

struct KeySource {
    base: Box<dyn HashContext>,
    block_len: usize,
    session_id: Digest,
    input: KeyInput,
}

impl KeySource {
    fn derive(&self, len: usize) -> Vec<u8> {
        let block_len = self.block_len;
        let mut key = vec![0; len];

        // K1 = HASH(K || H || X || session_id)
        let mut context = self.base.fork();
        context.update(&[u8::from(self.input)]);
        context.update(self.session_id.as_ref());
        let block = context.finish();
        let bytes = block.as_ref();
        let mut have = Ord::min(bytes.len(), len);
        key[..have].copy_from_slice(&block.as_ref()[..have]);

        // K2 = HASH(K || H || K1), K3 = HASH(K || H || K1 || K2), ...
        while have < len {
            let mut context = self.base.fork();
            context.update(&key[..have]);
            let block = context.finish();
            let take = block_len.min(len - have);
            key[have..have + take].copy_from_slice(&block.as_ref()[..take]);
            have += take;
        }

        key
    }
}

#[derive(Clone, Copy)]
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

pub struct HandshakeHash(Box<dyn HashContext>);

impl HandshakeHash {
    pub fn prefixed(&mut self, data: &[u8]) {
        self.0.update(&(data.len() as u32).to_be_bytes());
        self.0.update(data);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> Digest {
        self.0.finish()
    }
}

#[derive(Default)]
pub struct HandshakeBuffer(Vec<u8>);

impl HandshakeBuffer {
    pub fn hash(self, algorithm: &dyn Hash) -> HandshakeHash {
        let Self(bytes) = self;
        let mut context = algorithm.start();
        context.update(&bytes);
        HandshakeHash(context)
    }

    pub fn prefixed(&mut self, data: &[u8]) {
        self.0.extend_from_slice(&(data.len() as u32).to_be_bytes());
        self.0.extend_from_slice(data);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
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
    /// Complete the exchange using the peer's public value
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<AgreedKey, CryptoError>;
}

/// The result of completing a key exchange, produced by [`ActiveKeyExchange::complete`]
pub struct AgreedKey {
    /// Our public value to send to the peer (`Q_S` / `S_REPLY`)
    pub public_key: Vec<u8>,

    /// The shared secret `K`
    pub shared_secret: SharedSecret,
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

pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    pub fn secret_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SharedSecret {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// An error returned by a cryptographic operation
#[derive(Clone, Copy, Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
    use sha1::Sha1;
    use sha2::{Digest as _, Sha256};

    use super::*;

    /// NIST ACVP SSH KDF known-answer tests for SHA2-256.
    ///
    /// Vectors come from the NIST ACVP-Server project, test group `kdf-components-ssh-1.0`
    /// (`internalProjection.json`), the group with `cipher: TDES`, `hashAlg: SHA2-256`. The
    /// SSH KDF from RFC 4253 section 7.2 does not depend on the cipher; the cipher only fixes
    /// the output lengths (8-byte IV, 24-byte encryption key here).
    #[test]
    fn acvp_ssh_kdf_sha256() {
        // Group `cipher: TDES`, `hashAlg: SHA2-256`, cases tcId 41, 42, 43.
        let vectors: &[Vector] = &[
            Vector {
                k: b"\x00\x00\x01\x00\x63\x4a\x21\x58\xd6\xa4\x13\xbf\x26\x8f\x88\xb4\x68\x5b\x2a\xc6\x65\xb9\xed\x06\xdb\x44\x1f\xcb\x26\x76\x4f\xfa\x48\x2a\xd0\x7a\xa4\xeb\xbf\x30\x9f\x36\x9d\x17\xec\x87\x82\x25\x13\xb7\xa3\x1f\xb2\xc8\xd0\x40\xbf\x97\x5f\x23\x7a\xc1\x8f\x73\xbb\x00\x47\xa9\xb5\x9b\x6b\x0c\x7b\xdc\x8f\x36\xfa\xac\x9e\x3a\x68\x9a\x8d\xb6\xe9\x0b\xfb\x8f\xd3\x86\x16\x10\xf7\x3b\x0c\x2f\x6c\x97\xc4\x8a\xc2\xeb\xbf\xa0\x6d\x8d\x2b\xad\x58\xa4\xc6\xd6\xa8\x56\x5e\x87\xf0\xfb\x0a\x80\x8a\x09\x94\x75\x3c\xd9\x9a\xa6\x8a\xe7\xda\xc0\x82\x46\x90\xc7\x22\x7e\xb1\xf4\x8b\x85\x98\x68\xfb\x52\xe9\x91\xe1\x97\x16\x47\x58\x46\xd0\x53\xb2\xe2\x1f\x1f\x81\xb7\x32\xf0\x0c\xc1\x29\x91\xe8\x40\x1f\x07\x43\x62\xc6\x5b\x5c\x47\x57\x5b\xf8\x1b\x5d\xbd\xd8\xe7\x82\xab\xd7\x79\x07\x41\x85\xf5\x57\x52\xe0\xf5\xaf\x52\xae\xe1\xad\x3f\x54\xef\x2e\xda\xf2\xa8\xcc\xb9\x24\xa4\x14\xd8\x09\x13\xe5\xbc\x14\xd7\x73\x96\x7f\x73\xf6\x72\x3d\xb9\x03\x28\x01\x7b\x00\x0c\xf4\x67\xd0\xbe\xa3\x96\x83\x4b\x0f\x87\xb5\x7c\x67\x94\x0c\xe4\x1d\xb1\xce\xae\xee\xa2\xa7\x25",
                h: b"\xaa\xce\xa0\xab\xe6\x88\x03\x40\xf1\xef\x82\x63\x05\xd9\xd0\xe3\x2a\xe6\xac\x3e\x05\x47\x90\x2d\xcf\xb7\x80\xa6\x6f\x45\xf3\x74",
                session_id: b"\x8d\x24\xd0\xf8\xa2\x2e\x53\x03\xf1\xff\x45\x48\x88\xf3\x7a\x2d\x12\xe8\x8a\x41\x24\x3b\x8b\x73\x45\xbf\x4a\xa7\x12\x67\xe1\xd4",
                iv_client: b"\x4e\xe3\xba\x3a\xe4\xa9\xe4\x7b",
                iv_server: b"\x24\x38\xe9\xfb\x30\xcd\x28\xbc",
                enc_client: b"\x96\x37\xd5\xc0\x2d\xcb\x8b\xe2\xc1\x24\x5e\xcb\xab\xc2\x1a\x27\x03\xe8\x5e\x73\x6d\xe9\xa2\x11",
                enc_server: b"\x23\x16\x50\xb6\xc8\xfd\x25\x0f\xaa\x23\x3b\x28\x8e\xdb\xce\x91\x2a\x53\x1b\xb3\xda\x56\x19\x12",
            },
            Vector {
                k: b"\x00\x00\x01\x00\x35\x63\x9d\x80\x66\xd3\x74\xa6\x36\x29\xec\xfe\x23\x0e\x11\x55\xca\xe5\xdd\x7e\x3c\xf1\xdc\x2d\xbe\xd1\xcf\x70\x4d\xe4\x70\x96\x9f\x74\xd3\x17\x34\x6c\xad\x14\xcb\x31\x4a\xfe\xb7\x51\x5e\x4e\xf4\xa3\x57\x8d\x80\x81\x5c\x08\x7a\xd2\xed\x13\xe8\x40\xd7\x81\x27\xa3\x50\x82\x5c\x06\xf8\x21\x72\x5d\xff\x99\xfa\x56\xff\xac\xe4\xb7\xb0\x25\x65\x98\x39\xef\xf6\x30\x1d\x2d\x8e\x1f\x72\xcb\xca\x44\x55\xb6\xfd\x43\x05\xa5\xc8\xbc\x25\xb9\x70\x53\x38\x98\xff\x7b\x33\x5a\x0c\xa2\xc5\x7d\x5a\x4d\xc5\x62\xab\xc1\xde\x98\x17\x6f\xed\x32\xef\xff\x27\x17\x11\xbd\xc7\x2a\x15\x93\x3d\xbc\x92\xc8\xee\x6c\xb7\x89\x3b\xb7\x77\x44\xb5\x24\x5a\x17\x62\x8f\xe7\x3b\x4c\xad\x0f\xcb\x60\xed\xe7\xeb\xe4\x47\x59\x3d\xc2\x10\x72\x20\x7a\x0d\x50\xc5\xd3\x63\x1d\xfd\xfe\x4f\xec\x0e\x02\xf6\x04\x21\x68\xd8\xa3\xaf\xdd\x0d\xd6\x3f\x31\x8b\xed\x58\xb4\x75\x94\xa2\x33\x5d\x0e\x66\xb0\x4f\x13\xf0\x5c\xec\xd8\x37\x2d\x19\x76\xd2\x9f\x0e\xb3\x56\xb2\xa6\x7e\x88\x74\x01\x14\xe6\x54\x7a\xe9\xd7\x87\x1a\x27\x79\xc8\xa3\x2f\x1b\x2e\x56\x55\x5b\x95\x4a",
                h: b"\x8f\x3e\x6b\xfb\xfb\xa7\xad\x47\xaa\xa0\x50\xc5\x05\xde\xa1\xc7\x37\x4d\xf4\x59\x22\x89\x92\x8d\x7f\x84\x55\x73\x1c\xe9\xe1\xe8",
                session_id: b"\x22\x83\x89\xae\xc5\xd5\x3f\x41\x98\x6f\x5d\xbf\xdf\x9e\x9b\x27\xb2\xdd\x06\x62\x6b\x96\x8e\x8d\x00\x57\xc8\xf3\x9c\x54\xbc\x79",
                iv_client: b"\x53\xec\xf6\x2c\x16\xf2\x0a\x04",
                iv_server: b"\xcf\x75\x6e\x45\xcc\xa5\xce\x9d",
                enc_client: b"\x35\x6c\x5c\xdc\x92\x48\x59\x53\x51\xc5\x53\x00\xdc\xbf\x96\x81\x1e\x0c\x09\x3f\x5b\x6e\x29\x07",
                enc_server: b"\x85\x59\xe7\x6e\xf9\xc8\x4a\x8e\x6c\x89\x35\x88\x88\x96\xe1\x57\x9b\x79\x4e\x73\xea\x26\x67\x84",
            },
            Vector {
                k: b"\x00\x00\x01\x01\x00\x91\x99\x8c\x73\xea\xef\x12\x46\xa3\xc4\x59\xe5\xef\x3e\x28\xfa\x62\xc5\xb8\x6b\x01\x9b\x0f\x5e\x68\xa5\x10\x54\xd6\xc2\x9b\x00\x94\x9a\x67\x19\x31\x31\x47\xa4\x3b\x29\xc1\xde\x4d\x19\xae\xac\x13\x69\xa6\x87\x9d\x92\x5b\xf9\xb3\xbd\xa4\x32\x94\x4d\x70\x65\xa2\xa6\xfe\x9d\xea\x3c\x63\x08\x4c\x56\xfd\x5c\x94\xc2\x1c\x0d\xd7\xa4\xa2\x46\x27\x3d\xa7\x93\x38\x52\x56\x95\x3a\x94\xfa\x38\x86\x56\xa0\x6a\x26\x86\x50\xb6\xaf\xce\xc4\x45\x25\x93\x4b\x09\x53\xdf\xc7\x8f\x86\xf6\xbb\x42\x10\x25\x23\x3b\xf3\x12\xd7\x11\x9b\x23\xf0\xdf\xcb\x6f\xec\x9f\x33\x28\x3d\xe3\x80\xb8\xb8\x5b\x8d\x49\xa8\x11\xa5\x96\x5c\x77\x35\x6b\xd9\x13\x25\x84\xde\xed\xb1\x44\xfd\xde\xef\xd8\x52\xfb\xf0\x6d\x25\xe2\x6e\xf1\xae\xea\x38\x48\xc0\xd1\x00\x88\x55\x98\x01\xe0\xb8\x1d\x6a\xdd\x0c\x58\x0a\xab\xd4\x2e\xa2\xf0\xa4\x4d\x1a\xa8\x9a\xfb\x2e\x5e\x57\xed\x89\x44\xf0\x31\xdd\xe9\x99\x86\x73\xa0\xcf\x93\x26\x6d\xa3\x8a\x68\x53\x40\xc5\xdf\x38\x2f\x28\x79\x9d\xba\x99\x0f\xc8\x38\xd1\x73\xde\x8b\x0d\x67\x74\xac\x4b\x71\xb4\x66\xd1\x19\x1d\xeb\xd5",
                h: b"\xd2\xf5\xba\x20\x42\x8f\x1e\xd6\xa7\xaf\xab\x28\xf0\x37\xcf\x82\xeb\xd0\x28\x26\xce\xee\xb0\x09\x9b\xbf\x92\xe4\xeb\x9d\xfd\xc0",
                session_id: b"\x4e\x7b\x7c\x02\xc5\x14\xf6\x4e\x14\x68\xa9\x54\xa4\x68\x04\x42\x1e\x7c\xf5\x6a\x34\xe6\xa2\x69\x67\x7d\xd9\x1b\x6d\x40\x09\x75",
                iv_client: b"\x14\x7d\xda\xa9\xae\x20\x82\x87",
                iv_server: b"\x2e\x0b\x42\x83\xbf\x98\x01\x1c",
                enc_client: b"\xa5\xf8\xe7\xc4\x72\xf1\xa7\x9e\x56\x48\x56\xd4\xb5\x3c\x78\x5f\x56\x6e\x2e\xe1\xe2\x9d\x89\x2a",
                enc_server: b"\x3c\x1e\xae\x5e\x77\xd1\x51\xbf\xcc\xcb\x1c\x60\xef\x41\x9e\xe1\x61\x0a\x36\xa5\x7d\xcb\xad\x50",
            },
        ];

        check_vectors(&TestSha256, vectors);
    }

    /// A pure-Rust SHA-256 [`Hash`] used only to exercise the KDF in tests.
    struct TestSha256;

    impl Hash for TestSha256 {
        fn start(&self) -> Box<dyn HashContext> {
            Box::new(TestSha256Context(Sha256::new()))
        }

        fn output_len(&self) -> usize {
            32
        }
    }

    struct TestSha256Context(Sha256);

    impl HashContext for TestSha256Context {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        fn fork(&self) -> Box<dyn HashContext> {
            Box::new(Self(self.0.clone()))
        }

        fn finish(self: Box<Self>) -> Digest {
            Digest::new(self.0.finalize().as_slice())
        }
    }

    /// NIST ACVP SSH KDF known-answer tests for SHA-1.
    ///
    /// SHA-1's 20-byte block is shorter than the 24-byte encryption key, so deriving the
    /// encryption key exercises the multi-block extension path (`K2 = HASH(K || H || K1)`),
    /// which the SHA-256 vectors cannot reach (all their outputs fit in one 32-byte block).
    #[test]
    fn acvp_ssh_kdf_sha1() {
        // Group `cipher: TDES`, `hashAlg: SHA-1`, cases tcId 1, 2, 3.
        let vectors: &[Vector] = &[
            Vector {
                k: b"\x00\x00\x01\x00\x2a\x19\xd1\x31\x6d\xe1\x00\x65\x91\xa9\x80\xc1\x20\xd0\xeb\xab\x1d\x51\xbd\x41\x5a\xaf\xb6\xd9\xd5\x42\xff\x33\x05\x68\x01\x19\xf5\xfb\x7e\x18\xbf\x06\x82\xd9\x15\x42\x71\x15\x55\xd5\xdb\x99\x30\x38\x2e\xf7\x55\x5c\x22\xa9\x32\x90\x38\xf0\xba\x15\xa7\x02\xbf\xd6\x97\xfc\x6a\x1b\xe3\x4c\x49\x13\x9e\x7c\x59\xe9\x69\x0d\x32\xba\x48\xad\x6b\xc1\xef\x8c\xf8\xe8\x34\xa3\x53\xcc\xed\xb3\xbe\xca\xff\xbf\xe2\x0e\x54\x79\xe5\x9a\xb9\x45\xe9\x1a\x92\x66\x34\x8b\xbc\xa7\xc9\x65\xcd\xbe\x95\x7a\x0b\xbe\x95\xc9\xe6\x02\x59\x87\x96\xeb\x50\x9e\x98\xef\x62\x11\x12\x39\x7f\x85\x07\x03\xa7\xca\x6d\x39\xce\x46\x3a\x55\xb6\x4f\x5d\x7b\xfe\xb6\x8b\xf8\xd3\x38\xca\xf0\x1d\x39\x31\xa1\xc4\x8b\xee\x03\xbb\x83\x0d\xf3\xf6\x09\x75\x21\xc2\xb9\x3b\x23\x77\xb4\x25\x81\x3f\x5d\x7b\x50\x15\xce\xbd\x8d\x78\xfd\x0c\x1c\xec\x2f\xf3\x0a\x6a\xb2\x0a\xdb\xd0\x9c\xd9\x79\x07\xa1\xc7\x90\xc6\x42\xee\x2a\x55\x1d\xd0\xb8\x95\x58\xb5\xc5\x5f\xde\x90\xcf\x82\x7c\xc3\x89\x4a\x01\x66\x66\xde\x7a\x9e\x10\x15\x10\xa8\xcb\x93\x1c\x6b\x08\xcd\x8f\x98\xaf",
                h: b"\x2d\x14\xe9\x31\x1b\xd3\xe7\xc1\x5e\x7c\x00\x99\x9a\xfd\x33\xc6\xf5\x3c\x66\x26",
                session_id: b"\x78\x56\x5b\x81\xda\x33\x85\x9c\x08\xa3\xd4\x1d\x32\xa0\xd6\x58\x98\x33\xdb\xae",
                iv_client: b"\x1b\x9e\x68\x98\x3b\x68\x64\x01",
                iv_server: b"\x62\x27\xba\x6c\x60\x5c\xf1\xc9",
                enc_client: b"\xad\xb5\x1e\x00\x41\xc3\x99\x8f\x70\x34\xbc\x55\x24\x06\x76\xee\x23\xc5\x55\x62\x68\x02\xc8\x7f",
                enc_server: b"\x01\x4b\xcb\x22\x18\x02\x6b\x51\xcf\x64\xee\x13\x34\xa8\x30\xe8\x13\xf6\x06\xbd\x70\x33\xbd\x39",
            },
            Vector {
                k: b"\x00\x00\x01\x01\x00\xd9\x40\x79\x36\x2d\xde\x4b\xa3\xbb\xef\x72\x21\xc0\x77\xc7\x88\xfd\x97\x9a\x78\x0d\xc6\x6c\x26\x60\x5c\xa1\xf6\x41\xed\xa1\x36\x6b\x65\x5f\x45\xa0\xde\xdb\xa4\xc1\x61\x37\x83\x91\xa6\xfc\x6c\xf6\x4e\x86\xce\x0a\x93\xb8\x38\x85\x1a\x15\x09\x83\x0c\x04\xf2\x73\x03\xc8\xbc\xe3\xbe\xd7\x84\x66\xa5\x0c\xc6\xff\xf2\x40\x75\x65\x24\x03\x46\xe0\x14\x3a\x33\x22\x43\x03\x77\x62\x41\x4a\xcd\x27\x36\x75\xd2\x1b\x62\x91\xf9\x94\x66\xe3\x44\xc7\xdb\x7b\x89\x91\x77\x4b\xcd\xda\x2c\x29\xe8\xd5\xe3\x1e\x75\xb8\x6b\xea\x49\xea\xd3\xa1\x7b\x7b\xd2\xed\xb1\xf2\xdd\x73\x09\xfd\x0f\x17\x41\xb8\xbb\xe3\x4d\x8b\x34\xa1\xc9\xb1\xf1\xa4\x09\x13\x83\xd7\x08\x70\xe0\x54\xdf\x1c\x34\x45\x75\xc5\xd6\x02\x7b\xf6\xdb\xd9\x7a\xed\x32\xf9\x8f\x74\x5b\x29\x3f\xb3\xbe\xaf\xc0\x48\xb3\x87\xf4\x58\x69\xe5\xd7\x8a\x05\x73\xb1\x4b\x57\xa9\xb5\x74\x54\x87\x61\xb1\xec\xbc\x9b\x78\x30\x71\x56\xb7\xde\xe4\x8f\xe6\x90\xcd\x6e\x8b\x76\xd0\x7e\x3d\x8b\x66\xa9\xcd\x71\xc0\xe6\xb2\xe1\x1e\x98\x4e\x96\x51\x15\x21\x13\x6a\x29\xe7\x23\x62\xf1\xae\x40\x22\x0c",
                h: b"\x7d\x18\xe0\x43\x0a\x48\x53\x71\x17\x6a\x45\xa0\xcb\x00\x0c\x99\x2d\xd4\x27\x53",
                session_id: b"\x7b\x64\x6a\xc6\x50\xba\xed\x2b\xad\x29\x2e\xc3\xaa\x9e\x32\xb1\xc4\x49\xa5\xe8",
                iv_client: b"\x23\xa5\x7f\x18\x29\xdb\xac\xb2",
                iv_server: b"\xa6\xac\x05\x94\xb6\xd6\x3f\xb8",
                enc_client: b"\x53\x9e\xe1\x32\x6c\x2f\xa1\x1f\x4c\xc8\xd5\xcd\x27\xd7\x93\x0e\xb0\x5c\x1a\x69\xe1\x97\xa1\x30",
                enc_server: b"\xb0\xa8\x3c\xd0\xae\x7d\xf0\x89\xe9\x73\x7a\x82\x24\x19\xe6\x60\xa3\x37\x81\x41\x55\x2e\xbc\x49",
            },
            Vector {
                k: b"\x00\x00\x01\x00\x01\xc4\x1b\x85\xa5\x43\xcd\xb1\xad\xb2\x0b\xe9\x2f\x51\x22\xbc\x91\x3f\x43\x7d\x4c\x2f\x93\xef\x60\x7c\x35\xc8\xb1\xd8\x6d\x9e\xaf\xff\x59\xa9\x30\x4e\x2f\x5c\x9b\xe4\xac\x4a\x16\x7d\x7a\xa6\x7c\x21\xf1\x8a\x8b\xba\xa4\x5b\x6d\x4c\xd4\xd5\xa0\x68\x96\x59\xfd\x22\x66\xaa\xf7\x9e\xdd\x82\xc9\xcf\x37\xf1\x8b\x00\x3b\x34\x51\xd5\x31\x48\x32\x6b\xc1\x16\xa9\x51\x47\x0e\xd0\xf9\x2b\xd3\xd6\x37\x4b\x51\xb1\xcc\x7b\xad\x69\x23\xf6\x4d\xd0\x4e\xac\xb5\x5a\xa5\xce\xcb\x3c\x6c\x91\x48\x74\x18\x76\x73\x4c\x47\xa5\xbf\x1c\x08\x3f\x38\xb5\x96\xd9\x20\xa1\x6d\xb4\xc3\xb4\x35\x2f\x20\xc4\x94\x55\x76\xb9\x48\xdc\x15\x6f\x00\xe8\x8b\xec\x1c\x1b\x1e\xe7\xaa\x83\xff\x6e\x71\x49\xb0\x1b\x88\x13\x18\x81\x01\x49\x5c\xa4\x62\x90\x68\x65\x8d\x6a\x9f\x08\xae\xa9\xff\x47\xf4\xa9\xb5\x85\x36\xc5\xfd\x92\xd3\x82\x55\xfc\xbb\x03\x23\xe7\xe4\xc3\x19\xff\x2f\x80\x95\xd2\xa1\x54\xac\xa8\x15\xd3\xf1\xc6\x46\x6c\x1f\xac\xfb\xfc\x45\x1b\x49\x8b\x24\xf8\x62\x09\xba\x39\x12\xb5\xdb\x9f\x70\x45\xb3\x14\x55\xb1\x82\x7c\xe0\x47\x1d\xf7\x7b\xb7\x06",
                h: b"\x86\x74\xbd\xf0\x19\x1e\x98\x7d\xb7\x27\x1d\xfe\x70\xb3\x6f\x18\x1d\xec\x0b\xa4",
                session_id: b"\x4c\x78\x22\x56\x72\xa7\x2d\xce\xd3\xda\xd7\xf1\xfb\x00\x2b\xba\x93\xc5\xd0\x08",
                iv_client: b"\xbb\x0b\xec\xc9\x96\x85\x54\xf8",
                iv_server: b"\x26\x2d\xbf\xba\x6a\x41\xe6\xaa",
                enc_client: b"\x53\xaf\xfb\x77\x48\x8b\x7b\xaa\xf1\x9d\xe1\xf6\xf5\xb1\x4d\x32\x26\x75\x79\xd5\x2c\xa8\x34\xef",
                enc_server: b"\x8d\xc0\xa0\x1a\xcb\x41\xaa\x25\xe0\xe0\x68\xd3\x5e\x88\xc1\x7e\x5b\x3a\xa6\x7b\x07\x39\x89\x9a",
            },
        ];

        check_vectors(&TestSha1, vectors);
    }

    fn check_vectors(hash: &'static dyn Hash, vectors: &[Vector]) {
        for vector in vectors {
            let derivation = KeyDerivation {
                hash,
                // `vector.k` is already the shared secret as an mpint (with its length
                // prefix), which is exactly the encoded form fed into the KDF.
                shared_secret: SharedSecret(vector.k.to_vec()),
                exchange_hash: Digest::new(vector.h),
                session_id: Digest::new(vector.session_id),
            };

            let iv_c = derivation.key(KeyInput::InitialIvClientToServer).derive(8);
            assert_eq!(iv_c, vector.iv_client);
            let iv_s = derivation.key(KeyInput::InitialIvServerToClient).derive(8);
            assert_eq!(iv_s, vector.iv_server);
            let enc_c = derivation
                .key(KeyInput::EncryptionKeyClientToServer)
                .derive(24);
            assert_eq!(enc_c, vector.enc_client);
            let enc_s = derivation
                .key(KeyInput::EncryptionKeyServerToClient)
                .derive(24);
            assert_eq!(enc_s, vector.enc_server);
        }
    }

    /// A pure-Rust SHA-1 [`Hash`] used only to exercise the KDF in tests.
    struct TestSha1;

    impl Hash for TestSha1 {
        fn start(&self) -> Box<dyn HashContext> {
            Box::new(TestSha1Context(Sha1::new()))
        }

        fn output_len(&self) -> usize {
            20
        }
    }

    struct TestSha1Context(Sha1);

    impl HashContext for TestSha1Context {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        fn fork(&self) -> Box<dyn HashContext> {
            Box::new(Self(self.0.clone()))
        }

        fn finish(self: Box<Self>) -> Digest {
            Digest::new(self.0.finalize().as_slice())
        }
    }

    /// One NIST ACVP SSH KDF vector: `k`, `h`, `session_id`, then the four derived
    /// outputs we can check (initial IV and encryption key, each direction).
    ///
    /// `k` is the shared secret as an SSH mpint (RFC 4251), including its 4-byte length
    /// prefix; we strip that prefix to recover the raw integer `KeyDerivation` re-encodes.
    struct Vector {
        k: &'static [u8],
        h: &'static [u8],
        session_id: &'static [u8],
        iv_client: &'static [u8],
        iv_server: &'static [u8],
        enc_client: &'static [u8],
        enc_server: &'static [u8],
    }
}
