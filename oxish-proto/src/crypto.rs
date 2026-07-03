use core::{error::Error as StdError, fmt};
use std::sync::Arc;

use crate::named::{EncryptionAlgorithm, KeyExchangeAlgorithm, MacAlgorithm, PublicKeyAlgorithm};

/// A bundle of cryptographic algorithm implementations
pub trait CryptoProvider: Send + Sync {
    /// Generate a fresh signing key
    ///
    /// Returns the key together with its PKCS#8 serialization, so the caller can
    /// persist it and load it again later with [`Self::host_key_from_pkcs8()`].
    fn generate_signing_key(
        &self,
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<(Arc<dyn SigningKey>, Vec<u8>), Error>;

    /// Load a signing key from its PKCS#8 serialization
    fn signing_key_from_pkcs8(&self, pkcs8: &[u8]) -> Result<Arc<dyn SigningKey>, Error>;

    /// Build a public key that can verify signatures for `algorithm`
    ///
    /// `key` is the raw public key material. Returns `Err` if the algorithm is not supported.
    fn verifying_key(
        &self,
        key: &[u8],
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<Arc<dyn VerifyingKey>, Error>;

    /// The transport cipher
    ///
    /// Returns `Err` if the algorithm is not supported.
    fn cipher(&self, algorithm: &EncryptionAlgorithm<'_>) -> Result<&'static dyn Cipher, Error>;

    /// The key exchange group
    ///
    /// Returns `Err` if the algorithm is not supported.
    fn key_exchange(
        &self,
        algorithm: &KeyExchangeAlgorithm<'_>,
    ) -> Result<&'static dyn KeyExchange, Error>;

    /// The MAC used to protect transport packets
    ///
    /// Returns `Err` if the algorithm is not supported.
    fn hmac(&self, algorithm: &MacAlgorithm<'_>) -> Result<&'static dyn Hmac, Error>;

    /// The hash function used for the exchange hash and key derivation
    ///
    /// Returns `Err` if the algorithm is not supported.
    fn hash(&self, algorithm: &KeyExchangeAlgorithm<'_>) -> Result<&'static dyn Hash, Error>;

    /// A source of cryptographically secure random bytes
    fn secure_random(&self) -> &'static dyn SecureRandom;
}

/// A symmetric cipher
pub trait Cipher: Send + Sync {
    /// Build an encryption state from `key` and `iv`
    fn encrypter(&self, key: &[u8], iv: &[u8]) -> Box<dyn Encrypter>;

    /// Build a decryption state from `key` and `iv`
    fn decrypter(&self, key: &[u8], iv: &[u8]) -> Box<dyn Decrypter>;

    /// The cipher's block length in bytes
    fn block_len(&self) -> usize;

    /// The length in bytes of the key this cipher expects
    fn key_len(&self) -> usize;

    /// The length in bytes of the IV this cipher expects
    fn iv_len(&self) -> usize;
}

/// An in-progress encryption, produced by [`Cipher::encrypter`]
pub trait Encrypter: Send {
    /// Encrypt `input` (a whole number of blocks) into `output` (same length)
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]);

    /// The cipher's block length in bytes
    fn block_len(&self) -> usize;
}

/// An in-progress decryption, produced by [`Cipher::decrypter`]
pub trait Decrypter: Send {
    /// Decrypt `input` (a whole number of blocks) into `output` (same length)
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]);

    /// The cipher's block length in bytes
    fn block_len(&self) -> usize;
}

/// A keyed MAC algorithm
pub trait Hmac: Send + Sync {
    /// Prepare to use `key` as a MAC key
    fn with_key(&self, key: &[u8]) -> Box<dyn HmacKey>;

    /// The length in bytes of the tags produced by this algorithm
    fn output_len(&self) -> usize;
}

/// A MAC key that is ready for use
pub trait HmacKey: Send + Sync {
    /// Compute a tag over the concatenation of the slices in `data`
    fn sign(&self, data: &[&[u8]]) -> Tag;

    /// Verify, in constant time, that `tag` matches a fresh computation over `data`
    fn verify(&self, data: &[&[u8]], tag: &[u8]) -> bool;

    /// The length in bytes of the tags produced by this key
    fn tag_len(&self) -> usize;
}

/// A MAC tag, stored inline
#[derive(Clone, Copy)]
pub struct Tag {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl Tag {
    /// Build a `Tag` from a slice of no more than [`Self::MAX_LEN`] bytes
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= Self::MAX_LEN);
        let mut buf = [0; Self::MAX_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Self {
            buf,
            used: bytes.len(),
        }
    }

    /// Maximum supported tag size: enough for HMAC-SHA512
    pub const MAX_LEN: usize = 64;
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
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
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error>;
}

/// An in-progress key exchange, produced by [`KeyExchange::start`]
pub trait ActiveKeyExchange: Send {
    /// Our ephemeral public key, to be sent to the peer
    fn public_key(&self) -> &[u8];

    /// Complete the exchange using the peer's public key, returning the shared secret
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<Vec<u8>, Error>;
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
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// A source of cryptographically secure randomness.
pub trait SecureRandom: Send + Sync {
    /// Fill `buf` with random bytes
    fn fill(&self, buf: &mut [u8]) -> Result<(), Error>;
}

/// An error returned by a cryptographic operation
#[derive(Clone, Copy, Debug)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cryptographic operation failed")
    }
}

impl StdError for Error {}
