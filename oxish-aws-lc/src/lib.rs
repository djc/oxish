use std::sync::Arc;

use ::aws_lc_rs::{
    agreement::{self, EphemeralPrivateKey, X25519},
    cipher::{
        self, DecryptionContext, EncryptionContext, StreamingDecryptingKey, StreamingEncryptingKey,
        UnboundCipherKey,
    },
    constant_time, digest, hmac, rand,
    signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use proto::{
    EncryptionAlgorithm, KeyExchangeAlgorithm, MacAlgorithm, PublicKeyAlgorithm,
    crypto::{
        ActiveKeyExchange, Cipher, CryptoError, CryptoProvider, Decrypter, Digest, Encrypter, Hash,
        HashContext, Hmac, HmacKey, KeyExchange, SecureRandom, SigningKey, Tag, VerifyingKey,
    },
};

pub const DEFAULT_PROVIDER: &'static dyn CryptoProvider = &Provider;

/// The aws-lc-rs [`CryptoProvider`].
#[derive(Clone, Copy, Debug)]
struct Provider;

impl CryptoProvider for Provider {
    fn generate_signing_key(
        &self,
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<(Arc<dyn SigningKey>, Vec<u8>), CryptoError> {
        match algorithm {
            PublicKeyAlgorithm::Ed25519 => {
                let key_pair =
                    Ed25519KeyPair::generate().map_err(|_| CryptoError::KeyGenerationFailed)?;

                let pkcs8 = key_pair
                    .to_pkcs8v1()
                    .map_err(|_| CryptoError::Unspecified)?
                    .as_ref()
                    .to_vec();

                Ok((Arc::new(Ed25519SigningKey::new(key_pair)), pkcs8))
            }
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn signing_key_from_pkcs8(&self, pkcs8: &[u8]) -> Result<Arc<dyn SigningKey>, CryptoError> {
        Ok(Arc::new(Ed25519SigningKey::new(
            Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| CryptoError::KeyRejected)?,
        )))
    }

    fn verifying_key(
        &self,
        key: &[u8],
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<Arc<dyn VerifyingKey>, CryptoError> {
        match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => Ok(Arc::new(EcdsaP256VerifyingKey {
                key: UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key.to_owned()),
            })),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn cipher(
        &self,
        algorithm: &EncryptionAlgorithm<'_>,
    ) -> Result<&'static dyn Cipher, CryptoError> {
        match algorithm {
            EncryptionAlgorithm::Aes128Ctr => Ok(&Aes128Ctr),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn key_exchange(
        &self,
        algorithm: &KeyExchangeAlgorithm<'_>,
    ) -> Result<&'static dyn KeyExchange, CryptoError> {
        match algorithm {
            KeyExchangeAlgorithm::Curve25519Sha256 => Ok(&X25519Kx),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn hmac(&self, algorithm: &MacAlgorithm<'_>) -> Result<&'static dyn Hmac, CryptoError> {
        match algorithm {
            MacAlgorithm::HmacSha2256 => Ok(&HmacSha256),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn hash(&self, algorithm: &KeyExchangeAlgorithm<'_>) -> Result<&'static dyn Hash, CryptoError> {
        match algorithm {
            KeyExchangeAlgorithm::Curve25519Sha256 => Ok(&Sha256),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn secure_random(&self) -> &'static dyn SecureRandom {
        &SystemRandom
    }
}

struct Aes128Ctr;

impl Aes128Ctr {
    const BLOCK_LEN: usize = 16;
    const KEY_LEN: usize = 16;
    const IV_LEN: usize = 16;
}

impl Cipher for Aes128Ctr {
    fn encrypter(&self, key: &[u8], iv: &[u8]) -> Box<dyn Encrypter> {
        let iv: [u8; Self::IV_LEN] = iv.try_into().expect("iv length");
        let key = StreamingEncryptingKey::less_safe_ctr(
            UnboundCipherKey::new(&cipher::AES_128, key).expect("aes-128 key"),
            EncryptionContext::Iv128(iv.into()),
        )
        .expect("aes-128-ctr encrypter");
        Box::new(Aes128CtrEncrypter {
            key,
            scratch: Vec::new(),
        })
    }

    fn decrypter(&self, key: &[u8], iv: &[u8]) -> Box<dyn Decrypter> {
        let iv: [u8; Self::IV_LEN] = iv.try_into().expect("iv length");
        let key = StreamingDecryptingKey::ctr(
            UnboundCipherKey::new(&cipher::AES_128, key).expect("aes-128 key"),
            DecryptionContext::Iv128(iv.into()),
        )
        .expect("aes-128-ctr decrypter");
        Box::new(Aes128CtrDecrypter(key))
    }

    fn block_len(&self) -> usize {
        Self::BLOCK_LEN
    }

    fn key_len(&self) -> usize {
        Self::KEY_LEN
    }

    fn iv_len(&self) -> usize {
        Self::IV_LEN
    }
}

struct Aes128CtrEncrypter {
    key: StreamingEncryptingKey,
    /// aws-lc-rs requires an output buffer up to one block larger than the
    /// input; we encrypt into this scratch buffer and copy back the written
    /// bytes (of which, for CTR, there are exactly `input.len()`).
    scratch: Vec<u8>,
}

impl Encrypter for Aes128CtrEncrypter {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        self.scratch.resize(input.len() + Aes128Ctr::BLOCK_LEN, 0);
        let update = self
            .key
            .update(input, &mut self.scratch)
            .expect("aes-128-ctr update");
        let written = update.written().len();
        debug_assert_eq!(written, output.len());
        output.copy_from_slice(&self.scratch[..written]);
    }

    fn block_len(&self) -> usize {
        Aes128Ctr::BLOCK_LEN
    }
}

struct Aes128CtrDecrypter(StreamingDecryptingKey);

impl Decrypter for Aes128CtrDecrypter {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        // It is fine to use `less_safe_update` as we always decrypt whole blocks at a time
        let update = self
            .0
            .less_safe_update(input, output)
            .expect("aes-128-ctr update");
        debug_assert_eq!(update.remainder().len(), 0);
    }

    fn block_len(&self) -> usize {
        Aes128Ctr::BLOCK_LEN
    }
}

struct X25519Kx;

impl KeyExchange for X25519Kx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let random = rand::SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &random)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;

        let public_key = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::Unspecified)?;

        Ok(Box::new(X25519KeyExchange {
            private_key,
            public_key: public_key.as_ref().to_vec(),
        }))
    }
}

struct X25519KeyExchange {
    private_key: EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl ActiveKeyExchange for X25519KeyExchange {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let peer = agreement::UnparsedPublicKey::new(&X25519, peer_public_key);
        agreement::agree_ephemeral(
            self.private_key,
            peer,
            CryptoError::KeyAgreementFailed,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
    }
}

struct Ed25519SigningKey {
    key_pair: Ed25519KeyPair,
    public_key: Vec<u8>,
}

impl Ed25519SigningKey {
    fn new(key_pair: Ed25519KeyPair) -> Self {
        let public_key = key_pair.public_key().as_ref().to_vec();
        Self {
            key_pair,
            public_key,
        }
    }
}

impl SigningKey for Ed25519SigningKey {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message).as_ref().to_vec()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm<'static> {
        PublicKeyAlgorithm::Ed25519
    }
}

struct EcdsaP256VerifyingKey {
    key: UnparsedPublicKey<Vec<u8>>,
}

impl VerifyingKey for EcdsaP256VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.key
            .verify(message, signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

struct HmacSha256;

impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn HmacKey> {
        Box::new(HmacSha256Key(hmac::Key::new(hmac::HMAC_SHA256, key)))
    }

    fn output_len(&self) -> usize {
        digest::SHA256.output_len()
    }
}

struct HmacSha256Key(hmac::Key);

impl HmacSha256Key {
    fn compute(&self, data: &[&[u8]]) -> hmac::Tag {
        let mut context = hmac::Context::with_key(&self.0);
        for slice in data {
            context.update(slice);
        }
        context.sign()
    }
}

impl HmacKey for HmacSha256Key {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        Tag::new(self.compute(data).as_ref())
    }

    fn verify(&self, data: &[&[u8]], tag: &[u8]) -> bool {
        constant_time::verify_slices_are_equal(self.compute(data).as_ref(), tag).is_ok()
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().digest_algorithm().output_len
    }
}

struct Sha256;

impl Hash for Sha256 {
    fn start(&self) -> Box<dyn HashContext> {
        Box::new(Sha256Context(digest::Context::new(&digest::SHA256)))
    }

    fn output_len(&self) -> usize {
        digest::SHA256.output_len()
    }
}

struct Sha256Context(digest::Context);

impl HashContext for Sha256Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn fork(&self) -> Box<dyn HashContext> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Digest {
        Digest::new(self.0.finish().as_ref())
    }
}

struct SystemRandom;

impl SecureRandom for SystemRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        rand::fill(buf).map_err(|_| CryptoError::NoRandomness)
    }
}
