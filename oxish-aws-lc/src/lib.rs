use std::sync::Arc;

use ::aws_lc_rs::{
    aead::{AES_128_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    agreement::{self, EphemeralPrivateKey, X25519},
    digest,
    kem::ML_KEM_768,
    rand,
    signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use aws_lc_rs::kem::EncapsulationKey;
use proto::{
    EncryptionAlgorithm, KeyExchangeAlgorithm, PublicKeyAlgorithm,
    crypto::{
        ActiveKeyExchange, AgreedKey, CryptoError, CryptoProvider, Digest, Hash, HashContext,
        KeyExchange, KeySourceSide, OpeningKey, SealingKey, SecureRandom, SharedSecret, SigningKey,
        VerifyingKey,
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

    fn opening_key(
        &self,
        source: KeySourceSide,
        algorithm: &EncryptionAlgorithm<'_>,
    ) -> Result<Box<dyn OpeningKey>, CryptoError> {
        match algorithm {
            EncryptionAlgorithm::Aes128Gcm => Ok(Box::new(Aes128GcmOpener(GcmState::new(source)?))),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn sealing_key(
        &self,
        source: KeySourceSide,
        algorithm: &EncryptionAlgorithm<'_>,
    ) -> Result<Box<dyn SealingKey>, CryptoError> {
        match algorithm {
            EncryptionAlgorithm::Aes128Gcm => Ok(Box::new(Aes128GcmSealer(GcmState::new(source)?))),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn key_exchange(
        &self,
        algorithm: &KeyExchangeAlgorithm<'_>,
    ) -> Result<&'static dyn KeyExchange, CryptoError> {
        match algorithm {
            KeyExchangeAlgorithm::MlKem768X25519Sha256 => Ok(&Mlkem768X25519Kx),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn hash(&self, algorithm: &KeyExchangeAlgorithm<'_>) -> Result<&'static dyn Hash, CryptoError> {
        match algorithm {
            KeyExchangeAlgorithm::MlKem768X25519Sha256 => Ok(&Sha256),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn secure_random(&self) -> &'static dyn SecureRandom {
        &SystemRandom
    }
}

struct Aes128GcmSealer(GcmState);

impl SealingKey for Aes128GcmSealer {
    fn seal_in_place(
        &mut self,
        _seq: u32,
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nonce = self.0.nonce()?;
        let Some((length, plaintext)) = data.split_at_mut_checked(4) else {
            return Err(CryptoError::InvalidLength);
        };

        let computed = self
            .0
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(length), plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        tag.copy_from_slice(computed.as_ref());
        Ok(())
    }

    fn block_len(&self) -> usize {
        16
    }

    fn tag_len(&self) -> usize {
        self.0.key.algorithm().tag_len()
    }
}

struct Aes128GcmOpener(GcmState);

impl OpeningKey for Aes128GcmOpener {
    fn open_in_place(&mut self, _seq: u32, data: &mut [u8], tag: &[u8]) -> Result<(), CryptoError> {
        let nonce = self.0.nonce()?;
        let Some((length, ciphertext)) = data.split_at_mut_checked(4) else {
            return Err(CryptoError::InvalidLength);
        };

        self.0
            .key
            .open_in_place_separate_tag(nonce, Aad::from(&length[..]), tag, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(())
    }

    fn decrypt_packet_length(&mut self, _seq: u32, encrypted: [u8; 4]) -> [u8; 4] {
        // The packet length is transmitted in cleartext (authenticated as AAD).
        encrypted
    }

    fn tag_len(&self) -> usize {
        self.0.key.algorithm().tag_len()
    }
}

/// Shared AES-128-GCM state: the key and the current 12-byte nonce
struct GcmState {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
}

impl GcmState {
    fn new(source: KeySourceSide) -> Result<Self, CryptoError> {
        Ok(Self {
            key: LessSafeKey::new(
                UnboundKey::new(&AES_128_GCM, &source.encryption_key.derive::<16>())
                    .map_err(|_| CryptoError::InvalidLength)?,
            ),
            nonce: source.initial_iv.derive::<NONCE_LEN>(),
        })
    }

    /// Return the nonce for the next packet and advance the invocation counter
    ///
    /// <https://www.rfc-editor.org/rfc/rfc5647#section-7.1>: the low 8 bytes form a
    /// big-endian invocation counter that is incremented after each packet.
    fn nonce(&mut self) -> Result<Nonce, CryptoError> {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        let Some((_, counter)) = self.nonce.split_first_chunk_mut::<4>() else {
            return Err(CryptoError::InvalidLength);
        };

        let Some((counter, rest)) = counter.split_first_chunk_mut::<8>() else {
            return Err(CryptoError::InvalidLength);
        };

        debug_assert!(rest.is_empty(), "nonce length is not 12 bytes");
        let count = u64::from_be_bytes(*counter);
        let Some(next) = count.checked_add(1) else {
            return Err(CryptoError::NonceOverflow);
        };

        *counter = next.to_be_bytes();
        Ok(nonce)
    }
}

/// The `mlkem768x25519-sha256` key exchange
struct Mlkem768X25519Kx;

impl KeyExchange for Mlkem768X25519Kx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        Ok(Box::new(Mlkem768X25519KeyExchange))
    }
}

struct Mlkem768X25519KeyExchange;

impl Mlkem768X25519KeyExchange {
    /// Length of an ML-KEM-768 encapsulation key
    const MLKEM768_ENCAPS_KEY_LEN: usize = 1184;
}

impl ActiveKeyExchange for Mlkem768X25519KeyExchange {
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<AgreedKey, CryptoError> {
        // `C_INIT` = ML-KEM-768 encapsulation key || X25519 public key
        let Some((encaps_key, peer_x25519)) =
            peer_public_key.split_at_checked(Self::MLKEM768_ENCAPS_KEY_LEN)
        else {
            return Err(CryptoError::InvalidLength);
        };

        let encaps_key =
            EncapsulationKey::new(&ML_KEM_768, encaps_key).map_err(|_| CryptoError::KeyRejected)?;
        let (ciphertext, pq_secret) = encaps_key
            .encapsulate()
            .map_err(|_| CryptoError::KeyAgreementFailed)?;

        let random = rand::SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &random)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        let classic_public_key = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::Unspecified)?
            .as_ref()
            .to_vec();

        let peer = agreement::UnparsedPublicKey::new(&X25519, peer_x25519);
        let classic_secret = agreement::agree_ephemeral(
            private_key,
            peer,
            CryptoError::KeyAgreementFailed,
            |shared_secret| Ok(shared_secret.to_vec()),
        )?;

        // K = SHA256(K_PQ || K_CL)
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(pq_secret.as_ref());
        context.update(&classic_secret);
        let shared_secret = SharedSecret::from(context.finish().as_ref().to_vec());

        // `S_REPLY` = ML-KEM-768 ciphertext || X25519 public key
        let mut public_key =
            Vec::with_capacity(ciphertext.as_ref().len() + classic_public_key.len());
        public_key.extend_from_slice(ciphertext.as_ref());
        public_key.extend_from_slice(&classic_public_key);

        Ok(AgreedKey {
            public_key,
            shared_secret,
        })
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
