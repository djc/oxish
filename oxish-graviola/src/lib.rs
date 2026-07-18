use std::sync::Arc;

use graviola::{
    aead::AesGcm,
    hashing::{Hash as GHash, HashContext as GHashContext, Sha256 as GSha256},
    key_agreement::{mlkem768, p256::StaticPrivateKey, x25519},
    random,
    signing::{
        ecdsa::{self, P256},
        eddsa::{Ed25519SigningKey, Ed25519VerifyingKey as GEd25519VerifyingKey},
    },
};
use proto::{
    EncryptionAlgorithm, KeyExchangeAlgorithm, MacAlgorithm, PublicKeyAlgorithm,
    crypto::{
        ActiveKeyExchange, AgreedKey, CryptoError, CryptoProvider, Digest, Hash, HashContext,
        KeyExchange, KeySourceSide, OpeningKey, SealingKey, SecureRandom, SharedSecret, SigningKey,
        SupportedAlgorithms, VerifyingKey,
    },
};

pub const DEFAULT_PROVIDER: &'static dyn CryptoProvider = &Provider;

/// The graviola [`CryptoProvider`].
#[derive(Clone, Copy, Debug)]
struct Provider;

impl CryptoProvider for Provider {
    fn generate_signing_key(
        &self,
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<(Arc<dyn SigningKey>, Vec<u8>), CryptoError> {
        match algorithm {
            PublicKeyAlgorithm::Ed25519 => {
                let key =
                    Ed25519SigningKey::generate().map_err(|_| CryptoError::KeyGenerationFailed)?;

                // An Ed25519 PKCS#8 v2 document (with the embedded public key) is
                // well under 128 bytes.
                let mut buf = [0u8; 128];
                let pkcs8 = key
                    .to_pkcs8_der(&mut buf)
                    .map_err(|_| CryptoError::Unspecified)?
                    .to_vec();

                Ok((Arc::new(Ed25519Key::new(key)), pkcs8))
            }
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let private_key =
                    StaticPrivateKey::new_random().map_err(|_| CryptoError::KeyGenerationFailed)?;
                let key = ecdsa::SigningKey::<P256> { private_key };

                // A P-256 PKCS#8 v1 document (with the embedded public key) is
                // comfortably under 256 bytes.
                let mut buf = [0u8; 256];
                let pkcs8 = key
                    .to_pkcs8_der(&mut buf)
                    .map_err(|_| CryptoError::Unspecified)?
                    .to_vec();

                Ok((Arc::new(EcdsaP256Key::new(key)), pkcs8))
            }
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn signing_key_from_pkcs8(&self, pkcs8: &[u8]) -> Result<Arc<dyn SigningKey>, CryptoError> {
        // The PKCS#8 algorithm identifier distinguishes the key type; each loader
        // validates it, so try Ed25519 first and fall back to ECDSA P-256.
        if let Ok(key) = Ed25519SigningKey::from_pkcs8_der(pkcs8) {
            return Ok(Arc::new(Ed25519Key::new(key)));
        }

        let key = ecdsa::SigningKey::<P256>::from_pkcs8_der(pkcs8)
            .map_err(|_| CryptoError::KeyRejected)?;
        Ok(Arc::new(EcdsaP256Key::new(key)))
    }

    fn verifying_key(
        &self,
        key: &[u8],
        algorithm: &PublicKeyAlgorithm<'_>,
    ) -> Result<Arc<dyn VerifyingKey>, CryptoError> {
        match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => Ok(Arc::new(EcdsaP256VerifyingKey(
                ecdsa::VerifyingKey::<P256>::from_x962_uncompressed(key)
                    .map_err(|_| CryptoError::KeyRejected)?,
            ))),
            PublicKeyAlgorithm::Ed25519 => Ok(Arc::new(Ed25519VerifyingKey(
                GEd25519VerifyingKey::from_bytes(key).map_err(|_| CryptoError::KeyRejected)?,
            ))),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn opening_key(
        &self,
        counter: u64,
        source: &KeySourceSide,
    ) -> Result<Box<dyn OpeningKey>, CryptoError> {
        match source.algorithm {
            EncryptionAlgorithm::Aes128Gcm => {
                Ok(Box::new(Aes128GcmOpener(GcmState::new(counter, source)?)))
            }
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn sealing_key(
        &self,
        counter: u64,
        source: &KeySourceSide,
    ) -> Result<Box<dyn SealingKey>, CryptoError> {
        match source.algorithm {
            EncryptionAlgorithm::Aes128Gcm => {
                Ok(Box::new(Aes128GcmSealer(GcmState::new(counter, source)?)))
            }
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

    fn supported_algorithms(&self) -> SupportedAlgorithms {
        SupportedAlgorithms {
            key_exchange: &[KeyExchangeAlgorithm::MlKem768X25519Sha256],
            public_key: &[
                PublicKeyAlgorithm::EcdsaSha2Nistp256,
                PublicKeyAlgorithm::Ed25519,
            ],
            encryption: &[EncryptionAlgorithm::Aes128Gcm],
            mac: &[MacAlgorithm::None],
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

        let Some(tag) = tag.first_chunk_mut::<TAG_LEN>() else {
            return Err(CryptoError::InvalidLength);
        };

        // The cleartext packet length is authenticated as associated data.
        self.0.key.encrypt(&nonce, length, plaintext, tag);
        Ok(())
    }

    fn counter(&self) -> u64 {
        self.0.counter
    }

    fn block_len(&self) -> usize {
        16
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
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
            .decrypt(&nonce, length, ciphertext, tag)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn decrypt_packet_length(&mut self, _seq: u32, encrypted: [u8; 4]) -> [u8; 4] {
        // The packet length is transmitted in cleartext (authenticated as AAD).
        encrypted
    }

    fn counter(&self) -> u64 {
        self.0.counter
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Shared AES-128-GCM state: the key and the current 12-byte nonce
struct GcmState {
    key: AesGcm,
    nonce: [u8; NONCE_LEN],
    counter: u64,
}

impl GcmState {
    fn new(counter: u64, source: &KeySourceSide) -> Result<Self, CryptoError> {
        let mut new = Self {
            key: AesGcm::new(&source.encryption_key.derive::<16>()),
            nonce: source.initial_iv.derive::<NONCE_LEN>(),
            counter,
        };
        new.increment(counter)?;
        Ok(new)
    }

    /// Return the nonce for the next packet and advance the invocation counter
    ///
    /// <https://www.rfc-editor.org/rfc/rfc5647#section-7.1>: the low 8 bytes form a
    /// big-endian invocation counter that is incremented after each packet.
    fn nonce(&mut self) -> Result<[u8; NONCE_LEN], CryptoError> {
        let nonce = self.nonce;
        self.increment(1)?;
        Ok(nonce)
    }

    fn increment(&mut self, delta: u64) -> Result<(), CryptoError> {
        let Some(counter_dst) = self.nonce.last_chunk_mut::<8>() else {
            return Err(CryptoError::InvalidLength);
        };

        let Some(new) = u64::from_be_bytes(*counter_dst).checked_add(delta) else {
            return Err(CryptoError::NonceOverflow);
        };

        *counter_dst = new.to_be_bytes();
        self.counter += delta;
        Ok(())
    }
}

/// The `mlkem768x25519-sha256` PQ-hybrid key exchange
struct Mlkem768X25519Kx;

impl KeyExchange for Mlkem768X25519Kx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        Ok(Box::new(Mlkem768X25519KeyExchange))
    }
}

struct Mlkem768X25519KeyExchange;

impl ActiveKeyExchange for Mlkem768X25519KeyExchange {
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<AgreedKey, CryptoError> {
        // `C_INIT` = ML-KEM-768 encapsulation key || X25519 public key
        let Some((encaps_key, peer_x25519)) = peer_public_key.split_first_chunk() else {
            return Err(CryptoError::InvalidLength);
        };

        let encaps_key = mlkem768::EncapKey::from_bytes(encaps_key)
            .map_err(|_| CryptoError::KeyAgreementFailed)?;
        let (pq_secret, ciphertext) = encaps_key
            .encaps()
            .map_err(|_| CryptoError::KeyAgreementFailed)?;

        let x25519_private =
            x25519::PrivateKey::new_random().map_err(|_| CryptoError::NoRandomness)?;
        let x25519_public = x25519_private.public_key().as_bytes();
        let peer =
            x25519::PublicKey::try_from_slice(peer_x25519).map_err(|_| CryptoError::KeyRejected)?;
        let shared = x25519_private
            .diffie_hellman(&peer)
            .map_err(|_| CryptoError::KeyAgreementFailed)?;
        let classic_secret = shared.as_bytes().to_vec();

        // K = SHA256(K_PQ || K_CL)
        let mut context = GSha256::new();
        context.update(pq_secret.as_ref());
        context.update(&classic_secret);
        let shared_secret = SharedSecret::from(context.finish().as_ref().to_vec());

        // `S_REPLY` = ML-KEM-768 ciphertext || X25519 public key
        let mut public_key = Vec::with_capacity(ciphertext.as_ref().len() + x25519_public.len());
        public_key.extend_from_slice(ciphertext.as_ref());
        public_key.extend_from_slice(&x25519_public);

        Ok(AgreedKey {
            public_key,
            shared_secret,
        })
    }
}

struct Ed25519Key {
    key: Ed25519SigningKey,
    public_key: Vec<u8>,
}

impl Ed25519Key {
    fn new(key: Ed25519SigningKey) -> Self {
        let public_key = key.public_key().as_bytes().to_vec();
        Self { key, public_key }
    }
}

impl SigningKey for Ed25519Key {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).to_vec()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm<'static> {
        PublicKeyAlgorithm::Ed25519
    }
}

struct EcdsaP256Key {
    key: ecdsa::SigningKey<P256>,
    public_key: Vec<u8>,
}

impl EcdsaP256Key {
    fn new(key: ecdsa::SigningKey<P256>) -> Self {
        let public_key = key.private_key.public_key_uncompressed().to_vec();
        Self { key, public_key }
    }
}

impl SigningKey for EcdsaP256Key {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        // ECDSA over P-256 with SHA-256 produces a fixed-length `r || s`
        // signature (32 bytes each); the SSH mpint framing is applied by the
        // protocol layer.
        let mut signature = [0u8; 64];
        match self.key.sign::<GSha256>(&[message], &mut signature) {
            Ok(signature) => signature.to_vec(),
            Err(_) => Vec::new(),
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> PublicKeyAlgorithm<'static> {
        PublicKeyAlgorithm::EcdsaSha2Nistp256
    }
}

struct EcdsaP256VerifyingKey(ecdsa::VerifyingKey<P256>);

impl VerifyingKey for EcdsaP256VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        // The SSH ecdsa-sha2-nistp256 signature has already been converted to the
        // fixed-length r||s encoding graviola expects.
        self.0
            .verify::<GSha256>(&[message], signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

struct Ed25519VerifyingKey(GEd25519VerifyingKey);

impl VerifyingKey for Ed25519VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.0
            .verify(signature, message)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

struct Sha256;

impl Hash for Sha256 {
    fn start(&self) -> Box<dyn HashContext> {
        Box::new(Sha256Context(GSha256::new()))
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Sha256Context(<GSha256 as GHash>::Context);

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
        random::fill(buf).map_err(|_| CryptoError::NoRandomness)
    }
}
