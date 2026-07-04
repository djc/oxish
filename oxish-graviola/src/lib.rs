use std::sync::Arc;

use graviola::{
    aead::AesGcm,
    hashing::{Hash as GHash, HashContext as GHashContext, Sha256 as GSha256},
    key_agreement::x25519,
    random,
    signing::{
        ecdsa::{self, P256},
        eddsa::Ed25519SigningKey,
    },
};
use proto::{
    EncryptionAlgorithm, KeyExchangeAlgorithm, PublicKeyAlgorithm,
    crypto::{
        ActiveKeyExchange, CryptoError, CryptoProvider, Digest, Hash, HashContext, KeyExchange,
        KeySourceSide, OpeningKey, SealingKey, SecureRandom, SigningKey, VerifyingKey,
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
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn signing_key_from_pkcs8(&self, pkcs8: &[u8]) -> Result<Arc<dyn SigningKey>, CryptoError> {
        Ok(Arc::new(Ed25519Key::new(
            Ed25519SigningKey::from_pkcs8_der(pkcs8).map_err(|_| CryptoError::KeyRejected)?,
        )))
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
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn opening_key(
        &self,
        source: KeySourceSide,
        algorithm: &EncryptionAlgorithm<'_>,
    ) -> Result<Box<dyn OpeningKey>, CryptoError> {
        match algorithm {
            EncryptionAlgorithm::Aes128Gcm => Ok(Box::new(Aes128GcmOpener(GcmState::new(source)))),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }

    fn sealing_key(
        &self,
        source: KeySourceSide,
        algorithm: &EncryptionAlgorithm<'_>,
    ) -> Result<Box<dyn SealingKey>, CryptoError> {
        match algorithm {
            EncryptionAlgorithm::Aes128Gcm => Ok(Box::new(Aes128GcmSealer(GcmState::new(source)))),
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
}

impl GcmState {
    fn new(source: KeySourceSide) -> Self {
        Self {
            key: AesGcm::new(&source.encryption_key.derive::<16>()),
            nonce: source.initial_iv.derive::<NONCE_LEN>(),
        }
    }

    /// Return the nonce for the next packet and advance the invocation counter
    ///
    /// <https://www.rfc-editor.org/rfc/rfc5647#section-7.1>: the low 8 bytes form a
    /// big-endian invocation counter that is incremented after each packet.
    fn nonce(&mut self) -> Result<[u8; NONCE_LEN], CryptoError> {
        let nonce = self.nonce;
        let Some(counter) = self.nonce.last_chunk_mut::<8>() else {
            return Err(CryptoError::InvalidLength);
        };

        let Some(next) = u64::from_be_bytes(*counter).checked_add(1) else {
            return Err(CryptoError::NonceOverflow);
        };

        *counter = next.to_be_bytes();
        Ok(nonce)
    }
}

struct X25519Kx;

impl KeyExchange for X25519Kx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let private_key =
            x25519::PrivateKey::new_random().map_err(|_| CryptoError::KeyGenerationFailed)?;

        Ok(Box::new(X25519KeyExchange {
            public_key: private_key.public_key().as_bytes().to_vec(),
            private_key,
        }))
    }
}

struct X25519KeyExchange {
    private_key: x25519::PrivateKey,
    public_key: Vec<u8>,
}

impl ActiveKeyExchange for X25519KeyExchange {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let peer = x25519::PublicKey::try_from_slice(peer_public_key)
            .map_err(|_| CryptoError::KeyAgreementFailed)?;

        let shared = self
            .private_key
            .diffie_hellman(&peer)
            .map_err(|_| CryptoError::KeyAgreementFailed)?;

        Ok(shared.as_bytes().to_vec())
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
