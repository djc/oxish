//! Encode Signingkey to OpenSSH v1 private key format

use data_encoding::BASE64;
use zeroize::Zeroizing;

use crate::{
    Encode, ProtoError, PublicKeyAlgorithm, crypto::SigningKey, key_exchange::encode_mpint,
};

/// Encode SigningKey as an unencrypted OpenSSH v1 private key file
pub fn encode(key: &dyn SigningKey) -> Result<Zeroizing<String>, ProtoError> {
    /// Block size of the `none` cipher
    const BLOCK_SIZE: usize = 8;
    /// Check value, written twice at the head of the private section
    ///
    /// OpenSSH compares the two copies after decryption to detect a
    /// wrong passphrase; the value itself is not meaningful. This is
    /// ASCII "SSH1". If encryption is ever supported, generate this
    /// randomly instead, to avoid placing known plaintext at the
    /// start of the encrypted blob.
    const CHECK: u32 = 0x5353_4831;

    let pubkey = key.public_key();
    let Ok(seckey) = key.private_key() else {
        return Err(ProtoError::InvalidHostKey("key cannot be serialized"));
    };

    let mut private = Zeroizing::new(Vec::with_capacity(512));
    CHECK.encode(&mut private);
    CHECK.encode(&mut private);

    // The private key shares its leading fields with the public blob
    let mut public = Vec::new();
    match key.algorithm() {
        PublicKeyAlgorithm::Ed25519 => {
            if pubkey.len() != 32 || seckey.len() != 32 {
                return Err(ProtoError::InvalidHostKey("invalid ed25519 key"));
            }

            b"ssh-ed25519".as_slice().encode(&mut public);
            pubkey.encode(&mut public);
            private.extend_from_slice(&public);

            64u32.encode(&mut private);
            private.extend_from_slice(&seckey);
            private.extend_from_slice(pubkey);
        }
        PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
            b"ecdsa-sha2-nistp256".as_slice().encode(&mut public);
            b"nistp256".as_slice().encode(&mut public);
            pubkey.encode(&mut public);
            private.extend_from_slice(&public);

            encode_mpint(&seckey, &mut private);
        }
        PublicKeyAlgorithm::Unknown(_) => {
            return Err(ProtoError::InvalidHostKey("unsupported key type"));
        }
    }

    b"".as_slice().encode(&mut private); // comment

    let padding = private.len().next_multiple_of(BLOCK_SIZE) - private.len();
    for i in 0..padding {
        private.push((i + 1) as u8);
    }

    let mut blob = Zeroizing::new(Vec::with_capacity(private.len() + public.len() + 64));
    blob.extend_from_slice(b"openssh-key-v1\0");
    b"none".as_slice().encode(&mut blob); // ciphername
    b"none".as_slice().encode(&mut blob); // kdfname
    b"".as_slice().encode(&mut blob); // kdfoptions
    1u32.encode(&mut blob); // number of keys
    public.as_slice().encode(&mut blob);
    private.as_slice().encode(&mut blob);

    let base64 = Zeroizing::new(BASE64.encode(&blob));
    let mut out = Zeroizing::new(String::with_capacity(base64.len() + 128));

    out.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    let mut rest = base64.as_str();
    while !rest.is_empty() {
        // base64 is ASCII, so splitting on a byte index is safe
        let (line, tail) = rest.split_at(rest.len().min(70));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");

    Ok(out)
}
