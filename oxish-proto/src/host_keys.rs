use core::str::{self, FromStr};
use std::{fs, path::Path};

use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::{
    Decode, Decoded, Encode, ProtoError, PublicKeyAlgorithm,
    crypto::{CryptoError, CryptoProvider, SigningKey},
    key_exchange::Negotiated,
    named::Named,
};

/// The server's host keys, used to authenticate the key exchange
#[expect(clippy::type_complexity)]
pub struct HostKeys(Vec<(Zeroizing<Vec<u8>>, Box<dyn SigningKey>)>);

impl HostKeys {
    /// Find host keys in the given directory
    ///
    /// Scans `dir` (usually `/etc/ssh`) for files named `ssh_host_*_key` containing
    /// unencrypted private keys in the OpenSSH key format. Keys using algorithms not
    /// known to this implementation are skipped.
    pub fn from_dir(dir: &Path, provider: &dyn CryptoProvider) -> Result<Self, ProtoError> {
        let mut keys = Vec::new();
        let mut error = None;
        for entry in dir.read_dir()? {
            let Ok(entry) = entry else {
                debug!("skipping unreadable entry in host key directory");
                continue;
            };

            let Ok(ty) = entry.file_type() else {
                debug!(name = ?entry.file_name(), "skipping unreadable entry in host key directory");
                continue;
            };

            if !ty.is_file() {
                continue;
            }

            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };

            if !name.starts_with("ssh_host_") || !name.ends_with("_key") {
                continue;
            }

            let pem = match fs::read_to_string(entry.path()) {
                Ok(pem) => Zeroizing::new(pem),
                Err(e) => {
                    debug!(name, error = %e, "skipping unreadable host key file");
                    error = Some((ProtoError::Io(e), entry.path().to_owned()));
                    continue;
                }
            };

            let decoded = match OpenSshKeyV1::from_str(&pem) {
                Ok(keys) => keys,
                Err(e) => {
                    debug!(name, "skipping host key file with invalid format");
                    error = Some((e, entry.path().to_owned()));
                    continue;
                }
            };

            for pkcs8 in decoded.keys {
                let signing_key = provider.signing_key_from_pkcs8(&pkcs8)?;
                keys.push((pkcs8, signing_key));
            }

            if keys.len() >= Self::MAX_KEYS {
                return Err(ProtoError::TooManyHostKeys);
            }
        }

        if keys.is_empty() {
            return Err(match error {
                Some((error, path)) => {
                    warn!(?path, %error, "no valid host keys found in directory");
                    error
                }
                None => ProtoError::NoHostKeys,
            });
        }

        Ok(Self(keys))
    }

    /// Create a new set of host keys from the given PKCS#8 private keys
    ///
    /// `pkcs8` must have more than 0 and less than 16 elements.
    pub fn new(
        pkcs8: impl Iterator<Item = Zeroizing<Vec<u8>>>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, ProtoError> {
        let mut keys = Vec::new();
        for pkcs8 in pkcs8 {
            if keys.len() >= Self::MAX_KEYS {
                return Err(ProtoError::TooManyHostKeys);
            }

            let signing_key = provider.signing_key_from_pkcs8(&pkcs8)?;
            keys.push((pkcs8, signing_key));
        }

        if keys.is_empty() {
            return Err(ProtoError::NoHostKeys);
        }

        Ok(Self(keys))
    }

    /// Select the host key matching the negotiated algorithm
    pub fn key<'a>(&'a self, negotiated: &Negotiated) -> Result<ServerHostKey<'a>, CryptoError> {
        let mut iter = self.0.iter();
        match iter.find(|(_, key)| key.algorithm() == negotiated.server_host_key) {
            Some((pkcs8, key)) => Ok(ServerHostKey {
                pkcs8,
                key: key.as_ref(),
            }),
            None => Err(CryptoError::UnknownAlgorithm),
        }
    }

    /// The public key algorithms of the held host keys
    pub fn algorithms(&self) -> impl Iterator<Item = PublicKeyAlgorithm<'static>> + '_ {
        self.0.iter().map(|(_, key)| key.algorithm())
    }

    /// The number of host keys
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    const MAX_KEYS: usize = 16;
}

/// A borrowed single host key, used to sign the key exchange output
pub struct ServerHostKey<'a> {
    pkcs8: &'a Zeroizing<Vec<u8>>,
    pub(crate) key: &'a dyn SigningKey,
}

impl Encode for ServerHostKey<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self { pkcs8, key: _ } = self;
        pkcs8.encode(buf);
    }
}

#[doc(hidden)] // for testing
impl<'a> From<(&'a Zeroizing<Vec<u8>>, &'a dyn SigningKey)> for ServerHostKey<'a> {
    fn from((pkcs8, key): (&'a Zeroizing<Vec<u8>>, &'a dyn SigningKey)) -> Self {
        Self { pkcs8, key }
    }
}

/// A single host key, used to sign rekeying exchanges
pub struct SessionHostKey(pub(crate) Box<dyn SigningKey>);

impl SessionHostKey {
    /// Create a new session host key from a borrowed server host key
    pub fn from_server(
        host_key: ServerHostKey<'_>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, ProtoError> {
        Ok(Self(provider.signing_key_from_pkcs8(host_key.pkcs8)?))
    }

    /// Decode a host key from encoded PKCS#8 bytes
    pub fn decode<'a>(
        buf: &'a [u8],
        provider: &dyn CryptoProvider,
    ) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: pkcs8, next } = <&[u8]>::decode(buf)?;
        Ok(Decoded {
            value: Self(provider.signing_key_from_pkcs8(pkcs8)?),
            next,
        })
    }

    /// The public key algorithm of this host key
    pub fn algorithm(&self) -> PublicKeyAlgorithm<'static> {
        self.0.algorithm()
    }
}

/// Extract a PKCS#8 document from an unencrypted OpenSSH-format private key file
///
/// Only supports unencrypted keys for now.
struct OpenSshKeyV1 {
    keys: Vec<Zeroizing<Vec<u8>>>,
}

// Format:
//
//	byte[]	"openssh-key-v1"
//	string	ciphername
//	string	kdfname
//	string	kdfoptions
//	uint32	number of keys N
//	string	publickey1
//	string	publickey2
//	...
//	string	publickeyN
//	string	encrypted, padded list of private keys
//
// Unencrypted private keys:
//
// 	uint32	checkint
//	uint32	checkint
//	byte[]	privatekey1
//	string	comment1
//	byte[]	privatekey2
//	string	comment2
//	...
//	byte[]	privatekeyN
//	string	commentN
//	byte	1
//	byte	2
//	byte	3
//	...
//	byte	padlen % 255
impl FromStr for OpenSshKeyV1 {
    type Err = ProtoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut lines = input.lines();
        if lines.next() != Some("-----BEGIN OPENSSH PRIVATE KEY-----") {
            return Err(ProtoError::InvalidHostKey("missing PEM header"));
        }

        let mut base64 = Zeroizing::new(String::new());
        let mut footer = false;
        for line in lines {
            if line == "-----END OPENSSH PRIVATE KEY-----" {
                footer = true;
                break;
            }

            base64.push_str(line);
        }

        if !footer {
            return Err(ProtoError::InvalidHostKey("missing PEM footer"));
        }

        let Ok(blob) = data_encoding::BASE64.decode(base64.as_bytes()) else {
            return Err(ProtoError::InvalidHostKey("invalid base64"));
        };

        let blob = Zeroizing::new(blob);
        let Some(next) = blob.strip_prefix(b"openssh-key-v1\0") else {
            return Err(ProtoError::InvalidHostKey("invalid magic"));
        };

        let Decoded {
            value: cipher,
            next,
        } = <&[u8]>::decode(next)?;
        let Decoded { value: kdf, next } = <&[u8]>::decode(next)?;
        let Decoded { next, .. } = <&[u8]>::decode(next)?;
        if cipher != b"none" || kdf != b"none" {
            return Err(ProtoError::InvalidHostKey(
                "encrypted keys are not supported",
            ));
        }

        let Decoded {
            value: key_count,
            next,
        } = u32::decode(next)?;
        if key_count == 0 {
            return Err(ProtoError::InvalidHostKey("no keys found"));
        }

        let mut next = next;
        for _ in 0..key_count {
            next = <&[u8]>::decode(next)?.next;
        }

        let Decoded {
            value: private,
            next,
        } = <&[u8]>::decode(next)?;
        if !next.is_empty() {
            return Err(ProtoError::InvalidHostKey(
                "trailing data after private key section",
            ));
        }

        let Decoded {
            value: check1,
            next,
        } = u32::decode(private)?;
        let Decoded {
            value: check2,
            next,
        } = u32::decode(next)?;
        if check1 != check2 {
            return Err(ProtoError::InvalidHostKey("check values do not match"));
        }

        let mut keys = Vec::with_capacity(key_count as usize);
        let mut next_key = next;
        for _ in 0..key_count {
            let Decoded {
                value: key_type,
                next,
            } = <&[u8]>::decode(next_key)?;
            let Ok(key_type) = str::from_utf8(key_type) else {
                return Err(ProtoError::InvalidHostKey("invalid key type"));
            };

            let next = match PublicKeyAlgorithm::typed(key_type) {
                PublicKeyAlgorithm::Ed25519 => {
                    let Decoded { value, next } = SshEd25519Key::decode(next)?;
                    keys.push(value.to_pkcs8());
                    next
                }
                PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                    let Decoded { value, next } = SshEcdsaKey::decode(next)?;
                    keys.push(value.to_pkcs8());
                    next
                }
                PublicKeyAlgorithm::Unknown(_) => {
                    return Err(ProtoError::InvalidHostKey("unsupported key type"));
                }
            };

            next_key = <&[u8]>::decode(next)?.next;
        }

        for (i, &byte) in next_key.iter().enumerate() {
            if byte != (i + 1) as u8 {
                return Err(ProtoError::InvalidHostKey("invalid padding"));
            }
        }

        Ok(Self { keys })
    }
}

struct SshEcdsaKey<'a> {
    scalar: &'a [u8],
    public: &'a [u8],
}

impl<'a> SshEcdsaKey<'a> {
    fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        /// PKCS#8 v1 prefix for an ECDSA P-256 private key (RFC 5915), up to the 32-byte scalar
        ///
        /// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 },
        /// OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING ... } } }`
        const ECDSA_P256_PKCS8_PREFIX: &[u8] = &[
            0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
            0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
        ];

        /// Continuation of [`ECDSA_P256_PKCS8_PREFIX`] between the scalar and the 65-byte public point
        ///
        /// `[1] { BIT STRING }`
        const ECDSA_P256_PKCS8_MIDDLE: &[u8] = &[0xa1, 0x44, 0x03, 0x42, 0x00];

        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(
            ECDSA_P256_PKCS8_PREFIX.len() + 32 + ECDSA_P256_PKCS8_MIDDLE.len() + 65,
        ));
        pkcs8.extend_from_slice(ECDSA_P256_PKCS8_PREFIX);
        let padded = ECDSA_P256_PKCS8_PREFIX.len() + (32 - self.scalar.len());
        pkcs8.resize(padded, 0);
        pkcs8.extend_from_slice(self.scalar);
        pkcs8.extend_from_slice(ECDSA_P256_PKCS8_MIDDLE);
        pkcs8.extend_from_slice(self.public);
        pkcs8
    }
}

impl<'a> Decode<'a> for SshEcdsaKey<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: curve, next } = <&[u8]>::decode(input)?;
        if curve != b"nistp256" {
            return Err(ProtoError::InvalidHostKey(
                "unexpected curve for ecdsa-sha2-nistp256",
            ));
        }

        let Decoded {
            value: public,
            next,
        } = <&[u8]>::decode(next)?;
        let Decoded {
            value: scalar,
            next,
        } = <&[u8]>::decode(next)?;

        let mut scalar = scalar;
        while let [0, rest @ ..] = scalar {
            scalar = rest;
        }

        if public.len() != 65 || scalar.is_empty() || scalar.len() > 32 {
            return Err(ProtoError::InvalidHostKey("invalid ecdsa key data"));
        }

        Ok(Decoded {
            value: Self { scalar, public },
            next,
        })
    }
}

struct SshEd25519Key<'a> {
    #[expect(dead_code)]
    public: &'a [u8],
    private: &'a [u8],
}

impl SshEd25519Key<'_> {
    fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        /// PKCS#8 v1 (RFC 5208) prefix for an Ed25519 private key (RFC 8410), up to the 32-byte seed
        ///
        /// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING } }`
        const ED25519_PKCS8_PREFIX: &[u8] = &[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];

        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32));
        pkcs8.extend_from_slice(ED25519_PKCS8_PREFIX);
        pkcs8.extend_from_slice(&self.private[..32]);
        pkcs8
    }
}

impl<'a> Decode<'a> for SshEd25519Key<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded {
            value: public,
            next,
        } = <&[u8]>::decode(bytes)?;

        let Decoded {
            value: private,
            next,
        } = <&[u8]>::decode(next)?;

        if public.len() != 32 || private.len() != 64 || private[32..] != *public {
            return Err(ProtoError::InvalidHostKey("invalid ed25519 key data"));
        }

        Ok(Decoded {
            value: Self { public, private },
            next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_ed25519_key() {
        let keys = OpenSshKeyV1::from_str(ED25519_KEY).unwrap();
        let expected = data_encoding::HEXLOWER
            .decode(b"302e020100300506032b657004220420973548d5e2993b158ba0bd0d3582c155560e68ff3a0950f650939cc87aab45ba")
            .unwrap();
        assert_eq!(*keys.keys[0], expected);
    }

    #[test]
    fn openssh_ecdsa_key() {
        let keys = OpenSshKeyV1::from_str(ECDSA_KEY).unwrap();
        let expected = data_encoding::HEXLOWER
            .decode(b"308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042018a3b62a37e956048f449849d41825b8491a6d1d0091589bcf0146edbf517464a1440342000470c85a09c02960bc0da257d4437611c3f0bc4abb10cb6ef0e858cad06b44e40d54be0a8bf1007192ef04802672dc9f88f0a3b813a9545b9d9de797492eaf46ab")
            .unwrap();
        assert_eq!(*keys.keys[0], expected);
    }

    const ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDXl3FOtNA7kAGgEi9HtmxhmtlqWxHTZmfFXnKiYhsdPwAAAJB+4DeLfuA3
iwAAAAtzc2gtZWQyNTUxOQAAACDXl3FOtNA7kAGgEi9HtmxhmtlqWxHTZmfFXnKiYhsdPw
AAAECXNUjV4pk7FYugvQ01gsFVVg5o/zoJUPZQk5zIeqtFuteXcU600DuQAaASL0e2bGGa
2WpbEdNmZ8VecqJiGx0/AAAAB2ZpeHR1cmUBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
";

    const ECDSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRwyFoJwClgvA2iV9RDdhHD8LxKuxDL
bvDoWMrQa0TkDVS+CovxAHGS7wSAJnLcn4jwo7gTqVRbnZ3nl0kur0arAAAAmOhdh/voXY
f7AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHDIWgnAKWC8DaJX
1EN2EcPwvEq7EMtu8OhYytBrROQNVL4Ki/EAcZLvBIAmctyfiPCjuBOpVFudneeXSS6vRq
sAAAAgGKO2KjfpVgSPRJhJ1BgluEkabR0AkVibzwFG7b9RdGQAAAAA
-----END OPENSSH PRIVATE KEY-----
";
}
