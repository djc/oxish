use core::str::{self, FromStr};
use std::{fs, path::Path};

use tracing::warn;
use zeroize::Zeroizing;

use crate::{
    Decode, Decoded, Encode, ProtoError, PublicKeyAlgorithm,
    crypto::{CryptoError, CryptoProvider, SigningKey},
    key_exchange::{Negotiated, encode_mpint},
    named::Named,
};

/// The server's host keys, used to authenticate the key exchange
#[expect(clippy::type_complexity)]
pub struct HostKeys(Vec<(Zeroizing<Vec<u8>>, Box<dyn SigningKey>)>);

impl HostKeys {
    /// Create host keys from a list of OpenSSH-format private key files
    ///
    /// Files that cannot be read or parsed are skipped. Only supports
    /// unencrypted keys for now.
    pub fn from_files(
        paths: impl Iterator<Item = impl AsRef<Path>>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, ProtoError> {
        let mut keys = Vec::new();
        for path in paths {
            let path = path.as_ref();

            // FIXME avoid read_to_string() leaving key material in reallocated buffers
            let pem = match fs::read_to_string(path) {
                Ok(pem) => Zeroizing::new(pem),
                Err(error) => {
                    warn!(?path, %error, "skipping unreadable host key file");
                    continue;
                }
            };

            match OpenSshKeyV1::from_str(&pem) {
                Ok(openssh) => keys.extend(openssh.keys.iter().map(SshPrivateKey::to_pkcs8)),
                Err(error) => warn!(?path, %error, "skipping host key file with invalid format"),
            }
        }

        Self::new(keys.into_iter(), provider)
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
            let signing_key = provider.signing_key_from_pkcs8(&pkcs8)?;
            keys.push((pkcs8, signing_key));

            if keys.len() >= Self::MAX_KEYS {
                return Err(ProtoError::TooManyHostKeys);
            }
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

/// Private keys held in an unencrypted OpenSSH-format private key file
///
/// Only supports unencrypted keys for now.
pub struct OpenSshKeyV1 {
    keys: Vec<SshPrivateKey>,
}

impl OpenSshKeyV1 {
    /// Create an OpenSSH-format private key file holding the given keys
    ///
    /// Returns `None` if `keys` is empty, as the format requires at least one key.
    pub fn new(keys: impl IntoIterator<Item = SshPrivateKey>) -> Option<Self> {
        let keys = keys.into_iter().collect::<Vec<_>>();
        if keys.is_empty() {
            return None;
        }
        Some(Self { keys })
    }

    /// Encode as an SSH wire format
    pub fn to_bytes(
        &self,
        provider: &dyn CryptoProvider,
    ) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
        let mut check = [0; 4];
        provider.secure_random().fill(&mut check)?;

        let mut blob = Zeroizing::new(b"openssh-key-v1\0".to_vec());
        b"none".encode(&mut blob); // ciphername
        b"none".encode(&mut blob); // kdfname
        b"".encode(&mut blob); // kdfoptions
        (self.keys.len() as u32).encode(&mut blob);

        let mut private = Zeroizing::new(Vec::new());
        private.extend_from_slice(&check);
        private.extend_from_slice(&check);
        for key in &self.keys {
            let mut public = Vec::new();
            key.algorithm().name().as_bytes().encode(&mut public); // key type
            match key {
                SshPrivateKey::Ed25519(key) => key.public.encode(&mut public),
                SshPrivateKey::EcdsaSha2Nistp256(key) => {
                    b"nistp256".encode(&mut public); // curve identifier
                    key.public.encode(&mut public);
                }
            }

            public.encode(&mut blob);
            key.encode(&mut private);
            b"".encode(&mut private); // comment
        }

        // Pad to the cipher block size (8 for "none", per OpenSSH's cipher.c)
        // with 1, 2, 3, ...
        for i in 1..=(8 - private.len() % 8) % 8 {
            private.push(i as u8);
        }
        private.encode(&mut blob);

        Ok(blob)
    }
}

/// Encode given SSH wire format data to private key file
pub fn pem_encode(label: &str, data: &[u8]) -> Zeroizing<String> {
    let base64 = Zeroizing::new(data_encoding::BASE64.encode(data));
    let mut pem = Zeroizing::new(format!("-----BEGIN {label}-----\n"));

    for line in base64.as_bytes().chunks(70) {
        pem.push_str(str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
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
            let Decoded { value, next } = SshPrivateKey::decode(next_key)?;
            keys.push(value);
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

/// A private key held in an OpenSSH-format private key file
#[non_exhaustive]
pub enum SshPrivateKey {
    /// An `ssh-ed25519` key
    Ed25519(SshEd25519Key),
    /// An `ecdsa-sha2-nistp256` key
    EcdsaSha2Nistp256(SshEcdsaKey),
}

impl SshPrivateKey {
    /// From PKCS#8 document
    pub fn from_pkcs8(pkcs8: &[u8], key: &dyn SigningKey) -> Result<Self, ProtoError> {
        match key.algorithm() {
            PublicKeyAlgorithm::Ed25519 => Ok(Self::Ed25519(SshEd25519Key::from_pkcs8(
                pkcs8,
                key.public_key(),
            )?)),
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                Ok(Self::EcdsaSha2Nistp256(SshEcdsaKey::from_pkcs8(pkcs8)?))
            }
            PublicKeyAlgorithm::Unknown(_) => {
                Err(ProtoError::InvalidHostKey("unsupported key type"))
            }
        }
    }

    fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Ed25519(key) => key.to_pkcs8(),
            Self::EcdsaSha2Nistp256(key) => key.to_pkcs8(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm<'static> {
        match self {
            Self::Ed25519(_) => PublicKeyAlgorithm::Ed25519,
            Self::EcdsaSha2Nistp256(_) => PublicKeyAlgorithm::EcdsaSha2Nistp256,
        }
    }
}

impl Encode for SshPrivateKey {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.algorithm().name().as_bytes().encode(buf);
        match self {
            Self::Ed25519(key) => key.encode(buf),
            Self::EcdsaSha2Nistp256(key) => key.encode(buf),
        }
    }
}

impl<'a> Decode<'a> for SshPrivateKey {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded {
            value: key_type,
            next,
        } = <&[u8]>::decode(input)?;
        let Ok(key_type) = str::from_utf8(key_type) else {
            return Err(ProtoError::InvalidHostKey("invalid key type"));
        };

        match PublicKeyAlgorithm::typed(key_type) {
            PublicKeyAlgorithm::Ed25519 => {
                let Decoded { value, next } = SshEd25519Key::decode(next)?;
                Ok(Decoded {
                    value: Self::Ed25519(value),
                    next,
                })
            }
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let Decoded { value, next } = SshEcdsaKey::decode(next)?;
                Ok(Decoded {
                    value: Self::EcdsaSha2Nistp256(value),
                    next,
                })
            }
            PublicKeyAlgorithm::Unknown(_) => {
                Err(ProtoError::InvalidHostKey("unsupported key type"))
            }
        }
    }
}

/// An ECDSA private key on the NIST P-256 curve
pub struct SshEcdsaKey {
    /// Big-endian, left-padded to 32 bytes
    scalar: Zeroizing<[u8; 32]>,
    public: [u8; 65],
}

impl SshEcdsaKey {
    /// Copy the scalar and public point from a PKCS#8 v1 document
    ///
    /// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 },
    /// OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING (32), [1] { BIT STRING (65) } } } }`
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, ProtoError> {
        if pkcs8.len() != 138
            || !pkcs8.starts_with(Self::PKCS8_PREFIX)
            || pkcs8[68..73] != *Self::PKCS8_MIDDLE
        {
            return Err(ProtoError::InvalidHostKey("unexpected p256 pkcs8 layout"));
        }

        let mut key = Self {
            scalar: Zeroizing::new([0; 32]),
            public: [0; 65],
        };
        key.scalar.copy_from_slice(&pkcs8[36..68]);
        key.public.copy_from_slice(&pkcs8[73..]);
        Ok(key)
    }

    fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(
            Self::PKCS8_PREFIX.len() + 32 + Self::PKCS8_MIDDLE.len() + 65,
        ));
        pkcs8.extend_from_slice(Self::PKCS8_PREFIX);
        pkcs8.extend_from_slice(&*self.scalar);
        pkcs8.extend_from_slice(Self::PKCS8_MIDDLE);
        pkcs8.extend_from_slice(&self.public);
        pkcs8
    }

    /// PKCS#8 v1 prefix for an ECDSA P-256 private key (RFC 5915), up to the 32-byte scalar
    ///
    /// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 },
    /// OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING ... } } }`
    const PKCS8_PREFIX: &'static [u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];

    /// Continuation of [`Self::PKCS8_PREFIX`] between the scalar and the 65-byte public point
    ///
    /// `[1] { BIT STRING }`
    const PKCS8_MIDDLE: &'static [u8] = &[0xa1, 0x44, 0x03, 0x42, 0x00];
}

impl Encode for SshEcdsaKey {
    fn encode(&self, buf: &mut Vec<u8>) {
        b"nistp256".encode(buf);
        self.public.encode(buf);
        encode_mpint(&*self.scalar, buf);
    }
}

impl<'a> Decode<'a> for SshEcdsaKey {
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

        let mut key = Self {
            scalar: Zeroizing::new([0; 32]),
            public: [0; 65],
        };

        // Left-pad the big-endian scalar with zeros:
        //
        //   0                32 - scalar.len()    32
        //   +----------------+--------------------+
        //   |   00 ... 00    |       scalar       |
        //   +----------------+--------------------+
        key.scalar[32 - scalar.len()..].copy_from_slice(scalar);
        key.public.copy_from_slice(public);
        Ok(Decoded { value: key, next })
    }
}

/// An Ed25519 private key
pub struct SshEd25519Key {
    public: [u8; 32],
    seed: Zeroizing<[u8; 32]>,
}

impl SshEd25519Key {
    /// Copy the seed from a PKCS#8 v1 or v2 (RFC 5958) document
    ///
    /// The v2 layout accepted here differs from v1 only in the outer length,
    /// the version and a trailing `[1] IMPLICIT BIT STRING` holding the public
    /// key. `public` is taken separately since v1 does not hold it; for v2 it
    /// must match the embedded one.
    pub fn from_pkcs8(pkcs8: &[u8], public: &[u8]) -> Result<Self, ProtoError> {
        let header: &[u8] = match pkcs8.len() {
            // v1
            48 => &Self::PKCS8_PREFIX[..5],
            // v2
            83 if pkcs8[48..51] == [0x81, 0x21, 0x00] && pkcs8[51..] == *public => {
                &[0x30, 0x51, 0x02, 0x01, 0x01]
            }
            _ => {
                return Err(ProtoError::InvalidHostKey(
                    "unexpected ed25519 pkcs8 layout",
                ));
            }
        };

        if public.len() != 32 || pkcs8[..5] != *header || pkcs8[5..16] != Self::PKCS8_PREFIX[5..] {
            return Err(ProtoError::InvalidHostKey(
                "unexpected ed25519 pkcs8 layout",
            ));
        }

        let mut key = Self {
            public: [0; 32],
            seed: Zeroizing::new([0; 32]),
        };
        key.public.copy_from_slice(public);
        key.seed.copy_from_slice(&pkcs8[16..48]);
        Ok(key)
    }

    fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(Self::PKCS8_PREFIX.len() + 32));
        pkcs8.extend_from_slice(Self::PKCS8_PREFIX);
        pkcs8.extend_from_slice(&*self.seed);
        pkcs8
    }

    /// PKCS#8 v1 (RFC 5208) prefix for an Ed25519 private key (RFC 8410), up to the 32-byte seed
    ///
    /// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING } }`
    const PKCS8_PREFIX: &'static [u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
}

impl Encode for SshEd25519Key {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.public.encode(buf);
        // OpenSSH stores the 64-byte `seed || public` form as the private key
        64u32.encode(buf);
        buf.extend_from_slice(&*self.seed);
        buf.extend_from_slice(&self.public);
    }
}

impl<'a> Decode<'a> for SshEd25519Key {
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

        let mut key = Self {
            public: [0; 32],
            seed: Zeroizing::new([0; 32]),
        };
        key.public.copy_from_slice(public); // Checked public.len() is 32
        key.seed.copy_from_slice(&private[..32]);
        Ok(Decoded { value: key, next })
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
        assert_eq!(*keys.keys[0].to_pkcs8(), expected);
    }

    #[test]
    fn openssh_ecdsa_key() {
        let keys = OpenSshKeyV1::from_str(ECDSA_KEY).unwrap();
        let expected = data_encoding::HEXLOWER
            .decode(b"308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042018a3b62a37e956048f449849d41825b8491a6d1d0091589bcf0146edbf517464a1440342000470c85a09c02960bc0da257d4437611c3f0bc4abb10cb6ef0e858cad06b44e40d54be0a8bf1007192ef04802672dc9f88f0a3b813a9545b9d9de797492eaf46ab")
            .unwrap();
        assert_eq!(*keys.keys[0].to_pkcs8(), expected);
    }

    #[test]
    fn roundtrip_private_section() {
        for pem in [ED25519_KEY, ECDSA_KEY] {
            let key = OpenSshKeyV1::from_str(pem).unwrap().keys.remove(0);
            let blob = data_encoding::BASE64
                .decode(
                    pem.lines()
                        .skip(1)
                        .take_while(|l| !l.starts_with("-----"))
                        .collect::<String>()
                        .as_bytes(),
                )
                .unwrap();

            // The last occurrence of the key type is in the private section;
            // the entry starts at its length prefix
            let algorithm = key.algorithm();
            let name = algorithm.name();
            let start = blob
                .windows(name.len())
                .rposition(|w| w == name.as_bytes())
                .unwrap()
                - 4;
            let Decoded { next, .. } = SshPrivateKey::decode(&blob[start..]).unwrap();
            let expected = &blob[start..blob.len() - next.len()];

            let pkcs8 = key.to_pkcs8();
            let rebuilt = match &key {
                SshPrivateKey::Ed25519(key) => {
                    SshPrivateKey::Ed25519(SshEd25519Key::from_pkcs8(&pkcs8, &key.public).unwrap())
                }
                SshPrivateKey::EcdsaSha2Nistp256(_) => {
                    SshPrivateKey::EcdsaSha2Nistp256(SshEcdsaKey::from_pkcs8(&pkcs8).unwrap())
                }
            };
            let mut out = Vec::new();
            rebuilt.encode(&mut out);
            assert_eq!(out, expected, "{name}");
        }
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
