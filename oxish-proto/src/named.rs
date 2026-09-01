use core::{fmt, str};
use std::borrow::Cow;

use crate::{Decode, Decoded, Encode, ProtoError, crypto::KeyLengths};

/// Authentication method names
///
/// See <https://www.rfc-editor.org/rfc/rfc4252>.
#[derive(Debug)]
pub enum MethodName<'a> {
    /// `publickey`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
    PublicKey,
    /// `password`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-8>.
    Password,
    /// `hostbased`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-9>.
    HostBased,
    /// `none`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-5.2>.
    None,
    /// A method name not known to this implementation
    Unknown(&'a str),
}

impl<'a> Named<'a> for MethodName<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "publickey" => MethodName::PublicKey,
            "password" => MethodName::Password,
            "hostbased" => MethodName::HostBased,
            "none" => MethodName::None,
            _ => MethodName::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::PublicKey => "publickey",
            Self::Password => "password",
            Self::HostBased => "hostbased",
            Self::None => "none",
            Self::Unknown(name) => name,
        }
    }
}

impl PartialEq for MethodName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

/// Service names for `SSH_MSG_SERVICE_REQUEST`
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-10>.
#[derive(Debug)]
pub enum ServiceName<'a> {
    /// `ssh-userauth`, the user authentication protocol (RFC 4252)
    UserAuth,
    /// `ssh-connection`, the connection protocol (RFC 4254)
    Connection,
    /// A service name not known to this implementation
    Unknown(&'a str),
}

impl<'a> Named<'a> for ServiceName<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "ssh-userauth" => Self::UserAuth,
            "ssh-connection" => Self::Connection,
            name => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::UserAuth => "ssh-userauth",
            Self::Connection => "ssh-connection",
            Self::Unknown(name) => name,
        }
    }
}

impl PartialEq for ServiceName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

#[derive(Debug)]
pub(crate) enum ExtensionName<'a> {
    ServerSigAlgs,
    Unknown(&'a str),
}

impl<'a> Named<'a> for ExtensionName<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "server-sig-algs" => Self::ServerSigAlgs,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::ServerSigAlgs => "server-sig-algs",
            Self::Unknown(name) => name,
        }
    }
}

/// Channel types for `SSH_MSG_CHANNEL_OPEN`
///
/// See <https://www.rfc-editor.org/rfc/rfc4250#section-4.9.1>.
#[derive(Debug, PartialEq)]
pub enum ChannelType<'a> {
    /// `session`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4254#section-6.1>.
    Session,
    /// A channel type not known to this implementation
    Unknown(&'a str),
}

impl<'a> Named<'a> for ChannelType<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "session" => Self::Session,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Session => "session",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyExchangeAlgorithmOrExtensionId<'a> {
    KeyExchange(KeyExchangeAlgorithm<'a>),
    Extension(ExtensionId<'a>),
}

impl<'a> Named<'a> for KeyExchangeAlgorithmOrExtensionId<'a> {
    fn typed(name: &'a str) -> Self {
        match KeyExchangeAlgorithm::typed(name) {
            KeyExchangeAlgorithm::Unknown(_) => {}
            key_exchange => return Self::KeyExchange(key_exchange),
        };

        match ExtensionId::typed(name) {
            ExtensionId::Unknown(_) => Self::KeyExchange(KeyExchangeAlgorithm::Unknown(name)),
            extension => Self::Extension(extension),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::KeyExchange(key_exchange) => key_exchange.name(),
            Self::Extension(extension) => extension.name(),
        }
    }
}

/// Key exchange algorithm names
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-7>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyExchangeAlgorithm<'a> {
    /// `mlkem768x25519-sha256` key exchange algorithm: hybrid using ML-KEM-768 and X25519
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc10042.html>.
    MlKem768X25519Sha256,
    /// `curve25519-sha256` key exchange algorithm: ECDH using X25519
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc8731>.
    Curve25519Sha256,
    /// A key exchange algorithm not known to this implementation
    Unknown(&'a str),
}

impl KeyExchangeAlgorithm<'_> {
    /// Whether it's secure against attacks with a cryptographically relevant quantum computer
    pub fn post_quantum_secure(&self) -> bool {
        match self {
            Self::MlKem768X25519Sha256 => true,
            Self::Curve25519Sha256 | Self::Unknown(_) => false,
        }
    }
}

impl<'a> Named<'a> for KeyExchangeAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "mlkem768x25519-sha256" => Self::MlKem768X25519Sha256,
            "curve25519-sha256" => Self::Curve25519Sha256,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::MlKem768X25519Sha256 => "mlkem768x25519-sha256",
            Self::Curve25519Sha256 => "curve25519-sha256",
            Self::Unknown(name) => name,
        }
    }
}

/// Extension marker names sent in the `SSH_MSG_KEXINIT` key exchange name list
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionId<'a> {
    /// `ext-info-c`, the client's extension information marker
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc8308>.
    ExtInfoC,
    /// `kex-strict-c-v00@openssh.com`, the client's strict key exchange marker
    ///
    /// As defined in <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL>.
    StrictKexClient,
    /// `kex-strict-s-v00@openssh.com`, the server's strict key exchange marker
    ///
    /// As defined in <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL>.
    StrictKexServer,
    /// An extension marker not known to this implementation
    Unknown(&'a str),
}

impl<'a> Named<'a> for ExtensionId<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "ext-info-c" => Self::ExtInfoC,
            "kex-strict-c-v00@openssh.com" => Self::StrictKexClient,
            "kex-strict-s-v00@openssh.com" => Self::StrictKexServer,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::ExtInfoC => "ext-info-c",
            Self::StrictKexClient => "kex-strict-c-v00@openssh.com",
            Self::StrictKexServer => "kex-strict-s-v00@openssh.com",
            Self::Unknown(name) => name,
        }
    }
}

/// Public key algorithm names
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-6.6>.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyAlgorithm<'a> {
    /// `ecdsa-sha2-nistp256`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc5656>.
    EcdsaSha2Nistp256,
    /// `ssh-ed25519`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc8709>.
    Ed25519,
    /// A public key algorithm not known to this implementation
    Unknown(Cow<'a, str>),
}

impl PublicKeyAlgorithm<'_> {
    /// Copy any borrowed data so the value can outlive the input buffer
    pub fn to_owned(&self) -> PublicKeyAlgorithm<'static> {
        match self {
            Self::EcdsaSha2Nistp256 => PublicKeyAlgorithm::EcdsaSha2Nistp256,
            Self::Ed25519 => PublicKeyAlgorithm::Ed25519,
            Self::Unknown(name) => PublicKeyAlgorithm::Unknown(Cow::Owned(name.to_string())),
        }
    }
}

impl<'a> Named<'a> for PublicKeyAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "ecdsa-sha2-nistp256" => Self::EcdsaSha2Nistp256,
            "ssh-ed25519" => Self::Ed25519,
            _ => Self::Unknown(Cow::Borrowed(name)),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256",
            Self::Ed25519 => "ssh-ed25519",
            Self::Unknown(name) => name,
        }
    }
}

/// Bulk/symmetric encryption algorithm names
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-6.3>.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncryptionAlgorithm<'a> {
    /// `aes128-gcm@openssh.com` encryption algorithm: 128-bit AES in Galois/Counter Mode
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc5647>.
    Aes128Gcm,
    /// An encryption algorithm not known to this implementation
    Unknown(Cow<'a, str>),
}

impl EncryptionAlgorithm<'_> {
    /// Copy any borrowed data so the value can outlive the input buffer
    pub fn to_owned(&self) -> EncryptionAlgorithm<'static> {
        match self {
            Self::Aes128Gcm => EncryptionAlgorithm::Aes128Gcm,
            Self::Unknown(name) => EncryptionAlgorithm::Unknown(Cow::Owned(name.to_string())),
        }
    }

    /// The key and IV lengths this algorithm requires, if known
    pub fn lengths(&self) -> Option<KeyLengths> {
        match self {
            Self::Aes128Gcm => Some(KeyLengths {
                key_len: 16,
                iv_len: 12,
            }),
            Self::Unknown(_) => None,
        }
    }
}

impl<'a> Named<'a> for EncryptionAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "aes128-gcm@openssh.com" => Self::Aes128Gcm,
            _ => Self::Unknown(Cow::Borrowed(name)),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
            Self::Unknown(name) => name,
        }
    }
}

/// MAC algorithm names
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-6.4>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacAlgorithm<'a> {
    /// `hmac-sha2-256`
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc6668#section-2>.
    HmacSha2256,
    /// `none`, for AEAD ciphers that need no separate MAC
    None,
    /// A MAC algorithm not known to this implementation
    Unknown(&'a str),
}

impl<'a> Named<'a> for MacAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "hmac-sha2-256" => Self::HmacSha2256,
            "none" => Self::None,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::HmacSha2256 => "hmac-sha2-256",
            Self::None => "none",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompressionAlgorithm<'a> {
    None,
    Unknown(&'a str),
}

impl<'a> Named<'a> for CompressionAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "none" => Self::None,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Language<'a> {
    Unknown(&'a str),
}

impl<'a> Named<'a> for Language<'a> {
    fn typed(name: &'a str) -> Self {
        Self::Unknown(name)
    }

    fn name(&self) -> &str {
        match self {
            Self::Unknown(name) => name,
        }
    }
}

pub(crate) struct IncomingNameList<T>(pub(crate) Vec<T>);

impl<'a, T: Named<'a>> Decode<'a> for IncomingNameList<T> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: len, next } = u32::decode(bytes)?;

        let Some(list) = next.get(..len as usize) else {
            return Err(ProtoError::Incomplete(Some(len as usize - next.len())));
        };

        let Some(next) = next.get(len as usize..) else {
            return Err(ProtoError::Unreachable(
                "unable to extract rest after name list",
            ));
        };

        let mut value = Vec::new();
        if list.is_empty() {
            return Ok(Decoded {
                value: Self(value),
                next,
            });
        }

        for name in list.split(|&b| b == b',') {
            match str::from_utf8(name) {
                Ok(name) => value.push(T::typed(name)),
                Err(_) => return Err(ProtoError::InvalidPacket("invalid name")),
            }
        }

        Ok(Decoded {
            value: Self(value),
            next,
        })
    }
}

#[derive(Debug)]
pub(crate) struct OutgoingNameList<'a, T>(pub(crate) &'a [T]);

impl<'a, T: Named<'a>> Encode for OutgoingNameList<'_, T> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let offset = buf.len();
        buf.extend_from_slice(&[0, 0, 0, 0]);
        let mut first = true;
        for name in self.0 {
            match first {
                true => first = false,
                false => buf.push(b','),
            }

            buf.extend(name.name().as_bytes());
        }

        let len = (buf.len() - offset - 4) as u32;
        if let Some(slice) = buf.get_mut(offset..offset + 4) {
            slice.copy_from_slice(&len.to_be_bytes());
        }
    }
}

impl<'a, T: Named<'a>> Decode<'a> for T {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value, next } = <&[u8]>::decode(bytes)?;
        let name = str::from_utf8(value)
            .map_err(|_| ProtoError::InvalidPacket("invalid UTF-8 in named value"))?;

        Ok(Decoded {
            value: T::typed(name),
            next,
        })
    }
}

impl<'a, T: Named<'a>> Encode for T {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.name().as_bytes().encode(buf);
    }
}

/// A type represented on the wire by a name
///
/// Names are used in name lists and `string` fields as specified in
/// <https://www.rfc-editor.org/rfc/rfc4251#section-5>.
pub trait Named<'a>: fmt::Debug + Send + Sync {
    /// Map `name` to a known value, or a catch-all unknown value
    fn typed(name: &'a str) -> Self;

    /// The wire name for this value
    fn name(&self) -> &str;
}
