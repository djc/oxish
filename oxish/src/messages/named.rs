use core::str;
use std::borrow::Cow;

use super::base::{Decode, Decoded, Encode};
use crate::Error;

#[derive(Debug)]
pub(crate) enum MethodName<'a> {
    PublicKey,
    Password,
    HostBased,
    None,
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

#[derive(Debug)]
pub(crate) enum ServiceName<'a> {
    UserAuth,
    Connection,
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

#[derive(Debug, PartialEq)]
pub(crate) enum ChannelType<'a> {
    Session,
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
pub(crate) enum KeyExchangeAlgorithm<'a> {
    /// curve25519-sha256 (<https://www.rfc-editor.org/rfc/rfc8731>)
    Curve25519Sha256,
    Unknown(&'a str),
}

impl<'a> Named<'a> for KeyExchangeAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "curve25519-sha256" => Self::Curve25519Sha256,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Curve25519Sha256 => "curve25519-sha256",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicKeyAlgorithm<'a> {
    /// ssh-ed25519 (<https://www.rfc-editor.org/rfc/rfc8709>)
    Ed25519,
    Unknown(Cow<'a, str>),
}

impl<'a> Named<'a> for PublicKeyAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "ssh-ed25519" => Self::Ed25519,
            _ => Self::Unknown(Cow::Borrowed(name)),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncryptionAlgorithm<'a> {
    /// aes128-ctr (<https://www.rfc-editor.org/rfc/rfc4344#section-4>)
    Aes128Ctr,
    Unknown(&'a str),
}

impl<'a> Named<'a> for EncryptionAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "aes128-ctr" => Self::Aes128Ctr,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Aes128Ctr => "aes128-ctr",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacAlgorithm<'a> {
    /// hmac-sha2-256 (<https://www.rfc-editor.org/rfc/rfc6668#section-2>)
    HmacSha2256,
    Unknown(&'a str),
}

impl<'a> Named<'a> for MacAlgorithm<'a> {
    fn typed(name: &'a str) -> Self {
        match name {
            "hmac-sha2-256" => Self::HmacSha2256,
            _ => Self::Unknown(name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::HmacSha2256 => "hmac-sha2-256",
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

pub(super) struct IncomingNameList<T>(pub(super) Vec<T>);

impl<'a, T: Named<'a>> Decode<'a> for IncomingNameList<T> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value: len, next } = u32::decode(bytes)?;

        let Some(list) = next.get(..len as usize) else {
            return Err(Error::Incomplete(Some(len as usize - next.len())));
        };

        let Some(next) = next.get(len as usize..) else {
            return Err(Error::Unreachable("unable to extract rest after name list"));
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
                Err(_) => return Err(Error::InvalidPacket("invalid name")),
            }
        }

        Ok(Decoded {
            value: Self(value),
            next,
        })
    }
}
pub(super) struct OutgoingNameList<'a, T>(pub(super) &'a [T]);

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
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = <&[u8]>::decode(bytes)?;
        let name = str::from_utf8(value)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in named value"))?;

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

trait Named<'a> {
    fn typed(name: &'a str) -> Self;

    fn name(&self) -> &str;
}
