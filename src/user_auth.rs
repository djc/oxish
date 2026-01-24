use core::str;

use crate::{
    proto::{Decode, Decoded, Encode, IncomingPacket, MessageType, ServiceName},
    Error,
};

#[derive(Debug)]
pub(crate) struct UserAuthRequest<'a> {
    pub(crate) user_name: &'a str,
    pub(crate) service_name: ServiceName<'a>,
    pub(crate) method_name: MethodName<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for UserAuthRequest<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::UserAuthRequest {
            return Err(Error::InvalidPacket("expected user auth request packet"));
        }

        let Decoded {
            value: user_name,
            next,
        } = <&[u8]>::decode(packet.payload)?;
        let user_name = str::from_utf8(user_name)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in user name"))?;

        let Decoded {
            value: service_name,
            next,
        } = ServiceName::decode(next)?;

        let Decoded {
            value: method_name,
            next,
        } = MethodName::decode(next)?;

        if !next.is_empty() {
            return Err(Error::InvalidPacket(
                "method-specific fields currently unsupported",
            ));
        }

        Ok(UserAuthRequest {
            user_name,
            service_name,
            method_name,
        })
    }
}

#[derive(Debug)]
pub(crate) enum MethodName<'a> {
    PublicKey,
    Password,
    HostBased,
    None,
    Unknown(&'a str),
}

impl<'a> MethodName<'a> {
    fn as_str(&self) -> &str {
        match self {
            MethodName::PublicKey => "publickey",
            MethodName::Password => "password",
            MethodName::HostBased => "hostbased",
            MethodName::None => "none",
            MethodName::Unknown(name) => name,
        }
    }
}

impl<'a> Decode<'a> for MethodName<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = <&[u8]>::decode(bytes)?;
        let value = match str::from_utf8(value) {
            Ok("publickey") => MethodName::PublicKey,
            Ok("password") => MethodName::Password,
            Ok("hostbased") => MethodName::HostBased,
            Ok("none") => MethodName::None,
            Ok(name) => MethodName::Unknown(name),
            Err(_) => return Err(Error::InvalidPacket("invalid UTF-8 in method name")),
        };

        Ok(Decoded { value, next })
    }
}

impl Encode for MethodName<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_str().as_bytes().encode(buf);
    }
}

impl PartialEq for MethodName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
