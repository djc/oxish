use core::{fmt, str};

use crate::{proto::Completion, Error, IdentificationError};

#[derive(Debug)]
pub(crate) struct Identification<'a> {
    pub(crate) protocol: &'a str,
    pub(crate) software: &'a str,
    pub(crate) comments: &'a str,
}

impl<'a> Identification<'a> {
    pub(crate) fn decode(bytes: &'a [u8]) -> Result<Completion<Decoded<'a, Self>>, Error> {
        let Ok(message) = str::from_utf8(bytes) else {
            return Err(IdentificationError::InvalidUtf8.into());
        };

        let Some((message, next)) = message.split_once("\r\n") else {
            // The maximum length is 255 bytes including CRLF. message excludes
            // the CRLF, so subtract 2.
            return match message.len() > 255 - 2 {
                true => Err(IdentificationError::TooLong.into()),
                false => Ok(Completion::Incomplete(None)),
            };
        };

        let Some(rest) = message.strip_prefix("SSH-") else {
            return Err(IdentificationError::NoSsh.into());
        };

        let Some((protocol, rest)) = rest.split_once('-') else {
            return Err(IdentificationError::NoVersion.into());
        };

        let (software, comments) = match rest.split_once(' ') {
            Some((software, comments)) => (software, comments),
            None => (rest, ""),
        };

        let out = Self {
            protocol,
            software,
            comments,
        };

        Ok(Completion::Complete(Decoded {
            value: out,
            next: next.as_bytes(),
        }))
    }

    pub(crate) fn outgoing() -> Self {
        Self {
            protocol: PROTOCOL,
            software: SOFTWARE,
            comments: "",
        }
    }
}

impl Encode for Identification<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"SSH-");
        buf.extend_from_slice(self.protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(self.software.as_bytes());
        if !self.comments.is_empty() {
            buf.push(b' ');
            buf.extend_from_slice(self.comments.as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
    }
}

pub(crate) struct ServiceAccept<'a> {
    pub(crate) service_name: ServiceName<'a>,
}

impl Encode for ServiceAccept<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::ServiceAccept.encode(buf);
        self.service_name.encode(buf);
    }
}

#[derive(Debug)]
pub(crate) struct ServiceRequest<'a> {
    pub(crate) service_name: ServiceName<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ServiceRequest<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ServiceRequest {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: service_name,
            next,
        } = ServiceName::decode(packet.payload)?;
        if !next.is_empty() {
            return Err(Error::InvalidPacket("extra data in service request"));
        }

        Ok(ServiceRequest { service_name })
    }
}

#[derive(Debug)]
pub(crate) enum ServiceName<'a> {
    UserAuth,
    Connection,
    Unknown(&'a str),
}

impl<'a> ServiceName<'a> {
    pub(crate) fn as_str(&self) -> &'a str {
        match self {
            ServiceName::UserAuth => "ssh-userauth",
            ServiceName::Connection => "ssh-connection",
            ServiceName::Unknown(name) => name,
        }
    }
}

impl<'a> Decode<'a> for ServiceName<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = <&[u8]>::decode(bytes)?;
        let value = match str::from_utf8(value) {
            Ok("ssh-userauth") => ServiceName::UserAuth,
            Ok("ssh-connection") => ServiceName::Connection,
            Ok(name) => ServiceName::Unknown(name),
            Err(_) => return Err(Error::InvalidPacket("invalid UTF-8 in service name")),
        };

        Ok(Decoded { value, next })
    }
}

impl Encode for ServiceName<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.as_str().as_bytes().encode(buf);
    }
}

impl PartialEq for ServiceName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

#[derive(Debug)]
pub(crate) struct Disconnect<'a> {
    pub(crate) reason_code: DisconnectReason,
    pub(crate) description: &'a str,
}

impl<'a> TryFrom<IncomingPacket<'a>> for Disconnect<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::Disconnect {
            return Err(Error::InvalidPacket("expected disconnect packet"));
        }

        let Decoded {
            value: reason_code,
            next,
        } = u32::decode(packet.payload)?;

        let Decoded {
            value: description,
            next,
        } = <&[u8]>::decode(next)?;

        let description = str::from_utf8(description)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in disconnect description"))?;

        let Decoded {
            value: _, // language tag
            next,
        } = <&[u8]>::decode(next)?;

        if !next.is_empty() {
            return Err(Error::InvalidPacket("extra data in disconnect packet"));
        }

        Ok(Disconnect {
            reason_code: DisconnectReason::try_from(reason_code)?,
            description,
        })
    }
}

impl Encode for Disconnect<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::Disconnect.encode(buf);
        (self.reason_code as u32).encode(buf);
        self.description.as_bytes().encode(buf);
        "en-US".as_bytes().encode(buf);
    }
}

#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum DisconnectReason {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

impl TryFrom<u32> for DisconnectReason {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::HostNotAllowedToConnect,
            2 => Self::ProtocolError,
            3 => Self::KeyExchangeFailed,
            4 => Self::Reserved,
            5 => Self::MacError,
            6 => Self::CompressionError,
            7 => Self::ServiceNotAvailable,
            8 => Self::ProtocolVersionNotSupported,
            9 => Self::HostKeyNotVerifiable,
            10 => Self::ConnectionLost,
            11 => Self::ByApplication,
            12 => Self::TooManyConnections,
            13 => Self::AuthCancelledByUser,
            14 => Self::NoMoreAuthMethodsAvailable,
            15 => Self::IllegalUserName,
            _ => return Err(Error::InvalidPacket("unknown disconnect reason code")),
        })
    }
}

pub(crate) struct IncomingPacket<'a> {
    pub(crate) sequence_number: u32,
    pub(crate) message_type: MessageType,
    pub(crate) payload: &'a [u8],
}

impl fmt::Debug for IncomingPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            sequence_number,
            message_type,
            payload: _,
        } = self;

        f.debug_struct("IncomingPacket")
            .field("sequence_number", sequence_number)
            .field("message_type", message_type)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageType {
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,
    KeyExchangeInit,
    NewKeys,
    KeyExchangeEcdhInit,
    KeyExchangeEcdhReply,
    UserAuthRequest,
    UserAuthFailure,
    UserAuthSuccess,
    UserAuthBanner,
    GlobalRequest,
    RequestSuccess,
    RequestFailure,
    ChannelOpen,
    ChannelOpenConfirmation,
    ChannelOpenFailure,
    ChannelWindowAdjust,
    ChannelData,
    ChannelExtendedData,
    ChannelEof,
    ChannelClose,
    ChannelRequest,
    ChannelSuccess,
    ChannelFailure,
    Unknown(u8),
}

impl Encode for MessageType {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(u8::from(*self));
    }
}

impl<'a> Decode<'a> for MessageType {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = u8::decode(bytes)?;
        Ok(Decoded {
            value: Self::from(value),
            next,
        })
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Disconnect,
            2 => Self::Ignore,
            3 => Self::Unimplemented,
            4 => Self::Debug,
            5 => Self::ServiceRequest,
            6 => Self::ServiceAccept,
            20 => Self::KeyExchangeInit,
            21 => Self::NewKeys,
            30 => Self::KeyExchangeEcdhInit,
            31 => Self::KeyExchangeEcdhReply,
            50 => Self::UserAuthRequest,
            51 => Self::UserAuthFailure,
            52 => Self::UserAuthSuccess,
            53 => Self::UserAuthBanner,
            80 => Self::GlobalRequest,
            81 => Self::RequestSuccess,
            82 => Self::RequestFailure,
            90 => Self::ChannelOpen,
            91 => Self::ChannelOpenConfirmation,
            92 => Self::ChannelOpenFailure,
            93 => Self::ChannelWindowAdjust,
            94 => Self::ChannelData,
            95 => Self::ChannelExtendedData,
            96 => Self::ChannelEof,
            97 => Self::ChannelClose,
            98 => Self::ChannelRequest,
            99 => Self::ChannelSuccess,
            100 => Self::ChannelFailure,
            value => Self::Unknown(value),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Disconnect => 1,
            MessageType::Ignore => 2,
            MessageType::Unimplemented => 3,
            MessageType::Debug => 4,
            MessageType::ServiceRequest => 5,
            MessageType::ServiceAccept => 6,
            MessageType::KeyExchangeInit => 20,
            MessageType::NewKeys => 21,
            MessageType::KeyExchangeEcdhInit => 30,
            MessageType::KeyExchangeEcdhReply => 31,
            MessageType::UserAuthRequest => 50,
            MessageType::UserAuthFailure => 51,
            MessageType::UserAuthSuccess => 52,
            MessageType::UserAuthBanner => 53,
            MessageType::GlobalRequest => 80,
            MessageType::RequestSuccess => 81,
            MessageType::RequestFailure => 82,
            MessageType::ChannelOpen => 90,
            MessageType::ChannelOpenConfirmation => 91,
            MessageType::ChannelOpenFailure => 92,
            MessageType::ChannelWindowAdjust => 93,
            MessageType::ChannelData => 94,
            MessageType::ChannelExtendedData => 95,
            MessageType::ChannelEof => 96,
            MessageType::ChannelClose => 97,
            MessageType::ChannelRequest => 98,
            MessageType::ChannelSuccess => 99,
            MessageType::ChannelFailure => 100,
            MessageType::Unknown(value) => value,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PacketLength {
    pub(crate) inner: u32,
}

impl Decode<'_> for PacketLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, Error> {
        let Decoded { value, next } = u32::decode(bytes)?;
        if value > 256 * 1024 {
            return Err(Error::InvalidPacket("packet too large"));
        }

        Ok(Decoded {
            value: Self { inner: value },
            next,
        })
    }
}

impl<'a> Decode<'a> for &'a [u8] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let len = u32::decode(bytes)?;
        let Some(value) = len.next.get(..len.value as usize) else {
            return Err(Error::Incomplete(Some(len.value as usize - len.next.len())));
        };

        let Some(next) = len.next.get(len.value as usize..) else {
            return Err(Error::Unreachable("unable to extract rest after slice"));
        };

        Ok(Decoded { value, next })
    }
}

impl Encode for [u8] {
    fn encode(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode(buf);
        buf.extend_from_slice(self);
    }
}

impl Decode<'_> for bool {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, Error> {
        <[u8; 1]>::decode(bytes).map(|decoded| Decoded {
            value: decoded.value[0] != 0,
            next: decoded.next,
        })
    }
}

impl Encode for bool {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(if *self { 1 } else { 0 });
    }
}

impl Decode<'_> for u32 {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, Error> {
        <[u8; 4]>::decode(bytes).map(|decoded| Decoded {
            value: Self::from_be_bytes(decoded.value),
            next: decoded.next,
        })
    }
}

impl Encode for u32 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl<'a, const N: usize> Decode<'a> for [u8; N] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Some(inner) = bytes.get(..N) else {
            return Err(Error::Incomplete(Some(N - bytes.len())));
        };

        let Some(next) = bytes.get(N..) else {
            return Err(Error::Unreachable(
                "unable to extract rest after fixed-length slice",
            ));
        };

        let Ok(value) = <[u8; N]>::try_from(inner) else {
            return Err(Error::Unreachable("fixed-length slice converts to array"));
        };

        Ok(Decoded { value, next })
    }
}

impl<'a> Decode<'a> for u8 {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Some(&inner) = bytes.first() else {
            return Err(Error::Incomplete(Some(1)));
        };

        let Some(next) = bytes.get(1..) else {
            return Err(Error::Unreachable("unable to extract rest after u8"));
        };

        Ok(Decoded { value: inner, next })
    }
}

pub(crate) trait Encode {
    fn encode(&self, buf: &mut Vec<u8>);
}

pub(crate) trait Decode<'a>: Sized {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error>;
}

pub(crate) struct Decoded<'a, T> {
    pub(crate) value: T,
    pub(crate) next: &'a [u8],
}

pub(crate) const PROTOCOL: &str = "2.0";
pub(crate) const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
