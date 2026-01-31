use core::fmt;

use crate::Error;

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
    ExtInfo,
    KeyExchangeInit,
    NewKeys,
    KeyExchangeEcdhInit,
    KeyExchangeEcdhReply,
    UserAuthRequest,
    UserAuthFailure,
    UserAuthSuccess,
    UserAuthBanner,
    UserAuthPkOk,
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
            7 => Self::ExtInfo,
            20 => Self::KeyExchangeInit,
            21 => Self::NewKeys,
            30 => Self::KeyExchangeEcdhInit,
            31 => Self::KeyExchangeEcdhReply,
            50 => Self::UserAuthRequest,
            51 => Self::UserAuthFailure,
            52 => Self::UserAuthSuccess,
            53 => Self::UserAuthBanner,
            60 => Self::UserAuthPkOk,
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
            MessageType::ExtInfo => 7,
            MessageType::KeyExchangeInit => 20,
            MessageType::NewKeys => 21,
            MessageType::KeyExchangeEcdhInit => 30,
            MessageType::KeyExchangeEcdhReply => 31,
            MessageType::UserAuthRequest => 50,
            MessageType::UserAuthFailure => 51,
            MessageType::UserAuthSuccess => 52,
            MessageType::UserAuthBanner => 53,
            MessageType::UserAuthPkOk => 60,
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

pub(crate) enum Completion<T> {
    Complete(T),
    Incomplete(Option<usize>),
}

pub(crate) trait Encode: fmt::Debug + Send + Sync {
    fn encode(&self, buf: &mut Vec<u8>);
}

pub(crate) trait Decode<'a>: Sized {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error>;
}

pub(crate) struct Decoded<'a, T> {
    pub(crate) value: T,
    pub(crate) next: &'a [u8],
}
