use core::fmt;

use crate::ProtoError;

#[derive(Debug, Default)]
pub struct Ignore<'a>(pub &'a [u8]);

impl Encode for Ignore<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::Ignore.encode(buf);
        self.0.encode(buf);
    }
}

pub struct IncomingPacket<'a> {
    pub sequence_number: u32,
    pub message_type: MessageType,
    pub payload: &'a [u8],
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
pub enum MessageType {
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
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
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

#[derive(Debug)]
pub struct PacketLength(pub u32);

impl Decode<'_> for PacketLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value, next } = u32::decode(bytes)?;
        if value > 256 * 1024 {
            return Err(ProtoError::InvalidPacket("packet too large"));
        }

        Ok(Decoded {
            value: Self(value),
            next,
        })
    }
}

#[derive(Debug)]
pub struct PaddingLength(pub u8);

impl Decode<'_> for PaddingLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value, next } = u8::decode(bytes)?;
        if value < 4 {
            return Err(ProtoError::InvalidPacket("padding too short"));
        }

        Ok(Decoded {
            value: Self(value),
            next,
        })
    }
}

impl<'a> Decode<'a> for &'a [u8] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let len = u32::decode(bytes)?;
        let Some(value) = len.next.get(..len.value as usize) else {
            return Err(ProtoError::Incomplete(Some(
                len.value as usize - len.next.len(),
            )));
        };

        let Some(next) = len.next.get(len.value as usize..) else {
            return Err(ProtoError::Unreachable(
                "unable to extract rest after slice",
            ));
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
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
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
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
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

impl Decode<'_> for u64 {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        <[u8; 8]>::decode(bytes).map(|decoded| Decoded {
            value: Self::from_be_bytes(decoded.value),
            next: decoded.next,
        })
    }
}

impl Encode for u64 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl<'a, const N: usize> Decode<'a> for [u8; N] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        match bytes.split_first_chunk::<N>() {
            Some((&value, next)) => Ok(Decoded { value, next }),
            None => Err(ProtoError::Incomplete(Some(N - bytes.len()))),
        }
    }
}

impl<'a> Decode<'a> for u8 {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        match bytes.split_first() {
            Some((&value, next)) => Ok(Decoded { value, next }),
            None => Err(ProtoError::Incomplete(Some(1))),
        }
    }
}

pub enum Completion<T> {
    Complete(T),
    /// Not enough input was available to produce a value
    ///
    /// The payload, if known, is the number of additional bytes needed beyond
    /// the end of the current input (as in `required - available`).
    Incomplete(Option<usize>),
}

pub trait Encode: fmt::Debug + Send + Sync {
    fn encode(&self, buf: &mut Vec<u8>);
}

pub trait Decode<'a>: Sized {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError>;
}

#[derive(Debug)]
pub struct Decoded<'a, T> {
    pub value: T,
    pub next: &'a [u8],
}
