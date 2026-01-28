use core::{fmt, str};
use std::{borrow::Cow, collections::BTreeMap};

use tracing::{debug, warn};

use crate::{Error, IdentificationError};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyExchangeAlgorithm<'a> {
    /// curve25519-sha256 (<https://www.rfc-editor.org/rfc/rfc8731>)
    Curve25519Sha256,
    Unknown(&'a str),
}

impl Encode for KeyExchangeAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Curve25519Sha256 => buf.extend_from_slice(b"curve25519-sha256"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for KeyExchangeAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "curve25519-sha256" => Self::Curve25519Sha256,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicKeyAlgorithm<'a> {
    /// ssh-ed25519 (<https://www.rfc-editor.org/rfc/rfc8709>)
    Ed25519,
    Unknown(Cow<'a, str>),
}

impl<'a> PublicKeyAlgorithm<'a> {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::Unknown(name) => name,
        }
    }
}

impl Encode for PublicKeyAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_str().as_bytes());
    }
}

impl<'a> From<&'a str> for PublicKeyAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "ssh-ed25519" => Self::Ed25519,
            _ => Self::Unknown(Cow::Borrowed(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncryptionAlgorithm<'a> {
    /// aes128-ctr (<https://www.rfc-editor.org/rfc/rfc4344#section-4>)
    Aes128Ctr,
    Unknown(&'a str),
}

impl Encode for EncryptionAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Aes128Ctr => buf.extend_from_slice(b"aes128-ctr"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for EncryptionAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "aes128-ctr" => Self::Aes128Ctr,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacAlgorithm<'a> {
    /// hmac-sha2-256 (<https://www.rfc-editor.org/rfc/rfc6668#section-2>)
    HmacSha2256,
    Unknown(&'a str),
}

impl Encode for MacAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::HmacSha2256 => buf.extend_from_slice(b"hmac-sha2-256"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for MacAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "hmac-sha2-256" => Self::HmacSha2256,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompressionAlgorithm<'a> {
    None,
    Unknown(&'a str),
}

impl Encode for CompressionAlgorithm<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::None => buf.extend_from_slice(b"none"),
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for CompressionAlgorithm<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "none" => Self::None,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Language<'a> {
    Unknown(&'a str),
}

impl Encode for Language<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Unknown(name) => buf.extend_from_slice(name.as_bytes()),
        }
    }
}

impl<'a> From<&'a str> for Language<'a> {
    fn from(value: &'a str) -> Self {
        Self::Unknown(value)
    }
}

#[derive(Debug)]
pub(crate) struct NewKeys;

impl<'a> TryFrom<IncomingPacket<'a>> for NewKeys {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::NewKeys {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        if !packet.payload.is_empty() {
            debug!(bytes = ?packet.payload, "unexpected trailing bytes");
            return Err(Error::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Self)
    }
}

impl Encode for NewKeys {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::NewKeys.encode(buf);
    }
}

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

#[derive(Debug)]
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
pub(crate) struct ChannelOpen<'a> {
    pub(crate) r#type: ChannelType<'a>,
    pub(crate) sender_channel: u32,
    pub(crate) initial_window_size: u32,
    pub(crate) maximum_packet_size: u32,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelOpen<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelOpen {
            return Err(Error::InvalidPacket("expected channel open packet"));
        }

        let Decoded {
            value: r#type,
            next,
        } = ChannelType::decode(packet.payload)?;

        let Decoded {
            value: sender_channel,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: initial_window_size,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: maximum_packet_size,
            next,
        } = u32::decode(next)?;

        match r#type {
            ChannelType::Session => match next.is_empty() {
                true => {}
                false => return Err(Error::InvalidPacket("extra data in channel open packet")),
            },
            ChannelType::Unknown(_) => {}
        }

        Ok(ChannelOpen {
            r#type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum ChannelType<'a> {
    Session,
    Unknown(&'a str),
}

impl<'a> Decode<'a> for ChannelType<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = <&[u8]>::decode(input)?;
        let type_str = str::from_utf8(value)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in channel type"))?;

        let value = match type_str {
            "session" => ChannelType::Session,
            name => ChannelType::Unknown(name),
        };

        Ok(Decoded { value, next })
    }
}

#[derive(Debug)]
pub(crate) struct ChannelOpenConfirmation {
    pub(crate) recipient_channel: u32,
    pub(crate) sender_channel: u32,
    pub(crate) initial_window_size: u32,
    pub(crate) maximum_packet_size: u32,
}

impl Encode for ChannelOpenConfirmation {
    fn encode(&self, buffer: &mut Vec<u8>) {
        MessageType::ChannelOpenConfirmation.encode(buffer);
        self.recipient_channel.encode(buffer);
        self.sender_channel.encode(buffer);
        self.initial_window_size.encode(buffer);
        self.maximum_packet_size.encode(buffer);
    }
}

#[derive(Debug)]
pub(crate) struct ChannelOpenFailure<'a> {
    recipient_channel: u32,
    reason_code: ChannelOpenFailureReason,
    description: &'a str,
}

impl ChannelOpenFailure<'static> {
    pub(crate) fn duplicate_id(recipient_channel: u32) -> Self {
        Self {
            recipient_channel,
            reason_code: ChannelOpenFailureReason::AdministrativelyProhibited,
            description: "channel ID already in use",
        }
    }

    pub(crate) fn unknown_type(recipient_channel: u32) -> Self {
        Self {
            recipient_channel,
            reason_code: ChannelOpenFailureReason::UnknownChannelType,
            description: "only 'session' channel type is supported",
        }
    }
}

impl Encode for ChannelOpenFailure<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        MessageType::ChannelOpenFailure.encode(buffer);
        self.recipient_channel.encode(buffer);
        self.reason_code.encode(buffer);
        self.description.as_bytes().encode(buffer);
        "en-US".as_bytes().encode(buffer);
    }
}

#[expect(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
enum ChannelOpenFailureReason {
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
}

impl Encode for ChannelOpenFailureReason {
    fn encode(&self, buffer: &mut Vec<u8>) {
        (*self as u32).encode(buffer);
    }
}

#[derive(Debug)]
pub(crate) struct ChannelRequest<'a> {
    pub(crate) recipient_channel: u32,
    pub(crate) r#type: ChannelRequestType<'a>,
    pub(crate) want_reply: bool,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelRequest<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelRequest {
            return Err(Error::InvalidPacket("expected channel request packet"));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        let Decoded {
            value: r#type,
            next,
        } = <&[u8]>::decode(next)?;

        let Decoded {
            value: want_reply,
            next,
        } = bool::decode(next)?;

        let r#type = match r#type {
            b"pty-req" => {
                let Decoded { value, next } = PtyReq::decode(next)?;
                match next.is_empty() {
                    true => ChannelRequestType::PtyReq(value),
                    false => {
                        return Err(Error::InvalidPacket(
                            "extra data in pty-req channel request",
                        ))
                    }
                }
            }
            b"env" => {
                let Decoded { value, next } = Env::decode(next)?;
                match next.is_empty() {
                    true => ChannelRequestType::Env(value),
                    false => return Err(Error::InvalidPacket("extra data in env channel request")),
                }
            }
            b"shell" => match next.is_empty() {
                true => ChannelRequestType::Shell,
                false => return Err(Error::InvalidPacket("extra data in shell channel request")),
            },
            _ => {
                match str::from_utf8(r#type) {
                    Ok(r#type) => warn!(%r#type, "unknown channel request type"),
                    Err(_) => warn!(?r#type, "unknown channel request type"),
                }

                return Err(Error::InvalidPacket("unknown channel request type"));
            }
        };

        Ok(ChannelRequest {
            recipient_channel,
            r#type,
            want_reply,
        })
    }
}

#[derive(Debug)]
pub(crate) enum ChannelRequestType<'a> {
    PtyReq(PtyReq<'a>),
    Env(Env<'a>),
    Shell,
}

#[derive(Debug)]
pub(crate) struct Env<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a str,
}

impl<'a> Decode<'a> for Env<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value: name, next } = <&[u8]>::decode(input)?;
        let name =
            str::from_utf8(name).map_err(|_| Error::InvalidPacket("invalid UTF-8 in env name"))?;

        let Decoded { value, next } = <&[u8]>::decode(next)?;
        let value = str::from_utf8(value)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in env value"))?;

        Ok(Decoded {
            value: Env { name, value },
            next,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PtyReq<'a> {
    pub(crate) term: Cow<'a, str>,
    pub(crate) cols: u32,
    pub(crate) rows: u32,
    pub(crate) width_px: u32,
    pub(crate) height_px: u32,
    pub(crate) terminal_modes: BTreeMap<Mode, u32>,
}

impl<'a> PtyReq<'a> {
    pub(crate) fn into_owned(self) -> PtyReq<'static> {
        PtyReq {
            term: Cow::Owned(self.term.into_owned()),
            cols: self.cols,
            rows: self.rows,
            width_px: self.width_px,
            height_px: self.height_px,
            terminal_modes: self.terminal_modes,
        }
    }
}

impl<'a> Decode<'a> for PtyReq<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value: term, next } = <&[u8]>::decode(input)?;
        let term = str::from_utf8(term)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in pty-req data"))?;

        let Decoded { value: cols, next } = u32::decode(next)?;
        let Decoded { value: rows, next } = u32::decode(next)?;
        let Decoded {
            value: width_px,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: height_px,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: terminal_modes,
            next,
        } = BTreeMap::<Mode, u32>::decode(next)?;

        Ok(Decoded {
            value: PtyReq {
                term: Cow::Borrowed(term),
                cols,
                rows,
                width_px,
                height_px,
                terminal_modes,
            },
            next,
        })
    }
}

impl<'a> Decode<'a> for BTreeMap<Mode, u32> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next: rest } = <&[u8]>::decode(input)?;
        let mut input = value;
        let mut modes = Self::new();

        loop {
            let Decoded { value, next } = Option::<Mode>::decode(input)?;
            input = next;

            match value {
                Some(mode) => {
                    let Decoded { value, next } = u32::decode(input)?;
                    modes.insert(mode, value);
                    input = next;
                }
                None => break,
            }
        }

        Ok(Decoded {
            value: modes,
            next: rest,
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Mode {
    VIntr = 1,
    VQuit = 2,
    VErase = 3,
    VKill = 4,
    VEof = 5,
    VEol = 6,
    VEol2 = 7,
    VStart = 8,
    VStop = 9,
    VSusp = 10,
    VDSusp = 11,
    VReprint = 12,
    VWErase = 13,
    VLNext = 14,
    VFlush = 15,
    VSwtch = 16,
    VStatus = 17,
    VDiscard = 18,
    IgnPar = 30,
    ParMrk = 31,
    INPck = 32,
    IStrip = 33,
    INlCr = 34,
    IgnCr = 35,
    ICrNl = 36,
    IUcLc = 37,
    IxOn = 38,
    IxAny = 39,
    IxOff = 40,
    IMaxBel = 41,
    IUtf8 = 42,
    ISig = 50,
    ICanon = 51,
    XCase = 52,
    Echo = 53,
    EchoE = 54,
    EchoK = 55,
    EchoNl = 56,
    NoFlsh = 57,
    TOStop = 58,
    IExten = 59,
    EchoCtl = 60,
    EchoKe = 61,
    Pendin = 62,
    OPost = 70,
    OLcUc = 71,
    ONlCr = 72,
    OCrNl = 73,
    ONoCr = 74,
    ONlRet = 75,
    Cs7 = 90,
    Cs8 = 91,
    ParenB = 92,
    ParOdd = 93,
    TtyOpISpeed = 128,
    TtyOpOSpeed = 129,
}

impl<'a> Decode<'a> for Option<Mode> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = u8::decode(input)?;
        let mode = match value {
            0 => return Ok(Decoded { value: None, next }),
            1 => Mode::VIntr,
            2 => Mode::VQuit,
            3 => Mode::VErase,
            4 => Mode::VKill,
            5 => Mode::VEof,
            6 => Mode::VEol,
            7 => Mode::VEol2,
            8 => Mode::VStart,
            9 => Mode::VStop,
            10 => Mode::VSusp,
            11 => Mode::VDSusp,
            12 => Mode::VReprint,
            13 => Mode::VWErase,
            14 => Mode::VLNext,
            15 => Mode::VFlush,
            16 => Mode::VSwtch,
            17 => Mode::VStatus,
            18 => Mode::VDiscard,
            30 => Mode::IgnPar,
            31 => Mode::ParMrk,
            32 => Mode::INPck,
            33 => Mode::IStrip,
            34 => Mode::INlCr,
            35 => Mode::IgnCr,
            36 => Mode::ICrNl,
            37 => Mode::IUcLc,
            38 => Mode::IxOn,
            39 => Mode::IxAny,
            40 => Mode::IxOff,
            41 => Mode::IMaxBel,
            42 => Mode::IUtf8,
            50 => Mode::ISig,
            51 => Mode::ICanon,
            52 => Mode::XCase,
            53 => Mode::Echo,
            54 => Mode::EchoE,
            55 => Mode::EchoK,
            56 => Mode::EchoNl,
            57 => Mode::NoFlsh,
            58 => Mode::TOStop,
            59 => Mode::IExten,
            60 => Mode::EchoCtl,
            61 => Mode::EchoKe,
            62 => Mode::Pendin,
            70 => Mode::OPost,
            71 => Mode::OLcUc,
            72 => Mode::ONlCr,
            73 => Mode::OCrNl,
            74 => Mode::ONoCr,
            75 => Mode::ONlRet,
            90 => Mode::Cs7,
            91 => Mode::Cs8,
            92 => Mode::ParenB,
            93 => Mode::ParOdd,
            128 => Mode::TtyOpISpeed,
            129 => Mode::TtyOpOSpeed,
            val => {
                warn!(%val, "unknown terminal mode code");
                return Err(Error::InvalidPacket("unknown terminal mode code"));
            }
        };

        Ok(Decoded {
            value: Some(mode),
            next,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ChannelRequestSuccess {
    pub(crate) recipient_channel: u32,
}

impl Encode for ChannelRequestSuccess {
    fn encode(&self, buffer: &mut Vec<u8>) {
        MessageType::ChannelSuccess.encode(buffer);
        self.recipient_channel.encode(buffer);
    }
}

#[expect(dead_code)]
#[derive(Debug)]
pub(crate) struct ChannelRequestFailure {
    recipient_channel: u32,
}

impl Encode for ChannelRequestFailure {
    fn encode(&self, buffer: &mut Vec<u8>) {
        MessageType::ChannelFailure.encode(buffer);
        self.recipient_channel.encode(buffer);
    }
}

pub(crate) struct ChannelData<'a> {
    pub(crate) recipient_channel: u32,
    pub(crate) data: Cow<'a, [u8]>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelData<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelData {
            return Err(Error::InvalidPacket("expected channel data packet"));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        let Decoded { value: data, next } = <&[u8]>::decode(next)?;

        match next.is_empty() {
            true => Ok(ChannelData {
                recipient_channel,
                data: Cow::Borrowed(data),
            }),
            false => Err(Error::InvalidPacket("extra data in channel data packet")),
        }
    }
}

impl Encode for ChannelData<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        MessageType::ChannelData.encode(buffer);
        self.recipient_channel.encode(buffer);
        self.data.as_ref().encode(buffer);
    }
}

impl fmt::Debug for ChannelData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelData")
            .field("recipient_channel", &self.recipient_channel)
            .field("data", &format_args!("[{} bytes]", self.data.len()))
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct ChannelEof {
    pub(crate) recipient_channel: u32,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelEof {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelEof {
            return Err(Error::InvalidPacket("expected channel eof packet"));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        match next.is_empty() {
            true => Ok(Self { recipient_channel }),
            false => Err(Error::InvalidPacket("extra data in channel eof packet")),
        }
    }
}

impl Encode for ChannelEof {
    fn encode(&self, buffer: &mut Vec<u8>) {
        MessageType::ChannelEof.encode(buffer);
        self.recipient_channel.encode(buffer);
    }
}

#[derive(Debug)]
pub(crate) struct ChannelClose {
    pub(crate) recipient_channel: u32,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelClose {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelClose {
            return Err(Error::InvalidPacket("expected channel close packet"));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        match next.is_empty() {
            true => Ok(Self { recipient_channel }),
            false => Err(Error::InvalidPacket("extra data in channel close packet")),
        }
    }
}

impl Encode for ChannelClose {
    fn encode(&self, buffer: &mut Vec<u8>) {
        MessageType::ChannelClose.encode(buffer);
        self.recipient_channel.encode(buffer);
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

impl<T: Encode> Encode for [T] {
    fn encode(&self, buf: &mut Vec<u8>) {
        let offset = buf.len();
        buf.extend_from_slice(&[0, 0, 0, 0]);
        let mut first = true;
        for name in self {
            match first {
                true => first = false,
                false => buf.push(b','),
            }

            name.encode(buf);
        }

        let len = (buf.len() - offset - 4) as u32;
        if let Some(slice) = buf.get_mut(offset..offset + 4) {
            slice.copy_from_slice(&len.to_be_bytes());
        }
    }
}

impl<'a, T: From<&'a str>> Decode<'a> for Vec<T> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value: len, next } = u32::decode(bytes)?;

        let Some(list) = next.get(..len as usize) else {
            return Err(Error::Incomplete(Some(len as usize - next.len())));
        };

        let Some(next) = next.get(len as usize..) else {
            return Err(Error::Unreachable("unable to extract rest after name list"));
        };

        let mut value = Self::new();
        if list.is_empty() {
            return Ok(Decoded { value, next });
        }

        for name in list.split(|&b| b == b',') {
            match str::from_utf8(name) {
                Ok(name) => value.push(T::from(name)),
                Err(_) => return Err(Error::InvalidPacket("invalid name")),
            }
        }

        Ok(Decoded { value, next })
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
