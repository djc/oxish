use core::str;
use std::collections::{btree_map::Entry, BTreeMap};

use crate::{
    proto::{Decode, Decoded, Encode, IncomingPacket, MessageType},
    Error,
};

#[derive(Default)]
pub(crate) struct Channels {
    next_id: u32,
    channels: BTreeMap<u32, Channel>,
}

impl Channels {
    pub(crate) fn handle(
        &mut self,
        message: IncomingChannelMessage<'_>,
    ) -> Result<Option<OutgoingChannelMessage<'static>>, Error> {
        debug!(?message, "handling channel message");
        match message {
            IncomingChannelMessage::Open(open) => {
                if open.r#type != ChannelType::Session {
                    return Ok(Some(OutgoingChannelMessage::OpenFailure(
                        ChannelOpenFailure::unknown_type(open.sender_channel),
                    )));
                }

                let local_id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                let entry = match self.channels.entry(local_id) {
                    Entry::Vacant(entry) => entry,
                    Entry::Occupied(_) => {
                        return Ok(Some(OutgoingChannelMessage::OpenFailure(
                            ChannelOpenFailure::duplicate_id(open.sender_channel),
                        )));
                    }
                };

                let channel = entry.insert(Channel {
                    remote_id: open.sender_channel,
                    window_size: open.initial_window_size,
                    maximum_packet_size: open.maximum_packet_size,
                });

                Ok(Some(OutgoingChannelMessage::OpenConfirmation(
                    channel.confirmation(local_id),
                )))
            }
            IncomingChannelMessage::Request(request) => {
                let Some(channel) = self.channels.get(&request.recipient_channel) else {
                    return Err(Error::InvalidPacket(
                        "channel request for unknown channel ID",
                    ));
                };

                match request.r#type {
                    ChannelRequestType::PtyReq(_) if request.want_reply => Ok(Some(
                        OutgoingChannelMessage::RequestSuccess(channel.success()),
                    )),
                    ChannelRequestType::PtyReq(_) => Ok(None),
                    ChannelRequestType::Unknown(_) => {
                        Err(Error::InvalidPacket("channel request of unknown type"))
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct Channel {
    remote_id: u32,
    window_size: u32,
    maximum_packet_size: u32,
}

impl Channel {
    fn confirmation(&self, local_id: u32) -> ChannelOpenConfirmation {
        ChannelOpenConfirmation {
            recipient_channel: self.remote_id,
            sender_channel: local_id,
            initial_window_size: self.window_size,
            maximum_packet_size: self.maximum_packet_size,
        }
    }

    fn success(&self) -> ChannelRequestSuccess {
        ChannelRequestSuccess {
            recipient_channel: self.remote_id,
        }
    }
}

#[derive(Debug)]
pub(crate) enum OutgoingChannelMessage<'a> {
    OpenConfirmation(ChannelOpenConfirmation),
    OpenFailure(ChannelOpenFailure<'a>),
    RequestSuccess(ChannelRequestSuccess),
}

impl Encode for OutgoingChannelMessage<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::OpenConfirmation(msg) => msg.encode(buffer),
            Self::OpenFailure(msg) => msg.encode(buffer),
            Self::RequestSuccess(msg) => msg.encode(buffer),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ChannelOpenConfirmation {
    recipient_channel: u32,
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
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
    fn duplicate_id(recipient_channel: u32) -> Self {
        Self {
            recipient_channel,
            reason_code: ChannelOpenFailureReason::AdministrativelyProhibited,
            description: "channel ID already in use",
        }
    }

    fn unknown_type(recipient_channel: u32) -> Self {
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
pub(crate) struct ChannelRequestSuccess {
    recipient_channel: u32,
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

#[derive(Debug)]
pub(crate) enum IncomingChannelMessage<'a> {
    Open(ChannelOpen<'a>),
    Request(ChannelRequest<'a>),
}

impl<'a> TryFrom<IncomingPacket<'a>> for IncomingChannelMessage<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        match packet.message_type {
            MessageType::ChannelOpen => {
                Ok(IncomingChannelMessage::Open(ChannelOpen::try_from(packet)?))
            }
            MessageType::ChannelRequest => Ok(IncomingChannelMessage::Request(
                ChannelRequest::try_from(packet)?,
            )),
            _ => Err(Error::InvalidPacket("unexpected channel message type")),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ChannelRequest<'a> {
    recipient_channel: u32,
    r#type: ChannelRequestType<'a>,
    want_reply: bool,
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
            _ => return Err(Error::InvalidPacket("unknown channel request type")),
        };

        Ok(ChannelRequest {
            recipient_channel,
            r#type,
            want_reply,
        })
    }
}

#[derive(Debug)]
enum ChannelRequestType<'a> {
    #[expect(dead_code)]
    PtyReq(PtyReq<'a>),
    #[expect(dead_code)]
    Unknown(&'a str),
}

#[derive(Debug)]
struct PtyReq<'a> {
    #[expect(dead_code)]
    term: &'a str,
    #[expect(dead_code)]
    cols: u32,
    #[expect(dead_code)]
    rows: u32,
    #[expect(dead_code)]
    width_px: u32,
    #[expect(dead_code)]
    height_px: u32,
    #[expect(dead_code)]
    terminal_modes: BTreeMap<Mode, u32>,
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
                term,
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
enum Mode {
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
            _ => return Err(Error::InvalidPacket("unknown terminal mode code")),
        };

        Ok(Decoded {
            value: Some(mode),
            next,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ChannelOpen<'a> {
    r#type: ChannelType<'a>,
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
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
