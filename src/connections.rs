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
    ) -> Result<OutgoingChannelMessage<'static>, Error> {
        match dbg!(message) {
            IncomingChannelMessage::Open(open) => {
                if open.r#type != ChannelType::Session {
                    return Ok(OutgoingChannelMessage::OpenFailure(
                        ChannelOpenFailure::unknown_type(open.sender_channel),
                    ));
                }

                let local_id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                let entry = match self.channels.entry(local_id) {
                    Entry::Vacant(entry) => entry,
                    Entry::Occupied(_) => {
                        return Ok(OutgoingChannelMessage::OpenFailure(
                            ChannelOpenFailure::duplicate_id(open.sender_channel),
                        ));
                    }
                };

                let channel = entry.insert(Channel {
                    remote_id: open.sender_channel,
                    window_size: open.initial_window_size,
                    maximum_packet_size: open.maximum_packet_size,
                });

                Ok(OutgoingChannelMessage::OpenConfirmation(
                    channel.confirmation(local_id),
                ))
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
}

#[derive(Debug)]
pub(crate) enum OutgoingChannelMessage<'a> {
    OpenConfirmation(ChannelOpenConfirmation),
    OpenFailure(ChannelOpenFailure<'a>),
}

impl Encode for OutgoingChannelMessage<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::OpenConfirmation(msg) => msg.encode(buffer),
            Self::OpenFailure(msg) => msg.encode(buffer),
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
pub(crate) enum IncomingChannelMessage<'a> {
    Open(ChannelOpen<'a>),
}

impl<'a> TryFrom<IncomingPacket<'a>> for IncomingChannelMessage<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        match packet.message_type {
            MessageType::ChannelOpen => {
                Ok(IncomingChannelMessage::Open(ChannelOpen::try_from(packet)?))
            }
            _ => Err(Error::InvalidPacket("unexpected channel message type")),
        }
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
