use core::str;
use std::collections::BTreeMap;

use crate::{
    proto::{Decode, Decoded, IncomingPacket, MessageType},
    Error,
};

#[derive(Default)]
pub(crate) struct Channels {
    next_id: u32,
    channels: BTreeMap<u32, Channel>,
}

impl Channels {
    pub(crate) fn handle(&mut self, message: IncomingChannelMessage<'_>) -> Result<(), Error> {
        match message {
            IncomingChannelMessage::Open(open) => {
                let local_id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.channels.insert(
                    local_id,
                    Channel {
                        remote_id: open.sender_channel,
                        window_size: open.initial_window_size,
                        maximum_packet_size: open.maximum_packet_size,
                    },
                );
            }
        }
        Ok(())
    }
}

#[expect(dead_code)]
#[derive(Debug)]
pub(crate) struct Channel {
    remote_id: u32,
    window_size: u32,
    maximum_packet_size: u32,
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
    #[expect(dead_code)]
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

#[derive(Debug)]
pub(crate) enum ChannelType<'a> {
    Session,
    #[expect(dead_code)]
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
