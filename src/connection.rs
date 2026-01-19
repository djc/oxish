use core::sync::atomic::AtomicU64;
use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
};

use crate::{
    proto::{Decode, Decoded, Encode, IncomingPacket, MessageType, OutgoingPacket},
    service::{ConnectionEvent, Service},
    Error,
};

const BUFFER_SIZE: u32 = 1024;

pub(crate) struct SshConnectionService {
    connection_id: ConnectionId,
    next_channel_id: u32,
    channels: HashMap<u32, ChannelState>,
    pending_channels: VecDeque<PendingChannelData>,
    pending_packets: VecDeque<OutgoingPacket<'static>>,
}

impl Service for SshConnectionService {
    const NAME: &'static [u8] = b"ssh-connection";

    fn poll_transmit(&mut self) -> Option<OutgoingPacket<'_>> {
        self.pending_packets.pop_front()
    }

    fn poll_event(&mut self) -> Option<ConnectionEvent> {
        // FIXME: Implement clean closing of connections.
        None
    }

    fn handle_packet(&mut self, packet: IncomingPacket<'_>) -> Result<(), Error> {
        match packet.message_type {
            MessageType::ChannelOpen => {
                let message = ChannelOpen::try_from(packet)?;
                self.pending_channels.push_back(PendingChannelData {
                    channel_type: message.channel_type.to_vec(),
                    remote_id: message.remote_id,
                    initial_window_size: message.initial_window_size,
                    max_packet_size: message.max_packet_size,
                    type_specific_data: message.type_specific_data.to_vec(),
                });
            }
            MessageType::ChannelData => {
                let message = ChannelData::try_from(packet)?;
                if let Some(ChannelState::Active(channel_state)) =
                    self.channels.get_mut(&message.channel_id)
                {
                    channel_state.stdin.extend_from_slice(message.data);
                }
            }
            MessageType::ChannelWindowAdjust => {
                let message = ChannelWindowAdjust::try_from(packet)?;
                if let Some(ChannelState::Active(channel_state)) =
                    self.channels.get_mut(&message.channel_id)
                {
                    channel_state.window_size = channel_state
                        .window_size
                        .saturating_add(message.bytes_to_add);
                }
            }
            MessageType::ChannelClose => {
                let message = ChannelClose::try_from(packet)?;
                if let Some(ChannelState::Active(channel_state)) =
                    self.channels.get_mut(&message.channel_id)
                {
                    self.pending_packets.push_back(
                        ChannelClose {
                            channel_id: channel_state.remote_id,
                        }
                        .into_packet(),
                    );
                }
                self.channels.remove(&message.channel_id);
            }
            MessageType::ChannelRequest => {
                let message = ChannelRequest::try_from(packet)?;
                if let Some(ChannelState::Active(channel_state)) =
                    self.channels.get_mut(&message.channel_id)
                {
                    // FIXME: Implement proper handling instead of this shim to make the remote happy
                    match message.request_type {
                        b"pty-req" | b"shell" if message.want_reply => {
                            self.pending_packets.push_back(
                                ChannelSuccess {
                                    channel_id: channel_state.remote_id,
                                }
                                .into_packet(),
                            );
                        }
                        _ if message.want_reply => {
                            self.pending_packets.push_back(
                                ChannelFailure {
                                    channel_id: channel_state.remote_id,
                                }
                                .into_packet(),
                            );
                        }
                        _ => {}
                    }
                }
            }
            _ => self.pending_packets.push_back(packet.unimplemented()),
        }

        Ok(())
    }
}

impl SshConnectionService {
    #[expect(unused)]
    pub(crate) fn new() -> Self {
        Self {
            connection_id: ConnectionId::new(),
            next_channel_id: 0,
            channels: HashMap::new(),
            pending_channels: VecDeque::new(),
            pending_packets: VecDeque::new(),
        }
    }

    #[expect(unused)]
    pub(crate) fn poll_pending_channel<'a>(&'a mut self) -> Option<PendingChannel<'a>> {
        self.pending_channels
            .pop_front()
            .map(|data| PendingChannel {
                data,
                connection: self,
            })
    }

    fn get_next_channel_id(&mut self) -> u32 {
        loop {
            let id = self.next_channel_id;
            self.next_channel_id += 1;
            if !self.channels.contains_key(&id) {
                return id;
            }
        }
    }
}

pub(crate) struct PendingChannel<'a> {
    data: PendingChannelData,
    connection: &'a mut SshConnectionService,
}

impl PendingChannel<'_> {
    #[expect(unused)]
    pub(crate) fn channel_type(&self) -> &[u8] {
        &self.data.channel_type
    }

    #[expect(unused)]
    pub(crate) fn type_specific_data(&self) -> &[u8] {
        &self.data.type_specific_data
    }

    #[expect(unused)]
    pub(crate) fn accept(self) -> ChannelId {
        let our_id = self.connection.get_next_channel_id();
        self.connection.pending_packets.push_back(
            ChannelOpenConfirmation {
                remote_id: self.data.remote_id,
                our_id,
                initial_window_size: BUFFER_SIZE,
                maximum_packet_size: BUFFER_SIZE,
            }
            .into_packet(),
        );
        self.connection.channels.insert(
            our_id,
            ChannelState::Active(ActiveChannelData {
                remote_id: self.data.remote_id,
                window_size: self.data.initial_window_size,
                max_packet_size: self.data.max_packet_size,
                stdin: vec![],
            }),
        );

        let result = ChannelId {
            connection_id: self.connection.connection_id,
            our_channel_id: our_id,
        };
        //Inhibit drop
        core::mem::forget(self);
        result
    }

    #[expect(unused)]
    pub(crate) fn decline(self) {
        // Actual logic is in drop of self.
    }
}

impl Drop for PendingChannel<'_> {
    fn drop(&mut self) {
        self.connection.pending_packets.push_back(
            ChannelOpenFailure {
                remote_id: self.data.remote_id,
            }
            .into_packet(),
        );
    }
}

pub(crate) struct Channel<'a> {
    id: u32,
    connection: &'a mut SshConnectionService,
}

impl Channel<'_> {
    #[expect(unused)]
    pub(crate) fn poll_recv(&mut self) -> Option<Vec<u8>> {
        let Some(ChannelState::Active(state)) = self.connection.channels.get_mut(&self.id) else {
            unreachable!("Channel struct for non-existing channel");
        };

        if state.stdin.is_empty() {
            None
        } else {
            let mut result = vec![];
            core::mem::swap(&mut result, &mut state.stdin);
            self.connection.pending_packets.push_back(
                ChannelWindowAdjust {
                    channel_id: state.remote_id,
                    bytes_to_add: state.stdin.len() as u32,
                }
                .into_packet(),
            );
            Some(result)
        }
    }

    #[expect(unused)]
    fn send(&mut self, buf: &[u8]) -> usize {
        let Some(ChannelState::Active(state)) = self.connection.channels.get_mut(&self.id) else {
            unreachable!("Channel struct for non-existing channel");
        };

        let output_len = buf
            .len()
            .min(state.max_packet_size.min(state.window_size) as usize);
        if output_len > 0 {
            self.connection.pending_packets.push_back(
                ChannelData {
                    channel_id: state.remote_id,
                    data: &buf[..output_len],
                }
                .into_packet(),
            );
            state.window_size -= output_len as u32;
        }

        output_len
    }

    #[expect(unused)]
    fn close(self) {
        let Some(ChannelState::Active(state)) = self.connection.channels.get_mut(&self.id) else {
            unreachable!("Channel struct for non-existing channel");
        };

        self.connection.pending_packets.push_back(
            ChannelClose {
                channel_id: state.remote_id,
            }
            .into_packet(),
        );
        *self.connection.channels.get_mut(&self.id).unwrap() = ChannelState::Closing;
    }
}

struct PendingChannelData {
    channel_type: Vec<u8>,
    remote_id: u32,
    initial_window_size: u32,
    max_packet_size: u32,
    type_specific_data: Vec<u8>,
}

enum ChannelState {
    Closing,
    Active(ActiveChannelData),
}

struct ActiveChannelData {
    remote_id: u32,
    window_size: u32,
    max_packet_size: u32,
    stdin: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ChannelId {
    connection_id: ConnectionId,
    our_channel_id: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct ConnectionId {
    id: u64,
}

impl ConnectionId {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self {
            id: NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[expect(
    unused,
    reason = "Use marking from the service trait is failing in the compiler"
)]
struct ChannelOpen<'a> {
    channel_type: &'a [u8],
    remote_id: u32,
    initial_window_size: u32,
    max_packet_size: u32,
    type_specific_data: &'a [u8],
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelOpen<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelOpen {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: channel_type,
            next,
        } = <&[u8]>::decode(packet.payload)?;
        let Decoded {
            value: remote_id,
            next,
        } = u32::decode(next)?;
        let Decoded {
            value: initial_window_size,
            next,
        } = u32::decode(next)?;
        let Decoded {
            value: max_packet_size,
            next: type_specific_data,
        } = u32::decode(next)?;
        Ok(ChannelOpen {
            channel_type,
            remote_id,
            initial_window_size,
            max_packet_size,
            type_specific_data,
        })
    }
}

struct ChannelOpenConfirmation {
    remote_id: u32,
    our_id: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
}

impl ChannelOpenConfirmation {
    fn into_packet(self) -> OutgoingPacket<'static> {
        let mut payload = Vec::with_capacity(16);
        self.remote_id.encode(&mut payload);
        self.our_id.encode(&mut payload);
        self.initial_window_size.encode(&mut payload);
        self.maximum_packet_size.encode(&mut payload);
        OutgoingPacket {
            message_type: MessageType::ChannelOpenConfirmation,
            payload: Cow::Owned(payload),
        }
    }
}

struct ChannelOpenFailure {
    remote_id: u32,
}

impl ChannelOpenFailure {
    fn into_packet(self) -> OutgoingPacket<'static> {
        let mut payload = Vec::with_capacity(16);
        self.remote_id.encode(&mut payload);
        2u32.encode(&mut payload);
        b"".encode(&mut payload);
        b"".encode(&mut payload);
        OutgoingPacket {
            message_type: MessageType::ChannelOpenFailure,
            payload: Cow::Owned(payload),
        }
    }
}

struct ChannelData<'a> {
    channel_id: u32,
    data: &'a [u8],
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelData<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelData {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: channel_id,
            next,
        } = u32::decode(packet.payload)?;
        let Decoded { value: data, .. } = <&[u8]>::decode(next)?;

        Ok(ChannelData { channel_id, data })
    }
}

impl ChannelData<'_> {
    fn into_packet(self) -> OutgoingPacket<'static> {
        let mut payload = Vec::with_capacity(self.data.len() + 8);
        self.channel_id.encode(&mut payload);
        self.data.encode(&mut payload);
        OutgoingPacket {
            message_type: MessageType::ChannelData,
            payload: Cow::Owned(payload),
        }
    }
}

struct ChannelWindowAdjust {
    channel_id: u32,
    bytes_to_add: u32,
}

impl TryFrom<IncomingPacket<'_>> for ChannelWindowAdjust {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'_>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelWindowAdjust {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: channel_id,
            next,
        } = u32::decode(packet.payload)?;
        let Decoded {
            value: bytes_to_add,
            ..
        } = u32::decode(next)?;

        Ok(Self {
            channel_id,
            bytes_to_add,
        })
    }
}

impl ChannelWindowAdjust {
    fn into_packet(self) -> OutgoingPacket<'static> {
        let mut payload = Vec::with_capacity(8);
        self.channel_id.encode(&mut payload);
        self.bytes_to_add.encode(&mut payload);
        OutgoingPacket {
            message_type: MessageType::ChannelWindowAdjust,
            payload: Cow::Owned(payload),
        }
    }
}

struct ChannelClose {
    channel_id: u32,
}

impl TryFrom<IncomingPacket<'_>> for ChannelClose {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'_>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelClose {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: channel_id, ..
        } = u32::decode(packet.payload)?;

        Ok(Self { channel_id })
    }
}

impl ChannelClose {
    fn into_packet(self) -> OutgoingPacket<'static> {
        let mut payload = Vec::with_capacity(4);
        self.channel_id.encode(&mut payload);
        OutgoingPacket {
            message_type: MessageType::ChannelClose,
            payload: Cow::Owned(payload),
        }
    }
}

#[expect(
    unused,
    reason = "Use marking from the service trait is failing in the compiler"
)]
struct ChannelRequest<'a> {
    channel_id: u32,
    request_type: &'a [u8],
    want_reply: bool,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelRequest<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelRequest {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: channel_id,
            next,
        } = u32::decode(packet.payload)?;
        let Decoded {
            value: request_type,
            next,
        } = <&[u8]>::decode(next)?;
        let Decoded {
            value: want_reply, ..
        } = bool::decode(next)?;

        Ok(ChannelRequest {
            channel_id,
            request_type,
            want_reply,
        })
    }
}

struct ChannelSuccess {
    channel_id: u32,
}

impl ChannelSuccess {
    #[expect(
        unused,
        reason = "Use marking from the service trait is failing in the compiler"
    )]
    fn into_packet(self) -> OutgoingPacket<'static> {
        let mut payload = Vec::with_capacity(4);
        self.channel_id.encode(&mut payload);
        OutgoingPacket {
            message_type: MessageType::ChannelSuccess,
            payload: Cow::Owned(payload),
        }
    }
}

struct ChannelFailure {
    channel_id: u32,
}

impl ChannelFailure {
    #[expect(
        unused,
        reason = "Use marking from the service trait is failing in the compiler"
    )]
    fn into_packet(self) -> OutgoingPacket<'static> {
        let mut payload = Vec::with_capacity(4);
        self.channel_id.encode(&mut payload);
        OutgoingPacket {
            message_type: MessageType::ChannelFailure,
            payload: Cow::Owned(payload),
        }
    }
}
