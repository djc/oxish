use core::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    borrow::Cow,
    collections::{btree_map::Entry, BTreeMap},
};

use tracing::{debug, warn};

use crate::{
    messages::{
        ChannelClose, ChannelData, ChannelEof, ChannelOpen, ChannelOpenConfirmation,
        ChannelOpenFailure, ChannelRequest, ChannelRequestSuccess, ChannelRequestType, ChannelType,
        Encode, IncomingPacket, MessageType, PtyReq,
    },
    terminal::Terminal,
    Error,
};

#[derive(Default)]
pub(crate) struct Channels {
    next_id: u32,
    channels: BTreeMap<u32, Channel>,
}

impl Channels {
    pub(crate) fn open(&mut self, open: ChannelOpen<'_>) -> OutgoingChannelMessage<'static> {
        if open.r#type != ChannelType::Session {
            return OutgoingChannelMessage::OpenFailure(ChannelOpenFailure::unknown_type(
                open.sender_channel,
            ));
        }

        let local_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let entry = match self.channels.entry(local_id) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(_) => {
                return OutgoingChannelMessage::OpenFailure(ChannelOpenFailure::duplicate_id(
                    open.sender_channel,
                ));
            }
        };

        let channel = entry.insert(Channel {
            remote_id: open.sender_channel,
            window_size: open.initial_window_size,
            maximum_packet_size: open.maximum_packet_size,
            env: Vec::new(),
            terminal: None,
            closed: ClosedState::default(),
        });

        OutgoingChannelMessage::OpenConfirmation(channel.confirmation(local_id))
    }

    pub(crate) fn request(
        &mut self,
        request: ChannelRequest<'_>,
    ) -> Result<Option<OutgoingChannelMessage<'static>>, Error> {
        let Some(channel) = self.channels.get_mut(&request.recipient_channel) else {
            return Err(Error::InvalidPacket(
                "channel request for unknown channel ID",
            ));
        };

        match request.r#type {
            ChannelRequestType::PtyReq(pty_req) => {
                channel.terminal = Some(TerminalState::Requested(pty_req.into_owned()));
            }
            ChannelRequestType::Env(env) => {
                channel
                    .env
                    .push((env.name.to_owned(), env.value.to_owned()));
            }
            ChannelRequestType::Shell => {
                let Some(TerminalState::Requested(pty_req)) = channel.terminal.take() else {
                    return Err(Error::InvalidPacket("shell request without prior pty-req"));
                };

                channel.terminal = Some(TerminalState::Running(Terminal::spawn(
                    &pty_req,
                    &channel.env,
                )?));
            }
        }

        Ok(request
            .want_reply
            .then(|| OutgoingChannelMessage::RequestSuccess(channel.success())))
    }

    pub(crate) fn data<'m, 's>(
        &'s mut self,
        data: &'m ChannelData<'m>,
    ) -> Result<Option<(&'s mut Terminal, &'m [u8])>, Error> {
        let Some(channel) = self.channels.get_mut(&data.recipient_channel) else {
            return Err(Error::InvalidPacket("channel data for unknown channel ID"));
        };

        debug!(len = %data.data.len(), "received channel data");
        Ok(match &mut channel.terminal {
            Some(TerminalState::Running(terminal)) => Some((terminal, &data.data)),
            _ => None,
        })
    }

    pub(crate) fn eof(&mut self, eof: &ChannelEof) -> Result<(), Error> {
        let Some(_) = self.channels.get_mut(&eof.recipient_channel) else {
            return Err(Error::InvalidPacket("channel eof for unknown channel ID"));
        };

        debug!(channel_id = %eof.recipient_channel, "received channel eof from client");
        Ok(())
    }

    pub(crate) fn close(
        &mut self,
        close: &ChannelClose,
    ) -> Option<OutgoingChannelMessage<'static>> {
        let Some(channel) = self.channels.get_mut(&close.recipient_channel) else {
            warn!(channel_id = %close.recipient_channel, "channel close for unknown channel ID");
            return None;
        };

        debug!(channel_id = %close.recipient_channel, "received channel close from client");
        channel.closed.received = true;
        let recipient_channel = channel.remote_id;
        let sent = channel.closed.sent;
        if sent {
            debug!(channel = %close.recipient_channel, "both sides closed channel; removing");
            self.channels.remove(&close.recipient_channel);
        }

        (!sent).then_some(OutgoingChannelMessage::Close(ChannelClose {
            recipient_channel,
        }))
    }

    pub(crate) fn poll_terminals<'a>(&'a mut self) -> TerminalsFuture<'a> {
        TerminalsFuture { channels: self }
    }
}

pub(crate) struct TerminalsFuture<'a> {
    channels: &'a mut Channels,
}

impl<'a> Future for TerminalsFuture<'a> {
    type Output = Result<Option<OutgoingChannelMessage<'static>>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        for (&local_id, channel) in self.channels.channels.iter_mut() {
            let Some(state) = &mut channel.terminal else {
                continue;
            };

            let terminal = match state {
                TerminalState::Running(terminal) => terminal,
                TerminalState::Requested(_) => continue,
                TerminalState::Closing => {
                    if channel.closed.sent {
                        continue;
                    }

                    channel.closed.sent = true;
                    let recipient_channel = channel.remote_id;
                    if channel.closed.received {
                        debug!(channel = local_id, "both sides closed channel; removing");
                        self.channels.channels.remove(&local_id);
                    }

                    return Poll::Ready(Ok(Some(OutgoingChannelMessage::Close(ChannelClose {
                        recipient_channel,
                    }))));
                }
            };

            let mut buf = [0u8; 4096];
            match terminal.poll_read(&mut buf, cx) {
                Poll::Ready(Ok(0)) => {
                    if let TerminalState::Running(terminal) =
                        mem::replace(state, TerminalState::Closing)
                    {
                        if let Poll::Ready(Err(err)) = terminal.poll_kill(cx) {
                            warn!(%err, "error killing terminal after EOF");
                            return Poll::Ready(Err(err.into()));
                        }
                    }

                    return Poll::Ready(Ok(Some(OutgoingChannelMessage::Eof(ChannelEof {
                        recipient_channel: channel.remote_id,
                    }))));
                }
                Poll::Ready(Ok(n)) => {
                    return Poll::Ready(Ok(Some(OutgoingChannelMessage::Data(ChannelData {
                        recipient_channel: channel.remote_id,
                        data: Cow::Owned(buf[..n].to_vec()),
                    }))));
                }
                Poll::Ready(Err(err)) => {
                    warn!(%err, "error reading from terminal");
                    if let TerminalState::Running(terminal) =
                        mem::replace(state, TerminalState::Closing)
                    {
                        if let Poll::Ready(Err(err)) = terminal.poll_kill(cx) {
                            warn!(%err, "error killing terminal after EOF");
                            return Poll::Ready(Err(err.into()));
                        }
                    }

                    return Poll::Ready(Err(err.into()));
                }
                Poll::Pending => continue,
            }
        }

        Poll::Pending
    }
}

#[derive(Debug)]
pub(crate) struct Channel {
    remote_id: u32,
    window_size: u32,
    maximum_packet_size: u32,
    env: Vec<(String, String)>,
    terminal: Option<TerminalState>,
    closed: ClosedState,
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

enum TerminalState {
    Requested(PtyReq<'static>),
    Running(Terminal),
    Closing,
}

impl fmt::Debug for TerminalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested(req) => f.debug_tuple("Requested").field(req).finish(),
            Self::Running(_) => f.debug_tuple("Running").field(&"...").finish(),
            Self::Closing => f.debug_tuple("Closing").finish(),
        }
    }
}

#[derive(Debug, Default)]
struct ClosedState {
    sent: bool,
    received: bool,
}

#[derive(Debug)]
pub(crate) enum OutgoingChannelMessage<'a> {
    OpenConfirmation(ChannelOpenConfirmation),
    OpenFailure(ChannelOpenFailure<'a>),
    RequestSuccess(ChannelRequestSuccess),
    Data(ChannelData<'a>),
    Eof(ChannelEof),
    Close(ChannelClose),
}

impl Encode for OutgoingChannelMessage<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::OpenConfirmation(msg) => msg.encode(buffer),
            Self::OpenFailure(msg) => msg.encode(buffer),
            Self::RequestSuccess(msg) => msg.encode(buffer),
            Self::Data(msg) => msg.encode(buffer),
            Self::Eof(msg) => msg.encode(buffer),
            Self::Close(msg) => msg.encode(buffer),
        }
    }
}

#[derive(Debug)]
pub(crate) enum IncomingChannelMessage<'a> {
    Open(ChannelOpen<'a>),
    Request(ChannelRequest<'a>),
    Data(ChannelData<'a>),
    Eof(ChannelEof),
    Close(ChannelClose),
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
            MessageType::ChannelData => {
                Ok(IncomingChannelMessage::Data(ChannelData::try_from(packet)?))
            }
            MessageType::ChannelEof => {
                Ok(IncomingChannelMessage::Eof(ChannelEof::try_from(packet)?))
            }
            MessageType::ChannelClose => Ok(IncomingChannelMessage::Close(ChannelClose::try_from(
                packet,
            )?)),
            _ => {
                warn!(?packet.message_type, "unexpected channel message type");
                Err(Error::InvalidPacket("unexpected channel message type"))
            }
        }
    }
}
