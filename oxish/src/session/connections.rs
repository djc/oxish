use core::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, btree_map::Entry},
};

use proto::{
    Encode, Encoder, IncomingPacket, MAX_PACKET_LEN, MessageType, ProtoError,
    channels::{
        ChannelClose, ChannelData, ChannelEof, ChannelOpen, ChannelOpenConfirmation,
        ChannelOpenFailure, ChannelRequest, ChannelRequestFailure, ChannelRequestSuccess,
        ChannelRequestType, ChannelWindowAdjust, PtyReq,
    },
    named::ChannelType,
};
use tracing::{debug, warn};

use super::terminal::Terminal;
use crate::Error;

#[derive(Default)]
pub(crate) struct Channels {
    next_id: u32,
    channels: BTreeMap<u32, Channel>,
}

impl Channels {
    pub(crate) fn open(
        &mut self,
        open: ChannelOpen<'_>,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), Error> {
        if open.r#type != ChannelType::Session {
            encoder.encode(&ChannelOpenFailure::unknown_type(open.sender_channel))?;
            return Ok(());
        }

        let local_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let entry = match self.channels.entry(local_id) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(_) => {
                encoder.encode(&ChannelOpenFailure::duplicate_id(open.sender_channel))?;
                return Ok(());
            }
        };

        let channel = entry.insert(Channel {
            remote_id: open.sender_channel,
            send_window: open.initial_window_size,
            receive_window: 0,
            maximum_packet_size: open.maximum_packet_size,
            env: Vec::new(),
            terminal: None,
            closed: ClosedState::default(),
        });

        encoder.encode(&channel.confirmation(local_id))?;
        Ok(())
    }

    pub(crate) fn request(
        &mut self,
        request: ChannelRequest<'_>,
        encoder: &mut Encoder<'_>,
        banner: Option<&str>,
    ) -> Result<(), Error> {
        let Some(channel) = self.channels.get_mut(&request.recipient_channel) else {
            return Err(ProtoError::InvalidPacket("channel request for unknown channel ID").into());
        };

        match request.r#type {
            ChannelRequestType::PtyReq(pty_req) => {
                channel.terminal = Some(TerminalState::Requested(pty_req.into_owned()));
            }
            ChannelRequestType::Env(env) => {
                const ALLOW_ENV: &[&str] = &["TZ", "LANG"];
                match ALLOW_ENV.contains(&env.name) || env.name.starts_with("LC_") {
                    true if channel.env.len() < 32 => channel
                        .env
                        .push((env.name.to_owned(), env.value.to_owned())),
                    _ => {
                        debug!(name = env.name, "ignoring environment variable request");
                        if request.want_reply {
                            encoder.encode(&channel.failure())?;
                        }
                        return Ok(());
                    }
                }
            }
            ChannelRequestType::Shell => {
                let Some(TerminalState::Requested(pty_req)) = channel.terminal.take() else {
                    return Err(
                        ProtoError::InvalidPacket("shell request without prior pty-req").into(),
                    );
                };

                channel.terminal = Some(TerminalState::Running(Terminal::spawn(
                    &pty_req,
                    &channel.env,
                )?));

                channel.receive_window = INITIAL_WINDOW_SIZE;
                encoder.encode(&ChannelWindowAdjust {
                    recipient_channel: channel.remote_id,
                    bytes_to_add: INITIAL_WINDOW_SIZE,
                })?;
            }
            ChannelRequestType::WindowChange(window_change) => match &channel.terminal {
                Some(TerminalState::Running(terminal)) => terminal.resize(&window_change)?,
                _ => warn!("window-change request without running terminal"),
            },
            // Agent forwarding is not supported -- only reply when asked
            ChannelRequestType::AuthAgentReq | ChannelRequestType::Unknown(_) => {
                if request.want_reply {
                    encoder.encode(&channel.failure())?;
                }
                return Ok(());
            }
        }

        if request.want_reply {
            encoder.encode(&channel.success())?;
        }

        let Some(banner) = banner else {
            return Ok(());
        };

        let Some(window) = channel.send_window.checked_sub(banner.len() as u32) else {
            return Ok(());
        };

        channel.send_window = window;
        encoder.encode(&ChannelData {
            recipient_channel: channel.remote_id,
            data: Cow::Borrowed(banner.as_bytes()),
        })?;
        Ok(())
    }

    pub(crate) fn adjust_window(&mut self, adjust: &ChannelWindowAdjust) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&adjust.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel window adjust for unknown channel ID",
            ));
        };

        if u32::MAX - channel.send_window < adjust.bytes_to_add {
            debug!(channel_id = %adjust.recipient_channel, "window adjust would overflow; capping");
        }

        channel.send_window = channel.send_window.saturating_add(adjust.bytes_to_add);
        Ok(())
    }

    pub(crate) fn data<'m, 's>(
        &'s mut self,
        data: &'m ChannelData<'m>,
        encoder: &mut Encoder<'_>,
    ) -> Result<Option<(&'s mut Terminal, &'m [u8])>, ProtoError> {
        let Some(channel) = self.channels.get_mut(&data.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel data for unknown channel ID",
            ));
        };

        match channel.receive_window.checked_sub(data.data.len() as u32) {
            Some(window) => channel.receive_window = window,
            None => {
                return Err(ProtoError::InvalidPacket(
                    "channel data exceeds receive window",
                ));
            }
        }

        if channel.receive_window < INITIAL_WINDOW_SIZE / 2 {
            debug!(channel_id = %data.recipient_channel, "receive window low; sending window adjust");
            let bytes_to_add = INITIAL_WINDOW_SIZE - channel.receive_window;
            channel.receive_window = INITIAL_WINDOW_SIZE;
            encoder.encode(&ChannelWindowAdjust {
                recipient_channel: channel.remote_id,
                bytes_to_add,
            })?;
        }

        debug!(len = %data.data.len(), "received channel data");
        Ok(match &mut channel.terminal {
            Some(TerminalState::Running(terminal)) => Some((terminal, &data.data)),
            _ => None,
        })
    }

    pub(crate) fn eof(&mut self, eof: &ChannelEof) -> Result<(), ProtoError> {
        let Some(_) = self.channels.get_mut(&eof.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel eof for unknown channel ID",
            ));
        };

        debug!(channel_id = %eof.recipient_channel, "received channel eof from client");
        Ok(())
    }

    pub(crate) fn close(
        &mut self,
        close: &ChannelClose,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), Error> {
        let Some(channel) = self.channels.get_mut(&close.recipient_channel) else {
            warn!(channel_id = %close.recipient_channel, "channel close for unknown channel ID");
            return Ok(());
        };

        debug!(channel_id = %close.recipient_channel, "received channel close from client");
        channel.closed.received = true;
        let recipient_channel = channel.remote_id;
        let sent = channel.closed.sent;
        if sent {
            debug!(channel = %close.recipient_channel, "both sides closed channel; removing");
            self.channels.remove(&close.recipient_channel);
        }

        if !sent {
            encoder.encode(&ChannelClose { recipient_channel })?;
        }

        Ok(())
    }

    pub(crate) fn channels_mut(&mut self) -> &mut BTreeMap<u32, Channel> {
        &mut self.channels
    }
}

pub(crate) struct TerminalsFuture<'a> {
    channels: &'a mut BTreeMap<u32, Channel>,
}

impl<'a> TerminalsFuture<'a> {
    pub(crate) fn new(channels: &'a mut BTreeMap<u32, Channel>) -> Self {
        Self { channels }
    }
}

impl<'a> Future for TerminalsFuture<'a> {
    type Output = Result<Option<OutgoingChannelMessage<'static>>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        for (&local_id, channel) in self.channels.iter_mut() {
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
                        self.channels.remove(&local_id);
                    }

                    return Poll::Ready(Ok(Some(OutgoingChannelMessage::Close(ChannelClose {
                        recipient_channel,
                    }))));
                }
            };

            let mut buf = [0u8; 4096];
            let limit = Ord::min(channel.maximum_packet_size, channel.send_window) as usize;
            let writable = match limit {
                0 => continue,
                _ if limit < buf.len() => &mut buf[..limit],
                _ => &mut buf,
            };

            match terminal.poll_read(writable, cx) {
                Poll::Ready(result @ Ok(0)) | Poll::Ready(result @ Err(_)) => {
                    if let TerminalState::Running(terminal) =
                        mem::replace(state, TerminalState::Closing)
                    {
                        if let Poll::Ready(Err(error)) = terminal.poll_kill(cx) {
                            warn!(%error, "error killing terminal");
                            return Poll::Ready(Err(error.into()));
                        }
                    }

                    return Poll::Ready(match result {
                        Ok(_) => Ok(Some(OutgoingChannelMessage::Eof(ChannelEof {
                            recipient_channel: channel.remote_id,
                        }))),
                        Err(error) => {
                            warn!(%error, "error reading from terminal");
                            Err(error.into())
                        }
                    });
                }
                Poll::Ready(Ok(n)) => {
                    channel.send_window = channel.send_window.saturating_sub(n as u32);
                    return Poll::Ready(Ok(Some(OutgoingChannelMessage::Data(ChannelData {
                        recipient_channel: channel.remote_id,
                        data: Cow::Owned(buf[..n].to_vec()),
                    }))));
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
    send_window: u32,
    receive_window: u32,
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
            initial_window_size: 0,
            maximum_packet_size: MAX_PACKET_LEN - 64, // Leave some room for packet overhead
        }
    }

    fn success(&self) -> ChannelRequestSuccess {
        ChannelRequestSuccess {
            recipient_channel: self.remote_id,
        }
    }

    fn failure(&self) -> ChannelRequestFailure {
        ChannelRequestFailure {
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
    Data(ChannelData<'a>),
    Eof(ChannelEof),
    Close(ChannelClose),
}

impl Encode for OutgoingChannelMessage<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
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
    WindowAdjust(ChannelWindowAdjust),
    Eof(ChannelEof),
    Close(ChannelClose),
}

impl<'a> TryFrom<IncomingPacket<'a>> for IncomingChannelMessage<'a> {
    type Error = ProtoError;

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
            MessageType::ChannelWindowAdjust => Ok(IncomingChannelMessage::WindowAdjust(
                ChannelWindowAdjust::try_from(packet)?,
            )),
            MessageType::ChannelEof => {
                Ok(IncomingChannelMessage::Eof(ChannelEof::try_from(packet)?))
            }
            MessageType::ChannelClose => Ok(IncomingChannelMessage::Close(ChannelClose::try_from(
                packet,
            )?)),
            _ => Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[
                    MessageType::ChannelOpen,
                    MessageType::ChannelRequest,
                    MessageType::ChannelData,
                    MessageType::ChannelWindowAdjust,
                    MessageType::ChannelEof,
                    MessageType::ChannelClose,
                ],
            )),
        }
    }
}

const INITIAL_WINDOW_SIZE: u32 = 16 * MAX_PACKET_LEN;
