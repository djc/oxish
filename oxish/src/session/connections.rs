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
    ChannelClose, ChannelData, ChannelEof, ChannelOpen, ChannelOpenConfirmation,
    ChannelOpenFailure, ChannelRequest, ChannelRequestFailure, ChannelRequestSuccess,
    ChannelRequestType, ChannelType, ChannelWindowAdjust, Encode, Encoder, IncomingPacket,
    MessageType, ProtoError, PtyReq,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    net::UnixStream,
};
use tracing::{debug, warn};

use super::agent::AgentListener;
use super::terminal::Terminal;
use crate::Error;

/// Initial window size offered for server-opened agent channels
const AGENT_WINDOW_SIZE: u32 = 64 * 1024;
/// Maximum packet size offered for server-opened agent channels
const AGENT_MAXIMUM_PACKET_SIZE: u32 = 16 * 1024;

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
            encoder.enqueue(&ChannelOpenFailure::unknown_type(open.sender_channel))?;
            return Ok(());
        }

        let local_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let entry = match self.channels.entry(local_id) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(_) => {
                encoder.enqueue(&ChannelOpenFailure::duplicate_id(open.sender_channel))?;
                return Ok(());
            }
        };

        let channel = entry.insert(Channel {
            remote_id: open.sender_channel,
            window_size: open.initial_window_size,
            maximum_packet_size: open.maximum_packet_size,
            kind: ChannelKind::Session {
                env: Vec::new(),
                terminal: None,
                agent: None,
            },
            closed: ClosedState::default(),
        });

        encoder.enqueue(&channel.confirmation(local_id))?;
        Ok(())
    }

    pub(crate) fn request(
        &mut self,
        request: ChannelRequest<'_>,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), Error> {
        let Some(channel) = self.channels.get_mut(&request.recipient_channel) else {
            return Err(ProtoError::InvalidPacket("channel request for unknown channel ID").into());
        };

        let failure = channel.failure();
        let ChannelKind::Session {
            env,
            terminal,
            agent,
        } = &mut channel.kind
        else {
            warn!("channel request for non-session channel");
            if request.want_reply {
                encoder.enqueue(&failure)?;
            }
            return Ok(());
        };

        match request.r#type {
            ChannelRequestType::PtyReq(pty_req) => {
                *terminal = Some(Box::new(TerminalState::Requested(pty_req.into_owned())));
            }
            ChannelRequestType::Env(new) => {
                const ALLOW_ENV: &[&str] = &["TZ", "LANG"];
                match ALLOW_ENV.contains(&new.name) || new.name.starts_with("LC_") {
                    true if env.len() < 32 => env.push((new.name.to_owned(), new.value.to_owned())),
                    _ => {
                        debug!(name = new.name, "ignoring environment variable request");
                        if request.want_reply {
                            encoder.enqueue(&failure)?;
                        }
                        return Ok(());
                    }
                }
            }
            ChannelRequestType::Shell => {
                let Some(TerminalState::Requested(pty_req)) = terminal.take().map(|state| *state)
                else {
                    return Err(
                        ProtoError::InvalidPacket("shell request without prior pty-req").into(),
                    );
                };

                *terminal = Some(Box::new(TerminalState::Running(Terminal::spawn(
                    &pty_req, env,
                )?)));
            }
            ChannelRequestType::WindowChange(window_change) => match terminal.as_deref() {
                Some(TerminalState::Running(terminal)) => terminal.resize(&window_change)?,
                _ => warn!("window-change request without running terminal"),
            },
            ChannelRequestType::AuthAgentReq => {
                if agent.is_none() {
                    match AgentListener::bind() {
                        Ok(listener) => {
                            env.push((
                                "SSH_AUTH_SOCK".to_owned(),
                                listener.path().to_string_lossy().into_owned(),
                            ));
                            *agent = Some(listener);
                        }
                        Err(error) => {
                            warn!(%error, "failed to set up agent forwarding");
                            if request.want_reply {
                                encoder.enqueue(&failure)?;
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }

        if request.want_reply {
            encoder.enqueue(&channel.success())?;
        }

        Ok(())
    }

    /// Open a new agent channel towards the client for an accepted agent connection
    pub(crate) fn agent_connection(
        &mut self,
        stream: UnixStream,
        encoder: &mut Encoder<'_>,
    ) -> Result<(), Error> {
        let local_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let entry = match self.channels.entry(local_id) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(_) => {
                warn!("dropping agent connection: channel ID already in use");
                return Ok(());
            }
        };

        // The remote ID, window size and maximum packet size come from the
        // client's confirmation of our channel open message.
        entry.insert(Channel {
            remote_id: 0,
            window_size: 0,
            maximum_packet_size: 0,
            kind: ChannelKind::Agent(AgentState::Pending(stream)),
            closed: ClosedState::default(),
        });

        encoder.enqueue(&ChannelOpen {
            r#type: ChannelType::AuthAgent,
            sender_channel: local_id,
            initial_window_size: AGENT_WINDOW_SIZE,
            maximum_packet_size: AGENT_MAXIMUM_PACKET_SIZE,
        })?;

        Ok(())
    }

    pub(crate) fn confirmation(
        &mut self,
        confirmation: &ChannelOpenConfirmation,
    ) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&confirmation.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel open confirmation for unknown channel ID",
            ));
        };

        let ChannelKind::Agent(state @ AgentState::Pending(_)) = &mut channel.kind else {
            return Err(ProtoError::InvalidPacket(
                "channel open confirmation for unexpected channel",
            ));
        };

        let AgentState::Pending(stream) = mem::replace(state, AgentState::Closing) else {
            return Err(ProtoError::Unreachable(
                "agent channel state must be pending",
            ));
        };

        channel.remote_id = confirmation.sender_channel;
        channel.window_size = confirmation.initial_window_size;
        channel.maximum_packet_size = confirmation.maximum_packet_size;
        channel.kind = ChannelKind::Agent(AgentState::Open(stream));
        debug!(channel_id = %confirmation.recipient_channel, "agent channel confirmed by client");
        Ok(())
    }

    pub(crate) fn open_failure(
        &mut self,
        failure: &ChannelOpenFailure<'_>,
    ) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get(&failure.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel open failure for unknown channel ID",
            ));
        };

        if !matches!(channel.kind, ChannelKind::Agent(AgentState::Pending(_))) {
            return Err(ProtoError::InvalidPacket(
                "channel open failure for unexpected channel",
            ));
        }

        // Dropping the channel closes the agent connection
        warn!(
            reason = ?failure.reason_code,
            description = failure.description,
            "client rejected agent channel"
        );
        self.channels.remove(&failure.recipient_channel);
        Ok(())
    }

    pub(crate) fn data<'m, 's>(
        &'s mut self,
        data: &'m ChannelData<'m>,
    ) -> Result<Option<(DataTarget<'s>, &'m [u8])>, ProtoError> {
        let Some(channel) = self.channels.get_mut(&data.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel data for unknown channel ID",
            ));
        };

        debug!(len = %data.data.len(), "received channel data");
        Ok(match &mut channel.kind {
            ChannelKind::Session { terminal, .. } => match terminal.as_deref_mut() {
                Some(TerminalState::Running(terminal)) => {
                    Some((DataTarget::Terminal(terminal), &data.data))
                }
                _ => None,
            },
            ChannelKind::Agent(AgentState::Open(stream)) => {
                Some((DataTarget::Agent(stream), &data.data))
            }
            ChannelKind::Agent(_) => None,
        })
    }

    pub(crate) fn window_adjust(&mut self, adjust: &ChannelWindowAdjust) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&adjust.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel window adjust for unknown channel ID",
            ));
        };

        channel.window_size = channel.window_size.saturating_add(adjust.bytes_to_add);
        Ok(())
    }

    /// Handle an end-of-file message from the client
    ///
    /// For agent channels, yields the connection so the caller can shut down its write side.
    pub(crate) fn eof(&mut self, eof: &ChannelEof) -> Result<Option<&mut UnixStream>, ProtoError> {
        let Some(channel) = self.channels.get_mut(&eof.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel eof for unknown channel ID",
            ));
        };

        debug!(channel_id = %eof.recipient_channel, "received channel eof from client");
        Ok(match &mut channel.kind {
            ChannelKind::Agent(AgentState::Open(stream)) => Some(stream),
            _ => None,
        })
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
        // Agent channels have nothing left to flush once the client has closed, so
        // dropping the channel (and with it, the agent connection) is safe here.
        if sent || matches!(channel.kind, ChannelKind::Agent(_)) {
            debug!(channel = %close.recipient_channel, "channel closed; removing");
            self.channels.remove(&close.recipient_channel);
        }

        if !sent {
            encoder.enqueue(&ChannelClose { recipient_channel })?;
        }

        Ok(())
    }

    pub(crate) fn channels_mut(&mut self) -> &mut BTreeMap<u32, Channel> {
        &mut self.channels
    }
}

pub(crate) struct ChannelsFuture<'a> {
    channels: &'a mut BTreeMap<u32, Channel>,
}

impl<'a> ChannelsFuture<'a> {
    pub(crate) fn new(channels: &'a mut BTreeMap<u32, Channel>) -> Self {
        Self { channels }
    }
}

impl<'a> Future for ChannelsFuture<'a> {
    type Output = Result<Option<ChannelEvent>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        for (&local_id, channel) in self.channels.iter_mut() {
            match &mut channel.kind {
                ChannelKind::Session {
                    terminal, agent, ..
                } => {
                    if let Some(listener) = agent {
                        match listener.poll_accept(cx) {
                            Poll::Ready(Ok(stream)) => {
                                return Poll::Ready(Ok(Some(ChannelEvent::AgentConnection(
                                    stream,
                                ))));
                            }
                            Poll::Ready(Err(error)) => {
                                warn!(%error, "failed to accept agent connection");
                                *agent = None;
                            }
                            Poll::Pending => {}
                        }
                    }

                    let Some(state) = terminal.as_deref_mut() else {
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

                            return Poll::Ready(Ok(Some(ChannelEvent::Outgoing(
                                OutgoingChannelMessage::Close(ChannelClose { recipient_channel }),
                            ))));
                        }
                    };

                    let mut buf = [0u8; 4096];
                    match terminal.poll_read(&mut buf, cx) {
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
                                Ok(_) => Ok(Some(ChannelEvent::Outgoing(
                                    OutgoingChannelMessage::Eof(ChannelEof {
                                        recipient_channel: channel.remote_id,
                                    }),
                                ))),
                                Err(error) => {
                                    warn!(%error, "error reading from terminal");
                                    Err(error.into())
                                }
                            });
                        }
                        Poll::Ready(Ok(n)) => {
                            return Poll::Ready(Ok(Some(ChannelEvent::Outgoing(
                                OutgoingChannelMessage::Data(ChannelData {
                                    recipient_channel: channel.remote_id,
                                    data: Cow::Owned(buf[..n].to_vec()),
                                }),
                            ))));
                        }
                        Poll::Pending => continue,
                    }
                }
                ChannelKind::Agent(state) => match state {
                    AgentState::Pending(_) => continue,
                    AgentState::Open(stream) => {
                        let mut buf = [0u8; 4096];
                        let mut read_buf = ReadBuf::new(&mut buf);
                        match Pin::new(stream).poll_read(cx, &mut read_buf) {
                            Poll::Pending => continue,
                            Poll::Ready(result) => {
                                if let Err(error) = result {
                                    warn!(%error, "error reading from agent connection");
                                }

                                let recipient_channel = channel.remote_id;
                                let filled = read_buf.filled();
                                if filled.is_empty() {
                                    // EOF (or error): close the connection and signal the client
                                    *state = AgentState::Closing;
                                    return Poll::Ready(Ok(Some(ChannelEvent::Outgoing(
                                        OutgoingChannelMessage::Eof(ChannelEof {
                                            recipient_channel,
                                        }),
                                    ))));
                                }

                                return Poll::Ready(Ok(Some(ChannelEvent::Outgoing(
                                    OutgoingChannelMessage::Data(ChannelData {
                                        recipient_channel,
                                        data: Cow::Owned(filled.to_vec()),
                                    }),
                                ))));
                            }
                        }
                    }
                    AgentState::Closing => {
                        if channel.closed.sent {
                            continue;
                        }

                        channel.closed.sent = true;
                        let recipient_channel = channel.remote_id;
                        if channel.closed.received {
                            debug!(channel = local_id, "both sides closed channel; removing");
                            self.channels.remove(&local_id);
                        }

                        return Poll::Ready(Ok(Some(ChannelEvent::Outgoing(
                            OutgoingChannelMessage::Close(ChannelClose { recipient_channel }),
                        ))));
                    }
                },
            }
        }

        Poll::Pending
    }
}

/// An event yielded by [`ChannelsFuture`]
#[derive(Debug)]
pub(crate) enum ChannelEvent {
    /// A message to send to the client
    Outgoing(OutgoingChannelMessage<'static>),
    /// A new connection accepted on an agent forwarding socket
    AgentConnection(UnixStream),
}

/// The target for incoming channel data
pub(crate) enum DataTarget<'a> {
    Terminal(&'a mut Terminal),
    Agent(&'a mut UnixStream),
}

#[derive(Debug)]
pub(crate) struct Channel {
    remote_id: u32,
    window_size: u32,
    maximum_packet_size: u32,
    kind: ChannelKind,
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

    fn failure(&self) -> ChannelRequestFailure {
        ChannelRequestFailure {
            recipient_channel: self.remote_id,
        }
    }
}

enum ChannelKind {
    /// A session channel opened by the client
    Session {
        env: Vec<(String, String)>,
        terminal: Option<Box<TerminalState>>,
        agent: Option<AgentListener>,
    },
    /// An agent forwarding channel opened by the server
    Agent(AgentState),
}

impl fmt::Debug for ChannelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session {
                env,
                terminal,
                agent,
            } => f
                .debug_struct("Session")
                .field("env", env)
                .field("terminal", terminal)
                .field("agent", &agent.is_some())
                .finish(),
            Self::Agent(state) => f.debug_tuple("Agent").field(state).finish(),
        }
    }
}

enum AgentState {
    /// The channel open message was sent, awaiting the client's response
    Pending(UnixStream),
    /// The client confirmed the channel; data is proxied to the connection
    Open(UnixStream),
    /// The connection was closed; waiting to send our channel close message
    Closing,
}

impl fmt::Debug for AgentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending(_) => f.debug_tuple("Pending").finish(),
            Self::Open(_) => f.debug_tuple("Open").finish(),
            Self::Closing => f.debug_tuple("Closing").finish(),
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
    OpenConfirmation(ChannelOpenConfirmation),
    OpenFailure(ChannelOpenFailure<'a>),
    Request(ChannelRequest<'a>),
    WindowAdjust(ChannelWindowAdjust),
    Data(ChannelData<'a>),
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
            MessageType::ChannelOpenConfirmation => Ok(IncomingChannelMessage::OpenConfirmation(
                ChannelOpenConfirmation::try_from(packet)?,
            )),
            MessageType::ChannelOpenFailure => Ok(IncomingChannelMessage::OpenFailure(
                ChannelOpenFailure::try_from(packet)?,
            )),
            MessageType::ChannelRequest => Ok(IncomingChannelMessage::Request(
                ChannelRequest::try_from(packet)?,
            )),
            MessageType::ChannelWindowAdjust => Ok(IncomingChannelMessage::WindowAdjust(
                ChannelWindowAdjust::try_from(packet)?,
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
                Err(ProtoError::InvalidPacket("unexpected channel message type"))
            }
        }
    }
}
