use core::pin::Pin;
use std::collections::HashMap;

use futures::FutureExt;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    select,
};

use crate::{
    buffered_stream::{buffered_stream, BufferedStream},
    proto::{Decode, Decoded, Encode, OwnedPacket, Packet},
    service::Service,
    Error,
};

const BUFFER_SIZE: u32 = 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ConnectionMessageType {
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

impl Encode for ConnectionMessageType {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::GlobalRequest => buf.push(80),
            Self::RequestSuccess => buf.push(81),
            Self::RequestFailure => buf.push(82),
            Self::ChannelOpen => buf.push(90),
            Self::ChannelOpenConfirmation => buf.push(91),
            Self::ChannelOpenFailure => buf.push(92),
            Self::ChannelWindowAdjust => buf.push(93),
            Self::ChannelData => buf.push(94),
            Self::ChannelExtendedData => buf.push(95),
            Self::ChannelEof => buf.push(96),
            Self::ChannelClose => buf.push(97),
            Self::ChannelRequest => buf.push(98),
            Self::ChannelSuccess => buf.push(99),
            Self::ChannelFailure => buf.push(100),
            Self::Unknown(value) => buf.push(*value),
        }
    }
}

impl<'a> Decode<'a> for ConnectionMessageType {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value, next } = u8::decode(bytes)?;
        Ok(Decoded {
            value: Self::from(value),
            next,
        })
    }
}

impl From<u8> for ConnectionMessageType {
    fn from(value: u8) -> Self {
        match value {
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

struct ChannelOpenFailure(u32);

impl Encode for ChannelOpenFailure {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelOpenFailure.encode(buf);
        self.0.encode(buf);
        2u32.encode(buf);
        b"".encode(buf);
        b"".encode(buf);
    }
}

struct ChannelOpenConfirmation {
    remote_id: u32,
    our_id: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
}

impl Encode for ChannelOpenConfirmation {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelOpenConfirmation.encode(buf);
        self.remote_id.encode(buf);
        self.our_id.encode(buf);
        self.initial_window_size.encode(buf);
        self.maximum_packet_size.encode(buf);
    }
}

struct ChannelWindowAdjust {
    remote_id: u32,
    additional_bytes: u32,
}

impl Encode for ChannelWindowAdjust {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelWindowAdjust.encode(buf);
        self.remote_id.encode(buf);
        self.additional_bytes.encode(buf);
    }
}

struct ChannelData {
    remote_id: u32,
    data: Vec<u8>,
}

impl Encode for ChannelData {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelData.encode(buf);
        self.remote_id.encode(buf);
        self.data.encode(buf);
    }
}

struct ChannelExtendedDataStderr {
    remote_id: u32,
    data: Vec<u8>,
}

impl Encode for ChannelExtendedDataStderr {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelExtendedData.encode(buf);
        self.remote_id.encode(buf);
        1u32.encode(buf);
        self.data.encode(buf);
    }
}

struct ChannelClose {
    remote_id: u32,
}

impl Encode for ChannelClose {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelClose.encode(buf);
        self.remote_id.encode(buf);
    }
}

struct ChannelRequestExitStatus {
    remote_id: u32,
    exit_status: u32,
}

impl Encode for ChannelRequestExitStatus {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelRequest.encode(buf);
        self.remote_id.encode(buf);
        b"exit-status".encode(buf);
        false.encode(buf);
        self.exit_status.encode(buf);
    }
}

struct ChannelSuccess(u32);

impl Encode for ChannelSuccess {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelSuccess.encode(buf);
        self.0.encode(buf);
    }
}

struct ChannelFailure(u32);

impl Encode for ChannelFailure {
    fn encode(&self, buf: &mut Vec<u8>) {
        ConnectionMessageType::ChannelFailure.encode(buf);
        self.0.encode(buf);
    }
}

pub struct ChannelStreams {
    pub exit_status: tokio::sync::oneshot::Sender<u32>,
    pub stdin: tokio::io::ReadHalf<BufferedStream<{ BUFFER_SIZE as usize }>>,
    pub stdout: tokio::io::WriteHalf<BufferedStream<{ BUFFER_SIZE as usize }>>,
    pub stderr: tokio::io::WriteHalf<BufferedStream<{ BUFFER_SIZE as usize }>>,
}

enum ChannelInternalState {
    Open {
        exit_status: tokio::sync::oneshot::Receiver<u32>,
        stdin: tokio::io::WriteHalf<BufferedStream<{ BUFFER_SIZE as usize }>>,
        stdout: tokio::io::ReadHalf<BufferedStream<{ BUFFER_SIZE as usize }>>,
        stderr: tokio::io::ReadHalf<BufferedStream<{ BUFFER_SIZE as usize }>>,
    },
    ServerClosed,
}

struct ChannelInternalData {
    remote_id: u32,
    state: ChannelInternalState,
    pending_in: Option<u32>,
    allowed_out: u32,
    max_packet_size: u32,
}

struct AbortingJoinHandle<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortingJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct ConnectionService {
    packet_stream: tokio::sync::mpsc::UnboundedSender<OwnedPacket>,
    #[allow(unused)]
    handling_task: AbortingJoinHandle<()>,
}

impl Service for ConnectionService {
    fn packet_types(&self) -> std::borrow::Cow<'static, [u8]> {
        (&[90, 93, 94, 97]).into()
    }

    fn handle_packet(&mut self, packet: Packet<'_>) {
        let _ = self.packet_stream.send(packet.to_owned());
    }
}

impl ConnectionService {
    pub fn new<F: 'static + Send + FnMut(&[u8], &[u8], ChannelStreams) -> bool>(
        mut channel_handler: F,
        packet_sender: tokio::sync::mpsc::UnboundedSender<Box<dyn Encode + Send + 'static>>,
    ) -> Self {
        let (packet_stream, mut packet_receiver) = tokio::sync::mpsc::unbounded_channel();
        let handling_task = AbortingJoinHandle(tokio::task::spawn(async move {
            let mut channels: HashMap<u32, ChannelInternalData> = HashMap::new();
            let mut next_channel_id = 0u32;

            enum SelectResult {
                Packet(Option<OwnedPacket>),
            }

            loop {
                let channel_future = core::future::poll_fn(|context| {
                    let mut buf = [0u8; BUFFER_SIZE as usize];
                    let mut read_buf = ReadBuf::new(&mut buf);
                    for (_, channel) in channels.iter_mut() {
                        let (exit_status, mut stdin, mut stdout, mut stderr) =
                            match &mut channel.state {
                                ChannelInternalState::Open {
                                    exit_status,
                                    stdin,
                                    stdout,
                                    stderr,
                                } => (exit_status, stdin, stdout, stderr),
                                ChannelInternalState::ServerClosed => continue,
                            };

                        if let core::task::Poll::Ready(exit_status) =
                            exit_status.poll_unpin(context)
                        {
                            if let Ok(exit_status) = exit_status {
                                let _ = packet_sender.send(Box::new(ChannelRequestExitStatus {
                                    remote_id: channel.remote_id,
                                    exit_status,
                                }));
                            }
                            let _ = packet_sender.send(Box::new(ChannelClose {
                                remote_id: channel.remote_id,
                            }));
                            channel.state = ChannelInternalState::ServerClosed;
                            continue;
                        }

                        if let Some(pending_in) = channel.pending_in {
                            if matches!(
                                Pin::new(&mut stdin).poll_flush(context),
                                core::task::Poll::Ready(_)
                            ) {
                                let _ = packet_sender.send(Box::new(ChannelWindowAdjust {
                                    remote_id: channel.remote_id,
                                    additional_bytes: pending_in,
                                }));
                                channel.pending_in = None;
                            }
                        }

                        loop {
                            let acceptable_out = BUFFER_SIZE
                                .min(channel.allowed_out)
                                .min(channel.max_packet_size);
                            read_buf.clear();
                            if acceptable_out > 0
                                && matches!(
                                    Pin::new(&mut stderr).poll_read(context, &mut read_buf),
                                    core::task::Poll::Ready(_)
                                )
                            {
                                let data = read_buf.filled();
                                channel.allowed_out = channel
                                    .allowed_out
                                    .saturating_sub(data.len().try_into().unwrap());
                                let _ = packet_sender.send(Box::new(ChannelExtendedDataStderr {
                                    remote_id: channel.remote_id,
                                    data: data.into(),
                                }));
                                continue;
                            }
                            break;
                        }

                        loop {
                            let acceptable_out = BUFFER_SIZE
                                .min(channel.allowed_out)
                                .min(channel.max_packet_size);
                            read_buf.clear();
                            if acceptable_out > 0
                                && matches!(
                                    Pin::new(&mut stdout).poll_read(context, &mut read_buf),
                                    core::task::Poll::Ready(_)
                                )
                            {
                                let data = read_buf.filled();
                                channel.allowed_out = channel
                                    .allowed_out
                                    .saturating_sub(data.len().try_into().unwrap());
                                let _ = packet_sender.send(Box::new(ChannelData {
                                    remote_id: channel.remote_id,
                                    data: data.into(),
                                }));
                                continue;
                            }
                            break;
                        }
                    }
                    core::task::Poll::Pending::<()>
                });

                let select_result = select! {
                    r = packet_receiver.recv() => SelectResult::Packet(r),
                    _ = channel_future => unreachable!(),
                };

                match select_result {
                    SelectResult::Packet(Some(packet)) => {
                        let Ok(Decoded {
                            value: packet_type,
                            next,
                        }) = ConnectionMessageType::decode(&packet.payload)
                        else {
                            continue;
                        };

                        match packet_type {
                            ConnectionMessageType::ChannelOpen => {
                                let Ok(Decoded {
                                    value: channel_type,
                                    next,
                                }) = <&[u8]>::decode(next)
                                else {
                                    continue;
                                };
                                let Ok(Decoded {
                                    value: remote_id,
                                    next,
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };
                                let Ok(Decoded {
                                    value: initial_window_size,
                                    next,
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };
                                let Ok(Decoded {
                                    value: max_packet_size,
                                    next: type_specific_data,
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };

                                let (exit_status_sender, exit_status) =
                                    tokio::sync::oneshot::channel();
                                let (stdin, stdin_sender) = buffered_stream();
                                let (stdout_receiver, stdout) = buffered_stream();
                                let (stderr_receiver, stderr) = buffered_stream();

                                if channel_handler(
                                    channel_type,
                                    type_specific_data,
                                    ChannelStreams {
                                        exit_status: exit_status_sender,
                                        stdin,
                                        stdout,
                                        stderr,
                                    },
                                ) {
                                    let channel_id = loop {
                                        let channel_id = next_channel_id;
                                        next_channel_id = next_channel_id.wrapping_add(1);
                                        if !channels.contains_key(&channel_id) {
                                            break channel_id;
                                        }
                                    };

                                    channels.insert(
                                        channel_id,
                                        ChannelInternalData {
                                            remote_id,
                                            pending_in: None,
                                            allowed_out: initial_window_size,
                                            max_packet_size,
                                            state: ChannelInternalState::Open {
                                                exit_status,
                                                stdin: stdin_sender,
                                                stdout: stdout_receiver,
                                                stderr: stderr_receiver,
                                            },
                                        },
                                    );

                                    let _ = packet_sender.send(Box::new(ChannelOpenConfirmation {
                                        remote_id,
                                        our_id: channel_id,
                                        initial_window_size: BUFFER_SIZE,
                                        maximum_packet_size: BUFFER_SIZE,
                                    }));
                                } else {
                                    let _ =
                                        packet_sender.send(Box::new(ChannelOpenFailure(remote_id)));
                                }
                            }
                            ConnectionMessageType::ChannelWindowAdjust => {
                                let Ok(Decoded {
                                    value: channel_id,
                                    next,
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };
                                let Ok(Decoded {
                                    value: bytes_to_add,
                                    ..
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };

                                if let Some(channel) = channels.get_mut(&channel_id) {
                                    channel.allowed_out =
                                        channel.allowed_out.saturating_add(bytes_to_add);
                                }
                            }
                            ConnectionMessageType::ChannelData => {
                                let Ok(Decoded {
                                    value: channel_id,
                                    next,
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };
                                let Ok(Decoded { value: data, .. }) = <&[u8]>::decode(next) else {
                                    continue;
                                };

                                if let Some(channel) = channels.get_mut(&channel_id) {
                                    match &mut channel.state {
                                        ChannelInternalState::Open { stdin, .. } => {
                                            let _ = stdin.write_all(data).await;
                                            if let Some(pending_in) = &mut channel.pending_in {
                                                *pending_in =
                                                    BUFFER_SIZE.min(pending_in.saturating_add(
                                                        data.len().try_into().unwrap(),
                                                    ))
                                            } else {
                                                channel.pending_in = Some(
                                                    BUFFER_SIZE.min(data.len().try_into().unwrap()),
                                                );
                                            }
                                        }
                                        ChannelInternalState::ServerClosed => {}
                                    }
                                }
                            }
                            ConnectionMessageType::ChannelRequest => {
                                let Ok(Decoded {
                                    value: channel_id,
                                    next,
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };
                                let Ok(Decoded {
                                    value: request_type,
                                    next,
                                }) = <&[u8]>::decode(next)
                                else {
                                    continue;
                                };
                                let Ok(Decoded {
                                    value: want_reply, ..
                                }) = bool::decode(next)
                                else {
                                    continue;
                                };

                                if let Some(channel) = channels.get(&channel_id) {
                                    match request_type {
                                        b"pty-req" | b"shell" if want_reply => {
                                            let _ = packet_sender
                                                .send(Box::new(ChannelSuccess(channel.remote_id)));
                                        }
                                        _ if want_reply => {
                                            let _ = packet_sender
                                                .send(Box::new(ChannelFailure(channel.remote_id)));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            ConnectionMessageType::ChannelClose => {
                                let Ok(Decoded {
                                    value: channel_id,
                                    next: _,
                                }) = u32::decode(next)
                                else {
                                    continue;
                                };

                                if let Some(channel) = channels.remove(&channel_id) {
                                    match channel.state {
                                        ChannelInternalState::Open { .. } => {
                                            let _ = packet_sender.send(Box::new(ChannelClose {
                                                remote_id: channel.remote_id,
                                            }));
                                        }
                                        ChannelInternalState::ServerClosed => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    SelectResult::Packet(None) => return,
                }
            }
        }));

        Self {
            packet_stream,
            handling_task,
        }
    }
}
