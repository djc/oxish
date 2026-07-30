use core::{cmp::Ordering, future, mem::MaybeUninit};
use std::{
    io::{self, IoSliceMut},
    os::fd::AsFd,
};

use proto::{
    Decoded, Disconnect, Encoder, MessageType, Pretty, ReadState, WriteState,
    crypto::CryptoProvider,
    key_exchange::{Rekey, SessionHostKey},
};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tracing::{debug, info, instrument, trace, warn};
use zeroize::Zeroizing;

use crate::{Connection, DEFAULT_PROVIDER, Error, SessionState, receive, send};

mod connections;
use connections::{Channels, IncomingChannelMessage, TerminalsFuture};
mod terminal;

/// A single SSH connection
pub struct Session<T> {
    conn: Connection<T>,
    rekey: Rekey,
    channels: Channels,
}

impl Session<TcpStream> {
    pub fn from_message(source: &impl AsFd) -> Result<Self, Error> {
        let mut length = None;
        let mut received = Zeroizing::new(Vec::new());
        let mut tcp = None;
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut chunk = vec![0; 16_384];

        loop {
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let mut iov = [IoSliceMut::new(&mut chunk)];
            let message = rustix::net::recvmsg(source, &mut iov, &mut control, RecvFlags::empty())
                .map_err(io::Error::from)?;

            let Some((buffered, _)) = chunk.split_at_checked(message.bytes) else {
                return Err(Error::InvalidState("invalid message length received"));
            };

            if buffered.is_empty() {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF while receiving handoff message",
                )));
            }

            for ancillary in control.drain() {
                if let RecvAncillaryMessage::ScmRights(fds) = ancillary {
                    if tcp.is_none() {
                        tcp = fds.into_iter().next();
                    }
                }
            }

            match length {
                Some(len) => match (received.len() + buffered.len()).cmp(&len) {
                    Ordering::Greater => {
                        return Err(Error::InvalidState("received more bytes than expected"));
                    }
                    Ordering::Equal => {
                        received.extend_from_slice(&chunk[..message.bytes]);
                        break;
                    }
                    Ordering::Less => received.extend_from_slice(&chunk[..message.bytes]),
                },
                None => match buffered.split_first_chunk::<4>() {
                    Some((len, rest)) => {
                        let len = u32::from_be_bytes(*len) as usize;
                        length = Some(len);
                        received.extend_from_slice(rest);
                        match received.len().cmp(&len) {
                            Ordering::Greater => {
                                return Err(Error::InvalidState(
                                    "received more bytes than expected",
                                ));
                            }
                            Ordering::Equal => break,
                            Ordering::Less => continue,
                        }
                    }
                    None => {
                        return Err(Error::InvalidState(
                            "received fewer than 4 bytes for length prefix",
                        ));
                    }
                },
            }
        }

        let Some(fd) = tcp else {
            return Err(Error::InvalidState("no file descriptor received"));
        };

        let provider = DEFAULT_PROVIDER;
        let Decoded { value: state, next } =
            SessionState::<SessionHostKey>::decode(&received, provider)?;
        if !next.is_empty() {
            return Err(Error::InvalidState("trailing bytes after message"));
        }

        // Acknowledge the handoff so the parent releases its copy of the descriptor
        rustix::net::send(source, &[1], SendFlags::empty()).map_err(io::Error::from)?;
        debug!(?state, "received session state, reconstructing connection");

        let SessionState {
            addr,
            host_key,
            identities,
            strict_kx,
            session_id,
            read,
            write,
            read_buf,
        } = state;

        let opener = provider.opening_key(read.counter, &read.source)?;
        let sealer = provider.sealing_key(write.counter, &write.source)?;

        let mut write_state = WriteState::new(provider.secure_random());
        write_state.sequence_number = write.sequence_number;
        write_state.sealer = Some(sealer);

        let stream = std::net::TcpStream::from(fd);
        stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(stream)?;

        Ok(Self {
            conn: Connection {
                stream,
                addr,
                read: ReadState {
                    buf: read_buf,
                    last_length: 0,
                    sequence_number: read.sequence_number,
                    opener: Some(opener),
                },
                write: write_state,
            },
            rekey: Rekey::new(session_id, strict_kx, identities, host_key),
            channels: Channels::default(),
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Session<T> {
    pub(crate) fn new(conn: Connection<T>, rekey: Rekey) -> Self {
        Self {
            conn,
            channels: Channels::default(),
            rekey,
        }
    }

    /// Drive the connection forward
    #[instrument(name = "connection", skip(self, provider), fields(addr = %self.conn.addr))]
    pub async fn run(mut self, provider: &'static dyn CryptoProvider) -> Result<(), Error> {
        loop {
            tokio::select! {
                result = receive(&mut self.conn.stream, &mut self.conn.read) => {
                    let packet = result?;
                    match packet.message_type {
                        MessageType::Ignore | MessageType::Debug => {
                            trace!(?packet.message_type, "ignoring transport-layer message");
                            continue;
                        }
                        MessageType::Disconnect => {
                            match Disconnect::try_from(packet) {
                                Ok(disconnect) => info!(?disconnect, "received disconnect packet, closing connection"),
                                Err(error) => warn!(%error, "failed to read disconnect packet"),
                            }
                            return Ok(());
                        }
                        // The client can start a rekey at any point by sending a fresh
                        // key exchange init (RFC 4253 section 9).
                        MessageType::KeyExchangeInit => {
                            let kx = self.rekey.start(packet, provider)?;
                            self.conn.rekey(kx, &self.rekey, provider).await?;
                            continue;
                        }
                        _ => {}
                    }

                    let channel_message = IncomingChannelMessage::try_from(packet)?;
                    debug!(message = %Pretty(&channel_message), "handling channel message");
                    let mut encoder = Encoder::new(&mut self.conn.write);
                    match channel_message {
                        IncomingChannelMessage::Open(open) => self.channels.open(open, &mut encoder),
                        IncomingChannelMessage::Request(request) => self.channels.request(request, &mut encoder),
                        IncomingChannelMessage::Data(data) => match self.channels.data(&data, &mut encoder) {
                            Ok(Some((session, data))) => match session.write(data).await {
                                Ok(_) => Ok(()),
                                Err(error) => Err(error.into()),
                            },
                            Ok(None) => Ok(()),
                            Err(error) => Err(error.into()),
                        }
                        IncomingChannelMessage::WindowAdjust(adjust) => self.channels.adjust_window(&adjust).map_err(Into::into),
                        IncomingChannelMessage::Eof(eof) => self.channels.eof(&eof).map_err(Into::into),
                        IncomingChannelMessage::Close(close) => self.channels.close(&close, &mut encoder),
                    }?;

                    future::poll_fn(|cx| send(&mut self.conn.stream, encoder.write, cx))
                        .await?;
                }
                result = TerminalsFuture::new(self.channels.channels_mut()) => {
                    match result {
                        Ok(Some(outgoing)) => {
                            debug!(outgoing = %Pretty(&outgoing), "sending channel message from session");
                            self.conn.send(&outgoing).await?;
                        }
                        Ok(None) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
}
