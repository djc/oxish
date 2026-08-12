use core::future;
#[cfg(windows)]
use core::mem;
#[cfg(unix)]
use core::{cmp::Ordering, mem::MaybeUninit};
use std::io;
#[cfg(unix)]
use std::{io::IoSliceMut, os::fd::AsFd};
#[cfg(windows)]
use std::{
    io::{Read, Write},
    os::windows::io::{FromRawSocket, RawSocket},
};

use proto::{
    Decoded, Disconnect, Encoder, MessageType, Pretty, ReadState, WriteState,
    crypto::CryptoProvider,
    key_exchange::{Rekey, SessionHostKey},
};
#[cfg(unix)]
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tracing::{debug, info, instrument, trace, warn};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    FROM_PROTOCOL_INFO, INVALID_SOCKET, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED, WSADATA,
    WSAGetLastError, WSAPROTOCOL_INFOW, WSASocketW, WSAStartup,
};
use zeroize::Zeroizing;

use crate::{Connection, DEFAULT_PROVIDER, Error, SessionState, receive, send};

mod connections;
use connections::{Channels, IncomingChannelMessage, TerminalsFuture};
#[cfg_attr(unix, path = "terminal/unix.rs")]
#[cfg_attr(windows, path = "terminal/windows.rs")]
mod terminal;

/// A single SSH session's state
///
/// Call [`Session::run()`] to drive the session forward.
pub struct Session<T> {
    conn: Connection<T>,
    rekey: Rekey,
    channels: Channels,
}

impl Session<TcpStream> {
    /// Resume an SSH session from the session state received over the Unix socket `source`
    #[cfg(unix)]
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

        let session = Self::resume(&received, std::net::TcpStream::from(fd))?;

        // Acknowledge the handoff so the parent releases its copy of the descriptor
        rustix::net::send(source, &[1], SendFlags::empty()).map_err(io::Error::from)?;
        Ok(session)
    }

    /// Resume an SSH session from the session state received on standard input
    ///
    /// Reads the length-prefixed session state followed by the `WSAPROTOCOL_INFOW` describing
    /// the connection's socket (duplicated into this process by the server), then acknowledges
    /// the handoff on standard output.
    #[cfg(windows)]
    pub fn from_message() -> Result<Self, Error> {
        let mut stdin = io::stdin().lock();

        let mut length = [0; 4];
        stdin.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;

        let mut received = Zeroizing::new(vec![0; length]);
        stdin.read_exact(&mut received)?;

        const INFO_LEN: usize = size_of::<WSAPROTOCOL_INFOW>();
        let mut info = [0; INFO_LEN];
        stdin.read_exact(&mut info)?;
        // SAFETY: `WSAPROTOCOL_INFOW` is a plain-old-data struct for which any bit pattern
        // is valid, and the array has exactly the struct's size.
        let info = unsafe { mem::transmute::<[u8; INFO_LEN], WSAPROTOCOL_INFOW>(info) };

        // Winsock must be initialized before `WSASocketW()`; the standard library only
        // does so lazily on first use of `std::net`.
        // SAFETY: `data` is a plain-old-data struct, valid for writes.
        let mut data = unsafe { mem::zeroed::<WSADATA>() };
        // SAFETY: `data` is valid for writes.
        let ret = unsafe { WSAStartup(0x0202, &mut data) };
        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret).into());
        }

        // SAFETY: `info` describes a socket duplicated into this process by the server.
        let socket = unsafe {
            WSASocketW(
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                &info,
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if socket == INVALID_SOCKET {
            // SAFETY: `WSAGetLastError()` takes no arguments and has no preconditions.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }).into());
        }

        // SAFETY: `socket` was just created from the duplicated protocol info and this
        // process exclusively owns it.
        let stream = unsafe { std::net::TcpStream::from_raw_socket(socket as RawSocket) };
        let session = Self::resume(&received, stream)?;

        // Acknowledge the handoff so the parent releases its reference to the socket
        let mut stdout = io::stdout().lock();
        stdout.write_all(&[1])?;
        stdout.flush()?;
        Ok(session)
    }

    /// Reconstruct the session from the encoded state and the connection's socket
    fn resume(received: &[u8], stream: std::net::TcpStream) -> Result<Self, Error> {
        let provider = DEFAULT_PROVIDER;
        let Decoded { value: state, next } =
            SessionState::<SessionHostKey>::decode(received, provider)?;
        if !next.is_empty() {
            return Err(Error::InvalidState("trailing bytes after message"));
        }

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

    /// Run the session, driving the connection forward and handling channel messages
    ///
    /// This function never returns unless the connection is closed or an error occurs.
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
