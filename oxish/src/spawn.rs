use core::{
    cmp::Ordering,
    fmt,
    mem::MaybeUninit,
    net::SocketAddr,
    str::{self, FromStr},
};
use std::{
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    process::Stdio,
};

use proto::{
    Decode, Decoded, Encode, EncryptionAlgorithm, KeySourceSet, ProtoError, ReadState, WriteState,
    crypto::{CryptoProvider, KeyLengths, KeySourceSide},
};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};

use crate::{Connection, Error};

/// The state needed to resume an authenticated connection in a session process
pub struct SessionState {
    addr: SocketAddr,
    read: SideState,
    write: SideState,
    /// Residual inbound bytes already drained from the socket (pipelined packets)
    read_buf: Vec<u8>,
}

impl SessionState {
    /// Receive a [`SessionState`] and the connection's file descriptor from `source`
    pub fn from_fd(source: &impl AsFd) -> Result<(Self, OwnedFd), Error> {
        let mut length = None;
        let mut received = Vec::new();
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

        let Decoded { value: state, next } = Self::decode(&received)?;
        if !next.is_empty() {
            return Err(Error::InvalidState("trailing bytes after message"));
        }

        // Acknowledge the handoff so the parent releases its copy of the descriptor
        rustix::net::send(source, &[1], SendFlags::empty()).map_err(io::Error::from)?;

        Ok((state, fd))
    }

    /// Construct a [`SessionState`] from a [`Connection`] and its [`KeySourceSet`]
    ///
    /// Fails if no keys were installed or the write buffer still holds unflushed bytes.
    pub fn from_connection<T>(conn: Connection<T>, keys: KeySourceSet) -> Result<(Self, T), Error> {
        let Connection {
            stream,
            addr,
            mut read,
            write,
        } = conn;

        if !write.buffered().is_empty() {
            return Err(Error::InvalidState("unflushed bytes in write buffer"));
        }

        // Compact the bytes of the last decoded packet, which are still at the front of
        // the buffer (they are usually dropped at the start of the next `poll_packet()`).
        if read.last_length > 0 {
            read.buf.copy_within(read.last_length.., 0);
            read.buf.truncate(read.buf.len() - read.last_length);
            read.last_length = 0;
        }

        Ok((
            Self {
                addr,
                read: SideState {
                    source: keys.client_to_server,
                    counter: read.opener.as_ref().map_or(0, |opener| opener.counter()),
                    sequence_number: read.sequence_number,
                },
                write: SideState {
                    source: keys.server_to_client,
                    counter: write.sealer.as_ref().map_or(0, |sealer| sealer.counter()),
                    sequence_number: write.sequence_number,
                },
                read_buf: read.buf,
            },
            stream,
        ))
    }

    /// Spawn a child process for the authenticated session
    ///
    /// Decomposes `conn` into a [`SessionState`] and the TCP stream, spawns `session_bin` with one end of a Unix socket pair as its stdin, and sends the serialized state plus the TCP
    /// socket's file descriptor (via `SCM_RIGHTS`) over the other end. The child reconstructs
    /// the connection with [`SessionState::from_fd()`] and [`SessionState::into_connection()`].
    pub async fn spawn(self, stream: TcpStream, binary: &Path) -> Result<Child, Error> {
        let tcp = stream.into_std()?;

        let (parent, child_sock) = UnixStream::pair()?;
        let child = Command::new(binary)
            .stdin(Stdio::from(OwnedFd::from(child_sock)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        // The `[u8]` encoding yields the `u32` length prefix followed by the state itself.
        let mut message = vec![0; 4];
        self.encode(&mut message);
        let payload_len = (message.len() - 4) as u32;
        message[..4].copy_from_slice(&payload_len.to_be_bytes());

        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let fds = [tcp.as_fd()];
        control.push(SendAncillaryMessage::ScmRights(&fds));

        // The file descriptor rides along with the first message; if the socket buffer cannot
        // hold the full message, send the rest without ancillary data.
        let mut sent = rustix::net::sendmsg(
            &parent,
            &[IoSlice::new(&message)],
            &mut control,
            SendFlags::empty(),
        )
        .map_err(io::Error::from)?;

        while sent < message.len() {
            sent += rustix::net::send(&parent, &message[sent..], SendFlags::empty())
                .map_err(io::Error::from)?;
        }

        // Keep the connection's file descriptor open until the child acknowledges the
        // handoff; observed on macOS: closing the parent's copy while the descriptor is
        // still in flight tears down the connection.
        let mut ack = [0];
        let mut iov = [IoSliceMut::new(&mut ack)];
        let mut control = RecvAncillaryBuffer::default();
        let received = rustix::net::recvmsg(&parent, &mut iov, &mut control, RecvFlags::empty())
            .map_err(io::Error::from)?;
        match received.bytes {
            0 => Err(Error::InvalidState(
                "session process exited before acknowledging handoff",
            )),
            _ => Ok(child),
        }
    }

    /// Rebuild an authenticated connection from a decoded [`SessionState`]
    pub fn into_connection<T>(
        self,
        stream: T,
        provider: &dyn CryptoProvider,
    ) -> Result<Connection<T>, Error> {
        let Self {
            addr: peer_addr,
            read,
            write,
            read_buf,
        } = self;

        let opener = provider.opening_key(read.counter, &read.source)?;
        let sealer = provider.sealing_key(write.counter, &write.source)?;

        let mut write_state = WriteState::new(provider.secure_random());
        write_state.sequence_number = write.sequence_number;
        write_state.sealer = Some(sealer);

        Ok(Connection {
            stream,
            addr: peer_addr,
            read: ReadState {
                buf: read_buf,
                last_length: 0,
                sequence_number: read.sequence_number,
                opener: Some(opener),
            },
            write: write_state,
        })
    }
}

impl Encode for SessionState {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.addr.to_string().as_bytes().encode(buf);
        self.read.encode(buf);
        self.write.encode(buf);
        self.read_buf.encode(buf);
    }
}

impl Decode<'_> for SessionState {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value: addr, next } = <&[u8]>::decode(bytes)?;
        let Ok(addr) = str::from_utf8(addr) else {
            return Err(ProtoError::InvalidPacket("invalid UTF-8 in peer address"));
        };

        let Ok(addr) = SocketAddr::from_str(addr) else {
            return Err(ProtoError::InvalidPacket("invalid peer address"));
        };

        let Decoded { value: read, next } = SideState::decode(next)?;
        let Decoded { value: write, next } = SideState::decode(next)?;
        let Decoded {
            value: read_buf,
            next,
        } = <&[u8]>::decode(next)?;

        Ok(Decoded {
            value: Self {
                addr,
                read,
                write,
                read_buf: read_buf.to_vec(),
            },
            next,
        })
    }
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("addr", &self.addr)
            .field("read", &self.read)
            .field("write", &self.write)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct SideState {
    source: KeySourceSide,
    counter: u64,
    sequence_number: u32,
}

impl Encode for SideState {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.source.algorithm.encode(buf);
        self.source.encryption_key.encode(buf);
        self.source.initial_iv.encode(buf);
        self.counter.encode(buf);
        self.sequence_number.encode(buf);
    }
}

impl Decode<'_> for SideState {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded {
            value: algorithm,
            next,
        } = EncryptionAlgorithm::decode(bytes)?;

        let Some(KeyLengths { key_len, iv_len }) = algorithm.lengths() else {
            return Err(ProtoError::InvalidPacket(
                "unsupported encryption algorithm",
            ));
        };

        let Decoded {
            value: encryption_key,
            next,
        } = <&[u8]>::decode(next)?;
        if encryption_key.len() != key_len {
            return Err(ProtoError::InvalidPacket("invalid encryption key length"));
        }

        let Decoded {
            value: initial_iv,
            next,
        } = <&[u8]>::decode(next)?;
        if initial_iv.len() != iv_len {
            return Err(ProtoError::InvalidPacket("invalid IV length"));
        }

        let Decoded {
            value: counter,
            next,
        } = u64::decode(next)?;

        let Decoded {
            value: sequence_number,
            next,
        } = u32::decode(next)?;

        Ok(Decoded {
            value: Self {
                source: KeySourceSide {
                    algorithm: algorithm.to_owned(),
                    initial_iv: initial_iv.to_owned(),
                    encryption_key: encryption_key.to_owned(),
                },
                counter,
                sequence_number,
            },
            next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_state_round_trip() {
        let state = SessionState {
            addr: SocketAddr::from(([192, 0, 2, 7], 22022)),
            read: SideState {
                source: KeySourceSide {
                    algorithm: EncryptionAlgorithm::Aes128Gcm,
                    initial_iv: vec![2; 12],
                    encryption_key: vec![1; 16],
                },
                counter: 42,
                sequence_number: 17,
            },
            write: SideState {
                source: KeySourceSide {
                    algorithm: EncryptionAlgorithm::Aes128Gcm,
                    initial_iv: vec![4; 12],
                    encryption_key: vec![3; 16],
                },
                counter: 7,
                sequence_number: 23,
            },
            read_buf: b"pipelined".to_vec(),
        };

        let mut buf = Vec::new();
        state.encode(&mut buf);

        let Decoded {
            value: decoded,
            next,
        } = SessionState::decode(&buf).unwrap();
        assert!(next.is_empty());

        assert_eq!(decoded.addr, state.addr);
        assert_eq!(decoded.read_buf, state.read_buf);
        assert_eq!(
            decoded.read.source.algorithm,
            EncryptionAlgorithm::Aes128Gcm
        );
        assert_eq!(decoded.read.source.encryption_key, [1; 16]);
        assert_eq!(decoded.read.source.initial_iv, [2; 12]);
        assert_eq!(
            decoded.write.source.algorithm,
            EncryptionAlgorithm::Aes128Gcm
        );
        assert_eq!(decoded.write.source.encryption_key, [3; 16]);
        assert_eq!(decoded.write.source.initial_iv, [4; 12]);
        assert_eq!(decoded.read.counter, 42);
        assert_eq!(decoded.read.sequence_number, 17);
        assert_eq!(decoded.write.counter, 7);
        assert_eq!(decoded.write.sequence_number, 23);
    }
}
