use core::{cmp::Ordering, mem::MaybeUninit};
use std::io::{self, IoSliceMut};

use proto::{
    Decoded, ReadState, SessionHostKey, WriteState, crypto::CryptoProvider, key_exchange::Rekey,
};
use rustix::{
    io::FdFlags,
    net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags},
};
use tokio::net::TcpStream;
use tracing::debug;
use zeroize::Zeroizing;

use crate::{Connection, Error, Session, SessionState, session::Channels};

mod terminal;
pub(crate) use terminal::Terminal;

/// Resume an SSH session from the session state received over the Unix socket `source`
pub fn resume(provider: &'static dyn CryptoProvider) -> Result<Session<TcpStream>, Error> {
    let source = rustix::stdio::stdin();
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
                            return Err(Error::InvalidState("received more bytes than expected"));
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

    // Mark the connection close-on-exec so the session does not inherit a copy of the socket.
    rustix::io::fcntl_setfd(&fd, FdFlags::CLOEXEC).map_err(io::Error::from)?;

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
        post_quantum_kx,
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

    Ok(Session {
        provider,
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
        post_quantum_kx,
    })
}
