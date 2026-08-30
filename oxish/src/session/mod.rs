use core::{
    cmp::Ordering,
    future,
    mem::MaybeUninit,
    str::{self, FromStr},
};
use std::{
    io::{self, IoSliceMut},
    os::fd::AsFd,
};

use proto::{
    Decoded, Disconnect, Encoder, GlobalRequest, MessageType, Pretty, ReadState, SessionHostKey,
    WriteState,
    channels::{ChannelRequest, ChannelRequestType},
    crypto::CryptoProvider,
    key_exchange::{EcdhKeyExchangeInit, KeyExchange, Rekey},
};
use rustix::{
    io::FdFlags,
    net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tracing::{debug, info, instrument, trace, warn};
use zeroize::Zeroizing;

use crate::{Connection, Error, KeyExchangeOutput, SessionState, receive, send};

mod connections;
use connections::{Channels, IncomingChannelMessage, TerminalsFuture};
mod terminal;

/// A single SSH session's state
///
/// Call [`Session::run()`] to drive the session forward.
pub struct Session<T> {
    provider: &'static dyn CryptoProvider,
    conn: Connection<T>,
    rekey: Rekey,
    channels: Channels,
    post_quantum_kx: bool,
}

impl Session<TcpStream> {
    /// Resume an SSH session from the session state received over the Unix socket `source`
    pub fn from_message(
        source: &impl AsFd,
        provider: &'static dyn CryptoProvider,
    ) -> Result<Self, Error> {
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

        Ok(Self {
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
}

impl<T: AsyncRead + AsyncWrite + Unpin> Session<T> {
    pub(crate) fn new(
        kx: KeyExchangeOutput<'_>,
        conn: Connection<T>,
        provider: &'static dyn CryptoProvider,
    ) -> Result<Self, Error> {
        Ok(Self {
            provider,
            conn,
            channels: Channels::default(),
            rekey: Rekey::new(
                kx.session_id,
                kx.strict_kx,
                kx.identities,
                SessionHostKey::from_server(kx.host_key, provider)?,
            ),
            post_quantum_kx: kx.post_quantum_kx,
        })
    }

    /// Run the session, driving the connection forward and handling channel messages
    ///
    /// This function never returns unless the connection is closed or an error occurs.
    #[instrument(name = "connection", skip(self), fields(addr = %self.conn.addr))]
    pub async fn run(mut self) -> Result<(), Error> {
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
                            let kx = self.rekey.start(packet, self.provider)?;
                            let post_quantum_kx = kx.negotiated.key_exchange.post_quantum_secure();
                            rekey(kx, &mut self.conn, &self.rekey, self.provider).await?;
                            self.post_quantum_kx = post_quantum_kx;
                            continue;
                        }
                        MessageType::GlobalRequest => {
                            let request = GlobalRequest::try_from(packet)?;
                            debug!(name = %String::from_utf8_lossy(request.name), "refusing unsupported global request");
                            if request.want_reply {
                                self.conn.send(&MessageType::RequestFailure).await?;
                            }
                            continue;
                        }
                        MessageType::RequestSuccess | MessageType::RequestFailure => {
                            trace!(?packet.message_type, "ignoring unexpected global request reply");
                            continue;
                        }
                        _ => {}
                    }

                    let channel_message = IncomingChannelMessage::try_from(packet)?;
                    debug!(message = %Pretty(&channel_message), "handling channel message");
                    let mut encoder = Encoder::new(&mut self.conn.write);
                    match channel_message {
                        IncomingChannelMessage::Open(open) => self.channels.open(open, &mut encoder),
                        IncomingChannelMessage::Request(request) => {
                            let banner = banner(&request, self.rekey.client_identity(), self.post_quantum_kx);
                            self.channels.request(request, &mut encoder, banner.as_deref())
                        }
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

/// Complete a client-initiated rekey after its `SSH_MSG_KEXINIT` has been parsed
async fn rekey(
    mut kx: KeyExchange,
    conn: &mut Connection<impl AsyncRead + AsyncWrite + Unpin>,
    rekey: &Rekey,
    provider: &dyn CryptoProvider,
) -> Result<(), Error> {
    debug!("starting client-initiated rekey");

    conn.send_handshake(&kx.local, Some(&mut kx.exchange))
        .await?;

    let packet = receive(&mut conn.stream, &mut conn.read).await?;
    let ecdh_key_exchange_init = EcdhKeyExchangeInit::try_from(packet)?;
    let (key_exchange_reply, keys) = rekey.complete(
        ecdh_key_exchange_init,
        &kx.negotiated,
        kx.exchange,
        provider,
    )?;

    conn.send(&key_exchange_reply).await?;
    conn.update_keys(&keys, rekey.strict_key_exchange(), provider)
        .await?;

    debug!("completed client-initiated rekey");
    Ok(())
}

fn banner(
    request: &ChannelRequest<'_>,
    client_identity: &[u8],
    post_quantum_kx: bool,
) -> Option<String> {
    if post_quantum_kx {
        return None;
    }

    let width = match &request.r#type {
        // A zero dimension means the client left it unspecified (RFC 4254 section 6.2)
        ChannelRequestType::PtyReq(pty) => match pty.cols {
            0 => 80,
            cols => Ord::max(40, cols as usize),
        },
        _ => return None,
    };

    let mut banner = String::with_capacity(PREFIX.len() + NO_PQ_WARNING.len());
    banner.push_str(PREFIX);
    let mut left = width.saturating_sub(PREFIX.len());
    for token in NO_PQ_WARNING.split(' ') {
        if token.len() + 1 >= left {
            banner.push_str("\r\n");
            banner.push_str(PREFIX);
            left = width.saturating_sub(PREFIX.len());
        }

        banner.push_str(token);
        banner.push(' ');
        left = left.saturating_sub(token.len() + 1);
    }

    banner.push_str("\r\n");
    let Some(version) = client_identity.strip_prefix(b"SSH-2.0-OpenSSH_") else {
        return Some(banner);
    };

    let Ok(version) = str::from_utf8(version) else {
        return Some(banner);
    };

    let Some((major, minor)) = version.split_once('.') else {
        return Some(banner);
    };

    let minor = match minor.split_once(|c: char| !c.is_ascii_digit()) {
        Some((minor, _)) => minor,
        None => minor,
    };

    let (Ok(major), Ok(minor)) = (u8::from_str(major), u8::from_str(minor)) else {
        return Some(banner);
    };

    if (major, minor) < (9, 9) {
        banner.push_str(PREFIX);
        banner.push_str(NO_PQ_WARNING_OPENSSH);
        banner.push_str("\r\n");
    }

    Some(banner)
}

const PREFIX: &str = "WARNING: ";
const NO_PQ_WARNING: &str = "the client negotiated a key exchange algorithm that is not post-quantum secure; your session may be decrypted by a cryptographically relevant quantum computer in the future";
const NO_PQ_WARNING_OPENSSH: &str =
    "consider upgrading your client version to OpenSSH 9.9 or newer";

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::BTreeMap;

    use proto::channels::PtyReq;

    use super::*;

    #[test]
    fn banner_at_80_columns() {
        let banner = banner(&pty_request(80), b"SSH-2.0-OpenSSH_10.0", false).unwrap();
        assert_eq!(
            banner,
            "WARNING: the client negotiated a key exchange algorithm that is not \r\n\
             WARNING: post-quantum secure; your session may be decrypted by a \r\n\
             WARNING: cryptographically relevant quantum computer in the future \r\n"
        );
        assert!(banner.lines().all(|line| line.len() <= 80));
    }

    #[test]
    fn banner_at_80_columns_with_openssh_warning() {
        let banner = banner(&pty_request(80), b"SSH-2.0-OpenSSH_9.8p1", false).unwrap();
        assert_eq!(
            banner,
            "WARNING: the client negotiated a key exchange algorithm that is not \r\n\
             WARNING: post-quantum secure; your session may be decrypted by a \r\n\
             WARNING: cryptographically relevant quantum computer in the future \r\n\
             WARNING: consider upgrading your client version to OpenSSH 9.9 or newer\r\n"
        );
        assert!(banner.lines().all(|line| line.len() <= 80));
    }

    fn pty_request(cols: u32) -> ChannelRequest<'static> {
        ChannelRequest {
            recipient_channel: 0,
            r#type: ChannelRequestType::PtyReq(PtyReq {
                term: Cow::Borrowed("xterm-256color"),
                cols,
                rows: 24,
                width_px: 0,
                height_px: 0,
                terminal_modes: BTreeMap::new(),
            }),
            want_reply: true,
        }
    }
}
