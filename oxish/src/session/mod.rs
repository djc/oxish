use core::{cmp::Ordering, future, mem::MaybeUninit};
use std::{
    io::{self, IoSliceMut},
    os::fd::AsFd,
};

use proto::{
    Decode, Decoded, Disconnect, Encoder, ExtensionId, HostKeys, IncomingPacket, KeyExchange,
    MessageType, Pretty, ProtoError, ReadState, WriteState,
    crypto::{CryptoProvider, Digest, HandshakeBuffer},
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
    channels: Channels,
    rekey: Rekey,
}

/// The state a session needs to honor a client-initiated rekey
///
/// A rekey reuses the identification strings and session identifier from the initial
/// handshake, but performs a fresh key exchange (which requires a host key to sign the
/// new exchange hash) and derives new key material from it.
struct Rekey {
    host_keys: HostKeys,
    /// Session identifier, fixed at the first key exchange (RFC 4253 section 7.2)
    session_id: Digest,
    /// The client's identification string (`V_C`), fed into every exchange hash
    client_ident: Vec<u8>,
    /// Our identification string (`V_S`), fed into every exchange hash
    server_ident: Vec<u8>,
}

impl Rekey {
    /// Process the client's `SSH_MSG_KEXINIT` and negotiate the new algorithms
    fn start(
        &self,
        packet: IncomingPacket<'_>,
        provider: &dyn CryptoProvider,
    ) -> Result<KeyExchange, ProtoError> {
        // Every exchange hash starts with `V_C` and `V_S` (RFC 4253 section 8).
        let mut exchange = HandshakeBuffer::default();
        exchange.prefixed(&self.client_ident);
        exchange.prefixed(&self.server_ident);

        // A rekey advertises no extensions: the strict key exchange and ext-info markers
        // are only valid in the first key exchange (RFC 8308, OpenSSH strict kex).
        KeyExchange::start(
            packet,
            exchange,
            self.host_keys.algorithms().collect(),
            core::iter::empty::<ExtensionId<'static>>(),
            provider,
        )
    }
}

impl Session<TcpStream> {
    pub fn new(source: &impl AsFd) -> Result<Self, Error> {
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

        let Decoded { value: state, next } = SessionState::decode(&received)?;
        if !next.is_empty() {
            return Err(Error::InvalidState("trailing bytes after message"));
        }

        // Acknowledge the handoff so the parent releases its copy of the descriptor
        rustix::net::send(source, &[1], SendFlags::empty()).map_err(io::Error::from)?;
        debug!(?state, "received session state, reconstructing connection");

        let SessionState {
            addr,
            read,
            write,
            read_buf,
            session_id,
            client_ident,
            server_ident,
            host_keys_pkcs8,
        } = state;

        let provider = DEFAULT_PROVIDER;
        let opener = provider.opening_key(read.counter, &read.source)?;
        let sealer = provider.sealing_key(write.counter, &write.source)?;

        // Rebuild the host keys so the session can sign a client-initiated rekey.
        let host_keys = host_keys_pkcs8
            .iter()
            .map(|pkcs8| provider.signing_key_from_pkcs8(pkcs8))
            .collect::<Result<Vec<_>, _>>()?;
        let host_keys = HostKeys::try_from(host_keys)?;

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
            channels: Channels::default(),
            rekey: Rekey {
                host_keys,
                session_id,
                client_ident,
                server_ident,
            },
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Session<T> {
    /// Drive the connection forward
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
                            let kx = self.rekey.start(packet, DEFAULT_PROVIDER)?;
                            self.conn
                                .rekey_exchange(
                                    kx,
                                    &self.rekey.host_keys,
                                    self.rekey.session_id.clone(),
                                    DEFAULT_PROVIDER,
                                )
                                .await?;
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
                        IncomingChannelMessage::Data(data) => match self.channels.data(&data) {
                            Ok(Some((session, data))) => match session.write(data).await {
                                Ok(_) => Ok(()),
                                Err(error) => Err(error.into()),
                            },
                            Ok(None) => Ok(()),
                            Err(error) => Err(error.into()),
                        }
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
