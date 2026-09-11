use core::str::{self, FromStr};
use std::ops::ControlFlow;

use proto::{
    Disconnect, GlobalRequest, MessageType, Pretty, SessionHostKey,
    channels::{ChannelRequest, ChannelRequestType},
    crypto::CryptoProvider,
    key_exchange::{RekeyState, Rekeyed},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, instrument, trace, warn};

use crate::{Connection, Error, KeyExchangeOutput, receive};

mod connections;
pub(crate) use connections::Channels;
use connections::{IncomingChannelMessage, TerminalsFuture};

/// A single SSH session's state
///
/// Call [`Session::run()`] to drive the session forward.
pub struct Session<T> {
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) conn: Connection<T>,
    pub(crate) kx: RekeyState,
    pub(crate) channels: Channels,
    pub(crate) post_quantum_kx: bool,
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
            kx: RekeyState::new(
                kx.session_id,
                kx.strict_kx,
                kx.identities,
                SessionHostKey::from_server(kx.host_key, provider)?,
            ),
            post_quantum_kx: kx.post_quantum_kx,
            channels: Channels::default(),
        })
    }

    /// Run the session, driving the connection forward and handling channel messages
    ///
    /// This function never returns unless the connection is closed or an error occurs.
    #[instrument(name = "connection", skip(self), fields(addr = %self.conn.addr))]
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            let mut receive = self.receive();
        }
    }

    async fn receive(&mut self) -> ControlFlow<Result<(), Error>> {
        let packet = match receive(&mut self.conn.stream, &mut self.conn.read).await {
            Ok(packet) => packet,
            Err(error) => return ControlFlow::Break(Err(error.into())),
        };

        let kx = packet.message_type == MessageType::KeyExchangeInit || self.kx.in_progress();
        match packet.message_type {
            MessageType::Ignore | MessageType::Debug => {
                trace!(?packet.message_type, "ignoring transport-layer message");
                return ControlFlow::Continue(());
            }
            MessageType::Disconnect => {
                match Disconnect::try_from(packet) {
                    Ok(disconnect) => info!(
                        ?disconnect,
                        "received disconnect packet, closing connection"
                    ),
                    Err(error) => warn!(%error, "failed to read disconnect packet"),
                }
                return ControlFlow::Break(Ok(()));
            }
            _ if kx => {
                let rekeyed = match self.kx.handle(packet, &mut self.conn.write, self.provider) {
                    Ok(rekeyed) => rekeyed,
                    Err(error) => {
                        return ControlFlow::Break(Err(error.into()));
                    }
                };

                let Some(rekeyed) = rekeyed else {
                    return ControlFlow::Continue(());
                };

                let Rekeyed {
                    update,
                    post_quantum_kx,
                } = rekeyed;

                if let Err(error) = update.apply(&mut self.conn.write, &mut self.conn.read) {
                    return ControlFlow::Break(Err(error.into()));
                }

                self.post_quantum_kx = post_quantum_kx;
                debug!("completed client-initiated rekey");
                return ControlFlow::Continue(());
            }
            MessageType::GlobalRequest => {
                let request = match GlobalRequest::try_from(packet) {
                    Ok(request) => request,
                    Err(error) => return ControlFlow::Break(Err(error.into())),
                };

                debug!(name = %String::from_utf8_lossy(request.name), "refusing unsupported global request");
                if !request.want_reply {
                    return ControlFlow::Continue(());
                }

                if let Err(error) = self.conn.write.encode(&MessageType::RequestFailure) {
                    return ControlFlow::Break(Err(error.into()));
                }

                return ControlFlow::Continue(());
            }
            MessageType::RequestSuccess | MessageType::RequestFailure => {
                trace!(?packet.message_type, "ignoring unexpected global request reply");
                return ControlFlow::Continue(());
            }
            _ => {}
        }

        let channel_message = match IncomingChannelMessage::try_from(packet) {
            Ok(message) => message,
            Err(error) => return ControlFlow::Break(Err(error.into())),
        };

        debug!(message = %Pretty(&channel_message), "handling channel message");
        let result = match channel_message {
            IncomingChannelMessage::Open(open) => self.channels.open(open, &mut self.conn.write),
            IncomingChannelMessage::Request(request) => {
                let banner = banner(&request, self.kx.client_identity(), self.post_quantum_kx);
                self.channels
                    .request(request, &mut self.conn.write, banner.as_deref())
            }
            IncomingChannelMessage::Data(data) => {
                match self.channels.data(&data, &mut self.conn.write) {
                    Ok(Some((session, data))) => match session.write(data).await {
                        Ok(_) => Ok(()),
                        Err(error) => Err(error.into()),
                    },
                    Ok(None) => Ok(()),
                    Err(error) => Err(error.into()),
                }
            }
            IncomingChannelMessage::WindowAdjust(adjust) => {
                self.channels.adjust_window(&adjust).map_err(Into::into)
            }
            IncomingChannelMessage::Eof(eof) => self.channels.eof(&eof).map_err(Into::into),
            IncomingChannelMessage::Close(close) => {
                self.channels.close(&close, &mut self.conn.write)
            }
        };

        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => ControlFlow::Break(Err(error)),
        }
    }

    async fn send(&mut self) -> Result<(), Error> {
        if self.kx.in_progress() {
            return Ok(());
        }

        TerminalsFuture::new(self.channels.channels_mut(), &mut self.conn.write).await?;
        self.conn.flush().await
    }
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
