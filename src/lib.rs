use core::{fmt, net::SocketAddr};
use std::{io, str, sync::Arc};

use aws_lc_rs::signature::Ed25519KeyPair;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, instrument, warn};

mod connections;
use connections::{Channels, IncomingChannelMessage};
mod key_exchange;
use key_exchange::{EcdhKeyExchangeInit, KeyExchange, KeyExchangeInit, RawKeySet};
mod messages;
use messages::{
    Completion, Decoded, Disconnect, DisconnectReason, Identification, MessageType, MethodName,
    NewKeys, ServiceAccept, ServiceName, ServiceRequest, UserAuthRequest, PROTOCOL,
};
mod proto;
use proto::{AesCtrReadKeys, AesCtrWriteKeys, HandshakeHash, ReadState, WriteState};
mod terminal;

/// A single SSH connection
pub struct Connection<T> {
    stream: T,
    context: ConnectionContext,
    read: ReadState,
    write: WriteState,
    channels: Channels,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Create a new [`Connection`]
    pub fn new(stream: T, addr: SocketAddr, host_key: Arc<Ed25519KeyPair>) -> anyhow::Result<Self> {
        Ok(Self {
            stream,
            context: ConnectionContext { addr, host_key },
            read: ReadState::default(),
            write: WriteState::default(),
            channels: Channels::default(),
        })
    }

    /// Drive the connection forward
    #[instrument(name = "connection", skip(self), fields(addr = %self.context.addr))]
    pub async fn run(mut self) {
        let mut exchange = HandshakeHash::default();
        let state = VersionExchange::default();
        let state = match state.advance(&mut exchange, &mut self).await {
            Ok(state) => state,
            Err(error) => {
                error!(%error, "failed to complete version exchange");
                return;
            }
        };

        // Receive and send key exchange init packets

        let packet = match self.read.packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                error!(%error, "failed to read packet");
                return;
            }
        };
        exchange.update(&((packet.payload.len() + 1) as u32).to_be_bytes());
        exchange.update(&[u8::from(packet.message_type)]);
        exchange.update(packet.payload);
        let peer_key_exchange_init = match KeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                error!(%error, "failed to read key exchange init");
                return;
            }
        };

        let Ok((key_exchange_init, state)) = state.advance(peer_key_exchange_init, &self.context)
        else {
            return;
        };

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &key_exchange_init, Some(&mut exchange))
            .await
        {
            error!(%error, "failed to send key exchange init packet");
            return;
        }

        // Perform ECDH key exchange

        let packet = match self.read.packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                error!(%error, "failed to read packet");
                return;
            }
        };

        let ecdh_key_exchange_init = match EcdhKeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                error!(%error, "failed to read ecdh key exchange init");
                return;
            }
        };

        let Ok((key_exchange_reply, keys)) =
            state.advance(ecdh_key_exchange_init, exchange, &self.context)
        else {
            return;
        };

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &key_exchange_reply, None)
            .await
        {
            warn!(%error, "failed to send key exchange init packet");
            return;
        }

        // Exchange new keys packets and install new keys

        if let Err(error) = self.update_keys(keys).await {
            error!(%error, "failed to update keys");
            return;
        }

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &MessageType::Ignore, None)
            .await
        {
            error!(%error, "failed to send ignore packet");
            return;
        }

        let packet = match self.read.packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                error!(%error, "failed to read packet");
                return;
            }
        };

        let service_request = match ServiceRequest::try_from(packet) {
            Ok(req) => req,
            Err(error) => {
                error!(%error, "failed to read service request");
                return;
            }
        };

        if service_request.service_name != ServiceName::UserAuth {
            error!(
                service_name = ?service_request.service_name,
                "unsupported service requested"
            );

            let disconnect = Disconnect {
                reason_code: DisconnectReason::ServiceNotAvailable,
                description: "only user authentication service is supported",
            };
            if let Err(error) = self
                .write
                .write_packet(&mut self.stream, &disconnect, None)
                .await
            {
                error!(%error, "failed to send disconnect packet");
            }
            return;
        }

        let service_accept = ServiceAccept {
            service_name: ServiceName::UserAuth,
        };
        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &service_accept, None)
            .await
        {
            error!(%error, "failed to send service accept packet");
            return;
        }

        let packet = match self.read.packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                error!(%error, "failed to read packet");
                return;
            }
        };

        let user_auth_request = match UserAuthRequest::try_from(packet) {
            Ok(req) => req,
            Err(error) => {
                error!(%error, "failed to read user auth request");
                return;
            }
        };

        if user_auth_request.service_name != ServiceName::Connection {
            error!(
                service_name = ?user_auth_request.service_name,
                "unsupported service requested"
            );

            let disconnect = Disconnect {
                reason_code: DisconnectReason::ServiceNotAvailable,
                description: "only connection service is supported",
            };
            if let Err(error) = self
                .write
                .write_packet(&mut self.stream, &disconnect, None)
                .await
            {
                error!(%error, "failed to send disconnect packet");
            }
            return;
        }

        if user_auth_request.method_name != MethodName::None {
            error!(
                method_name = ?user_auth_request.method_name,
                "unsupported authentication method requested"
            );

            let disconnect = Disconnect {
                reason_code: DisconnectReason::NoMoreAuthMethodsAvailable,
                description: "only 'none' authentication method is supported",
            };
            if let Err(error) = self
                .write
                .write_packet(&mut self.stream, &disconnect, None)
                .await
            {
                error!(%error, "failed to send disconnect packet");
            }
            return;
        }

        #[expect(unused_variables)]
        let user = user_auth_request.user_name.to_owned();
        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &MessageType::UserAuthSuccess, None)
            .await
        {
            error!(%error, "failed to send user auth success packet");
            return;
        }

        loop {
            tokio::select! {
                packet = self.read.packet(&mut self.stream) => {
                    let packet = match packet {
                        Ok(packet) => packet,
                        Err(error) => {
                            error!(%error, "failed to read packet");
                            return;
                        }
                    };

                    if packet.message_type == MessageType::Disconnect {
                        match Disconnect::try_from(packet) {
                            Ok(disconnect) => info!(?disconnect, "received disconnect packet, closing connection"),
                            Err(error) => warn!(%error, "failed to read disconnect packet"),
                        }
                        return;
                    }

                    let channel_message = match IncomingChannelMessage::try_from(packet) {
                        Ok(req) => req,
                        Err(error) => {
                            error!(%error, "failed to read channel message");
                            return;
                        }
                    };

                    debug!(message = %Pretty(&channel_message), "handling channel message");
                    let outgoing = match channel_message {
                        IncomingChannelMessage::Open(open) => Some(self.channels.open(open)),
                        IncomingChannelMessage::Request(request) => match self.channels.request(request) {
                            Ok(outgoing) => outgoing,
                            Err(error) => {
                                error!(%error, "failed to handle channel request");
                                return;
                            }
                        }
                        IncomingChannelMessage::Data(data) => match self.channels.data(&data) {
                            Ok(Some((session, data))) => {
                                if let Err(error) = session.write(data).await {
                                    error!(%error, "failed to write data to session");
                                    return;
                                }
                                None
                            }
                            Ok(None) => None,
                            Err(error) => {
                                error!(%error, "failed to handle channel data");
                                return;
                            }
                        }
                        IncomingChannelMessage::Eof(eof) => {
                            if let Err(error) = self.channels.eof(&eof) {
                                error!(%error, "failed to handle channel eof");
                                return;
                            }
                            None
                        }
                        IncomingChannelMessage::Close(close) => self.channels.close(&close),
                    };

                    if let Some(outgoing) = outgoing {
                        debug!(outgoing = %Pretty(&outgoing), "sending channel message");
                        if let Err(error) = self
                            .write
                            .write_packet(&mut self.stream, &outgoing, None)
                            .await
                        {
                            error!(%error, "failed to send channel message");
                            return;
                        }
                    }
                }
                result = self.channels.poll_terminals() => {
                    match result {
                        Ok(Some(outgoing)) => {
                            debug!(outgoing = %Pretty(&outgoing), "sending channel message from session");
                            if let Err(error) = self
                                .write
                                .write_packet(&mut self.stream, &outgoing, None)
                                .await
                            {
                                error!(%error, "failed to send channel message");
                                return;
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            error!(%error, "failed to poll sessions");
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn update_keys(&mut self, keys: RawKeySet) -> Result<(), Error> {
        let packet = self.read.packet(&mut self.stream).await?;
        NewKeys::try_from(packet)?;
        self.write
            .write_packet(&mut self.stream, &NewKeys, None)
            .await?;

        let RawKeySet {
            client_to_server,
            server_to_client,
        } = keys;

        // Cipher and MAC algorithms are negotiated during key exchange.
        // Currently this hard codes AES-128-CTR and HMAC-SHA256.
        self.read.decryption_key = Some(AesCtrReadKeys::new(client_to_server));
        self.write.keys = Some(AesCtrWriteKeys::new(server_to_client));
        Ok(())
    }
}

struct ConnectionContext {
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
}

#[derive(Default)]
struct VersionExchange(());

impl VersionExchange {
    async fn advance(
        &self,
        exchange: &mut HandshakeHash,
        conn: &mut Connection<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> Result<KeyExchange, Error> {
        // TODO: enforce timeout if this is taking too long
        let (buf, Decoded { value: ident, next }) = loop {
            let bytes = conn.read.buffer(&mut conn.stream).await?;
            match Identification::decode(bytes) {
                Ok(Completion::Complete(decoded)) => break (bytes, decoded),
                Ok(Completion::Incomplete(_length)) => continue,
                Err(error) => return Err(error),
            }
        };

        debug!(addr = %conn.context.addr, ?ident, "received identification");
        if ident.protocol != PROTOCOL {
            warn!(addr = %conn.context.addr, ?ident, "unsupported protocol version");
            return Err(IdentificationError::UnsupportedVersion(ident.protocol.to_owned()).into());
        }

        let rest = next.len();
        let v_c_len = buf.len() - rest - 2;
        if let Some(v_c) = buf.get(..v_c_len) {
            exchange.prefixed(v_c);
        }

        let ident = Identification::outgoing();
        let server_ident_bytes = conn.write.encoded(&ident);
        if let Err(error) = conn.stream.write_all(server_ident_bytes).await {
            warn!(addr = %conn.context.addr, %error, "failed to send version exchange");
            return Err(error.into());
        }

        let v_s_len = server_ident_bytes.len() - 2;
        if let Some(v_s) = server_ident_bytes.get(..v_s_len) {
            exchange.prefixed(v_s);
        }

        let last_length = buf.len() - rest;
        conn.read.set_last_length(last_length);
        Ok(KeyExchange::default())
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("failed to get random bytes")]
    FailedRandomBytes,
    #[error("failed to parse identification: {0}")]
    Identification(#[from] IdentificationError),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("incomplete message: {0:?}")]
    Incomplete(Option<usize>),
    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),
    #[error("no common {0} algorithms")]
    NoCommonAlgorithm(&'static str),
    #[error("invalid mac for packet")]
    InvalidMac,
    #[error("unreachable code: {0}")]
    Unreachable(&'static str),
}

#[derive(Debug, Error)]
enum IdentificationError {
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    #[error("No SSH prefix")]
    NoSsh,
    #[error("No version found")]
    NoVersion,
    #[error("Identification too long")]
    TooLong,
    #[error("Unsupported protocol version")]
    UnsupportedVersion(String),
}

struct Pretty<T>(T);

impl<T: fmt::Debug> fmt::Display for Pretty<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", &self.0)
    }
}
