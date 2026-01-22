use std::borrow::Cow;

use tracing::debug;

use crate::{
    proto::{Decode, Decoded, Encode, MessageType, Packet},
    Error, SshTransportConnection,
};

pub trait Service {
    fn packet_types(&self) -> Cow<'static, [u8]>;
    fn handle_packet(&mut self, packet: Packet<'_>);
}

/// Simple do-nothing service for debugging
pub struct NoopService;

impl Service for NoopService {
    fn packet_types(&self) -> Cow<'static, [u8]> {
        (&[]).into()
    }

    fn handle_packet(&mut self, _packet: Packet<'_>) {}
}

pub struct ServiceRunner<F> {
    service: Option<Box<dyn Service>>,
    outgoing_receiver: tokio::sync::mpsc::UnboundedReceiver<Box<dyn Encode + Send + 'static>>,
    outgoing_sender: tokio::sync::mpsc::UnboundedSender<Box<dyn Encode + Send + 'static>>,
    connection: SshTransportConnection,
    service_provider: F,
}

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
enum DisconnectReason {
    HostNotAllowedToConnect,
    ProtocolError,
    KeyExchangeFailed,
    Reserved,
    MacError,
    CompressionError,
    ServiceNotAvailable,
    ProtocolVersionNotSupported,
    HostKeyNotVerifiable,
    ConnectionLost,
    ByApplication,
    TooManyConnections,
    AuthCancelledByUser,
    NoMoreAuthMethodsAvailable,
    IllegalUserName,
    Unknown(u32),
}

impl Encode for DisconnectReason {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::HostNotAllowedToConnect => 1,
            Self::ProtocolError => 2,
            Self::KeyExchangeFailed => 3,
            Self::Reserved => 4,
            Self::MacError => 5,
            Self::CompressionError => 6,
            Self::ServiceNotAvailable => 7,
            Self::ProtocolVersionNotSupported => 8,
            Self::HostKeyNotVerifiable => 9,
            Self::ConnectionLost => 10,
            Self::ByApplication => 11,
            Self::TooManyConnections => 12,
            Self::AuthCancelledByUser => 13,
            Self::NoMoreAuthMethodsAvailable => 14,
            Self::IllegalUserName => 15,
            Self::Unknown(v) => *v,
        }
        .encode(buf);
    }
}

struct DisconnectMsg(DisconnectReason);

impl Encode for DisconnectMsg {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::Disconnect.encode(buf);
        self.0.encode(buf);
        b"".encode(buf);
        b"".encode(buf);
    }
}

struct ServiceAcceptMsg<'a> {
    name: Cow<'a, [u8]>,
}

impl Encode for ServiceAcceptMsg<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::ServiceAccept.encode(buf);
        self.name.encode(buf);
    }
}

struct UnimplementedMsg {
    sequence_no: u32,
}

impl Encode for UnimplementedMsg {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::Unimplemented.encode(buf);
        self.sequence_no.encode(buf);
    }
}

impl<
        F: FnMut(
            &[u8],
            tokio::sync::mpsc::UnboundedSender<Box<dyn Encode + Send + 'static>>,
        ) -> Option<Box<dyn Service>>,
    > ServiceRunner<F>
{
    pub fn new(connection: SshTransportConnection, service_provider: F) -> Self {
        let (outgoing_sender, outgoing_receiver) = tokio::sync::mpsc::unbounded_channel();
        Self {
            service: None,
            outgoing_receiver,
            outgoing_sender,
            connection,
            service_provider,
        }
    }

    pub async fn run(mut self) {
        enum SelectResult<'a> {
            Recv(Result<Packet<'a>, Error>),
            Send(Option<Box<dyn Encode + Send + 'static>>),
        }
        loop {
            let select_result = tokio::select! {
                recv = self.connection.recv_packet() => SelectResult::Recv(recv),
                send = self.outgoing_receiver.recv() => SelectResult::Send(send),
            };

            match select_result {
                SelectResult::Recv(Ok(packet)) => {
                    match MessageType::decode(packet.payload) {
                        Ok(Decoded {
                            value: MessageType::Disconnect,
                            ..
                        }) => {
                            return;
                        }
                        Ok(Decoded {
                            value: MessageType::Unknown(v),
                            ..
                        }) => {
                            let sequence_no = packet.number;
                            let mut handled = false;
                            if let Some(ref mut service) = self.service {
                                // FIXME: make this a let chain once we move to Rust2024
                                if service.packet_types().contains(&v) {
                                    service.handle_packet(packet);
                                    handled = true;
                                }
                            }
                            if !handled {
                                debug!("Received unhandled packet of type {v}");
                                if let Err(e) = self
                                    .connection
                                    .send_packet(&UnimplementedMsg { sequence_no })
                                    .await
                                {
                                    debug!("Error sending packet: {e}");
                                    return;
                                }
                            }
                        }
                        Ok(Decoded {
                            value: MessageType::ServiceRequest,
                            next,
                        }) => {
                            let service_name = match <&[u8]>::decode(next) {
                                Ok(Decoded { value, next: &[] }) => value,
                                Ok(_) => {
                                    debug!("Excess bytes in packet, dropping connection");
                                    if let Err(e) = self
                                        .connection
                                        .send_packet(&DisconnectMsg(
                                            DisconnectReason::ProtocolError,
                                        ))
                                        .await
                                    {
                                        debug!("Error sending packet: {e}");
                                    }
                                    return;
                                }
                                Err(_) => todo!(),
                            };

                            if let Some(service) =
                                (self.service_provider)(service_name, self.outgoing_sender.clone())
                            {
                                if self.service.is_none() {
                                    self.service = Some(service);
                                } else {
                                    if let Err(e) = self
                                        .connection
                                        .send_packet(&DisconnectMsg(
                                            DisconnectReason::ProtocolError,
                                        ))
                                        .await
                                    {
                                        debug!("Error sending packet: {e}");
                                    }
                                    return;
                                }
                                let packet = ServiceAcceptMsg {
                                    name: service_name.to_vec().into(),
                                };
                                if let Err(e) = self.connection.send_packet(&packet).await {
                                    debug!("Error sending packet: {e}");
                                    return;
                                }
                            } else {
                                debug!(
                                    "Request for unknown service {}",
                                    String::from_utf8_lossy(service_name)
                                );
                                if let Err(e) = self
                                    .connection
                                    .send_packet(&DisconnectMsg(
                                        DisconnectReason::ServiceNotAvailable,
                                    ))
                                    .await
                                {
                                    debug!("Error sending packet: {e}");
                                }
                                return;
                            }
                        }
                        Ok(_) => {
                            // FIXME: Figure out what to do with the other known message types instead of ignoring
                        }
                        Err(e) => {
                            debug!("Error decoding packet type: {e}");
                            if let Err(e) = self
                                .connection
                                .send_packet(&DisconnectMsg(DisconnectReason::ProtocolError))
                                .await
                            {
                                debug!("Error sending packet: {e}");
                            }
                            return;
                        }
                    }
                }
                SelectResult::Recv(Err(Error::Io(e))) => {
                    debug!("Io error on connection, dropping: {e}");
                    return;
                }
                SelectResult::Recv(Err(Error::InvalidMac)) => {
                    debug!("Invalid mac on received packet, dropping connection");
                    if let Err(e) = self
                        .connection
                        .send_packet(&DisconnectMsg(DisconnectReason::MacError))
                        .await
                    {
                        debug!("Error sending packet: {e}");
                    }
                    return;
                }
                SelectResult::Recv(Err(e)) => {
                    debug!("Receiving packet failed with error {e}, dropping connection");
                    if let Err(e) = self
                        .connection
                        .send_packet(&DisconnectMsg(DisconnectReason::ProtocolError))
                        .await
                    {
                        debug!("Error sending packet: {e}");
                    }
                    return;
                }
                SelectResult::Send(Some(payload)) => {
                    if let Err(e) = self.connection.send_packet(&*payload).await {
                        debug!("Error sending packet: {e}");
                        return;
                    }
                }
                SelectResult::Send(None) => {}
            }
        }
    }
}
