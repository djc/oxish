use crate::{
    proto::{IncomingPacket, OutgoingPacket},
    Error,
};

// FIXME: move this to the transport connection code once that is implemented.
#[expect(unused)]
pub(crate) enum ConnectionEvent {
    Close,
}

#[expect(unused)]
pub(crate) trait Service {
    /// Service name used by SshTransportConnection during handshake
    const NAME: &'static [u8];

    /// Poll for packets to transmit through the transport layer.
    ///
    /// Should be called first of the poll functions.
    fn poll_transmit(&mut self) -> Option<OutgoingPacket<'_>>;
    /// Poll for connection events that need handling by the
    /// transport layer.
    ///
    /// Should be called second of the poll functions. However
    /// services should ensure themselves that all outgoing packets
    /// are sent before emitting a connectionevent that results in
    /// termination of the connection or service.
    fn poll_event(&mut self) -> Option<ConnectionEvent>;
    /// Handle a packet
    fn handle_packet(&mut self, packet: IncomingPacket<'_>) -> Result<(), Error>;
}
