# Sans-IO inspired design

This document presents a Sans-IO inspired design for an SSH connection library. Guiding goals for design were, from most to least important
- Not do any IO nor synchronisation within the library.
- Match in broad strokes the design of the SSH standard to simplify implementation.
- Ensure testability of individual components of the protocol.
- Maximize opportunity for eliminating copying of data.

The design here does not yet explicitly contain all configuration structs needed to instantiate the various components. It is the view of the author that these are unlikely to significantly impact the split into major components presented here. With similar motivation, various other edges are also not yet fully worked out.

## Internal design

We start our discussion with the internal split of the various components. The main protocol is split into three layers:
```rust
/// Inner most connection primitive. Handles the transition from raw bytestream to
/// individual packets, decrypting them with the provided cryptographic primitives.
/// 
/// Also handles the NEW_KEYS messages in both directions, and the identification string.
/// May also send connection closure messages on receiving garbage. 
struct SshCryptoConnection {}

impl SshCryptoConnection {
    fn poll_transmit<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        todo!()
    }
    /// Handle received bytes. The return value on OK is how many bytes were actually processed.
    /// This allows the connection to provide backpressure.
    fn handle_recv<'a>(&mut self, buf: &'a [u8]) -> Result<usize, Error> {
        todo!()
    }

    /// Will silently drop the packet if the connection is already closed
    fn send_packet(&mut self, packet: OutgoingPacket<'_>) {
        todo!()
    }

    fn recv_packet<'a>(&'a mut self) -> Option<IncomingPacket<'a>> {
        todo!()
    }
    /// Whether the connection is still open for transmit/recv
    fn closed(&self) -> bool {
        todo!()
    }

    /// Will silently ignore keys when connection is already closed
    fn set_keys(&mut self, todo: Todo) {
        todo!()
    }
}

/// Entity responsible for handling the key exchange. This would handle the initial and
/// intermediate key exchanges.
struct SshTransportConnection {}

impl SshTransportConnection {
    fn handle_packet_with<S: Service>(&mut self, packet: IncomingPacket<'_>, service: &mut S) {
        todo!()
    }

    fn poll_transmit_with<'a,  S: Service>(&'a mut self, service: &'a mut S) -> Option<OutgoingPacket<'a>>{
        todo!()
    }

    fn poll_new_keys(&mut self) -> Option<Todo> {
        todo!()
    }
}

trait Service {
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
```

The service layer is what implements the authentication and connection protocols (RFC 4252 and RFC4254), wheras the other two layers implement together the transport layer protocol (RCF 4253).

The split of the transport layer protocol essentially splits of the parsing/decryption and validation of packets, which operates semi-independently of the rest of the protocol. This split has already proven quite convenient in the current POC implementation.

Working with an explicitly passed in pointer in the transport layer was chosen for two reasons:
- It allows the service to mutate over the lifetime of the connection, which is needed as the auth protocol transitions into the connection protocol.
- It avoids having to buffer messages in the transport layer, as those get passed immediately up to the service that needs to handle them. This avoids copies.

### Authentication service

The authentication service implements the `ssh-userauth` subprotocol. The core idea is that this transforms into a wrapper layer after succesfull authentication. The wrapper layer is needed as the authentication protocol specifies a bit 

Exact details on how authentication is handled is not yet done here. The author believes however that that can be safely delayed to a later point in time without affecting much of the rest of the design.

```rust
struct SshAuthService;

impl Service for SshAuthService {
    const NAME: &'static [u8] = b"ssh-userauth";

    fn poll_transmit(&mut self) -> Option<OutgoingPacket<'_>> {
        todo!()
    }

    fn poll_event(&mut self) -> Option<ConnectionEvent> {
        todo!()
    }

    fn handle_packet(&mut self, packet: IncomingPacket<'_>) -> Result<(), Error> {
        todo!()
    }
}

enum AuthenticationStatus {
    Pending(SshAuthService),
    Complete {
        // Wrapper for the inner service, needed as the authentication service
        // will need to keep handling some messages.
        inner_service_wrapper: Todo,
        // Information provided by authentication process
        username: Todo,
        requested_service: Todo,
    },
}

impl SshAuthService {
    /// Get
    fn get_pending_auth_request<'a>(&'a mut self) -> Option<PendingAuthRequest<'a>> {
        todo!()
    }

    fn finish_authentication(self) -> AuthenticationStatus {
        todo!()
    }
}

struct PendingAuthRequest<'a> {
    todo: PhantomData<&'a mut ()>,
}

impl PendingAuthRequest<'_> {
    fn requested_service(&self) -> &[u8] {
        todo!()
    }
    fn username(&self) -> &[u8] {
        todo!()
    }
    // This needs some more design later
    fn validate_with(self, todo: Todo) -> bool {
        todo!()
    }
}
```

### Connection service

The connection service should allow multiple channels of communication between the server and client. In many ways this is very reminiscant of the concept of multiple streams within a QUIC connection, and consequently the design here for handling the channels is inspired by quinn-proto:

```rust
struct SshConnectionService;

impl Service for SshConnectionService {
    const NAME: &'static [u8] = b"ssh-connection";
    fn poll_transmit(&mut self) -> Option<OutgoingPacket<'_>> {
        todo!()
    }

    fn poll_event(&mut self) -> Option<ConnectionEvent> {
        todo!()
    }

    fn handle_packet(&mut self, packet: IncomingPacket<'_>) -> Result<(), Error> {
        todo!()
    }
}

impl SshConnectionService {
    /// Get new channel open requests from remote
    fn listen_for_new_channel<'a>(&'a mut self) -> Option<CandidateChannel<'a>> {
        todo!()
    }

    /// Open a channel from our end
    fn open_channel(&mut self, channel_type: &[u8]) -> PendingOpenChannel {
        todo!()
    }

    /// Checks and if possible completes the opening of a channel.
    fn complete_open_channel(
        &mut self,
        pending_channel: PendingOpenChannel,
    ) -> Option<Result<ChannelId, Error>> {
        todo!()
    }

    // TODO: functions for global messages, lets design those later

    /// Get the actual channel for operations (design here is easy to change, maybe this should be split but ok as a starting point).
    /// Note that this is fallable as there is no guarantee the ChannelId is still valid
    fn get_channel(&mut self, channel: ChannelId) -> Option<Todo> {
        todo!()
    }
}

struct CandidateChannel<'a> {
    todo: PhantomData<&'a mut ()>,
}

impl CandidateChannel<'_> {
    fn channel_type(&self) -> &str {
        todo!()
    }

    // Perhaps other information from the request

    fn accept(self) -> ChannelId {
        todo!()
    }

    fn reject(self) {
        // Actual implementation via drop
    }
}

struct PendingOpenChannel {
    todo: (),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct ChannelId {
    todo: (),
}
```

Although within a Sans-IO context likely unavoidable, the choice to use identifiers for the individual channels leads to quite significant potential for misuse of the API. Examples of this are forgetting to properly close channels before dropping the identifier, and trying to use an identifier with a different connection from which it was originated. As seen below, these difficulties extend to the public interface.

## External interface

The primitives presented above can be combined in a relatively thin layer to provide an external interface along the lines of
```rust
struct SshConnection<State> {
    todo: PhantomData<State>,
}

impl<State> SshConnection<State> {
    fn poll_transmit<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        todo!()
    }
    fn handle_recv<'a>(&mut self, buf: &'a [u8]) -> Result<usize, Error> {
        todo!()
    }
}

impl SshConnection<Authenticating> {
    // Wrappers for relevant functions from SshAuthService
}

impl SshConnection<Connected> {
    // Wrappers for relevant functions from SshConnectionService
}
```

This is relatively missuse resistant, although the issues with channel ids remain.
