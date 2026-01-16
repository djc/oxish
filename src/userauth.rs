use std::borrow::Cow;

use crate::{
    proto::{Decode, Decoded, IncomingPacket, MessageType, OutgoingPacket},
    service::Service,
    Error,
};

pub(crate) struct SshUserauth {
    state: AuthState,
}

impl SshUserauth {
    #[expect(unused)]
    pub(crate) fn new() -> Self {
        Self {
            state: AuthState::WaitingForAuthRequest(WaitingForAuthRequest::new_session()),
        }
    }

    #[expect(unused)]
    pub(crate) fn poll_authrequest(&mut self) -> Option<AuthRequest<'_>> {
        match &self.state {
            AuthState::WaitingForAuthDecision(waiting_for_auth_decision) => {
                match waiting_for_auth_decision.method() {
                    AuthenticationMethod::None => Some(AuthRequest::None(NoneAuthRequest {
                        state: &mut self.state,
                    })),
                    AuthenticationMethod::Unknown(cow) => {
                        unreachable!("Pending auth request with unknown method")
                    }
                }
            }
            _ => None,
        }
    }

    #[expect(unused)]
    pub(crate) fn poll_complete<S: Service>(
        mut self,
    ) -> Result<(impl FnOnce(S) -> SshUserauthWrapper<S>, AuthData), Self> {
        match self.state.take() {
            AuthState::AuthCompleted(auth_completed) => Ok((
                |inner| SshUserauthWrapper { inner },
                AuthData {
                    username: auth_completed.username,
                    service: auth_completed.service,
                },
            )),
            s => {
                self.state = s;
                Err(self)
            }
        }
    }
}

/// Main result of authentication
pub(crate) struct AuthData {
    username: Vec<u8>,
    service: Vec<u8>,
}

impl AuthData {
    #[expect(unused)]
    fn username(&self) -> &[u8] {
        &self.username
    }

    #[expect(unused)]
    fn service(&self) -> &[u8] {
        &self.service
    }
}

/// Wrapper needed to handle the authentication messages after completion of authentication
#[expect(unused)]
pub(crate) struct SshUserauthWrapper<S> {
    inner: S,
}

impl<S: Service> Service for SshUserauthWrapper<S> {
    const NAME: &'static [u8] = S::NAME;

    fn poll_transmit(&mut self) -> Option<OutgoingPacket<'_>> {
        self.inner.poll_transmit()
    }

    fn poll_event(&mut self) -> Option<crate::service::ConnectionEvent> {
        self.inner.poll_event()
    }

    fn handle_packet(&mut self, packet: IncomingPacket<'_>) -> Result<(), Error> {
        match packet.message_type {
            MessageType::UserauthRequest
            | MessageType::UserauthSuccess
            | MessageType::UserauthFailure
            | MessageType::UserauthBanner => {
                // Ignore per RFC4252 section 5.3
                Ok(())
            }
            _ => self.inner.handle_packet(packet),
        }
    }
}

// FIXME: Implement actual proper authentication methods
pub(crate) enum AuthRequest<'a> {
    #[expect(unused)]
    None(NoneAuthRequest<'a>),
}

pub(crate) struct NoneAuthRequest<'a> {
    state: &'a mut AuthState,
}

impl NoneAuthRequest<'_> {
    #[expect(unused)]
    pub(crate) fn username(&self) -> &[u8] {
        match &self.state {
            AuthState::WaitingForAuthDecision(waiting_for_auth_decision) => {
                waiting_for_auth_decision.username()
            }
            _ => unreachable!("Invalid state for auth request"),
        }
    }

    #[expect(unused)]
    pub(crate) fn service(&self) -> &[u8] {
        match &self.state {
            AuthState::WaitingForAuthDecision(waiting_for_auth_decision) => {
                waiting_for_auth_decision.service()
            }
            _ => unreachable!("Invalid state for auth request"),
        }
    }

    #[expect(unused)]
    pub(crate) fn accept(self) {
        match self.state.take() {
            AuthState::WaitingForAuthDecision(waiting_for_auth_decision) => {
                *self.state =
                    AuthState::AuthCompletedWaitingForTransmit(waiting_for_auth_decision.accept())
            }
            _ => unreachable!("Invalid state for auth request"),
        }
    }

    #[expect(unused)]
    pub(crate) fn decline(self) {
        match self.state.take() {
            AuthState::WaitingForAuthDecision(waiting_for_auth_decision) => {
                *self.state = AuthState::AuthFailed(waiting_for_auth_decision.decline())
            }
            _ => unreachable!("Invalid state for auth request"),
        }
    }
}

impl Service for SshUserauth {
    const NAME: &'static [u8] = b"ssh-userauth";

    fn poll_transmit(&mut self) -> Option<OutgoingPacket<'_>> {
        match self.state.take() {
            AuthState::AuthCompletedWaitingForTransmit(auth_completed_waiting_for_transmit) => {
                let (new_state, packet) = auth_completed_waiting_for_transmit.advance();
                self.state = AuthState::AuthCompleted(new_state);
                Some(packet)
            }
            AuthState::AuthFailed(auth_failed) => {
                let (new_state, packet) = auth_failed.advance();
                self.state = AuthState::WaitingForAuthRequest(new_state);
                Some(packet)
            }
            AuthState::WaitingToSendUnimplemented(waiting_to_send_unimplemented) => {
                let (new_state, packet) = waiting_to_send_unimplemented.advance();
                self.state = AuthState::WaitingForAuthRequest(new_state);
                Some(packet)
            }
            AuthState::Poisoned => {
                panic!("Poisoned authentication state. Error was non-recoverable.")
            }
            s => {
                self.state = s;
                None
            }
        }
    }

    fn poll_event(&mut self) -> Option<crate::service::ConnectionEvent> {
        None
    }

    fn handle_packet(&mut self, packet: IncomingPacket<'_>) -> Result<(), Error> {
        match self.state.take() {
            AuthState::WaitingForAuthRequest(waiting_for_auth_request) => {
                if packet.message_type == MessageType::UserauthRequest {
                    let request = UserauthRequest::try_from(packet)?;
                    self.state = match waiting_for_auth_request.advance(request) {
                        Ok(waiting_for_auth_decision) => {
                            AuthState::WaitingForAuthDecision(waiting_for_auth_decision)
                        }
                        Err(auth_failed) => AuthState::AuthFailed(auth_failed),
                    };
                } else {
                    self.state = AuthState::WaitingToSendUnimplemented(
                        WaitingToSendUnimplemented::from(packet),
                    );
                }
            }
            AuthState::WaitingForAuthDecision(_)
            | AuthState::AuthCompletedWaitingForTransmit(_)
            | AuthState::AuthCompleted(_)
            | AuthState::AuthFailed(_)
            | AuthState::WaitingToSendUnimplemented(_) => return Err(Error::NotReady),
            AuthState::Poisoned => {
                panic!("Poisoned authentication state. Error was non-recoverable.")
            }
        }

        Ok(())
    }
}

#[expect(
    unused,
    reason = "Use marking from the service trait is failing in the compiler"
)]
enum AuthState {
    WaitingForAuthRequest(WaitingForAuthRequest),
    WaitingForAuthDecision(WaitingForAuthDecision),
    AuthCompletedWaitingForTransmit(AuthCompletedWaitingForTransmit),
    AuthCompleted(AuthCompleted),
    AuthFailed(AuthFailed),
    WaitingToSendUnimplemented(WaitingToSendUnimplemented),
    Poisoned,
}

impl AuthState {
    fn take(&mut self) -> Self {
        let mut val = Self::Poisoned;
        core::mem::swap(&mut val, self);
        val
    }
}

struct WaitingForAuthRequest {}

impl WaitingForAuthRequest {
    fn new_session() -> Self {
        Self {}
    }

    #[expect(
        unused,
        reason = "Use marking from the service trait is failing in the compiler"
    )]
    fn advance(self, request: UserauthRequest<'_>) -> Result<WaitingForAuthDecision, AuthFailed> {
        match request.method {
            AuthenticationMethod::None => Ok(WaitingForAuthDecision {
                username: request.username.to_vec(),
                service: request.service.to_vec(),
                method: AuthenticationMethod::None,
            }),
            AuthenticationMethod::Unknown(_) => Err(AuthFailed {}),
        }
    }
}

impl WaitingForAuthRequest {}

struct WaitingForAuthDecision {
    username: Vec<u8>,
    service: Vec<u8>,
    method: AuthenticationMethod<'static>,
}

impl WaitingForAuthDecision {
    fn username(&self) -> &[u8] {
        &self.username
    }

    fn service(&self) -> &[u8] {
        &self.service
    }

    fn method(&self) -> AuthenticationMethod<'_> {
        self.method.borrowed()
    }

    fn accept(self) -> AuthCompletedWaitingForTransmit {
        AuthCompletedWaitingForTransmit {
            username: self.username,
            service: self.service,
        }
    }

    fn decline(self) -> AuthFailed {
        AuthFailed {}
    }
}

struct AuthCompletedWaitingForTransmit {
    username: Vec<u8>,
    service: Vec<u8>,
}

impl AuthCompletedWaitingForTransmit {
    #[expect(
        unused,
        reason = "Use marking from the service trait is failing in the compiler"
    )]
    fn advance(self) -> (AuthCompleted, OutgoingPacket<'static>) {
        (
            AuthCompleted {
                username: self.username,
                service: self.service,
            },
            OutgoingPacket {
                message_type: MessageType::UserauthSuccess,
                payload: Cow::Borrowed(&[]),
            },
        )
    }
}

struct AuthCompleted {
    username: Vec<u8>,
    service: Vec<u8>,
}

struct AuthFailed {}

impl AuthFailed {
    #[expect(
        unused,
        reason = "Use marking from the service trait is failing in the compiler"
    )]
    fn advance(self) -> (WaitingForAuthRequest, OutgoingPacket<'static>) {
        (
            WaitingForAuthRequest {},
            OutgoingPacket {
                message_type: MessageType::UserauthFailure,
                payload: Cow::Borrowed(b"\0\0\0\0\0"),
            },
        )
    }
}

struct WaitingToSendUnimplemented {
    packet: OutgoingPacket<'static>,
}

impl From<IncomingPacket<'_>> for WaitingToSendUnimplemented {
    fn from(value: IncomingPacket<'_>) -> Self {
        Self {
            packet: value.unimplemented(),
        }
    }
}

impl WaitingToSendUnimplemented {
    #[expect(
        unused,
        reason = "Use marking from the service trait is failing in the compiler"
    )]
    fn advance(self) -> (WaitingForAuthRequest, OutgoingPacket<'static>) {
        (WaitingForAuthRequest {}, self.packet)
    }
}

#[derive(Debug, Clone)]
enum AuthenticationMethod<'a> {
    None,
    Unknown(Cow<'a, [u8]>),
}

impl<'b> AuthenticationMethod<'b> {
    fn borrowed<'a: 'b>(&'a self) -> AuthenticationMethod<'a> {
        match self {
            Self::None => Self::None,
            Self::Unknown(Cow::Borrowed(b)) => Self::Unknown(Cow::Borrowed(b)),
            Self::Unknown(Cow::Owned(b)) => Self::Unknown(Cow::Borrowed(b)),
        }
    }
}

impl<'a> Decode<'a> for AuthenticationMethod<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded {
            value: bytestring,
            next,
        } = <&[u8]>::decode(bytes)?;
        Ok(Decoded {
            value: AuthenticationMethod::from(bytestring),
            next,
        })
    }
}

impl<'a> From<&'a [u8]> for AuthenticationMethod<'a> {
    fn from(value: &'a [u8]) -> Self {
        match value {
            b"none" => Self::None,
            _ => Self::Unknown(Cow::Borrowed(value)),
        }
    }
}

struct UserauthRequest<'a> {
    username: &'a [u8],
    service: &'a [u8],
    method: AuthenticationMethod<'a>,
    #[expect(unused)]
    method_specific_data: &'a [u8],
}

impl<'a> TryFrom<IncomingPacket<'a>> for UserauthRequest<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::UserauthRequest {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: username,
            next,
        } = <&[u8]>::decode(packet.payload)?;
        let Decoded {
            value: service,
            next,
        } = <&[u8]>::decode(next)?;
        let Decoded {
            value: method,
            next: method_specific_data,
        } = AuthenticationMethod::decode(next)?;

        Ok(Self {
            username,
            service,
            method,
            method_specific_data,
        })
    }
}
