use core::{fmt, ops::Deref, time::Duration};
use std::{borrow::Cow, ffi::CStr, io, path::PathBuf, str};

use proto::{
    Disconnect, DisconnectReason, IncomingPacket, MessageType, ProtoError, WriteState,
    auth::{
        AuthorizedKey, Method, ServiceAccept, ServiceRequest, SignatureData, UserAuthFailure,
        UserAuthPkOk, UserAuthRequest,
    },
    crypto::{CryptoError, CryptoProvider, Digest},
    named::{MethodName, PublicKeyAlgorithm, ServiceName},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::spawn_blocking,
    time::timeout,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{Connection, Error, receive};

#[instrument(name = "authentication", skip(session_id, conn, store, provider), fields(addr = %conn.addr))]
pub(crate) async fn authenticate<T: AsyncRead + AsyncWrite + Unpin>(
    session_id: &Digest,
    conn: &mut Connection<T>,
    store: &dyn UserStore,
    provider: &dyn CryptoProvider,
) -> anyhow::Result<User> {
    let mut state = AuthenticationState::default();
    let future = async {
        loop {
            let packet = receive(&mut conn.stream, &mut conn.read).await?;
            let handled = state
                .handle(packet, session_id, &mut conn.write, store, provider)
                .await;

            match (handled, conn.flush().await) {
                (Ok(AuthenticationState::Complete(user)), Ok(())) => return Ok(user),
                (Ok(next), Ok(())) => state = next,
                (Err(error), _) | (_, Err(error)) => return Err(error),
            }
        }
    };

    let (error, disconnect) = match timeout(Duration::from_secs(60), future).await {
        Ok(Ok(user)) => return Ok(user),
        Ok(Err(error)) => {
            let disconnect = match &error {
                Error::Auth(AuthError::TooManyAttempts) => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description: "too many authentication attempts",
                },
                Error::InvalidState(description) => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description,
                },
                Error::InvalidUsername => Disconnect {
                    reason_code: DisconnectReason::IllegalUserName,
                    description: "invalid username",
                },
                Error::Proto(ProtoError::ServiceNotAvailable(description)) => Disconnect {
                    reason_code: DisconnectReason::ServiceNotAvailable,
                    description,
                },
                _ => Disconnect {
                    reason_code: DisconnectReason::ByApplication,
                    description: "authentication failed",
                },
            };

            (error, disconnect)
        }
        Err(_) => (
            Error::Io(io::Error::from(io::ErrorKind::TimedOut)),
            Disconnect {
                reason_code: DisconnectReason::ByApplication,
                description: "authentication timed out",
            },
        ),
    };

    conn.write.encode(&disconnect)?;
    let _ = timeout(Duration::from_secs(1), conn.flush()).await;
    Err(error.into())
}

#[derive(Default)]
enum AuthenticationState {
    #[default]
    AwaitServiceRequest,
    AwaitAuthRequest {
        cached: Option<CachedUser>,
        attempts: u8,
    },
    Complete(User),
}

impl AuthenticationState {
    pub(crate) async fn handle(
        self,
        packet: IncomingPacket<'_>,
        session_id: &Digest,
        write: &mut WriteState,
        store: &dyn UserStore,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, Error> {
        match (self, packet.message_type) {
            (state, MessageType::Ignore | MessageType::Debug) => Ok(state),
            (_, MessageType::Disconnect) => Err(AuthError::Canceled.into()),
            (Self::AwaitServiceRequest, MessageType::ServiceRequest) => {
                match ServiceRequest::try_from(packet)?.service_name {
                    ServiceName::UserAuth => {
                        write.encode(&ServiceAccept {
                            service_name: ServiceName::UserAuth,
                        })?;
                        Ok(Self::AwaitAuthRequest {
                            cached: None,
                            attempts: 6,
                        })
                    }
                    service_name => {
                        error!(?service_name, "unsupported service requested");
                        Err(ProtoError::ServiceNotAvailable(
                            "only user authentication service is supported",
                        )
                        .into())
                    }
                }
            }
            (
                Self::AwaitAuthRequest {
                    mut cached,
                    mut attempts,
                },
                MessageType::UserAuthRequest,
            ) => {
                attempts -= 1;
                if attempts == 0 {
                    error!("too many authentication attempts");
                    return Err(AuthError::TooManyAttempts.into());
                }

                let user_auth_request = UserAuthRequest::try_from(packet)?;
                debug!(?user_auth_request, "received user auth request");
                if user_auth_request.service_name != ServiceName::Connection {
                    error!(
                        service_name = ?user_auth_request.service_name,
                        "unsupported service requested"
                    );

                    return Err(ProtoError::ServiceNotAvailable(
                        "only connection service is supported",
                    )
                    .into());
                }

                let Method::PublicKey(public_key) = user_auth_request.method else {
                    warn!(
                        method = ?user_auth_request.method,
                        "unsupported authentication method requested"
                    );
                    send_auth_failed(write)?;
                    return Ok(Self::AwaitAuthRequest { cached, attempts });
                };

                let user = match &mut cached {
                    Some(user) if &*user.data.name == user_auth_request.user_name => user,
                    _ => {
                        let Ok(name) = Username::try_from(user_auth_request.user_name.to_owned())
                        else {
                            send_auth_failed(write)?;
                            return Ok(Self::AwaitAuthRequest { cached, attempts });
                        };

                        let Some(user) = store.lookup(name) else {
                            send_auth_failed(write)?;
                            return Ok(Self::AwaitAuthRequest { cached, attempts });
                        };

                        let keys = store.keys(&user, provider);
                        cached.insert(CachedUser { data: user, keys })
                    }
                };

                let authorized_key = user.keys.iter().find(|key| key.matches(&public_key));
                let (sig, authorized_key) = match (public_key.signature, authorized_key) {
                    // Signature, authorized key => verify signature
                    (Some(sig), Some(key)) if &sig.algorithm == key.algorithm() => {
                        (sig, key.clone())
                    }
                    // Signature, no authorized key => verify signature against fake key
                    (Some(sig), None) => (
                        sig,
                        match fake_key(&public_key.algorithm, provider) {
                            Ok(key) => key,
                            Err(_) => {
                                warn!(algorithm = ?public_key.algorithm, "unsupported public key algorithm");
                                send_auth_failed(write)?;
                                return Ok(Self::AwaitAuthRequest { cached, attempts });
                            }
                        },
                    ),
                    // Signature, authorized key but mismatched algorithms => fail authentication without verifying signature
                    (Some(_), Some(_)) => {
                        warn!(
                            algorithm = ?public_key.algorithm,
                            "mismatched signature algorithm in authentication request"
                        );
                        send_auth_failed(write)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                    // No signature, authorized key => send pk-ok and wait for signature
                    (None, Some(_)) => {
                        let pk_ok = UserAuthPkOk {
                            algorithm: public_key.algorithm.to_owned(),
                            key_blob: Cow::Owned(public_key.key_blob.to_vec()),
                        };
                        debug!(ok = ?pk_ok, "sending pk-ok for user");
                        write.encode(&pk_ok)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                    // No signature, no authorized key => fail authentication
                    (None, None) => {
                        send_auth_failed(write)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                };

                let message = SignatureData {
                    session_id: session_id.as_ref(),
                    user_name: &user.data.name,
                    service_name: user_auth_request.service_name,
                    algorithm: public_key.algorithm,
                    public_key: public_key.key_blob,
                }
                .encode();

                let signature = match sig.encode() {
                    Ok(signature) => signature,
                    Err(error) => {
                        debug!(%error, "failed to encode signature");
                        send_auth_failed(write)?;
                        return Ok(Self::AwaitAuthRequest { cached, attempts });
                    }
                };

                match spawn_blocking(move || authorized_key.verify(message, signature)).await {
                    Ok(Ok(())) => {
                        let Some(user) = cached else {
                            return Err(ProtoError::Unreachable("must have cached user").into());
                        };

                        info!(user = %user.data.name, "authentication successful");
                        write.encode(&MessageType::UserAuthSuccess)?;
                        Ok(Self::Complete(user.data))
                    }
                    _ => {
                        send_auth_failed(write)?;
                        Ok(Self::AwaitAuthRequest { cached, attempts })
                    }
                }
            }
            (_, _) => {
                error!(
                    message_type = ?packet.message_type,
                    "unexpected packet received during authentication"
                );
                Err(Error::InvalidState(
                    "unexpected packet received during authentication",
                ))
            }
        }
    }
}

/// Build a fake key for the given `algorithm` to mitigate timing attacks
///
/// We want to execute a signature verification even when the user does not have a matching
/// authorized key, so we build a fake key for the requested algorithm and verify the
/// signature against it. This ensures that the response time is consistent regardless of
/// whether the user has a matching authorized key.
fn fake_key(
    algorithm: &PublicKeyAlgorithm<'_>,
    provider: &dyn CryptoProvider,
) -> Result<AuthorizedKey, CryptoError> {
    AuthorizedKey::from_str(
        match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE4MlZd759Tv7GElTKPf1D0FCmDWB9LEkkWyaP3E8T0H/fKyFnA0e0yBm/XpkG9erfxrcgMkAu1CM3e19g9bZWg=",
            PublicKeyAlgorithm::Ed25519 => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDX+GNCeikghR3A2bLB0KmlovqxdC+BUHAfYhYGcUJxA",
            _ => return Err(CryptoError::UnknownAlgorithm),
        },
        provider,
    )
    .ok_or(CryptoError::KeyRejected)
}

/// Encode a `SSH_MSG_USERAUTH_FAILURE` message
fn send_auth_failed(write: &mut WriteState) -> Result<(), ProtoError> {
    write.encode(&UserAuthFailure {
        can_continue: SUPPORTED_METHODS,
        partial_success: false,
    })
}

/// User store that only contains a single user
pub(crate) struct SingleUser(pub(crate) CachedUser);

impl SingleUser {
    #[cfg(test)]
    pub(crate) fn with_keys(data: User, keys: Vec<AuthorizedKey>) -> Self {
        Self(CachedUser { data, keys })
    }
}

impl UserStore for SingleUser {
    fn lookup(&self, name: Username) -> Option<User> {
        match self.0.data.name == name {
            true => Some(self.0.data.clone()),
            false => {
                warn!(
                    requested = %name,
                    authorized = %self.0.data.name,
                    "requested user does not match authorized user",
                );
                None
            }
        }
    }

    fn keys(&self, _: &User, _: &dyn CryptoProvider) -> Vec<AuthorizedKey> {
        self.0.keys.clone()
    }

    fn drop_privileges(&self) -> bool {
        false
    }
}

/// A user store resolves a username to a `User` type containing data used for authentication
pub trait UserStore: Send + Sync + 'static {
    /// Lookup a user by name, returning `None` if the user does not exist or cannot be retrieved
    fn lookup(&self, name: Username) -> Option<User>;

    /// Lookup the authorized keys for a user
    fn keys(&self, user: &User, provider: &dyn CryptoProvider) -> Vec<AuthorizedKey>;

    /// Whether the user store should set the UID of the process to the authenticated user
    fn drop_privileges(&self) -> bool;
}

pub(crate) struct CachedUser {
    pub(crate) data: User,
    pub(crate) keys: Vec<AuthorizedKey>,
}

/// User data as retrieved from the system database
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct User {
    /// The user's name
    pub name: Username,
    /// The user's UID
    pub id: u32,
    /// The user's GID
    pub gid: u32,
    /// The user's home directory
    pub home_dir: PathBuf,
    /// The user's shell
    pub shell: PathBuf,
}

/// A validated username
///
/// Must be valid UTF-8 without any ASCII control characters or slashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Username(String);

impl Username {
    pub(crate) fn nobody() -> Self {
        Self("nobody".to_owned())
    }
}

impl TryFrom<&CStr> for Username {
    type Error = Error;

    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        let Ok(name) = value.to_str() else {
            return Err(Error::InvalidUsername);
        };

        Self::try_from(name.to_owned())
    }
}

impl TryFrom<String> for Username {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.chars().any(|c| c.is_control() || c == '/') {
            true => Err(Error::InvalidUsername),
            false => Ok(Self(value)),
        }
    }
}

impl Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Errors that can occur during authentication
#[derive(Debug, Error)]
pub enum AuthError {
    /// The client canceled the authentication process
    #[error("canceled by the client")]
    Canceled,
    /// Too many authentication attempts for a single connection
    #[error("too many authentication attempts")]
    TooManyAttempts,
}

const SUPPORTED_METHODS: &[MethodName<'_>] = &[MethodName::PublicKey];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_PROVIDER;

    #[test]
    fn parse_fake_keys() {
        fake_key(&PublicKeyAlgorithm::EcdsaSha2Nistp256, DEFAULT_PROVIDER).unwrap();
        fake_key(&PublicKeyAlgorithm::Ed25519, DEFAULT_PROVIDER).unwrap();
    }
}
