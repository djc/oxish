use core::str;
use std::borrow::Cow;

use tracing::warn;

use crate::{
    ProtoError,
    base::{Decode, Decoded, Encode, IncomingPacket, MessageType},
    named::{MethodName, OutgoingNameList, PublicKeyAlgorithm, ServiceName},
};

/// The `SSH_MSG_USERAUTH_REQUEST` message
///
/// Sent by the client to start or continue authentication.
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-5>.
#[derive(Debug)]
pub struct UserAuthRequest<'a> {
    /// The user name to authenticate as
    pub user_name: &'a str,
    /// The service to start after authentication succeeds
    pub service_name: ServiceName<'a>,
    /// The authentication method and its method-specific data
    pub method: Method<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for UserAuthRequest<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::UserAuthRequest {
            return Err(ProtoError::InvalidPacket(
                "expected user auth request packet",
            ));
        }

        let Decoded {
            value: user_name,
            next,
        } = <&[u8]>::decode(packet.payload)?;
        let user_name = str::from_utf8(user_name)
            .map_err(|_| ProtoError::InvalidPacket("invalid UTF-8 in user name"))?;

        let Decoded {
            value: service_name,
            next,
        } = ServiceName::decode(next)?;

        let Decoded {
            value: method_name,
            next,
        } = MethodName::decode(next)?;

        let method = match method_name {
            MethodName::PublicKey => {
                let Decoded {
                    value: public_key,
                    next,
                } = PublicKey::decode(next)?;

                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "trailing bytes in public key auth request",
                    ));
                }

                Method::PublicKey(public_key)
            }
            MethodName::None => {
                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "unexpected data after none auth method",
                    ));
                }
                Method::None
            }
            _ => {
                warn!(method = ?method_name, "unsupported authentication method");
                return Err(ProtoError::InvalidPacket(
                    "unsupported authentication method",
                ));
            }
        };

        Ok(UserAuthRequest {
            user_name,
            service_name,
            method,
        })
    }
}

/// Authentication method data from a [`UserAuthRequest`]
#[derive(Debug)]
pub enum Method<'a> {
    /// The `publickey` method
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
    PublicKey(PublicKey<'a>),
    /// The `none` method
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4252#section-5.2>.
    None,
}

/// Method-specific data for `publickey` authentication
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
#[derive(Debug)]
pub struct PublicKey<'a> {
    /// The public key algorithm name
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The public key blob, encoded per its algorithm
    pub key_blob: &'a [u8],
    /// The signature proving possession of the private key, if present
    pub signature: Option<Signature<'a>>,
}

impl<'a> Decode<'a> for PublicKey<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded {
            value: has_signature,
            next,
        } = bool::decode(input)?;

        let Decoded {
            value: algorithm,
            next,
        } = PublicKeyAlgorithm::decode(next)?;

        let Decoded {
            value: key_blob,
            next,
        } = <&[u8]>::decode(next)?;

        let (signature, next) = match (has_signature, next.is_empty()) {
            (false, true) => (None, next),
            (false, false) => {
                return Err(ProtoError::InvalidPacket(
                    "trailing bytes in public key auth without signature",
                ));
            }
            (true, _) => {
                let Decoded {
                    value: signature,
                    next,
                } = Signature::decode(next)?;

                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "trailing bytes in public key auth with signature",
                    ));
                }

                (Some(signature), next)
            }
        };

        Ok(Decoded {
            value: PublicKey {
                algorithm,
                key_blob,
                signature,
            },
            next,
        })
    }
}

/// A signature over the [`SignatureData`] in a `publickey` authentication request
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
#[derive(Debug)]
pub struct Signature<'a> {
    /// The public key algorithm used to produce the signature
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The raw signature bytes
    pub signature_blob: &'a [u8],
}

impl<'a> Decode<'a> for Signature<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: input, next } = <&[u8]>::decode(input)?;
        if !next.is_empty() {
            return Err(ProtoError::InvalidPacket(
                "extra data in ECDSA signature data",
            ));
        }

        let Decoded {
            value: algorithm,
            next,
        } = PublicKeyAlgorithm::decode(input)?;

        let Decoded {
            value: signature_blob,
            next,
        } = <&[u8]>::decode(next)?;

        if !next.is_empty() {
            return Err(ProtoError::InvalidPacket(
                "extra data in ECDSA signature blob",
            ));
        }

        Ok(Decoded {
            value: Signature {
                algorithm,
                signature_blob,
            },
            next,
        })
    }
}

/// The `SSH_MSG_USERAUTH_FAILURE` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-5.1>.
#[derive(Debug)]
pub struct UserAuthFailure<'a> {
    /// Authentication methods that may productively continue the exchange
    pub can_continue: &'a [MethodName<'a>],
    /// Whether the rejected request was itself successful
    pub partial_success: bool,
}

impl Encode for UserAuthFailure<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::UserAuthFailure.encode(buf);
        OutgoingNameList(self.can_continue).encode(buf);
        self.partial_success.encode(buf);
    }
}

/// The `SSH_MSG_USERAUTH_PK_OK` message
///
/// Confirms that the given public key would be acceptable for authentication.
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
#[derive(Debug)]
pub struct UserAuthPkOk<'a> {
    /// The public key algorithm name from the request
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The public key blob from the request
    pub key_blob: Cow<'a, [u8]>,
}

impl Encode for UserAuthPkOk<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::UserAuthPkOk.encode(buf);
        self.algorithm.encode(buf);
        self.key_blob.encode(buf);
    }
}

/// The data signed by the client for `publickey` authentication
///
/// See <https://www.rfc-editor.org/rfc/rfc4252#section-7>.
pub struct SignatureData<'a> {
    /// The session identifier from the initial key exchange
    pub session_id: &'a [u8],
    /// The user name from the authentication request
    pub user_name: &'a str,
    /// The service name from the authentication request
    pub service_name: ServiceName<'a>,
    /// The public key algorithm name
    pub algorithm: PublicKeyAlgorithm<'a>,
    /// The public key blob
    pub public_key: &'a [u8],
}

impl<'a> SignatureData<'a> {
    /// Build the data that the client signs for public key authentication (RFC 4252 Section 7)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.session_id.encode(&mut buf);
        MessageType::UserAuthRequest.encode(&mut buf);
        self.user_name.as_bytes().encode(&mut buf);
        self.service_name.encode(&mut buf);
        MethodName::PublicKey.encode(&mut buf);
        true.encode(&mut buf);
        self.algorithm.encode(&mut buf);
        self.public_key.encode(&mut buf);
        buf
    }
}

/// The `SSH_MSG_SERVICE_ACCEPT` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-10>.
#[derive(Debug)]
pub struct ServiceAccept<'a> {
    /// The service name from the accepted request
    pub service_name: ServiceName<'a>,
}

impl Encode for ServiceAccept<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::ServiceAccept.encode(buf);
        self.service_name.encode(buf);
    }
}

/// The `SSH_MSG_SERVICE_REQUEST` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-10>.
#[derive(Debug)]
pub struct ServiceRequest<'a> {
    /// The name of the service to start
    pub service_name: ServiceName<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ServiceRequest<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ServiceRequest {
            return Err(ProtoError::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: service_name,
            next,
        } = ServiceName::decode(packet.payload)?;
        if !next.is_empty() {
            return Err(ProtoError::InvalidPacket("extra data in service request"));
        }

        Ok(ServiceRequest { service_name })
    }
}
