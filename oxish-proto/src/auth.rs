use core::str;
use std::borrow::Cow;

use tracing::warn;

use crate::{
    ProtoError,
    base::{Decode, Decoded, Encode, IncomingPacket, MessageType},
    named::{MethodName, OutgoingNameList, PublicKeyAlgorithm, ServiceName},
};

#[derive(Debug)]
pub struct UserAuthRequest<'a> {
    pub user_name: &'a str,
    pub service_name: ServiceName<'a>,
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

#[derive(Debug)]
pub enum Method<'a> {
    PublicKey(PublicKey<'a>),
    None,
}

#[derive(Debug)]
pub struct PublicKey<'a> {
    pub algorithm: PublicKeyAlgorithm<'a>,
    pub key_blob: &'a [u8],
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

#[derive(Debug)]
pub struct Signature<'a> {
    pub algorithm: PublicKeyAlgorithm<'a>,
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

#[derive(Debug)]
pub struct UserAuthFailure<'a> {
    pub can_continue: &'a [MethodName<'a>],
    pub partial_success: bool,
}

impl Encode for UserAuthFailure<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::UserAuthFailure.encode(buf);
        OutgoingNameList(self.can_continue).encode(buf);
        self.partial_success.encode(buf);
    }
}

#[derive(Debug)]
pub struct UserAuthPkOk<'a> {
    pub algorithm: PublicKeyAlgorithm<'a>,
    pub key_blob: Cow<'a, [u8]>,
}

impl Encode for UserAuthPkOk<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::UserAuthPkOk.encode(buf);
        self.algorithm.encode(buf);
        self.key_blob.encode(buf);
    }
}

pub struct SignatureData<'a> {
    pub session_id: &'a [u8],
    pub user_name: &'a str,
    pub service_name: ServiceName<'a>,
    pub algorithm: PublicKeyAlgorithm<'a>,
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

#[derive(Debug)]
pub struct ServiceAccept<'a> {
    pub service_name: ServiceName<'a>,
}

impl Encode for ServiceAccept<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::ServiceAccept.encode(buf);
        self.service_name.encode(buf);
    }
}

#[derive(Debug)]
pub struct ServiceRequest<'a> {
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
