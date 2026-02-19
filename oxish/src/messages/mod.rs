use core::str;
use std::borrow::Cow;

use tracing::{debug, warn};

use crate::Error;

mod base;
pub(crate) use base::{Completion, Decode, Decoded, Encode, IncomingPacket, MessageType};
mod channels;
pub(crate) use channels::{
    ChannelClose, ChannelData, ChannelEof, ChannelOpen, ChannelOpenConfirmation,
    ChannelOpenFailure, ChannelRequest, ChannelRequestSuccess, ChannelRequestType, Mode, PtyReq,
};
mod named;
use named::IncomingNameList;
pub(crate) use named::{
    ChannelType, CompressionAlgorithm, EncryptionAlgorithm, ExtensionName, KeyExchangeAlgorithm,
    Language, MacAlgorithm, MethodName, Named, OutgoingNameList, PublicKeyAlgorithm, ServiceName,
};

#[derive(Debug)]
pub(crate) struct Identification<'a> {
    pub(crate) protocol: &'a str,
    pub(crate) software: &'a str,
    pub(crate) comments: &'a str,
}

impl<'a> Identification<'a> {
    pub(crate) fn decode(bytes: &'a [u8]) -> Result<Completion<Decoded<'a, Self>>, Error> {
        let Ok(message) = str::from_utf8(bytes) else {
            return Err(IdentificationError::InvalidUtf8.into());
        };

        let Some((message, next)) = message.split_once("\r\n") else {
            // The maximum length is 255 bytes including CRLF. message excludes
            // the CRLF, so subtract 2.
            return match message.len() > 255 - 2 {
                true => Err(IdentificationError::TooLong.into()),
                false => Ok(Completion::Incomplete(None)),
            };
        };

        let Some(rest) = message.strip_prefix("SSH-") else {
            return Err(IdentificationError::NoSsh.into());
        };

        let Some((protocol, rest)) = rest.split_once('-') else {
            return Err(IdentificationError::NoVersion.into());
        };

        let (software, comments) = match rest.split_once(' ') {
            Some((software, comments)) => (software, comments),
            None => (rest, ""),
        };

        let out = Self {
            protocol,
            software,
            comments,
        };

        Ok(Completion::Complete(Decoded {
            value: out,
            next: next.as_bytes(),
        }))
    }
}

impl Encode for Identification<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"SSH-");
        buf.extend_from_slice(self.protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(self.software.as_bytes());
        if !self.comments.is_empty() {
            buf.push(b' ');
            buf.extend_from_slice(self.comments.as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
    }
}

#[derive(Debug)]
pub(crate) struct KeyExchangeInit<'a> {
    cookie: [u8; 16],
    pub(crate) key_exchange_algorithms: Vec<KeyExchangeAlgorithm<'a>>,
    pub(crate) server_host_key_algorithms: Vec<PublicKeyAlgorithm<'a>>,
    pub(crate) encryption_algorithms_client_to_server: Vec<EncryptionAlgorithm<'a>>,
    pub(crate) encryption_algorithms_server_to_client: Vec<EncryptionAlgorithm<'a>>,
    pub(crate) mac_algorithms_client_to_server: Vec<MacAlgorithm<'a>>,
    pub(crate) mac_algorithms_server_to_client: Vec<MacAlgorithm<'a>>,
    pub(crate) compression_algorithms_client_to_server: Vec<CompressionAlgorithm<'a>>,
    pub(crate) compression_algorithms_server_to_client: Vec<CompressionAlgorithm<'a>>,
    pub(crate) languages_client_to_server: Vec<Language<'a>>,
    pub(crate) languages_server_to_client: Vec<Language<'a>>,
    first_kex_packet_follows: bool,
    extended: u32,
}

impl KeyExchangeInit<'static> {
    pub(crate) fn new(cookie: [u8; 16]) -> Result<Self, Error> {
        Ok(Self {
            cookie,
            key_exchange_algorithms: vec![KeyExchangeAlgorithm::Curve25519Sha256],
            server_host_key_algorithms: vec![PublicKeyAlgorithm::Ed25519],
            encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::Aes128Ctr],
            encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::Aes128Ctr],
            mac_algorithms_client_to_server: vec![MacAlgorithm::HmacSha2256],
            mac_algorithms_server_to_client: vec![MacAlgorithm::HmacSha2256],
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::None],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::None],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            extended: 0,
        })
    }
}

impl<'a> TryFrom<IncomingPacket<'a>> for KeyExchangeInit<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::KeyExchangeInit {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: cookie,
            next,
        } = <[u8; 16]>::decode(packet.payload)?;

        let Decoded {
            value: key_exchange_algorithms,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: server_host_key_algorithms,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: encryption_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: encryption_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: mac_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: mac_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: compression_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: compression_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: languages_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: languages_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: first_kex_packet_follows,
            next,
        } = u8::decode(next)?;

        let Decoded {
            value: extended,
            next,
        } = u32::decode(next)?;

        let value = Self {
            cookie,
            key_exchange_algorithms: key_exchange_algorithms.0,
            server_host_key_algorithms: server_host_key_algorithms.0,
            encryption_algorithms_client_to_server: encryption_algorithms_client_to_server.0,
            encryption_algorithms_server_to_client: encryption_algorithms_server_to_client.0,
            mac_algorithms_client_to_server: mac_algorithms_client_to_server.0,
            mac_algorithms_server_to_client: mac_algorithms_server_to_client.0,
            compression_algorithms_client_to_server: compression_algorithms_client_to_server.0,
            compression_algorithms_server_to_client: compression_algorithms_server_to_client.0,
            languages_client_to_server: languages_client_to_server.0,
            languages_server_to_client: languages_server_to_client.0,
            first_kex_packet_follows: first_kex_packet_follows != 0,
            extended,
        };

        if !next.is_empty() {
            debug!(bytes = ?next, "unexpected trailing bytes");
            return Err(Error::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(value)
    }
}

impl Encode for KeyExchangeInit<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::KeyExchangeInit.encode(buf);
        buf.extend_from_slice(&self.cookie);
        OutgoingNameList(&self.key_exchange_algorithms).encode(buf);
        OutgoingNameList(&self.server_host_key_algorithms).encode(buf);
        OutgoingNameList(&self.encryption_algorithms_client_to_server).encode(buf);
        OutgoingNameList(&self.encryption_algorithms_server_to_client).encode(buf);
        OutgoingNameList(&self.mac_algorithms_client_to_server).encode(buf);
        OutgoingNameList(&self.mac_algorithms_server_to_client).encode(buf);
        OutgoingNameList(&self.compression_algorithms_client_to_server).encode(buf);
        OutgoingNameList(&self.compression_algorithms_server_to_client).encode(buf);
        OutgoingNameList(&self.languages_client_to_server).encode(buf);
        OutgoingNameList(&self.languages_server_to_client).encode(buf);
        buf.push(if self.first_kex_packet_follows { 1 } else { 0 });
        buf.extend_from_slice(&self.extended.to_be_bytes());
    }
}

#[derive(Debug)]
pub(crate) struct NewKeys;

impl<'a> TryFrom<IncomingPacket<'a>> for NewKeys {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::NewKeys {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        if !packet.payload.is_empty() {
            debug!(bytes = ?packet.payload, "unexpected trailing bytes");
            return Err(Error::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Self)
    }
}

impl Encode for NewKeys {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::NewKeys.encode(buf);
    }
}

#[derive(Debug)]
pub(crate) struct ExtInfo<'a> {
    pub(crate) extensions: Vec<(ExtensionName<'a>, &'a dyn Encode)>,
}

impl Encode for ExtInfo<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::ExtInfo.encode(buf);
        (self.extensions.len() as u32).encode(buf);
        for (name, value) in &self.extensions {
            name.encode(buf);
            value.encode(buf);
        }
    }
}

#[derive(Debug)]
pub(crate) struct UserAuthRequest<'a> {
    pub(crate) user_name: &'a str,
    pub(crate) service_name: ServiceName<'a>,
    pub(crate) method: Method<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for UserAuthRequest<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::UserAuthRequest {
            return Err(Error::InvalidPacket("expected user auth request packet"));
        }

        let Decoded {
            value: user_name,
            next,
        } = <&[u8]>::decode(packet.payload)?;
        let user_name = str::from_utf8(user_name)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in user name"))?;

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
                    return Err(Error::InvalidPacket(
                        "trailing bytes in public key auth request",
                    ));
                }

                Method::PublicKey(public_key)
            }
            MethodName::None => {
                if !next.is_empty() {
                    return Err(Error::InvalidPacket(
                        "unexpected data after none auth method",
                    ));
                }
                Method::None
            }
            _ => {
                warn!(method = ?method_name, "unsupported authentication method");
                return Err(Error::InvalidPacket("unsupported authentication method"));
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
pub(crate) enum Method<'a> {
    PublicKey(PublicKey<'a>),
    None,
}

#[derive(Debug)]
pub(crate) struct PublicKey<'a> {
    pub(crate) algorithm: PublicKeyAlgorithm<'a>,
    pub(crate) key_blob: &'a [u8],
    pub(crate) signature: Option<Signature<'a>>,
}

impl<'a> Decode<'a> for PublicKey<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
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
                return Err(Error::InvalidPacket(
                    "trailing bytes in public key auth without signature",
                ))
            }
            (true, _) => {
                let Decoded {
                    value: signature,
                    next,
                } = Signature::decode(next)?;

                if !next.is_empty() {
                    return Err(Error::InvalidPacket(
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
pub(crate) struct Signature<'a> {
    pub(crate) algorithm: PublicKeyAlgorithm<'a>,
    pub(crate) signature_blob: &'a [u8],
}

impl<'a> Decode<'a> for Signature<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded { value: input, next } = <&[u8]>::decode(input)?;
        if !next.is_empty() {
            return Err(Error::InvalidPacket("extra data in ECDSA signature data"));
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
            return Err(Error::InvalidPacket("extra data in ECDSA signature blob"));
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
pub(crate) struct UserAuthFailure<'a> {
    pub(crate) can_continue: &'a [MethodName<'a>],
    pub(crate) partial_success: bool,
}

impl Encode for UserAuthFailure<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::UserAuthFailure.encode(buf);
        OutgoingNameList(self.can_continue).encode(buf);
        self.partial_success.encode(buf);
    }
}

#[derive(Debug)]
pub(crate) struct UserAuthPkOk<'a> {
    pub(crate) algorithm: PublicKeyAlgorithm<'a>,
    pub(crate) key_blob: Cow<'a, [u8]>,
}

impl Encode for UserAuthPkOk<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::UserAuthPkOk.encode(buf);
        self.algorithm.encode(buf);
        self.key_blob.encode(buf);
    }
}

pub(crate) struct SignatureData<'a> {
    pub(crate) session_id: &'a [u8],
    pub(crate) user_name: &'a str,
    pub(crate) service_name: ServiceName<'a>,
    pub(crate) algorithm: PublicKeyAlgorithm<'a>,
    pub(crate) public_key: &'a [u8],
}

impl<'a> SignatureData<'a> {
    /// Build the data that the client signs for public key authentication (RFC 4252 Section 7)
    pub(crate) fn encode(&self) -> Vec<u8> {
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
pub(crate) struct ServiceAccept<'a> {
    pub(crate) service_name: ServiceName<'a>,
}

impl Encode for ServiceAccept<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::ServiceAccept.encode(buf);
        self.service_name.encode(buf);
    }
}

#[derive(Debug)]
pub(crate) struct ServiceRequest<'a> {
    pub(crate) service_name: ServiceName<'a>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ServiceRequest<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ServiceRequest {
            return Err(Error::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: service_name,
            next,
        } = ServiceName::decode(packet.payload)?;
        if !next.is_empty() {
            return Err(Error::InvalidPacket("extra data in service request"));
        }

        Ok(ServiceRequest { service_name })
    }
}

#[derive(Debug)]
pub(crate) struct Disconnect<'a> {
    pub(crate) reason_code: DisconnectReason,
    pub(crate) description: &'a str,
}

impl<'a> TryFrom<IncomingPacket<'a>> for Disconnect<'a> {
    type Error = Error;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::Disconnect {
            return Err(Error::InvalidPacket("expected disconnect packet"));
        }

        let Decoded {
            value: reason_code,
            next,
        } = u32::decode(packet.payload)?;

        let Decoded {
            value: description,
            next,
        } = <&[u8]>::decode(next)?;

        let description = str::from_utf8(description)
            .map_err(|_| Error::InvalidPacket("invalid UTF-8 in disconnect description"))?;

        let Decoded {
            value: _, // language tag
            next,
        } = <&[u8]>::decode(next)?;

        if !next.is_empty() {
            return Err(Error::InvalidPacket("extra data in disconnect packet"));
        }

        Ok(Disconnect {
            reason_code: DisconnectReason::try_from(reason_code)?,
            description,
        })
    }
}

impl Encode for Disconnect<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::Disconnect.encode(buf);
        (self.reason_code as u32).encode(buf);
        self.description.as_bytes().encode(buf);
        "en-US".as_bytes().encode(buf);
    }
}

#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum DisconnectReason {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

impl TryFrom<u32> for DisconnectReason {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::HostNotAllowedToConnect,
            2 => Self::ProtocolError,
            3 => Self::KeyExchangeFailed,
            4 => Self::Reserved,
            5 => Self::MacError,
            6 => Self::CompressionError,
            7 => Self::ServiceNotAvailable,
            8 => Self::ProtocolVersionNotSupported,
            9 => Self::HostKeyNotVerifiable,
            10 => Self::ConnectionLost,
            11 => Self::ByApplication,
            12 => Self::TooManyConnections,
            13 => Self::AuthCancelledByUser,
            14 => Self::NoMoreAuthMethodsAvailable,
            15 => Self::IllegalUserName,
            _ => return Err(Error::InvalidPacket("unknown disconnect reason code")),
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum IdentificationError {
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

pub(crate) const PROTOCOL: &str = "2.0";
