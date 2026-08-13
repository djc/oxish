//! Sans-IO implementation of the SSH transport layer protocol
//!
//! Message types and state machines for the SSH protocol as specified in RFC 4250 through 4254 and
//! related documents.

#![warn(missing_docs, unsafe_code)]

use core::{fmt, str};

use thiserror::Error;

/// User authentication protocol messages (RFC 4252)
pub mod auth;
/// Connection protocol channel messages (RFC 4254)
pub mod channels;
/// Traits abstracting over cryptographic primitives and key derivation
pub mod crypto;
use crypto::CryptoError;
mod host_keys;
pub use host_keys::{HostKeys, ServerHostKey, SessionHostKey};
mod io;
pub use io::{Encoder, ReadState, WriteState};
/// Key exchange messages and negotiation (RFC 4253 section 7, RFC 5656)
pub mod key_exchange;
/// Named algorithms, services and methods, and name-list encoding (RFC 4251 section 5)
pub mod named;
use named::PublicKeyAlgorithm;

/// Protocol version exchange identification string
///
/// Exchanged by both sides before any packets are sent, in the form
/// `SSH-protoversion-softwareversion SP comments CR LF`.
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-4.2>.
#[derive(Debug)]
pub struct Identification<'a> {
    /// The protocol version, `2.0` for this version of the protocol
    pub protocol: &'a str,
    /// The software name and version of the implementation
    pub software: &'a str,
    /// Optional comments, empty if not present
    pub comments: &'a str,
}

impl<'a> Identification<'a> {
    /// Decode an identification string from the start of `bytes`
    pub fn decode(bytes: &'a [u8]) -> Result<Completion<Decoded<'a, Self>>, ProtoError> {
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
        let Self {
            protocol,
            software,
            comments,
        } = self;

        buf.extend_from_slice(b"SSH-");
        buf.extend_from_slice(protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(software.as_bytes());
        if !self.comments.is_empty() {
            buf.push(b' ');
            buf.extend_from_slice(comments.as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
    }
}

/// The `SSH_MSG_DISCONNECT` message
///
/// Terminates the connection; no party may send or receive data after it.
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-11.1>.
#[derive(Debug)]
pub struct Disconnect<'a> {
    /// Machine-readable reason for the disconnect
    pub reason_code: DisconnectReason,
    /// Human-readable description of the reason
    pub description: &'a str,
}

impl<'a> TryFrom<IncomingPacket<'a>> for Disconnect<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::Disconnect {
            return Err(ProtoError::InvalidPacket("expected disconnect packet"));
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
            .map_err(|_| ProtoError::InvalidPacket("invalid UTF-8 in disconnect description"))?;

        let Decoded {
            value: _, // language tag
            next,
        } = <&[u8]>::decode(next)?;

        if !next.is_empty() {
            return Err(ProtoError::InvalidPacket("extra data in disconnect packet"));
        }

        Ok(Disconnect {
            reason_code: DisconnectReason::try_from(reason_code)?,
            description,
        })
    }
}

impl Encode for Disconnect<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self {
            reason_code,
            description,
        } = self;

        MessageType::Disconnect.encode(buf);
        (*reason_code as u32).encode(buf);
        description.as_bytes().encode(buf);
        "en-US".as_bytes().encode(buf);
    }
}

/// Reason codes for the `SSH_MSG_DISCONNECT` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-11.1> for the semantics and
/// <https://www.rfc-editor.org/rfc/rfc4250#section-4.2.2> for the registry.
#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum DisconnectReason {
    /// `SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT`
    HostNotAllowedToConnect = 1,
    /// `SSH_DISCONNECT_PROTOCOL_ERROR`
    ProtocolError = 2,
    /// `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`
    KeyExchangeFailed = 3,
    /// `SSH_DISCONNECT_RESERVED`
    Reserved = 4,
    /// `SSH_DISCONNECT_MAC_ERROR`
    MacError = 5,
    /// `SSH_DISCONNECT_COMPRESSION_ERROR`
    CompressionError = 6,
    /// `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE`
    ServiceNotAvailable = 7,
    /// `SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED`
    ProtocolVersionNotSupported = 8,
    /// `SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE`
    HostKeyNotVerifiable = 9,
    /// `SSH_DISCONNECT_CONNECTION_LOST`
    ConnectionLost = 10,
    /// `SSH_DISCONNECT_BY_APPLICATION`
    ByApplication = 11,
    /// `SSH_DISCONNECT_TOO_MANY_CONNECTIONS`
    TooManyConnections = 12,
    /// `SSH_DISCONNECT_AUTH_CANCELLED_BY_USER`
    AuthCancelledByUser = 13,
    /// `SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE`
    NoMoreAuthMethodsAvailable = 14,
    /// `SSH_DISCONNECT_ILLEGAL_USER_NAME`
    IllegalUserName = 15,
}

impl TryFrom<u32> for DisconnectReason {
    type Error = ProtoError;

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
            _ => return Err(ProtoError::InvalidPacket("unknown disconnect reason code")),
        })
    }
}

/// A decrypted incoming packet, before message-specific decoding
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-6> for the packet format.
pub struct IncomingPacket<'a> {
    pub(crate) sequence_number: u32,
    /// The message type from the first byte of the payload
    pub message_type: MessageType,
    pub(crate) payload: &'a [u8],
}

impl fmt::Debug for IncomingPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            sequence_number,
            message_type,
            payload: _,
        } = self;

        f.debug_struct("IncomingPacket")
            .field("sequence_number", sequence_number)
            .field("message_type", message_type)
            .finish_non_exhaustive()
    }
}

/// SSH message numbers, sent as the first byte of each packet payload
///
/// See <https://www.rfc-editor.org/rfc/rfc4250#section-4.1> for the registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageType {
    /// `SSH_MSG_DISCONNECT` (RFC 4253 section 11.1)
    Disconnect,
    /// `SSH_MSG_IGNORE` (RFC 4253 section 11.2)
    Ignore,
    /// `SSH_MSG_UNIMPLEMENTED` (RFC 4253 section 11.4)
    Unimplemented,
    /// `SSH_MSG_DEBUG` (RFC 4253 section 11.3)
    Debug,
    /// `SSH_MSG_SERVICE_REQUEST` (RFC 4253 section 10)
    ServiceRequest,
    /// `SSH_MSG_SERVICE_ACCEPT` (RFC 4253 section 10)
    ServiceAccept,
    /// `SSH_MSG_EXT_INFO` (RFC 8308 section 2.3)
    ExtInfo,
    /// `SSH_MSG_KEXINIT` (RFC 4253 section 7.1)
    KeyExchangeInit,
    /// `SSH_MSG_NEWKEYS` (RFC 4253 section 7.3)
    NewKeys,
    /// `SSH_MSG_KEX_ECDH_INIT` (RFC 5656 section 4)
    KeyExchangeEcdhInit,
    /// `SSH_MSG_KEX_ECDH_REPLY` (RFC 5656 section 4)
    KeyExchangeEcdhReply,
    /// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 section 5)
    UserAuthRequest,
    /// `SSH_MSG_USERAUTH_FAILURE` (RFC 4252 section 5.1)
    UserAuthFailure,
    /// `SSH_MSG_USERAUTH_SUCCESS` (RFC 4252 section 5.1)
    UserAuthSuccess,
    /// `SSH_MSG_USERAUTH_BANNER` (RFC 4252 section 5.4)
    UserAuthBanner,
    /// `SSH_MSG_USERAUTH_PK_OK` (RFC 4252 section 7)
    UserAuthPkOk,
    /// `SSH_MSG_GLOBAL_REQUEST` (RFC 4254 section 4)
    GlobalRequest,
    /// `SSH_MSG_REQUEST_SUCCESS` (RFC 4254 section 4)
    RequestSuccess,
    /// `SSH_MSG_REQUEST_FAILURE` (RFC 4254 section 4)
    RequestFailure,
    /// `SSH_MSG_CHANNEL_OPEN` (RFC 4254 section 5.1)
    ChannelOpen,
    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (RFC 4254 section 5.1)
    ChannelOpenConfirmation,
    /// `SSH_MSG_CHANNEL_OPEN_FAILURE` (RFC 4254 section 5.1)
    ChannelOpenFailure,
    /// `SSH_MSG_CHANNEL_WINDOW_ADJUST` (RFC 4254 section 5.2)
    ChannelWindowAdjust,
    /// `SSH_MSG_CHANNEL_DATA` (RFC 4254 section 5.2)
    ChannelData,
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA` (RFC 4254 section 5.2)
    ChannelExtendedData,
    /// `SSH_MSG_CHANNEL_EOF` (RFC 4254 section 5.3)
    ChannelEof,
    /// `SSH_MSG_CHANNEL_CLOSE` (RFC 4254 section 5.3)
    ChannelClose,
    /// `SSH_MSG_CHANNEL_REQUEST` (RFC 4254 section 5.4)
    ChannelRequest,
    /// `SSH_MSG_CHANNEL_SUCCESS` (RFC 4254 section 5.4)
    ChannelSuccess,
    /// `SSH_MSG_CHANNEL_FAILURE` (RFC 4254 section 5.4)
    ChannelFailure,
    /// A message number not known to this implementation
    Unknown(u8),
}

impl Encode for MessageType {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(u8::from(*self));
    }
}

impl<'a> Decode<'a> for MessageType {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value, next } = u8::decode(bytes)?;
        Ok(Decoded {
            value: Self::from(value),
            next,
        })
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Disconnect,
            2 => Self::Ignore,
            3 => Self::Unimplemented,
            4 => Self::Debug,
            5 => Self::ServiceRequest,
            6 => Self::ServiceAccept,
            7 => Self::ExtInfo,
            20 => Self::KeyExchangeInit,
            21 => Self::NewKeys,
            30 => Self::KeyExchangeEcdhInit,
            31 => Self::KeyExchangeEcdhReply,
            50 => Self::UserAuthRequest,
            51 => Self::UserAuthFailure,
            52 => Self::UserAuthSuccess,
            53 => Self::UserAuthBanner,
            60 => Self::UserAuthPkOk,
            80 => Self::GlobalRequest,
            81 => Self::RequestSuccess,
            82 => Self::RequestFailure,
            90 => Self::ChannelOpen,
            91 => Self::ChannelOpenConfirmation,
            92 => Self::ChannelOpenFailure,
            93 => Self::ChannelWindowAdjust,
            94 => Self::ChannelData,
            95 => Self::ChannelExtendedData,
            96 => Self::ChannelEof,
            97 => Self::ChannelClose,
            98 => Self::ChannelRequest,
            99 => Self::ChannelSuccess,
            100 => Self::ChannelFailure,
            value => Self::Unknown(value),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Disconnect => 1,
            MessageType::Ignore => 2,
            MessageType::Unimplemented => 3,
            MessageType::Debug => 4,
            MessageType::ServiceRequest => 5,
            MessageType::ServiceAccept => 6,
            MessageType::ExtInfo => 7,
            MessageType::KeyExchangeInit => 20,
            MessageType::NewKeys => 21,
            MessageType::KeyExchangeEcdhInit => 30,
            MessageType::KeyExchangeEcdhReply => 31,
            MessageType::UserAuthRequest => 50,
            MessageType::UserAuthFailure => 51,
            MessageType::UserAuthSuccess => 52,
            MessageType::UserAuthBanner => 53,
            MessageType::UserAuthPkOk => 60,
            MessageType::GlobalRequest => 80,
            MessageType::RequestSuccess => 81,
            MessageType::RequestFailure => 82,
            MessageType::ChannelOpen => 90,
            MessageType::ChannelOpenConfirmation => 91,
            MessageType::ChannelOpenFailure => 92,
            MessageType::ChannelWindowAdjust => 93,
            MessageType::ChannelData => 94,
            MessageType::ChannelExtendedData => 95,
            MessageType::ChannelEof => 96,
            MessageType::ChannelClose => 97,
            MessageType::ChannelRequest => 98,
            MessageType::ChannelSuccess => 99,
            MessageType::ChannelFailure => 100,
            MessageType::Unknown(value) => value,
        }
    }
}

/// The `packet_length` field at the start of each packet
///
/// Covers `padding_length`, `payload` and `padding`, but not the length field itself or the MAC
/// (<https://www.rfc-editor.org/rfc/rfc4253#section-6>). Decoding rejects lengths beyond
/// [`MAX_PACKET_LEN`].
#[derive(Clone, Copy, Debug)]
pub struct PacketLength(u32);

impl Decode<'_> for PacketLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value, next } = u32::decode(bytes)?;

        if value > MAX_PACKET_LEN {
            return Err(ProtoError::InvalidPacket("packet too large"));
        }

        Ok(Decoded {
            value: Self(value),
            next,
        })
    }
}

impl From<PacketLength> for usize {
    fn from(len: PacketLength) -> Self {
        len.0 as Self
    }
}

impl From<PacketLength> for u32 {
    fn from(len: PacketLength) -> Self {
        len.0
    }
}

/// The `padding_length` field of a packet
///
/// There must be at least 4 bytes of padding.
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-6>.
#[derive(Debug)]
pub struct PaddingLength(pub(crate) u8);

impl Decode<'_> for PaddingLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value, next } = u8::decode(bytes)?;
        if value < 4 {
            return Err(ProtoError::InvalidPacket("padding too short"));
        }

        Ok(Decoded {
            value: Self(value),
            next,
        })
    }
}

/// The `SSH_MSG_IGNORE` message
///
/// Must be ignored by the receiver; can be used as a countermeasure against traffic analysis.
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-11.2>.
#[derive(Debug, Default)]
pub struct Ignore<'a>(pub &'a [u8]);

impl Encode for Ignore<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self(payload) = self;
        MessageType::Ignore.encode(buf);
        payload.encode(buf);
    }
}

/// The `SSH_MSG_GLOBAL_REQUEST` message
///
/// Requests that apply to the connection as a whole rather than to a single channel, such as
/// the client's `keepalive@openssh.com` liveness probe.
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-4>.
#[derive(Debug)]
pub struct GlobalRequest<'a> {
    /// The name of the request
    pub name: &'a [u8],
    /// Whether the sender wants a `SSH_MSG_REQUEST_SUCCESS` or `SSH_MSG_REQUEST_FAILURE` reply
    pub want_reply: bool,
}

impl<'a> TryFrom<IncomingPacket<'a>> for GlobalRequest<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::GlobalRequest {
            return Err(ProtoError::InvalidPacket("expected global request packet"));
        }

        let Decoded { value: name, next } = <&[u8]>::decode(packet.payload)?;
        // Request-specific data follows `want_reply`, but we don't act on any request, so
        // parsing the boolean is enough to know whether the sender expects a reply.
        let Decoded {
            value: want_reply, ..
        } = bool::decode(next)?;

        Ok(Self { name, want_reply })
    }
}

impl<'a> Decode<'a> for &'a [u8] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let len = u32::decode(bytes)?;
        let Some(value) = len.next.get(..len.value as usize) else {
            return Err(ProtoError::Incomplete(Some(
                len.value as usize - len.next.len(),
            )));
        };

        let Some(next) = len.next.get(len.value as usize..) else {
            return Err(ProtoError::Unreachable(
                "unable to extract rest after slice",
            ));
        };

        Ok(Decoded { value, next })
    }
}

impl Encode for [u8] {
    fn encode(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode(buf);
        buf.extend_from_slice(self);
    }
}

impl Decode<'_> for bool {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        <[u8; 1]>::decode(bytes).map(|decoded| Decoded {
            value: decoded.value[0] != 0,
            next: decoded.next,
        })
    }
}

impl Encode for bool {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(if *self { 1 } else { 0 });
    }
}

impl Decode<'_> for u32 {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        <[u8; 4]>::decode(bytes).map(|decoded| Decoded {
            value: Self::from_be_bytes(decoded.value),
            next: decoded.next,
        })
    }
}

impl Encode for u32 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl Decode<'_> for u64 {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        <[u8; 8]>::decode(bytes).map(|decoded| Decoded {
            value: Self::from_be_bytes(decoded.value),
            next: decoded.next,
        })
    }
}

impl Encode for u64 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl<'a, const N: usize> Decode<'a> for [u8; N] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        match bytes.split_first_chunk::<N>() {
            Some((&value, next)) => Ok(Decoded { value, next }),
            None => Err(ProtoError::Incomplete(Some(N - bytes.len()))),
        }
    }
}

impl<'a> Decode<'a> for u8 {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        match bytes.split_first() {
            Some((&value, next)) => Ok(Decoded { value, next }),
            None => Err(ProtoError::Incomplete(Some(1))),
        }
    }
}

/// The result of decoding from input that may not yet hold a full value
pub enum Completion<T> {
    /// A complete value was decoded
    Complete(T),
    /// Not enough input was available to produce a value
    ///
    /// The payload, if known, is the number of additional bytes needed beyond
    /// the end of the current input (as in `required - available`).
    Incomplete(Option<usize>),
}

/// A type that can be encoded into the SSH wire format
///
/// Data type representations are defined in <https://www.rfc-editor.org/rfc/rfc4251#section-5>.
pub trait Encode: Send + Sync {
    /// Append the wire representation of `self` to `buf`
    fn encode(&self, buf: &mut Vec<u8>);
}

/// A type that can be decoded from the SSH wire format
///
/// Data type representations are defined in <https://www.rfc-editor.org/rfc/rfc4251#section-5>.
pub trait Decode<'a>: Sized {
    /// Decode a value from the start of `bytes`
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError>;
}

/// A decoded value together with the remaining input
#[derive(Debug)]
pub struct Decoded<'a, T> {
    /// The decoded value
    pub value: T,
    /// The input remaining after the decoded value
    pub next: &'a [u8],
}

/// An error in the SSH protocol layer
#[derive(Debug, Error)]
pub enum ProtoError {
    /// A cryptographic operation failed
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// The peer's identification string was malformed
    #[error("failed to parse identification: {0}")]
    Identification(#[from] IdentificationError),
    /// An I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The input was too short to decode a complete message
    ///
    /// The payload, if known, is the number of additional bytes needed beyond the end of the
    /// current input (`required - available`).
    #[error("incomplete message: {0:?}")]
    Incomplete(Option<usize>),
    /// An unknown or unsupported channel type was requested
    #[error("invalid packet: {0}")]
    InvalidChannelType(String),
    /// A host key file could not be used; the payload describes why
    #[error("invalid host key: {0}")]
    InvalidHostKey(&'static str),
    /// A packet violated the protocol; the payload describes how
    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),
    /// No host keys were found or specified
    #[error("no host keys found or specified")]
    NoHostKeys,
    /// Algorithm negotiation failed for the named algorithm category
    #[error("no common {0} algorithms")]
    NoCommonAlgorithm(&'static str),
    /// Too many host keys were specified
    #[error("too many host keys specified")]
    TooManyHostKeys,
    /// An internal invariant was violated (this is a bug)
    #[error("unreachable code: {0}")]
    Unreachable(&'static str),
    /// The requested service was not available in the current state
    #[error("service not available: {0}")]
    ServiceNotAvailable(&'static str),
}

/// An error parsing the peer's identification string
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-4.2> for the required format.
#[derive(Debug, Error, PartialEq)]
pub enum IdentificationError {
    /// The identification string contained invalid UTF-8
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    /// The identification string did not start with `SSH-`
    #[error("No SSH prefix")]
    NoSsh,
    /// No protocol version was found after the `SSH-` prefix
    #[error("No version found")]
    NoVersion,
    /// The identification string exceeded the 255-byte maximum length
    #[error("Identification too long")]
    TooLong,
    /// The peer requested a protocol version other than `2.0`
    #[error("Unsupported protocol version")]
    UnsupportedVersion(String),
}

/// Adapter that formats its inner value with `{:#?}` when displayed
pub struct Pretty<T>(pub T);

impl<T: fmt::Debug> fmt::Display for Pretty<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

/// Maximum packet length in bytes
///
/// Must be at least 35 kB per
/// <https://datatracker.ietf.org/doc/html/rfc4253#section-6.1>.
pub const MAX_PACKET_LEN: u32 = 64 * 1024;

/// The protocol version implemented by this crate
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-4.2>.
pub const PROTOCOL: &str = "2.0";
