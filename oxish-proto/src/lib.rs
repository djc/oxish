//! Sans-IO implementation of the SSH transport layer protocol
//!
//! Message types and state machines for the SSH protocol as specified in RFC 4250 through 4254 and
//! related documents.

#![warn(missing_docs)]

use core::{fmt, str};

use thiserror::Error;

/// User authentication protocol messages (RFC 4252)
pub mod auth;
mod base;
pub use base::{
    Completion, Decode, Decoded, Disconnect, DisconnectReason, Encode, Ignore, IncomingPacket,
    MessageType, PacketLength, PaddingLength,
};
/// Connection protocol channel messages (RFC 4254)
pub mod channels;
/// Traits abstracting over cryptographic primitives and key derivation
pub mod crypto;
use crypto::CryptoError;
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

/// An error in the SSH protocol layer
#[derive(Debug, Error, PartialEq)]
pub enum ProtoError {
    /// A cryptographic operation failed
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// The peer's identification string was malformed
    #[error("failed to parse identification: {0}")]
    Identification(#[from] IdentificationError),
    /// The input was too short to decode a complete message
    ///
    /// The payload, if known, is the number of additional bytes needed beyond the end of the
    /// current input (`required - available`).
    #[error("incomplete message: {0:?}")]
    Incomplete(Option<usize>),
    /// A packet violated the protocol; the payload describes how
    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),
    /// No host keys were found or specified
    #[error("no host keys found or specified")]
    NoHostKeys,
    /// Algorithm negotiation failed for the named algorithm category
    #[error("no common {0} algorithms")]
    NoCommonAlgorithm(&'static str),
    /// An internal invariant was violated (this is a bug)
    #[error("unreachable code: {0}")]
    Unreachable(&'static str),
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
