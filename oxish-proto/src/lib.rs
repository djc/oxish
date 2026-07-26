use core::{fmt, str};

use thiserror::Error;

pub mod auth;
mod base;
pub use base::{
    Completion, Decode, Decoded, Disconnect, DisconnectReason, Encode, Ignore, IncomingPacket,
    MessageType, PacketLength, PaddingLength,
};
pub mod channels;
pub mod crypto;
use crypto::CryptoError;
mod io;
pub use io::{Encoder, ReadState, WriteState};
pub mod key_exchange;
pub mod named;
use named::PublicKeyAlgorithm;

#[derive(Debug)]
pub struct Identification<'a> {
    pub protocol: &'a str,
    pub software: &'a str,
    pub comments: &'a str,
}

impl<'a> Identification<'a> {
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

#[derive(Debug, Error, PartialEq)]
pub enum ProtoError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("failed to parse identification: {0}")]
    Identification(#[from] IdentificationError),
    /// The input was too short to decode a complete message
    ///
    /// The payload, if known, is the number of additional bytes needed beyond
    /// the end of the current input (i.e. `required - available`).
    #[error("incomplete message: {0:?}")]
    Incomplete(Option<usize>),
    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),
    #[error("no host keys found or specified")]
    NoHostKeys,
    #[error("no common {0} algorithms")]
    NoCommonAlgorithm(&'static str),
    #[error("unreachable code: {0}")]
    Unreachable(&'static str),
}

#[derive(Debug, Error, PartialEq)]
pub enum IdentificationError {
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

pub const PROTOCOL: &str = "2.0";
