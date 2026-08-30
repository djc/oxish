use core::{fmt, str};
use std::{borrow::Cow, collections::BTreeMap};

use tracing::warn;

use crate::{Decode, Decoded, Encode, IncomingPacket, MessageType, ProtoError, named::ChannelType};

/// The `SSH_MSG_CHANNEL_OPEN` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.1>.
#[derive(Debug)]
pub struct ChannelOpen<'a> {
    /// The channel type to open
    pub r#type: ChannelType<'a>,
    /// The sender's identifier for the channel
    pub sender_channel: u32,
    /// Initial number of bytes the sender is willing to receive
    pub initial_window_size: u32,
    /// Maximum packet size the sender is willing to receive
    pub maximum_packet_size: u32,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelOpen<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelOpen {
            return Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[MessageType::ChannelOpen],
            ));
        }

        let Decoded {
            value: r#type,
            next,
        } = ChannelType::decode(packet.payload)?;

        let Decoded {
            value: sender_channel,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: initial_window_size,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: maximum_packet_size,
            next,
        } = u32::decode(next)?;

        match r#type {
            ChannelType::Session => match next.is_empty() {
                true => {}
                false => {
                    return Err(ProtoError::InvalidPacket(
                        "extra data in channel open packet",
                    ));
                }
            },
            ChannelType::Unknown(_) => {}
        }

        Ok(ChannelOpen {
            r#type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }
}

/// The `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.1>.
#[derive(Debug)]
pub struct ChannelOpenConfirmation {
    /// The channel identifier chosen by the original sender
    pub recipient_channel: u32,
    /// The responder's identifier for the channel
    pub sender_channel: u32,
    /// Initial number of bytes the responder is willing to receive
    pub initial_window_size: u32,
    /// Maximum packet size the responder is willing to receive
    pub maximum_packet_size: u32,
}

impl Encode for ChannelOpenConfirmation {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        } = self;

        MessageType::ChannelOpenConfirmation.encode(buffer);
        recipient_channel.encode(buffer);
        sender_channel.encode(buffer);
        initial_window_size.encode(buffer);
        maximum_packet_size.encode(buffer);
    }
}

/// The `SSH_MSG_CHANNEL_OPEN_FAILURE` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.1>.
#[derive(Debug)]
pub struct ChannelOpenFailure<'a> {
    recipient_channel: u32,
    reason_code: ChannelOpenFailureReason,
    description: &'a str,
}

impl ChannelOpenFailure<'static> {
    /// Failure response for a channel open reusing an active channel identifier
    pub fn duplicate_id(recipient_channel: u32) -> Self {
        Self {
            recipient_channel,
            reason_code: ChannelOpenFailureReason::AdministrativelyProhibited,
            description: "channel ID already in use",
        }
    }

    /// Failure response for a channel open with an unsupported channel type
    pub fn unknown_type(recipient_channel: u32) -> Self {
        Self {
            recipient_channel,
            reason_code: ChannelOpenFailureReason::UnknownChannelType,
            description: "only 'session' channel type is supported",
        }
    }
}

impl Encode for ChannelOpenFailure<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self {
            recipient_channel,
            reason_code,
            description,
        } = self;

        MessageType::ChannelOpenFailure.encode(buffer);
        recipient_channel.encode(buffer);
        reason_code.encode(buffer);
        description.as_bytes().encode(buffer);
        "en-US".as_bytes().encode(buffer);
    }
}

#[expect(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
enum ChannelOpenFailureReason {
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
}

impl Encode for ChannelOpenFailureReason {
    fn encode(&self, buffer: &mut Vec<u8>) {
        (*self as u32).encode(buffer);
    }
}

/// The `SSH_MSG_CHANNEL_REQUEST` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.4>; request types for session channels are
/// defined in <https://www.rfc-editor.org/rfc/rfc4254#section-6>.
#[derive(Debug)]
pub struct ChannelRequest<'a> {
    /// The channel the request applies to
    pub recipient_channel: u32,
    /// The request type and its type-specific data
    pub r#type: ChannelRequestType<'a>,
    /// Whether the sender wants a success or failure reply
    pub want_reply: bool,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelRequest<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelRequest {
            return Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[MessageType::ChannelRequest],
            ));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        let Decoded {
            value: r#type,
            next,
        } = <&[u8]>::decode(next)?;

        let Decoded {
            value: want_reply,
            next,
        } = bool::decode(next)?;

        let r#type = match r#type {
            b"pty-req" => {
                let Decoded { value, next } = PtyReq::decode(next)?;
                match next.is_empty() {
                    true => ChannelRequestType::PtyReq(value),
                    false => {
                        return Err(ProtoError::InvalidPacket(
                            "extra data in pty-req channel request",
                        ));
                    }
                }
            }
            b"env" => {
                let Decoded { value, next } = Env::decode(next)?;
                match next.is_empty() {
                    true => ChannelRequestType::Env(value),
                    false => {
                        return Err(ProtoError::InvalidPacket(
                            "extra data in env channel request",
                        ));
                    }
                }
            }
            b"shell" => match next.is_empty() {
                true => ChannelRequestType::Shell,
                false => {
                    return Err(ProtoError::InvalidPacket(
                        "extra data in shell channel request",
                    ));
                }
            },
            b"window-change" => {
                let Decoded { value, next } = WindowChange::decode(next)?;
                match next.is_empty() {
                    true => ChannelRequestType::WindowChange(value),
                    false => {
                        return Err(ProtoError::InvalidPacket(
                            "extra data in window-change channel request",
                        ));
                    }
                }
            }
            b"auth-agent-req@openssh.com" => ChannelRequestType::AuthAgentReq,
            _ => match str::from_utf8(r#type) {
                Ok(r#type) => ChannelRequestType::Unknown(r#type),
                Err(_) => {
                    warn!(?r#type, "unknown channel request type");
                    return Err(ProtoError::InvalidPacket(
                        "unknown channel request type (invalid UTF-8)",
                    ));
                }
            },
        };

        Ok(ChannelRequest {
            recipient_channel,
            r#type,
            want_reply,
        })
    }
}

impl Encode for ChannelRequest<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self {
            recipient_channel,
            r#type,
            want_reply,
        } = self;

        MessageType::ChannelRequest.encode(buffer);
        recipient_channel.encode(buffer);
        r#type.name().as_bytes().encode(buffer);
        want_reply.encode(buffer);
        match r#type {
            ChannelRequestType::ExitStatus(status) => status.encode(buffer),
            ChannelRequestType::PtyReq(pty_req) => pty_req.encode(buffer),
            ChannelRequestType::Env(env) => env.encode(buffer),
            ChannelRequestType::WindowChange(window_change) => window_change.encode(buffer),
            ChannelRequestType::AuthAgentReq
            | ChannelRequestType::Shell
            | ChannelRequestType::Unknown(_) => {}
        }
    }
}

/// Request type-specific data from a [`ChannelRequest`]
#[derive(Debug)]
pub enum ChannelRequestType<'a> {
    /// `auth-agent-req@openssh.com`
    ///
    /// Not currently supported.
    AuthAgentReq,
    /// `exit-status`, report the exit status of a process
    ///
    /// As defined in <https://www.rfc-editor.org/info/rfc4254/#section-6.10>.
    ExitStatus(u32),
    /// `pty-req`, request a pseudo-terminal
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4254#section-6.2>.
    PtyReq(PtyReq<'a>),
    /// `env`, set an environment variable
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4254#section-6.4>.
    Env(Env<'a>),
    /// `shell`, start the user's default shell
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4254#section-6.5>.
    Shell,
    /// `window-change`, report new terminal dimensions
    ///
    /// As defined in <https://www.rfc-editor.org/rfc/rfc4254#section-6.7>.
    WindowChange(WindowChange),
    /// Unknown channel request type; the string is the request type name
    Unknown(&'a str),
}

impl ChannelRequestType<'_> {
    fn name(&self) -> &str {
        match self {
            Self::AuthAgentReq => "auth-agent-req@openssh.com",
            Self::ExitStatus(_) => "exit-status",
            Self::PtyReq(_) => "pty-req",
            Self::Env(_) => "env",
            Self::Shell => "shell",
            Self::WindowChange(_) => "window-change",
            Self::Unknown(name) => name,
        }
    }
}

/// Type-specific data for the `window-change` channel request
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-6.7>.
#[derive(Clone, Copy, Debug)]
pub struct WindowChange {
    /// Terminal width in columns
    pub cols: u32,
    /// Terminal height in rows
    pub rows: u32,
    /// Terminal width in pixels
    pub width_px: u32,
    /// Terminal height in pixels
    pub height_px: u32,
}

impl<'a> Decode<'a> for WindowChange {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: cols, next } = u32::decode(input)?;
        let Decoded { value: rows, next } = u32::decode(next)?;
        let Decoded {
            value: width_px,
            next,
        } = u32::decode(next)?;
        let Decoded {
            value: height_px,
            next,
        } = u32::decode(next)?;

        Ok(Decoded {
            value: Self {
                cols,
                rows,
                width_px,
                height_px,
            },
            next,
        })
    }
}

impl Encode for WindowChange {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self {
            cols,
            rows,
            width_px,
            height_px,
        } = self;

        cols.encode(buffer);
        rows.encode(buffer);
        width_px.encode(buffer);
        height_px.encode(buffer);
    }
}

/// Type-specific data for the `env` channel request
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-6.4>.
#[derive(Debug)]
pub struct Env<'a> {
    /// The environment variable name
    pub name: &'a str,
    /// The environment variable value
    pub value: &'a str,
}

impl<'a> Decode<'a> for Env<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: name, next } = <&[u8]>::decode(input)?;
        let name = str::from_utf8(name)
            .map_err(|_| ProtoError::InvalidPacket("invalid UTF-8 in env name"))?;

        let Decoded { value, next } = <&[u8]>::decode(next)?;
        let value = str::from_utf8(value)
            .map_err(|_| ProtoError::InvalidPacket("invalid UTF-8 in env value"))?;

        Ok(Decoded {
            value: Env { name, value },
            next,
        })
    }
}

impl Encode for Env<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self { name, value } = self;
        name.as_bytes().encode(buffer);
        value.as_bytes().encode(buffer);
    }
}

/// Type-specific data for the `pty-req` channel request
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-6.2>.
#[derive(Debug)]
pub struct PtyReq<'a> {
    /// The `TERM` environment variable value (e.g. `vt100`)
    pub term: Cow<'a, str>,
    /// Terminal width in columns
    pub cols: u32,
    /// Terminal height in rows
    pub rows: u32,
    /// Terminal width in pixels
    pub width_px: u32,
    /// Terminal height in pixels
    pub height_px: u32,
    /// Encoded terminal modes
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc4254#section-8>.
    pub terminal_modes: BTreeMap<Mode, u32>,
}

impl<'a> PtyReq<'a> {
    /// Copy any borrowed data so the value can outlive the input buffer
    pub fn into_owned(self) -> PtyReq<'static> {
        PtyReq {
            term: Cow::Owned(self.term.into_owned()),
            cols: self.cols,
            rows: self.rows,
            width_px: self.width_px,
            height_px: self.height_px,
            terminal_modes: self.terminal_modes,
        }
    }
}

impl<'a> Decode<'a> for PtyReq<'a> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: term, next } = <&[u8]>::decode(input)?;
        let term = str::from_utf8(term)
            .map_err(|_| ProtoError::InvalidPacket("invalid UTF-8 in pty-req data"))?;

        let Decoded { value: cols, next } = u32::decode(next)?;
        let Decoded { value: rows, next } = u32::decode(next)?;
        let Decoded {
            value: width_px,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: height_px,
            next,
        } = u32::decode(next)?;

        let Decoded {
            value: terminal_modes,
            next,
        } = BTreeMap::<Mode, u32>::decode(next)?;

        Ok(Decoded {
            value: PtyReq {
                term: Cow::Borrowed(term),
                cols,
                rows,
                width_px,
                height_px,
                terminal_modes,
            },
            next,
        })
    }
}

impl Encode for PtyReq<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self {
            term,
            cols,
            rows,
            width_px,
            height_px,
            terminal_modes,
        } = self;

        term.as_bytes().encode(buffer);
        cols.encode(buffer);
        rows.encode(buffer);
        width_px.encode(buffer);
        height_px.encode(buffer);
        terminal_modes.encode(buffer);
    }
}

impl<'a> Decode<'a> for BTreeMap<Mode, u32> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value, next: rest } = <&[u8]>::decode(input)?;
        let mut input = value;
        let mut modes = Self::new();

        loop {
            let Decoded { value, next } = Option::<Mode>::decode(input)?;
            input = next;

            match value {
                Some(mode) => {
                    let Decoded { value, next } = u32::decode(input)?;
                    modes.insert(mode, value);
                    input = next;
                }
                None => break,
            }
        }

        Ok(Decoded {
            value: modes,
            next: rest,
        })
    }
}

impl Encode for BTreeMap<Mode, u32> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        // Each mode is one opcode byte plus a `u32` argument, terminated by `TTY_OP_END` (0)
        ((self.len() * 5 + 1) as u32).encode(buffer);
        for (mode, value) in self {
            buffer.push(*mode as u8);
            value.encode(buffer);
        }
        buffer.push(0);
    }
}

/// Terminal mode opcodes for the `pty-req` channel request
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-8> for the encoding and opcode semantics;
/// these largely mirror the POSIX termios flags.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// `VINTR`, interrupt character
    VIntr = 1,
    /// `VQUIT`, quit character
    VQuit = 2,
    /// `VERASE`, erase the character to the left of the cursor
    VErase = 3,
    /// `VKILL`, kill the current input line
    VKill = 4,
    /// `VEOF`, end-of-file character
    VEof = 5,
    /// `VEOL`, end-of-line character in addition to carriage return and/or linefeed
    VEol = 6,
    /// `VEOL2`, additional end-of-line character
    VEol2 = 7,
    /// `VSTART`, continues paused output
    VStart = 8,
    /// `VSTOP`, pauses output
    VStop = 9,
    /// `VSUSP`, suspends the current program
    VSusp = 10,
    /// `VDSUSP`, another suspend character
    VDSusp = 11,
    /// `VREPRINT`, reprints the current input line
    VReprint = 12,
    /// `VWERASE`, erases a word left of the cursor
    VWErase = 13,
    /// `VLNEXT`, enter the next character typed literally
    VLNext = 14,
    /// `VFLUSH`, character to flush output
    VFlush = 15,
    /// `VSWTCH`, switch to a different shell layer
    VSwtch = 16,
    /// `VSTATUS`, prints the system status line
    VStatus = 17,
    /// `VDISCARD`, toggles the flushing of terminal output
    VDiscard = 18,
    /// `IGNPAR`, the ignore parity flag
    IgnPar = 30,
    /// `PARMRK`, mark parity and framing errors
    ParMrk = 31,
    /// `INPCK`, enable checking of parity errors
    INPck = 32,
    /// `ISTRIP`, strip 8th bit off characters
    IStrip = 33,
    /// `INLCR`, map NL into CR on input
    INlCr = 34,
    /// `IGNCR`, ignore CR on input
    IgnCr = 35,
    /// `ICRNL`, map CR to NL on input
    ICrNl = 36,
    /// `IUCLC`, translate uppercase characters to lowercase
    IUcLc = 37,
    /// `IXON`, enable output flow control
    IxOn = 38,
    /// `IXANY`, any character will restart after stop
    IxAny = 39,
    /// `IXOFF`, enable input flow control
    IxOff = 40,
    /// `IMAXBEL`, ring bell on input queue full
    IMaxBel = 41,
    /// `IUTF8`, terminal input and output is assumed to be UTF-8 encoded
    IUtf8 = 42,
    /// `ISIG`, enable signals INTR, QUIT and \[D\]SUSP
    ISig = 50,
    /// `ICANON`, canonicalize input lines
    ICanon = 51,
    /// `XCASE`, escaped uppercase input and output
    XCase = 52,
    /// `ECHO`, enable echoing
    Echo = 53,
    /// `ECHOE`, visually erase characters
    EchoE = 54,
    /// `ECHOK`, kill character discards current line
    EchoK = 55,
    /// `ECHONL`, echo NL even if ECHO is off
    EchoNl = 56,
    /// `NOFLSH`, don't flush after interrupt
    NoFlsh = 57,
    /// `TOSTOP`, stop background jobs from output
    TOStop = 58,
    /// `IEXTEN`, enable extensions
    IExten = 59,
    /// `ECHOCTL`, echo control characters as ^X
    EchoCtl = 60,
    /// `ECHOKE`, visual erase for line kill
    EchoKe = 61,
    /// `PENDIN`, retype pending input
    Pendin = 62,
    /// `OPOST`, enable output processing
    OPost = 70,
    /// `OLCUC`, convert lowercase to uppercase on output
    OLcUc = 71,
    /// `ONLCR`, map NL to CR-NL on output
    ONlCr = 72,
    /// `OCRNL`, translate carriage return to newline on output
    OCrNl = 73,
    /// `ONOCR`, translate newline to carriage return-newline on output
    ONoCr = 74,
    /// `ONLRET`, newline performs a carriage return on output
    ONlRet = 75,
    /// `CS7`, 7-bit mode
    Cs7 = 90,
    /// `CS8`, 8-bit mode
    Cs8 = 91,
    /// `PARENB`, parity enable
    ParenB = 92,
    /// `PARODD`, odd parity, else even
    ParOdd = 93,
    /// `TTY_OP_ISPEED`, input baud rate in bits per second
    TtyOpISpeed = 128,
    /// `TTY_OP_OSPEED`, output baud rate in bits per second
    TtyOpOSpeed = 129,
}

impl<'a> Decode<'a> for Option<Mode> {
    fn decode(input: &'a [u8]) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value, next } = u8::decode(input)?;
        let mode = match value {
            0 => return Ok(Decoded { value: None, next }),
            1 => Mode::VIntr,
            2 => Mode::VQuit,
            3 => Mode::VErase,
            4 => Mode::VKill,
            5 => Mode::VEof,
            6 => Mode::VEol,
            7 => Mode::VEol2,
            8 => Mode::VStart,
            9 => Mode::VStop,
            10 => Mode::VSusp,
            11 => Mode::VDSusp,
            12 => Mode::VReprint,
            13 => Mode::VWErase,
            14 => Mode::VLNext,
            15 => Mode::VFlush,
            16 => Mode::VSwtch,
            17 => Mode::VStatus,
            18 => Mode::VDiscard,
            30 => Mode::IgnPar,
            31 => Mode::ParMrk,
            32 => Mode::INPck,
            33 => Mode::IStrip,
            34 => Mode::INlCr,
            35 => Mode::IgnCr,
            36 => Mode::ICrNl,
            37 => Mode::IUcLc,
            38 => Mode::IxOn,
            39 => Mode::IxAny,
            40 => Mode::IxOff,
            41 => Mode::IMaxBel,
            42 => Mode::IUtf8,
            50 => Mode::ISig,
            51 => Mode::ICanon,
            52 => Mode::XCase,
            53 => Mode::Echo,
            54 => Mode::EchoE,
            55 => Mode::EchoK,
            56 => Mode::EchoNl,
            57 => Mode::NoFlsh,
            58 => Mode::TOStop,
            59 => Mode::IExten,
            60 => Mode::EchoCtl,
            61 => Mode::EchoKe,
            62 => Mode::Pendin,
            70 => Mode::OPost,
            71 => Mode::OLcUc,
            72 => Mode::ONlCr,
            73 => Mode::OCrNl,
            74 => Mode::ONoCr,
            75 => Mode::ONlRet,
            90 => Mode::Cs7,
            91 => Mode::Cs8,
            92 => Mode::ParenB,
            93 => Mode::ParOdd,
            128 => Mode::TtyOpISpeed,
            129 => Mode::TtyOpOSpeed,
            val => {
                warn!(%val, "unknown terminal mode code");
                return Err(ProtoError::InvalidPacket("unknown terminal mode code"));
            }
        };

        Ok(Decoded {
            value: Some(mode),
            next,
        })
    }
}

/// The `SSH_MSG_CHANNEL_SUCCESS` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.4>.
#[derive(Debug)]
pub struct ChannelRequestSuccess {
    /// The channel the reply applies to
    pub recipient_channel: u32,
}

impl Encode for ChannelRequestSuccess {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self { recipient_channel } = self;
        MessageType::ChannelSuccess.encode(buffer);
        recipient_channel.encode(buffer);
    }
}

/// The `SSH_MSG_CHANNEL_FAILURE` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.4>.
#[derive(Debug)]
pub struct ChannelRequestFailure {
    /// The channel the reply applies to
    pub recipient_channel: u32,
}

impl Encode for ChannelRequestFailure {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self { recipient_channel } = self;
        MessageType::ChannelFailure.encode(buffer);
        recipient_channel.encode(buffer);
    }
}

/// The `SSH_MSG_CHANNEL_DATA` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.2>.
pub struct ChannelData<'a> {
    /// The channel the data belongs to
    pub recipient_channel: u32,
    /// The data being transferred
    pub data: Cow<'a, [u8]>,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelData<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelData {
            return Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[MessageType::ChannelData],
            ));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        let Decoded { value: data, next } = <&[u8]>::decode(next)?;

        match next.is_empty() {
            true => Ok(ChannelData {
                recipient_channel,
                data: Cow::Borrowed(data),
            }),
            false => Err(ProtoError::InvalidPacket(
                "extra data in channel data packet",
            )),
        }
    }
}

impl Encode for ChannelData<'_> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self {
            recipient_channel,
            data,
        } = self;

        MessageType::ChannelData.encode(buffer);
        recipient_channel.encode(buffer);
        data.as_ref().encode(buffer);
    }
}

impl fmt::Debug for ChannelData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelData")
            .field("recipient_channel", &self.recipient_channel)
            .field("data", &format_args!("[{} bytes]", self.data.len()))
            .finish()
    }
}

/// The `SSH_MSG_CHANNEL_WINDOW_ADJUST` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.2>.
#[derive(Debug)]
pub struct ChannelWindowAdjust {
    /// The channel whose window to extend
    pub recipient_channel: u32,
    /// Number of bytes to add to the window
    pub bytes_to_add: u32,
}

impl Encode for ChannelWindowAdjust {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self {
            recipient_channel,
            bytes_to_add,
        } = self;

        MessageType::ChannelWindowAdjust.encode(buffer);
        recipient_channel.encode(buffer);
        bytes_to_add.encode(buffer);
    }
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelWindowAdjust {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelWindowAdjust {
            return Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[MessageType::ChannelWindowAdjust],
            ));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        let Decoded {
            value: bytes_to_add,
            next,
        } = u32::decode(next)?;

        match next.is_empty() {
            true => Ok(Self {
                recipient_channel,
                bytes_to_add,
            }),
            false => Err(ProtoError::InvalidPacket(
                "extra data in channel window adjust packet",
            )),
        }
    }
}

/// The `SSH_MSG_CHANNEL_EOF` message
///
/// Signals that no more data will be sent to the channel.
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.3>.
#[derive(Debug)]
pub struct ChannelEof {
    /// The channel that will receive no more data
    pub recipient_channel: u32,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelEof {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelEof {
            return Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[MessageType::ChannelEof],
            ));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        match next.is_empty() {
            true => Ok(Self { recipient_channel }),
            false => Err(ProtoError::InvalidPacket(
                "extra data in channel eof packet",
            )),
        }
    }
}

impl Encode for ChannelEof {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self { recipient_channel } = self;
        MessageType::ChannelEof.encode(buffer);
        recipient_channel.encode(buffer);
    }
}

/// The `SSH_MSG_CHANNEL_CLOSE` message
///
/// See <https://www.rfc-editor.org/rfc/rfc4254#section-5.3>.
#[derive(Debug)]
pub struct ChannelClose {
    /// The channel being closed
    pub recipient_channel: u32,
}

impl<'a> TryFrom<IncomingPacket<'a>> for ChannelClose {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::ChannelClose {
            return Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[MessageType::ChannelClose],
            ));
        }

        let Decoded {
            value: recipient_channel,
            next,
        } = u32::decode(packet.payload)?;

        match next.is_empty() {
            true => Ok(Self { recipient_channel }),
            false => Err(ProtoError::InvalidPacket(
                "extra data in channel close packet",
            )),
        }
    }
}

impl Encode for ChannelClose {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let Self { recipient_channel } = self;
        MessageType::ChannelClose.encode(buffer);
        recipient_channel.encode(buffer);
    }
}
