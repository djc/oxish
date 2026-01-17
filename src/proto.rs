use core::{iter, net::SocketAddr, ops::Deref};

use aws_lc_rs::{digest, rand};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, error};

use crate::Error;

pub(crate) struct ReadState {
    pub(crate) buf: Vec<u8>,
    pub(crate) used: usize,
}

impl ReadState {
    pub(crate) async fn packet<'a, T: TryFrom<Packet<'a>, Error = Error> + 'a>(
        &'a mut self,
        stream: &mut (impl AsyncRead + Unpin),
        addr: SocketAddr,
    ) -> Result<Packeted<'a, T>, Error> {
        let bytes = self.buffer(stream).await?;
        let (packet, rest) = match Packet::decode(bytes) {
            Ok(Decoded {
                value: packet,
                next,
            }) => (packet, next.len()),
            Err(error) => {
                error!(%addr, %error, "failed to read packet");
                return Err(error);
            }
        };

        let payload = packet.payload;
        match T::try_from(packet) {
            Ok(decoded) => Ok(Packeted {
                payload,
                decoded,
                rest,
            }),
            Err(error) => {
                error!(%addr, %error, "failed to parse packet");
                Err(error)
            }
        }
    }

    pub(crate) async fn buffer<'a>(
        &'a mut self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> Result<&'a [u8], Error> {
        if self.used > 0 {
            let next = self.buf.len() - self.used;
            self.buf.copy_within(self.used.., 0);
            self.buf.truncate(next);
        }

        let read = reader.read_buf(&mut self.buf).await?;
        debug!(bytes = read, "read from stream");
        Ok(&self.buf)
    }
}

impl Default for ReadState {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(16_384),
            used: 0,
        }
    }
}

pub(crate) struct Packeted<'a, T: 'a> {
    payload: &'a [u8],
    decoded: T,
    rest: usize,
}

impl<'a, T> Packeted<'a, T> {
    pub(crate) fn hash(self, hash: &mut HandshakeHash) -> (T, usize) {
        let Self {
            payload,
            decoded,
            rest,
        } = self;
        hash.prefixed(payload);
        (decoded, rest)
    }

    pub(crate) fn into_inner(self) -> T {
        self.decoded
    }
}

impl<T> Deref for Packeted<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.decoded
    }
}

pub(crate) struct HandshakeHash(digest::Context);

impl HandshakeHash {
    pub(crate) fn prefixed(&mut self, data: &[u8]) {
        self.0.update(&(data.len() as u32).to_be_bytes());
        self.0.update(data);
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub(crate) fn finish(self) -> digest::Digest {
        self.0.finish()
    }
}

impl Default for HandshakeHash {
    fn default() -> Self {
        Self(digest::Context::new(&digest::SHA256))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageType {
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,
    KeyExchangeInit,
    NewKeys,
    KeyExchangeEcdhInit,
    KeyExchangeEcdhReply,
    Unknown(u8),
}

impl Encode for MessageType {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Disconnect => buf.push(1),
            Self::Ignore => buf.push(2),
            Self::Unimplemented => buf.push(3),
            Self::Debug => buf.push(4),
            Self::ServiceRequest => buf.push(5),
            Self::ServiceAccept => buf.push(6),
            Self::KeyExchangeInit => buf.push(20),
            Self::NewKeys => buf.push(21),
            Self::KeyExchangeEcdhInit => buf.push(30),
            Self::KeyExchangeEcdhReply => buf.push(31),
            Self::Unknown(value) => buf.push(*value),
        }
    }
}

impl<'a> Decode<'a> for MessageType {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
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
            20 => Self::KeyExchangeInit,
            21 => Self::NewKeys,
            30 => Self::KeyExchangeEcdhInit,
            31 => Self::KeyExchangeEcdhReply,
            value => Self::Unknown(value),
        }
    }
}

pub(crate) struct Packet<'a> {
    pub(crate) payload: &'a [u8],
}

impl Packet<'_> {
    pub(crate) fn builder(buf: &mut Vec<u8>) -> PacketBuilder<'_> {
        let start = buf.len();
        buf.extend_from_slice(&[0, 0, 0, 0]); // packet_length
        buf.push(0); // padding_length
        PacketBuilder { buf, start }
    }
}

impl<'a> Decode<'a> for Packet<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Decoded {
            value: packet_length,
            next,
        } = PacketLength::decode(bytes)?;

        let Decoded {
            value: padding_length,
            next,
        } = PaddingLength::decode(next)?;

        let payload_len = (packet_length.inner - 1 - padding_length.inner as u32) as usize;
        let Some(payload) = next.get(..payload_len) else {
            return Err(Error::Incomplete(Some(payload_len - next.len())));
        };

        let Some(next) = next.get(payload_len..) else {
            return Err(Error::Unreachable(
                "unable to extract rest after fixed-length slice",
            ));
        };

        let Some(_) = next.get(..padding_length.inner as usize) else {
            return Err(Error::Incomplete(Some(
                padding_length.inner as usize - next.len(),
            )));
        };

        let Some(next) = next.get(padding_length.inner as usize..) else {
            return Err(Error::Unreachable("unable to extract rest after padding"));
        };

        // No MAC support yet

        Ok(Decoded {
            value: Self { payload },
            next,
        })
    }
}

pub(crate) struct PacketBuilder<'a> {
    buf: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> PacketBuilder<'a> {
    pub(crate) fn with_payload(self, payload: &impl Encode) -> PacketBuilderWithPayload<'a> {
        let Self { buf, start } = self;
        payload.encode(buf);
        PacketBuilderWithPayload { buf, start }
    }
}

pub(crate) struct PacketBuilderWithPayload<'a> {
    buf: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> PacketBuilderWithPayload<'a> {
    pub(crate) fn payload(&self) -> Result<&[u8], Error> {
        self.buf
            .get(self.start + 5..)
            .ok_or(Error::Unreachable("unable to extract packet"))
    }

    pub(crate) fn without_mac(self) -> Result<OutgoingPacket<'a>, Error> {
        let Self { buf, start } = self;

        // <https://www.rfc-editor.org/rfc/rfc4253#section-6>
        //
        // Note that the length of the concatenation of 'packet_length',
        // 'padding_length', 'payload', and 'random padding' MUST be a multiple
        // of the cipher block size or 8, whichever is larger.  This constraint
        // MUST be enforced, even when using stream ciphers.  Note that the
        // 'packet_length' field is also encrypted, and processing it requires
        // special care when sending or receiving packets.  Also note that the
        // insertion of variable amounts of 'random padding' may help thwart
        // traffic analysis.
        //
        // The minimum size of a packet is 16 (or the cipher block size,
        // whichever is larger) bytes (plus 'mac').  Implementations SHOULD
        // decrypt the length after receiving the first 8 (or cipher block size,
        // whichever is larger) bytes of a packet.

        let min_padding = 8 - (buf.len() - start) % 8;
        let padding_len = match min_padding < 4 {
            true => min_padding + 8,
            false => min_padding,
        };

        if let Some(padding_length_dst) = buf.get_mut(start + 4) {
            *padding_length_dst = padding_len as u8;
        }

        let padding_start = buf.len();
        buf.extend(iter::repeat_n(0, padding_len)); // padding
        if let Some(padding) = buf.get_mut(padding_start..) {
            if rand::fill(padding).is_err() {
                return Err(Error::Unreachable("failed to get random padding"));
            }
        }

        buf.extend_from_slice(&[]); // mac

        let packet_len = (buf.len() - start - 4) as u32;
        if let Some(packet_length_dst) = buf.get_mut(start..start + 4) {
            packet_length_dst.copy_from_slice(&packet_len.to_be_bytes());
        }

        match buf.get(start..) {
            Some(packet) => Ok(OutgoingPacket(packet)),
            None => Err(Error::Unreachable("unable to extract packet")),
        }
    }
}

#[must_use]
pub(crate) struct OutgoingPacket<'a>(&'a [u8]);

impl Deref for OutgoingPacket<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug)]
struct PacketLength {
    inner: u32,
}

impl Decode<'_> for PacketLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, Error> {
        let Decoded { value, next } = u32::decode(bytes)?;
        if value > 256 * 1024 {
            return Err(Error::InvalidPacket("packet too large"));
        }

        Ok(Decoded {
            value: Self { inner: value },
            next,
        })
    }
}

#[derive(Debug)]
struct PaddingLength {
    inner: u8,
}

impl Decode<'_> for PaddingLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, Error> {
        let Decoded { value, next } = u8::decode(bytes)?;
        if value < 4 {
            return Err(Error::InvalidPacket("padding too short"));
        }

        Ok(Decoded {
            value: Self { inner: value },
            next,
        })
    }
}

impl<'a> Decode<'a> for &'a [u8] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let len = u32::decode(bytes)?;
        let Some(value) = len.next.get(..len.value as usize) else {
            return Err(Error::Incomplete(Some(len.value as usize - len.next.len())));
        };

        let Some(next) = len.next.get(len.value as usize..) else {
            return Err(Error::Unreachable("unable to extract rest after slice"));
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

impl Decode<'_> for u32 {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, Error> {
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

impl<'a, const N: usize> Decode<'a> for [u8; N] {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Some(inner) = bytes.get(..N) else {
            return Err(Error::Incomplete(Some(N - bytes.len())));
        };

        let Some(next) = bytes.get(N..) else {
            return Err(Error::Unreachable(
                "unable to extract rest after fixed-length slice",
            ));
        };

        let Ok(value) = <[u8; N]>::try_from(inner) else {
            return Err(Error::Unreachable("fixed-length slice converts to array"));
        };

        Ok(Decoded { value, next })
    }
}

impl<'a> Decode<'a> for u8 {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let Some(&inner) = bytes.first() else {
            return Err(Error::Incomplete(Some(1)));
        };

        let Some(next) = bytes.get(1..) else {
            return Err(Error::Unreachable("unable to extract rest after u8"));
        };

        Ok(Decoded { value: inner, next })
    }
}

pub(crate) trait Encode {
    fn encode(&self, buf: &mut Vec<u8>);
}

pub(crate) trait Decode<'a>: Sized {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error>;
}

pub(crate) struct Decoded<'a, T> {
    pub(crate) value: T,
    pub(crate) next: &'a [u8],
}

/// The mpint data type is defined in RFC4251 section 5.
///
/// Remove leading zeros, and prepend a zero byte if the first byte has its
/// most significant bit set.
pub(crate) fn with_mpint_bytes(int: &[u8], mut f: impl FnMut(&[u8])) {
    let leading_zeros = int.iter().take_while(|&&b| b == 0).count();
    // This slice indexing is safe as leading_zeros can be no larger than the length of int
    let int = &int[leading_zeros..];
    let prepend = matches!(int.first(), Some(&b) if b & 0x80 != 0);
    let len = int.len() + if prepend { 1 } else { 0 };
    f(&(len as u32).to_be_bytes());
    if prepend {
        f(&[0]);
    }
    f(int);
}
