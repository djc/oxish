use core::iter;
use std::io;

use aws_lc_rs::{cipher::StreamingDecryptingKey, constant_time, hmac, rand};
use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::Error;

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

/// A reader which decrypts data on the fly.
// FIXME implement in-place decryption once aws-lc-rs supports this for AES-CTR.
pub(crate) struct DecryptingReader<R: AsyncReadExt + Unpin> {
    stream: R,
    buf: Vec<u8>,
    decrypted_buf: Vec<u8>,
    unread_start: usize,

    packet_number: u32,
    pub(crate) decryption_key: Option<(StreamingDecryptingKey, hmac::Key)>,
}

impl<R: AsyncReadExt + Unpin> DecryptingReader<R> {
    pub(crate) fn new(stream: R) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(16_384),
            decrypted_buf: Vec::with_capacity(16_384),
            unread_start: 0,
            packet_number: 0,
            decryption_key: None,
        }
    }

    async fn ensure_at_least(
        stream: &mut R,
        buf: &mut Vec<u8>,
        unread_start: &mut usize,
        n: u32,
    ) -> Result<(), Error> {
        while buf.len() - *unread_start < n as usize {
            let read = stream.read_buf(buf).await?;
            debug!(bytes = read, "read from stream");
            if read == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF",
                )));
            }
        }
        Ok(())
    }

    /// Read a single byte without packet structure or encryption.
    ///
    /// This should only be used for reading the identification string.
    pub(crate) async fn read_u8_cleartext(&mut self) -> Result<u8, Error> {
        assert!(self.decryption_key.is_none());

        Self::ensure_at_least(&mut self.stream, &mut self.buf, &mut self.unread_start, 1).await?;

        let byte = self.buf[self.unread_start];
        self.unread_start += 1;
        Ok(byte)
    }

    pub(crate) async fn read_packet<'a>(&'a mut self) -> Result<Packet<'a>, Error> {
        // Compact the internal buffer
        if self.unread_start > 0 {
            self.buf.copy_within(self.unread_start.., 0);
            self.buf.truncate(self.buf.len() - self.unread_start);
            self.unread_start = 0;
            self.decrypted_buf.clear();
        }

        let (packet_without_mac, mac_len) = if let Some((decrypting_key, integrity_key)) =
            &mut self.decryption_key
        // comment to prevent rustfmt indenting the entire if
        {
            let block_len = decrypting_key.algorithm().block_len();

            Self::ensure_at_least(
                &mut self.stream,
                &mut self.buf,
                &mut self.unread_start,
                block_len as u32,
            )
            .await?;
            self.decrypted_buf.resize(block_len, 0);

            // It is fine to use less_safe_update as we make sure to decrypt whole blocks at a time
            let update = decrypting_key
                .less_safe_update(&self.buf[..block_len], &mut self.decrypted_buf[..block_len])
                .unwrap();
            assert_eq!(update.remainder().len(), 0);

            let Decoded {
                value: packet_length,
                next,
            } = PacketLength::decode(&self.decrypted_buf[..4])?;
            assert!(next.is_empty());

            Self::ensure_at_least(
                &mut self.stream,
                &mut self.buf,
                &mut self.unread_start,
                4 + packet_length.inner
                    + integrity_key.algorithm().digest_algorithm().output_len as u32,
            )
            .await?;
            self.decrypted_buf
                .resize(4 + packet_length.inner as usize, 0);

            // It is fine to use less_safe_update as we make sure to decrypt whole blocks at a time
            let update = decrypting_key
                .less_safe_update(
                    &self.buf[block_len..4 + packet_length.inner as usize],
                    &mut self.decrypted_buf[block_len..4 + packet_length.inner as usize],
                )
                .unwrap();
            assert_eq!(update.remainder().len(), 0);

            let packet_excl_mac = &self.decrypted_buf[..4 + packet_length.inner as usize];

            let mut hmac_ctx = hmac::Context::with_key(integrity_key);
            hmac_ctx.update(&self.packet_number.to_be_bytes());
            hmac_ctx.update(packet_excl_mac);
            let actual_mac = hmac_ctx.sign();
            let expected_mac = &self.buf[4 + packet_length.inner as usize
                ..4 + packet_length.inner as usize
                    + integrity_key.algorithm().digest_algorithm().output_len];
            if constant_time::verify_slices_are_equal(actual_mac.as_ref(), expected_mac).is_err() {
                return Err(Error::InvalidMac);
            }

            (
                packet_excl_mac,
                integrity_key.algorithm().digest_algorithm().output_len,
            )
        } else {
            Self::ensure_at_least(&mut self.stream, &mut self.buf, &mut self.unread_start, 4)
                .await?;
            let Decoded {
                value: packet_length,
                next,
            } = PacketLength::decode(&self.buf[..4])?;
            assert!(next.is_empty());

            Self::ensure_at_least(
                &mut self.stream,
                &mut self.buf,
                &mut self.unread_start,
                4 + packet_length.inner,
            )
            .await?;

            (&self.buf[..4 + packet_length.inner as usize], 0)
        };

        // Note: this needs to be done AFTER the IO to ensure
        // this async function is cancel-safe
        self.packet_number = self.packet_number.wrapping_add(1);

        let Decoded {
            value: packet,
            next,
        } = Packet::decode(packet_without_mac)?;
        assert!(next.is_empty());

        self.unread_start = packet_without_mac.len() + mac_len;

        Ok(packet)
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

impl<'a> Packet<'a> {
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

    pub(crate) fn without_mac(self) -> Result<&'a [u8], Error> {
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

        buf.get(start..)
            .ok_or(Error::Unreachable("unable to extract packet"))
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
