use core::iter;
use std::io;

use aws_lc_rs::{
    cipher::{StreamingDecryptingKey, StreamingEncryptingKey},
    constant_time, hmac, rand,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::Error;

/// The reader and decryption state for an SSH connection.
// FIXME implement in-place decryption once aws-lc-rs supports this for AES-CTR.
pub(crate) struct ReadState {
    buf: Vec<u8>,
    decrypted_buf: Vec<u8>,
    unread_start: usize,
    needed: usize,

    sequence_number: u32,
    pub(crate) decryption_key: Option<(StreamingDecryptingKey, hmac::Key)>,
}

impl Default for ReadState {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(16_384),
            decrypted_buf: Vec::with_capacity(16_384),
            unread_start: 0,
            needed: 0,
            sequence_number: 0,
            decryption_key: None,
        }
    }
}

impl ReadState {
    pub(crate) async fn read_packet<'a>(
        &'a mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<Packet<'a>, Error> {
        loop {
            match self.poll_packet()? {
                Some((sequence_number, packet_length)) => {
                    return self.decode_packet(sequence_number, packet_length);
                }
                None => {
                    let read = stream.read_buf(&mut self.incoming_buf()).await?;
                    debug!(read, "read from stream");
                    if read == 0 {
                        return Err(Error::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF",
                        )));
                    }
                }
            }
        }
    }

    // This and decode_packet are split because of a borrowck limitation.
    pub(crate) fn poll_packet(&mut self) -> Result<Option<(u32, PacketLength)>, Error> {
        // Compact the internal buffer
        if self.unread_start > 0 {
            debug_assert!(self.needed == 0);
            self.buf.copy_within(self.unread_start.., 0);
            self.buf.truncate(self.buf.len() - self.unread_start);
            self.unread_start = 0;
            self.decrypted_buf.clear();
        }

        if self.buf.len() < self.needed {
            return Ok(None);
        }

        let (packet_length, mac_len) = if let Some((decrypting_key, integrity_key)) =
            &mut self.decryption_key
        // comment to prevent rustfmt indenting the entire if
        {
            let block_len = decrypting_key.algorithm().block_len();

            self.needed = block_len;
            if self.buf.len() < self.needed {
                return Ok(None);
            }
            self.decrypted_buf.resize(self.buf.len() + block_len, 0);

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

            self.needed = 4
                + packet_length.inner as usize
                + integrity_key.algorithm().digest_algorithm().output_len;
            if self.buf.len() < self.needed {
                return Ok(None);
            }

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
            hmac_ctx.update(&self.sequence_number.to_be_bytes());
            hmac_ctx.update(packet_excl_mac);
            let actual_mac = hmac_ctx.sign();
            let expected_mac = &self.buf[4 + packet_length.inner as usize
                ..4 + packet_length.inner as usize
                    + integrity_key.algorithm().digest_algorithm().output_len];
            if constant_time::verify_slices_are_equal(actual_mac.as_ref(), expected_mac).is_err() {
                return Err(Error::InvalidMac);
            }

            (
                packet_length,
                integrity_key.algorithm().digest_algorithm().output_len,
            )
        } else {
            self.needed = 4;
            if self.buf.len() < self.needed {
                return Ok(None);
            }
            let Decoded {
                value: packet_length,
                next,
            } = PacketLength::decode(&self.buf[..4])?;
            assert!(next.is_empty());

            self.needed = 4 + packet_length.inner as usize;
            if self.buf.len() < self.needed {
                return Ok(None);
            }

            self.decrypted_buf.clear();
            self.decrypted_buf
                .extend_from_slice(&self.buf[..4 + packet_length.inner as usize]);

            (packet_length, 0)
        };

        // Note: this needs to be done AFTER the IO to ensure
        // this async function is cancel-safe
        let sequence_number = self.sequence_number;
        self.sequence_number = self.sequence_number.wrapping_add(1);

        self.unread_start = 4 + packet_length.inner as usize + mac_len;
        self.needed = 0;

        Ok(Some((sequence_number, packet_length)))
    }

    pub(crate) fn decode_packet<'a>(
        &'a self,
        sequence_number: u32,
        packet_length: PacketLength,
    ) -> Result<Packet<'a>, Error> {
        let Decoded {
            value: padding_length,
            next,
        } = PaddingLength::decode(&self.decrypted_buf[4..4 + packet_length.inner as usize])?;

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

        Ok(Packet {
            number: sequence_number,
            payload,
        })
    }

    /// The buffer to read data into.
    ///
    /// You may not touch existing data and must only append new data at the end.
    pub(crate) fn incoming_buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

// Message type for the transport layer and key exchange messages.
// Note: this MUST map service messages to the unknown type, otherwise
// the service manager will not work right.
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

pub(crate) struct EncryptingWriter<W: AsyncWriteExt + Unpin> {
    stream: W,
    buf: Vec<u8>,
    encrypted_buf: Vec<u8>,

    packet_number: u32,
    encryption_key: Option<(StreamingEncryptingKey, hmac::Key)>,
}

impl<W: AsyncWriteExt + Unpin> EncryptingWriter<W> {
    pub(crate) fn new(stream: W) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(16_384),
            encrypted_buf: Vec::with_capacity(16_384),
            packet_number: 0,
            encryption_key: None,
        }
    }

    /// Write raw bytes without packet structure or encryption.
    ///
    /// This should only be used for writing the identification string.
    pub(crate) async fn write_raw_cleartext(&mut self, bytes: &[u8]) -> Result<(), Error> {
        assert!(self.encryption_key.is_none());
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    pub(crate) fn set_encryption_key(
        &mut self,
        encryption_key: StreamingEncryptingKey,
        integrity_key: hmac::Key,
    ) {
        self.encryption_key = Some((encryption_key, integrity_key));
    }

    /// Write a packet. Returns written [`Packet`].
    pub(crate) async fn write_packet(
        &mut self,
        payload: &(impl Encode + ?Sized),
        update_exchange_hash: impl FnOnce(&[u8]),
    ) -> Result<(), Error> {
        self.buf.clear();
        self.encrypted_buf.clear();

        let packet_number = self.packet_number;
        self.packet_number = self.packet_number.wrapping_add(1);

        let packet = Packet::builder(&mut self.buf).with_payload(payload);
        update_exchange_hash(packet.payload()?);

        if let Some((encryption_key, integrity_key)) = &mut self.encryption_key {
            let block_len = encryption_key.algorithm().block_len();

            let data = packet.without_mac(block_len)?;

            self.encrypted_buf.resize(data.len() + block_len, 0);
            let update = encryption_key
                .update(data, &mut self.encrypted_buf)
                .unwrap();
            assert_eq!(update.remainder().len(), block_len);
            self.encrypted_buf.truncate(data.len());

            let mut hmac_ctx = hmac::Context::with_key(integrity_key);
            hmac_ctx.update(&packet_number.to_be_bytes());
            hmac_ctx.update(data);
            let mac = hmac_ctx.sign();
            self.encrypted_buf.extend_from_slice(mac.as_ref());

            self.stream.write_all(&self.encrypted_buf).await?;
        } else {
            self.stream.write_all(packet.without_mac(0)?).await?;
        };

        Ok(())
    }
}

pub struct Packet<'a> {
    pub(crate) number: u32,
    pub(crate) payload: &'a [u8],
}

pub struct OwnedPacket {
    #[expect(unused)]
    pub(crate) number: u32,
    pub(crate) payload: Vec<u8>,
}

impl<'a> Packet<'a> {
    pub(crate) fn builder(buf: &'a mut Vec<u8>) -> PacketBuilder<'a> {
        let start = buf.len();
        buf.extend_from_slice(&[0, 0, 0, 0]); // packet_length
        buf.push(0); // padding_length
        PacketBuilder { buf, start }
    }

    pub(crate) fn to_owned(&self) -> OwnedPacket {
        OwnedPacket {
            number: self.number,
            payload: self.payload.to_owned(),
        }
    }
}

pub(crate) struct PacketBuilder<'a> {
    buf: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> PacketBuilder<'a> {
    pub(crate) fn with_payload(
        self,
        payload: &(impl Encode + ?Sized),
    ) -> PacketBuilderWithPayload<'a> {
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

    pub(crate) fn without_mac(self, cipher_block_len: usize) -> Result<&'a [u8], Error> {
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

        let block_size = cipher_block_len.max(8);
        let min_packet_len = (buf.len() - start).next_multiple_of(block_size).max(16);
        let min_padding = min_packet_len - (buf.len() - start);
        let padding_len = match min_padding < 4 {
            true => min_padding + block_size,
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

        let packet_len = (buf.len() - start - 4) as u32;
        if let Some(packet_length_dst) = buf.get_mut(start..start + 4) {
            packet_length_dst.copy_from_slice(&packet_len.to_be_bytes());
        }

        buf.get(start..)
            .ok_or(Error::Unreachable("unable to extract packet"))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PacketLength {
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

impl Decode<'_> for bool {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, Error> {
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

pub trait Encode {
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
