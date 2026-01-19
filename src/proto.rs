use core::future;
use core::iter;
use core::pin::Pin;
use core::task::{ready, Context, Poll};
use std::{borrow::Cow, io};

use aws_lc_rs::{
    cipher::{self, StreamingDecryptingKey, StreamingEncryptingKey, UnboundCipherKey},
    constant_time, digest, hmac, rand,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::debug;

use crate::{key_exchange::RawKeys, Error};

/// The reader and decryption state for an SSH connection
pub(crate) struct ReadState {
    /// Buffer for incoming data from the transport stream
    buf: Vec<u8>,
    /// Full length of the last decoded packet, including packet length and MAC
    ///
    /// Set after decoding and decrypting a packet successfully in `poll_packet()`; reduced at
    /// the start of each call to `poll_packet()`.
    last_length: usize,

    /// Buffer with blocks of decrypted data
    ///
    /// aws-lc-rs does not support in-place decryption for AES-CTR.
    decrypted_buf: Vec<u8>,
    /// Whether the a first block including the packet length has been decrypted
    decrypted_first_block: bool,

    sequence_number: u32,
    pub(crate) decryption_key: Option<AesCtrReadKeys>,
}

impl ReadState {
    pub(crate) async fn packet<'a>(
        &'a mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<IncomingPacket<'a>, Error> {
        loop {
            match self.poll_packet()? {
                Completion::Complete((sequence_number, packet_length)) => {
                    return self.decode_packet(sequence_number, packet_length)
                }
                Completion::Incomplete(_amount) => {
                    let _ = self.buffer(stream).await?;
                    continue;
                }
            }
        }
    }

    // This and decode_packet are split because of a borrowck limitation
    pub(crate) fn poll_packet(&mut self) -> Result<Completion<(u32, PacketLength)>, Error> {
        // Compact the internal buffer
        if self.last_length > 0 {
            self.buf.copy_within(self.last_length.., 0);
            self.buf.truncate(self.buf.len() - self.last_length);
            self.last_length = 0;
            self.decrypted_buf.clear();
            self.decrypted_first_block = false;
        }

        let (packet_length, mac_len) = if let Some(keys) = &mut self.decryption_key {
            let block_len = keys.decryption.algorithm().block_len();

            let needed = block_len;
            if self.buf.len() < needed {
                return Ok(Completion::Incomplete(Some(needed)));
            }
            self.decrypted_buf.resize(self.buf.len() + block_len, 0);

            if !self.decrypted_first_block {
                // It is fine to use less_safe_update as we make sure to decrypt whole blocks at a time
                let update = keys
                    .decryption
                    .less_safe_update(&self.buf[..block_len], &mut self.decrypted_buf[..block_len])
                    .unwrap();
                assert_eq!(update.remainder().len(), 0);
                self.decrypted_first_block = true;
            }

            let Decoded {
                value: packet_length,
                next,
            } = PacketLength::decode(&self.decrypted_buf[..4])?;
            assert!(next.is_empty());

            let needed = 4
                + packet_length.inner as usize
                + keys.mac.algorithm().digest_algorithm().output_len;
            if self.buf.len() < needed {
                return Ok(Completion::Incomplete(Some(needed)));
            }

            // It is fine to use less_safe_update as we make sure to decrypt whole blocks at a time
            let update = keys
                .decryption
                .less_safe_update(
                    &self.buf[block_len..4 + packet_length.inner as usize],
                    &mut self.decrypted_buf[block_len..4 + packet_length.inner as usize],
                )
                .unwrap();
            assert_eq!(update.remainder().len(), 0);

            let packet_excl_mac = &self.decrypted_buf[..4 + packet_length.inner as usize];

            let mut hmac_ctx = hmac::Context::with_key(&keys.mac);
            hmac_ctx.update(&self.sequence_number.to_be_bytes());
            hmac_ctx.update(packet_excl_mac);
            let actual_mac = hmac_ctx.sign();
            let expected_mac = &self.buf[4 + packet_length.inner as usize
                ..4 + packet_length.inner as usize
                    + keys.mac.algorithm().digest_algorithm().output_len];
            if constant_time::verify_slices_are_equal(actual_mac.as_ref(), expected_mac).is_err() {
                return Err(Error::InvalidMac);
            }

            (
                packet_length,
                keys.mac.algorithm().digest_algorithm().output_len,
            )
        } else {
            let needed = 4;
            if self.buf.len() < needed {
                return Ok(Completion::Incomplete(Some(needed)));
            }
            let Decoded {
                value: packet_length,
                next,
            } = PacketLength::decode(&self.buf[..4])?;
            assert!(next.is_empty());

            let needed = 4 + packet_length.inner as usize;
            if self.buf.len() < needed {
                return Ok(Completion::Incomplete(Some(needed)));
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
        self.last_length = 4 + packet_length.inner as usize + mac_len;
        Ok(Completion::Complete((sequence_number, packet_length)))
    }

    pub(crate) fn decode_packet<'a>(
        &'a self,
        sequence_number: u32,
        packet_length: PacketLength,
    ) -> Result<IncomingPacket<'a>, Error> {
        let Decoded {
            value: padding_length,
            next,
        } = PaddingLength::decode(&self.decrypted_buf[4..4 + packet_length.inner as usize])?;

        let payload_len = (packet_length.inner - 1 - padding_length.inner as u32) as usize;
        let Some(payload) = next.get(..payload_len) else {
            return Err(Error::Incomplete(Some(payload_len - next.len())));
        };

        let Decoded {
            value: message_type,
            next: payload,
        } = MessageType::decode(payload).map_err(|e| {
            if matches!(e, Error::Incomplete(_)) {
                Error::InvalidPacket("Packet without message type")
            } else {
                e
            }
        })?;

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

        Ok(IncomingPacket {
            sequence_number,
            message_type,
            payload,
        })
    }

    pub(crate) async fn buffer<'a>(
        &'a mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<&'a [u8], Error> {
        let read = stream.read_buf(&mut self.buf).await?;
        debug!(read, "read from stream");
        match read {
            0 => Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF",
            ))),
            _ => Ok(&self.buf),
        }
    }

    pub(crate) fn set_last_length(&mut self, len: usize) {
        self.last_length = len;
    }
}

impl Default for ReadState {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(16_384),
            decrypted_buf: Vec::with_capacity(16_384),
            last_length: 0,
            decrypted_first_block: false,
            sequence_number: 0,
            decryption_key: None,
        }
    }
}

/// Decryption and HMAC key for AES-128-CTR + HMAC-SHA256
pub(crate) struct AesCtrReadKeys {
    decryption: StreamingDecryptingKey,
    mac: hmac::Key,
}

impl AesCtrReadKeys {
    pub(crate) fn new(keys: RawKeys) -> Self {
        Self {
            decryption: StreamingDecryptingKey::ctr(
                UnboundCipherKey::new(&cipher::AES_128, &keys.encryption_key.derive::<16>())
                    .unwrap(),
                cipher::DecryptionContext::Iv128(keys.initial_iv.derive::<16>().into()),
            )
            .unwrap(),
            mac: hmac::Key::new(hmac::HMAC_SHA256, &keys.integrity_key.derive::<32>()),
        }
    }
}

pub(crate) enum Completion<T> {
    Complete(T),
    Incomplete(Option<usize>),
}

pub(crate) struct WriteState {
    /// Buffer for encoded but unencrypted packets
    buf: Vec<u8>,

    /// Buffer with encrypted data ready to be sent to the transport stream
    ///
    /// aws-lc-rs does not support in-place encryption for AES-CTR.
    encrypted_buf: Vec<u8>,

    /// The amount of bytes at the start of `encrypted_buf`` that have already
    /// been sent to the transport stream
    written: usize,

    sequence_number: u32,
    pub(crate) keys: Option<AesCtrWriteKeys>,
}

impl WriteState {
    pub(crate) async fn write_packet(
        &mut self,
        stream: &mut (impl AsyncWrite + Unpin),
        payload: &impl Encode,
        exchange_hash: Option<&mut HandshakeHash>,
    ) -> Result<(), Error> {
        self.handle_packet(payload, exchange_hash)?;

        future::poll_fn(|cx| self.poll_write_to(cx, stream)).await?;

        Ok(())
    }

    fn handle_packet(
        &mut self,
        payload: &impl Encode,
        exchange_hash: Option<&mut HandshakeHash>,
    ) -> Result<(), Error> {
        self.buf.clear();

        let sequence_number = self.sequence_number;
        self.sequence_number = self.sequence_number.wrapping_add(1);

        let pending_length = self.encrypted_buf.len();

        let Some(keys) = &mut self.keys else {
            let packet = EncodedPacket::new(&mut self.encrypted_buf, payload, 1)?;
            if let Some(exchange_hash) = exchange_hash {
                exchange_hash.prefixed(packet.payload());
            }
            return Ok(());
        };

        let block_len = keys.encryption.algorithm().block_len();

        let packet = EncodedPacket::new(&mut self.buf, payload, block_len)?;
        if let Some(exchange_hash) = exchange_hash {
            exchange_hash.prefixed(packet.payload());
        }
        let data = packet.without_mac();

        self.encrypted_buf
            .resize(pending_length + data.len() + block_len, 0);
        let update = keys
            .encryption
            .update(data, &mut self.encrypted_buf[pending_length..])
            .unwrap();
        assert_eq!(update.remainder().len(), block_len);
        self.encrypted_buf.truncate(pending_length + data.len());

        let mut hmac_ctx = hmac::Context::with_key(&keys.mac);
        hmac_ctx.update(&sequence_number.to_be_bytes());
        hmac_ctx.update(data);
        let mac = hmac_ctx.sign();
        self.encrypted_buf.extend_from_slice(mac.as_ref());

        Ok(())
    }

    pub(crate) fn poll_write_to(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Poll<Result<(), Error>> {
        self.written +=
            ready!(Pin::new(stream).poll_write(cx, &self.encrypted_buf[self.written..]))?;

        if self.written == self.encrypted_buf.len() {
            self.encrypted_buf.clear();
            self.written = 0;
        }

        Poll::Ready(Ok(()))
    }

    pub(crate) fn encoded(&mut self, payload: &impl Encode) -> &[u8] {
        payload.encode(&mut self.buf);
        &self.buf
    }
}

impl Default for WriteState {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(16_384),
            encrypted_buf: Vec::with_capacity(16_384),
            written: 0,
            sequence_number: 0,
            keys: None,
        }
    }
}

/// Encryption and HMAC key for AES-128-CTR + HMAC-SHA256
pub(crate) struct AesCtrWriteKeys {
    encryption: StreamingEncryptingKey,
    mac: hmac::Key,
}

impl AesCtrWriteKeys {
    pub(crate) fn new(keys: RawKeys) -> Self {
        Self {
            encryption: StreamingEncryptingKey::less_safe_ctr(
                UnboundCipherKey::new(&cipher::AES_128, &keys.encryption_key.derive::<16>())
                    .unwrap(),
                cipher::EncryptionContext::Iv128(keys.initial_iv.derive::<16>().into()),
            )
            .unwrap(),
            mac: hmac::Key::new(hmac::HMAC_SHA256, &keys.integrity_key.derive::<32>()),
        }
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
        buf.push(u8::from(*self));
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

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Disconnect => 1,
            MessageType::Ignore => 2,
            MessageType::Unimplemented => 3,
            MessageType::Debug => 4,
            MessageType::ServiceRequest => 5,
            MessageType::ServiceAccept => 6,
            MessageType::KeyExchangeInit => 20,
            MessageType::NewKeys => 21,
            MessageType::KeyExchangeEcdhInit => 30,
            MessageType::KeyExchangeEcdhReply => 31,
            MessageType::Unknown(value) => value,
        }
    }
}

pub(crate) struct IncomingPacket<'a> {
    pub(crate) sequence_number: u32,
    pub(crate) message_type: MessageType,
    pub(crate) payload: &'a [u8],
}

impl IncomingPacket<'_> {
    #[expect(unused)]
    pub(crate) fn unimplemented(self) -> OutgoingPacket<'static> {
        OutgoingPacket {
            message_type: MessageType::Unimplemented,
            payload: Cow::Owned(self.sequence_number.to_be_bytes().to_vec()),
        }
    }
}

pub(crate) struct OutgoingPacket<'a> {
    #[expect(unused)]
    pub(crate) message_type: MessageType,
    // FIXME: Figure out a way to encode the payload requiring fewer boxes/copies.
    #[expect(unused)]
    pub(crate) payload: Cow<'a, [u8]>,
}

/// An encoded outgoing packet including length field and padding, but
/// excluding encryption and MAC
#[must_use]
struct EncodedPacket<'a> {
    packet: &'a [u8],
    payload: &'a [u8],
}

impl<'a> EncodedPacket<'a> {
    fn new(
        buf: &'a mut Vec<u8>,
        payload: &impl Encode,
        cipher_block_len: usize,
    ) -> Result<Self, Error> {
        let start = buf.len();

        buf.extend_from_slice(&[0, 0, 0, 0]); // packet_length
        buf.push(0); // padding_length

        let payload_start = buf.len();
        payload.encode(buf);
        let payload_range = payload_start..buf.len();

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

        Ok(EncodedPacket {
            packet: &buf[start..],
            payload: &buf[payload_range],
        })
    }

    fn payload(&self) -> &[u8] {
        self.payload
    }

    fn without_mac(&self) -> &[u8] {
        self.packet
    }
}

#[derive(Debug)]
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
