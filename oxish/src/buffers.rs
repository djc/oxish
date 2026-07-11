use core::{
    future, iter,
    pin::Pin,
    task::{ready, Context, Poll},
};
use std::io;

use proto::{
    crypto::{CryptoError, HandshakeHash, OpeningKey, SealingKey, SecureRandom},
    Completion, Decode, Decoded, Encode, IncomingPacket, MessageType, ProtoError,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::{error, trace};

use crate::Error;

/// The reader and decryption state for an SSH connection
pub(crate) struct ReadState {
    /// Buffer for incoming data from the transport stream
    buf: Vec<u8>,
    /// Full length of the last decoded packet, including packet length and tag
    ///
    /// Set after decoding and decrypting a packet successfully in `poll_packet()`; reduced at
    /// the start of each call to `poll_packet()`.
    last_length: usize,

    sequence_number: u32,
    pub(crate) opener: Option<Box<dyn OpeningKey>>,
}

impl ReadState {
    pub(crate) async fn packet<'a>(
        &'a mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<IncomingPacket<'a>, ()> {
        loop {
            let (sequence_number, packet_length) = match self.poll_packet() {
                Ok(Completion::Complete((sequence_number, packet_length))) => {
                    (sequence_number, packet_length)
                }
                Ok(Completion::Incomplete(_amount)) => {
                    if let Err(error) = self.buffer(stream).await {
                        error!(%error, "failed to buffer from stream");
                        return Err(());
                    }
                    continue;
                }
                Err(error) => {
                    error!(%error, "failed to decrypt packet");
                    return Err(());
                }
            };

            if packet_length.inner > 64 * 1024 {
                error!(packet_length = packet_length.inner, "packet too large");
                return Err(());
            }

            match self.decode_packet(sequence_number, packet_length) {
                Ok(packet) => return Ok(packet),
                Err(error) => {
                    error!(%error, "failed to decode packet");
                    return Err(());
                }
            }
        }
    }

    // This and decode_packet are split because of a borrowck limitation
    fn poll_packet(&mut self) -> Result<Completion<(u32, PacketLength)>, Error> {
        // Compact the internal buffer
        if self.last_length > 0 {
            self.buf.copy_within(self.last_length.., 0);
            self.buf.truncate(self.buf.len() - self.last_length);
            self.last_length = 0;
        }

        let (packet_length, tag_len) = if let Some(opener) = &mut self.opener {
            // The packet length is transmitted in cleartext (authenticated as AAD).
            let Some((length, _)) = self.buf.split_first_chunk() else {
                return Ok(Completion::Incomplete(Some(4)));
            };

            let length_bytes = opener.decrypt_packet_length(self.sequence_number, *length);
            let Decoded {
                value: packet_length,
                next,
            } = PacketLength::decode(&length_bytes)?;
            assert!(next.is_empty());

            let tag_len = opener.tag_len();
            let end = 4 + packet_length.inner as usize;
            let Some((length_data, rest)) = self.buf.split_at_mut_checked(end) else {
                return Ok(Completion::Incomplete(Some(end + tag_len)));
            };

            let Some(tag) = rest.get(..tag_len) else {
                return Ok(Completion::Incomplete(Some(end + tag_len)));
            };

            // Verify and decrypt the packet in place in `buf`. `open_in_place` authenticates
            // the cleartext length field, which stays in `buf` alongside the ciphertext even
            // though it is not itself decrypted.
            opener.open_in_place(self.sequence_number, length_data, tag)?;

            (packet_length, tag_len)
        } else {
            let Some((length, _)) = self.buf.split_at_checked(4) else {
                return Ok(Completion::Incomplete(Some(4)));
            };

            let Decoded {
                value: packet_length,
                next,
            } = PacketLength::decode(length)?;
            assert!(next.is_empty());

            let needed = 4 + packet_length.inner as usize;
            if self.buf.len() < needed {
                return Ok(Completion::Incomplete(Some(needed)));
            }

            (packet_length, 0)
        };

        // Note: this needs to be done AFTER the IO to ensure
        // this async function is cancel-safe
        let sequence_number = self.sequence_number;
        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.last_length = 4 + packet_length.inner as usize + tag_len;
        Ok(Completion::Complete((sequence_number, packet_length)))
    }

    fn decode_packet<'a>(
        &'a self,
        sequence_number: u32,
        packet_length: PacketLength,
    ) -> Result<IncomingPacket<'a>, Error> {
        let payload = self
            .buf
            .get(4..4 + packet_length.inner as usize)
            .ok_or(CryptoError::InvalidLength)?;

        let Decoded {
            value: padding_length,
            next,
        } = PaddingLength::decode(payload)?;

        let payload_len = (packet_length.inner - 1 - padding_length.inner as u32) as usize;
        let Some(payload) = next.get(..payload_len) else {
            return Err(ProtoError::Incomplete(Some(payload_len - next.len())).into());
        };

        let Decoded {
            value: message_type,
            next: payload,
        } = MessageType::decode(payload).map_err(|e| match e {
            ProtoError::Incomplete(_) => ProtoError::InvalidPacket("packet without message type"),
            _ => e,
        })?;

        let Some(next) = next.get(payload_len..) else {
            return Err(
                ProtoError::Unreachable("unable to extract rest after fixed-length slice").into(),
            );
        };

        let Some(_) = next.get(..padding_length.inner as usize) else {
            return Err(
                ProtoError::Incomplete(Some(padding_length.inner as usize - next.len())).into(),
            );
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
        trace!(read, "read from stream");
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

    /// Reset the receive sequence number to zero
    ///
    /// As required by strict key exchange after receiving `SSH_MSG_NEWKEYS`.
    pub(crate) fn reset_sequence_number(&mut self) {
        self.sequence_number = 0;
    }
}

impl Default for ReadState {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(16_384),
            last_length: 0,
            sequence_number: 0,
            opener: None,
        }
    }
}

pub(crate) struct WriteState {
    /// Buffer for encoded but unencrypted packets
    buf: Vec<u8>,

    /// The amount of bytes at the start of `encrypted_buf`` that have already
    /// been sent to the transport stream
    written: usize,

    sequence_number: u32,
    pub(crate) sealer: Option<Box<dyn SealingKey>>,

    /// Source of random bytes for packet padding
    secure_random: &'static dyn SecureRandom,
}

impl WriteState {
    pub(crate) fn new(secure_random: &'static dyn SecureRandom) -> Self {
        Self {
            buf: Vec::with_capacity(16_384),
            written: 0,
            sequence_number: 0,
            sealer: None,
            secure_random,
        }
    }

    pub(crate) fn handle_packet(
        &mut self,
        payload: &impl Encode,
        exchange_hash: Option<&mut HandshakeHash>,
    ) -> Result<(), Error> {
        let start = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0, 0]); // packet_length
        self.buf.push(0); // padding_length

        let payload_start = self.buf.len();
        payload.encode(&mut self.buf);
        let payload_len = self.buf.len() - payload_start;

        // <https://www.rfc-editor.org/rfc/rfc4253#section-6>
        //
        // Note that the length of the concatenation of 'packet_length', 'padding_length',
        // 'payload', and 'random padding' MUST be a multiple of the cipher block size or 8,
        // whichever is larger. This constraint MUST be enforced, even when using stream ciphers.
        //
        // For AEAD ciphers (like aes128-gcm@openssh.com, RFC 5647) the 'packet_length' field is
        // transmitted in cleartext and is excluded from the block-aligned region;
        // `unencrypted_prefix` is 4 in that case and 0 otherwise.

        let block_size = Ord::max(
            match &self.sealer {
                Some(sealer) => sealer.block_len(),
                None => 0,
            },
            8,
        );

        let unencrypted_prefix = match &self.sealer {
            Some(_) => 4,
            None => 0,
        };

        let region = self.buf.len() - start - unencrypted_prefix;
        // The minimum size of a packet is 16 bytes
        let min_padding = Ord::max(region.next_multiple_of(block_size), 16) - region;
        // Padding is at least 4 bytes
        let padding_len = match min_padding < 4 {
            true => min_padding + block_size,
            false => min_padding,
        };

        let padding_start = self.buf.len();
        self.buf.extend(iter::repeat_n(0, padding_len)); // padding
        if let Some(padding) = self.buf.get_mut(padding_start..) {
            if self.secure_random.fill(padding).is_err() {
                return Err(ProtoError::Unreachable("failed to get random padding").into());
            }
        }

        if let Some(sealer) = &mut self.sealer {
            self.buf.extend(iter::repeat_n(0, sealer.tag_len())); // tag
        }

        let Some(packet) = self.buf.get_mut(start..) else {
            return Err(ProtoError::Unreachable("unable to reslice packet").into());
        };

        let Some((packet_length_dst, rest)) = packet.split_first_chunk_mut::<4>() else {
            return Err(ProtoError::Unreachable("unable to split packet length").into());
        };

        // packet_length covers padding_length (1 byte), payload and padding
        *packet_length_dst = ((1 + payload_len + padding_len) as u32).to_be_bytes();

        let Some((padding_length_dst, padded_payload)) = rest.split_first_chunk_mut::<1>() else {
            return Err(ProtoError::Unreachable("unable to split padding length").into());
        };

        padding_length_dst[0] = padding_len as u8;

        if let Some(exchange_hash) = exchange_hash {
            if let Some(payload) = padded_payload.get(..payload_len) {
                exchange_hash.prefixed(payload);
            }
        }

        if let Some(sealer) = &mut self.sealer {
            let Some((body, tag)) = packet.split_at_mut_checked(5 + payload_len + padding_len)
            else {
                return Err(ProtoError::Unreachable("unable to split tag from packet").into());
            };

            sealer.seal_in_place(self.sequence_number, body, tag)?;
        }

        self.sequence_number = self.sequence_number.wrapping_add(1);
        Ok(())
    }

    pub(crate) fn poll_write_to(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Poll<Result<(), Error>> {
        let Some(buf) = self.buf.get(self.written..) else {
            return Poll::Ready(Err(Error::from(CryptoError::InvalidLength)));
        };

        self.written += ready!(Pin::new(stream).poll_write(cx, buf))?;
        if self.written == self.buf.len() {
            self.buf.clear();
            self.written = 0;
        }

        Poll::Ready(Ok(()))
    }

    pub(crate) fn encoder(&mut self) -> Encoder<'_> {
        Encoder {
            write: self,
            buffered: false,
        }
    }

    pub(crate) fn encoded(&mut self, payload: &impl Encode) -> &[u8] {
        payload.encode(&mut self.buf);
        &self.buf
    }

    /// Clear the outgoing buffer after writing its contents to the stream directly
    pub(crate) fn clear(&mut self) {
        self.buf.clear();
    }

    /// Reset the send sequence number to zero
    ///
    /// As required by strict key exchange after sending `SSH_MSG_NEWKEYS`.
    pub(crate) fn reset_sequence_number(&mut self) {
        self.sequence_number = 0;
    }
}

pub(crate) struct Encoder<'a> {
    write: &'a mut WriteState,
    pub(crate) buffered: bool,
}

impl Encoder<'_> {
    pub(crate) fn enqueue(&mut self, payload: &impl Encode) -> Result<(), Error> {
        self.buffered = true;
        self.write
            .handle_packet(payload, None)
            .inspect_err(|error| {
                error!(%error, ?payload, "failed to encode packet");
            })
    }

    pub(crate) async fn flush(self, stream: &mut (impl AsyncWrite + Unpin)) -> Result<(), ()> {
        if !self.buffered {
            return Ok(());
        }

        future::poll_fn(|cx| self.write.poll_write_to(cx, stream))
            .await
            .map_err(|error| {
                error!(%error, "failed to write queued packets to stream");
            })
    }
}

#[derive(Debug)]
struct PacketLength {
    inner: u32,
}

impl Decode<'_> for PacketLength {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value, next } = u32::decode(bytes)?;
        if value > 256 * 1024 {
            return Err(ProtoError::InvalidPacket("packet too large"));
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
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value, next } = u8::decode(bytes)?;
        if value < 4 {
            return Err(ProtoError::InvalidPacket("padding too short"));
        }

        Ok(Decoded {
            value: Self { inner: value },
            next,
        })
    }
}
