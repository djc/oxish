use oxish_proto::{Completion, IncomingPacket, ProtoError, ReadState};

#[test]
fn padding_too_large() {
    const PACKET: &[u8] = include_bytes!("padding-too-large.bin");
    let mut state = ReadState::default();
    assert_eq!(
        decode(PACKET, &mut state).unwrap_err(),
        ProtoError::InvalidPacket("padding length exceeds packet length")
    );
}

fn decode<'a>(bytes: &[u8], state: &'a mut ReadState) -> Result<IncomingPacket<'a>, ProtoError> {
    state.buf.extend_from_slice(bytes);
    match state.poll_packet()? {
        Completion::Complete((sequence_number, packet_length)) => {
            state.decode_packet(sequence_number, packet_length)
        }
        Completion::Incomplete(needed) => Err(ProtoError::Incomplete(needed)),
    }
}
