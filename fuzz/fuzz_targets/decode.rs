#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::{
    ChannelClose, ChannelData, ChannelEof, ChannelOpen, ChannelRequest, Completion, Disconnect,
    EcdhKeyExchangeInit, KeyExchangeInit, MessageType, NewKeys, ReadState,
    ServiceRequest, UserAuthRequest,
};

fuzz_target!(|data: &[u8]| {
    let mut state = ReadState::default();
    state.buf.extend_from_slice(data);

    let Ok(Completion::Complete((sequence_number, packet_length))) = state.poll_packet() else {
        return;
    };

    let Ok(packet) = state.decode_packet(sequence_number, packet_length) else {
        return;
    };

    match packet.message_type {
        MessageType::Disconnect => _ = Disconnect::try_from(packet),
        MessageType::ServiceRequest => _ = ServiceRequest::try_from(packet),
        MessageType::KeyExchangeInit => _ = KeyExchangeInit::try_from(packet),
        MessageType::NewKeys => _ = NewKeys::try_from(packet),
        MessageType::KeyExchangeEcdhInit => _ = EcdhKeyExchangeInit::try_from(packet),
        MessageType::UserAuthRequest => _ = UserAuthRequest::try_from(packet),
        MessageType::ChannelOpen => _ = ChannelOpen::try_from(packet),
        MessageType::ChannelData => _ = ChannelData::try_from(packet),
        MessageType::ChannelEof => _ = ChannelEof::try_from(packet),
        MessageType::ChannelClose => _ = ChannelClose::try_from(packet),
        MessageType::ChannelRequest => _ = ChannelRequest::try_from(packet),
        _ => {}
    }
});
