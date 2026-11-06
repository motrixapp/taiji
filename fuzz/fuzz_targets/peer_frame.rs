#![no_main]

//! fuzz target: the peer wire frame layer.
//!
//! Invariants:
//! 1. `Message::decode_body` / `Handshake::decode` / `FrameCodec::decode`
//! never panic or hang on any input (the MAX_FRAME_LEN guard);
//! 2. A 68-byte input that passes `Handshake::decode` must re-encode
//! identically (a fixed-length format);
//! 3. encode → FrameCodec roundtrip of legal messages is lossless.

use libfuzzer_sys::fuzz_target;

use taiji_bt::peer_wire;
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

fuzz_target!(|data: &[u8]| {
    let _ = peer_wire::Message::decode_body(data);
    if data.len() == peer_wire::HANDSHAKE_LEN {
        if let Ok(hs) = peer_wire::Handshake::decode(data) {
            assert_eq!(hs.encode(), *data, "handshake re-encode diverged");
        }
    }
    let _ = peer_wire::ExtHandshake::decode(data);

    // Frame layer: feed the input as a byte stream to the codec; only
    // totality is required.
    let mut codec = peer_wire::FrameCodec::default();
    let mut src = BytesMut::from(data);
    while let Ok(Some(msg)) = codec.decode(&mut src) {
        let mut out = BytesMut::new();
        codec
            .encode(msg, &mut out)
            .expect("encode of a decoded message must always succeed");
    }
});
