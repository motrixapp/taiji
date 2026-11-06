#![no_main]

//! DHT KRPC message fuzz target.
//!
//! Invariants:
//! 1. [`taiji_bt::dht::decode_message`] never panics or hangs on any input
//! (bencode-layer depth/size guards + per-field type/length validation
//! at the message layer);
//! 2. A successful decode that can be encoded round-trips internally,
//! `decode(encode(m)) == m` (the message layer is a schema projection:
//! unknown fields are ignored, as in aria2, so `encode(decode(x)) == x`
//! does not hold and the assertion runs in the inner direction). The
//! single exemption is the BEP32 send/receive asymmetry: the decoder
//! must accept hybrid 6/18-byte values lists ("must be able to properly
//! parse hybrid "values" lists") while the encoder refuses to send them
//! (MixedAddressFamilies; the engine filters by the request's network
//! layer before encoding). decode OK / encode Err on this path is
//! specified behavior, not a defect; any other encode failure is a
//! crash.

use libfuzzer_sys::fuzz_target;

use taiji_bt::dht;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = dht::decode_message(data) {
        let re_encoded = match dht::encode_message(&msg) {
            Ok(bytes) => bytes,
            // BEP32 send/receive asymmetry: the decoder accepts hybrid
            // values lists (interop with old peers, spec-mandated) while
            // the encoder rejects mixed families (MixedAddressFamilies,
            // see the dht::message module docs). The nodes side never
            // hits this path — the two keys (nodes/nodes6) decode into a
            // canonical order (v4 first, v6 after), and mixed-family nodes
            // encode sorted into the two keys, closing the roundtrip.
            Err(dht::DhtError::MixedAddressFamilies) => return,
            Err(e) => panic!("decode succeeded but encode failed: {e:?} (msg={msg:?})"),
        };
        let decoded_again = match dht::decode_message(&re_encoded) {
            Ok(m) => m,
            Err(e) => panic!("re-decode failed: {e:?} (wire={re_encoded:?})"),
        };
        assert_eq!(
            decoded_again, msg,
            "inner roundtrip diverged: wire={re_encoded:?}"
        );
    }
});
