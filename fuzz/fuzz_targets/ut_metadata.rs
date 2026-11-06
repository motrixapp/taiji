#![no_main]

//! fuzz target: the ut_metadata payload.
//!
//! Invariants:
//! 1. `UtMetadata::decode` never panics or hangs on any input (including
//! the bencode value-end structural scan);
//! 2. Any successfully decoded message must re-encode into something
//! decodable and semantically equal (request/reject roundtrip exactly;
//! data keeps total_size/data verbatim).

use libfuzzer_sys::fuzz_target;

use taiji_bt::ut_metadata::UtMetadata;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = UtMetadata::decode(data) {
        if let Ok(encoded) = msg.encode() {
            let re = match UtMetadata::decode(&encoded) {
                Ok(re) => re,
                Err(e) => panic!("encode output must re-decode: {e:?}"),
            };
            assert_eq!(re, msg, "roundtrip must be exact");
        }
    }
});
