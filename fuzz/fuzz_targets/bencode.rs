#![no_main]

//! bencode fuzz target.
//!
//! Invariants:
//! 1. `decode` / `decode_with_info_span` never panic or hang on any input
//! (depth guard [`bencode::MAX_DEPTH`] + size guards: string lengths
//! bounded by the input length, checked arithmetic on
//! integer/string-length accumulation);
//! 2. A successful decode implies canonical bencode, so
//! `encode(decode(x)) == x` (the decoder rejects every non-canonical
//! form, see the bencode module docs; a tripped assertion means a
//! strictness hole — a crash-level defect).

use libfuzzer_sys::fuzz_target;

use taiji_bt::bencode;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = bencode::decode(data) {
        if let Ok(encoded) = bencode::encode(&value) {
            assert_eq!(
                encoded, data,
                "decode succeeded but re-encode diverged: strictness hole"
            );
        } else {
            panic!("encode of a decoded value must always succeed");
        }
    }
    let _ = bencode::decode_with_info_span(data);
});
