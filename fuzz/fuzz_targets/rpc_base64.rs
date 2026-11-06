#![no_main]

//! fuzz target: the RPC addTorrent base64 decoder (an in-house parsing
//! surface under the "every parser gets a fuzz target" rule).
//!
//! Invariants:
//! 1. `base64::decode` never panics on any input (length/padding/alphabet
//! checks all short-circuit through Option — no out-of-bounds indexing);
//! 2. A successful decode implies the output length is bounded by the
//! RFC 4648 §4 shape: within `(len/4)*3` (the final padded group falls
//! back at most 2 bytes).
//!
//! A canonical roundtrip assertion is intentionally omitted: the decoder
//! accepts non-canonical trailing bits (e.g. "Zh==", a nonzero
//! final-group remainder) — the same leniency as aria2 (reference
//! base64.cc does not validate trailing bits), so a failed roundtrip is
//! not a defect.

use libfuzzer_sys::fuzz_target;

use taiji_rpc::base64;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(&data);
    if let Some(decoded) = base64::decode(&s) {
        assert!(
            decoded.len() <= data.len() / 4 * 3 + 2,
            "decoded length exceeded RFC 4648 bound"
        );
    }
});
