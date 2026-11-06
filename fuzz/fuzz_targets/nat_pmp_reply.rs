//! fuzz target: NAT-PMP reply decoding.
//!
//! Contract: `decode_reply` is total over any byte string (Ok/Err, never
//! panic or UB) — the same implementation serves the byte-exact RFC 6886
//! unit-test vectors, preventing behavior drift.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decodability is not guaranteed for arbitrary input, but panics never
    // happen.
    let _ = taiji_io::nat::natpmp::decode_reply(data);
});
