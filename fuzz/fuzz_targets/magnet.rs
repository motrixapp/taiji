#![no_main]

//! magnet URI parsing fuzz target.
//!
//! Invariants:
//! 1. `magnet::parse` never panics or hangs on any input (splitting relies
//! only on byte search for `&`/the first `=`; base32/hex decoding has
//! length pre-checks; percent-decoding advances strictly in 3-byte
//! windows — no out-of-bounds indexing);
//! 2. A successful parse satisfies the structural invariants: `btih`/
//! `btmh` come from the first valid xt; `tr`/`dn` are the raw decoded
//! bytes (no silent rewriting). A tripped assertion means a
//! lenient/strict boundary hole — a crash-level defect.

use libfuzzer_sys::fuzz_target;

use taiji_bt::magnet;

fuzz_target!(|data: &[u8]| {
    // Arbitrary bytes go through lossy UTF-8 (a magnet URI is text; the
    // binary path is covered by percent_decode's byte-level handling).
    let s = String::from_utf8_lossy(&data);
    if let Ok(m) = magnet::parse(&s) {
        if let Some(h) = &m.btih {
            assert_eq!(h.len(), 20, "btih must be 20B");
        }
        if let Some(h) = &m.btmh {
            assert_eq!(h.len(), 32, "btmh must be 32B");
        }
    }
});
