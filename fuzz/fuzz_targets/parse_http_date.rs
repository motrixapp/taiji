#![no_main]

//! fuzz target for `parse_http_date` (RFC 7231 IMF-fixdate et al.).
//!
//! Invariant: no text input panics; Some implies a sane timestamp
//! magnitude (|ts| < 2^40 — within roughly ten thousand years, no absurd
//! values from parse misalignment).

use libfuzzer_sys::fuzz_target;

use taiji_http::remotetime::parse_http_date;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Some(ts) = parse_http_date(&s) {
        assert!(ts.abs() < (1i64 << 40), "timestamp magnitude sane: {ts}");
    }
});
