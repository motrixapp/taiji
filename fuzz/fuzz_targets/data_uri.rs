#![no_main]

//! fuzz target: the `data:` URI parser of the media key face
//! (`taiji_media::datauri`; the media parser-roster row
//! deliverable 2 — the §10 parse-surface fuzz red line inherits to
//! this parser).
//!
//! Invariants:
//! 1. `parse_data_uri` / `parse_key_data_uri` never panic on any byte
//! input (lossy UTF-8; all arithmetic bounded);
//! 2. on success the decoded payload never exceeds the 64KiB cap;
//! 3. a successful `parse_key_data_uri` always yields exactly 16
//! bytes (wrong lengths are explicit errors, never truncation);
//! 4. parsing is deterministic: the same bytes produce the same
//! verdict.

use libfuzzer_sys::fuzz_target;
use taiji_media::datauri::{MAX_DATA_URI_BYTES, parse_data_uri, parse_key_data_uri};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // Deterministic verdicts.
    let first = parse_data_uri(&text);
    let second = parse_data_uri(&text);
    debug_assert_eq!(first.is_ok(), second.is_ok());
    if let Ok(payload) = first {
        debug_assert!(
            payload.len() <= MAX_DATA_URI_BYTES,
            "the decoded payload respects the 64KiB cap"
        );
        if let Ok(payload2) = second {
            debug_assert_eq!(payload, payload2, "deterministic decode");
        }
    }
    match parse_key_data_uri(&text) {
        Ok(key) => debug_assert_eq!(key.len(), 16, "key bodies are exactly 16 bytes"),
        Err(_) => {}
    }
});
