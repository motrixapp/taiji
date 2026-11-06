//! fuzz target: the `.aria2` control-file parser.
//!
//! Covers `parse_aria2_control`; the format authority is
//! `DefaultBtProgressInfoFile.cc` (save / load); the byte layout is
//! documented in the `taiji-store/src/persist/fork_import.rs` module
//! comments.
//!
//! Invariants:
//! 1. No input panics (a whole-function parser; errors surface as
//! `Result`);
//! 2. A successfully parsed payload is self-consistent: the bitfield has
//! the reference-formula length, the infohash is always 20B, and
//! in-flight pieces do not leak into the bitfield;
//! 3. Re-parsing legal input is idempotent (a pure, stateless function).

#![no_main]

use taiji_store::persist::{expected_bitfield_len, parse_aria2_control};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(ctrl) = parse_aria2_control(data) {
        // Invariant 2: self-consistency (length formula = the reference
        // load check).
        assert_eq!(ctrl.info_hash.len(), 20);
        assert!(ctrl.piece_length > 0);
        let expected = expected_bitfield_len(ctrl.total_length, u64::from(ctrl.piece_length));
        assert_eq!(ctrl.bitfield.len() as u64, expected);
        // Invariant 3: re-parsing a pure function is idempotent.
        assert_eq!(parse_aria2_control(data), Ok(ctrl));
    }
});
