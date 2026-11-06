#![no_main]

//! Fuzz target for the top-level `Metainfo::parse`.
//!
//! Invariants:
//! 1. No input panics (bencode depth cap 50 + filetree sanitization + the
//! piece-length domain checks are total);
//! 2. A successful parse has a piece length in the legal domain (> 0) and
//! `resident_estimate_bytes` never panics or overflows into a distorted
//! value (the estimate is a rough upper bound, not a lower bound on the
//! raw bytes, but it must be finite and >= each component).

use libfuzzer_sys::fuzz_target;

use taiji_domain::metainfo::Metainfo;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Metainfo::parse(data) {
        assert!(m.meta.piece_length > 0, "piece_length in domain");
        let est = m.resident_estimate_bytes();
        assert!(est >= m.v1_pieces.len() * 20, "estimate >= v1 hash-string component");
        assert!(est < usize::MAX / 2, "estimate finite, no overflow shape");
        // Non-empty path assertion for file rows (sanitized paths still
        // need non-empty members).
        for f in &m.meta.files {
            if !f.padding {
                assert!(!f.path.as_os_str().is_empty(), "non-padding file paths are non-empty");
            }
        }
    }
});
