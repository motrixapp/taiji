#![no_main]

//! fuzz target: whole-document byte-stream parsing of metalink v4
//! (RFC 5854) via `taiji_metalink::parse`.
//!
//! Invariants:
//! 1. `taiji_metalink::parse` never panics on any input — structural
//! errors / limit overruns / DOCTYPE are explicit errors (legal exits,
//! not crashes);
//! 2. Success implies `files` is non-empty (zero entries is a hard error),
//! `<file>` <= 10k, and `<url>` <= 64 per file (the spec caps are
//! enforced at parse time; a successful result cannot exceed them);
//! 3. Success implies every known-kind hash hex passed parse validation
//! (even length / legal hex / known-kind digest length), so `decode`
//! always works.

use libfuzzer_sys::fuzz_target;

use taiji_metalink::hash::HashKind;

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = taiji_metalink::parse(data) else {
        // Explicit rejection (structure/encoding/limits/version downgrade)
        // is a legal exit.
        return;
    };

    // Caps are hard errors at parse time; a successful result cannot
    // exceed them.
    assert!(
        doc.files.len() <= taiji_metalink::MAX_FILES,
        "files {} must not exceed the cap",
        doc.files.len()
    );
    assert!(!doc.files.is_empty(), "success implies at least one file");
    for file in &doc.files {
        assert!(
            file.urls.len() <= taiji_metalink::MAX_URLS_PER_FILE,
            "urls {} of {:?} must not exceed the cap",
            file.urls.len(),
            file.name
        );
        for hash in &file.hashes {
            assert!(
                hash.decode().is_some(),
                "parse-validated hash must always decode"
            );
            if let HashKind::Other(_) = hash.kind() {
                // Unknown kind: no verification surface (explicitly absent,
                // not faked).
            } else {
                assert!(
                    hash.verify(b"fuzz").is_ok(),
                    "known-kind hash must be verifiable"
                );
            }
        }
    }
});
