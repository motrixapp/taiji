#![no_main]

//! fuzz target: the ngosang/trackerslist parser.
//!
//! Invariants:
//! 1. `parse_trackerslist` never panics or hangs on any UTF-8 text input
//! (`lines()` + `trim` + prefix checks; no index arithmetic, no split
//! loop to blow up);
//! 2. Every output URL is non-empty, starts with no `#`, and has no
//! leading/trailing whitespace (the format contract);
//! 3. Total output bytes <= input bytes (no allocation amplification).

use libfuzzer_sys::fuzz_target;

use taiji_bt::tracker::trackerslist::parse_trackerslist;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(&data);
    let urls = parse_trackerslist(&s);
    let mut total = 0usize;
    for u in &urls {
        assert!(!u.is_empty(), "parsed url must be non-empty");
        assert!(!u.starts_with('#'), "comment lines must be skipped");
        assert_eq!(u.trim(), u.as_str(), "urls must be trimmed");
        total += u.len();
    }
    assert!(
        total <= data.len(),
        "output bytes {total} must not exceed input {}",
        data.len()
    );
});
