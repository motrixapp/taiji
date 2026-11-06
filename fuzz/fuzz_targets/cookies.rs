#![no_main]

//! fuzz target: the `--load-cookies` Netscape cookie-file parser.
//!
//! Invariants:
//! 1. `from_netscape_bytes` never panics on any input — <= 1MiB parses
//! leniently (bad lines skipped), over the limit is an explicit error
//! (a legal exit, not a crash);
//! 2. jar size <= input line count (line-by-line parsing, no allocation
//! amplification);
//! 3. a `header_for` Cookie header never contains control characters
//! (0x00-0x1F/0x7F) — the Cookie-header injection surface is closed
//! (`;` separators are excluded at the pairing-validation layer).

use libfuzzer_sys::fuzz_target;

use taiji_segment::cookies::CookieJar;

fuzz_target!(|data: &[u8]| {
    let jar = match CookieJar::from_netscape_bytes(data) {
        Ok(j) => j,
        // Explicit rejection over the 1MiB cap is a legal exit.
        Err(_) => return,
    };

    // Count <= lines (each cookie consumes at least one line).
    let line_count = data.iter().filter(|b| **b == b'\n').count() + 1;
    assert!(
        jar.len() <= line_count,
        "cookies {} must not exceed input lines {line_count}",
        jar.len()
    );

    // Probe URLs of several shapes: domain tail-match / host-only / IP
    // host / path boundaries.
    let probes = [
        "https://a.example/",
        "http://sub.a.example/deep/x",
        "https://127.0.0.1:8080/p?q=1",
        "http://a.example",
    ];
    for p in probes {
        let Ok(url) = url::Url::parse(p) else {
            continue;
        };
        if let Some(header) = jar.header_for(&url) {
            assert!(
                !header.bytes().any(|b| b < 0x20 || b == 0x7f),
                "cookie header must be control-char free: {header:?}"
            );
            assert!(!header.is_empty(), "empty header must be None");
        }
    }
});
