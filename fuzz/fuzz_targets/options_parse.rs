#![no_main]

//! fuzz target: the taiji-core option-string parsers.
//!
//! Covers `parse_size` (size literals) and `parse_select_file` (BEP53
//! 1-based interval lists). Invariants:
//! 1. No text input panics;
//! 2. `parse_size` Some implies a finite value with no sign flip;
//! 3. `parse_select_file` Ok implies 0-based, strictly increasing output
//! (deduplicated order), all < the domain cap (the 0-based projection
//! of the aria2 1..=1048576 domain).

use libfuzzer_sys::fuzz_target;

use taiji_core::session::{parse_select_file, parse_size};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // parse_size: Some implies no panic and no overflow flip (inside
    // u64 — checked_mul; value-domain validation belongs to option
    // acceptance, not parsing). Wired in: the import
    // shipped unused (the cargo-check gate's warning was the tell)
    // while this doc block claimed the coverage — the declared face
    // now actually runs.
    if let Some(v) = parse_size(&s) {
        // A suffix multiplier never decreases the value; an accepted
        // digit string is < 2^64 (u64::MAX itself must parse plain).
        let plain = s.trim_end_matches(['k', 'K', 'm', 'M', 'g', 'G']);
        if let Ok(n) = plain.parse::<u64>() {
            let mult = match s.chars().last() {
                Some('k' | 'K') => 1024u64,
                Some('m' | 'M') => 1024 * 1024,
                Some('g' | 'G') => 1024 * 1024 * 1024,
                _ => 1,
            };
            let expect = n.checked_mul(mult);
            assert_eq!(Some(v), expect, "parse_size agrees with its parts");
        }
    }
    if let Ok(idxs) = parse_select_file(&s) {
        // Output is 0-based (the 1-based → 0-based conversion converges at
        // this single point), strictly increasing in expansion order (the
        // projection of the parser's built-in dedup + sorting); the domain
        // cap 1-based 1048576 → 0-based < 1048576.
        for (prev, cur) in idxs.iter().zip(idxs.iter().skip(1)) {
            assert!(prev < cur, "expansion order strictly increasing: {prev} !< {cur}");
        }
        for i in &idxs {
            assert!(*i < 1_048_576, "0-based domain upper bound (aria2 1..=1048576)");
        }
    }
});
