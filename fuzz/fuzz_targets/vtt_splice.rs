#![no_main]

//! fuzz target: the WebVTT cue parser + timeline splice of the
//! subtitle sidecar line (`taiji_media::vtt`; parse-surface fuzz red line:
//! the splice implements cue-level parsing with timestamp rebasing,
//! so the fuzz target is mandatory).
//!
//! Invariants:
//! 1. `parse_vtt` never panics on any byte input (lossy UTF-8; all
//! cue/payload caps enforced as explicit errors);
//! 2. on success every cue satisfies `start ≤ end` and the cue counts
//! respect the per-segment cap;
//! 3. `splice_timeline` over fuzzed segment cue sets never panics
//! (checked arithmetic on the ms timeline), and on success yields
//! a start-sorted timeline within the total-cue cap;
//! 4. both faces are deterministic: the same bytes produce the same
//! verdict.

use libfuzzer_sys::fuzz_target;
use taiji_media::vtt::{self, MAX_CUES_PER_SEGMENT, SpliceOutcome};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // Deterministic parse verdicts.
    let first = vtt::parse_vtt(&text);
    let second = vtt::parse_vtt(&text);
    debug_assert_eq!(first.is_ok(), second.is_ok());
    if let Ok(cues) = first {
        debug_assert!(cues.len() <= MAX_CUES_PER_SEGMENT);
        for cue in &cues {
            debug_assert!(cue.start_ms <= cue.end_ms, "cue window is well-ordered");
            debug_assert!(!cue.lines.is_empty(), "cues carry a payload");
        }
        if let Ok(cues2) = second {
            debug_assert_eq!(cues, cues2, "deterministic parse");
        }
        // Splice a two-segment timeline from the same fuzzed cue set
        // (the rebasing arithmetic is the fuzz surface).
        let segments = vec![(0usize, cues.clone(), 2000u64), (1, cues, 3000)];
        if let Ok(SpliceOutcome::Complete(joined)) = vtt::splice_timeline(&segments) {
            let mut sorted = joined.clone();
            sorted.sort_by_key(|c| c.start_ms);
            debug_assert_eq!(joined, sorted, "spliced timeline is start-sorted");
            // Rendering the product must round-trip through the parser
            // without panicking too.
            let rendered = vtt::render_sidecar(&joined);
            let _ = vtt::parse_vtt(&rendered);
        }
    }
});
