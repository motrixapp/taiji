#![no_main]

//! fuzz target: the `-progress pipe:1` line-protocol parser
//! (`taiji_media::progress::ProgressParser`; the parser-roster row).
//!
//! Invariants:
//! 1. `feed`/`finish` never panic on any byte input (invalid UTF-8 is
//! converted lossily per line; unparseable values degrade to `None`
//! on the typed accessors — never an error);
//! 2. chunk-size invariance: feeding the input in odd-sized chunks
//! yields exactly the same snapshot count as a one-shot feed
//! (partial-line buffering is invisible to the caller);
//! 3. a snapshot with `end == true` can only come from a
//! `progress=end` line (its `fields` map carries it verbatim);
//! 4. every parsed numeric field, when present, is non-negative
//! (negative/unparseable values were dropped, not wrapped).

use libfuzzer_sys::fuzz_target;
use taiji_media::progress::ProgressParser;

fuzz_target!(|data: &[u8]| {
    // One-shot.
    let mut whole = ProgressParser::new();
    let mut snapshots = whole.feed(data);
    snapshots.extend(whole.finish());

    // Chunked (odd size to straddle line boundaries).
    let mut chunked = ProgressParser::new();
    let mut count = 0;
    for chunk in data.chunks(7) {
        count += chunked.feed(chunk).len();
    }
    count += chunked.finish().len();
    assert_eq!(count, snapshots.len(), "chunk-size invariance violated");

    for snap in &snapshots {
        if snap.end {
            assert_eq!(snap.fields.get("progress").map(String::as_str), Some("end"));
        }
        for value in [
            snap.frame,
            snap.total_size,
            snap.out_time_us,
            snap.dup_frames,
            snap.drop_frames,
        ] {
            if let Some(v) = value {
                assert!(v <= i64::MAX as u64);
            }
        }
        if let Some(speed) = snap.speed_x {
            assert!(speed.is_finite());
        }
        if let Some(fps) = snap.fps {
            assert!(fps.is_finite());
        }
    }
});
