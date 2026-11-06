#![no_main]

//! fuzz target: the ffprobe JSON structuring surface
//! (`taiji_media::ffprobe::FfprobeReport::parse`; the ffprobe-json
//! parser-roster row).
//!
//! Invariants:
//! 1. `parse` never panics on any byte input — non-JSON or
//! wrong-shaped input is an explicit `taiji.media.ffmpeg_parse`
//! error (serde_json's recursion limit bounds depth, so hostile
//! nesting errors out instead of overflowing the stack);
//! 2. success implies the derived accessors stay consistent:
//! `stream_summary()` covers every stream, and a present duration
//! is a finite f64;
//! 3. re-serializing a successful parse succeeds (the doctor `--json`
//! face round-trips through the same structures).

use libfuzzer_sys::fuzz_target;
use taiji_media::ffprobe::FfprobeReport;

fuzz_target!(|data: &[u8]| {
    match FfprobeReport::parse(data) {
        Ok(report) => {
            assert_eq!(report.stream_summary().len(), report.streams.len());
            if let Some(duration) = report.duration_seconds() {
                assert!(duration.is_finite());
                assert!(duration >= 0.0);
            }
            assert!(serde_json::to_string(&report).is_ok());
        }
        Err(e) => {
            assert_eq!(e.code(), "taiji.media.ffmpeg_parse");
        }
    }
});
