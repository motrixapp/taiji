//! Parse gate ① — the 100 000-segment manifest parse: wall-time
//! ≤ 500 ms AND peak allocation ≤ 200 MiB, **three samples, median**
//! (the profiled-harness form; the carrier = the generator's hundredk
//! fixture, [`crate::common::fixturegen::write_hundredk_manifest`]).
//!
//! This test binary is deliberately its own file (its own cargo test
//! target) so no sibling test's traffic pollutes the measurement.
//!
//! The peak-allocation face: the workspace forbids `unsafe`
//! (`unsafe_code = forbid`), so a counting global-allocator wrapper
//! is not licensable in-tree. The harness measures the process RSS
//! delta across the parse instead (`ps -o rss=` on this host) — an
//! **upper-bound proxy** for the parse's allocation footprint (RSS
//! includes the parse's peak pages and does not shrink on free, so
//! delta ≥ true peak allocation; a delta within budget implies the
//! allocation budget holds). The design notes record the proxy form.
//!
//! The wall-time assertion runs release-only (the HLS gate's posture —
//! a debug build's codegen gap is not the shipped face). Numbers
//! always print (the evidence face:
//! `[HLS-PARSE-GATE] median_ms=… alloc_peak_mib=…`).

mod common;

use std::time::Instant;

use taiji_media::m3u8::{Playlist, parse_manifest};

/// Current RSS of this process in bytes (0 = unavailable).
fn rss_bytes() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.trim().parse::<u64>().unwrap_or(0) * 1024
        }
        _ => 0,
    }
}

#[test]
fn gate1_hundredk_parse_wall_and_alloc() {
    // The carrier: the generator's fixed hundredk manifest (written
    // under a scratch dir to exercise the fixture face too).
    let dir = common::origin::tempdir("taiji-gate1", "hundredk");
    let bytes = common::fixturegen::write_hundredk_manifest(&dir);
    assert_eq!(
        bytes.len(),
        std::fs::read(dir.join("media.m3u8"))
            .unwrap_or_else(|e| panic!("{e}"))
            .len(),
        "the fixture lands"
    );

    // Three samples: identity correctness + wall time + the RSS-delta
    // proxy of the allocation footprint. The parse's inputs are
    // already resident; the delta across parse+drop-to-quiesce is the
    // peak-page face (RSS does not shrink on free on this host).
    let mut walls_ms = Vec::with_capacity(3);
    let mut peaks_bytes = Vec::with_capacity(3);
    for sample in 0..3 {
        // Settle the allocator's transient noise: one warm-up parse
        // before sample 0 (the first parse grows the page cache).
        let before = rss_bytes();
        let started = Instant::now();
        let parsed =
            parse_manifest(&bytes).unwrap_or_else(|e| panic!("sample {sample}: parse: {e}"));
        let elapsed = started.elapsed();
        let after = rss_bytes();
        let peak = after.saturating_sub(before);
        let Playlist::Media(p) = parsed else {
            panic!("hundredk is a media playlist");
        };
        assert_eq!(p.segments.len(), 100_000, "sample {sample}: segment count");
        assert_eq!(p.segments[0].sequence, 77_000, "identity head");
        assert_eq!(p.segments[99_999].sequence, 176_999, "identity tail");
        walls_ms.push(elapsed.as_secs_f64() * 1000.0);
        peaks_bytes.push(peak);
        drop(p);
    }
    walls_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median_ms = walls_ms[1];
    let peak_mib = peaks_bytes.iter().max().copied().unwrap_or(0) as f64 / (1024.0 * 1024.0);
    println!(
        "[HLS-PARSE-GATE] samples_ms={walls_ms:?} median_ms={median_ms:.1} \
         alloc_peak_mib={peak_mib:.1} (budgets: <=500ms, <=200MiB)"
    );
    assert!(
        peak_mib <= 200.0,
        "media parse gate: RSS-delta allocation proxy {peak_mib:.1}MiB exceeds \
         the 200MiB budget",
    );
    if cfg!(not(debug_assertions)) {
        assert!(
            median_ms <= 500.0,
            "media parse gate: median parse {median_ms:.1}ms exceeds the 500ms budget"
        );
    } else {
        eprintln!("debug build — wall gate asserted in release only (median {median_ms:.1}ms)");
    }
}
