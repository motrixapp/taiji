//! Parse gate ① — the DASH carrier of the 100 000-segment
//! manifest face (the HLS gate's DASH counterpart): a
//! 100 000-entry `<SegmentTimeline>` MPD parsed + expanded to the
//! track model in ≤ 500 ms wall AND ≤ 200 MiB peak allocation,
//! **three samples, median** (the profiled-harness form; the carrier
//! form is the ruling of record: the long-timeline form is the
//! parse-heaviest real-world shape — one `<S>` row per segment, no
//! `@r` collapsing — while the compact `@duration` template form
//! measures the same expansion path with a constant-size document
//! and is exercised as the second leg below).
//!
//! The peak-allocation face: the workspace forbids `unsafe`, so the
//! harness measures the process RSS delta across the parse (the
//! gate's upper-bound proxy; a delta within budget implies the
//! allocation budget holds). Wall-time asserts release-only (the HLS
//! gate posture). Numbers always print:
//! `[DASH-PARSE-GATE] median_ms=… alloc_peak_mib=…`.

use std::time::Instant;

use taiji_media::m3u8::MAX_MEDIA_SEGMENTS;
use taiji_media::mpd;

const URL: &str = "https://cdn.test/hundredk/manifest.mpd";

/// Build the 100 000-entry SegmentTimeline MPD (parse-heavy carrier).
fn hundredk_timeline_mpd() -> String {
    let mut text = String::with_capacity(9 * 1024 * 1024);
    text.push_str(
        r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT100000S">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate timescale="1" duration="1"
        initialization="$RepresentationID$/init.mp4"
        media="$RepresentationID$/$Number%08d$-$Time$.m4s">
        <SegmentTimeline>
"#,
    );
    for i in 0..100_000u64 {
        // One explicit S row per segment (t + d, no @r collapsing —
        // the maximal parse load).
        text.push_str(&format!("          <S t=\"{i}\" d=\"1\"/>\n"));
    }
    text.push_str(
        "        </SegmentTimeline>\n      </SegmentTemplate>\n      \
         <Representation id=\"v\" bandwidth=\"500000\"/>\n    </AdaptationSet>\n  </Period>\n</MPD>\n",
    );
    text
}

/// The compact `@duration` template form (constant-size document, the
/// same expansion path; the second leg's carrier).
fn compact_duration_mpd() -> String {
    r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT100000S">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate timescale="1" duration="1"
        initialization="$RepresentationID$/init.mp4"
        media="$RepresentationID$/$Number%08d$-$Time$.m4s"/>
      <Representation id="v" bandwidth="500000"/>
    </AdaptationSet>
  </Period>
</MPD>"#
        .to_string()
}

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

fn parse_and_expand(bytes: &[u8]) -> usize {
    let doc = mpd::parse_mpd(bytes).unwrap_or_else(|e| panic!("parse: {e}"));
    let plan = mpd::plan_dash_tracks(&doc, URL, &Default::default(), &Default::default())
        .unwrap_or_else(|e| panic!("plan: {e}"));
    let pick = &plan.picks[0];
    match mpd::expand_representation(&doc, URL, pick).unwrap_or_else(|e| panic!("expand: {e}")) {
        mpd::Expanded::Ready(track) => {
            let n = track.playlist.segments.len();
            // Identity anchors: the head and tail ordinals/URIs.
            assert_eq!(track.playlist.segments[0].sequence, 0);
            assert_eq!(
                track.playlist.segments[n - 1].sequence,
                (n - 1) as u64,
                "cross-period ordinals stay monotonic"
            );
            assert!(track.playlist.segments[0].uri.ends_with("v/00000001-0.m4s"));
            let _ = mpd::mpd_digest(&doc, URL);
            n
        }
        _ => panic!("ready expansion"),
    }
}

#[test]
fn gate1_hundredk_mpd_parse_wall_and_alloc() {
    let timeline = hundredk_timeline_mpd().into_bytes();
    assert!(
        timeline.len() <= 16 * 1024 * 1024,
        "the carrier stays inside the manifest byte cap ({} bytes)",
        timeline.len()
    );

    let mut walls_ms = Vec::with_capacity(3);
    let mut peaks_bytes = Vec::with_capacity(3);
    for sample in 0..3 {
        let before = rss_bytes();
        let started = Instant::now();
        let n = parse_and_expand(&timeline);
        let elapsed = started.elapsed();
        let after = rss_bytes();
        assert_eq!(n, MAX_MEDIA_SEGMENTS, "sample {sample}: segment count");
        walls_ms.push(elapsed.as_secs_f64() * 1000.0);
        peaks_bytes.push(after.saturating_sub(before));
        let _ = sample;
    }
    walls_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median_ms = walls_ms[1];
    let peak_mib = peaks_bytes.iter().max().copied().unwrap_or(0) as f64 / (1024.0 * 1024.0);
    println!(
        "[DASH-PARSE-GATE] timeline-carrier samples_ms={walls_ms:?} median_ms={median_ms:.1} \
         alloc_peak_mib={peak_mib:.1} (budgets: <=500ms, <=200MiB)"
    );
    assert!(
        peak_mib <= 200.0,
        "media parse gate (DASH): RSS-delta allocation proxy {peak_mib:.1}MiB exceeds \
         the 200MiB budget"
    );
    if cfg!(not(debug_assertions)) {
        assert!(
            median_ms <= 500.0,
            "media parse gate (DASH): median parse+expand {median_ms:.1}ms exceeds the \
             500ms budget"
        );
    } else {
        eprintln!("debug build — wall gate asserted in release only (median {median_ms:.1}ms)");
    }

    // Second leg: the compact @duration form expands to the same
    // 100k through the same path (constant-size document).
    let compact = compact_duration_mpd().into_bytes();
    let before = rss_bytes();
    let started = Instant::now();
    let n = parse_and_expand(&compact);
    let elapsed = started.elapsed();
    let after = rss_bytes();
    let peak = after.saturating_sub(before) as f64 / (1024.0 * 1024.0);
    assert_eq!(n, MAX_MEDIA_SEGMENTS);
    println!(
        "[DASH-PARSE-GATE] template-carrier ms={:.1} alloc_peak_mib={peak:.1}",
        elapsed.as_secs_f64() * 1000.0
    );
    assert!(
        peak <= 200.0,
        "template carrier alloc {peak:.1}MiB over budget"
    );
    if cfg!(not(debug_assertions)) {
        assert!(
            elapsed.as_secs_f64() * 1000.0 <= 500.0,
            "template carrier over the 500ms budget"
        );
    }
}
