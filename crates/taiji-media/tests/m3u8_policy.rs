//! m3u8 policy matrix + parse-budget smoke.
//!
//! The wall-time half of the media parse gate (100k-segment
//! manifest ≤ 500ms) is asserted **release-only** — a debug build is
//! not the gate's build. The allocation half (≤ 200MiB) needs the
//! profiled harness named by the spec; it is not measured here (the
//! model for a 100k-segment manifest is on the order of tens of MiB).

use std::time::Instant;

use taiji_media::m3u8::{MasterPlaylist, Playlist, VariantPolicy, parse_manifest, select_variant};

fn master(bytes: &[u8]) -> MasterPlaylist {
    match parse_manifest(bytes) {
        Ok(Playlist::Master(m)) => m,
        other => panic!("expected a master playlist, got {other:?}"),
    }
}

const LADDER: &[u8] = b"#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=414000,RESOLUTION=416x234\n gear0/index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=692000,RESOLUTION=640x360\n gear1/index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=1327000,RESOLUTION=960x540\n gear2/index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=2323700,RESOLUTION=1280x720\n gear3/index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=6293700,RESOLUTION=1920x1080\n gear4/index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=8000,RESOLUTION=640x360,AUDIO=\"aud\"\n audio-only.m3u8\n";

#[test]
fn policy_parse_forms() {
    for (text, want) in [
        ("highest", VariantPolicy::Highest),
        (" highest ", VariantPolicy::Highest),
        ("HIGHEST", VariantPolicy::Highest),
        ("resolution=720", VariantPolicy::Resolution { height: 720 }),
        (
            "bandwidth=1500000",
            VariantPolicy::Bandwidth {
                bits_per_second: 1_500_000,
            },
        ),
    ] {
        let got = match VariantPolicy::parse(text) {
            Ok(p) => p,
            Err(e) => panic!("{text:?}: {e}"),
        };
        assert_eq!(got, want, "{text:?}");
    }
    assert_eq!(VariantPolicy::default(), VariantPolicy::Highest);
}

#[test]
fn policy_selection_matrix() {
    let m = master(LADDER);
    let pick = |policy: &str| -> String {
        let p = match VariantPolicy::parse(policy) {
            Ok(p) => p,
            Err(e) => panic!("{policy}: {e}"),
        };
        match select_variant(&m, &p) {
            Ok(v) => v.uri.trim().to_owned(),
            Err(e) => panic!("{policy}: {e}"),
        }
    };
    assert_eq!(pick("highest"), "gear4/index.m3u8", "max bandwidth");
    assert_eq!(
        pick("resolution=720"),
        "gear3/index.m3u8",
        "cap: best variant at height <= 720 (not the 1080 gear4)"
    );
    assert_eq!(
        pick("resolution=234"),
        "gear0/index.m3u8",
        "cap hits the floor exactly"
    );
    assert_eq!(
        pick("bandwidth=1500000"),
        "gear2/index.m3u8",
        "cap: best bandwidth <= 1500000 (not the exact 1327000 requirement)"
    );
}

/// Fully equal rank → first declared wins (stable order).
#[test]
fn policy_tie_break_is_declaration_order() {
    let text = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=960x540\nfirst.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=960x540\nsecond.m3u8\n";
    let m = master(text.as_bytes());
    let chosen = match select_variant(&m, &VariantPolicy::Highest) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(
        chosen.uri, "first.m3u8",
        "full rank tie → declaration order"
    );

    // Equal bandwidth, different resolution: resolution outranks order.
    let text = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=640x360\nsmall.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=960x540\nbig.m3u8\n";
    let m = master(text.as_bytes());
    let chosen = match select_variant(&m, &VariantPolicy::Highest) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(chosen.uri, "big.m3u8");

    // Different bandwidths: resolution does not outrank it.
    let text = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=3840x2160\nsmall-bw-4k.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=2000000,RESOLUTION=640x360\nbig-bw-sd.m3u8\n";
    let m = master(text.as_bytes());
    let chosen = match select_variant(&m, &VariantPolicy::Highest) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(chosen.uri, "big-bw-sd.m3u8", "bandwidth is the primary key");
}

/// Variants without RESOLUTION are ineligible under a resolution cap
/// (never guessed), but fully eligible under the other policies.
#[test]
fn policy_resolution_cap_skips_resolutionless_variants() {
    let text = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=6293700\nno-res.m3u8\n";
    let m = master(text.as_bytes());
    let chosen = match select_variant(&m, &VariantPolicy::Highest) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(chosen.uri, "no-res.m3u8");
    let e = match select_variant(&m, &VariantPolicy::Resolution { height: 1080 }) {
        Err(e) => e,
        Ok(v) => panic!("must refuse, chose {}", v.uri),
    };
    assert_eq!(e.code(), "taiji.media.variant_policy");
}

/// 100k-segment parse: identity correctness always; wall-time ≤ 500ms
/// asserted in release builds only (the gate build).
#[test]
fn hundred_thousand_segment_parse() {
    let mut text = String::with_capacity(1_400_000);
    text.push_str("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:77000\n");
    for i in 0..100_000u64 {
        // Multiple write! calls per segment; the compiler folds them.
        text.push_str("#EXTINF:2.000,\n");
        text.push_str("https://cdn.example.com/s/");
        let _ = std::fmt::Write::write_str(&mut text, &i.to_string());
        text.push_str(".ts\n");
    }
    text.push_str("#EXT-X-ENDLIST\n");
    let bytes = text.as_bytes();

    let started = Instant::now();
    let p = match parse_manifest(bytes) {
        Ok(Playlist::Media(p)) => p,
        other => panic!("expected a media playlist, got {other:?}"),
    };
    let elapsed = started.elapsed();
    assert_eq!(p.segments.len(), 100_000);
    assert_eq!(p.segments[0].sequence, 77_000);
    assert_eq!(
        p.segments[99_999].sequence, 176_999,
        "absolute identity to the end"
    );
    if cfg!(not(debug_assertions)) {
        assert!(
            elapsed.as_millis() < 500,
            "media parse gate: 100k segments in {}ms",
            elapsed.as_millis()
        );
    }
}
