//! Golden-fixture tests for the taiji-media initial parse surface (the
//! recorded-output contract: recorded `-version` / `-demuxers` / `-muxers` /
//! `-progress` outputs + an ffprobe JSON sample — all platform-runnable
//! pure-parse tests, no ffmpeg required).
//!
//! Recorded against ffmpeg 9.0.2 (Homebrew arm64, 2026-10-27). The
//! recorded build carries `--enable-gpl` (Homebrew formula fact) — the
//! fixtures are *honest recordings*; the license assertions below test
//! both directions against them: the recorded GPL configuration must
//! trip the gate (red), and a synthesized clean configuration must
//! pass (green). Synthetic strings are constructed in-test and labeled
//! as such.

use std::fs;
use std::path::Path;

use taiji_media::capability::{Capabilities, Direction};
use taiji_media::version::{
    LicenseAudit, LicenseStrictness, VersionInfo, license_verdict, versions_agree,
};

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

#[test]
fn recorded_version_parses() {
    let text = fixture("ffmpeg-version.txt");
    let v = match VersionInfo::parse(&text) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(v.program, "ffmpeg");
    assert_eq!(v.version, "9.0.2");
    assert!(v.configuration.starts_with("--prefix=/opt/homebrew"));

    let probe = match VersionInfo::parse(&fixture("ffprobe-version.txt")) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(probe.program, "ffprobe");
    // Same-origin pairing, second half: version tokens agree.
    assert!(versions_agree(&v, &probe));
}

#[test]
fn recorded_configuration_is_gpl_and_the_gate_goes_red() {
    // Positive-negative pair #1: the *recorded* Homebrew configuration
    // carries --enable-gpl (no --enable-nonfree) — the gate must
    // refuse it under `gate` strictness.
    let text = fixture("ffmpeg-version.txt");
    let v = match VersionInfo::parse(&text) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    let audit = LicenseAudit::audit(&v.configuration);
    assert!(audit.gpl, "recorded configuration must carry --enable-gpl");
    assert!(!audit.nonfree);
    match license_verdict(audit, LicenseStrictness::Gate, "recorded") {
        Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_license_gate"),
        Ok(a) => panic!("gate must refuse a GPL configuration, got {a:?}"),
    }
    // info tier passes with the same audit (warning posture).
    assert!(license_verdict(audit, LicenseStrictness::Info, "recorded").is_ok());
}

#[test]
fn synthetic_gpl_and_nonfree_configurations_go_red() {
    // Positive-negative pair #2: constructed fake configuration
    // strings (the card's acceptance shape: fake --enable-gpl → red).
    let cases = [
        ("--enable-gpl", true, false),
        ("--enable-nonfree", false, true),
        ("--enable-gpl --enable-nonfree", true, true),
        // Substring false-positives stay clean (token-exact audit).
        ("--enable-gplish --enable-nonfree1", false, false),
    ];
    for (config, gpl, nonfree) in cases {
        let audit = LicenseAudit::audit(config);
        assert_eq!(audit.gpl, gpl, "gpl mismatch for {config:?}");
        assert_eq!(audit.nonfree, nonfree, "nonfree mismatch for {config:?}");
        let expect_clean = !gpl && !nonfree;
        assert_eq!(
            audit.is_clean(),
            expect_clean,
            "clean mismatch for {config:?}"
        );
        let gated = license_verdict(audit, LicenseStrictness::Gate, "synthetic");
        assert_eq!(gated.is_ok(), expect_clean, "gate mismatch for {config:?}");
    }
}

#[test]
fn synthetic_clean_version_output_goes_green() {
    // Positive-negative pair #3: a full synthesized clean -version
    // block (LGPL-shaped build) parses and passes the gate.
    let synthetic = "\
ffmpeg version 7.1.0-lgpl Copyright (c) 2000-2026 the FFmpeg developers
built with cc (Ubuntu clang)
configuration: --prefix=/opt/taiji-ffmpeg --enable-shared --disable-programs --enable-protocol=file
libavutil      59. 39.100 / 59. 39.100
";
    let v = match VersionInfo::parse(synthetic) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(v.version, "7.1.0-lgpl");
    let audit = LicenseAudit::audit(&v.configuration);
    assert!(audit.is_clean());
    assert!(license_verdict(audit, LicenseStrictness::Gate, "synthetic-clean").is_ok());
}

#[test]
fn recorded_capability_listings_parse_complete() {
    let caps = match Capabilities::parse(
        &fixture("ffmpeg-demuxers.txt"),
        &fixture("ffmpeg-muxers.txt"),
    ) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    // ffmpeg 9 registers hundreds per direction; sanity bounds.
    assert!(
        caps.demuxers.names().len() > 200,
        "demuxer count suspiciously low"
    );
    assert!(
        caps.muxers.names().len() > 100,
        "muxer count suspiciously low"
    );
    // The comma-alias rows land: matroska,webm and mov,mp4,...
    for name in taiji_media::REQUIRED_DEMUXERS {
        assert!(caps.demuxers.has(name), "required demuxer {name} missing");
    }
    for name in taiji_media::REQUIRED_MUXERS {
        assert!(caps.muxers.has(name), "required muxer {name} missing");
    }
    assert!(caps.is_complete());
}

#[test]
fn capability_direction_args_shape() {
    assert_eq!(
        Direction::Demuxers.args(),
        vec!["-hide_banner".to_string(), "-demuxers".to_string()]
    );
    assert_eq!(
        Direction::Muxers.args(),
        vec!["-hide_banner".to_string(), "-muxers".to_string()]
    );
}

#[test]
fn recorded_progress_stream_parses() {
    let bytes = fixture("ffmpeg-progress.txt").into_bytes();
    let mut parser = taiji_media::ProgressParser::new();
    let snapshots = parser.feed(&bytes);
    let mut snapshots = snapshots;
    snapshots.extend(parser.finish());

    // Recorded run: 11 blocks (10 continue + 1 end), a `-re` paced
    // copy remux of a 6s sample.
    assert_eq!(snapshots.len(), 11);
    assert_eq!(snapshots.iter().filter(|s| !s.end).count(), 10);
    let last = snapshots.last().cloned().unwrap_or_default();
    assert!(last.end);
    assert_eq!(last.frame, Some(180));
    assert_eq!(last.total_size, Some(659_063));
    assert_eq!(last.out_time_us, Some(6_000_000));
    // Scientific-notation speed ("6.49e+03x" shape) parses.
    assert!(last.speed_x.is_some_and(|s| s > 1.0));

    // Chunk-size invariance: feeding the same bytes in 3-byte chunks
    // yields the same snapshot count (partial-line buffering holds).
    let mut chunked = taiji_media::ProgressParser::new();
    let mut n = 0;
    for chunk in bytes.chunks(3) {
        n += chunked.feed(chunk).len();
    }
    n += chunked.finish().len();
    assert_eq!(n, snapshots.len());
}

#[test]
fn recorded_ffprobe_json_structures() {
    let raw = fixture("ffprobe-sample.json");
    let report = match taiji_media::FfprobeReport::parse(raw.as_bytes()) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(report.streams.len(), 2);
    assert_eq!(report.count_codec_type("video"), 1);
    assert_eq!(report.count_codec_type("audio"), 1);
    let v = &report.streams[0];
    assert_eq!(v.codec_name.as_deref(), Some("h264"));
    assert_eq!((v.width, v.height), (Some(320), Some(240)));
    assert_eq!(report.streams[1].codec_name.as_deref(), Some("aac"));
    // Container duration ≈ 6s (the recorded 6s sample).
    let duration = report.duration_seconds().unwrap_or_default();
    assert!((5.5..=6.5).contains(&duration), "duration {duration}");
    assert_eq!(
        report.stream_summary(),
        vec!["0:h264(video)".to_string(), "1:aac(audio)".to_string(),]
    );
    // Round-trip: the typed structure serializes (doctor --json face).
    let reser = match serde_json::to_string(&report) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    assert!(reser.contains("\"codec_name\":\"h264\""));
}
