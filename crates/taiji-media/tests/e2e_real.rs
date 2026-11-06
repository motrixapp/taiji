//! Real-machine e2e (the recorded contract: "if ffmpeg is installed on
//! the machine, add real-machine e2e (doctor all green + one measured
//! progress remux)").
//!
//! Runtime guard: discovery failure skips the ffmpeg-dependent tests
//! with a clear message (the golden/parse suites cover the no-ffmpeg
//! machines); every spawn goes through the full orchestrator (self-exec
//! shim + resource limits on unix, piped trio, kill_on_drop).
//!
//! Honesty note on "doctor all green": the dev machine's Homebrew ffmpeg
//! carries `--enable-gpl` (recorded fixture fact) — under the default
//! `gate` strictness doctor is *red* there BY DESIGN. The doctor e2e
//! therefore asserts internal consistency (license verdict matches the
//! audit, red accounting matches the findings) instead of hard-coding
//! green; the green posture is covered by the synthetic-clean golden
//! tests.

use std::path::PathBuf;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use taiji_media::discover::{DiscoveryRequest, discover};
use taiji_media::error::MediaError;
use taiji_media::ffprobe::{FfprobeReport, probe_args};
use taiji_media::process::{MAX_ALLOC_BYTES, MediaBin, MediaCommand};
use taiji_media::version::{LicenseAudit, LicenseStrictness};

/// Exec-shim host for test drivers (the libtest binary cannot host the
/// `maybe_run_shim` hook; production hosts use their own `main`).
fn shim_host() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_taiji-media-shim"))
}

/// Test scratch dir.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("taiji-e2e-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    dir
}

/// Discovery guard: Ok(pair) = real machine face on; Err = skip.
fn guard() -> Result<taiji_media::FfmpegPair, MediaError> {
    let pair = discover(&DiscoveryRequest::default());
    if let Err(e) = &pair {
        eprintln!("skipping (no local ffmpeg/ffprobe pair): {e}");
    }
    pair
}

#[tokio::test]
async fn shim_smoke_captures_stdout_and_exit_code() {
    // Cheapest full-orchestrator proof: /bin/echo through the shim
    // (limits + pipes + wait). Unix-only (no echo.exe assumption).
    if !cfg!(unix) {
        eprintln!("skipping (unix-only /bin/echo)");
        return;
    }
    let cmd = match MediaCommand::new(MediaBin::Ffmpeg, "/bin/echo") {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let child = match cmd
        .arg("tb-p89-shim-ok")
        .shim_program(Some(shim_host()))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let output = match child.wait().await {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert!(output.success, "exit {:?}", output.code);
    assert_eq!(output.stdout, b"tb-p89-shim-ok\n");
}

#[tokio::test]
async fn builder_contract_refuses_violations_without_spawning() {
    // Relative program path.
    match MediaCommand::new(MediaBin::Ffmpeg, "ffmpeg") {
        Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_not_absolute"),
        Ok(c) => panic!("unexpected success: {:?}", c.argv()),
    }
    // Output without an explicit -f.
    let dir = scratch("contract");
    let out = dir.join("o.mkv");
    let base = match MediaCommand::new(MediaBin::Ffmpeg, dir.join("ffmpeg")) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    match base.clone().output(&out) {
        Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_missing_format"),
        Ok(c) => panic!("unexpected success: {:?}", c.argv()),
    }
    // Output with a leading '-' in the filename.
    match base
        .clone()
        .format("matroska")
        .output(dir.join("-inject.mkv"))
    {
        Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_not_absolute"),
        Ok(c) => panic!("unexpected success: {:?}", c.argv()),
    }
    // argv face: format() + output() produce the explicit sequence.
    let cmd = match base.format("matroska").output(&out) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let argv: Vec<String> = cmd
        .argv()
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let fmt_at = argv.iter().position(|a| a == "-f");
    let out_at = argv.iter().position(|a| a == out.to_str().unwrap_or(""));
    assert!(fmt_at.is_some_and(|f| out_at.is_some_and(|o| f < o)));
}

#[tokio::test]
async fn doctor_report_is_internally_consistent() {
    let Ok(pair) = guard() else {
        return;
    };
    let report = taiji_media::run_doctor(taiji_media::DoctorOptions {
        strictness: LicenseStrictness::Gate,
        explicit_dir: None,
        shim_program: Some(shim_host()),
    })
    .await;
    // Discovery: found, absolute pair from one origin.
    assert!(
        report.discovery.error.is_none(),
        "{:?}",
        report.discovery.error
    );
    assert!(report.discovery.ffmpeg.is_absolute());
    assert!(report.discovery.ffprobe.is_absolute());
    assert_eq!(
        report.discovery.ffmpeg.parent(),
        report.discovery.ffprobe.parent()
    );
    assert_eq!(report.discovery.dir, pair.dir());
    // Version: both parsed, tokens agree (same-origin pairing).
    assert!(report.version.error.is_none(), "{:?}", report.version.error);
    assert!(!report.version.skipped);
    assert_eq!(report.version.versions_agree, Some(true));
    assert!(report.version.ffmpeg_version.is_some());
    // License verdict is consistent with the audit + the gate tier:
    // dirty audit => non-empty verdict + at least one red; clean audit
    // => empty verdict + no license red.
    let audit = report.version.license;
    let dirty = !audit.is_clean();
    assert_eq!(
        !report.version.verdict.is_empty(),
        dirty,
        "verdict {:?} vs audit {audit:?}",
        report.version.verdict
    );
    // Capability section ran (real machine face) — not skipped.
    assert!(!report.capabilities.skipped);
    // Capabilities: real builds satisfy the required set.
    assert!(
        report.capabilities.error.is_none(),
        "{:?}",
        report.capabilities.error
    );
    assert!(report.capabilities.missing_demuxers.is_empty());
    assert!(report.capabilities.missing_muxers.is_empty());
    // Red accounting: dirty audit contributes exactly one red here.
    let expected_red = u32::from(dirty);
    assert_eq!(report.red, expected_red, "{}", report.render_human());
    // Independent cross-check of the audit against the recorded-shape
    // token rule (defense against a report/audit drift).
    let config = report.version.configuration.as_deref().unwrap_or_default();
    assert_eq!(audit.gpl, LicenseAudit::audit(config).gpl);
    // Human rendering mentions the verdict when red.
    if dirty {
        assert!(report.render_human().contains("FAIL"));
    }
}

#[tokio::test]
async fn doctor_discovery_failure_skips_dependent_sections() {
    // Review-blocker regression (phantom findings on the failed-
    // discovery path): when discovery fails, the version/capability
    // sections never run — their defaults must read as absence, not as
    // verdicts. Before the fix this path reported red=2 (the never-run
    // pairing check counted `versions_agree: false, error: null`) and
    // the human rendering printed a phantom "pairing: FAIL" plus a
    // phantom "required set: complete" over zero registered formats.
    // The precedence-1 explicit dir makes the failure deterministic on
    // any machine (installed ffmpeg or not).
    let report = taiji_media::run_doctor(taiji_media::DoctorOptions {
        strictness: LicenseStrictness::Gate,
        explicit_dir: Some(PathBuf::from("/nonexistent-taiji-dir")),
        shim_program: Some(shim_host()),
    })
    .await;
    assert!(
        report.discovery.error.is_some(),
        "explicit nonexistent dir must fail discovery"
    );
    // Dependent sections are marked skipped, not errored.
    assert!(report.version.skipped);
    assert!(report.version.error.is_none());
    assert_eq!(report.version.versions_agree, None);
    assert!(report.capabilities.skipped);
    assert!(report.capabilities.error.is_none());
    // Exactly one red: the discovery failure itself.
    assert_eq!(report.red, 1, "{}", report.render_human());
    // Human rendering states the skips and fabricates no findings.
    let human = report.render_human();
    assert!(!human.contains("pairing: FAIL"), "{human}");
    assert!(!human.contains("required set: complete"), "{human}");
    assert!(!human.contains("verdict: pass"), "{human}");
    assert_eq!(human.matches("skipped").count(), 2, "{human}");
}

/// Generate a 2s a/v sample through the orchestrator (lavfi sources,
/// ultrafast x264 + aac).
async fn make_sample(pair: &taiji_media::FfmpegPair, out: &std::path::Path) {
    let cmd = match MediaCommand::new(MediaBin::Ffmpeg, &pair.ffmpeg) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let cmd = cmd
        .args([
            "-nostdin",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=duration=2:size=320x240:rate=30",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=2",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-shortest",
        ])
        .format("mp4")
        .output(out)
        .unwrap_or_else(|e| panic!("{e}"));
    let child = match cmd.shim_program(Some(shim_host())).spawn() {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let output = match child.wait().await {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    if !output.success {
        panic!(
            "sample generation failed ({:?}): {}",
            output.code,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn remux_with_live_progress_and_ffprobe_verify() {
    let Ok(pair) = guard() else {
        return;
    };
    let dir = scratch("remux");
    let sample = dir.join("sample.mp4");
    make_sample(&pair, &sample).await;
    let out = dir.join("out.mkv");

    // Remux shape per the product spec (max_alloc in decimal bytes — the
    // spec's
    // "512M" literal is rejected by ffmpeg 9, see MAX_ALLOC_BYTES).
    let cmd = match MediaCommand::new(MediaBin::Ffmpeg, &pair.ffmpeg) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let cmd = match cmd
        .args([
            "-nostdin",
            "-y",
            "-hide_banner",
            "-nostats",
            "-loglevel",
            "error",
            "-progress",
            "pipe:1",
            "-protocol_whitelist",
            "file",
            "-max_alloc",
            &MAX_ALLOC_BYTES.to_string(),
            "-i",
        ])
        .arg(&sample)
        .args(["-map", "0:v:0", "-map", "0:a:0", "-c", "copy"])
        .format("matroska")
        .output(&out)
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let child = match cmd
        .stdout_progress(Some(Duration::from_secs(30)))
        .shim_program(Some(shim_host()))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    // Live subscription observes at least the final block.
    let progress_rx = child.progress_subscription();
    let output = match child.wait().await {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert!(output.success, "remux failed: {:?}", output.code);
    assert!(
        out.is_file(),
        "remux output missing ({} bytes)",
        out.metadata().map(|m| m.len()).unwrap_or(0)
    );
    // Progress contract: at least one snapshot; terminal end=true.
    assert!(!output.snapshots.is_empty());
    let last = output.last_snapshot.clone().unwrap_or_default();
    assert!(last.end, "terminal snapshot must be progress=end");
    assert!(last.total_size.is_some());
    assert!(last.out_time_us.is_some_and(|us| us >= 1_900_000));
    let observed = match progress_rx {
        Some(rx) => rx.borrow().clone(),
        None => panic!("progress subscription missing"),
    };
    assert!(observed.end, "live subscription must see the end block");

    // ffprobe verification of the remux output (stream set + duration).
    let probe_cmd = match MediaCommand::new(MediaBin::Ffprobe, &pair.ffprobe) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let child = match probe_cmd
        .args(probe_args(&out))
        .shim_program(Some(shim_host()))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let probe_out = match child.wait().await {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert!(probe_out.success);
    let report = match FfprobeReport::parse(&probe_out.stdout) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(report.count_codec_type("video"), 1);
    assert_eq!(report.count_codec_type("audio"), 1);
    let duration = report.duration_seconds().unwrap_or_default();
    assert!(
        (1.9..=2.1).contains(&duration),
        "remux duration {duration} outside [0.98, 1.02] of the 2s sample"
    );
}

#[tokio::test]
async fn stall_watchdog_escalates_and_cancels() {
    let Ok(pair) = guard() else {
        return;
    };
    let dir = scratch("stall");
    let sample = dir.join("s.mp4");
    make_sample(&pair, &sample).await;
    let out = dir.join("o.mkv");

    // `-re` paces the copy at native rate (progress blocks ~0.5s
    // apart); a 150ms stall window must fire between blocks.
    let cmd = match MediaCommand::new(MediaBin::Ffmpeg, &pair.ffmpeg) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let cmd = match cmd
        .args([
            "-nostdin",
            "-y",
            "-hide_banner",
            "-nostats",
            "-loglevel",
            "error",
            "-re",
            "-progress",
            "pipe:1",
            "-i",
        ])
        .arg(&sample)
        .args(["-c", "copy"])
        .format("matroska")
        .output(&out)
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let child = match cmd
        .stdout_progress(Some(Duration::from_millis(150)))
        .shim_program(Some(shim_host()))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    match child.wait().await {
        Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_stalled"),
        Ok(o) => panic!(
            "watchdog must fire on a 150ms window with 0.5s-spaced blocks (exit {:?})",
            o.code
        ),
    }
}

#[tokio::test]
async fn cancel_token_kills_through_the_ladder() {
    let Ok(pair) = guard() else {
        return;
    };
    let dir = scratch("cancel");
    let sample = dir.join("s.mp4");
    make_sample(&pair, &sample).await;
    let out = dir.join("o.mkv");

    let token = CancellationToken::new();
    let cmd = match MediaCommand::new(MediaBin::Ffmpeg, &pair.ffmpeg) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let cmd = match cmd
        .args([
            "-nostdin",
            "-y",
            "-hide_banner",
            "-nostats",
            "-loglevel",
            "error",
            "-re",
            "-progress",
            "pipe:1",
            "-i",
        ])
        .arg(&sample)
        .args(["-c", "copy"])
        .format("matroska")
        .output(&out)
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let child = match cmd
        .stdout_progress(Some(Duration::from_secs(30)))
        .cancellation(token.clone())
        .shim_program(Some(shim_host()))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    token.cancel();
    match child.wait().await {
        Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_cancelled"),
        Ok(o) => panic!("cancelled run must not complete (exit {:?})", o.code),
    }
}
