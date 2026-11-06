//! The VOD fixture matrix acceptance legs (0.3.0
//! subset) — full generation, the reproducible-rebuild bit cross-check, and
//! the product sweep's dual validation (native probe box assertions
//! and ffprobe stream-set/duration dual-run when the local pair is
//! present).
//!
//! Runtime guard: the generator is ffmpeg-driven — discovery failure
//! skips these tests with a clear message (the honest-skip posture; the
//! pure-logic faces of the matrix — the hundredk manifest, the
//! negative rows — live in the always-on suites).

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::TrackSetVerdict;
use taiji_media::TrackState;
use taiji_media::ffmpegmux::FfmpegRuntime;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::synth::{self, MuxerPreference, OutputFormat, SynthesisConfig, TrackInput};
use taiji_media::trackdl::MediaLedger as _;

use common::fixturegen::{Generator, assert_bit_identical, discover_generator, generate_matrix};

// ---------------------------------------------------------------------------
// matrix cache + origin
// ---------------------------------------------------------------------------

/// Generate the matrix once per test binary (both tests share it).
fn matrix() -> Option<(PathBuf, Generator)> {
    static CACHE: std::sync::OnceLock<Option<(PathBuf, Generator)>> = std::sync::OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let fx = discover_generator()?;
        let root = common::origin::tempdir("taiji-matrix", "tree");
        match generate_matrix(&root, &fx) {
            Ok(_) => Some((root, fx)),
            Err(e) => panic!("fixture matrix generation failed: {e}"),
        }
    });
    (*cached).clone()
}

// ---------------------------------------------------------------------------
// ① matrix generation + rebuild bit cross-check
// ---------------------------------------------------------------------------

/// Acceptance ①: the full 0.3.0 VOD subset generates, and a rebuild
/// from the same fixed inputs is bit-identical (the sha256 manifest +
/// RECIPE.json land in the tree).
#[test]
fn matrix_full_generation_and_rebuild_bit_identical() {
    let Some((root, fx)) = matrix() else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    // The expected families are all present with products.
    for rel in [
        "master-multibitrate/master.m3u8",
        "master-multibitrate/v240/init.mp4",
        "master-multibitrate/v240/media.m3u8",
        "master-multibitrate/v180/init.mp4",
        "master-multibitrate/v120/init.mp4",
        "independent-audio/master.m3u8",
        "independent-audio/video/init.mp4",
        "independent-audio/audio/init.mp4",
        "aes-rotation/media.m3u8",
        "aes-rotation/init.mp4",
        "aes-rotation/eseg000.m4s",
        "aes-rotation/pseg004.m4s",
        "aes-rotation/keys/k1.bin",
        "aes-rotation/expected/archive.sha256",
        "byterange/explicit.m3u8",
        "byterange/omitted.m3u8",
        "byterange/blob.mp4",
        // The muxed-A/V matrix row: muxed A/V single-file BYTERANGE (the
        // dominant real-world form; init carries both traks).
        "muxed-av/master.m3u8",
        "muxed-av/muxed.m3u8",
        "muxed-av/muxed.mp4",
        "discontinuity/media.m3u8",
        "discontinuity/p0/init.mp4",
        "discontinuity/p1/init.mp4",
        "nonzero-seq/media.m3u8",
        "multimap-v8/media.m3u8",
        "multimap-v8/einit0.mp4",
        "multimap-v8/einit1.mp4",
        "multimap-v8/expected/init0.mp4",
        "mkv-fallback/ts.m3u8",
        "mkv-fallback/ts000.ts",
        "mkv-fallback/sample.mkv",
        "hundredk/media.m3u8",
        "SHA256SUMS",
        "RECIPE.json",
    ] {
        assert!(root.join(rel).is_file(), "matrix product missing: {rel}");
    }
    // ≥3 variants in the multibitrate master.
    let master = std::fs::read_to_string(root.join("master-multibitrate/master.m3u8"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        master
            .lines()
            .filter(|l| l.starts_with("#EXT-X-STREAM-INF"))
            .count(),
        3,
        "master carries 3 variants"
    );
    // The rotation playlist: 2 AES KEYs + 1 NONE reset + boundary form.
    let aes = std::fs::read_to_string(root.join("aes-rotation/media.m3u8"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(aes.matches("METHOD=AES-128").count(), 2);
    assert!(aes.contains("METHOD=NONE"));
    assert!(aes.contains("IV=0x"), "explicit-IV form present");
    // The omitted-offset derivative differs from the explicit form
    // but only in @offset presence.
    let explicit = std::fs::read_to_string(root.join("byterange/explicit.m3u8"))
        .unwrap_or_else(|e| panic!("{e}"));
    let omitted = std::fs::read_to_string(root.join("byterange/omitted.m3u8"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(explicit, omitted);
    assert!(
        omitted.contains("#EXT-X-BYTERANGE:"),
        "omitted form still carries lengths"
    );
    // The muxed-A/V matrix row's non-video-only proof at the source: the
    // muxed init parses TWO traks (vide + soun) and the master has no
    // EXT-X-MEDIA group (the audio rides inside the rendition).
    {
        let muxed_bytes = std::fs::read(root.join("muxed-av/muxed.mp4"))
            .unwrap_or_else(|e| panic!("read muxed.mp4: {e}"));
        // The single_file form seats the init at the file head under
        // the MAP BYTERANGE — walk it out of the playlist.
        let playlist_text = std::fs::read_to_string(root.join("muxed-av/muxed.m3u8"))
            .unwrap_or_else(|e| panic!("read muxed.m3u8: {e}"));
        let map_line = playlist_text
            .lines()
            .find(|l| l.starts_with("#EXT-X-MAP:"))
            .unwrap_or_else(|| panic!("muxed playlist carries a MAP: {playlist_text}"));
        let (off, len) = map_line
            .split("BYTERANGE=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .and_then(|r| r.split_once('@'))
            .map(|(l, o)| {
                (
                    o.parse::<u64>().unwrap_or(0),
                    l.parse::<usize>().unwrap_or(0),
                )
            })
            .unwrap_or_else(|| panic!("map byterange parse: {map_line}"));
        let init_bytes = &muxed_bytes[off as usize..off as usize + len];
        let tracks = taiji_media::bmff::parse_init_tracks(init_bytes)
            .unwrap_or_else(|e| panic!("muxed init parses: {e}"));
        assert_eq!(tracks.len(), 2, "the muxed init carries both traks");
        assert!(
            tracks.iter().any(|t| t.handler == *b"vide")
                && tracks.iter().any(|t| t.handler == *b"soun"),
            "vide + soun traks: {:?}",
            tracks.iter().map(|t| t.handler).collect::<Vec<_>>()
        );
        let mav_master = std::fs::read_to_string(root.join("muxed-av/master.m3u8"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !mav_master.contains("EXT-X-MEDIA"),
            "the muxed rendition has no rendition group"
        );
    }
    // SHA256SUMS rows == the on-tree products.
    let sums = std::fs::read_to_string(root.join("SHA256SUMS")).unwrap_or_else(|e| panic!("{e}"));
    assert!(sums.lines().count() >= 30, "sha manifest covers the tree");
    let recipe =
        std::fs::read_to_string(root.join("RECIPE.json")).unwrap_or_else(|e| panic!("{e}"));
    assert!(recipe.contains(&fx.version_line), "recipe records ffmpeg");
    assert!(recipe.contains("k1_sha256"), "recipe records key anchors");

    // Rebuild cross-check: a second run over the same fixed inputs is
    // bit-identical (file set + per-file sha256).
    let second = common::origin::tempdir("taiji-matrix", "rebuild");
    generate_matrix(&second, &fx).unwrap_or_else(|e| panic!("rebuild generation failed: {e}"));
    assert_bit_identical(&root, &second);
}

// ---------------------------------------------------------------------------
// ⑥ product sweep: download → synthesis → native probe + ffprobe dual-run
// ---------------------------------------------------------------------------

struct Swept {
    out_dir: PathBuf,
    staging: PathBuf,
    report: taiji_media::mediadl::MediaRunReport,
    ledger: common::ledger::StoreLedger,
    join: tokio::task::JoinHandle<()>,
}

async fn sweep_setup(tag: &str, addr: &SocketAddr, manifest_rel: &str, gid: &str) -> Swept {
    let out_dir = common::origin::tempdir("taiji-matrix", &format!("sweep-{tag}"));
    let db_dir = common::origin::tempdir("taiji-matrix", &format!("sweep-{tag}-db"));
    let (ledger, join) = common::ledger::spawn_ledger(&db_dir.join("taiji.sqlite3")).await;
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let dl = MediaDownload::new(
        gid,
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: out_dir.clone(),
            allow_private_key_url: true,
            ..MediaDownloadConfig::default()
        },
    );
    let url = format!("http://{addr}/fx/{manifest_rel}");
    let report = dl
        .run(&url, &ledger)
        .await
        .unwrap_or_else(|e| panic!("download {manifest_rel}: {e}"));
    let staging = report.staging_dir.clone();
    Swept {
        out_dir,
        staging,
        report,
        ledger,
        join,
    }
}

/// Build synthesis inputs from the swept report (the session orchestration
/// bridge shape over the generated fixture's tracks).
async fn sweep_inputs(
    s: &Swept,
    addr: &SocketAddr,
    manifest_rel: &str,
    gid: &str,
) -> Vec<TrackInput> {
    let mut inputs = Vec::new();
    for (planned, state) in &s.report.tracks {
        if !matches!(state, TrackState::Done) {
            continue;
        }
        let (track, segments) = s
            .ledger
            .load_track(gid, planned.track_idx)
            .await
            .unwrap_or_else(|e| panic!("load: {e}"))
            .unwrap_or_else(|| panic!("track {} missing", planned.track_idx));
        // The track's own playlist (re-fetched from the origin). The
        // planned URI stays verbatim from the manifest — relative
        // forms resolve against the entry manifest's directory.
        let origin_prefix = format!("http://{addr}/fx/");
        let track_rel = if let Some(tree_path) = planned.playlist_uri.strip_prefix(&origin_prefix) {
            // Absolute on-origin: the remainder is already the tree path.
            tree_path.to_string()
        } else if planned.playlist_uri.starts_with("http://")
            || planned.playlist_uri.starts_with("https://")
        {
            panic!("track uri off-origin: {}", planned.playlist_uri)
        } else if planned.playlist_uri.starts_with('/') {
            planned.playlist_uri.trim_start_matches('/').to_string()
        } else {
            // Relative form: resolve against the entry manifest's dir.
            format!("{}{}", dir_of(manifest_rel), planned.playlist_uri)
        };
        let playlist_text = http_get(addr, &track_rel).await;
        let playlist = match taiji_media::parse_manifest(playlist_text.as_bytes())
            .unwrap_or_else(|e| panic!("parse track playlist: {e}"))
        {
            taiji_media::Playlist::Media(m) => m,
            other => panic!("{other:?}"),
        };
        let archive = s.staging.join(&track.local_name);
        let inits: Vec<PathBuf> = track.init_files.iter().map(|n| s.staging.join(n)).collect();
        inputs.push(TrackInput {
            label: planned.label.clone(),
            kind: planned.kind.as_str().to_string(),
            archive,
            inits,
            segments,
            playlist,
            archive_name: track.local_name.clone(),
        });
    }
    inputs
}

fn dir_of(rel: &str) -> String {
    match rel.rfind('/') {
        Some(i) => rel[..i + 1].to_string(),
        None => String::new(),
    }
}

async fn http_get(addr: &SocketAddr, rel: &str) -> String {
    let url = format!("http://{addr}/fx/{rel}");
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let bytes = taiji_media::mediadl::http_get_bytes(&client, &url, &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("get {url}: {e}"));
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("utf8: {e}"))
}

/// The real-ffmpeg tfhd anchor canary — **flipped green by the
/// muxed-A/V fix** (previously `canary_real_ffmpeg_fmp4_tfhd_anchor_defect`,
/// pinning the recorded defect #1): `bmff`'s
/// `TFHD_DEFAULT_BASE_IS_MOOF` is now ISO/IEC 14496-12 §8.8.7's bit
/// 17 (`0x020000`); real-encoder moofs (ffmpeg 9 writes tfhd flags
/// 0x00020038 = 0x020000 | default duration/size/flags) parse, and
/// every anchor they declare is the accepted default-base-is-moof.
#[test]
fn canary_real_ffmpeg_fmp4_tfhd_anchor_accepted() {
    let Some((root, _fx)) = matrix() else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    let seg_path = root.join("master-multibitrate/v240/seg000.m4s");
    let bytes = std::fs::read(&seg_path).unwrap_or_else(|e| panic!("{e}"));
    let boxes = taiji_media::bmff::iter_boxes(&bytes)
        .unwrap_or_else(|e| panic!("walk real ffmpeg segment: {e}"));
    let moof = boxes
        .iter()
        .find(|b| b.typ == *b"moof")
        .unwrap_or_else(|| panic!("segment carries a moof"));
    let trafs = taiji_media::bmff::read_moof(moof.payload)
        .unwrap_or_else(|e| panic!("the real ffmpeg moof must parse post-fix: {e}"));
    assert!(!trafs.is_empty(), "the moof carries its traf");
    // The anchor of record: ffmpeg's tfhd flags word contains bit 17
    // (0x020000) and the traf reports default-base-is-moof (the
    // pre-fix constant read bit 21 and rejected the anchor).
    assert!(
        trafs.iter().all(|t| t.default_base_is_moof),
        "real-encoder trafs anchor at their moof: {:?}",
        trafs.iter().map(|t| t.track_id).collect::<Vec<_>>()
    );
    // And the fold walks the same segment end-to-end (one span, the
    // whole file).
    let init_bytes = std::fs::read(root.join("master-multibitrate/v240/init.mp4"))
        .unwrap_or_else(|e| panic!("{e}"));
    let spans = vec![taiji_media::bmff::SegmentSpan {
        archive_offset: 0,
        archive_len: bytes.len() as u64,
    }];
    let fold = taiji_media::bmff::fold_track(&init_bytes, &bytes, &spans)
        .unwrap_or_else(|e| panic!("real ffmpeg segment folds post-fix: {e}"));
    assert!(!fold.samples.is_empty(), "the fold walked real samples");
}

/// The muxed-A/V selection canary: ONE muxed init (both traks) +
/// ONE single-file BYTERANGE archive — the per-kind selection folds
/// the vide trak to video samples AND the soun trak to audio samples
/// off the same archive (the interleaved other-track trafs are
/// filtered inside `fold_track_for`). Pre-fix the multi-trak init was
/// refused outright (the recorded defect #3).
#[test]
fn muxed_av_init_folds_both_selected_tracks() {
    let Some((root, _fx)) = matrix() else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    let file_bytes = std::fs::read(root.join("muxed-av/muxed.mp4"))
        .unwrap_or_else(|e| panic!("read muxed.mp4: {e}"));
    let playlist_text = std::fs::read_to_string(root.join("muxed-av/muxed.m3u8"))
        .unwrap_or_else(|e| panic!("read muxed.m3u8: {e}"));
    let map_line = playlist_text
        .lines()
        .find(|l| l.starts_with("#EXT-X-MAP:"))
        .unwrap_or_else(|| panic!("muxed playlist carries a MAP"));
    let (init_off, init_len) = map_line
        .split("BYTERANGE=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .and_then(|r| r.split_once('@'))
        .map(|(l, o)| {
            (
                o.parse::<u64>().unwrap_or_else(|e| panic!("off: {e}")),
                l.parse::<usize>().unwrap_or_else(|e| panic!("len: {e}")),
            )
        })
        .unwrap_or_else(|| panic!("map byterange parse: {map_line}"));
    let init_bytes = &file_bytes[init_off as usize..init_off as usize + init_len];
    // The segments (the file after the init) — one span over the
    // archive slice (span offsets are slice-relative).
    let archive = &file_bytes[(init_off + init_len as u64) as usize..];
    let seg_span = taiji_media::bmff::SegmentSpan {
        archive_offset: 0,
        archive_len: archive.len() as u64,
    };
    let tracks = taiji_media::bmff::parse_init_tracks(init_bytes)
        .unwrap_or_else(|e| panic!("muxed init parses: {e}"));
    assert_eq!(tracks.len(), 2, "both traks present");
    for (kind, want_handler) in [("video", b"vide"), ("audio", b"soun")] {
        let desc = taiji_media::bmff::select_init_track(&tracks, kind)
            .unwrap_or_else(|| panic!("{kind} trak selectable"));
        assert_eq!(&desc.handler, want_handler, "selection picks by kind");
        let fold = taiji_media::bmff::fold_track_for(desc, archive, &[seg_span])
            .unwrap_or_else(|e| panic!("{kind} selection folds the muxed archive: {e}"));
        assert!(
            !fold.samples.is_empty(),
            "{kind} selection walked its samples"
        );
        assert_eq!(&fold.handler, want_handler, "the fold carries the handler");
    }
}

/// Acceptance ⑥: every fixture product goes through the pipeline and
/// gets the dual validation — the native probe's box-layer assertions
/// (Structural mode covers both channels) + the ffprobe
/// stream-set/duration dual-run when the local pair is present.
///
/// fMP4 legs: full `run_synthesis` (native primary, ffmpeg net) —
/// since the muxed-A/V fix every leg (including the muxed A/V single-file
/// BYTERANGE row) must reach a product and pass the full dual
/// validation; the pre-fix known-defect branch (tfhd anchor +
/// single-trak refusal, recorded defects #1/#3) is gone.
#[tokio::test]
async fn fixture_products_probe_and_ffprobe_dual_run() {
    let Some((root, _fx)) = matrix() else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    let (addr, _st) = common::origin::spawn_tree_origin(&root).await;
    let ffmpeg = common::ffmpeg_lab::local_ffmpeg().await;
    let Some(rt) = ffmpeg.as_ref() else {
        // Without the local pair the product faces that need ffmpeg
        // (TS fallback + MKV probe) cannot run. Honest skip.
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };

    // (manifest rel, gid, expected streams (video,audio))
    let cases: &[(&str, &str, (usize, usize))] = &[
        (
            "master-multibitrate/master.m3u8",
            "9000000000000001",
            (1, 0),
        ),
        ("independent-audio/master.m3u8", "9000000000000002", (1, 1)),
        ("aes-rotation/media.m3u8", "9000000000000003", (1, 0)),
        ("byterange/explicit.m3u8", "9000000000000004", (1, 0)),
        ("byterange/omitted.m3u8", "9000000000000005", (1, 0)),
        ("discontinuity/media.m3u8", "9000000000000006", (1, 0)),
        ("nonzero-seq/media.m3u8", "9000000000000007", (1, 0)),
        ("multimap-v8/media.m3u8", "9000000000000008", (1, 0)),
        // The muxed-A/V matrix row: muxed A/V single-file BYTERANGE — the
        // native channel folds the init's video trak (audio trafs
        // filtered), so the product carries the video stream of the
        // muxed source.
        ("muxed-av/master.m3u8", "900000000000000a", (1, 0)),
    ];
    for (rel, gid, (want_v, want_a)) in cases {
        let s = sweep_setup("case", &addr, rel, gid).await;
        assert!(
            matches!(s.report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
            "{rel}: verdict {:?}",
            s.report.verdict
        );
        let inputs = sweep_inputs(&s, &addr, rel, gid).await;
        assert!(!inputs.is_empty(), "{rel}: no synthesis inputs");
        let cfg = SynthesisConfig {
            phase_sink: None,
            format: OutputFormat::Mp4,
            muxer: MuxerPreference::Auto,
            output: s.out_dir.join(format!("{gid}.mp4")),
            staging_dir: s.staging.clone(),
            ffmpeg: ffmpeg.clone(),
            embed_subtitles: false,
            meta: taiji_media::mp4write::MovieMeta::default(),
            free_bytes_override: Some(None),
        };
        let tok = tokio_util::sync::CancellationToken::new();
        let sr = synth::run_synthesis(&inputs, &cfg, tok)
            .await
            .unwrap_or_else(|e| panic!("{rel}: synthesis (post-fix every leg must pass): {e}"));
        let product = &sr.product;
        assert!(product.is_file(), "{rel}: product missing");
        let expected_ms: u64 = inputs
            .iter()
            .map(|i| i.segments.iter().map(|s| s.duration_ms).sum::<u64>())
            .max()
            .unwrap_or(0);
        let bytes = std::fs::read(product).unwrap_or_else(|e| panic!("{rel}: read: {e}"));
        // The box-probe's expected track set from the same fold the
        // pipeline itself used (the dual run's first half).
        let content: Vec<&TrackInput> = inputs.iter().collect();
        let expected = synth::build_expectation(&content, &sr.rewrites)
            .unwrap_or_else(|e| panic!("{rel}: expectation fold: {e}"));
        let preport = taiji_media::probe::probe_product_mode(
            &bytes,
            &expected,
            expected_ms,
            &taiji_media::ExpectedMeta::default(),
            taiji_media::probe::ProbeMode::Structural,
        );
        assert!(
            preport.ok(),
            "{rel}: probe violations: {:?}",
            preport.violations
        );
        ffprobe_assert_stream_set_and_duration(rt, product, *want_v, *want_a, expected_ms, rel)
            .await;
        s.join.abort();
    }

    // --- The muxed A/V leg on the **ffmpeg channel**: the fallback
    // remux consumes the whole muxed rendition (both tracks), so the
    // product carries 1 video + 1 audio stream — the stream-set proof
    // that the muxed fixture is genuinely non-video-only. ---
    {
        let rel = "muxed-av/master.m3u8";
        let gid = "900000000000000b";
        let s = sweep_setup("muxed-ff", &addr, rel, gid).await;
        assert!(
            matches!(s.report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
            "muxed-ff: verdict {:?}",
            s.report.verdict
        );
        let inputs = sweep_inputs(&s, &addr, rel, gid).await;
        let expected_ms: u64 = inputs
            .iter()
            .map(|i| i.segments.iter().map(|x| x.duration_ms).sum::<u64>())
            .max()
            .unwrap_or(0);
        let cfg = SynthesisConfig {
            phase_sink: None,
            format: OutputFormat::Mp4,
            muxer: MuxerPreference::Ffmpeg,
            output: s.out_dir.join(format!("{gid}.mp4")),
            staging_dir: s.staging.clone(),
            ffmpeg: ffmpeg.clone(),
            embed_subtitles: false,
            meta: taiji_media::mp4write::MovieMeta::default(),
            free_bytes_override: Some(None),
        };
        let tok = tokio_util::sync::CancellationToken::new();
        let sr = synth::run_synthesis(&inputs, &cfg, tok)
            .await
            .unwrap_or_else(|e| panic!("muxed-ff synthesis: {e}"));
        assert!(sr.product.is_file(), "muxed-ff product lands");
        // Product semantics on BOTH channels: the plan's single
        // (video) track of the muxed rendition is what gets consumed
        // — the fallback maps `-map 0:v:0`, the native fold selects
        // the vide trak (the per-kind selection; a dual-track
        // consumer would be a private synthesis line explicitly
        // declined). The fixture's non-video-only proof is
        // pinned at the source: the matrix-generation test asserts
        // the muxed init parses TWO traks and the canary folds BOTH
        // selections with samples.
        ffprobe_assert_stream_set_and_duration(
            rt,
            &sr.product,
            1,
            0,
            expected_ms,
            "muxed-av/ffmpeg-channel",
        )
        .await;
        s.join.abort();
    }

    // --- TS line: the synthesis fallback face (no init section → ffmpeg
    // remux over the rewritten playlist) + ffprobe dual-run. ---
    {
        let rel = "mkv-fallback/ts.m3u8";
        let gid = "9000000000000009";
        let s = sweep_setup("ts", &addr, rel, gid).await;
        assert!(
            matches!(s.report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
            "ts: verdict {:?}",
            s.report.verdict
        );
        assert!(
            s.staging.join("archive-v.ts").is_file(),
            "TS archive staged"
        );
        // The rewrite (the fallback input form) — produced directly
        // from the downloaded track (the synthesis face; run_synthesis's
        // own verification builder is per-track-fMP4 and cannot carry
        // a TS track, which is exactly why this leg drives the
        // remux face itself).
        let (track, segments) = s
            .ledger
            .load_track(gid, 0)
            .await
            .unwrap_or_else(|e| panic!("load: {e}"))
            .unwrap_or_else(|| panic!("ts track missing"));
        let entry_text = http_get(&addr, rel).await;
        let playlist = match taiji_media::parse_manifest(entry_text.as_bytes())
            .unwrap_or_else(|e| panic!("parse {rel}: {e}"))
        {
            taiji_media::Playlist::Media(m) => m,
            other => panic!("{other:?}"),
        };
        let rw = taiji_media::rewrite_track(&playlist, &segments, "v", &track.local_name)
            .unwrap_or_else(|e| panic!("rewrite: {e}"));
        let local_playlist = s.staging.join("local-v.m3u8");
        std::fs::write(&local_playlist, rw.text.as_bytes())
            .unwrap_or_else(|e| panic!("write local: {e}"));
        let expected_ms: u64 = segments.iter().map(|g| g.duration_ms).sum();
        let out = s.out_dir.join("ts-fallback.mp4");
        let tok = tokio_util::sync::CancellationToken::new();
        let child = rt
            .run_remux(
                &local_playlist,
                None,
                &out,
                taiji_media::FallbackFormat::Mp4,
                None,
                tok,
            )
            .await
            .unwrap_or_else(|e| panic!("remux: {e}"));
        let output = child.wait().await.unwrap_or_else(|e| panic!("wait: {e}"));
        assert!(output.success, "fallback remux exit {:?}", output.code);
        assert!(out.is_file(), "fallback product lands");
        // The TS fallback product's dual validation: the ffprobe
        // stream-set + duration face. The native box probe's
        // expectation set is fold-derived (per-track fMP4 archives —
        // the synthesis design); a TS source has no fold, so a native-probe
        // expectation for this product is not derivable and the
        // ffprobe leg carries the validation (the same posture as the
        // synthesis matrix's TS face).
        let bytes = std::fs::read(&out).unwrap_or_else(|e| panic!("{e}"));
        assert!(bytes.len() > 1024, "a real product, not a stub");
        ffprobe_assert_stream_set_and_duration(rt, &out, 1, 0, expected_ms, "ts").await;
        s.join.abort();
    }

    // --- MKV product: the direct ffprobe stream-set validation (the
    // fallback-only container ruling). ---
    {
        let mkv = root.join("mkv-fallback/sample.mkv");
        let args: Vec<String> = taiji_media::probe_args(&mkv)
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let cmd = taiji_media::MediaCommand::new(taiji_media::MediaBin::Ffprobe, &rt.pair.ffprobe)
            .unwrap_or_else(|e| panic!("{e}"))
            .args(refs)
            .shim_program(rt.shim_program.clone());
        let child = cmd.spawn().unwrap_or_else(|e| panic!("{e}"));
        let out = child.wait().await.unwrap_or_else(|e| panic!("{e}"));
        assert!(out.success, "mkv ffprobe exit");
        let json = taiji_media::FfprobeReport::parse(&out.stdout)
            .unwrap_or_else(|e| panic!("mkv json: {e}"));
        assert_eq!(json.count_codec_type("video"), 1);
        assert_eq!(json.count_codec_type("audio"), 1);
        assert!(json.duration_seconds().unwrap_or(0.0) > 3.5, "≈4 s");
    }
}

/// ffprobe dual-run leg: stream set + duration within ±2 % of
/// ΣEXTINF (the remux duration-tolerance face).
async fn ffprobe_assert_stream_set_and_duration(
    rt: &FfmpegRuntime,
    product: &Path,
    want_v: usize,
    want_a: usize,
    expected_ms: u64,
    tag: &str,
) {
    let args: Vec<String> = taiji_media::probe_args(product)
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let cmd = taiji_media::MediaCommand::new(taiji_media::MediaBin::Ffprobe, &rt.pair.ffprobe)
        .unwrap_or_else(|e| panic!("{e}"))
        .args(refs)
        .shim_program(rt.shim_program.clone());
    let child = cmd.spawn().unwrap_or_else(|e| panic!("{e}"));
    let out = child.wait().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(
        out.success,
        "{tag}: ffprobe exit: {}",
        String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(2048)])
    );
    let json = taiji_media::FfprobeReport::parse(&out.stdout)
        .unwrap_or_else(|e| panic!("{tag}: ffprobe json: {e}"));
    assert_eq!(
        json.count_codec_type("video"),
        want_v,
        "{tag}: {:?}",
        json.stream_summary()
    );
    assert_eq!(
        json.count_codec_type("audio"),
        want_a,
        "{tag}: {:?}",
        json.stream_summary()
    );
    let d = json.duration_seconds().unwrap_or(0.0);
    assert!(
        (expected_ms as f64 / 1000.0 * 0.98..=expected_ms as f64 / 1000.0 * 1.02).contains(&d),
        "{tag}: ffprobe duration {d} vs ΣEXTINF {expected_ms} ms"
    );
}
