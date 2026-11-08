//! The three-vector end-to-end carriers (the parse gate's fixture
//! close-out) — the fixture-level close-out of the
//! parser-layer / decrypt-layer vectors, driven over the
//! generated ffmpeg fixture matrix through a local origin and the
//! real download pipeline.
//!
//! * ① **METHOD=NONE explicit reset** (`aes-rotation`): after the
//!   AES-128 rotation, the METHOD=NONE tail decrypts to plaintext and
//!   never inherits the retired key — the whole archive equals the
//!   ffmpeg plaintext concatenation, by bytes **and** sha256, and the
//!   plaintext segments carry no key id in the ledger;
//! * ② **BYTERANGE omitted offset** (`byterange/omitted`): the
//!   omitted-offset form (per-URI appearance-order accumulation,
//!   RFC 8216 §4.3.2.2) produces a byte-identical archive to the
//!   explicit form, equal to the blob's per-range slices, and the
//!   wire side shows the merged Range GET interval covering exactly
//!   the segment span (one merged GET for the ≤8 adjacent
//!   sub-segments);
//! * ③ **MAP-after-KEY** (`multimap-v8`): the KEY declared before the
//!   second MAP covers that encrypted init — the staged init files
//!   are byte-equal to the expected plaintext inits (decrypted init
//!   archive), the archive equals the expected plaintext segment
//!   concatenation, and the synthesis product probe runs (on the
//!   known-defect branch while the pinned tfhd anchor defect
//!   stands — see `fixture_matrix`).
//!
//! ffmpeg-gated: the whole carrier is the generated-matrix face (the
//! synthetic decrypt-layer vectors already live in `media_crypto_e2e`).

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::TrackSetVerdict;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::synth::{MuxerPreference, OutputFormat, SynthesisConfig};
use taiji_media::trackdl::MediaLedger as _;

use common::fixturegen::{Generator, discover_generator, generate_matrix, sha256_hex};
use common::origin::{spawn_tree_origin, tempdir};

/// Generate the matrix once per binary.
fn matrix() -> Option<(PathBuf, Generator)> {
    static CACHE: std::sync::OnceLock<Option<(PathBuf, Generator)>> = std::sync::OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let fx = discover_generator()?;
        let root = tempdir("taiji-vectors", "tree");
        match generate_matrix(&root, &fx) {
            Ok(_) => Some((root, fx)),
            Err(e) => panic!("fixture matrix generation failed: {e}"),
        }
    });
    (*cached).clone()
}

/// One fixture download into its own scratch + ledger.
async fn download(
    addr: &SocketAddr,
    rel: &str,
    gid: &str,
) -> (
    taiji_media::mediadl::MediaRunReport,
    common::ledger::StoreLedger,
    PathBuf,
    tokio::task::JoinHandle<()>,
) {
    let out_dir = tempdir("taiji-vectors", &format!("dl-{gid}"));
    let db_dir = tempdir("taiji-vectors", &format!("db-{gid}"));
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
    let url = format!("http://{addr}/fx/{rel}");
    let report = dl
        .run(&url, &ledger)
        .await
        .unwrap_or_else(|e| panic!("download {rel}: {e}"));
    (report, ledger, out_dir, join)
}

fn assert_complete(report: &taiji_media::mediadl::MediaRunReport, tag: &str) {
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "{tag}: verdict {:?}",
        report.verdict
    );
}

// ---------------------------------------------------------------------------
// ① METHOD=NONE explicit reset (aes-rotation fixture)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vector1_method_none_reset_archive_sha256() {
    let Some((root, _fx)) = matrix() else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    let (addr, _st) = spawn_tree_origin(&root).await;
    let (report, ledger, _out, join) =
        download(&addr, "aes-rotation/media.m3u8", "a1000000000000001").await;
    assert_complete(&report, "v1");

    // The archive: byte-equal to the ffmpeg plaintext concatenation.
    let expected: Vec<u8> = {
        let mut v = Vec::new();
        let mut names: Vec<String> = std::fs::read_dir(root.join("aes-rotation/expected"))
            .unwrap_or_else(|e| panic!("{e}"))
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("seg") && n.ends_with(".m4s"))
            .collect();
        names.sort();
        assert!(names.len() >= 6, "expected plaintext segments present");
        for n in &names {
            v.extend_from_slice(
                &std::fs::read(root.join("aes-rotation/expected").join(n))
                    .unwrap_or_else(|e| panic!("{e}")),
            );
        }
        v
    };
    let archive = std::fs::read(report.staging_dir.join("archive-v.m4s"))
        .unwrap_or_else(|e| panic!("archive: {e}"));
    assert_eq!(archive.len(), expected.len(), "plaintext length");
    assert_eq!(
        archive, expected,
        "plaintext bytes (rotation × IV × NONE tail)"
    );
    // The sha256 face of the card's ① assertion (plaintext archive
    // sha256 comparison):
    // both sides digested and compared, plus the generator's archived
    // digest for the same expected bytes.
    assert_eq!(sha256_hex(&archive), sha256_hex(&expected));
    let archived_digest =
        std::fs::read_to_string(root.join("aes-rotation/expected/archive.sha256"))
            .unwrap_or_else(|e| panic!("{e}"))
            .trim()
            .to_string();
    assert_eq!(
        sha256_hex(&archive),
        archived_digest,
        "vs the generator's digest"
    );

    // The NONE tail's segments carry no key id (never inherited the
    // retired k2); the encrypted prefix does.
    let (_track, segments) = ledger
        .load_track("a1000000000000001", 0)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("track"));
    let n = segments.len();
    for (i, seg) in segments.iter().enumerate() {
        if i < 4 {
            assert!(seg.key_id.is_some(), "segment {i} is key-covered");
        } else {
            assert!(
                seg.key_id.is_none(),
                "segment {i} (METHOD=NONE tail) must not inherit the retired key"
            );
        }
    }
    assert!(n >= 6, "rotation fixture has the full recipe");
    join.abort();
}

// ---------------------------------------------------------------------------
// ② BYTERANGE omitted offset (wire + archive both faces)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vector2_byterange_omitted_offset_wire_and_archive() {
    let Some((root, _fx)) = matrix() else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    let (addr, st) = spawn_tree_origin(&root).await;

    // The expected archive from the playlist's own ranges + the blob.
    let blob =
        std::fs::read(root.join("byterange/blob.mp4")).unwrap_or_else(|e| panic!("blob: {e}"));
    let manifest = std::fs::read_to_string(root.join("byterange/omitted.m3u8"))
        .unwrap_or_else(|e| panic!("{e}"));
    // (offset, len) per segment line: parse the BYTERANGE+URI pairs.
    let mut spans: Vec<(u64, u64)> = Vec::new();
    let mut pending: Option<(u64, u64)> = None;
    // The cursor state mirrors the parser: the MAP's own
    // BYTERANGE seats the per-URI cursor; omitted offsets consume it.
    let mut cursor: Option<u64> = None;
    for line in manifest.lines() {
        if line.starts_with("#EXT-X-MAP:") {
            if let Some(at) = line.split("BYTERANGE=\"").nth(1) {
                let spec = at.split('"').next().unwrap_or_default();
                if let Some((l, o)) = spec.split_once('@') {
                    let len: u64 = l.trim().parse().unwrap_or(0);
                    let off: u64 = o.trim().parse().unwrap_or(0);
                    cursor = Some(off + len);
                }
            }
        } else if let Some(rest) = line.strip_prefix("#EXT-X-BYTERANGE:") {
            let len: u64 = rest
                .split('@')
                .next()
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or_else(|e| panic!("len: {e}"));
            let off = rest
                .split_once('@')
                .and_then(|(_, o)| o.trim().parse::<u64>().ok());
            pending = Some(match off {
                Some(o) => (o, len),
                None => {
                    let base = cursor
                        .or_else(|| spans.last().map(|(o, l)| o + l))
                        .unwrap_or_else(|| panic!("omitted offset with no cursor"));
                    (base, len)
                }
            });
        } else if !line.starts_with('#') && !line.is_empty() {
            if let Some(sp) = pending.take() {
                cursor = Some(sp.0 + sp.1);
                spans.push(sp);
            }
        }
    }
    let mut expected: Vec<u8> = Vec::new();
    for (off, len) in &spans {
        expected.extend_from_slice(&blob[*off as usize..(*off + *len) as usize]);
    }
    assert!(spans.len() >= 3, "the fixture carries a real chain");

    // Run the omitted-offset form; the wire side must show the merged
    // Range GET (one GET for the adjacent sub-segment run).
    st.blob_hits.store(0, std::sync::atomic::Ordering::SeqCst);
    st.blob_ranges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    let (report, _ledger, _out, join) =
        download(&addr, "byterange/omitted.m3u8", "a1000000000000002").await;
    assert_complete(&report, "v2-omitted");
    let archive = std::fs::read(report.staging_dir.join("archive-v.m4s"))
        .unwrap_or_else(|e| panic!("archive: {e}"));
    assert_eq!(archive, expected, "omitted-offset archive == blob slices");

    // Wire face: the omitted-offset run's Range GETs on the blob tile
    // the segment span EXACTLY — the init MAP range is its own GET,
    // and the segment GETs (grid blocks over the merged sub-segment
    // extents) form a gapless, overlap-free cover of [first offset,
    // last end). The ≤8-adjacent-sub-segment merge means one extent
    // per block, not one GET for the whole span (a span wider than
    // the block size legitimately splits at block boundaries).
    let ranges = st.ranges();
    let seg_span = (
        spans.first().copied().unwrap_or((0, 0)).0,
        spans.last().map(|(o, l)| o + l).unwrap_or(0),
    );
    let init_len: u64 = spans.first().copied().unwrap_or((0, 0)).0;
    assert!(
        ranges.iter().any(|r| parse_bounds(r) == (0, init_len)),
        "the init MAP range is its own GET: {ranges:?}"
    );
    let mut seg_ranges: Vec<(u64, u64)> = ranges
        .iter()
        .map(|r| parse_bounds(r))
        .filter(|(a, _)| *a >= init_len)
        .collect();
    seg_ranges.sort();
    assert!(
        !seg_ranges.is_empty(),
        "at least one segment GET: {ranges:?}"
    );
    assert_eq!(
        seg_ranges.first().copied().unwrap_or((0, 0)).0,
        seg_span.0,
        "cover starts at the first segment offset: {seg_ranges:?}"
    );
    let mut cursor = seg_span.0;
    for (a, b) in &seg_ranges {
        assert_eq!(*a, cursor, "gapless tiling: {seg_ranges:?}");
        cursor = *b;
    }
    assert_eq!(cursor, seg_span.1, "cover ends at the last segment end");
    join.abort();

    // The explicit form: byte-identical archive AND the identical
    // wire interval set (cross-checking both faces).
    st.blob_hits.store(0, std::sync::atomic::Ordering::SeqCst);
    st.blob_ranges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    let (report2, _ledger2, _out2, join2) =
        download(&addr, "byterange/explicit.m3u8", "a1000000000000003").await;
    assert_complete(&report2, "v2-explicit");
    let archive2 = std::fs::read(report2.staging_dir.join("archive-v.m4s"))
        .unwrap_or_else(|e| panic!("archive: {e}"));
    assert_eq!(archive, archive2, "explicit == omitted (RFC 8216 §4.3.2.2)");
    let mut explicit_ranges: Vec<(u64, u64)> = st
        .ranges()
        .iter()
        .map(|r| parse_bounds(r))
        .filter(|(a, _)| *a >= init_len)
        .collect();
    explicit_ranges.sort();
    assert_eq!(
        seg_ranges, explicit_ranges,
        "the wire intervals are identical between the explicit and omitted forms"
    );
    join2.abort();
}

fn parse_bounds(range: &str) -> (u64, u64) {
    // "bytes=a-b" (inclusive) → (a, b+1).
    let spec = range.trim().strip_prefix("bytes=").unwrap_or("");
    match spec.split_once('-') {
        Some((a, b)) => (
            a.parse().unwrap_or(0),
            b.parse::<u64>().map(|v| v + 1).unwrap_or(0),
        ),
        None => (0, 0),
    }
}

// ---------------------------------------------------------------------------
// ③ MAP-after-KEY (multimap-v8 fixture)
// ---------------------------------------------------------------------------

// (Post-fix: the tfhd-anchor defect this file's vector ③
// once pinned is fixed — the canary account lives in
// `fixture_matrix`; the vector now requires the synthesis to pass.)

#[tokio::test]
async fn vector3_map_after_key_init_decrypt_and_product_probe() {
    let Some((root, _fx)) = matrix() else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    let (addr, _st) = spawn_tree_origin(&root).await;
    let (report, ledger, out_dir, join) =
        download(&addr, "multimap-v8/media.m3u8", "a1000000000000004").await;
    assert_complete(&report, "v3");

    // (a) The decrypted init archives: both staged init files are
    // byte-equal to the expected plaintext inits — init0 under the
    // v8 MAP KEY= attribute, init1 under the ambient KEY declared
    // BEFORE the MAP (the v0.3.1 boundary), default-IV chain falling
    // back to the first following segment's sequence.
    let staging = &report.staging_dir;
    for (staged, expected) in [
        ("init-v-0.mp4", "expected/init0.mp4"),
        ("init-v-1.mp4", "expected/init1.mp4"),
    ] {
        let got = std::fs::read(staging.join(staged)).unwrap_or_else(|e| panic!("{e}"));
        let want = std::fs::read(root.join("multimap-v8").join(expected))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, want, "{staged} decrypts to the plaintext init");
    }

    // (b) The segment archive: the decrypted concatenation.
    let mut expected: Vec<u8> = Vec::new();
    let mut names: Vec<String> = std::fs::read_dir(root.join("multimap-v8/expected"))
        .unwrap_or_else(|e| panic!("{e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("seg") && n.ends_with(".m4s"))
        .collect();
    names.sort();
    for n in &names {
        expected.extend_from_slice(
            &std::fs::read(root.join("multimap-v8/expected").join(n))
                .unwrap_or_else(|e| panic!("{e}")),
        );
    }
    let archive =
        std::fs::read(staging.join("archive-v.m4s")).unwrap_or_else(|e| panic!("archive: {e}"));
    assert_eq!(archive, expected, "v3 archive == expected plaintext");

    // (c) The synthesis product probe (dual validation's second face). While
    // the pinned tfhd anchor defect stands the synthesis is
    // blocked in the fold; assert the exact signature (the canary in
    // `fixture_matrix` pins the defect itself). Once fixed, this leg
    // requires the full product + structural probe.
    let ffmpeg = common::ffmpeg_lab::local_ffmpeg().await;
    let mut inputs = Vec::new();
    for (planned, state) in &report.tracks {
        if !matches!(state, taiji_media::TrackState::Done) {
            continue;
        }
        let (track, segments) = ledger
            .load_track("a1000000000000004", planned.track_idx)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("track"));
        let entry =
            std::fs::read_to_string(staging.join("source.m3u8")).unwrap_or_else(|e| panic!("{e}"));
        let playlist =
            match taiji_media::parse_manifest(entry.as_bytes()).unwrap_or_else(|e| panic!("{e}")) {
                taiji_media::Playlist::Media(m) => m,
                other => panic!("{other:?}"),
            };
        let inits: Vec<PathBuf> = track.init_files.iter().map(|n| staging.join(n)).collect();
        inputs.push(taiji_media::synth::TrackInput {
            label: planned.label.clone(),
            kind: planned.kind.as_str().to_string(),
            archive: staging.join(&track.local_name),
            inits,
            segments,
            playlist,
            archive_name: track.local_name.clone(),
        });
    }
    assert_eq!(inputs.len(), 1, "the single video track");
    let cfg = SynthesisConfig {
        phase_sink: None,
        format: OutputFormat::Mp4,
        muxer: MuxerPreference::Auto,
        output: out_dir.join("v3.mp4"),
        staging_dir: staging.clone(),
        ffmpeg,
        embed_subtitles: false,
        meta: taiji_media::mp4write::MovieMeta::default(),
        free_bytes_override: Some(None),
    };
    let tok = tokio_util::sync::CancellationToken::new();
    // Post-fix: the fold accepts real-encoder tfhd anchors,
    // so the vector's synthesis must SUCCEED and pass the box probe
    // with the fold-derived expectation (the pre-fix row landed on the
    // known-defect branch instead).
    let sr = taiji_media::synth::run_synthesis(&inputs, &cfg, tok)
        .await
        .unwrap_or_else(|e| panic!("v3 synthesis (post-fix must pass): {e}"));
    {
        let bytes = std::fs::read(&sr.product).unwrap_or_else(|e| panic!("product: {e}"));
        let expected_ms: u64 = inputs[0].segments.iter().map(|s| s.duration_ms).sum();
        let content: Vec<&taiji_media::synth::TrackInput> = inputs.iter().collect();
        let expected = taiji_media::synth::build_expectation(&content, &sr.rewrites)
            .unwrap_or_else(|e| panic!("v3 expectation fold: {e}"));
        let preport = taiji_media::probe::probe_product_mode(
            &bytes,
            &expected,
            expected_ms,
            &taiji_media::ExpectedMeta::default(),
            taiji_media::probe::ProbeMode::Structural,
        );
        assert!(preport.ok(), "v3 product probe: {:?}", preport.violations);
    }
    join.abort();
}
