//! VOD fixture generator (the 0.3.0 VOD subset of the media fixture
//! matrix) — an ffmpeg-driven, **reproducible**
//! builder shared by the test binaries (`fixture_matrix`,
//! `vectors_e2e`, the perf gates).
//!
//! Reproducibility contract ("generation recipe + product
//! sha256 manifest archived; fixed inputs rebuild bit-identical"):
//! * every ffmpeg invocation pins a fixed argv (lavfi synthetic
//! sources, `-threads 1`, `+bitexact` on container/streams, fixed
//! x264 params — no wall-clock/machine state in the output) and runs
//! with the target directory as cwd so the muxer-written playlists
//! carry bare relative URIs (no absolute paths in any product);
//! * the AES-128 post-processing (rotation/MAP-after-KEY encryption —
//! ffmpeg's hls muxer cannot express key rotation) is a pure-Rust
//! AES-128-CBC pass with fixed key/IV constants;
//! * [`generate_matrix`] writes the whole tree plus `SHA256SUMS`
//! (every product, sorted relative paths) and `RECIPE.json` (ffmpeg
//! version line, the recorded argv of every invocation, the crypto
//! constants). A second run over the same ffmpeg build is
//! **bit-identical** — the rebuild cross-check the matrix test asserts.
//!
//! The claim is machine/ffmpeg-build scoped (a different ffmpeg build
//! may encode differently): RECIPE.json records the exact version
//! line, and the rebuild cross-check is run against the same build that wrote
//! the archived SHA256SUMS.
//!
//! Matrix (the 0.3.0 VOD subset):
//! 1. `master-multibitrate` — master with 3 variants (240/180/120p);
//! 2. `independent-audio` — EXT-X-MEDIA audio rendition + video-only
//! variants (AUDIO group);
//! 3. `aes-rotation` — ≥2 KEY rotated exactly at segment boundaries,
//! explicit + default (media-sequence) IV forms, then the
//! vector-① METHOD=NONE reset tail;
//! 4. `byterange` — single-file fMP4 (MAP + segments as byte ranges
//! of one resource), explicit form as muxed plus the
//! vector-② **omitted-offset** derived form;
//! 5. `discontinuity` — two fMP4 parts at different resolutions
//! joined at an EXT-X-DISCONTINUITY with per-part MAPs;
//! 6. `nonzero-seq` — MEDIA-SEQUENCE base 50_000 media playlist;
//! 7. `multimap-v8` — v8 `KEY=` attribute on the first MAP + the
//! vector-③ MAP-after-KEY boundary (an ambient KEY declared
//! before the second MAP covers that encrypted init; default-IV
//! chain falls back to the first following segment's sequence);
//! 8. `mkv-fallback` — mpegts-segment playlist (the synthesis TS fallback
//! trigger: no init section) + a matroska product (the MKV form);
//! 9. `hundredk` — a 100 000-segment BYTERANGE manifest (the
//! ≤100k in-cap boundary form; the parse-gate carrier).
//!
//! This module is test-support only — never product code.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use sha2::{Digest as _, Sha256};

type Enc128 = cbc::Encryptor<aes::Aes128>;

/// Generator revision — bump when any recipe changes (the archived
/// SHA256SUMS of a previous revision no longer applies).
pub const GENERATOR_REV: &str = "media-fixturegen-r2";

/// Fixed crypto constants (recorded in RECIPE.json).
pub const K1: [u8; 16] = *b"taiji-fxgen-k1!!";
pub const K2: [u8; 16] = *b"taiji-fxgen-k2!!";
pub const K3: [u8; 16] = *b"taiji-fxgen-k3!!";
/// Vector-① explicit IVs (fixed, recorded).
pub const IV1: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const IV3: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];

/// The discovered, version-recorded ffmpeg pair (lenient: the
/// license gate is a production posture — the dev machine's Homebrew
/// build carries `--enable-gpl`, the recorded e2e_real fact).
#[derive(Clone)]
pub struct Generator {
    pub ffmpeg: PathBuf,
    pub ffprobe: PathBuf,
    /// The first line of `ffmpeg -version` (recorded in RECIPE.json).
    pub version_line: String,
}

/// Discover the generator's ffmpeg/ffprobe (None = absent; callers
/// skip the ffmpeg-driven faces with a clear message, the
/// runtime-guard posture).
pub fn discover_generator() -> Option<Generator> {
    let pair = taiji_media::discover(&taiji_media::DiscoveryRequest::default()).ok()?;
    let out = Command::new(&pair.ffmpeg)
        .arg("-version")
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let version_line = text.lines().next()?.to_string();
    Some(Generator {
        ffmpeg: pair.ffmpeg,
        ffprobe: pair.ffprobe,
        version_line,
    })
}

/// AES-128-CBC + PKCS7 (the encrypt side of the fixture builder; the
/// product decrypt core in `taiji_media::decrypt` is its inverse).
pub fn encrypt(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    Enc128::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_iv(iv: &[u8; 16]) -> String {
    let mut s = String::from("0x");
    for b in iv {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// The default IV for absolute media sequence `seq` (big-endian 128
/// — the decrypt chain; used both to encrypt and to spell the playlist).
pub fn seq_iv(seq: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[8..].copy_from_slice(&seq.to_be_bytes());
    iv
}

/// Run one pinned ffmpeg invocation with `dir` as cwd, recording the
/// argv into `log`. Returns failure text on a non-zero exit.
fn run_ffmpeg(
    fx: &Generator,
    dir: &Path,
    args: &[&str],
    log: &mut Vec<Vec<String>>,
) -> Result<(), String> {
    log.push(
        std::iter::once("ffmpeg".to_string())
            .chain(args.iter().map(|a| a.to_string()))
            .collect(),
    );
    let out = Command::new(&fx.ffmpeg)
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("spawn ffmpeg: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ffmpeg {args:?} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(1024)])
        ));
    }
    Ok(())
}

/// Determinism argv shared by every encode: single thread + bitexact
/// flags on container and both streams.
const DET_ARGS: [&str; 6] = [
    "-threads",
    "1",
    "-fflags",
    "+bitexact",
    "-flags",
    "+bitexact",
];

/// Encode one fMP4 HLS variant of `size` (video only unless `audio`),
/// 6 s, ~1 s segments, into `dir`. Returns the segment count muxed.
#[allow(clippy::too_many_arguments)]
fn gen_fmp4_variant(
    fx: &Generator,
    dir: &Path,
    w: u32,
    h: u32,
    audio: bool,
    duration_s: u32,
    hls_time: u32,
    log: &mut Vec<Vec<String>>,
) -> Result<usize, String> {
    let size = format!("size={w}x{h}:rate=12:duration={duration_s}");
    let mut args: Vec<String> = vec![
        "-y".into(),
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-f".into(),
        "lavfi".into(),
        "-i".into(),
        format!("testsrc2={size}"),
    ];
    if audio {
        args.push("-f".into());
        args.push("lavfi".into());
        args.push("-i".into());
        args.push(format!(
            "sine=frequency=440:sample_rate=44100:duration={duration_s}"
        ));
    }
    args.extend([
        "-c:v".to_string(),
        "libx264".to_string(),
        "-preset".to_string(),
        "ultrafast".to_string(),
        "-x264-params".to_string(),
        "keyint=12:min-keyint=12:scenecut=0:threads=1".to_string(),
        "-pix_fmt".to_string(),
        "yuv420p".to_string(),
    ]);
    if audio {
        args.extend([
            "-c:a".to_string(),
            "aac".to_string(),
            "-ac".to_string(),
            "1".to_string(),
            "-b:a".to_string(),
            "48k".to_string(),
            "-ar".to_string(),
            "44100".to_string(),
        ]);
    } else {
        args.push("-an".to_string());
    }
    args.extend(DET_ARGS.iter().map(|s| s.to_string()));
    args.extend([
        "-f".to_string(),
        "hls".to_string(),
        "-hls_time".to_string(),
        hls_time.to_string(),
        "-hls_list_size".to_string(),
        "0".to_string(),
        "-hls_playlist_type".to_string(),
        "vod".to_string(),
        "-hls_segment_type".to_string(),
        "fmp4".to_string(),
        "-hls_flags".to_string(),
        "independent_segments".to_string(),
        "-hls_segment_filename".to_string(),
        "seg%03d.m4s".to_string(),
        "-hls_fmp4_init_filename".to_string(),
        "init.mp4".to_string(),
        "media.m3u8".to_string(),
    ]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ffmpeg(fx, dir, &refs, log)?;
    // Count the muxed segments (media.m3u8's EXTINF lines).
    let text = std::fs::read_to_string(dir.join("media.m3u8"))
        .map_err(|e| format!("read media.m3u8: {e}"))?;
    Ok(text.lines().filter(|l| l.starts_with("#EXTINF")).count())
}

/// Generate the whole matrix into `root` (created). Returns the
/// per-product sha256 list written to SHA256SUMS. `Err` = an ffmpeg
/// invocation failed — the caller must treat the tree as unusable.
pub fn generate_matrix(root: &Path, fx: &Generator) -> Result<Vec<(String, String)>, String> {
    let mut argv_log: Vec<Vec<String>> = Vec::new();
    std::fs::create_dir_all(root).map_err(|e| format!("mkdir: {e}"))?;

    // ---- 1. master-multibitrate: 3 video-only variants ------------
    let mmb = root.join("master-multibitrate");
    for (name, w, h) in [
        ("v240", 426u32, 240u32),
        ("v180", 320, 180),
        ("v120", 214, 120),
    ] {
        let dir = mmb.join(name);
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
        gen_fmp4_variant(fx, &dir, w, h, false, 6, 1, &mut argv_log)?;
    }
    let mut master = String::from("#EXTM3U\n#EXT-X-VERSION:7\n");
    master.push_str("#EXT-X-INDEPENDENT-SEGMENTS\n");
    master
        .push_str("#EXT-X-STREAM-INF:BANDWIDTH=400000,RESOLUTION=426x240,CODECS=\"avc1.64000d\"\n");
    master.push_str("v240/media.m3u8\n");
    master
        .push_str("#EXT-X-STREAM-INF:BANDWIDTH=250000,RESOLUTION=320x180,CODECS=\"avc1.64000d\"\n");
    master.push_str("v180/media.m3u8\n");
    master
        .push_str("#EXT-X-STREAM-INF:BANDWIDTH=120000,RESOLUTION=214x120,CODECS=\"avc1.64000d\"\n");
    master.push_str("v120/media.m3u8\n");
    std::fs::write(mmb.join("master.m3u8"), master).map_err(|e| format!("write: {e}"))?;

    // ---- 2. independent-audio: video variant + audio rendition ----
    let iau = root.join("independent-audio");
    let vid = iau.join("video");
    let aud = iau.join("audio");
    std::fs::create_dir_all(&vid).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::create_dir_all(&aud).map_err(|e| format!("mkdir: {e}"))?;
    gen_fmp4_variant(fx, &vid, 426, 240, false, 6, 1, &mut argv_log)?;
    gen_fmp4_variant(fx, &aud, 64, 48, true, 6, 2, &mut argv_log)?;
    let mut master = String::from("#EXTM3U\n#EXT-X-VERSION:7\n");
    master.push_str(
        "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en\",NAME=\"English\",DEFAULT=YES,URI=\"audio/media.m3u8\"\n",
    );
    master.push_str(
        "#EXT-X-STREAM-INF:BANDWIDTH=400000,RESOLUTION=426x240,CODECS=\"avc1.64000d,mp4a.40.2\",AUDIO=\"aud\"\n",
    );
    master.push_str("video/media.m3u8\n");
    std::fs::write(iau.join("master.m3u8"), master).map_err(|e| format!("write: {e}"))?;

    // ---- 3. aes-rotation (vector ① carrier) ------------------------
    // Plaintext variant (video-only) → encrypted copies + expected/.
    let aes = root.join("aes-rotation");
    let plain = aes.join("plain");
    std::fs::create_dir_all(&plain).map_err(|e| format!("mkdir: {e}"))?;
    let nsegs = gen_fmp4_variant(fx, &plain, 426, 240, false, 6, 1, &mut argv_log)?;
    if nsegs < 6 {
        return Err(format!(
            "aes-rotation needs ≥6 segments for the rotation×IV×NONE recipe, muxed {nsegs}"
        ));
    }
    std::fs::create_dir_all(aes.join("keys")).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::create_dir_all(aes.join("expected")).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::write(aes.join("keys/k1.bin"), K1).map_err(|e| format!("write: {e}"))?;
    std::fs::write(aes.join("keys/k2.bin"), K2).map_err(|e| format!("write: {e}"))?;
    // MEDIA-SEQUENCE base 50_000 (non-zero default-IV chain).
    const SEQ_BASE: u64 = 50_000;
    let mut media = String::from("#EXTM3U\n#EXT-X-VERSION:5\n");
    media.push_str("#EXT-X-TARGETDURATION:1\n");
    media.push_str(&format!("#EXT-X-MEDIA-SEQUENCE:{SEQ_BASE}\n"));
    media.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    media.push_str("#EXT-X-MAP:URI=\"init.mp4\"\n");
    media.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"keys/k1.bin\",IV={}\n",
        hex_iv(&IV1)
    ));
    let mut expected_plain: Vec<u8> = Vec::new();
    let init = std::fs::read(plain.join("init.mp4")).map_err(|e| format!("read init: {e}"))?;
    std::fs::write(aes.join("expected/init.mp4"), &init).map_err(|e| format!("write: {e}"))?;
    // init.mp4 stays plaintext (MAP before any KEY → plaintext init).
    std::fs::copy(plain.join("init.mp4"), aes.join("init.mp4"))
        .map_err(|e| format!("copy init: {e}"))?;
    for i in 0..nsegs {
        let name = format!("seg{i:03}.m4s");
        let bytes = std::fs::read(plain.join(&name)).map_err(|e| format!("read {name}: {e}"))?;
        std::fs::write(aes.join(format!("expected/{name}")), &bytes)
            .map_err(|e| format!("write: {e}"))?;
        expected_plain.extend_from_slice(&bytes);
        if i == 2 {
            // Rotation point 1: k1@IV1 (explicit) → k2 (default IV =
            // absolute sequence). Exactly at the segment boundary.
            media.push_str("#EXT-X-KEY:METHOD=AES-128,URI=\"keys/k2.bin\"\n");
        }
        if i == 4 {
            // Vector ①: METHOD=NONE reset — the tail is plaintext and
            // must never inherit k2.
            media.push_str("#EXT-X-KEY:METHOD=NONE\n");
        }
        if i < 2 {
            media.push_str(&format!("#EXTINF:1.0,\neseg{i:03}.m4s\n"));
            let cipher = encrypt(&K1, &IV1, &bytes);
            std::fs::write(aes.join(format!("eseg{i:03}.m4s")), cipher)
                .map_err(|e| format!("write: {e}"))?;
        } else if i < 4 {
            media.push_str(&format!("#EXTINF:1.0,\neseg{i:03}.m4s\n"));
            let iv = seq_iv(SEQ_BASE + i as u64);
            let cipher = encrypt(&K2, &iv, &bytes);
            std::fs::write(aes.join(format!("eseg{i:03}.m4s")), cipher)
                .map_err(|e| format!("write: {e}"))?;
        } else {
            media.push_str(&format!("#EXTINF:1.0,\npseg{i:03}.m4s\n"));
            std::fs::copy(plain.join(&name), aes.join(format!("pseg{i:03}.m4s")))
                .map_err(|e| format!("copy {name}: {e}"))?;
        }
    }
    media.push_str("#EXT-X-ENDLIST\n");
    std::fs::write(aes.join("media.m3u8"), media).map_err(|e| format!("write: {e}"))?;
    std::fs::write(
        aes.join("expected/archive.sha256"),
        format!("{}\n", sha256_hex(&expected_plain)),
    )
    .map_err(|e| format!("write: {e}"))?;

    // ---- 4. byterange (vector ② carrier) ---------------------------
    let br = root.join("byterange");
    std::fs::create_dir_all(&br).map_err(|e| format!("mkdir: {e}"))?;
    {
        // Single-file fMP4: MAP + segments as explicit byte ranges of
        // blob.mp4. Video-only by design: the vector's subject is the
        // BYTERANGE offset semantics, and a muxed A/V rendition (the
        // real-world single-file form) trips the synthesis verification
        // builder's per-track single-trak constraint — that gap is a
        // separately reported finding, not this fixture's subject.
        let mut args: Vec<String> = vec![
            "-y".into(),
            "-hide_banner".into(),
            "-loglevel".into(),
            "error".into(),
            "-f".into(),
            "lavfi".into(),
            "-i".into(),
            "testsrc2=size=426x240:rate=12:duration=5".to_string(),
            "-c:v".into(),
            "libx264".into(),
            "-preset".into(),
            "ultrafast".into(),
            "-x264-params".into(),
            "keyint=12:min-keyint=12:scenecut=0:threads=1".to_string(),
            "-pix_fmt".into(),
            "yuv420p".to_string(),
            "-an".into(),
        ];
        args.extend(DET_ARGS.iter().map(|s| s.to_string()));
        args.extend([
            "-f".to_string(),
            "hls".to_string(),
            "-hls_time".to_string(),
            "1".to_string(),
            "-hls_list_size".to_string(),
            "0".to_string(),
            "-hls_playlist_type".to_string(),
            "vod".to_string(),
            "-hls_segment_type".to_string(),
            "fmp4".into(),
            "-hls_flags".to_string(),
            "independent_segments+single_file".to_string(),
            "-hls_segment_filename".to_string(),
            "blob.mp4".to_string(),
            "-hls_fmp4_init_filename".to_string(),
            "blob.mp4".to_string(),
            "explicit.m3u8".to_string(),
        ]);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_ffmpeg(fx, &br, &refs, &mut argv_log)?;
    }
    // Derive the omitted-offset form: continuation ranges of the same
    // URI drop the @offset (RFC 8216 §4.3.2.2 — accumulated by
    // appearance order). The MAP BYTERANGE and the first explicit
    // range stay; later same-URI ranges lose the offset.
    let explicit = std::fs::read_to_string(br.join("explicit.m3u8"))
        .map_err(|e| format!("read explicit.m3u8: {e}"))?;
    let mut omitted = String::new();
    let mut seen_uri_ranges: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in explicit.lines() {
        if let Some(rest) = line.strip_prefix("#EXT-X-BYTERANGE:") {
            // "len@off" — drop the offset when this URI already
            // carried an explicit range (the cursor takes over).
            let uri_key = "blob.mp4".to_string();
            if seen_uri_ranges.contains(&uri_key) {
                let len = rest.split('@').next().unwrap_or(rest);
                omitted.push_str("#EXT-X-BYTERANGE:");
                omitted.push_str(len.trim());
                omitted.push('\n');
                continue;
            }
            seen_uri_ranges.insert(uri_key);
            omitted.push_str(line);
            omitted.push('\n');
        } else if let Some(rest) = line.strip_prefix("#EXT-X-MAP:") {
            // The MAP's own BYTERANGE seats the cursor; keep verbatim
            // but mark the URI as ranged.
            if rest.contains("BYTERANGE=") {
                seen_uri_marks_map(&mut seen_uri_ranges, rest);
            }
            omitted.push_str(line);
            omitted.push('\n');
        } else {
            omitted.push_str(line);
            omitted.push('\n');
        }
    }
    std::fs::write(br.join("omitted.m3u8"), omitted).map_err(|e| format!("write: {e}"))?;

    // ---- 4b. muxed-av (the muxed-A/V matrix row): the dominant
    // real-world single-file BYTERANGE form — ONE media file whose
    // init carries BOTH traks and whose segments interleave the two
    // tracks' fragments. The pre-fix reader rejected ≥2-trak inits
    // outright (the recorded defect #3); the fold now selects per track
    // kind. Audio input + single_file, mirroring the byterange leg.
    let mav = root.join("muxed-av");
    std::fs::create_dir_all(&mav).map_err(|e| format!("mkdir: {e}"))?;
    {
        let mut args: Vec<String> = vec![
            "-y".into(),
            "-hide_banner".into(),
            "-loglevel".into(),
            "error".into(),
            "-f".into(),
            "lavfi".into(),
            "-i".into(),
            "testsrc2=size=426x240:rate=12:duration=5".to_string(),
            "-f".into(),
            "lavfi".into(),
            "-i".into(),
            "sine=frequency=440:sample_rate=44100:duration=5".to_string(),
            "-c:v".into(),
            "libx264".into(),
            "-preset".into(),
            "ultrafast".into(),
            "-x264-params".into(),
            "keyint=12:min-keyint=12:scenecut=0:threads=1".to_string(),
            "-pix_fmt".into(),
            "yuv420p".into(),
            "-c:a".into(),
            "aac".into(),
            "-ac".into(),
            "1".into(),
            "-b:a".into(),
            "48k".into(),
            "-ar".into(),
            "44100".into(),
        ];
        args.extend(DET_ARGS.iter().map(|s| s.to_string()));
        args.extend([
            "-f".into(),
            "hls".into(),
            "-hls_time".into(),
            "1".into(),
            "-hls_list_size".into(),
            "0".into(),
            "-hls_playlist_type".into(),
            "vod".into(),
            "-hls_segment_type".into(),
            "fmp4".into(),
            "-hls_flags".into(),
            "independent_segments+single_file".into(),
            "-hls_segment_filename".into(),
            "muxed.mp4".into(),
            "-hls_fmp4_init_filename".into(),
            "muxed.mp4".into(),
            "muxed.m3u8".into(),
        ]);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_ffmpeg(fx, &mav, &refs, &mut argv_log)?;
    }
    // The muxed master (single variant, no EXT-X-MEDIA group — the
    // audio rides inside the rendition).
    let mut mav_master = String::from("#EXTM3U\n#EXT-X-VERSION:7\n");
    mav_master.push_str("#EXT-X-INDEPENDENT-SEGMENTS\n");
    mav_master.push_str(
        "#EXT-X-STREAM-INF:BANDWIDTH=500000,RESOLUTION=426x240,CODECS=\"avc1.64000d,mp4a.40.2\"\n",
    );
    mav_master.push_str("muxed.m3u8\n");
    std::fs::write(mav.join("master.m3u8"), mav_master).map_err(|e| format!("write: {e}"))?;

    // ---- 5. discontinuity (two parts, per-part MAP) ----------------
    let disc = root.join("discontinuity");
    let p0 = disc.join("p0");
    let p1 = disc.join("p1");
    std::fs::create_dir_all(&p0).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::create_dir_all(&p1).map_err(|e| format!("mkdir: {e}"))?;
    let n0 = gen_fmp4_variant(fx, &p0, 426, 240, false, 3, 1, &mut argv_log)?;
    let n1 = gen_fmp4_variant(fx, &p1, 320, 180, false, 3, 1, &mut argv_log)?;
    let mut media = String::from("#EXTM3U\n#EXT-X-VERSION:7\n");
    media.push_str("#EXT-X-TARGETDURATION:1\n");
    media.push_str("#EXT-X-MEDIA-SEQUENCE:9\n");
    media.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    media.push_str("#EXT-X-MAP:URI=\"p0/init.mp4\"\n");
    for i in 0..n0 {
        media.push_str(&format!("#EXTINF:1.0,\np0/seg{i:03}.m4s\n"));
    }
    media.push_str("#EXT-X-DISCONTINUITY\n");
    media.push_str("#EXT-X-MAP:URI=\"p1/init.mp4\"\n");
    for i in 0..n1 {
        media.push_str(&format!("#EXTINF:1.0,\np1/seg{i:03}.m4s\n"));
    }
    media.push_str("#EXT-X-ENDLIST\n");
    std::fs::write(disc.join("media.m3u8"), media).map_err(|e| format!("write: {e}"))?;

    // ---- 6. nonzero-seq ---------------------------------------------
    let nzs = root.join("nonzero-seq");
    std::fs::create_dir_all(&nzs).map_err(|e| format!("mkdir: {e}"))?;
    let nn = gen_fmp4_variant(fx, &nzs, 426, 240, false, 6, 1, &mut argv_log)?;
    let mut media = String::from("#EXTM3U\n#EXT-X-VERSION:7\n");
    media.push_str("#EXT-X-TARGETDURATION:1\n");
    media.push_str("#EXT-X-MEDIA-SEQUENCE:50000\n");
    media.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    media.push_str("#EXT-X-MAP:URI=\"init.mp4\"\n");
    for i in 0..nn {
        media.push_str(&format!("#EXTINF:1.0,\nseg{i:03}.m4s\n"));
    }
    media.push_str("#EXT-X-ENDLIST\n");
    std::fs::write(nzs.join("media.m3u8"), media).map_err(|e| format!("write: {e}"))?;

    // ---- 7. multimap-v8 (vector ③ carrier) -------------------------
    let mm = root.join("multimap-v8");
    let q0 = mm.join("p0");
    let q1 = mm.join("p1");
    std::fs::create_dir_all(&q0).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::create_dir_all(&q1).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::create_dir_all(mm.join("keys")).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::create_dir_all(mm.join("expected")).map_err(|e| format!("mkdir: {e}"))?;
    let m0 = gen_fmp4_variant(fx, &q0, 426, 240, false, 3, 1, &mut argv_log)?;
    let m1 = gen_fmp4_variant(fx, &q1, 320, 180, false, 3, 1, &mut argv_log)?;
    std::fs::write(mm.join("keys/k1.bin"), K1).map_err(|e| format!("write: {e}"))?;
    std::fs::write(mm.join("keys/k2.bin"), K2).map_err(|e| format!("write: {e}"))?;
    std::fs::write(mm.join("keys/k3.bin"), K3).map_err(|e| format!("write: {e}"))?;
    // init0: encrypted under the MAP's own v8 KEY= attribute (k3@IV3).
    let init0 = std::fs::read(q0.join("init.mp4")).map_err(|e| format!("read: {e}"))?;
    std::fs::write(mm.join("expected/init0.mp4"), &init0).map_err(|e| format!("w: {e}"))?;
    std::fs::write(mm.join("einit0.mp4"), encrypt(&K3, &IV3, &init0))
        .map_err(|e| format!("w: {e}"))?;
    // init1: encrypted under the ambient k2 (declared BEFORE the MAP
    // — the MAP-after-KEY boundary); k2 carries no explicit IV so the
    // init's IV falls back to the sequence of the first segment this
    // MAP applies to (= SEQ_BASE2 + m0, the first part-1 segment).
    const SEQ_BASE2: u64 = 77_000;
    let init1 = std::fs::read(q1.join("init.mp4")).map_err(|e| format!("read: {e}"))?;
    std::fs::write(mm.join("expected/init1.mp4"), &init1).map_err(|e| format!("w: {e}"))?;
    std::fs::write(
        mm.join("einit1.mp4"),
        encrypt(&K2, &seq_iv(SEQ_BASE2 + m0 as u64), &init1),
    )
    .map_err(|e| format!("w: {e}"))?;
    let mut media = String::from("#EXTM3U\n#EXT-X-VERSION:8\n");
    media.push_str("#EXT-X-TARGETDURATION:1\n");
    media.push_str(&format!("#EXT-X-MEDIA-SEQUENCE:{SEQ_BASE2}\n"));
    media.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    // Ambient k1 covers part-0's segments...
    media.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"keys/k1.bin\",IV={}\n",
        hex_iv(&IV1)
    ));
    // ...while the MAP's own v8 KEY= attribute covers init0 (k3@IV3).
    media.push_str(&format!(
        "#EXT-X-MAP:URI=\"einit0.mp4\",KEY=\"METHOD=AES-128,URI=keys/k3.bin,IV={}\"\n",
        hex_iv(&IV3)
    ));
    for i in 0..m0 {
        let bytes =
            std::fs::read(q0.join(format!("seg{i:03}.m4s"))).map_err(|e| format!("read: {e}"))?;
        std::fs::write(mm.join(format!("expected/seg0-{i:03}.m4s")), &bytes)
            .map_err(|e| format!("w: {e}"))?;
        std::fs::write(
            mm.join(format!("eseg0-{i:03}.m4s")),
            encrypt(&K1, &IV1, &bytes),
        )
        .map_err(|e| format!("w: {e}"))?;
        media.push_str(&format!("#EXTINF:1.0,\neseg0-{i:03}.m4s\n"));
    }
    media.push_str("#EXT-X-DISCONTINUITY\n");
    // Rotation to k2 BEFORE the second MAP: init1 is encrypted under
    // the ambient key (the v0.3.1 boundary), default-IV chain.
    media.push_str("#EXT-X-KEY:METHOD=AES-128,URI=\"keys/k2.bin\"\n");
    media.push_str("#EXT-X-MAP:URI=\"einit1.mp4\"\n");
    for i in 0..m1 {
        let bytes =
            std::fs::read(q1.join(format!("seg{i:03}.m4s"))).map_err(|e| format!("read: {e}"))?;
        std::fs::write(mm.join(format!("expected/seg1-{i:03}.m4s")), &bytes)
            .map_err(|e| format!("w: {e}"))?;
        let iv = seq_iv(SEQ_BASE2 + m0 as u64 + i as u64);
        std::fs::write(
            mm.join(format!("eseg1-{i:03}.m4s")),
            encrypt(&K2, &iv, &bytes),
        )
        .map_err(|e| format!("w: {e}"))?;
        media.push_str(&format!("#EXTINF:1.0,\neseg1-{i:03}.m4s\n"));
    }
    media.push_str("#EXT-X-ENDLIST\n");
    std::fs::write(mm.join("media.m3u8"), media).map_err(|e| format!("write: {e}"))?;

    // ---- 8. mkv-fallback (TS line + MKV product) --------------------
    let mkv = root.join("mkv-fallback");
    std::fs::create_dir_all(&mkv).map_err(|e| format!("mkdir: {e}"))?;
    {
        // mpegts segments (no init section → the native-unsupported
        // TS line, the fallback trigger).
        let mut args: Vec<String> = vec![
            "-y".into(),
            "-hide_banner".into(),
            "-loglevel".into(),
            "error".into(),
            "-f".into(),
            "lavfi".into(),
            "-i".into(),
            "testsrc2=size=426x240:rate=12:duration=5".to_string(),
            "-c:v".into(),
            "libx264".into(),
            "-preset".into(),
            "ultrafast".into(),
            "-x264-params".into(),
            "keyint=12:min-keyint=12:scenecut=0:threads=1".to_string(),
            "-pix_fmt".into(),
            "yuv420p".into(),
            "-an".into(),
        ];
        args.extend(DET_ARGS.iter().map(|s| s.to_string()));
        args.extend([
            "-f".to_string(),
            "hls".to_string(),
            "-hls_time".to_string(),
            "1".to_string(),
            "-hls_list_size".to_string(),
            "0".to_string(),
            "-hls_playlist_type".to_string(),
            "vod".to_string(),
            "-hls_segment_type".to_string(),
            "mpegts".to_string(),
            "-hls_flags".to_string(),
            "independent_segments".to_string(),
            "-hls_segment_filename".to_string(),
            "ts%03d.ts".to_string(),
            "ts.m3u8".to_string(),
        ]);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_ffmpeg(fx, &mkv, &refs, &mut argv_log)?;
    }
    {
        // The MKV product itself (the fallback-only container ruling).
        let args: Vec<String> = vec![
            "-y".into(),
            "-hide_banner".into(),
            "-loglevel".into(),
            "error".into(),
            "-f".into(),
            "lavfi".into(),
            "-i".into(),
            "testsrc2=size=320x240:rate=12:duration=4".to_string(),
            "-f".into(),
            "lavfi".into(),
            "-i".into(),
            "sine=frequency=440:sample_rate=44100:duration=4".to_string(),
            "-c:v".into(),
            "libx264".into(),
            "-preset".into(),
            "ultrafast".into(),
            "-x264-params".into(),
            "keyint=12:min-keyint=12:scenecut=0:threads=1".to_string(),
            "-pix_fmt".into(),
            "yuv420p".into(),
            "-c:a".into(),
            "aac".into(),
            "-ac".into(),
            "1".into(),
            "-threads".into(),
            "1".into(),
            "-fflags".into(),
            "+bitexact".into(),
            "-flags".into(),
            "+bitexact".into(),
            "-flags:v".into(),
            "+bitexact".into(),
            "-flags:a".into(),
            "+bitexact".into(),
            "-f".into(),
            "matroska".into(),
            "sample.mkv".to_string(),
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_ffmpeg(fx, &mkv, &refs, &mut argv_log)?;
    }

    // ---- 9. hundredk (pure text, no ffmpeg) -------------------------
    let hk = root.join("hundredk");
    std::fs::create_dir_all(&hk).map_err(|e| format!("mkdir: {e}"))?;
    write_hundredk_manifest(&hk);

    // ---- manifest + recipe ------------------------------------------
    let sums = sha256_tree(root);
    let mut out = String::new();
    for (rel, sha) in &sums {
        out.push_str(&format!("{sha}  {rel}\n"));
    }
    std::fs::write(root.join("SHA256SUMS"), out).map_err(|e| format!("write: {e}"))?;
    let recipe = serde_json::json!({
        "generator_rev": GENERATOR_REV,
        "ffmpeg_version": fx.version_line,
        "argv_log": argv_log,
        "crypto": {
            "k1_sha256": sha256_hex(&K1),
            "k2_sha256": sha256_hex(&K2),
            "k3_sha256": sha256_hex(&K3),
            "iv1": hex_iv(&IV1),
            "iv3": hex_iv(&IV3),
            "aes_rotation_seq_base": 50_000u64,
            "multimap_v8_seq_base": 77_000u64,
        },
    });
    std::fs::write(
        root.join("RECIPE.json"),
        serde_json::to_string_pretty(&recipe).unwrap_or_default(),
    )
    .map_err(|e| format!("write: {e}"))?;
    Ok(sums)
}

/// Record that the MAP line carried a BYTERANGE for the blob URI
/// (the cursor-seat bookkeeping of the omitted-offset derivation).
fn seen_uri_marks_map(set: &mut std::collections::HashSet<String>, rest: &str) {
    if rest.contains("URI=\"blob.mp4\"") {
        set.insert("blob.mp4".to_string());
    }
}

/// Every file under `root` (excluding SHA256SUMS/RECIPE.json
/// themselves), sorted by relative path, with its sha256.
pub fn sha256_tree(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    files.sort();
    files
        .into_iter()
        .map(|rel| {
            let bytes = std::fs::read(root.join(&rel)).unwrap_or_default();
            let sha = sha256_hex(&bytes);
            (rel, sha)
        })
        .collect()
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else {
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let rel = rel.to_string_lossy().replace('\\', "/");
            if rel == "SHA256SUMS" || rel == "RECIPE.json" {
                continue;
            }
            out.push(rel);
        }
    }
}

/// Assert two generated trees are bit-identical (the rebuild cross-check):
/// same relative file set and same sha256 per file.
pub fn assert_bit_identical(a: &Path, b: &Path) {
    let sa = sha256_tree(a);
    let sb = sha256_tree(b);
    assert_eq!(
        sa.len(),
        sb.len(),
        "rebuild product count differs: {} vs {}",
        sa.len(),
        sb.len()
    );
    for ((ra, ha), (rb, hb)) in sa.iter().zip(sb.iter()) {
        assert_eq!(ra, rb, "rebuild file order/name differs at {ra}");
        assert_eq!(ha, hb, "rebuild digest differs for {ra}: {ha} vs {hb}");
    }
}

/// The 100 000-segment BYTERANGE manifest (the parse-gate carrier;
/// the ≤100k in-cap boundary form of the parser's limit) — pure text, no
/// ffmpeg, deterministic. Returns the manifest bytes.
pub fn write_hundredk_manifest(dir: &Path) -> Vec<u8> {
    let mut text = String::with_capacity(7_000_000);
    text.push_str("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:2\n");
    text.push_str("#EXT-X-MEDIA-SEQUENCE:77000\n#EXT-X-PLAYLIST-TYPE:VOD\n");
    text.push_str("#EXT-X-MAP:URI=\"init.mp4\"\n");
    for i in 0..100_000u64 {
        text.push_str("#EXTINF:1.0,\n");
        text.push_str(&format!("#EXT-X-BYTERANGE:1024@{}\n", 4096 + i * 1024));
        text.push_str("blob.bin\n");
    }
    text.push_str("#EXT-X-ENDLIST\n");
    let bytes = text.into_bytes();
    let _ = std::fs::write(dir.join("media.m3u8"), &bytes);
    bytes
}
