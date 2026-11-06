//! The synthesis qualification-gate matrix (kickoff gate; the media
//! spec's synthesis line and the carrier decision as
//! amended 2026-10-28 — the carrier is the **self-built minimal
//! ISO-BMFF write side**). Each row:
//! constructed source -> native write -> read-back assertion (the probe) + ffprobe dual-run
//! when a local pair exists (runtime guard, the e2e_real
//! pattern).
//!
//! Matrix of record (also rendered in docs/design/media-synthesis.md
//! and the completion report):
//!
//! | item | verdict | carrier note |
//! |---|---|---|
//! | tx3g subtitle embed | PASS | tx3g_track_spec + verbatim stsd; VTT markup stripped |
//! | covr cover art | PASS | udta.meta.ilst.covr.data, jpeg/png type codes |
//! | chpl chapter | PASS | Nero-style, 100 ns units (convention documented) |
//! | faststart | PASS | ftyp/moov/mdat by construction, offsets two-pass |
//! | multi-track merge | PASS | N traks, one mdat, per-track chunk |
//! | multi-Period concat | PASS | same-stsd sample-stream concat into one trak |
//! | MKV | degraded -> ffmpeg fallback | fallback-channel ruling; verdict
//! function + fallback argv |

mod common;

use common::*;
use taiji_media::bmff::{self, HANDLER_SUBTITLE, HANDLER_VIDEO};
use taiji_media::mp4write::{
    self, Chapter, MovieMeta, TrackSpec, track_spec_from_fold, tx3g_track_spec, write_progressive,
};
use taiji_media::probe::{self, ExpectedMeta, ExpectedTrack};
use taiji_media::synth::{self, MuxerPreference, OutputFormat, SynthesisConfig, TrackInput};

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("taiji-matrix-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    dir
}

/// A folded fixture track → TrackSpec.
fn spec_from_fixture(spec: &InitSpec, segments: usize, samples: usize) -> TrackSpec {
    let (init, archive, spans) = build_track_spans(spec, segments, samples);
    let fold = bmff::fold_track(&init, &archive, &spans).unwrap_or_else(|e| panic!("fold: {e}"));
    track_spec_from_fold(&fold, &archive).unwrap_or_else(|e| panic!("spec: {e}"))
}

/// The lenient local ffmpeg guard for the matrix's dual-run halves:
/// discovery + `-version` parse only. The LGPL gate is a
/// production posture — the dev machine's Homebrew ffmpeg carries
/// `--enable-gpl` (the recorded e2e_real fixture fact) and would
/// refuse under `gate` strictness, skipping the cross-tool check on
/// exactly the machines that have ffmpeg. The gate itself stays
/// exercised through `ffmpegmux::discover_asserted` (the production
/// face).
async fn guard() -> Option<taiji_media::ffmpegmux::FfmpegRuntime> {
    let pair = taiji_media::discover(&taiji_media::discover::DiscoveryRequest::default()).ok()?;
    let cmd = taiji_media::MediaCommand::new(taiji_media::MediaBin::Ffmpeg, &pair.ffmpeg)
        .unwrap_or_else(|e| panic!("{e}"))
        .args(taiji_media::VersionInfo::version_args().iter().copied())
        .shim_program(Some(std::path::PathBuf::from(env!(
            "CARGO_BIN_EXE_taiji-media-shim"
        ))));
    let child = cmd.spawn().ok()?;
    let out = child.wait().await.ok()?;
    if !out.success {
        eprintln!("skipping ffprobe dual-run (local ffmpeg -version failed)");
        return None;
    }
    let version = taiji_media::VersionInfo::parse(&String::from_utf8_lossy(&out.stdout)).ok()?;
    Some(taiji_media::ffmpegmux::FfmpegRuntime {
        pair,
        version,
        shim_program: Some(std::path::PathBuf::from(env!(
            "CARGO_BIN_EXE_taiji-media-shim"
        ))),
    })
}

/// ffprobe a file and return its stream summary + duration (when the
/// pair exists).
fn ffprobe_json(
    rt: &taiji_media::ffmpegmux::FfmpegRuntime,
    path: &std::path::Path,
) -> taiji_media::FfprobeReport {
    tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("{e}"))
        .block_on(async {
            let args: Vec<String> = taiji_media::probe_args(path)
                .into_iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let cmd =
                taiji_media::MediaCommand::new(taiji_media::MediaBin::Ffprobe, &rt.pair.ffprobe)
                    .unwrap_or_else(|e| panic!("{e}"))
                    .args(refs)
                    .shim_program(rt.shim_program.clone());
            let child = cmd.spawn().unwrap_or_else(|e| panic!("{e}"));
            let out = child.wait().await.unwrap_or_else(|e| panic!("{e}"));
            if !out.success {
                panic!(
                    "ffprobe exit {:?}: {}",
                    out.code,
                    String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(2048)])
                );
            }
            taiji_media::FfprobeReport::parse(&out.stdout).unwrap_or_else(|e| panic!("{e}"))
        })
}

// ---------------------------------------------------------------------------
// 1. tx3g subtitle embed
// ---------------------------------------------------------------------------

#[test]
fn matrix_tx3g_embed() {
    // VTT cues → tx3g track → movie with a video trak → probe asserts
    // the subtitle stsd type + sample timeline; ffprobe dual-run
    // counts a subtitle stream.
    let video = spec_from_fixture(&video_init_spec(), 2, 3);
    let video_expect = ExpectedTrack {
        handler: HANDLER_VIDEO,
        timescale: video.timescale,
        stsd_entry: video.stsd_entry.clone(),
        sample_count: video.samples.len(),
    };
    let cues = vec![
        (0u64, 1500u64, "hello world".to_string()),
        (2000, 3600, "second <c.b>cue</c>\nline".to_string()),
    ];
    let sub = tx3g_track_spec(&cues);
    assert_eq!(sub.stsd_entry[4..8], *b"tx3g");
    let sub_expect = ExpectedTrack {
        handler: HANDLER_SUBTITLE,
        timescale: sub.timescale,
        stsd_entry: mp4write::tx3g_stsd_entry(),
        sample_count: sub.samples.len(),
    };
    let mut out = Vec::new();
    write_progressive(&[video, sub], &MovieMeta::default(), &mut out);
    let report = probe::probe_product(
        &out,
        &[video_expect, sub_expect],
        3600,
        &ExpectedMeta::default(),
    );
    assert!(report.ok(), "violations: {:?}", report.violations);

    if let Some(rt) = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("{e}"))
        .block_on(guard())
    {
        let dir = scratch("tx3g");
        let path = dir.join("tx3g.mp4");
        std::fs::write(&path, &out).unwrap_or_else(|e| panic!("{e}"));
        let json = ffprobe_json(&rt, &path);
        assert_eq!(json.count_codec_type("video"), 1);
        assert_eq!(
            json.count_codec_type("subtitle"),
            1,
            "tx3g stream present: {}",
            json.stream_summary().join(", ")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// 2. covr cover art
// ---------------------------------------------------------------------------

#[test]
fn matrix_covr_cover() {
    let track = spec_from_fixture(&video_init_spec(), 1, 2);
    let cover = vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4, 5, 6, 7, 8];
    let meta = MovieMeta {
        title: None,
        covr: Some((cover.clone(), false)),
        chapters: Vec::new(),
    };
    let mut out = Vec::new();
    write_progressive(&[track], &meta, &mut out);
    let (init, _) = build_track(&video_init_spec(), 1, 2);
    let desc = bmff::parse_init(&init).unwrap_or_else(|e| panic!("{e}"));
    let expect = vec![ExpectedTrack {
        handler: HANDLER_VIDEO,
        timescale: 1000,
        stsd_entry: desc.stsd_entries[0].bytes.clone(),
        sample_count: 2,
    }];
    let meta_expect = ExpectedMeta {
        title: None,
        covr: Some((cover, false)),
        chapters: Vec::new(),
    };
    let report = probe::probe_product(&out, &expect, 66, &meta_expect);
    assert!(report.ok(), "violations: {:?}", report.violations);
}

// ---------------------------------------------------------------------------
// 3. chpl chapters
// ---------------------------------------------------------------------------

#[test]
fn matrix_chpl_chapters() {
    let track = spec_from_fixture(&audio_init_spec(), 1, 4);
    let meta = MovieMeta {
        title: None,
        covr: None,
        chapters: vec![
            Chapter {
                start: 0,
                title: "Intro".to_string(),
            },
            Chapter {
                start: 2000,
                title: "Kapitel Zwei".to_string(),
            },
        ],
    };
    let mut out = Vec::new();
    write_progressive(&[track], &meta, &mut out);
    let (init, _) = build_track(&audio_init_spec(), 1, 4);
    let desc = bmff::parse_init(&init).unwrap_or_else(|e| panic!("{e}"));
    let expect = vec![ExpectedTrack {
        handler: *b"soun",
        timescale: 44_100,
        stsd_entry: desc.stsd_entries[0].bytes.clone(),
        sample_count: 4,
    }];
    let meta_expect = ExpectedMeta {
        title: None,
        covr: None,
        chapters: vec![(0, "Intro".to_string()), (2000, "Kapitel Zwei".to_string())],
    };
    // 4096 media units @ 44100 ≈ 93 ms (the movie duration basis).
    let report = probe::probe_product(&out, &expect, 93, &meta_expect);
    assert!(report.ok(), "violations: {:?}", report.violations);
}

// ---------------------------------------------------------------------------
// 4. faststart
// ---------------------------------------------------------------------------

#[test]
fn matrix_faststart() {
    // moov strictly before mdat, on a merge-scale file (multi-track).
    let v = spec_from_fixture(&video_init_spec(), 3, 4);
    let a = spec_from_fixture(&audio_init_spec(), 3, 8);
    let mut out = Vec::new();
    write_progressive(&[v, a], &MovieMeta::default(), &mut out);
    let boxes = bmff::iter_boxes(&out).unwrap_or_else(|e| panic!("{e}"));
    let types: Vec<_> = boxes.iter().map(|b| b.typ).collect();
    assert_eq!(types, vec![*b"ftyp", *b"moov", *b"mdat"]);
    assert!(boxes[1].start < boxes[2].start, "moov before mdat");
    // The chunk offsets point past the moov (real faststart offsets,
    // not placeholders).
    let moov_children = bmff::iter_boxes(boxes[1].payload).unwrap_or_else(|e| panic!("{e}"));
    let mdat_start = boxes[2].start + 8;
    for trak in moov_children.iter().filter(|b| b.typ == *b"trak") {
        let mdia = bmff::boxes_of(trak.payload, b"mdia")
            .unwrap_or_else(|e| panic!("{e}"))
            .remove(0);
        let minf = bmff::boxes_of(mdia.payload, b"minf")
            .unwrap_or_else(|e| panic!("{e}"))
            .remove(0);
        let stbl = bmff::boxes_of(minf.payload, b"stbl")
            .unwrap_or_else(|e| panic!("{e}"))
            .remove(0);
        let stco = bmff::boxes_of(stbl.payload, b"stco")
            .unwrap_or_else(|e| panic!("{e}"))
            .remove(0);
        let off = u32::from_be_bytes([
            stco.payload[8],
            stco.payload[9],
            stco.payload[10],
            stco.payload[11],
        ]);
        assert!(
            off as u64 >= mdat_start,
            "chunk offset {off} ≥ mdat payload {mdat_start}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. multi-track merge (video + independent audio archives → single MP4)
// ---------------------------------------------------------------------------

#[test]
fn matrix_multi_track_merge() {
    let v = spec_from_fixture(&video_init_spec(), 2, 3);
    let a = spec_from_fixture(&audio_init_spec(), 2, 8);
    let expects = vec![
        ExpectedTrack {
            handler: HANDLER_VIDEO,
            timescale: 1000,
            stsd_entry: v.stsd_entry.clone(),
            sample_count: v.samples.len(),
        },
        ExpectedTrack {
            handler: *b"soun",
            timescale: 44_100,
            stsd_entry: a.stsd_entry.clone(),
            sample_count: a.samples.len(),
        },
    ];
    let mut out = Vec::new();
    write_progressive(&[v, a], &MovieMeta::default(), &mut out);
    // Movie duration = max over traks: video 2×3×33 = 198 ms, audio
    // 2×8×1024@44100 ≈ 372 ms → 372.
    let report = probe::probe_product(&out, &expects, 372, &ExpectedMeta::default());
    assert!(report.ok(), "violations: {:?}", report.violations);

    if let Some(rt) = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("{e}"))
        .block_on(guard())
    {
        let dir = scratch("merge");
        let path = dir.join("merge.mp4");
        std::fs::write(&path, &out).unwrap_or_else(|e| panic!("{e}"));
        let json = ffprobe_json(&rt, &path);
        assert_eq!(json.count_codec_type("video"), 1);
        assert_eq!(json.count_codec_type("audio"), 1);
        let duration = json.duration_seconds().unwrap_or(0.0);
        // Movie duration = max over traks (audio ≈ 372 ms governs).
        assert!(
            (0.372 * 0.98..=0.372 * 1.02).contains(&duration),
            "ffprobe duration {duration} ≈ 0.372 s"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// 6. multi-Period concat (same-codec sample streams → one trak)
// ---------------------------------------------------------------------------

#[test]
fn matrix_multi_period_concat() {
    // Two "periods": separate init+archive sets with identical stsd
    // (the same-shape precondition; the verdict refuses shape
    // changes). The concat composes one TrackSpec from both folds —
    // the write-side capability the matrix measures.
    let (init1, arch1, spans1) = build_track_spans(&video_init_spec(), 2, 3);
    let (init2, arch2, spans2) = build_track_spans(&video_init_spec(), 2, 3);
    let fold1 = bmff::fold_track(&init1, &arch1, &spans1).unwrap_or_else(|e| panic!("{e}"));
    let fold2 = bmff::fold_track(&init2, &arch2, &spans2).unwrap_or_else(|e| panic!("{e}"));
    let s1 = track_spec_from_fold(&fold1, &arch1).unwrap_or_else(|e| panic!("{e}"));
    let s2 = track_spec_from_fold(&fold2, &arch2).unwrap_or_else(|e| panic!("{e}"));
    let mut concatenated = TrackSpec {
        handler: s1.handler,
        timescale: s1.timescale,
        stsd_entry: s1.stsd_entry.clone(),
        media_header: s1.media_header.clone(),
        dinf: s1.dinf.clone(),
        tkhd_width_height: s1.tkhd_width_height,
        tkhd_volume: s1.tkhd_volume,
        samples: s1.samples.clone(),
        sample_sizes: s1.sample_sizes.clone(),
        media_data: s1.media_data.clone(),
    };
    concatenated.samples.extend(s2.samples.iter().copied());
    concatenated
        .sample_sizes
        .extend(s2.sample_sizes.iter().copied());
    concatenated
        .media_data
        .extend(s2.media_data.iter().copied());
    let total = concatenated.samples.len();
    let mut out = Vec::new();
    write_progressive(&[concatenated], &MovieMeta::default(), &mut out);
    let report = probe::probe_product(
        &out,
        &[ExpectedTrack {
            handler: HANDLER_VIDEO,
            timescale: 1000,
            stsd_entry: s1.stsd_entry.clone(),
            sample_count: total,
        }],
        396, // 4×3×33 ms
        &ExpectedMeta::default(),
    );
    assert!(report.ok(), "violations: {:?}", report.violations);
}

// ---------------------------------------------------------------------------
// 7. MKV → degraded ffmpeg fallback (verdict + argv form)
// ---------------------------------------------------------------------------

#[test]
fn matrix_mkv_degrades_to_fallback() {
    // The native writer has no MKV face by construction: the verdict
    // function routes MKV output to the fallback, the
    // fallback argv carries `-f matroska` without faststart.
    let dir = scratch("mkv");
    let (init, archive) = build_track(&video_init_spec(), 1, 2);
    let init_path = dir.join("init-v-0.mp4");
    std::fs::write(&init_path, &init).unwrap_or_else(|e| panic!("{e}"));
    let arch_path = dir.join("archive-v.m4s");
    std::fs::write(&arch_path, &archive).unwrap_or_else(|e| panic!("{e}"));
    let playlist: taiji_media::m3u8::MediaPlaylist =
        match taiji_media::parse_manifest(
            format!(
                "#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:0.1,\n#EXT-X-BYTERANGE:{}@0\nx.m4s\n#EXT-X-ENDLIST\n",
                archive.len()
            )
            .as_bytes(),
        )
        .unwrap_or_else(|e| panic!("{e}"))
        {
            taiji_media::Playlist::Media(m) => m,
            other => panic!("{other:?}"),
        };
    let input = TrackInput {
        label: "v".to_string(),
        kind: "video".to_string(),
        archive: arch_path,
        inits: vec![init_path],
        segments: taiji_media::segment_records(&playlist)
            .into_iter()
            .map(|mut s| {
                s.seg_len = archive.len() as u64;
                s
            })
            .collect(),
        playlist,
        archive_name: "archive-v.m4s".to_string(),
    };
    let cfg = SynthesisConfig {
        phase_sink: None,
        format: OutputFormat::Mkv,
        muxer: MuxerPreference::Auto,
        output: dir.join("out.mkv"),
        staging_dir: dir.clone(),
        ffmpeg: None,
        embed_subtitles: false,
        meta: taiji_media::mp4write::MovieMeta::default(),
        free_bytes_override: Some(None),
    };
    // Verdict: MKV is fallback territory; with no pair the start
    // precheck refuses (ffmpeg_missing before synthesis work).
    match synth::native_support(std::slice::from_ref(&input), &cfg) {
        synth::NativeSupport::Unsupported { reason } => {
            assert!(reason.contains("MKV"), "{reason}")
        }
        other => panic!("expected unsupported, got {other:?}"),
    }
    let tok = tokio_util::sync::CancellationToken::new();
    let err = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("{e}"))
        .block_on(synth::run_synthesis(&[input], &cfg, tok))
        .err()
        .unwrap_or_else(|| panic!("mkv without ffmpeg must refuse"));
    assert_eq!(err.code(), "taiji.media.ffmpeg_missing");
    // The fallback argv face for MKV: -f matroska, no faststart
    // (covered in ffmpegmux unit tests; asserted here via the pure
    // builder for the matrix row).
    let args = taiji_media::fallback_args(
        &dir.join("local-v.m3u8"),
        None,
        taiji_media::FallbackFormat::Mkv,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let joined: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(joined.contains(&"matroska".to_string()));
    assert!(!joined.contains(&"+faststart".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 8. fold regression (a review pass): explicit tfhd
// base-data-offset is segment-FILE-absolute (ISO/IEC 14496-12
// §8.8.7) — in a concatenated download archive it must re-base by the
// enclosing segment file's start. Pre-fix, segment B's samples
// folded into segment A's mdat carrying A's bytes with `Ok`
// (silent corruption; reproduced in a scratch-dir probe).
// ---------------------------------------------------------------------------

fn fold_fixture_samples(count: usize) -> Vec<FixtureSample> {
    (0..count)
        .map(|i| FixtureSample {
            duration: 50,
            size: 32,
            sync: i == 0,
            cts: 0,
        })
        .collect()
}

/// The reviewer's exact shape, byte-level: two explicit-base segments
/// concatenate; segment B's samples must fold inside segment B and
/// carry **B's** payload bytes (the pre-fix fold returned A's bytes).
#[test]
fn fold_explicit_base_two_segment_archive_bytes() {
    let (init, _) = build_track(&video_init_spec(), 0, 0);
    let pa: Vec<u8> = (0..64u8).cycle().take(128).collect();
    let pb: Vec<u8> = (200u8..=251u8).cycle().take(128).collect();
    let sega = build_segment_base(
        1,
        0,
        0,
        &fold_fixture_samples(2),
        &pa,
        TfhdBase::ExplicitBase { styp: false },
    );
    let segb = build_segment_base(
        1,
        1,
        100,
        &fold_fixture_samples(2),
        &pb,
        TfhdBase::ExplicitBase { styp: false },
    );
    let segb_start = sega.len() as u64;
    let spans = vec![
        bmff::SegmentSpan {
            archive_offset: 0,
            archive_len: segb_start,
        },
        bmff::SegmentSpan {
            archive_offset: segb_start,
            archive_len: segb.len() as u64,
        },
    ];
    let mut archive = sega.clone();
    archive.extend_from_slice(&segb);
    let fold = bmff::fold_track(&init, &archive, &spans).unwrap_or_else(|e| panic!("fold: {e}"));
    assert_eq!(fold.samples.len(), 4, "both segments fold");
    for (i, s) in fold.samples.iter().enumerate() {
        let floor = if i < 2 { 0 } else { segb_start };
        assert!(
            s.offset >= floor,
            "sample {i} at {} must sit inside its own segment (floor {floor})",
            s.offset
        );
    }
    // Byte-level: the folded spans carry each segment's OWN payload
    // (sample j of a segment = payload[j*32..j*32+32]).
    for (i, s) in fold.samples.iter().enumerate() {
        let expect: &[u8] = if i < 2 { &pa } else { &pb };
        let local = (i % 2) * 32;
        let got = &archive[s.offset as usize..(s.offset + u64::from(s.len)) as usize];
        assert_eq!(
            got,
            &expect[local..local + s.len as usize],
            "sample {i} bytes must come from its own segment's payload"
        );
    }
    // Explicitly: segment B's first folded bytes are B's opening
    // bytes (0xc8…), never A's (0x00…).
    let b0 = &fold.samples[2];
    let bytes = &archive[b0.offset as usize..b0.offset as usize + 8];
    assert_eq!(bytes, &pb[..8], "B's samples carry B's bytes");
}

/// A `styp` preamble opens the segment FILE before its moof: the
/// explicit base is measured from the styp, and the file-boundary
/// bookkeeping must treat the styp as part of the new segment (not
/// trailer bytes of the previous one).
#[test]
fn fold_explicit_base_styp_preamble() {
    let (init, _) = build_track(&video_init_spec(), 0, 0);
    let pa: Vec<u8> = (10..74u8).cycle().take(128).collect();
    let pb: Vec<u8> = (120..184u8).cycle().take(128).collect();
    let sega = build_segment_base(
        1,
        0,
        0,
        &fold_fixture_samples(2),
        &pa,
        TfhdBase::ExplicitBase { styp: false },
    );
    let segb = build_segment_base(
        1,
        1,
        100,
        &fold_fixture_samples(2),
        &pb,
        TfhdBase::ExplicitBase { styp: true },
    );
    let segb_start = sega.len() as u64;
    let spans = vec![
        bmff::SegmentSpan {
            archive_offset: 0,
            archive_len: segb_start,
        },
        bmff::SegmentSpan {
            archive_offset: segb_start,
            archive_len: segb.len() as u64,
        },
    ];
    let mut archive = sega;
    archive.extend_from_slice(&segb);
    let fold = bmff::fold_track(&init, &archive, &spans).unwrap_or_else(|e| panic!("fold: {e}"));
    assert_eq!(fold.samples.len(), 4);
    for s in &fold.samples[2..] {
        assert!(
            s.offset >= segb_start,
            "styp-prefixed segment B samples fold inside B ({} >= {segb_start})",
            s.offset
        );
    }
    let b0 = fold.samples[2];
    let bytes = &archive[b0.offset as usize..b0.offset as usize + 8];
    assert_eq!(bytes, &pb[..8], "B's samples carry B's bytes (styp form)");
}

/// The misresolution shape must fail LOUDLY, never fold silently
/// wrong bytes: a traf whose samples resolve into an **earlier**
/// segment's mdat is refused (own-segment-file containment) — the
/// defense that makes any future base-interpretation drift visible.
#[test]
fn fold_refuses_cross_segment_mdat_landing() {
    let (init, _) = build_track(&video_init_spec(), 0, 0);
    let pa: Vec<u8> = (0..64u8).cycle().take(128).collect();
    let pb: Vec<u8> = (200u8..=251u8).cycle().take(128).collect();
    let sega = build_segment_base(
        1,
        0,
        0,
        &fold_fixture_samples(2),
        &pa,
        TfhdBase::ExplicitBase { styp: false },
    );
    let mut segb = build_segment_base(
        1,
        1,
        100,
        &fold_fixture_samples(2),
        &pb,
        TfhdBase::ExplicitBase { styp: false },
    );
    // Sabotage segment B's trun data_offset to walk backwards into
    // segment A's mdat (base resolves inside B; data_offset negative
    // pulls the samples into A). Locate the word through the box walk
    // so the patch is structural, not a magic constant.
    let segb_boxes = bmff::iter_boxes(&segb).unwrap_or_else(|e| panic!("{e}"));
    let moof = &segb_boxes[0];
    assert_eq!(moof.typ, *b"moof");
    let moof_children = bmff::iter_boxes(moof.payload).unwrap_or_else(|e| panic!("{e}"));
    let traf = &moof_children[1];
    assert_eq!(traf.typ, *b"traf");
    let traf_children = bmff::iter_boxes(traf.payload).unwrap_or_else(|e| panic!("{e}"));
    let trun = &traf_children[2];
    assert_eq!(trun.typ, *b"trun");
    // data_offset word: moof hdr (8) + traf offset + traf hdr (8) +
    // trun offset + trun hdr (8) + verflags (4) + count (4).
    let data_offset_at = (8 + traf.start + 8 + trun.start + 8 + 4 + 4) as usize;
    assert_eq!(
        &segb[data_offset_at..data_offset_at + 4],
        &0i32.to_be_bytes(),
        "the builder writes data_offset 0 here (patch anchor)"
    );
    let back: i32 = -(sega.len() as i32); // walk to the same file-relative spot in A
    segb[data_offset_at..data_offset_at + 4].copy_from_slice(&back.to_be_bytes());
    let spans = vec![
        bmff::SegmentSpan {
            archive_offset: 0,
            archive_len: sega.len() as u64,
        },
        bmff::SegmentSpan {
            archive_offset: sega.len() as u64,
            archive_len: segb.len() as u64,
        },
    ];
    let mut archive = sega;
    archive.extend_from_slice(&segb);
    let err = bmff::fold_track(&init, &archive, &spans)
        .err()
        .unwrap_or_else(|| panic!("cross-segment mdat landing must refuse"));
    let text = err.to_string();
    assert!(
        text.contains("own segment span"),
        "the refusal names the own-file containment: {text}"
    );
}

// ---------------------------------------------------------------------------
// 9. fold regression (final review, round 3): ONE legal
// multi-fragment segment FILE (moof1/mdat1/moof2/mdat2 — a movie
// fragment sequence), every tfhd carrying an explicit
// file-absolute base at its own mdat's payload. The fold takes the
// EXACT segment span from the caller (the rewrite entries' ledger
// data) — no boundary heuristics. The pre-fix heuristic inferred
// moof2's file start as "first box after the previous mdat"
// (= moof2.start), shifting moof2's samples by moof2.start bytes
// into mdat2's payload slack → Ok with silently wrong bytes
// (reproduced in a scratch-dir probe: 440/568/696/824 vs the
// correct 288/416/544/672).
// ---------------------------------------------------------------------------

#[test]
fn fold_multi_fragment_file_explicit_base_exact_offsets() {
    let (init, _archive, _spans) = build_track_spans(&video_init_spec(), 0, 0);
    // mdat1 payload: 32 bytes tiled by 2×16 samples; mdat2 payload:
    // 1024 bytes (4×128 sample bytes + slack — the slack is what let
    // the pre-fix shift stay inside the payload, the silent shape).
    let pa: Vec<u8> = (0..64u8).cycle().take(32).collect();
    let pb: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let f1 = (
        0u32,
        0u64,
        vec![
            FixtureSample {
                duration: 50,
                size: 16,
                sync: true,
                cts: 0,
            },
            FixtureSample {
                duration: 50,
                size: 16,
                sync: false,
                cts: 0,
            },
        ],
        pa.clone(),
    );
    let f2 = (
        1u32,
        100u64,
        (0..4)
            .map(|i| FixtureSample {
                duration: 50,
                size: 128,
                sync: i == 0,
                cts: 0,
            })
            .collect(),
        pb.clone(),
    );
    let archive = build_multi_fragment_file(1, &[f1, f2]);
    // The whole archive IS one segment file → one exact span.
    let spans = vec![bmff::SegmentSpan {
        archive_offset: 0,
        archive_len: archive.len() as u64,
    }];
    let fold = bmff::fold_track(&init, &archive, &spans).unwrap_or_else(|e| panic!("fold: {e}"));
    assert_eq!(fold.samples.len(), 6, "both fragments fold");

    // Exact expected offsets: each fragment's samples tile its OWN
    // mdat payload from that payload's start (derived from the
    // archive's box walk, not magic constants).
    let boxes = bmff::iter_boxes(&archive).unwrap_or_else(|e| panic!("{e}"));
    let mdat_payload_starts: Vec<u64> = boxes
        .iter()
        .filter(|b| b.typ == *b"mdat")
        .map(|b| b.end - b.payload.len() as u64)
        .collect();
    assert_eq!(mdat_payload_starts.len(), 2);
    let expect: Vec<u64> = [
        (mdat_payload_starts[0], vec![0u64, 16]),
        (mdat_payload_starts[1], vec![0u64, 128, 256, 384]),
    ]
    .iter()
    .flat_map(|(base, offs)| offs.iter().map(move |o| base + o))
    .collect();
    let got: Vec<u64> = fold.samples.iter().map(|s| s.offset).collect();
    assert_eq!(
        got, expect,
        "sample offsets exact (the reviewer's 288/416/544/672 shape)"
    );

    // Byte-level: each sample carries its OWN payload's tiling — the
    // pre-fix residual shifted moof2's bytes by moof2.start.
    for (i, s) in fold.samples.iter().enumerate() {
        let (payload, local): (&Vec<u8>, usize) = if i < 2 {
            (&pa, (i % 2) * 16)
        } else {
            (&pb, (i - 2) * 128)
        };
        let bytes = &archive[s.offset as usize..(s.offset + u64::from(s.len)) as usize];
        assert_eq!(
            bytes,
            &payload[local..local + s.len as usize],
            "sample {i} bytes exact — never the moof2.start-shifted read"
        );
    }
    // The shift shape explicitly absent: moof2's first bytes are pb's
    // opening ramp, not pb[moof2_start..].
    let moof2_start = boxes
        .iter()
        .filter(|b| b.typ == *b"moof")
        .map(|b| b.start)
        .nth(1)
        .unwrap_or_else(|| panic!("second moof present"));
    let s2 = &fold.samples[2];
    let first8 = &archive[s2.offset as usize..s2.offset as usize + 8];
    assert_eq!(
        first8,
        &pb[..8],
        "moof2 sample 0 reads mdat2's opening bytes"
    );
    assert_ne!(
        first8,
        &pb[moof2_start as usize..moof2_start as usize + 8],
        "the bytes_shifted_by_moof2_start shape must be gone"
    );
}
