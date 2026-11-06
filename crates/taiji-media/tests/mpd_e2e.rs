//! Mock DASH e2e — the (a)/(b) layer rows through the real
//! pipeline to a synthesized product (the media spec's download and
//! synthesis lines):
//!
//! * **(b) row** — a multi-Period SegmentTemplate MPD ($Number$
//! addressing, no byte information): ordered segment fetches, the
//! `seg_bitmap` checkpoint face, one archive appending across the
//! period boundary with per-period init sections, then native
//! synthesis over the multi-period track + the resume invariant
//! (a second driver run over the same ledger re-fetches nothing);
//! * **(a) row** — a SegmentList + `@mediaRange` MPD over a single
//! blob resource: the extent-grid reuse (byte ranges → known
//! length), and the product through the same synthesis;
//! * the ffprobe dual-run rides the synthesis when a local pair is
//! present (the runtime-guard posture — the e2e_real suite's
//! recorded dev-machine fact, license-gate lenient).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures::future::BoxFuture;
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::MediaError;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::mpd;
use taiji_media::synth::{self, MuxerPreference, OutputFormat, SynthesisConfig, TrackInput};
use taiji_media::testkit::{
    FixtureSample, avcc_sample, build_init, build_segment, video_init_spec,
};
use taiji_media::trackdl::{
    MediaLedger, MediaTaskRecord, SegmentRecord, TrackLayer, TrackRecord, classify_track,
};
use taiji_media::trackset::{TrackSetVerdict, TrackState};

// ---------------------------------------------------------------------------
// mock origin
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Hits {
    /// Range headers seen on the blob resource (order-preserving).
    ranges: Arc<std::sync::Mutex<Vec<String>>>,
    /// Plain (non-range) GETs per path.
    gets: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Hits {
    fn ranges(&self) -> Vec<String> {
        self.ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn gets(&self) -> Vec<String> {
        self.gets.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

fn mpd_body(text: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/dash+xml")],
        text,
    )
        .into_response()
}

async fn spawn_with(build: impl FnOnce(SocketAddr) -> Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let app = build(addr);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// sqlite ledger (the synthesis e2e's StoreLedger, trimmed to this suite)
// ---------------------------------------------------------------------------

struct StoreLedger {
    handle: taiji_store::persist::writer::PersistHandle,
}

macro_rules! map_store {
    ($e:expr) => {
        $e.await
            .map(|_| ())
            .map_err(|e| MediaError::Staging(format!("ledger: {e}")))
    };
}
macro_rules! map_store_val {
    ($e:expr) => {
        $e.await
            .map_err(|e| MediaError::Staging(format!("ledger: {e}")))
    };
}

impl MediaLedger for StoreLedger {
    fn ensure_task<'a>(
        &'a self,
        row: &'a MediaTaskRecord,
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            use taiji_store::persist::MediaTaskRow;
            map_store!(self.handle.upsert_media_task(MediaTaskRow {
                gid: row.gid.clone(),
                kind: row.kind.clone(),
                manifest_url: row.manifest_url.clone(),
                state: row.state.clone(),
                phase_detail_json: None,
                variant_json: None,
                selector_json: None,
                output_name: None,
                bridge_json: None,
                staging_dir: row.staging_dir.clone(),
                output_path: row.output_path.clone(),
                manifest_norm_digest: row.manifest_norm_digest.clone(),
                total_done: 0,
                config_json: row.config_json.clone(),
                error_code: None,
                error_msg: None,
                created_at: 0,
                updated_at: 0,
            }))
        })
    }

    fn save_track<'a>(
        &'a self,
        gid: &'a str,
        track: &'a TrackRecord,
        segments: &'a [SegmentRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            use taiji_store::persist::{MediaSegmentRow, MediaTrackRow};
            let store_track = MediaTrackRow {
                gid: gid.to_string(),
                track_idx: track.track_idx as i64,
                kind: track.kind.clone(),
                playlist_uri: track.playlist_uri.clone(),
                local_name: track.local_name.clone(),
                init_files_json: Some(
                    serde_json::to_string(&track.init_files).unwrap_or_else(|_| "[]".into()),
                ),
                seg_bitmap: Some(track.seg_bitmap.clone()),
                seg_count: Some(track.seg_count as i64),
            };
            let store_segments: Vec<MediaSegmentRow> = segments
                .iter()
                .map(|s| MediaSegmentRow {
                    gid: gid.to_string(),
                    track_idx: track.track_idx as i64,
                    seg_idx: s.seg_idx as i64,
                    media_sequence: Some(s.media_sequence as i64),
                    uri: s.uri.clone(),
                    byte_range: s.byte_range.clone(),
                    key_id: s.key_id,
                    seg_len: s.seg_len as i64,
                    duration_ms: Some(s.duration_ms as i64),
                    validator_digest: Some(s.validator_digest.clone()),
                    map_idx: s.map.map(|m| m as i64),
                })
                .collect();
            map_store!(self.handle.replace_media_track(store_track, store_segments))
        })
    }

    fn load_track<'a>(
        &'a self,
        gid: &'a str,
        track_idx: usize,
    ) -> BoxFuture<'a, Result<Option<(TrackRecord, Vec<SegmentRecord>)>, MediaError>> {
        Box::pin(async move {
            let all = map_store_val!(self.handle.load_media_tracks(gid))?;
            let Some((t, segs)) = all
                .into_iter()
                .find(|(t, _)| t.track_idx as usize == track_idx)
            else {
                return Ok(None);
            };
            let track = TrackRecord {
                track_idx: t.track_idx as usize,
                kind: t.kind,
                playlist_uri: t.playlist_uri,
                local_name: t.local_name,
                init_files: t
                    .init_files_json
                    .and_then(|j| serde_json::from_str(&j).ok())
                    .unwrap_or_default(),
                seg_bitmap: t.seg_bitmap.unwrap_or_default(),
                seg_count: t.seg_count.unwrap_or(0) as usize,
            };
            let segments = segs
                .into_iter()
                .map(|s| SegmentRecord {
                    seg_idx: s.seg_idx as usize,
                    media_sequence: s.media_sequence.unwrap_or(0) as u64,
                    uri: s.uri,
                    byte_range: s.byte_range,
                    key_id: s.key_id,
                    seg_len: s.seg_len as u64,
                    duration_ms: s.duration_ms.unwrap_or(0) as u64,
                    map: s.map_idx.map(|m| m as usize),
                    validator_digest: s.validator_digest.unwrap_or_default(),
                })
                .collect();
            Ok(Some((track, segments)))
        })
    }

    fn upsert_media_keys<'a>(
        &'a self,
        _gid: &'a str,
        _keys: &'a [taiji_media::keys::KeyRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async { Ok(()) })
    }

    fn load_media_keys<'a>(
        &'a self,
        _gid: &'a str,
    ) -> BoxFuture<'a, Result<Vec<taiji_media::keys::KeyRecord>, MediaError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn tempdir(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("taiji-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

struct Rig {
    addr: SocketAddr,
    out_dir: PathBuf,
    db_path: PathBuf,
    hits: Hits,
    manifest_path: &'static str,
}

impl Rig {
    async fn ledger(&self) -> (StoreLedger, tokio::task::JoinHandle<()>) {
        let (handle, join) = taiji_store::persist::PersistWriter::spawn(self.db_path.clone())
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
        (StoreLedger { handle }, join)
    }

    fn download(&self) -> MediaDownload {
        let client =
            HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
        MediaDownload::new(
            "8000000000000116",
            client,
            RequestCtx::default(),
            MediaDownloadConfig {
                output_dir: self.out_dir.clone(),
                allow_private_key_url: true,
                ..MediaDownloadConfig::default()
            },
        )
    }

    fn manifest_url(&self) -> String {
        format!("http://{}{}", self.addr, self.manifest_path)
    }

    fn staging_dir(&self) -> PathBuf {
        self.out_dir.join(".taiji-b").join("8000000000000116")
    }

    /// The synthesis inputs through the session's DASH bridge shape:
    /// re-fetch the MPD, re-plan, re-expand the planned track.
    async fn dash_track_inputs(&self, report: &taiji_media::MediaRunReport) -> Vec<TrackInput> {
        let client =
            HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
        let bytes = taiji_media::mediadl::http_get_bytes(
            &client,
            &self.manifest_url(),
            &RequestCtx::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("mpd re-fetch: {e}"));
        let mpd_doc = mpd::parse_mpd(&bytes).unwrap_or_else(|e| panic!("re-parse: {e}"));
        let plan = mpd::plan_dash_tracks(
            &mpd_doc,
            &self.manifest_url(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap_or_else(|e| panic!("re-plan: {e}"));
        let mut inputs = Vec::new();
        for (planned, state) in &report.tracks {
            if matches!(state, TrackState::Failed(_) | TrackState::Degraded(_)) {
                continue;
            }
            let pick = &plan.picks[planned.track_idx];
            let track = match mpd::expand_representation(&mpd_doc, &self.manifest_url(), pick)
                .unwrap_or_else(|e| panic!("re-expand: {e}"))
            {
                mpd::Expanded::Ready(t) => t,
                mpd::Expanded::DeferredSidx(_) => panic!("no deferred sidx at synthesis"),
            };
            inputs.push(TrackInput {
                label: planned.label.clone(),
                kind: planned.kind.as_str().to_string(),
                archive: self
                    .staging_dir()
                    .join(format!("archive-{}.m4s", planned.label)),
                inits: (0..track.playlist.init_sections.len())
                    .map(|i| {
                        self.staging_dir()
                            .join(taiji_media::m3u8::init_section_filename(&planned.label, i))
                    })
                    .collect(),
                segments: Vec::new(), // filled by the caller from the ledger
                playlist: track.playlist,
                archive_name: format!("archive-{}.m4s", planned.label),
            });
        }
        inputs
    }
}

/// The lenient local ffmpeg runtime (the synthesis e2e's face: discovery +
/// `-version` parse; the license gate is a production posture —
/// the dev machine's Homebrew pair carries `--enable-gpl`).
async fn local_ffmpeg() -> Option<taiji_media::ffmpegmux::FfmpegRuntime> {
    let pair = taiji_media::discover(&taiji_media::DiscoveryRequest::default()).ok()?;
    let cmd = taiji_media::MediaCommand::new(taiji_media::MediaBin::Ffmpeg, &pair.ffmpeg)
        .ok()?
        .args(taiji_media::VersionInfo::version_args().iter().copied())
        .shim_program(Some(PathBuf::from(env!("CARGO_BIN_EXE_taiji-media-shim"))));
    let child = cmd.spawn().ok()?;
    let out = child.wait().await.ok()?;
    if !out.success {
        return None;
    }
    let version = taiji_media::VersionInfo::parse(&String::from_utf8_lossy(&out.stdout)).ok()?;
    Some(taiji_media::ffmpegmux::FfmpegRuntime {
        pair,
        version,
        shim_program: Some(PathBuf::from(env!("CARGO_BIN_EXE_taiji-media-shim"))),
    })
}

/// One fixture segment: 3 samples × 512 bytes.
fn fixture_segment(seq: u32, decode_time: u64) -> Vec<u8> {
    let samples: Vec<FixtureSample> = (0..3)
        .map(|i| FixtureSample {
            duration: 33,
            size: 512,
            sync: i == 0,
            cts: if i == 1 { 33 } else { 0 },
        })
        .collect();
    let payload: Vec<u8> = samples
        .iter()
        .enumerate()
        .flat_map(|(i, s)| avcc_sample(i == 0, s.size as usize))
        .collect();
    build_segment(1, seq, decode_time, &samples, &payload)
}

// ---------------------------------------------------------------------------
// (b) row: multi-Period SegmentTemplate → archive + native product
// ---------------------------------------------------------------------------

#[tokio::test]
async fn b_layer_multi_period_template_end_to_end() {
    let hits = Hits::default();
    let h = hits.clone();
    let addr = spawn_with(move |addr| {
        let mpd_text = String::from(
            r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT1.188S" profiles="urn:mpeg:dash:profile:isoff-live:2011">
  <Period id="p1" duration="PT0.594S">
    <AdaptationSet id="vid" mimeType="video/mp4" codecs="avc1.64001f">
      <SegmentTemplate timescale="1000" duration="99" startNumber="1"
        initialization="p1/init.mp4" media="p1/seg-$Number$.m4s"/>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
  <Period id="p2" duration="PT0.594S">
    <AdaptationSet id="vid" mimeType="video/mp4">
      <SegmentTemplate timescale="1000" duration="99" startNumber="1"
        initialization="p2/init.mp4" media="p2/seg-$Number$.m4s"/>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
        );
        let vspec = video_init_spec();
        let init0 = build_init(&vspec);
        let init1 = build_init(&vspec);
        // Period 1: 594ms / 99ms = 6 segments per period (the
        // fixture segments each carry 3 samples x 33ms).
        let mut p1 = Vec::new();
        for i in 0..6u32 {
            p1.push(fixture_segment(i, u64::from(i) * 99));
        }
        let mut p2 = Vec::new();
        for i in 0..6u32 {
            p2.push(fixture_segment(100 + i, u64::from(i) * 99));
        }
        let mut app = Router::new();
        app = app.route(
            "/media.mpd",
            get(move || {
                let text = mpd_text.clone();
                async move { mpd_body(text) }
            }),
        );
        let count = move |h: &Hits| h.gets.clone();
        let _ = count;
        app = app.route(
            "/p1/init.mp4",
            get({
                let h = h.clone();
                move || {
                    let bytes = init0.clone();
                    let h = h.clone();
                    async move {
                        h.gets
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push("p1/init.mp4".to_string());
                        file_200(bytes, "video/mp4")
                    }
                }
            }),
        );
        app = app.route(
            "/p2/init.mp4",
            get({
                let h = h.clone();
                move || {
                    let bytes = init1.clone();
                    let h = h.clone();
                    async move {
                        h.gets
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push("p2/init.mp4".to_string());
                        file_200(bytes, "video/mp4")
                    }
                }
            }),
        );
        for (i, seg) in p1.into_iter().enumerate() {
            let path = format!("/p1/seg-{}.m4s", i + 1);
            let name = path.clone();
            let h = h.clone();
            app = app.route(
                &path,
                get(move || {
                    let bytes = seg.clone();
                    let h = h.clone();
                    let name = name.clone();
                    async move {
                        h.gets.lock().unwrap_or_else(|e| e.into_inner()).push(name);
                        file_200(bytes, "video/mp4")
                    }
                }),
            );
        }
        for (i, seg) in p2.into_iter().enumerate() {
            let path = format!("/p2/seg-{}.m4s", i + 1);
            let name = path.clone();
            let h = h.clone();
            app = app.route(
                &path,
                get(move || {
                    let bytes = seg.clone();
                    let h = h.clone();
                    let name = name.clone();
                    async move {
                        h.gets.lock().unwrap_or_else(|e| e.into_inner()).push(name);
                        file_200(bytes, "video/mp4")
                    }
                }),
            );
        }
        let _ = addr;
        app
    })
    .await;

    let out_dir = tempdir("b-layer");
    let db_dir = tempdir("b-layer-db");
    let rig = Rig {
        addr,
        out_dir,
        db_path: db_dir.join("taiji.sqlite3"),
        hits,
        manifest_path: "/media.mpd",
    };
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));
    join.abort();

    // Track set + layer.
    assert_eq!(report.tracks.len(), 1, "one video track");
    assert!(matches!(report.verdict, TrackSetVerdict::Complete { .. }));
    let staging = rig.staging_dir();
    assert!(staging.join("archive-v.m4s").is_file(), "the archive");
    assert!(staging.join("init-v-0.mp4").is_file(), "period-1 init");
    assert!(staging.join("init-v-1.mp4").is_file(), "period-2 init");
    assert!(staging.join("source.mpd").is_file(), "the raw MPD archived");

    // The archive is the cross-period append: exactly the fixture
    // segments in order (plaintext — no DASH keys).
    let archive = std::fs::read(staging.join("archive-v.m4s")).unwrap_or_else(|e| panic!("{e}"));
    let mut expect = Vec::new();
    for i in 0..6u32 {
        expect.extend_from_slice(&fixture_segment(i, u64::from(i) * 99));
    }
    for i in 0..6u32 {
        expect.extend_from_slice(&fixture_segment(100 + i, u64::from(i) * 99));
    }
    assert_eq!(archive, expect, "cross-period ordered append");

    // Ledger: 12 rows, cross-period ordinals 0..12, bitmap complete.
    let (ledger2, join2) = rig.ledger().await;
    let (track, segments) = ledger2
        .load_track("8000000000000116", 0)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("track row"));
    assert_eq!(track.kind, "video");
    assert_eq!(segments.len(), 12);
    for (i, seg) in segments.iter().enumerate() {
        assert_eq!(seg.media_sequence, i as u64, "cross-period ordinal");
        assert!(seg.seg_len > 0);
    }
    assert_eq!(
        taiji_media::trackdl::unpack_bitmap_prefix(&track.seg_bitmap),
        12,
        "the bitmap prefix is complete"
    );
    assert_eq!(track.init_files.len(), 2);

    // ---- Resume invariant: a second run over the same ledger leaves
    // the archive byte-identical and re-fetches no MEDIA segment (the
    // seg_bitmap domain). Init sections re-fetch per run by design
    // (the download face: unconditional, idempotent overwrite — outside
    // the bitmap's resume domain). ----
    let seg_gets = |h: &Hits| -> usize { h.gets().iter().filter(|p| p.contains("seg-")).count() };
    let seg_gets_before = seg_gets(&rig.hits);
    let init_gets_before = rig
        .hits
        .gets()
        .iter()
        .filter(|p| p.contains("init"))
        .count();
    let archive_before = archive.clone();
    let report2 = rig
        .download()
        .run(&rig.manifest_url(), &ledger2)
        .await
        .unwrap_or_else(|e| panic!("resume run: {e}"));
    join2.abort();
    assert!(matches!(report2.verdict, TrackSetVerdict::Complete { .. }));
    let archive_after =
        std::fs::read(staging.join("archive-v.m4s")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(archive_before, archive_after, "resume keeps the archive");
    assert_eq!(
        seg_gets(&rig.hits),
        seg_gets_before,
        "the resumed run re-fetched no media segment"
    );
    let init_gets_after = rig
        .hits
        .gets()
        .iter()
        .filter(|p| p.contains("init"))
        .count();
    assert_eq!(
        init_gets_after,
        init_gets_before + 2,
        "the two per-period init sections re-fetched (idempotent, outside the bitmap domain)"
    );

    // ---- Synthesis (the session's DASH bridge shape) → product. ----
    let mut inputs = rig.dash_track_inputs(&report2).await;
    for input in &mut inputs {
        let (_, segments) = {
            let (ledger3, join3) = rig.ledger().await;
            let loaded = ledger3
                .load_track("8000000000000116", 0)
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .unwrap_or_else(|| panic!("track row"));
            join3.abort();
            loaded
        };
        input.segments = segments;
    }
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].playlist.segments.len(), 12);
    assert_eq!(inputs[0].playlist.init_sections.len(), 2);
    // The synthetic playlist keeps the layer judgment honest ((b)):
    assert_eq!(
        classify_track(&inputs[0].playlist),
        TrackLayer::UnknownLength
    );

    let cfg = SynthesisConfig {
        phase_sink: None,
        format: OutputFormat::Mp4,
        muxer: MuxerPreference::Auto,
        output: rig.out_dir.join("b-layer.mp4"),
        staging_dir: staging.clone(),
        ffmpeg: local_ffmpeg().await,
        embed_subtitles: false,
        meta: taiji_media::mp4write::MovieMeta::default(),
        free_bytes_override: Some(None),
    };
    let synth_report =
        synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
            .await
            .unwrap_or_else(|e| panic!("synthesis: {e}"));
    assert_eq!(synth_report.channel_used, "native");
    let product = std::fs::metadata(&synth_report.product).unwrap_or_else(|e| panic!("{e}"));
    assert!(product.len() > 0, "the multi-period product landed");
    // The native probe (box assertions) + the ffprobe dual-run ran inside
    // run_synthesis (the dual-run only when the local pair exists —
    // the runtime guard; a missing pair is not a failure).
}

fn file_200(bytes: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], bytes).into_response()
}

// ---------------------------------------------------------------------------
// (a) row: SegmentList + mediaRange → extent grid + product
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_layer_segment_list_media_range_end_to_end() {
    // The single resource: [init 0..init_len][seg0][seg1][seg2].
    let vspec = video_init_spec();
    let init = build_init(&vspec);
    let segs: Vec<Vec<u8>> = (0..3u32)
        .map(|i| fixture_segment(i, u64::from(i) * 99))
        .collect();
    let mut blob = init.clone();
    let init_len = init.len() as u64;
    let mut ranges = Vec::new();
    for seg in &segs {
        let begin = blob.len() as u64;
        blob.extend_from_slice(seg);
        ranges.push((begin, blob.len() as u64 - 1));
    }
    let blob_len = blob.len() as u64;

    let hits = Hits::default();
    let h = hits.clone();
    let blob_for_route = blob.clone();
    let ranges_for_mpd = ranges.clone();
    let init_len_for_mpd = init_len;
    let addr = spawn_with(move |addr| {
        let mpd_text = format!(
            r#"<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentList timescale="1000" duration="99">
        <Initialization sourceURL="media.bin" range="0-{}"/>
        <SegmentURL media="media.bin" mediaRange="{}-{}"/>
        <SegmentURL media="media.bin" mediaRange="{}-{}"/>
        <SegmentURL media="media.bin" mediaRange="{}-{}"/>
      </SegmentList>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
            init_len_for_mpd - 1,
            ranges_for_mpd[0].0,
            ranges_for_mpd[0].1,
            ranges_for_mpd[1].0,
            ranges_for_mpd[1].1,
            ranges_for_mpd[2].0,
            ranges_for_mpd[2].1,
        );
        let _ = addr;
        let mut app = Router::new();
        app = app.route(
            "/media.mpd",
            get(move || {
                let text = mpd_text.clone();
                async move { mpd_body(text) }
            }),
        );
        let blob = std::sync::Arc::new(blob_for_route.clone());
        let h = h.clone();
        app = app.route(
            "/media.bin",
            get(move |req: axum::extract::Request| {
                let blob = Arc::clone(&blob);
                let h = h.clone();
                async move {
                    let range = req
                        .headers()
                        .get(header::RANGE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    if !range.is_empty() {
                        h.ranges
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(range.clone());
                    } else {
                        h.gets
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push("media.bin".to_string());
                    }
                    if range.is_empty() {
                        return file_200((*blob).clone(), "application/octet-stream");
                    }
                    let (start, end_incl) = parse_range(&range, blob.len() as u64);
                    let body = blob[start as usize..=(end_incl as usize)].to_vec();
                    let mut resp = Response::new(axum::body::Body::from(body));
                    *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let headers = resp.headers_mut();
                    let cr =
                        HeaderValue::from_str(&format!("bytes {start}-{end_incl}/{}", blob.len()))
                            .unwrap_or_else(|e| panic!("content-range: {e}"));
                    headers.insert(header::CONTENT_RANGE, cr);
                    headers.insert(
                        header::CONTENT_LENGTH,
                        HeaderValue::from(end_incl - start + 1),
                    );
                    resp
                }
            }),
        );
        app
    })
    .await;

    let out_dir = tempdir("a-layer");
    let db_dir = tempdir("a-layer-db");
    let rig = Rig {
        addr,
        out_dir,
        db_path: db_dir.join("taiji.sqlite3"),
        hits,
        manifest_path: "/media.mpd",
    };
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));
    join.abort();
    assert!(matches!(report.verdict, TrackSetVerdict::Complete { .. }));

    let staging = rig.staging_dir();
    // The init section landed from its byte range; the archive holds
    // exactly the three contiguous slices.
    let init_file = std::fs::read(staging.join("init-v-0.mp4")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(init_file, init, "the init range slice");
    let archive = std::fs::read(staging.join("archive-v.m4s")).unwrap_or_else(|e| panic!("{e}"));
    let mut expect = Vec::new();
    for seg in &segs {
        expect.extend_from_slice(seg);
    }
    assert_eq!(archive, expect, "the mediaRange slices in order");

    // (a)-layer wire face: the touching same-URI ranges fold — the
    // media GETs are extent-covering Range requests that never dip
    // below the first media byte (the init's own 0..init_len GET is
    // the init face, counted out by its exact bound).
    let seen = rig.hits.ranges();
    assert!(!seen.is_empty(), "the (a) layer used Range GETs");
    let init_get = format!("bytes=0-{}", init_len - 1);
    let media_gets: Vec<&String> = seen.iter().filter(|r| **r != init_get).collect();
    assert!(
        !media_gets.is_empty(),
        "media Range GETs happened: {seen:?}"
    );
    for r in &media_gets {
        let (start, _) = parse_range(r, blob_len);
        assert!(start >= ranges[0].0, "range {r} covers media bytes only");
    }

    // ---- product through the same synthesis bridge ----
    let mut inputs = rig.dash_track_inputs(&report).await;
    for input in &mut inputs {
        let (ledger3, join3) = rig.ledger().await;
        let (_, segments) = ledger3
            .load_track("8000000000000116", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("track row"));
        join3.abort();
        input.segments = segments;
    }
    assert_eq!(inputs.len(), 1);
    assert_eq!(classify_track(&inputs[0].playlist), TrackLayer::KnownLength);
    let cfg = SynthesisConfig {
        phase_sink: None,
        format: OutputFormat::Mp4,
        muxer: MuxerPreference::Auto,
        output: rig.out_dir.join("a-layer.mp4"),
        staging_dir: staging.clone(),
        ffmpeg: local_ffmpeg().await,
        embed_subtitles: false,
        meta: taiji_media::mp4write::MovieMeta::default(),
        free_bytes_override: Some(None),
    };
    let synth_report =
        synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
            .await
            .unwrap_or_else(|e| panic!("synthesis: {e}"));
    assert_eq!(synth_report.channel_used, "native");
    assert!(
        std::fs::metadata(&synth_report.product)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "the (a)-layer product landed"
    );
}

fn parse_range(range: &str, total: u64) -> (u64, u64) {
    let spec = range.trim().strip_prefix("bytes=").unwrap_or("");
    match spec.split_once('-') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() => (
            a.parse().unwrap_or(0),
            b.parse::<u64>().unwrap_or(total - 1).min(total - 1),
        ),
        Some((a, _)) if !a.is_empty() => (a.parse().unwrap_or(0), total - 1),
        _ => (0, total - 1),
    }
}
