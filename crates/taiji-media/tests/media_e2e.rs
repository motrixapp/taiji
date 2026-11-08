//! Multi-track HLS acceptance e2e: mock multi-track HLS over a local axum
//! source, programmatic drive (no RPC), real sqlite ledger.
//!
//! Covers the acceptance faces:
//! * ① three tracks end-to-end — archives + init sections +
//!   source.m3u8 staged, media_track/media_segment accounting
//!   consistent with the bitmaps and archive lengths;
//! * ② the BYTERANGE ≤8 merge wire assertion — 16 adjacent
//!   sub-segments of one resource fetched with exactly **one** Range
//!   GET (mock-side request count);
//! * ③ unknown-length segments take the no-grid (b) layer and resume
//!   from the segment bitmap (a mid-run failure leaves a partial
//!   prefix; the retry fetches only the tail);
//! * required-track failure fails the set; sidecar failure degrades
//!   to completion with the warning recorded;
//! * multi-MAP boundaries + non-zero media sequence land in the
//!   ledger rows;
//! * the out-of-order write-back window anchor constants (media-side
//!   copy of the base's named anchors).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bytes::Bytes;
use futures::future::BoxFuture;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::keys::KeyRecord;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::trackdl::{MediaLedger, MediaTaskRecord, SegmentRecord, TrackRecord};
use taiji_media::{MediaError, TrackSetVerdict, TrackState};
use taiji_store::persist::writer::{
    MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow, PersistWriter,
};

// ---------------------------------------------------------------------------
// mock source
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MockState {
    /// Total GET hits on the BYTERANGE resource.
    blob_hits: Arc<AtomicU64>,
    /// Range headers seen on the BYTERANGE resource (one per hit).
    blob_ranges: Arc<std::sync::Mutex<Vec<String>>>,
    /// GET hits on plain segments (paths, in order).
    seg_hits: Arc<std::sync::Mutex<Vec<String>>>,
    /// Paths returning 500 while listed (failure injection).
    fail_paths: Arc<std::sync::Mutex<Vec<String>>>,
}

impl MockState {
    fn is_failing(&self, path: &str) -> bool {
        self.fail_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|p| p == path)
    }

    fn fail(&self, path: &str) {
        self.fail_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.to_string());
    }

    fn note_seg(&self, path: &str) {
        self.seg_hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.to_string());
    }
}

fn full_body(body: Vec<u8>) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "video/mp2t")], body).into_response()
}

/// Bind first, then build the app (the playlists embed the bound
/// address as absolute URIs).
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

/// The BYTERANGE resource: answers Range requests from an in-memory
/// blob (proper 206 + Content-Range echo), counting every hit.
async fn blob(State(st): State<MockState>, req: Request) -> Response {
    let blob = test_blob();
    let range = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    st.blob_hits.fetch_add(1, Ordering::SeqCst);
    st.blob_ranges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(range.clone());
    let (start, end_incl) = parse_range(&range, blob.len() as u64);
    let body = blob[start as usize..=(end_incl as usize)].to_vec();
    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
    let headers = resp.headers_mut();
    let cr = HeaderValue::from_str(&format!("bytes {start}-{end_incl}/{}", blob.len()))
        .unwrap_or_else(|e| panic!("content-range: {e}"));
    headers.insert(header::CONTENT_RANGE, cr);
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(end_incl - start + 1),
    );
    resp
}

fn parse_range(range: &str, total: u64) -> (u64, u64) {
    // "bytes=a-b" (inclusive); missing/odd -> whole resource.
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

/// Plain whole-body segment: counts a hit, honors the failure gate.
async fn segment(State(st): State<MockState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    if st.is_failing(&path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }
    st.note_seg(&path);
    full_body(segment_body(&path))
}

fn segment_body(path: &str) -> Vec<u8> {
    // Deterministic per-path bodies (the trailing index hashes into
    // both length and bytes).
    let idx: u64 = path
        .rsplit('/')
        .next()
        .and_then(|name| {
            let digits: String = name.chars().filter(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .unwrap_or(0);
    let len = 1024 + (idx as usize) * 37;
    (0..len)
        .map(|i| (i as u8).wrapping_add(idx as u8))
        .collect()
}

fn test_blob() -> Vec<u8> {
    (0..64 * 1024u32).map(|i| (i % 251) as u8).collect()
}

/// 16 BYTERANGE sub-segments (1KiB each, contiguous) across 2 MAPs
/// with a non-zero media sequence — the (a)-layer video playlist.
fn v720_playlist(addr: &SocketAddr) -> String {
    let mut t = String::from("#EXTM3U\n");
    t.push_str("#EXT-X-VERSION:7\n");
    t.push_str("#EXT-X-TARGETDURATION:2\n");
    t.push_str("#EXT-X-MEDIA-SEQUENCE:500\n");
    t.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/init0.mp4\"\n"));
    for i in 0..8u64 {
        t.push_str(&format!(
            "#EXTINF:1.0,\n#EXT-X-BYTERANGE:1024@{}\nhttp://{addr}/blob.bin\n",
            i * 1024
        ));
    }
    t.push_str("#EXT-X-DISCONTINUITY\n");
    t.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/init1.mp4\"\n"));
    for i in 8..16u64 {
        t.push_str(&format!(
            "#EXTINF:1.0,\n#EXT-X-BYTERANGE:1024@{}\nhttp://{addr}/blob.bin\n",
            i * 1024
        ));
    }
    t.push_str("#EXT-X-ENDLIST\n");
    t
}

fn master_playlist(addr: &SocketAddr) -> String {
    format!(
        "#EXTM3U\n\
         #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"fr\",NAME=\"Français\",DEFAULT=YES,URI=\"http://{addr}/audio.m3u8\"\n\
         #EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"sub\",LANGUAGE=\"en\",NAME=\"EN\",URI=\"http://{addr}/sub.m3u8\"\n\
         #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=1280x720,AUDIO=\"aud\",SUBTITLES=\"sub\"\n\
         http://{addr}/v720.m3u8\n"
    )
}

fn audio_playlist(addr: &SocketAddr) -> String {
    let mut t = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:9000\n");
    for i in 0..6u64 {
        t.push_str(&format!("#EXTINF:1.5,\nhttp://{addr}/aseg{i}.ts\n"));
    }
    t.push_str("#EXT-X-ENDLIST\n");
    t
}

fn sub_playlist(addr: &SocketAddr) -> String {
    let mut t = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
    for i in 0..3u64 {
        t.push_str(&format!("#EXTINF:2.0,\nhttp://{addr}/svtt{i}.vtt\n"));
    }
    t.push_str("#EXT-X-ENDLIST\n");
    t
}

fn build_router(addr: SocketAddr, st: MockState) -> Router {
    let manifest = master_playlist(&addr).into_bytes();
    let video = v720_playlist(&addr).into_bytes();
    let audio = audio_playlist(&addr).into_bytes();
    let sub = sub_playlist(&addr).into_bytes();
    Router::new()
        .route("/blob.bin", get(blob))
        .route(
            "/master.m3u8",
            get(move || async move { full_body(manifest.clone()) }),
        )
        .route(
            "/v720.m3u8",
            get(move || async move { full_body(video.clone()) }),
        )
        .route(
            "/audio.m3u8",
            get(move || async move { full_body(audio.clone()) }),
        )
        .route(
            "/sub.m3u8",
            get(move || async move { full_body(sub.clone()) }),
        )
        .route(
            "/init0.mp4",
            get(|| async move { full_body(b"INIT0".to_vec()) }),
        )
        .route(
            "/init1.mp4",
            get(|| async move { full_body(b"INIT1".to_vec()) }),
        )
        .route("/aseg0.ts", get(segment))
        .route("/aseg1.ts", get(segment))
        .route("/aseg2.ts", get(segment))
        .route("/aseg3.ts", get(segment))
        .route("/aseg4.ts", get(segment))
        .route("/aseg5.ts", get(segment))
        .route("/svtt0.vtt", get(segment))
        .route("/svtt1.vtt", get(segment))
        .route("/svtt2.vtt", get(segment))
        .with_state(st)
}

// ---------------------------------------------------------------------------
// store-backed ledger adapter
// ---------------------------------------------------------------------------

struct StoreLedger {
    handle: taiji_store::persist::writer::PersistHandle,
}

impl MediaLedger for StoreLedger {
    fn ensure_task<'a>(
        &'a self,
        row: &'a MediaTaskRecord,
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            let store_row = MediaTaskRow {
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
            };
            self.handle
                .upsert_media_task(store_row)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(())
        })
    }

    fn save_track<'a>(
        &'a self,
        gid: &'a str,
        track: &'a TrackRecord,
        segments: &'a [SegmentRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
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
            self.handle
                .replace_media_track(store_track, store_segments)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(())
        })
    }

    fn load_track<'a>(
        &'a self,
        gid: &'a str,
        track_idx: usize,
    ) -> BoxFuture<'a, Result<Option<(TrackRecord, Vec<SegmentRecord>)>, MediaError>> {
        Box::pin(async move {
            let all = self
                .handle
                .load_media_tracks(gid)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
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
        gid: &'a str,
        keys: &'a [KeyRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            let rows: Vec<MediaKeyRow> = keys
                .iter()
                .map(|k| MediaKeyRow {
                    id: None,
                    gid: gid.to_string(),
                    key_id: k.key_id.clone(),
                    uri: k.uri.clone(),
                    iv: k.iv.map(|iv| iv.to_vec()),
                    key: k.key.to_vec(),
                })
                .collect();
            self.handle
                .upsert_media_keys(gid, rows)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(())
        })
    }

    fn load_media_keys<'a>(
        &'a self,
        gid: &'a str,
    ) -> BoxFuture<'a, Result<Vec<KeyRecord>, MediaError>> {
        Box::pin(async move {
            let rows = self
                .handle
                .load_media_keys(gid)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(rows
                .into_iter()
                .map(|r| KeyRecord {
                    db_id: r.id,
                    key_id: r.key_id,
                    uri: r.uri,
                    iv: r.iv.and_then(|iv| <[u8; 16]>::try_from(iv.as_slice()).ok()),
                    key: r.key.try_into().unwrap_or([0; 16]),
                })
                .collect())
        })
    }
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct Rig {
    addr: SocketAddr,
    state: MockState,
    out_dir: PathBuf,
    db_path: PathBuf,
}

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("taiji-media-e2e-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
    path
}

async fn rig(tag: &str) -> Rig {
    let state = MockState::default();
    let st = state.clone();
    let addr = spawn_with(move |a| build_router(a, st)).await;
    let out_dir = tempdir(tag);
    let db_dir = tempdir(&format!("{tag}-db"));
    Rig {
        addr,
        state,
        out_dir,
        db_path: db_dir.join("taiji.sqlite3"),
    }
}

impl Rig {
    async fn ledger(&self) -> (StoreLedger, tokio::task::JoinHandle<()>) {
        let (handle, join) = PersistWriter::spawn(self.db_path.clone())
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
        (StoreLedger { handle }, join)
    }

    fn download(&self) -> MediaDownload {
        let client =
            HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
        MediaDownload::new(
            "8000000000000091",
            client,
            RequestCtx::default(),
            MediaDownloadConfig {
                output_dir: self.out_dir.clone(),
                // Migration: the mock source lives on the
                // loopback — the SSRF default-deny would refuse its
                // segment URLs, so the lab runs with the allow flag
                // (the documented migration policy for local/mock
                // sources).
                allow_private_key_url: true,
                ..MediaDownloadConfig::default()
            },
        )
    }

    fn manifest_url(&self) -> String {
        format!("http://{}/master.m3u8", self.addr)
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// ①+②+multi-MAP+non-zero-seq: three tracks end-to-end; the 16
/// sub-segment BYTERANGE resource is fetched with exactly ONE Range
/// GET (maximal span merge); ledger rows consistent with the archives.
#[tokio::test]
async fn multi_track_end_to_end_and_wire_merge() {
    let rig = rig("main").await;
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));

    // Track set: v + a + s0, all Done.
    assert_eq!(report.tracks.len(), 3);
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "verdict: {:?}",
        report.verdict
    );
    for (track, state) in &report.tracks {
        assert_eq!(*state, TrackState::Done, "track {}", track.label);
    }

    // ② The wire assertion: 16 adjacent sub-segments → one Range GET.
    let hits = rig.state.blob_hits.load(Ordering::SeqCst);
    let ranges = rig
        .state
        .blob_ranges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(hits, 1, "BYTERANGE resource hits: {ranges:?}");
    assert_eq!(
        ranges.first().map(String::as_str),
        Some("bytes=0-16383"),
        "the single GET covers the whole maximal span"
    );

    // ① Staging layout: archives + init sections + source manifest.
    let stage = &report.staging_dir;
    assert!(stage.is_dir());
    assert!(stage.join("archive-v.m4s").is_file(), "video archive");
    assert!(stage.join("archive-a.ts").is_file(), "audio archive");
    assert!(stage.join("archive-s0.vtt").is_file(), "subtitle archive");
    assert!(stage.join("init-v-0.mp4").is_file(), "MAP 0 init section");
    assert!(stage.join("init-v-1.mp4").is_file(), "MAP 1 init section");
    assert!(stage.join("source.m3u8").is_file(), "raw manifest archived");

    // Archive bytes == the virtual layout (resource slice in playlist
    // order — positional (a)-layer writes reproduce the source bytes).
    let blob = test_blob();
    let v = std::fs::read(stage.join("archive-v.m4s")).unwrap_or_else(|e| panic!("read v: {e}"));
    assert_eq!(v.len(), 16 * 1024);
    assert_eq!(v[..1024], blob[0..1024]);
    assert_eq!(v[15 * 1024..], blob[15 * 1024..16 * 1024]);

    // Init section bodies land verbatim.
    assert_eq!(
        std::fs::read(stage.join("init-v-0.mp4")).unwrap_or_else(|e| panic!("init0: {e}")),
        b"INIT0".to_vec()
    );
    assert_eq!(
        std::fs::read(stage.join("init-v-1.mp4")).unwrap_or_else(|e| panic!("init1: {e}")),
        b"INIT1".to_vec()
    );

    // Audio archive == concatenated segment bodies in order.
    let a = std::fs::read(stage.join("archive-a.ts")).unwrap_or_else(|e| panic!("read a: {e}"));
    let expect_a: Vec<u8> = (0..6u64)
        .flat_map(|i| segment_body(&format!("/aseg{i}.ts")))
        .collect();
    assert_eq!(a, expect_a);

    // ① Ledger accounting: media_track/media_segment rows vs
    // bitmaps and archive lengths.
    drop(ledger);
    join.await.ok();
    let (ledger2, join2) = rig.ledger().await;
    let all = ledger2
        .handle
        .load_media_tracks("8000000000000091")
        .await
        .unwrap_or_else(|e| panic!("load: {e}"));
    drop(ledger2);
    join2.await.ok();
    assert_eq!(all.len(), 3, "one row set per track");
    for (track, segments) in &all {
        match track.kind.as_str() {
            "video" => {
                assert_eq!(track.local_name, "archive-v.m4s");
                assert_eq!(segments.len(), 16);
                assert_eq!(track.seg_count, Some(16));
                let bitmap = track.seg_bitmap.clone().unwrap_or_default();
                assert_eq!(bitmap, vec![0xFF, 0xFF], "all 16 bits set");
                // Non-zero sequence: 500..515.
                assert_eq!(segments[0].media_sequence, Some(500));
                assert_eq!(segments[15].media_sequence, Some(515));
                // Segment lengths sum to the archive length.
                let sum: i64 = segments.iter().map(|s| s.seg_len).sum();
                assert_eq!(sum, 16 * 1024);
                // Validator digests present and distinct.
                assert!(segments.iter().all(|s| s.validator_digest.is_some()));
                assert_ne!(segments[0].validator_digest, segments[1].validator_digest);
                // Multi-MAP boundary bookkeeping: segments 0-7 under
                // MAP 0, 8-15 under MAP 1.
                assert_eq!(segments[0].map_idx, Some(0));
                assert_eq!(segments[7].map_idx, Some(0));
                assert_eq!(segments[8].map_idx, Some(1));
                assert_eq!(segments[15].map_idx, Some(1));
            }
            "audio" => {
                assert_eq!(track.local_name, "archive-a.ts");
                assert_eq!(segments.len(), 6);
                assert_eq!(segments[0].media_sequence, Some(9000));
                let sum: i64 = segments.iter().map(|s| s.seg_len).sum();
                assert_eq!(
                    sum as u64,
                    std::fs::metadata(stage.join("archive-a.ts"))
                        .unwrap_or_else(|e| panic!("meta: {e}"))
                        .len(),
                    "seg_len Σ == archive length"
                );
            }
            "subtitle" => {
                assert_eq!(segments.len(), 3);
                let bitmap = track.seg_bitmap.clone().unwrap_or_default();
                assert_eq!(bitmap, vec![0b0000_0111]);
            }
            other => panic!("unexpected track kind {other}"),
        }
    }

    // (a)-layer idempotent re-run (the grid-bitmap resume form): with
    // the ledger reporting every segment done, the re-run seeds the
    // whole grid and re-fetches nothing — the blob hit count stays 1.
    {
        let (ledger3, join3) = rig.ledger().await;
        let report = rig
            .download()
            .run(&rig.manifest_url(), &ledger3)
            .await
            .unwrap_or_else(|e| panic!("rerun: {e}"));
        assert!(
            matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
            "rerun verdict: {:?}",
            report.verdict
        );
        drop(ledger3);
        join3.await.ok();
        assert_eq!(
            rig.state.blob_hits.load(Ordering::SeqCst),
            1,
            "grid-bitmap resume: no BYTERANGE refetch"
        );
    }

    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// ③ Unknown-length resume: a mid-run failure leaves a partial prefix
/// in the ledger/archive; the re-run fetches only the tail
/// (wire-level segment counts), truncating a corrupt archive tail to
/// the last complete segment boundary first.
#[tokio::test]
async fn unknown_length_resume_from_seg_bitmap() {
    let rig = rig("resume").await;
    // Direct media playlist entry (unknown-length whole segments —
    // the (b) layer, no grid).
    let manifest = format!("http://{}/audio.m3u8", rig.addr);
    rig.state.fail("/aseg4.ts");
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run1: {e}"));
    // The single track is required: its failure fails the set.
    match report.verdict.clone() {
        TrackSetVerdict::Failed { required, .. } => assert_eq!(required, "v"),
        other => panic!("expected Failed, got {other:?}"),
    }
    let stage = &report.staging_dir;
    let archive = stage.join("archive-v.ts");
    let partial_len = std::fs::metadata(&archive)
        .unwrap_or_else(|e| panic!("meta: {e}"))
        .len();
    let expected_partial: u64 = (0..4u64)
        .map(|i| segment_body(&format!("/aseg{i}.ts")).len() as u64)
        .sum();
    assert_eq!(
        partial_len, expected_partial,
        "partial archive == 4 segments"
    );
    drop(ledger);
    join.await.ok();

    // Ledger prefix: 4 bits, all six rows persisted (plan-time write).
    let (ledger2, join2) = rig.ledger().await;
    let all = ledger2
        .handle
        .load_media_tracks("8000000000000091")
        .await
        .unwrap_or_else(|e| panic!("load: {e}"));
    let (t, segs) = &all[0];
    assert_eq!(t.seg_bitmap.clone().unwrap_or_default(), vec![0b0000_1111]);
    assert_eq!(segs.len(), 6, "all six rows persisted (plan-time write)");

    // Crash emulation: junk tail beyond the ledger boundary.
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&archive)
            .unwrap_or_else(|e| panic!("append: {e}"));
        f.write_all(b"JUNKTAIL")
            .unwrap_or_else(|e| panic!("junk: {e}"));
    }

    // Recovery invariant on reload: the archive is truncated back to
    // the last complete segment boundary (the 4-segment prefix), then
    // only the two missing segments are fetched. The transient server
    // fault is gone (the gate clears before the retry).
    rig.state
        .fail_paths
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    {
        let seg_hits = rig
            .state
            .seg_hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let report = rig
            .download()
            .run(&manifest, &ledger2)
            .await
            .unwrap_or_else(|e| panic!("run2: {e}"));
        assert!(
            matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
            "run2 verdict: {:?}",
            report.verdict
        );
        let after = rig
            .state
            .seg_hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(
            after - seg_hits,
            2,
            "only the two missing segments re-fetched ({seg_hits} before, {after} after)"
        );
        // Archive repaired to the full six-segment concatenation.
        let expect: Vec<u8> = (0..6u64)
            .flat_map(|i| segment_body(&format!("/aseg{i}.ts")))
            .collect();
        assert_eq!(
            std::fs::read(&archive).unwrap_or_else(|e| panic!("read: {e}")),
            expect,
            "junk tail truncated at the boundary, then completed"
        );
    }
    drop(ledger2);
    join2.await.ok();
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// Sidecar degradation: every subtitle segment 500s → the set
/// completes degraded with the warning payload recorded; video/audio
/// archives land normally.
/// Acceptance-① invariant in the **resume** form (review round-2
/// regression): a (b)-layer track that fails mid-run and resumes to
/// completion must persist ledger rows with Σseg_len == archive
/// length and no zero-length rows in the delivered set — and the
/// completed archive must survive the next reconcile untouched (zero
/// segments re-fetched). The pre-fix sink lost the resumed prefix's
/// ledger lengths (Σseg_len collapsed to this-run bytes only), and
/// the zeroed prefix rows then demoted the full bitmap to
/// keep_count=0 — truncating the completed archive and re-fetching
/// every segment despite the full-done bitmap.
#[tokio::test]
async fn resumed_track_ledger_matches_archive() {
    let rig = rig("resumelens").await;
    let manifest = format!("http://{}/audio.m3u8", rig.addr);
    rig.state.fail("/aseg4.ts");
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run1: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Failed { .. }),
        "run1 verdict: {:?}",
        report.verdict
    );
    drop(ledger);
    join.await.ok();
    rig.state
        .fail_paths
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();

    // Run 2: the failure is gone — resume completes the track.
    let (ledger2, join2) = rig.ledger().await;
    let report = rig
        .download()
        .run(&manifest, &ledger2)
        .await
        .unwrap_or_else(|e| panic!("run2: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "run2 verdict: {:?}",
        report.verdict
    );
    let stage = &report.staging_dir;
    let archive = stage.join("archive-v.ts");
    drop(ledger2);
    join2.await.ok();

    // After resume Σseg_len == archive length, and no zero-length rows anywhere
    // in the delivered set (the resumed prefix keeps its lengths).
    let (ledger3, join3) = rig.ledger().await;
    let all = ledger3
        .handle
        .load_media_tracks("8000000000000091")
        .await
        .unwrap_or_else(|e| panic!("load: {e}"));
    drop(ledger3);
    join3.await.ok();
    let (t, segs) = all.first().unwrap_or_else(|| panic!("one track row set"));
    assert_eq!(t.seg_bitmap.clone().unwrap_or_default(), vec![0b0011_1111]);
    let lens: Vec<i64> = segs.iter().map(|s| s.seg_len).collect();
    assert!(
        lens.iter().all(|l| *l > 0),
        "no zero-length rows in a completed track: {lens:?}"
    );
    let sum: i64 = lens.iter().sum();
    let archive_len = std::fs::metadata(&archive)
        .unwrap_or_else(|e| panic!("meta: {e}"))
        .len();
    assert_eq!(sum as u64, archive_len, "Σseg_len == archive length");

    // Run 3: the completed track is idempotent — reconcile must not
    // truncate the archive nor re-fetch anything (the pre-fix
    // zero-prefix rows forced a full 6/6 re-fetch here).
    let hits_before = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let (ledger4, join4) = rig.ledger().await;
    let report = rig
        .download()
        .run(&manifest, &ledger4)
        .await
        .unwrap_or_else(|e| panic!("run3: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "run3 verdict: {:?}",
        report.verdict
    );
    drop(ledger4);
    join4.await.ok();
    let hits_after = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    assert_eq!(
        hits_after - hits_before,
        0,
        "completed archive not truncated/re-fetched by reconcile"
    );
    let expect: Vec<u8> = (0..6u64)
        .flat_map(|i| segment_body(&format!("/aseg{i}.ts")))
        .collect();
    assert_eq!(
        std::fs::read(&archive).unwrap_or_else(|e| panic!("read: {e}")),
        expect,
        "archive bytes untouched by the idempotent re-run"
    );
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

#[tokio::test]
async fn sidecar_failure_degrades_to_completion() {
    let rig = rig("sidecar").await;
    for p in ["/svtt0.vtt", "/svtt1.vtt", "/svtt2.vtt"] {
        rig.state.fail(p);
    }
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    match report.verdict {
        TrackSetVerdict::Complete { degraded } => {
            assert_eq!(degraded.len(), 1);
            assert_eq!(degraded[0].0, "s0");
            assert!(
                !degraded[0].1.is_empty(),
                "warning carries the failure text: {:?}",
                degraded[0].1
            );
        }
        other => panic!("expected degraded Complete, got {other:?}"),
    }
    // Video/audio archives landed; the sidecar's partial archive
    // stays (staging retention until the session cleanup).
    let stage = &report.staging_dir;
    assert!(stage.join("archive-v.m4s").is_file());
    assert!(stage.join("archive-a.ts").is_file());
    drop(ledger);
    join.await.ok();
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// Required-track failure: the variant playlist is unreachable → the
/// set fails fast and the verdict names the required label.
#[tokio::test]
async fn required_track_failure_fails_set() {
    let rig = rig("required").await;
    // A dedicated mock whose master names a dead variant URI.
    let app = Router::new()
        .route(
            "/master.m3u8",
            get(|| async {
                full_body(
                    "#EXTM3U\n\
                     #EXT-X-STREAM-INF:BANDWIDTH=1\n\
                     http://127.0.0.1:1/dead.m3u8\n"
                        .to_string()
                        .into_bytes(),
                )
            }),
        )
        .with_state(rig.state.clone());
    let addr = spawn_with(|_| app).await;
    let (ledger, join) = rig.ledger().await;
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let dl = MediaDownload::new(
        "8000000000000091",
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: rig.out_dir.clone(),
            allow_private_key_url: true,
            ..MediaDownloadConfig::default()
        },
    );
    let report = dl
        .run(&format!("http://{addr}/master.m3u8"), &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    match report.verdict {
        TrackSetVerdict::Failed { required, error } => {
            assert_eq!(required, "v");
            assert!(!error.is_empty());
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    drop(ledger);
    join.await.ok();
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// Origin-hole regression (recovery invariant, no-ledger form): the
/// staging tree survives but the ledger rows are gone — the re-run
/// must truncate the stale archive to zero and re-download, never
/// append after the old bytes (the pre-fix shape doubled the archive
/// while the run still reported Done: Σseg_len = half the file).
#[tokio::test]
async fn ledger_loss_rerun_does_not_duplicate_archive() {
    let rig = rig("ledgerloss").await;
    // Direct media playlist entry — the (b)-layer append path.
    let manifest = format!("http://{}/audio.m3u8", rig.addr);
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run1: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "run1 verdict: {:?}",
        report.verdict
    );
    drop(ledger);
    join.await.ok();

    let stage = &report.staging_dir;
    let archive = stage.join("archive-v.ts");
    let expect: Vec<u8> = (0..6u64)
        .flat_map(|i| segment_body(&format!("/aseg{i}.ts")))
        .collect();
    assert_eq!(
        std::fs::read(&archive).unwrap_or_else(|e| panic!("read1: {e}")),
        expect
    );

    // Ledger lost: a fresh empty database over the surviving staging
    // tree (load_track -> None -> resume=None on a non-empty archive).
    let db2_dir = tempdir("ledgerloss-db2");
    let (handle2, join2) = PersistWriter::spawn(db2_dir.join("taiji.sqlite3"))
        .await
        .unwrap_or_else(|e| panic!("writer2 spawn: {e}"));
    let ledger2 = StoreLedger { handle: handle2 };
    let seg_hits_before = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let report = rig
        .download()
        .run(&manifest, &ledger2)
        .await
        .unwrap_or_else(|e| panic!("run2: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "run2 verdict: {:?}",
        report.verdict
    );
    drop(ledger2);
    join2.await.ok();

    // The archive holds exactly one copy: no duplication.
    assert_eq!(
        std::fs::read(&archive).unwrap_or_else(|e| panic!("read2: {e}")),
        expect,
        "stale bytes truncated, not appended after (no 2x archive)"
    );
    // Wire: nothing was provable without the ledger — all six segments
    // re-fetched (the honest cost of the zero-bitmap boundary).
    let after = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    assert_eq!(after - seg_hits_before, 6);

    // Ledger of the re-run is self-consistent: Σseg_len == archive
    // length (the invariant the pre-fix doubling violated).
    let (h3, join3) = PersistWriter::spawn(db2_dir.join("taiji.sqlite3"))
        .await
        .unwrap_or_else(|e| panic!("writer3 spawn: {e}"));
    let all = h3
        .load_media_tracks("8000000000000091")
        .await
        .unwrap_or_else(|e| panic!("load: {e}"));
    drop(h3);
    join3.await.ok();
    let (_, segs) = all.first().unwrap_or_else(|| panic!("one track row set"));
    let sum: i64 = segs.iter().map(|s| s.seg_len).sum();
    assert_eq!(
        sum as u64,
        std::fs::metadata(&archive)
            .unwrap_or_else(|e| panic!("meta: {e}"))
            .len(),
        "Σseg_len == archive length after the no-ledger rerun"
    );
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
    let _ = std::fs::remove_dir_all(&db2_dir);
}

/// Staging-quota watermark violation is a **task error**: the
/// deterministic track-boundary recheck fires `Err` out of
/// `run` with `taiji.media.staging_quota_exceeded` — never a silently
/// swallowed track state. The completed first track's ledger row is
/// durable (resumable); later tracks never start.
#[tokio::test]
async fn watermark_violation_fails_the_task() {
    let rig = rig("quota").await;
    let (ledger, join) = rig.ledger().await;
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    // Degenerate quota (0 GiB): admission passes on the empty staging
    // root (usage 0), any staged byte then violates at the first track
    // boundary — the deterministic trigger for the watermark error
    // path (the flag-based 30s sampler needs no clock tricks here).
    let dl = MediaDownload::new(
        "8000000000000091",
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: rig.out_dir.clone(),
            staging_quota_gib: 0,
            allow_private_key_url: true,
            ..MediaDownloadConfig::default()
        },
    );
    let err = dl
        .run(&rig.manifest_url(), &ledger)
        .await
        .err()
        .unwrap_or_else(|| panic!("quota run must fail with Err"));
    assert_eq!(err.code(), "taiji.media.staging_quota_exceeded");

    // The first (required, video) track completed and persisted; the
    // later tracks never ran.
    let staging_root = rig.out_dir.join(".taiji-b");
    let gid_dir = staging_root.join("8000000000000091");
    assert!(
        gid_dir.join("archive-v.m4s").is_file(),
        "video prefix durable for resume"
    );
    assert!(
        !gid_dir.join("archive-a.ts").is_file(),
        "audio never started after the violation"
    );
    drop(ledger);
    join.await.ok();
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// Out-of-order write-back window anchor (media-side copy of the
/// base's named constants) plus the quota/watermark anchors.
#[test]
fn lookahead_anchor_constants_media_side() {
    assert_eq!(
        taiji_http::sequence::LOOKAHEAD_SEGMENTS_PER_WORKER,
        8,
        "concurrency x 8-segment lookahead window anchor"
    );
    assert_eq!(
        taiji_http::sequence::LOOKAHEAD_BUFFER_CAP_BYTES,
        32 * 1024 * 1024,
        "32MiB buffer cap anchor"
    );
    assert_eq!(taiji_http::sequence::lookahead_segments(8), 64);
    assert_eq!(taiji_media::options::DEFAULT_STAGING_QUOTA_GIB, 50);
    assert_eq!(
        taiji_media::staging::WATERMARK_INTERVAL,
        std::time::Duration::from_secs(30)
    );
    // Unused-import guard for the dev faces this file carries.
    let _ = Bytes::new();
}
