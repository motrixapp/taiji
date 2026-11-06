//! Synthesis acceptance e2e: mock three-track HLS (encrypted fMP4 video
//! (a)-layer with 2 MAPs + DISCONTINUITY + data:-URI AES key /
//! independent audio (b)-layer / VTT subtitle sidecar) → the download
//! line → per-track rewrite (the golden contract: plaintext form, init refs, archive
//! BYTERANGE spans) → native synthesis (Processing) → box-probe +
//! ffprobe dual-run (Verifying) → product + `.vtt`; then the
//! negative faces: disk precheck, both-channels terminal + idempotent
//! re-run, ffmpeg-missing zero-traffic, subtitle-sidecar degradation,
//! and the ffmpeg fallback channel (real-machine, runtime-guarded).
//!
//! Programmatic drive (no RPC — the integration-test precedent; the
//! session mounts the same faces). Real sqlite ledger (the store side of the
//! media_track/media_segment write faces).

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aes::cipher::{BlockEncryptMut as _, KeyIvInit as _, block_padding::Pkcs7};
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use common::*;
use futures::future::BoxFuture;
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::bmff;
use taiji_media::ffmpegmux::FfmpegRuntime;
use taiji_media::keys::KeyRecord;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::probe::{self, ExpectedTrack};
use taiji_media::synth::{self, MuxerPreference, OutputFormat, Phase, SynthesisConfig, TrackInput};
use taiji_media::trackdl::{MediaLedger, MediaTaskRecord, SegmentRecord, TrackRecord};
use taiji_media::vtt;
use taiji_media::{MediaError, TrackSetVerdict};

// ---------------------------------------------------------------------------
// crypto helpers (the fixture pre-encrypts; the decrypt layer consumes on the wire)
// ---------------------------------------------------------------------------

type Enc = cbc::Encryptor<aes::Aes128>;
const KEY: [u8; 16] = *b"0123456789abcdef";
const IV: [u8; 16] = {
    let mut iv = [0u8; 16];
    iv[15] = 1;
    iv
};

fn encrypt(plain: &[u8]) -> Vec<u8> {
    Enc::new(&KEY.into(), &IV.into()).encrypt_padded_vec_mut::<Pkcs7>(plain)
}

fn b64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------------------
// mock source
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MockState {
    /// Total GET hits on any route (the zero-traffic assertion face).
    hits: Arc<AtomicU64>,
}

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

async fn spawn_with(build: impl FnOnce(SocketAddr) -> Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let app = build(addr);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

/// The whole fixture: video (encrypted, 2 MAPs + DISCONTINUITY +
/// non-zero media sequence, (a)-layer BYTERANGE), audio ((b)-layer
/// whole-resource), subtitle sidecar.
struct Fixture {
    blob: Vec<u8>,
    init0_cipher: Vec<u8>,
    init1_cipher: Vec<u8>,
    audio_segments: Vec<Vec<u8>>,
    master: String,
    video: String,
    audio_pl: String,
    sub_pl: String,
}

fn build_fixture(addr: &SocketAddr) -> Fixture {
    // Video: 2 MAP regions × 3 segments × 3 samples.
    let vspec = video_init_spec();
    let init0 = build_init(&vspec);
    let init1 = build_init(&vspec); // same shape (native-eligible multi-MAP)
    let mut blob = Vec::new();
    let mut spans = Vec::new();
    let mut seg_no = 0u32;
    let mut decode_time = 0u64;
    let mut video_segments = Vec::new();
    for _region in 0..2 {
        for _s in 0..3 {
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
            let seg = build_segment(1, seg_no, decode_time, &samples, &payload);
            let cipher = encrypt(&seg);
            spans.push((blob.len() as u64, cipher.len() as u64));
            blob.extend_from_slice(&cipher);
            decode_time += 99;
            seg_no += 1;
            video_segments.push(seg);
        }
    }
    let init0_cipher = encrypt(&init0);
    let init1_cipher = encrypt(&init1);
    // Video playlist: KEY before the MAPs (both inits encrypted), data:
    // URI key with explicit IV.
    let key_uri = format!("data:application/octet-stream;base64,{}", b64(&KEY));
    let mut video = String::from("#EXTM3U\n");
    video.push_str("#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n");
    video.push_str("#EXT-X-MEDIA-SEQUENCE:500\n");
    video.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"{key_uri}\",IV=0x{}\n",
        hex(&IV)
    ));
    video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/init0.mp4\"\n"));
    for (i, (off, len)) in spans.iter().enumerate().take(3) {
        video.push_str(&format!(
            "#EXTINF:0.099,\n#EXT-X-BYTERANGE:{len}@{off}\nhttp://{addr}/blob.bin\n"
        ));
        let _ = i;
    }
    video.push_str("#EXT-X-DISCONTINUITY\n");
    video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/init1.mp4\"\n"));
    for (off, len) in spans.iter().skip(3) {
        video.push_str(&format!(
            "#EXTINF:0.099,\n#EXT-X-BYTERANGE:{len}@{off}\nhttp://{addr}/blob.bin\n"
        ));
    }
    video.push_str("#EXT-X-ENDLIST\n");

    // Audio: 4 whole-resource fMP4 segments.
    let aspec = audio_init_spec();
    let audio_init = build_init(&aspec);
    let mut audio_segments = Vec::new();
    let mut adt = 0u64;
    for seq in 0..4u32 {
        let samples: Vec<FixtureSample> = (0..4)
            .map(|_| FixtureSample {
                duration: 1024,
                size: 320,
                sync: true,
                cts: 0,
            })
            .collect();
        let payload: Vec<u8> = samples
            .iter()
            .enumerate()
            .flat_map(|(i, s)| sample_bytes(40 + seq as u8 + i as u8, s.size as usize))
            .collect();
        audio_segments.push(build_segment(1, seq, adt, &samples, &payload));
        adt += 4096;
    }
    // The audio track's own init section (fMP4) rides as its MAP.
    let mut audio_pl =
        String::from("#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:9000\n");
    audio_pl.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/ainit.mp4\"\n"));
    for i in 0..4u32 {
        audio_pl.push_str(&format!("#EXTINF:0.0928,\nhttp://{addr}/aseg{i}.m4s\n"));
    }
    audio_pl.push_str("#EXT-X-ENDLIST\n");

    // Subtitles: 3 VTT segments.
    let mut sub_pl = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
    for i in 0..3u32 {
        sub_pl.push_str(&format!("#EXTINF:2.0,\nhttp://{addr}/svtt{i}.vtt\n"));
    }
    sub_pl.push_str("#EXT-X-ENDLIST\n");

    let master = format!(
        "#EXTM3U\n\
         #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en\",NAME=\"EN\",DEFAULT=YES,URI=\"http://{addr}/audio.m3u8\"\n\
         #EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"sub\",LANGUAGE=\"en\",NAME=\"EN\",URI=\"http://{addr}/sub.m3u8\"\n\
         #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,AUDIO=\"aud\",SUBTITLES=\"sub\"\n\
         http://{addr}/v720.m3u8\n"
    );
    let _ = &audio_init;
    let _ = &spans;
    Fixture {
        blob,
        init0_cipher,
        init1_cipher,
        audio_segments,
        master,
        video,
        audio_pl,
        sub_pl,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The BYTERANGE resource: 206 + Content-Range echo on Range requests
/// (the (a)-layer range transport contract), 200 otherwise.
fn blob_route(blob: Vec<u8>, range: &str) -> Response {
    let spec = range.trim().strip_prefix("bytes=").unwrap_or("");
    let (start, end_incl) = match spec.split_once('-') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() => (
            a.parse().unwrap_or(0),
            b.parse::<u64>()
                .unwrap_or(u64::MAX)
                .min(blob.len() as u64 - 1),
        ),
        Some((a, _)) if !a.is_empty() => (a.parse().unwrap_or(0), blob.len() as u64 - 1),
        _ => return full_body(blob, "video/mp4"),
    };
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

fn build_router(addr: SocketAddr, st: MockState, subs: Vec<Vec<u8>>) -> Router {
    let fx = build_fixture(&addr);
    let master = fx.master.clone().into_bytes();
    let video = fx.video.clone().into_bytes();
    let audio_pl = fx.audio_pl.clone().into_bytes();
    let sub_pl = fx.sub_pl.clone().into_bytes();
    let blob = fx.blob.clone();
    let init0 = fx.init0_cipher.clone();
    let init1 = fx.init1_cipher.clone();
    let aseg: Vec<Vec<u8>> = fx.audio_segments.clone();
    let ainit = build_init(&audio_init_spec());
    let state = st.clone();
    let sub_state = st.clone();
    let hit = move |st: &MockState| st.hits.fetch_add(1, Ordering::SeqCst);
    let mut routes = Router::new()
        .route(
            "/master.m3u8",
            get(move || async move { full_body(master.clone(), "application/vnd.apple.mpegurl") }),
        )
        .route(
            "/v720.m3u8",
            get(move || async move { full_body(video.clone(), "application/vnd.apple.mpegurl") }),
        )
        .route(
            "/audio.m3u8",
            get(
                move || async move { full_body(audio_pl.clone(), "application/vnd.apple.mpegurl") },
            ),
        )
        .route(
            "/sub.m3u8",
            get(move || async move { full_body(sub_pl.clone(), "application/vnd.apple.mpegurl") }),
        )
        .route(
            "/blob.bin",
            get(move |req: Request| async move {
                let range = req
                    .headers()
                    .get(header::RANGE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                blob_route(blob.clone(), &range)
            }),
        )
        .route(
            "/init0.mp4",
            get(move || async move { full_body(init0.clone(), "video/mp4") }),
        )
        .route(
            "/init1.mp4",
            get(move || async move { full_body(init1.clone(), "video/mp4") }),
        )
        .route(
            "/ainit.mp4",
            get(move || async move { full_body(ainit.clone(), "video/mp4") }),
        );
    for (i, seg) in aseg.iter().enumerate() {
        let seg = seg.clone();
        let st2 = st.clone();
        routes = routes.route(
            &format!("/aseg{i}.m4s"),
            get(move || {
                let st3 = st2.clone();
                async move {
                    let _ = hit(&st3);
                    full_body(seg.clone(), "video/mp4")
                }
            }),
        );
    }
    for (i, body) in subs.iter().enumerate() {
        let body = body.clone();
        let st2 = sub_state.clone();
        routes = routes.route(
            &format!("/svtt{i}.vtt"),
            get(move || {
                let st3 = st2.clone();
                async move {
                    let _ = hit(&st3);
                    full_body(body.clone(), "text/vtt")
                }
            }),
        );
    }
    routes.with_state(state)
}

fn good_subs() -> Vec<Vec<u8>> {
    vec![
        b"WEBVTT\n\n00:00:00.000 --> 00:00:01.500\nfirst cue\n".to_vec(),
        b"WEBVTT\n\n00:00:00.200 --> 00:00:01.800\nsecond cue\n".to_vec(),
        b"WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nthird cue\n".to_vec(),
    ]
}

// ---------------------------------------------------------------------------
// store-backed ledger adapter (the download e2e adapter)
// ---------------------------------------------------------------------------

use taiji_store::persist::writer::{
    MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow, PersistWriter,
};

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
    let path = std::env::temp_dir().join(format!("taiji-e2e-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

async fn rig(tag: &str, subs: Vec<Vec<u8>>) -> Rig {
    let state = MockState::default();
    let st = state.clone();
    let addr = spawn_with(move |a| build_router(a, st, subs)).await;
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
            "8000000000000093",
            client,
            RequestCtx::default(),
            MediaDownloadConfig {
                output_dir: self.out_dir.clone(),
                // The mock source lives on loopback — the SSRF
                // default-deny would refuse its URLs; the lab runs
                // with the allow flag (the mock-lab precedent).
                allow_private_key_url: true,
                ..MediaDownloadConfig::default()
            },
        )
    }

    fn manifest_url(&self) -> String {
        format!("http://{}/master.m3u8", self.addr)
    }

    fn staging_dir(&self) -> PathBuf {
        self.out_dir.join(".taiji-b").join("8000000000000093")
    }

    /// Build the synthesis inputs from the downloaded report + ledger
    /// (the session orchestration's bridge shape).
    async fn track_inputs(&self, ledger: &StoreLedger) -> Vec<TrackInput> {
        let mut inputs = Vec::new();
        // (track_idx, label, kind, playlist path on the mock)
        for (idx, label, kind, path) in [
            (0usize, "v", "video", "/v720.m3u8"),
            (1, "a", "audio", "/audio.m3u8"),
            (2, "s0", "subtitle", "/sub.m3u8"),
        ] {
            let text = reqwest_blocking_get(&format!("http://{}{path}", self.addr)).await;
            let playlist = match taiji_media::parse_manifest(text.as_bytes())
                .unwrap_or_else(|e| panic!("parse {path}: {e}"))
            {
                taiji_media::Playlist::Media(m) => m,
                other => panic!("{other:?}"),
            };
            let (track, segments) = ledger
                .load_track("8000000000000093", idx)
                .await
                .unwrap_or_else(|e| panic!("load: {e}"))
                .unwrap_or_else(|| panic!("track {idx} missing"));
            let archive = self.staging_dir().join(&track.local_name);
            let inits: Vec<PathBuf> = track
                .init_files
                .iter()
                .map(|n| self.staging_dir().join(n))
                .collect();
            inputs.push(TrackInput {
                label: label.to_string(),
                kind: kind.to_string(),
                archive,
                inits,
                segments,
                playlist,
                archive_name: track.local_name.clone(),
            });
        }
        inputs
    }
}

async fn reqwest_blocking_get(url: &str) -> String {
    // The mock is still serving; a plain TCP GET via the base client.
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
    let followed = client
        .get(url, &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut body = Vec::new();
    let mut resp = followed.response;
    while let Some(chunk) = resp.chunk().await.unwrap_or_else(|e| panic!("{e}")) {
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).unwrap_or_else(|e| panic!("{e}"))
}

/// The lenient local ffmpeg runtime for the e2e's real-machine legs
/// (discovery + `-version` parse; the license gate is a
/// production posture — the dev machine's Homebrew ffmpeg carries
/// `--enable-gpl`, the recorded e2e_real fixture fact — and would
/// refuse the pair under `gate` strictness).
async fn local_ffmpeg() -> Option<FfmpegRuntime> {
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
    Some(FfmpegRuntime {
        pair,
        version,
        shim_program: Some(PathBuf::from(env!("CARGO_BIN_EXE_taiji-media-shim"))),
    })
}

fn base_cfg(rig: &Rig, ffmpeg: Option<FfmpegRuntime>) -> SynthesisConfig {
    SynthesisConfig {
        phase_sink: None,
        format: OutputFormat::Mp4,
        muxer: MuxerPreference::Auto,
        output: rig.out_dir.join("out.mp4"),
        staging_dir: rig.staging_dir(),
        ffmpeg,
        embed_subtitles: false,
        meta: taiji_media::mp4write::MovieMeta::default(),
        free_bytes_override: Some(None), // optimistic (pure logic)
    }
}

// ---------------------------------------------------------------------------
// ① the golden path: download → rewrite golden → native synthesis →
// probe + dual-run → product + sidecar
// ---------------------------------------------------------------------------

#[tokio::test]
async fn synth_golden_path_native() {
    let rig = rig("gold", good_subs()).await;
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));
    assert_eq!(
        report.verdict,
        TrackSetVerdict::Complete { degraded: vec![] },
        "three tracks land"
    );

    // --- native synthesis ---
    let inputs = rig.track_inputs(&ledger).await;
    let ffmpeg = local_ffmpeg().await;
    let cfg = base_cfg(&rig, ffmpeg.clone());
    let tok = tokio_util::sync::CancellationToken::new();
    let synth_report = synth::run_synthesis(&inputs, &cfg, tok)
        .await
        .unwrap_or_else(|e| panic!("synthesis: {e}"));
    assert_eq!(synth_report.channel_used, "native");

    // --- rewrite golden (field by field) ---
    let staging = rig.staging_dir();
    let local_v = staging.join("local-v.m3u8");
    assert!(local_v.is_file(), "the rewrite product exists");
    let text = std::fs::read_to_string(&local_v).unwrap_or_else(|e| panic!("{e}"));
    assert!(text.starts_with("#EXTM3U\n"));
    assert!(text.contains("#EXT-X-VERSION:7\n"));
    assert!(text.contains("#EXT-X-MEDIA-SEQUENCE:500\n"));
    assert!(
        !text.contains("EXT-X-KEY") && !text.contains("METHOD=NONE"),
        "encrypted track rewrites to the plaintext form: {text}"
    );
    assert!(text.contains("#EXT-X-MAP:URI=\"init-v-0.mp4\"\n"));
    assert!(text.contains("#EXT-X-MAP:URI=\"init-v-1.mp4\"\n"));
    assert!(text.contains("#EXT-X-DISCONTINUITY\n"));
    assert!(text.trim_end().ends_with("#EXT-X-ENDLIST"));
    // The BYTERANGE spans address the decrypted archive with
    // plaintext lengths (ledger rows): first span @0, per-segment
    // lengths from the ledger.
    let (_v_track, v_segments) = ledger
        .load_track("8000000000000093", 0)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("video track"));
    let mut off = 0u64;
    for seg in &v_segments {
        assert!(
            text.contains(&format!(
                "#EXT-X-BYTERANGE:{}@{}\narchive-v.m4s",
                seg.seg_len, off
            )),
            "span {off}+{} present",
            seg.seg_len
        );
        off += seg.seg_len;
    }
    let archive_len = std::fs::metadata(staging.join("archive-v.m4s"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert_eq!(archive_len, off, "Σ plaintext seg_len == archive length");
    // source.m3u8 untouched: still the raw master archive (the
    // download face; the encrypted per-track playlist lives on the mock).
    let source =
        std::fs::read_to_string(staging.join("source.m3u8")).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        source.contains("EXT-X-STREAM-INF"),
        "raw master archive intact"
    );

    assert_eq!(
        synth_report.phases,
        vec![
            Phase::Processing { channel: "native" },
            Phase::Verifying,
            Phase::Done,
        ]
    );
    let product = &synth_report.product;
    assert!(product.is_file(), "renamed product in place");
    assert!(!cfg.part_path().exists(), "no leftover .part");

    // --- independent probe asserts (re-run in the test) ---
    let bytes = std::fs::read(product).unwrap_or_else(|e| panic!("{e}"));
    let init_bytes = std::fs::read(staging.join("init-v-0.mp4")).unwrap_or_else(|e| panic!("{e}"));
    let desc = bmff::parse_init(&init_bytes).unwrap_or_else(|e| panic!("{e}"));
    let archive_bytes =
        std::fs::read(staging.join("archive-v.m4s")).unwrap_or_else(|e| panic!("{e}"));
    let v_rewrite = synth_report
        .rewrites
        .iter()
        .find(|rw| rw.label == "v")
        .unwrap_or_else(|| panic!("video rewrite present"));
    let v_spans: Vec<bmff::SegmentSpan> = v_rewrite
        .entries
        .iter()
        .map(|e| bmff::SegmentSpan {
            archive_offset: e.archive_offset,
            archive_len: e.archive_len,
        })
        .collect();
    let fold =
        bmff::fold_track(&init_bytes, &archive_bytes, &v_spans).unwrap_or_else(|e| panic!("{e}"));
    let expects = vec![
        ExpectedTrack {
            handler: *b"vide",
            timescale: fold.timescale,
            stsd_entry: desc.stsd_entries[0].bytes.clone(),
            sample_count: fold.samples.len(),
        },
        ExpectedTrack {
            handler: *b"soun",
            timescale: 44_100,
            stsd_entry: {
                let ainit =
                    std::fs::read(staging.join("init-a-0.mp4")).unwrap_or_else(|e| panic!("{e}"));
                bmff::parse_init(&ainit)
                    .unwrap_or_else(|e| panic!("{e}"))
                    .stsd_entries[0]
                    .bytes
                    .clone()
            },
            sample_count: 16,
        },
    ];
    let expected_ms = v_segments.iter().map(|s| s.duration_ms).sum::<u64>();
    let preport = probe::probe_product(
        &bytes,
        &expects,
        expected_ms,
        &taiji_media::ExpectedMeta::default(),
    );
    assert!(preport.ok(), "probe violations: {:?}", preport.violations);

    // --- VTT sidecar: 3 cues, timeline continuity ---
    let sidecar = synth_report
        .sidecar
        .as_ref()
        .unwrap_or_else(|| panic!("sidecar"));
    let path = sidecar
        .as_ref()
        .unwrap_or_else(|e| panic!("sidecar degraded: {e}"));
    let vtt_text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{e}"));
    let cues = vtt::parse_vtt(&vtt_text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cues.len(), 3);
    // Segment 2 starts at 2000 ms (Σ EXTINF), its cue at +0.2 → 2200.
    assert_eq!(cues[0].start_ms, 0);
    assert_eq!(
        cues[1].start_ms, 2200,
        "second segment shifted onto the timeline"
    );
    assert_eq!(cues[2].start_ms, 4000);

    // --- ffprobe dual-run (when the fallback face is present) ---
    if let Some(rt) = &ffmpeg {
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
            "ffprobe exit: {}",
            String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(2048)])
        );
        let json = taiji_media::FfprobeReport::parse(&out.stdout).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            json.count_codec_type("video"),
            1,
            "{:?}",
            json.stream_summary()
        );
        assert_eq!(
            json.count_codec_type("audio"),
            1,
            "{:?}",
            json.stream_summary()
        );
        let d = json.duration_seconds().unwrap_or(0.0);
        assert!(
            (expected_ms as f64 / 1000.0 * 0.98..=expected_ms as f64 / 1000.0 * 1.02).contains(&d),
            "ffprobe duration {d} vs ΣEXTINF {expected_ms} ms"
        );
    } else {
        eprintln!("skipping ffprobe dual-run (no local ffmpeg)");
    }

    join.abort();
}

// ---------------------------------------------------------------------------
// ② disk precheck: insufficient refuses Processing; optimistic passes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn precheck_disk_positive_negative() {
    let rig = rig("disk", good_subs()).await;
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(report.verdict, TrackSetVerdict::Complete { .. }));
    let inputs = rig.track_inputs(&ledger).await;

    // Negative: a tiny free figure → refusal before any Processing
    // work (no .part ever created).
    let mut cfg = base_cfg(&rig, None);
    cfg.free_bytes_override = Some(Some(64));
    let err = synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
        .await
        .err()
        .unwrap_or_else(|| panic!("must refuse"));
    assert_eq!(err.code(), "taiji.media.staging");
    assert!(err.to_string().contains("disk precheck"), "{err}");
    assert!(!cfg.part_path().exists(), "no .part on precheck refusal");
    // Optimistic (unobtainable) passes.
    let mut cfg = base_cfg(&rig, None);
    cfg.free_bytes_override = Some(None);
    assert!(
        synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
            .await
            .is_ok()
    );
    // Positive: a large figure passes (== the golden-path run shape).
    let mut cfg = base_cfg(&rig, None);
    cfg.free_bytes_override = Some(Some(u64::MAX));
    assert!(
        synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
            .await
            .is_ok()
    );
    join.abort();
}

// ---------------------------------------------------------------------------
// ③ ffmpeg-missing at start (fallback-required form, zero traffic)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn precheck_ffmpeg_missing_zero_traffic() {
    let rig = rig("mkvmiss", good_subs()).await;
    let (ledger, join) = rig.ledger().await;
    // The activation-chain shape: the start precheck runs BEFORE
    // the download; a refusal means the mock serves nothing.
    let inputs_probe = {
        // Build the form statically: MKV output over the same fixture
        // shape (the verdict only reads init files, so a lightweight
        // input set is enough for the decision face).
        let dir = rig.out_dir.clone();
        let (init, archive) = build_track(&video_init_spec(), 1, 2);
        std::fs::write(dir.join("init-v-0.mp4"), &init).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(dir.join("archive-v.m4s"), &archive).unwrap_or_else(|e| panic!("{e}"));
        let playlist = match taiji_media::parse_manifest(
            format!(
                "#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:0.07,\n#EXT-X-BYTERANGE:{}@0\nx.m4s\n#EXT-X-ENDLIST\n",
                archive.len()
            )
            .as_bytes(),
        )
        .unwrap_or_else(|e| panic!("{e}"))
        {
            taiji_media::Playlist::Media(m) => m,
            other => panic!("{other:?}"),
        };
        let mut segments = taiji_media::segment_records(&playlist);
        for s in &mut segments {
            s.seg_len = archive.len() as u64;
        }
        vec![TrackInput {
            label: "v".to_string(),
            kind: "video".to_string(),
            archive: dir.join("archive-v.m4s"),
            inits: vec![dir.join("init-v-0.mp4")],
            segments,
            playlist,
            archive_name: "archive-v.m4s".to_string(),
        }]
    };
    let mut cfg = base_cfg(&rig, None);
    cfg.format = OutputFormat::Mkv;
    cfg.staging_dir = rig.out_dir.clone();
    cfg.output = rig.out_dir.join("out.mkv");

    // The start-precheck decision (the session mount's call).
    let need = synth::fallback_need(&inputs_probe, &cfg);
    match &need {
        taiji_media::FallbackNeed::Required { reason } => {
            assert!(reason.contains("MKV"), "{reason}")
        }
        other => panic!("fallback-required expected, got {other:?}"),
    }
    match taiji_media::sidecar_start_precheck(&need, false) {
        taiji_media::StartVerdict::FfmpegMissing(e) => {
            assert_eq!(e.code(), "taiji.media.ffmpeg_missing");
            assert!(e.to_string().contains("segment traffic"));
        }
        other => panic!("unexpected {other:?}"),
    }
    // Zero mock traffic: the download never started.
    assert_eq!(rig.state.hits.load(Ordering::SeqCst), 0, "no source hits");
    // The pipeline refuses identically before any synthesis work.
    let err = synth::run_synthesis(
        &inputs_probe,
        &cfg,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .err()
    .unwrap_or_else(|| panic!("must refuse"));
    assert_eq!(err.code(), "taiji.media.ffmpeg_missing");
    assert!(!cfg.part_path().exists());
    // The mock stayed untouched through the whole refusal.
    assert_eq!(
        rig.state.hits.load(Ordering::SeqCst),
        0,
        "still zero traffic"
    );
    let _ = ledger;
    join.abort();
}

// ---------------------------------------------------------------------------
// ④ both-channels terminal + idempotent re-run (staging retained)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn both_channels_failed_then_idempotent_rerun() {
    let rig = rig("bothfail", good_subs()).await;
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(report.verdict, TrackSetVerdict::Complete { .. }));
    let inputs = rig.track_inputs(&ledger).await;
    let archive_path = rig.staging_dir().join("archive-v.m4s");
    let original = std::fs::read(&archive_path).unwrap_or_else(|e| panic!("{e}"));

    // Corrupt the video archive (native fails; no ffmpeg pair → both
    // channels failed = task Error).
    let mut corrupted = original.clone();
    corrupted.truncate(corrupted.len() - 64);
    std::fs::write(&archive_path, &corrupted).unwrap_or_else(|e| panic!("{e}"));
    let cfg = base_cfg(&rig, None);
    let err = synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
        .await
        .err()
        .unwrap_or_else(|| panic!("must fail"));
    assert_eq!(err.code(), "taiji.media.staging", "compound terminal face");
    let text = err.to_string();
    assert!(text.contains("both synthesis channels failed"), "{text}");
    assert!(text.contains("native:"), "{text}");
    assert!(text.contains("staging retained"), "{text}");
    // Staging retained: archives + inits + local playlists intact.
    assert!(archive_path.is_file());
    assert!(rig.staging_dir().join("init-v-0.mp4").is_file());
    assert!(rig.staging_dir().join("local-v.m3u8").is_file());
    assert!(!cfg.part_path().exists(), "failed .part cleaned");

    // Idempotent re-run: repair the archive → the same call converges.
    std::fs::write(&archive_path, &original).unwrap_or_else(|e| panic!("{e}"));
    let ok = synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_or_else(|e| panic!("re-run must converge: {e}"));
    assert!(ok.product.is_file());
    join.abort();
}

// ---------------------------------------------------------------------------
// ⑤ subtitle-sidecar splice failure = degraded completion + warning
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subtitle_sidecar_failure_degrades() {
    let mut subs = good_subs();
    // Segment 1 serves unparseable bytes (not WebVTT).
    subs[1] = b"\x00\x01GARBAGE-not-vtt".to_vec();
    let rig = rig("subdeg", subs).await;
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { .. }),
        "bytes are bytes at the transport layer"
    );
    let inputs = rig.track_inputs(&ledger).await;
    let cfg = base_cfg(&rig, None);
    let out = synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_or_else(|e| panic!("the product must complete: {e}"));
    // Degraded sidecar + warning; never the both-channels state.
    let degraded = out
        .sidecar
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .cloned()
        .unwrap_or_else(|| panic!("sidecar must degrade, got {:?}", out.sidecar));
    assert!(degraded.contains("segment 1"), "{degraded}");
    assert!(
        out.warnings.iter().any(|w| w.contains("degraded")),
        "{:?}",
        out.warnings
    );
    assert!(out.product.is_file(), "product completes degraded");
    assert!(!cfg.part_path().exists(), "renamed, no .part residue");
    join.abort();
}

// ---------------------------------------------------------------------------
// ⑤b the two review-flagged sidecar escapes: a non-UTF-8 subtitle
// body and a truncated subtitle archive both degrade (the sidecar
// grading) — the
// product still completes; no panic, no post-rename Error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subtitle_sidecar_non_utf8_and_short_archive_degrade() {
    // (a) Non-UTF-8 segment body: 0xFF is not a valid UTF-8 start
    // byte — the whole archive fails the read, which must degrade
    // (previously this escaped as a task Error after the product
    // rename).
    let mut subs = good_subs();
    subs[1] = b"\xFF\xFE\xFA not-vtt".to_vec();
    let rig_a = rig("subutf8", subs).await;
    let (ledger, join) = rig_a.ledger().await;
    let report = rig_a
        .download()
        .run(&rig_a.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));
    assert!(matches!(report.verdict, TrackSetVerdict::Complete { .. }));
    let inputs = rig_a.track_inputs(&ledger).await;
    let cfg = base_cfg(&rig_a, None);
    let out = synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_or_else(|e| panic!("non-UTF-8 sidecar must degrade, not fail: {e}"));
    let degraded = out
        .sidecar
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .cloned()
        .unwrap_or_else(|| panic!("sidecar must degrade, got {:?}", out.sidecar));
    assert!(degraded.contains("UTF-8"), "{degraded}");
    assert!(out.product.is_file(), "the product still completes");
    assert!(!cfg.part_path().exists(), "renamed, no .part residue");
    join.abort();

    // (b) Truncated subtitle archive: the ledger spans no longer fit
    // the on-disk bytes — the bounds-checked splice degrades
    // (previously an unchecked slice panicked).
    let rig_b = rig("subshort", good_subs()).await;
    let (ledger, join) = rig_b.ledger().await;
    let report = rig_b
        .download()
        .run(&rig_b.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));
    assert!(matches!(report.verdict, TrackSetVerdict::Complete { .. }));
    let archive_path = rig_b.staging_dir().join("archive-s0.vtt");
    let original = std::fs::read(&archive_path).unwrap_or_else(|e| panic!("{e}"));
    // Truncate inside the last segment's span (the archive holds 3
    // segment bodies).
    std::fs::write(&archive_path, &original[..original.len() - 12])
        .unwrap_or_else(|e| panic!("{e}"));
    let inputs = rig_b.track_inputs(&ledger).await;
    let cfg = base_cfg(&rig_b, None);
    let out = synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_or_else(|e| panic!("short sidecar archive must degrade, not panic: {e}"));
    let degraded = out
        .sidecar
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .cloned()
        .unwrap_or_else(|| panic!("sidecar must degrade, got {:?}", out.sidecar));
    assert!(degraded.contains("outside"), "{degraded}");
    assert!(
        out.warnings.iter().any(|w| w.contains("degraded")),
        "{:?}",
        out.warnings
    );
    assert!(out.product.is_file(), "the product still completes");
    assert!(!cfg.part_path().exists(), "renamed, no .part residue");
    join.abort();
}

// ---------------------------------------------------------------------------
// ⑥ the ffmpeg fallback channel (real machine; runtime-guarded):
// user-explicit trigger + product verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fallback_channel_user_explicit() {
    let Some(rt) = local_ffmpeg().await else {
        eprintln!("skipping (no local ffmpeg/ffprobe pair)");
        return;
    };
    let rig = rig("fallback", good_subs()).await;
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download()
        .run(&rig.manifest_url(), &ledger)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));
    assert!(matches!(report.verdict, TrackSetVerdict::Complete { .. }));
    let inputs = rig.track_inputs(&ledger).await;

    // User-explicit ffmpeg on an MP4 output (the user-explicit rule).
    let mut cfg = base_cfg(&rig, Some(rt.clone()));
    cfg.muxer = MuxerPreference::Ffmpeg;
    cfg.output = rig.out_dir.join("explicit.mp4");
    let out = synth::run_synthesis(&inputs, &cfg, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_or_else(|e| panic!("fallback run: {e}"));
    assert_eq!(out.channel_used, "ffmpeg");
    assert!(out.product.is_file());
    // The product is a real MP4 per ffprobe with the selected streams.
    let args: Vec<String> = taiji_media::probe_args(&out.product)
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let cmd = taiji_media::MediaCommand::new(taiji_media::MediaBin::Ffprobe, &rt.pair.ffprobe)
        .unwrap_or_else(|e| panic!("{e}"))
        .args(refs)
        .shim_program(rt.shim_program.clone());
    let child = cmd.spawn().unwrap_or_else(|e| panic!("{e}"));
    let probe_out = child.wait().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(probe_out.success);
    let json =
        taiji_media::FfprobeReport::parse(&probe_out.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        json.count_codec_type("video"),
        1,
        "{:?}",
        json.stream_summary()
    );
    assert_eq!(
        json.count_codec_type("audio"),
        1,
        "{:?}",
        json.stream_summary()
    );
    join.abort();
}
