//! AES-128 acceptance e2e: AES-128 mock source over a local axum
//! server with pre-encrypted fixtures, programmatic drive (no RPC),
//! real sqlite ledger.
//!
//! Acceptance faces:
//! * ② rotation e2e — ≥2 KEY rotation exactly at segment boundaries,
//!   non-zero media sequence, default/explicit IV dual forms,
//!   METHOD=NONE reset, `data:` inline key with a **zero-outbound**
//!   assertion; archive plaintext compared by bytes **and** SHA-256;
//! * media_key persistence — rows written, `media_segment.key_id`
//!   references them, staging never holds key material (outside the
//!   verbatim source manifest), restart re-fetches nothing;
//! * ④ merged transport decrypt split — wire-side ONE Range GET over
//!   16 encrypted sub-segments, decrypt-side per-sub-segment IVs, the
//!   archive holds the split-decrypted concatenation;
//! * ④ init dual forms — MAP-after-KEY encrypted / MAP-before-KEY
//!   plaintext — plus the IV chain's three forms (MAP@IV via the v8
//!   `KEY=` attribute, applicable KEY@IV, sequence fallback);
//! * ③ SSRF matrix on the wire — loopback segments refused by default
//!   with zero outbound requests, `ftp://` key refused even under the
//!   allow flag, allow-flag positives throughout (the literal/resolver
//!   matrix lives in `ssrf` unit tests);
//! * negative faces — wrong-length key bodies, decrypt failures on
//!   non-block-length ciphertexts (`segment_decrypt_failed` after the
//!   retry budget);
//! * ⑥ encrypted resume — mid-run failure leaves a plaintext prefix;
//!   the retry fetches only the tail, Σseg_len (plaintext) == archive
//!   length, the reconcile never truncates a completed archive.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures::future::BoxFuture;
use sha2::{Digest as _, Sha256};
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::decrypt::iv_from_sequence;
use taiji_media::keys::KeyRecord;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::trackdl::{
    MediaLedger, MediaTaskRecord, SegmentRecord, TrackFetchConfig, TrackRecord,
};
use taiji_media::{MediaError, TrackSetVerdict, TrackState};
use taiji_store::persist::writer::{
    MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow, PersistWriter,
};

type Enc = cbc::Encryptor<aes::Aes128>;
type Dec = cbc::Decryptor<aes::Aes128>;

fn encrypt(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    Enc::new(&(*key).into(), &(*iv).into()).encrypt_padded_vec_mut::<Pkcs7>(plain)
}

fn decrypt_raw(key: &[u8; 16], iv: &[u8; 16], cipher: &[u8]) -> Vec<u8> {
    Dec::new(&(*key).into(), &(*iv).into())
        .decrypt_padded_vec_mut::<NoPadding>(cipher)
        .unwrap_or_default()
}

fn b64(data: &[u8]) -> String {
    const TAB: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for quad in data.chunks(3) {
        let b = [
            quad[0],
            quad.get(1).copied().unwrap_or(0),
            quad.get(2).copied().unwrap_or(0),
        ];
        let n = (quad.len() * 4).div_ceil(3);
        let units = [
            b[0] >> 2,
            ((b[0] & 0x03) << 4) | (b[1] >> 4),
            ((b[1] & 0x0F) << 2) | (b[2] >> 6),
            b[2] & 0x3F,
        ];
        for (i, u) in units.iter().enumerate() {
            if i < n {
                s.push(TAB[*u as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// fixtures (all deterministic)
// ---------------------------------------------------------------------------

const K1: [u8; 16] = [0x11; 16];
const K2: [u8; 16] = [0x22; 16];
const K3: [u8; 16] = [0x33; 16];
const K4: [u8; 16] = [0x44; 16];
const IV1: [u8; 16] = [0xA1; 16];
const IV2: [u8; 16] = [0xB2; 16];
const IV4: [u8; 16] = [0xD4; 16];

fn iv_hex(iv: &[u8; 16]) -> String {
    iv.iter().map(|b| format!("{b:02x}")).collect()
}

/// Plaintext body for rotation segment `i` (0-based; length varies so
/// the pad tier differs per segment).
fn rot_plain(i: usize) -> Vec<u8> {
    let len = 700 + i * 13;
    (0..len).map(|j| (j % 251) as u8 ^ (i as u8)).collect()
}

/// The rotation playlist: seq base 700.
/// * segs 0-2 under k1@IV1 (explicit IV),
/// * segs 3-5 under k2 (default IV = own absolute sequence),
/// * seg 6 plaintext (METHOD=NONE reset),
/// * seg 7 under k3 via a `data:` URI @IV3.
fn rot_playlist(addr: &SocketAddr) -> String {
    let iv1 = iv_hex(&IV1);
    let data_key = format!("data:application/octet-stream;base64,{}", b64(&K3));
    let mut t = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:700\n");
    t.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/1\",IV=0x{iv1}\n"
    ));
    for i in 0..3 {
        t.push_str(&format!("#EXTINF:2,\nhttp://{addr}/s/rs{i}\n"));
    }
    t.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/2\"\n"
    ));
    for i in 3..6 {
        t.push_str(&format!("#EXTINF:2,\nhttp://{addr}/s/rs{i}\n"));
    }
    t.push_str("#EXT-X-KEY:METHOD=NONE\n");
    t.push_str(&format!("#EXTINF:2,\nhttp://{addr}/s/rs6\n"));
    t.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"{data_key}\",IV=0x{}\n",
        iv_hex(&[0xC3; 16])
    ));
    t.push_str(&format!("#EXTINF:2,\nhttp://{addr}/s/rs7\n"));
    t.push_str("#EXT-X-ENDLIST\n");
    t
}

/// Ciphertext served for /s/rs{i} (rotation segments).
fn rot_cipher(i: usize) -> Vec<u8> {
    match i {
        0..=2 => encrypt(&K1, &IV1, &rot_plain(i)),
        3..=5 => encrypt(&K2, &iv_from_sequence(700 + i as u64), &rot_plain(i)),
        6 => rot_plain(i),
        7 => encrypt(&K3, &[0xC3; 16], &rot_plain(i)),
        _ => Vec::new(),
    }
}

/// The merged-transport playlist (a-layer): 16 contiguous 1024-byte
/// BYTERANGE sub-segments over /eblob.bin, all under k4 with the
/// default IV (each sub-segment's own absolute sequence — seq base
/// 720).
fn merge_playlist(addr: &SocketAddr) -> String {
    let mut t = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:720\n");
    t.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/4\"\n"
    ));
    for i in 0..16u64 {
        t.push_str(&format!(
            "#EXTINF:1,\n#EXT-X-BYTERANGE:1024@{}\nhttp://{addr}/eblob.bin\n",
            i * 1024
        ));
    }
    t.push_str("#EXT-X-ENDLIST\n");
    t
}

/// 16 sub-segments × 1023-byte plaintexts (pad tier 1), each encrypted
/// with its own sequence IV.
fn merge_plains() -> Vec<Vec<u8>> {
    (0..16)
        .map(|i| {
            let len = 1023;
            (0..len)
                .map(|j| (j % 241) as u8 ^ (i as u8))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn merge_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    for (i, plain) in merge_plains().iter().enumerate() {
        blob.extend_from_slice(&encrypt(&K4, &iv_from_sequence(720 + i as u64), plain));
    }
    blob
}

/// The init-sections playlist (seq base 800): the MAP-after-KEY /
/// MAP-before-KEY dual forms + the IV chain's three forms.
fn inits_playlist(addr: &SocketAddr) -> String {
    let iv1 = iv_hex(&IV1);
    let iv2 = iv_hex(&IV2);
    let iv4 = iv_hex(&IV4);
    let mut t = String::from(
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-VERSION:8\n#EXT-X-MEDIA-SEQUENCE:800\n",
    );
    // init0: MAP before any KEY → plaintext (the MAP-before-KEY form).
    t.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/initP.mp4\"\n"));
    // init1: ambient KEY@IV (the applicable KEY's explicit IV).
    t.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/1\",IV=0x{iv1}\n"
    ));
    t.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/initK1.mp4\"\n"));
    t.push_str(&format!("#EXTINF:1,\nhttp://{addr}/s/is0\n"));
    // init2: ambient KEY@IV under k2.
    t.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/2\",IV=0x{iv2}\n"
    ));
    t.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/initK2.mp4\"\n"));
    t.push_str(&format!("#EXTINF:1,\nhttp://{addr}/s/is1\n"));
    // init3: ambient KEY without IV → sequence fallback (first
    // following segment = is2 @ seq 802).
    t.push_str(&format!(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/3\"\n"
    ));
    t.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/initSeq.mp4\"\n"));
    t.push_str(&format!("#EXTINF:1,\nhttp://{addr}/s/is2\n"));
    // init4: v8 MAP KEY= attribute (MAP@IV form) after a METHOD=NONE
    // reset — the ambient is plaintext, the init carries its own key.
    t.push_str("#EXT-X-KEY:METHOD=NONE\n");
    t.push_str(&format!(
        "#EXT-X-MAP:URI=\"http://{addr}/initV8.mp4\",KEY=\"METHOD=AES-128,URI=http://{addr}/k/1,IV=0x{iv4}\"\n"
    ));
    t.push_str(&format!("#EXTINF:1,\nhttp://{addr}/s/is3\n"));
    t.push_str("#EXT-X-ENDLIST\n");
    t
}

fn init_plain(tag: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(tag.as_bytes());
    v.extend_from_slice(&[0x5A; 40]);
    v
}

fn inits_fixture() -> Vec<(&'static str, Vec<u8>)> {
    // (path, served body)
    vec![
        ("initP.mp4", init_plain("PLAIN-INIT")),
        ("initK1.mp4", encrypt(&K1, &IV1, &init_plain("K1-INIT"))),
        ("initK2.mp4", encrypt(&K2, &IV2, &init_plain("K2-INIT"))),
        (
            "initSeq.mp4",
            encrypt(&K3, &iv_from_sequence(802), &init_plain("SEQ-INIT")),
        ),
        ("initV8.mp4", encrypt(&K1, &IV4, &init_plain("V8-INIT"))),
    ]
}

fn is_cipher(i: usize) -> Vec<u8> {
    let plain = |tag: &str| -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(tag.as_bytes());
        v.extend_from_slice(&[0x33; 60]);
        v
    };
    match i {
        0 => encrypt(&K1, &IV1, &plain("IS0")),
        1 => encrypt(&K2, &IV2, &plain("IS1")),
        2 => encrypt(&K3, &iv_from_sequence(802), &plain("IS2")),
        _ => plain("IS3"),
    }
}

// ---------------------------------------------------------------------------
// mock source
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MockState {
    key_hits: Arc<std::sync::Mutex<Vec<String>>>,
    seg_hits: Arc<std::sync::Mutex<Vec<String>>>,
    blob_hits: Arc<AtomicU64>,
    blob_ranges: Arc<std::sync::Mutex<Vec<String>>>,
    fail_paths: Arc<std::sync::Mutex<Vec<String>>>,
}

impl MockState {
    fn fail(&self, path: &str) {
        self.fail_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.to_string());
    }
    fn clear_fail(&self, path: &str) {
        self.fail_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|p| p != path);
    }
    fn key_hits(&self, path: &str) -> usize {
        self.key_hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p == &path)
            .count()
    }
    fn seg_count(&self, path: &str) -> usize {
        self.seg_hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p == &path)
            .count()
    }
}

fn body(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "video/mp2t")],
        bytes,
    )
        .into_response()
}

async fn key_route(
    State(st): State<MockState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let path = format!("/k/{name}");
    if st
        .fail_paths
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|p| p == &path)
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }
    st.key_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(path);
    let material: &[u8] = match name.as_str() {
        "1" => &K1,
        "2" => &K2,
        "3" => &K3,
        "4" => &K4,
        // Wrong-length key bodies (the key_invalid negative face).
        "15" => &[0x99; 15],
        "big" => &[0x99; 17],
        _ => &[0x00; 16],
    };
    body(material.to_vec())
}

async fn seg_route(
    State(st): State<MockState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let path = format!("/s/{name}");
    if st
        .fail_paths
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|p| p == &path)
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }
    st.seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(path);
    let bytes: Vec<u8> = if let Some(idx) = name.strip_prefix("rs") {
        rot_cipher(idx.parse::<usize>().unwrap_or(0))
    } else if let Some(idx) = name.strip_prefix("is") {
        is_cipher(idx.parse::<usize>().unwrap_or(0))
    } else if name == "nonmult" {
        // 13 bytes — not a block multiple: decrypt failure territory.
        vec![0x41; 13]
    } else if name == "plain" {
        b"PLAINSEG-BODY".to_vec()
    } else {
        name.as_bytes().to_vec()
    };
    body(bytes)
}

async fn eblob(State(st): State<MockState>, req: Request) -> Response {
    let blob = merge_blob();
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
    let spec = range.trim().strip_prefix("bytes=").unwrap_or("");
    let (start, end_incl) = match spec.split_once('-') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() => (
            a.parse::<u64>().unwrap_or(0),
            b.parse::<u64>().unwrap_or(blob.len() as u64 - 1),
        ),
        _ => (0, blob.len() as u64 - 1),
    };
    let slice = blob[start as usize..=(end_incl as usize)].to_vec();
    let mut resp = Response::new(axum::body::Body::from(slice));
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

fn build_router(addr: SocketAddr, st: MockState) -> Router {
    let rot = rot_playlist(&addr).into_bytes();
    let merge = merge_playlist(&addr).into_bytes();
    let inits = inits_playlist(&addr).into_bytes();
    let mut r = Router::new()
        .route("/rot.m3u8", get(move || async move { body(rot.clone()) }))
        .route(
            "/merge.m3u8",
            get(move || async move { body(merge.clone()) }),
        )
        .route(
            "/inits.m3u8",
            get(move || async move { body(inits.clone()) }),
        )
        .route("/k/{name}", get(key_route))
        .route("/s/{name}", get(seg_route))
        .route("/eblob.bin", get(eblob))
        // The never-fetched private key (the SSRF wire negative).
        .route("/privkey", get(|| async { body([0x77; 16].to_vec()) }));
    for (name, bytes) in inits_fixture() {
        let path = format!("/{name}");
        r = r.route(&path, get(move || async move { body(bytes.clone()) }));
    }
    r.with_state(st)
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
// store-backed ledger
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
    let path = std::env::temp_dir().join(format!(
        "taiji-media-crypto-{tag}-{}-{n}",
        std::process::id()
    ));
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

fn fast_fetch() -> TrackFetchConfig {
    TrackFetchConfig {
        concurrency: 4,
        max_tries: 2,
        retry_wait: std::time::Duration::from_millis(10),
        watermark: None,
    }
}

impl Rig {
    async fn ledger(&self) -> (StoreLedger, tokio::task::JoinHandle<()>) {
        let (handle, join) = PersistWriter::spawn(self.db_path.clone())
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
        (StoreLedger { handle }, join)
    }

    fn download(&self, allow_private: bool) -> MediaDownload {
        let client =
            HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
        MediaDownload::new(
            "8000000000000092",
            client,
            RequestCtx::default(),
            MediaDownloadConfig {
                output_dir: self.out_dir.clone(),
                fetch: fast_fetch(),
                allow_private_key_url: allow_private,
                ..MediaDownloadConfig::default()
            },
        )
    }
}

fn track_text(report: &taiji_media::MediaRunReport, want: &str) -> String {
    report
        .tracks
        .iter()
        .find(|(t, _)| t.label == want)
        .map(|(_, s)| match s {
            TrackState::Failed(text) | TrackState::Degraded(text) => text.clone(),
            TrackState::Done => String::new(),
        })
        .unwrap_or_default()
}

/// Walk one directory tree: every regular file's bytes (path → bytes).
fn tree_files(root: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(tree_files(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((path, bytes));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// ② Rotation e2e + media_key persistence + staging-no-key +
/// data:-zero-outbound + sha256 comparison; then the restart re-run
/// (fresh writer over the same DB): no key re-fetch, no segment
/// re-fetch, archive untouched.
#[tokio::test]
async fn rotation_end_to_end_and_key_persistence() {
    let rig = rig("rot").await;
    let manifest = format!("http://{}/rot.m3u8", rig.addr);
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download(true)
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "verdict: {:?}",
        report.verdict
    );
    let stage = &report.staging_dir;

    // ② The archive: the decrypted concatenation, by bytes AND sha256.
    let expect: Vec<u8> = (0..8).flat_map(rot_plain).collect();
    let archive =
        std::fs::read(stage.join("archive-v.ts")).unwrap_or_else(|e| panic!("read archive: {e}"));
    assert_eq!(archive.len(), expect.len(), "plaintext length");
    assert_eq!(
        archive, expect,
        "plaintext bytes (rotation × IV forms × NONE reset × data: key)"
    );
    assert_eq!(
        sha256_hex(&archive),
        sha256_hex(&expect),
        "sha256 digest comparison"
    );

    // data: key = zero outbound for k3 (the mock never saw /k3).
    assert_eq!(rig.state.key_hits("/k/3"), 0, "data: key never fetched");
    // Each http key fetched exactly once in this run.
    assert_eq!(rig.state.key_hits("/k/1"), 1);
    assert_eq!(rig.state.key_hits("/k/2"), 1);
    // METHOD=NONE reset face: segment 6's ciphertext-free body lands
    // verbatim (no stale-key decrypt attempted) — implicitly proven by
    // the byte equality above.

    // ⑤ media_key rows: three identities (k1@IV1, k2, k3@IV3);
    // segments reference the stable ids; NONE segment has none.
    drop(ledger);
    join.await.ok();
    let (ledger2, join2) = rig.ledger().await;
    let key_rows = ledger2
        .handle
        .load_media_keys("8000000000000092")
        .await
        .unwrap_or_else(|e| panic!("load keys: {e}"));
    assert_eq!(key_rows.len(), 3, "rotation = 3 key rows");
    let k1_id = key_rows
        .iter()
        .find(|r| r.uri.ends_with("/k/1"))
        .and_then(|r| r.id);
    let k2_id = key_rows
        .iter()
        .find(|r| r.uri.ends_with("/k/2"))
        .and_then(|r| r.id);
    assert!(k1_id.is_some() && k2_id.is_some());
    let tracks = ledger2
        .handle
        .load_media_tracks("8000000000000092")
        .await
        .unwrap_or_else(|e| panic!("load tracks: {e}"));
    let (t, segs) = tracks
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("track rows"));
    assert_eq!(segs.len(), 8);
    assert_eq!(t.seg_bitmap.clone().unwrap_or_default(), vec![0xFF]);
    // key_id wiring: 0-2 → k1, 3-5 → k2, 6 → None (reset), 7 → k3.
    for (i, seg) in segs.iter().enumerate() {
        let want = match i {
            0..=2 => k1_id,
            3..=5 => k2_id,
            6 => None,
            _ => key_rows
                .iter()
                .find(|r| r.uri.starts_with("data:"))
                .and_then(|r| r.id),
        };
        assert_eq!(seg.key_id, want, "segment {i} key reference");
    }
    // Plaintext semantics: Σseg_len == archive length; per-seg lens exact.
    let sum: i64 = segs.iter().map(|s| s.seg_len).sum();
    assert_eq!(sum as u64, archive.len() as u64, "Σseg_len == archive");
    for (i, seg) in segs.iter().enumerate() {
        assert_eq!(
            seg.seg_len as u64,
            rot_plain(i).len() as u64,
            "seg {i} plain len"
        );
    }

    // ⑤ Staging holds no key material (outside the verbatim source
    // manifest — a data: URI embeds its material there by the
    // soft-frozen archive face; the scan covers every other file).
    for (path, bytes) in tree_files(stage) {
        if path.file_name().and_then(|n| n.to_str()) == Some("source.m3u8") {
            continue;
        }
        for (name, key) in [("k1", K1), ("k2", K2)] {
            assert!(
                !bytes.windows(16).any(|w| w == key),
                "staging file {} leaks {name} material",
                path.display()
            );
        }
    }

    // Restart face: a fresh writer over the same DB re-fetches no key
    // and no segment; the archive stays byte-identical.
    let seg_total = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let report2 = rig
        .download(true)
        .run(&manifest, &ledger2)
        .await
        .unwrap_or_else(|e| panic!("rerun: {e}"));
    assert!(
        matches!(report2.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty())
    );
    drop(ledger2);
    join2.await.ok();
    assert_eq!(
        rig.state.key_hits("/k/1"),
        1,
        "no key re-fetch after restart"
    );
    assert_eq!(
        rig.state.key_hits("/k/2"),
        1,
        "no key re-fetch after restart"
    );
    let seg_total2 = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    assert_eq!(
        seg_total2 - seg_total,
        0,
        "completed encrypted track resumes with zero refetch"
    );
    assert_eq!(
        std::fs::read(stage.join("archive-v.ts")).unwrap_or_else(|e| panic!("read: {e}")),
        expect,
        "archive untouched by the idempotent rerun"
    );
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// ④ Merged-transport decrypt split: ONE Range GET on the wire; the
/// decrypt side splits at sub-segment boundaries with per-sub-segment
/// sequence IVs; the archive is the decrypted concatenation and the
/// ledger rows carry the plaintext lengths.
#[tokio::test]
async fn merged_transport_decrypt_split() {
    let rig = rig("merge").await;
    let manifest = format!("http://{}/merge.m3u8", rig.addr);
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download(true)
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "verdict: {:?}",
        report.verdict
    );

    // Wire: exactly one Range GET covering the whole 16KiB span.
    assert_eq!(
        rig.state.blob_hits.load(Ordering::SeqCst),
        1,
        "wire merge held"
    );
    let ranges = rig
        .state
        .blob_ranges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(ranges.first().map(String::as_str), Some("bytes=0-16383"));

    // Decrypt side: per-sub-segment IVs reproduce the 16 plaintexts.
    let expect: Vec<u8> = merge_plains().concat();
    let archive = std::fs::read(report.staging_dir.join("archive-v.ts"))
        .unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        archive, expect,
        "split decrypt == independent per-segment decrypts"
    );
    assert_eq!(sha256_hex(&archive), sha256_hex(&expect));

    drop(ledger);
    join.await.ok();
    let (ledger2, join2) = rig.ledger().await;
    let tracks = ledger2
        .handle
        .load_media_tracks("8000000000000092")
        .await
        .unwrap_or_else(|e| panic!("load: {e}"));
    drop(ledger2);
    join2.await.ok();
    let (_, segs) = tracks.first().cloned().unwrap_or_else(|| panic!("rows"));
    assert_eq!(segs.len(), 16);
    for (i, seg) in segs.iter().enumerate() {
        assert_eq!(seg.seg_len as u64, 1023, "sub-segment {i} plaintext len");
        assert_eq!(seg.media_sequence, Some(720 + i as i64));
    }

    // ⑥ Completed-encrypted (a)-track re-run idempotence (a review
    // regression): the decrypt pass left the archive at
    // Σplaintext (16368) ≠ the ciphertext layout total (16384) — the
    // pre-fix re-run classified the completed archive as stale
    // (Restart zeroed it, the fully-seeded grid fetched nothing, and
    // the unconditional decrypt pass then re-fetched every segment
    // slice-by-slice: 16 independent Range GETs observed, and a dead
    // source destroyed the completed track). The short circuit must
    // re-run with ZERO blob GETs, a byte-identical archive and the
    // persisted ledger lengths intact.
    let archive_path = report.staging_dir.join("archive-v.ts");
    assert_eq!(
        std::fs::metadata(&archive_path)
            .unwrap_or_else(|e| panic!("meta: {e}"))
            .len(),
        16 * 1023,
        "completed encrypted archive length = Σplaintext"
    );
    let (ledger3, join3) = rig.ledger().await;
    let report2 = rig
        .download(true)
        .run(&manifest, &ledger3)
        .await
        .unwrap_or_else(|e| panic!("rerun: {e}"));
    assert!(
        matches!(report2.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "rerun verdict: {:?}",
        report2.verdict
    );
    drop(ledger3);
    join3.await.ok();
    assert_eq!(
        rig.state.blob_hits.load(Ordering::SeqCst),
        1,
        "completed encrypted (a) track re-runs with zero blob refetch \
         (the destructive Restart+decrypt-pass path did 16)"
    );
    assert_eq!(
        std::fs::read(&archive_path).unwrap_or_else(|e| panic!("read: {e}")),
        expect,
        "archive byte-identical after the idempotent re-run"
    );
    let (ledger4, join4) = rig.ledger().await;
    let tracks2 = ledger4
        .handle
        .load_media_tracks("8000000000000092")
        .await
        .unwrap_or_else(|e| panic!("load: {e}"));
    drop(ledger4);
    join4.await.ok();
    let (t2, segs2) = tracks2.first().cloned().unwrap_or_else(|| panic!("rows"));
    assert_eq!(
        t2.seg_bitmap.clone().unwrap_or_default(),
        vec![0xFF, 0xFF],
        "full bitmap preserved"
    );
    assert!(
        segs2.iter().all(|s| s.seg_len == 1023),
        "plaintext ledger lengths preserved: {segs2:?}"
    );
    let sum: i64 = segs2.iter().map(|s| s.seg_len).sum();
    assert_eq!(
        sum as u64,
        16 * 1023,
        "Σseg_len == archive length after re-run"
    );
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// ④ Init dual forms + the IV chain's three forms: MAP-after-KEY
/// encrypted / MAP-before-KEY plaintext / v8 MAP@IV / applicable
/// KEY@IV / sequence fallback. Init staging files hold plaintext.
#[tokio::test]
async fn init_section_dual_forms_and_iv_chain() {
    let rig = rig("inits").await;
    let manifest = format!("http://{}/inits.m3u8", rig.addr);
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download(true)
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "verdict: {:?}",
        report.verdict
    );
    let stage = &report.staging_dir;
    let read =
        |name: &str| std::fs::read(stage.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    // MAP-before-KEY: plaintext init (verbatim).
    assert_eq!(read("init-v-0.mp4"), init_plain("PLAIN-INIT"));
    // Applicable KEY@IV forms.
    assert_eq!(
        read("init-v-1.mp4"),
        init_plain("K1-INIT"),
        "ambient k1@IV1"
    );
    assert_eq!(
        read("init-v-2.mp4"),
        init_plain("K2-INIT"),
        "ambient k2@IV2"
    );
    // Sequence fallback (first following segment = seq 802).
    assert_eq!(
        read("init-v-3.mp4"),
        init_plain("SEQ-INIT"),
        "seq-fallback IV"
    );
    // v8 MAP@IV form (its own KEY= attribute, IV4).
    assert_eq!(read("init-v-4.mp4"), init_plain("V8-INIT"), "v8 MAP KEY@IV");

    // The encrypted segments around the init boundaries decrypt too
    // (is2 exercises the k3 default-IV at seq 802 — the same IV the
    // fallback derives).
    let is_plain = |tag: &str| -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(tag.as_bytes());
        v.extend_from_slice(&[0x33; 60]);
        v
    };
    let archive =
        std::fs::read(stage.join("archive-v.m4s")).unwrap_or_else(|e| panic!("archive: {e}"));
    let expect: Vec<u8> = [
        is_plain("IS0"),
        is_plain("IS1"),
        is_plain("IS2"),
        is_plain("IS3"),
    ]
    .concat();
    assert_eq!(archive, expect, "segments decrypt across the boundary keys");
    drop(ledger);
    join.await.ok();
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// ③ SSRF wire matrix: loopback media-segment URLs refused by default
/// with **zero outbound requests**; `ftp://` key refused even under
/// the allow flag (the scheme layer is flag-independent); wrong-length
/// key bodies are `key_invalid`; non-block-length ciphertext surfaces
/// `segment_decrypt_failed` after the retry budget.
#[tokio::test]
async fn ssrf_wire_matrix_and_negative_faces() {
    let rig = rig("ssrf").await;
    let addr = rig.addr;

    // (1) Default-deny on the segment face: flag off, loopback
    // playlist → the track fails before any segment/key request.
    let manifest = format!("http://{addr}/rot.m3u8");
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download(false)
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    let text = track_text(&report, "v");
    assert!(
        matches!(report.verdict, TrackSetVerdict::Failed { .. }),
        "default deny fails the set"
    );
    assert!(text.contains("taiji.media.ssrf_blocked"), "text: {text}");
    assert_eq!(
        rig.state
            .seg_hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
        0,
        "zero outbound segment requests under default deny"
    );
    assert_eq!(rig.state.key_hits("/k/1"), 0, "keys never reached either");
    drop(ledger);
    join.await.ok();

    // (2) `ftp://` key under the allow flag: the scheme layer refuses
    // regardless; no segment fetch starts (keys pre-expand first).
    // The failing URI enters the error face **query-stripped** (the
    // redaction rule:
    // signed key URLs must not leak through errors).
    let ftp_manifest = {
        let mut t = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
        t.push_str(&format!(
            "#EXT-X-KEY:METHOD=AES-128,URI=\"ftp://{addr}/k/1?sig=TOPSECRET\"\n"
        ));
        t.push_str(&format!("#EXTINF:2,\nhttp://{addr}/s/plain\n"));
        t.push_str("#EXT-X-ENDLIST\n");
        t
    };
    let ftp_bytes = ftp_manifest.into_bytes();
    let app = Router::new()
        .route(
            "/ftp.m3u8",
            get(move || async move { body(ftp_bytes.clone()) }),
        )
        .route("/s/plain", get(|| async { body(b"PLAINSEG".to_vec()) }))
        .with_state(rig.state.clone());
    let addr2 = spawn_with(|_| app).await;
    let (ledger2, join2) = rig.ledger().await;
    let report = rig
        .download(true)
        .run(&format!("http://{addr2}/ftp.m3u8"), &ledger2)
        .await
        .unwrap_or_else(|e| panic!("run ftp: {e}"));
    let text = track_text(&report, "v");
    assert!(
        text.contains("taiji.media.ssrf_blocked"),
        "ftp text: {text}"
    );
    assert!(
        !text.contains("sig=TOPSECRET") && !text.contains("TOPSECRET"),
        "the refused key URI is query-stripped in the error face: {text}"
    );
    assert_eq!(rig.state.seg_count("/s/plain"), 0, "no segment fetch");
    drop(ledger2);
    join2.await.ok();

    // (3) Wrong-length key bodies: 15B and 17B → key_invalid.
    for key in ["15", "big"] {
        let text_manifest = {
            let mut t = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
            t.push_str(&format!(
                "#EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/{key}\"\n"
            ));
            t.push_str(&format!("#EXTINF:2,\nhttp://{addr}/s/plain\n"));
            t.push_str("#EXT-X-ENDLIST\n");
            t
        };
        let bytes = text_manifest.into_bytes();
        let app = Router::new()
            .route(
                "/badlen.m3u8",
                get(move || async move { body(bytes.clone()) }),
            )
            .route("/s/plain", get(|| async { body(b"PLAINSEG".to_vec()) }))
            .with_state(rig.state.clone());
        let addr3 = spawn_with(|_| app).await;
        let (ledger3, join3) = rig.ledger().await;
        let report = rig
            .download(true)
            .run(&format!("http://{addr3}/badlen.m3u8"), &ledger3)
            .await
            .unwrap_or_else(|e| panic!("run badlen: {e}"));
        let text = track_text(&report, "v");
        assert!(
            text.contains("taiji.media.key_invalid"),
            "{key} text: {text}"
        );
        drop(ledger3);
        join3.await.ok();
    }

    // (4) Non-block-length ciphertext: decrypt failure after the
    // retry budget → segment_decrypt_failed in the failure text. A
    // dedicated listener serves the playlist (key on the main mock,
    // segment local) so the shared counters stay comparable.
    let nm_addr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let a = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let st = rig.state.clone();
        let router = Router::new()
            .route(
                "/nonmult.m3u8",
                get(move || async move {
                    body(
                        format!(
                            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
                             #EXT-X-KEY:METHOD=AES-128,URI=\"http://{addr}/k/1\",IV=0x{}\n\
                             #EXTINF:2,\nhttp://{a}/s/nonmult\n\
                             #EXT-X-ENDLIST\n",
                            iv_hex(&IV1)
                        )
                        .into_bytes(),
                    )
                }),
            )
            .route("/s/{name}", get(seg_route))
            .with_state(st);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                panic!("serve: {e}");
            }
        });
        a
    };
    let (ledger4, join4) = rig.ledger().await;
    let report = rig
        .download(true)
        .run(&format!("http://{nm_addr}/nonmult.m3u8"), &ledger4)
        .await
        .unwrap_or_else(|e| panic!("run nonmult: {e}"));
    let text = track_text(&report, "v");
    assert!(
        text.contains("taiji.media.segment_decrypt_failed"),
        "nonmult text: {text}"
    );
    drop(ledger4);
    join4.await.ok();
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// ⑥ Encrypted resume (bitmap and plaintext semantics): a mid-run failure
/// leaves a resumable plaintext prefix; the retry fetches only the
/// tail; Σseg_len == archive length; the reconcile never truncates a
/// completed archive.
#[tokio::test]
async fn encrypted_resume_from_seg_bitmap() {
    let rig = rig("resumecrypt").await;
    let manifest = format!("http://{}/rot.m3u8", rig.addr);
    rig.state.fail("/s/rs4");
    let (ledger, join) = rig.ledger().await;
    let report = rig
        .download(true)
        .run(&manifest, &ledger)
        .await
        .unwrap_or_else(|e| panic!("run1: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Failed { .. }),
        "run1: {:?}",
        report.verdict
    );
    let stage = &report.staging_dir;
    let archive = stage.join("archive-v.ts");
    let partial: Vec<u8> = (0..4).flat_map(rot_plain).collect();
    assert_eq!(
        std::fs::read(&archive).unwrap_or_else(|e| panic!("read: {e}")),
        partial,
        "durable prefix = 4 decrypted segments"
    );
    drop(ledger);
    join.await.ok();

    rig.state.clear_fail("/s/rs4");
    let hits_before: Vec<String> = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (ledger2, join2) = rig.ledger().await;
    let report = rig
        .download(true)
        .run(&manifest, &ledger2)
        .await
        .unwrap_or_else(|e| panic!("run2: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Complete { ref degraded } if degraded.is_empty()),
        "run2: {:?}",
        report.verdict
    );
    drop(ledger2);
    join2.await.ok();

    // Wire discipline: run 1 may look-ahead-fetch tail segments into
    // its reorder buffer without delivering them (the engine's
    // bounded lookahead), so the honest assertion is per-path hit
    // deltas — the delivered prefix (rs0..rs3) is never re-fetched,
    // and every tail segment is fetched at least once **in run 2**
    // (rs4 was fully gated during run 1's failure window).
    let hits_after: Vec<String> = rig
        .state
        .seg_hits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let count = |v: &[String], p: &str| v.iter().filter(|h| h == &p).count();
    for i in 0..4 {
        let path = format!("/s/rs{i}");
        assert_eq!(
            count(&hits_after, &path),
            count(&hits_before, &path),
            "prefix {path} never re-fetched"
        );
    }
    for i in 4..8 {
        let path = format!("/s/rs{i}");
        let in_run2 = count(&hits_after, &path).saturating_sub(if i == 4 {
            0
        } else {
            count(&hits_before, &path)
        });
        assert!(in_run2 >= 1, "tail {path} fetched in run 2");
    }
    assert_eq!(
        count(&hits_before, "/s/rs4"),
        0,
        "rs4 was failure-gated in run 1"
    );

    let full: Vec<u8> = (0..8).flat_map(rot_plain).collect();
    assert_eq!(
        std::fs::read(&archive).unwrap_or_else(|e| panic!("read: {e}")),
        full,
        "completed archive == full plaintext"
    );

    // Plaintext-semantics ledger: Σseg_len == archive, no zero rows, full
    // bitmap.
    let (ledger3, join3) = rig.ledger().await;
    let tracks = ledger3
        .handle
        .load_media_tracks("8000000000000092")
        .await
        .unwrap_or_else(|e| panic!("load: {e}"));
    drop(ledger3);
    join3.await.ok();
    let (t, segs) = tracks.first().cloned().unwrap_or_else(|| panic!("rows"));
    assert_eq!(t.seg_bitmap.clone().unwrap_or_default(), vec![0xFF]);
    assert!(segs.iter().all(|s| s.seg_len > 0), "no zero rows: {segs:?}");
    let sum: i64 = segs.iter().map(|s| s.seg_len).sum();
    assert_eq!(
        sum as u64,
        full.len() as u64,
        "Σseg_len == archive (plaintext)"
    );
    let _ = std::fs::remove_dir_all(&rig.out_dir);
    let _ = std::fs::remove_dir_all(rig.db_path.parent().unwrap_or(std::path::Path::new("/")));
}

/// Anchor assertions (the media-side named anchors of this card).
#[test]
fn crypto_anchor_constants() {
    assert_eq!(taiji_media::decrypt::KEY_LEN, 16);
    assert_eq!(taiji_media::decrypt::BLOCK_LEN, 16);
    assert_eq!(taiji_media::datauri::MAX_DATA_URI_BYTES, 64 * 1024);
    assert_eq!(
        taiji_media::options::parse_allow_private_key_url("true").ok(),
        Some(true)
    );
    // The mock fixture sanity: the raw CBC layer round-trips through
    // the same RustCrypto stack the crate uses (self-check of the
    // test's own encrypt helper — NoPadding returns the padded
    // plaintext, so the assertion covers the prefix + the PKCS7 tail).
    let iv = iv_from_sequence(703);
    let plain = rot_plain(3);
    let cipher = encrypt(&K2, &iv, &plain);
    let raw = decrypt_raw(&K2, &iv, &cipher);
    assert_eq!(raw[..plain.len()], plain[..]);
    let pad = cipher.len() - plain.len();
    assert!((1..=16).contains(&pad));
    assert!(raw[plain.len()..].iter().all(|b| *b == pad as u8));
}

// ---------------------------------------------------------------------------
// The second-order playlist fetch face. Pre-fix, the
// driver (and the session's precheck/synthesis re-fetch) GETted the
// planned variant/rendition playlist URIs unchecked — the forged-
// manifest intranet-fetch hole the ssrf module declares as its own
// threat ("a forged manifest driving intranet fetches"; the PoC
// recorded the private variant host serving /inner.m3u8 before the
// segment face caught up). Every playlist fetch point now rides
// check_uri: same policy, same flag, zero requests to the refused
// host.
// ---------------------------------------------------------------------------

/// A counting mock for the "private" second-order host: records every
/// request path it would have served (it must stay empty).
#[derive(Clone, Default)]
struct PrivateHits(Arc<std::sync::Mutex<Vec<String>>>);

impl PrivateHits {
    fn get(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

async fn spawn_private_counter() -> (SocketAddr, PrivateHits) {
    let hits = PrivateHits::default();
    let h = hits.clone();
    let addr = spawn_with(move |_a| {
        Router::new().fallback(move |req: axum::extract::Request| {
            let path = req.uri().path().to_string();
            h.0.lock().unwrap_or_else(|e| e.into_inner()).push(path);
            async move { body(b"SHOULD-NOT-BE-SERVED".to_vec()) }
        })
    })
    .await;
    (addr, hits)
}

/// Master form with a chosen variant target + (optionally) a
/// rendition row pointing at a third host.
fn r6_master(variant_uri: String, rendition_uri: Option<String>) -> Vec<u8> {
    let mut m = String::from("#EXTM3U\n#EXT-X-VERSION:3\n");
    if let Some(r) = rendition_uri {
        m.push_str(&format!(
            "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en\",NAME=\"EN\",DEFAULT=YES,URI=\"{r}\"\n"
        ));
        m.push_str(&format!(
            "#EXT-X-STREAM-INF:BANDWIDTH=500000,AUDIO=\"aud\"\n{variant_uri}\n"
        ));
    } else {
        m.push_str(&format!(
            "#EXT-X-STREAM-INF:BANDWIDTH=500000\n{variant_uri}\n"
        ));
    }
    m.into_bytes()
}

/// The main form (the PoC's dynamic shape, flag off): the master's
/// variant URI points at a private host — the refusal lands on the
/// **playlist fetch itself** (zero requests to that host; the track
/// set fails with `ssrf_blocked`), not after the variant playlist
/// has been served.
#[tokio::test]
async fn ssrf_playlist_face_variant_refused_before_fetch() {
    let (priv_addr, hits) = spawn_private_counter().await;
    // The entry master is served by an ordinary loopback mock (the
    // entry URL is first-order — user input, never check_uri'd).
    let master = r6_master(format!("http://{priv_addr}/inner.m3u8"), None);
    let entry = spawn_with(move |_a| {
        Router::new().route(
            "/master.m3u8",
            get(move || async move { body(master.clone()) }),
        )
    })
    .await;
    let out_dir = tempdir("r6-variant");
    let db_dir = tempdir("r6-variant-db");
    let (ledger, join) = {
        let (handle, j) = PersistWriter::spawn(db_dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
        (StoreLedger { handle }, j)
    };
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let dl = MediaDownload::new(
        "8000000000000093",
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: out_dir.clone(),
            fetch: fast_fetch(),
            allow_private_key_url: false,
            ..MediaDownloadConfig::default()
        },
    );
    let report = dl
        .run(&format!("http://{entry}/master.m3u8"), &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    let text = track_text(&report, "v");
    assert!(
        matches!(report.verdict, TrackSetVerdict::Failed { .. }),
        "the forged-variant set fails: {:?}",
        report.verdict
    );
    assert!(
        text.contains("taiji.media.ssrf_blocked"),
        "the refusal names the ssrf face: {text}"
    );
    assert!(
        hits.get().is_empty(),
        "ZERO requests reached the private variant host (pre-fix it \
         served /inner.m3u8 before the segment face caught up): {:?}",
        hits.get()
    );
    drop(ledger);
    join.await.ok();
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_dir_all(&db_dir);
}

/// The nested form (variant + rendition inside one master): with the
/// default posture BOTH second-order playlist targets — the variant
/// URI and the EXT-X-MEDIA rendition URI — are refused before any
/// GET; each target host records zero requests and the failure face
/// carries `ssrf_blocked`.
#[tokio::test]
async fn ssrf_playlist_face_rendition_refused_before_fetch() {
    let (priv_v, hits_v) = spawn_private_counter().await;
    let (priv_r, hits_r) = spawn_private_counter().await;
    let master = r6_master(
        format!("http://{priv_v}/inner.m3u8"),
        Some(format!("http://{priv_r}/audio.m3u8")),
    );
    let entry = spawn_with(move |_a| {
        Router::new().route(
            "/master.m3u8",
            get(move || async move { body(master.clone()) }),
        )
    })
    .await;
    let out_dir = tempdir("r6-rend");
    let db_dir = tempdir("r6-rend-db");
    let (ledger, join) = {
        let (handle, j) = PersistWriter::spawn(db_dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
        (StoreLedger { handle }, j)
    };
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let dl = MediaDownload::new(
        "8000000000000094",
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: out_dir.clone(),
            fetch: fast_fetch(),
            allow_private_key_url: false,
            ..MediaDownloadConfig::default()
        },
    );
    let report = dl
        .run(&format!("http://{entry}/master.m3u8"), &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    let joined = report
        .tracks
        .iter()
        .map(|(_, s)| match s {
            TrackState::Failed(t) | TrackState::Degraded(t) => t.clone(),
            TrackState::Done => String::new(),
        })
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        joined.contains("taiji.media.ssrf_blocked"),
        "the refusal names the ssrf face: {joined}"
    );
    assert!(
        matches!(report.verdict, TrackSetVerdict::Failed { .. }),
        "the required (variant) track's refusal fails the set"
    );
    assert!(
        hits_v.get().is_empty(),
        "zero requests to the private variant host: {:?}",
        hits_v.get()
    );
    assert!(
        hits_r.get().is_empty(),
        "zero requests to the private rendition host: {:?}",
        hits_r.get()
    );
    drop(ledger);
    join.await.ok();
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_dir_all(&db_dir);
}

// ---------------------------------------------------------------------------
// The in-track staging-watermark consumption point. The
// 30s watchdog flag had zero in-track consumers — a forged manifest
// with big segments (or big BYTERANGE) could fill the disk before
// the track-boundary check ever ran. The (b)-layer delivery boundary
// (and the (a)-layer supervisor tick) now probe the watermark; a
// violation fails the track mid-flight and the driver escalates to
// the task-level `taiji.media.staging_quota_exceeded` terminal.
// ---------------------------------------------------------------------------

/// Quota 0 + a many-segment (b)-layer playlist — the run must
/// terminate MID-TRACK (the origin serves fewer than the whole
/// segment set) with the task-level staging error, and the bytes on
/// disk at interception stay within quota + one segment's slack.
#[tokio::test]
async fn staging_quota_intercepts_mid_track() {
    const SEGS: usize = 60;
    const SEG_LEN: usize = 64 * 1024;
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let s2 = served.clone();
    let addr = spawn_with(move |_a| {
        let mut media =
            String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-PLAYLIST-TYPE:VOD\n");
        for i in 0..SEGS {
            media.push_str(&format!("#EXTINF:2.0,\n/s{i}.ts\n"));
        }
        media.push_str("#EXT-X-ENDLIST\n");
        let m = media.into_bytes();
        let mut app =
            Router::new().route("/media.m3u8", get(move || async move { body(m.clone()) }));
        for i in 0..SEGS {
            let path: &'static str = Box::leak(format!("/s{i}.ts").into_boxed_str());
            let counter = s2.clone();
            app = app.route(
                path,
                get(move || async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    body(vec![7u8; SEG_LEN])
                }),
            );
        }
        app
    })
    .await;
    let out_dir = tempdir("r7-quota");
    let db_dir = tempdir("r7-quota-db");
    let (ledger, join) = {
        let (handle, j) = PersistWriter::spawn(db_dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
        (StoreLedger { handle }, j)
    };
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let dl = MediaDownload::new(
        "8000000000000096",
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: out_dir.clone(),
            fetch: fast_fetch(),
            staging_quota_gib: 0,
            allow_private_key_url: true,
            ..MediaDownloadConfig::default()
        },
    );
    let err = dl
        .run(&format!("http://{addr}/media.m3u8"), &ledger)
        .await
        .err()
        .unwrap_or_else(|| panic!("the zero-quota run must fail at the task level"));
    assert_eq!(
        err.code(),
        "taiji.media.staging_quota_exceeded",
        "the in-track escalation face: {err}"
    );
    assert!(
        err.to_string().contains("in-track"),
        "the interception names its mid-track point: {err}"
    );
    let served = served.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        served < SEGS,
        "MID-TRACK interception: the origin served {served} of {SEGS} segments \
         (a whole-track completion would have served all)"
    );
    // Interception-time disk footprint: quota (0) + one segment of
    // slack (the delivery-boundary probe refuses the next append).
    let usage = taiji_media::staging::staging_usage_bytes(&out_dir.join(".taiji-b"));
    assert!(
        usage <= SEG_LEN as u64,
        "bytes on disk at interception ({usage}) stay within quota + one \
         segment ({SEG_LEN})"
    );
    drop(ledger);
    join.await.ok();
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_dir_all(&db_dir);
}
