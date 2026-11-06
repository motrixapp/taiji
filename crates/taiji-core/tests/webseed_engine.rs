//! Webseeding engine-surface acceptance: a local HTTP Range server + a
//! torrent with a url-list -> the engine completes with **no BT peers**,
//! purely webseed-supplied.
//!
//! Chain: assembly `attach_webseeds` (a duplex pseudo-peer + HTTP Range
//! fetches) -> HaveAll/Unchoke opening -> dispatch issues Requests -> the
//! responder prefetches whole pieces (piece-boundary Ranges) -> piece
//! replies -> the store pipeline verifies to disk -> EngineEnd::Completed.
//! Upstream anchor: aria2 webseed = HTTP sources fetching piece-boundary
//! Ranges competing in the same pool as BT (this test = that pool reduced
//! to HTTP sources only). The server is a hand-written tokio TcpListener
//! minimal HTTP/1.1 Range server (206 + Content-Range; the mock-server
//! shape in the in-repo taiji-http tests is not reusable across crates,
//! so an equivalent is written here).

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 512 * 1024;
const TOTAL: u64 = 8 * 1024 * 1024;

/// Deterministic pseudo-random payload (xorshift64* — no external
/// dependencies, reproducible).
fn test_content() -> Vec<u8> {
    let mut state = 0x9E3779B97F4A7C15u64;
    let mut out = Vec::with_capacity(TOTAL as usize);
    while out.len() < TOTAL as usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(TOTAL as usize);
    out
}

/// v1-only single-face config (engine_loop shape; linear goffs + a short
/// final piece).
fn v1_face_config(
    info_hash: [u8; 20],
    expected: Vec<ExpectedPieceHash>,
    content_len: u64,
) -> FaceConfig {
    FaceConfig {
        kind: FaceKind::V1,
        info_hash,
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..expected.len() as u64)
            .map(|k| k * u64::from(PIECE_LEN))
            .collect(),
        piece_bytes: (0..expected.len() as u64)
            .map(|k| (content_len - k * u64::from(PIECE_LEN)).min(u64::from(PIECE_LEN)))
            .collect(),
        expected,
        plan_file_lengths: vec![content_len],
        progress_file_lens: vec![content_len],
        cross: Vec::new(),
        hash_files: None,
    }
}

/// Local HTTP/1.1 Range server (206 + Content-Range; a keep-alive loop
/// per connection — matching the HttpClient connection-pool reuse
/// shape). Request line + headers parsed up to the blank line; a GET
/// without a Range header = 200 full body (this engine surface always
/// sends Range; kept only for defensive completeness).
async fn spawn_range_server(content: Vec<u8>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let content = content.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    buf.clear();
                    // Read until the request-head terminator.
                    loop {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    // Range: bytes=s-e (both ends inclusive).
                    let range = text.lines().find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        if !name.trim().eq_ignore_ascii_case("range") {
                            return None;
                        }
                        value.trim().strip_prefix("bytes=").map(|r| r.to_string())
                    });
                    let (status, head_extra, body): (&str, String, &[u8]) = match range
                        .as_deref()
                        .and_then(|r| r.split_once('-'))
                        .and_then(|(s, e)| {
                            Some((s.trim().parse::<u64>().ok()?, e.trim().parse::<u64>().ok()?))
                        }) {
                        Some((s, e)) if s <= e && e < content.len() as u64 => {
                            let body = &content[s as usize..=e as usize];
                            (
                                "206 Partial Content",
                                format!("Content-Range: bytes {s}-{e}/{}\r\n", content.len()),
                                body,
                            )
                        }
                        _ => (
                            "200 OK",
                            format!(
                                "Content-Range: bytes 0-{}/{}\r\n",
                                content.len() - 1,
                                content.len()
                            ),
                            &content,
                        ),
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{head_extra}\r\n",
                        body.len()
                    );
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    if sock.write_all(body).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    format!("http://{addr}/payload.bin")
}

/// Criterion: purely webseed supply (empty announce = no tracker, no
/// DHT, no inbound peers) -> all 8MiB / 16 pieces delivered via HTTP
/// Range fetches -> the engine completes + on-disk content matches byte
/// for byte (the store pipeline's SHA-1 verification surface comes for
/// free).
#[tokio::test]
async fn engine_downloads_from_webseed_only() {
    let content = test_content();
    let tmp = std::env::temp_dir().join(format!(
        "taiji-webseed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
    let mut roots = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        roots.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }

    // Start the HTTP source first (the url is then known).
    let url = spawn_range_server(content.clone()).await;

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        // Empty announce = no tracker: the minimal isolation for
        // pure-webseed supply — zero BT peers is this acceptance's
        // precondition.
        announce: String::new(),
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config([7u8; 20], roots, content.len() as u64)],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        // The spec's core acceptance payload: a single-URL url-list.
        webseeds: vec![url],
    };
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out (webseed-only download)"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    // On-disk content check (byte-for-byte = double insurance after all
    // piece-level SHA-1s pass).
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, content, "the download must match the HTTP source");
    let _ = std::fs::remove_dir_all(&tmp);
}
