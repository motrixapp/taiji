//! Rate limiting end to end — the engine downloads from a slow local
//! seeder; the measured rate stays <= limit x tolerance and the download
//! still completes (no starvation).
//!
//! Chain same shape as engine_loop.rs (fake tracker + mini-seeder); the
//! only difference is `EngineConfig::limiter`: the per_torrent download
//! bucket carries a small limit, the global bucket is unlimited (0 =
//! unlimited short-circuit). Protocol frames (handshake/interested/
//! request) pass through the same throttled streams as piece payloads —
//! the measured rate sits slightly below the limit (the lower-bound
//! assertion is tightened by the tolerance).

use std::sync::Arc;
use std::time::{Duration, Instant};

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_io::rate_limit::{LimiterPair, LimiterSet};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;
/// Download bucket limit (bytes/s): 2 pieces x 16KiB ≈ 4s theoretical
/// lower bound.
const DOWN_LIMIT_BPS: u64 = 8 * 1024;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-rate-limit-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

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

/// Fake tracker: answers compact peers = the seeder address (engine_loop
/// shape).
async fn fake_tracker(seeder_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock
                .read(&mut chunk)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            if n == 0 {
                break;
            }
            req.extend_from_slice(&chunk[..n]);
        }
        let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
            panic!("test expects IPv4 seeder addr");
        };
        let ip = v4.octets();
        let port = seeder_addr.port().to_be_bytes();
        let mut peers = Vec::new();
        peers.extend_from_slice(&ip);
        peers.extend_from_slice(&port);
        let mut raw = Vec::new();
        raw.extend_from_slice(b"d8:intervali60e5:peers");
        raw.extend_from_slice(peers.len().to_string().as_bytes());
        raw.push(b':');
        raw.extend_from_slice(&peers);
        raw.push(b'e');
        let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
        sock.write_all(head.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        sock.write_all(&raw).await.unwrap_or_else(|e| panic!("{e}"));
    });
    addr
}

/// Mini-seeder: interested -> unchoke, request -> piece (engine_loop
/// shape).
async fn spawn_mini_seeder(listener: tokio::net::TcpListener, content: Vec<u8>) {
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10; // extended
        resp[27] = 0x04; // fast
        resp[28..48].copy_from_slice(&[7u8; 20]);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // After the handshake the mini-seeder sends a full bitfield per
        // BEP 3 (2 pieces = 0b1100_0000). It used to send no ad and rely
        // on the dispatcher's blind-select fallback; that fallback went
        // away with ad-aware dispatch.
        sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        loop {
            let mut len_buf = [0u8; 4];
            if sock.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                continue; // keepalive
            }
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            match body[0] {
                2 => {
                    // interested -> unchoke.
                    sock.write_all(&[0, 0, 0, 1, 1])
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                6 => {
                    // request -> piece.
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * PIECE_LEN as usize + begin as usize;
                    let block = content[offset..offset + length as usize].to_vec();
                    let mut frame = Vec::new();
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(&block);
                    sock.write_all(&frame)
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                _ => {}
            }
        }
    });
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!("bh-p37-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// Under the limit the download completes without starving; the rate
/// stays <= limit x tolerance.
#[tokio::test]
async fn engine_download_respects_per_torrent_download_limit() {
    let content = test_content();
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    spawn_mini_seeder(seeder_listener, content.clone()).await;
    let tracker_addr = fake_tracker(seeder_addr).await;

    // Topology: global unlimited (0 = unlimited short-circuit) + a
    // per_torrent download limit.
    let limiter = Arc::new(LimiterSet {
        global: LimiterPair::new(0, 0),
        per_torrent: LimiterPair::new(DOWN_LIMIT_BPS, 0),
    });

    let tmp = temp_dir("engine");
    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: format!("http://{tracker_addr}/announce"),
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config([7u8; 20], expected, content.len() as u64)],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        // No peer exchange on this legacy test surface (wire behavior
        // unchanged).
        peer_exchange: false,
        metadata_serve: None,
        limiter: Some(limiter),
        hook: None,
        nat: None,   // no NAT on the test face (EngineConfig::nat default unchanged)
        stats: None, // no metrics fed on the test face (EngineConfig::stats default unchanged)
        webseeds: Vec::new(),
    };
    let engine = DownloadEngine::spawn(cfg, &root);
    let started = Instant::now();
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out (starved under limit?)"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    let elapsed = started.elapsed();
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // Rate ceiling: total transfer (2 x 16KiB piece payload + protocol
    // frames) @ 8KiB/s -> at least 4s in theory. The lower-bound
    // assertion = the payload-theoretical value x 0.7 (protocol frames
    // also charge the bucket, only increasing; bucket filling and clock
    // granularity get a small tolerance).
    let theoretical = content.len() as f64 / DOWN_LIMIT_BPS as f64;
    assert!(
        elapsed.as_secs_f64() >= theoretical * 0.7,
        "rate exceeded limit: {elapsed:?} < theoretical {theoretical}s"
    );
    // Content consistency (throttling does not corrupt the data plane).
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| {
        let entries = std::fs::read_dir(&tmp)
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        panic!("read failed: {e}; dest entries: {entries:?}");
    });
    assert_eq!(got, content, "downloaded content must match the source");
    let _ = std::fs::remove_dir_all(&tmp);
}
