//! Regression: real long-run progress stall (verify/dispatch loop) —
//! the write-cache-pressure reproduction surface.
//!
//! Reproduction shape aligned with a 12h real-swarm observation:
//! - piece length 256KiB (same parameters as the Ubuntu 24.04.4 official
//!   torrent: 12991 pieces; a 16MiB write cache holds only 64 pieces);
//! - many peers (under the spread-round semantics each peer claims
//!   different pieces) -> concurrent in-flight pieces far exceed the
//!   cache capacity -> cache pressure saturates;
//! - churning peers (fake seeders that periodically disconnect and
//!   reconnect) -> the connection population rotates.
//!
//! Observed failure shape: completed freezes (piece-verified logs stall)
//! while downloading continues — root cause = write-cache eviction
//! (under verify-before-write discipline, eviction = destruction)
//! systematically destroying near-complete pieces in largest-first
//! victim order, with eviction silent to engine/pipeline bookkeeping.
//! The fix criterion: verified retention grows monotonically to
//! completion (`EngineEnd::Completed` + on-disk content matches).

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Piece length = 256KiB (same as the observed torrent; a 16MiB cache
/// holds only 64 pieces — the critical peer count for pressure is 64,
/// and 90 peers saturate deterministically).
const PIECE_LEN: u32 = 256 * 1024;
/// Fake seeder count (>64: concurrent in-flight pieces exceed the cache
/// capacity — the pressure surface).
const SEEDERS: usize = 90;

fn pressure_content(pieces: usize) -> Arc<Vec<u8>> {
    let len = pieces as u64 * u64::from(PIECE_LEN);
    let mut v = Vec::with_capacity(len as usize);
    // xorshift64 fill (deterministic pseudo-random; the SHA1 expectations
    // and the seeder serving share this source).
    let mut state = 0x9E3779B97F4A7C15u64;
    while v.len() < len as usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        v.extend_from_slice(&state.to_be_bytes());
    }
    v.truncate(len as usize);
    Arc::new(v)
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

/// Fake tracker: accepts announces in a loop, answering compact peers =
/// all seeder addresses (short interval, so churned-off peers are
/// resupplied as candidates quickly through the min-peers gate).
async fn fake_tracker(seeder_addrs: Vec<std::net::SocketAddr>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let mut peers = Vec::new();
        for a in &seeder_addrs {
            let std::net::IpAddr::V4(v4) = a.ip() else {
                panic!("test expects IPv4 seeder addr");
            };
            peers.extend_from_slice(&v4.octets());
            peers.extend_from_slice(&a.port().to_be_bytes());
        }
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                }
            }
            // Hand-assembled bencode (peers is a binary byte string).
            let mut raw = Vec::new();
            raw.extend_from_slice(b"d8:intervali5e5:peers");
            raw.extend_from_slice(peers.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&raw).await;
        }
    });
    addr
}

/// Churn mini-seeder: one accept loop per seeder; each connection does
/// handshake + full bitfield ad first, then interested -> unchoke,
/// request -> piece (any request within a 16KiB block); the seeder side
/// closes the connection after `churn_period_ms(index)` (periodic
/// disconnect/reconnect, rotating the peer population).
async fn spawn_churn_seeder(
    listener: tokio::net::TcpListener,
    index: usize,
    content: Arc<Vec<u8>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let pieces = content.len().div_ceil(PIECE_LEN as usize);
    let bitfield_len = pieces.div_ceil(8);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((mut sock, _)) = accepted else { break };
                    // Churn period: phase-offset by seeder index (30s base
                    // + index spread); at any moment only ~1/9 of the
                    // peers are inside their reconnect window, keeping
                    // the connection population high.
                    let ttl = Duration::from_millis(
                        24_000 + (index % 9) as u64 * 3_000,
                    );
                    let content = content.clone();
                    let _ = tokio::time::timeout(ttl, async {
                        let mut hs = [0u8; 68];
                        if sock.read_exact(&mut hs).await.is_err() {
                            return;
                        }
                        let mut resp = [0u8; 68];
                        resp[0] = 19;
                        resp[1..20].copy_from_slice(b"BitTorrent protocol");
                        resp[25] = 0x10; // extended
                        resp[27] = 0x04; // fast
                        resp[28..48].copy_from_slice(&[7u8; 20]);
                        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
                        let _ = sock.write_all(&resp).await;
                        // Full bitfield (MSB = piece 0; per BEP 3 the peer
                        // truncates trailing bits by piece count, so
                        // all-ones on the test surface is fine).
                        let mut bf = vec![0u8; 4 + 1 + bitfield_len];
                        bf[0..4].copy_from_slice(&((1 + bitfield_len) as u32).to_be_bytes());
                        bf[4] = 5;
                        for b in bf.iter_mut().skip(5) {
                            *b = 0xFF;
                        }
                        let _ = sock.write_all(&bf).await;
                        // Frame loop: interested -> unchoke; request ->
                        // piece.
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
                            if sock.read_exact(&mut body).await.is_err() {
                                break;
                            }
                            match body[0] {
                                2 => {
                                    let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                                }
                                6 => {
                                    let index = u32::from_be_bytes([
                                        body[1], body[2], body[3], body[4],
                                    ]);
                                    let begin = u32::from_be_bytes([
                                        body[5], body[6], body[7], body[8],
                                    ]);
                                    let length = u32::from_be_bytes([
                                        body[9], body[10], body[11], body[12],
                                    ]);
                                    let offset =
                                        index as usize * PIECE_LEN as usize + begin as usize;
                                    let end = (offset + length as usize).min(content.len());
                                    if offset >= end {
                                        break;
                                    }
                                    let block = content[offset..end].to_vec();
                                    let mut frame = Vec::with_capacity(9 + block.len());
                                    frame.extend_from_slice(
                                        &((9 + block.len()) as u32).to_be_bytes(),
                                    );
                                    frame.push(7u8);
                                    frame.extend_from_slice(&index.to_be_bytes());
                                    frame.extend_from_slice(&begin.to_be_bytes());
                                    frame.extend_from_slice(&block);
                                    let _ = sock.write_all(&frame).await;
                                }
                                _ => {}
                            }
                        }
                    })
                    .await;
                    let _ = sock.shutdown().await;
                    // After closing, back to accept (the reconnect surface
                    // of the churn disconnect).
                }
            }
        }
    });
}

async fn spawn_seeder_farm(
    count: usize,
    content: Arc<Vec<u8>>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Vec<std::net::SocketAddr> {
    let mut addrs = Vec::with_capacity(count);
    for i in 0..count {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        addrs.push(addr);
        spawn_churn_seeder(listener, i, content.clone(), shutdown.clone()).await;
    }
    addrs
}

/// Shared pressure-run body: `pieces` x 256KiB with N churn seeders;
/// criterion = verified retention grows monotonically to completion
/// (`EngineEnd::Completed` + on-disk content matches the source).
async fn pressure_run(pieces: usize, timeout: Duration) -> EngineEnd {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let content = pressure_content(pieces);
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let tmp = std::env::temp_dir().join(format!(
        "taiji-p80-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("mkdir: {e}"));
    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));

    let farm_shutdown = tokio_util::sync::CancellationToken::new();
    let seeder_addrs = spawn_seeder_farm(SEEDERS, content.clone(), farm_shutdown.clone()).await;
    let tracker_addr = fake_tracker(seeder_addrs).await;

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        initial_selection: None,
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
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(timeout, engine).await;
    root.cancel();
    farm_shutdown.cancel();
    let end = match end {
        Ok(join) => join.unwrap_or_else(|e| panic!("join: {e}")),
        Err(_elapsed) => {
            // Timeout = verification retention stalled (the observed
            // failure shape). Fail with the diagnostic scene preserved.
            panic!(
                "engine timed out after {timeout:?}: verification stalled \
                 (loop: download continues, completions frozen)"
            );
        }
    };
    // On-disk content check.
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got.len(),
        content.len(),
        "the on-disk length must match the source"
    );
    assert_eq!(
        &got[..],
        &content[..],
        "downloaded content must match the source"
    );
    let _ = std::fs::remove_dir_all(&tmp);
    end
}

/// Fast pressure surface: 500 pieces (131MB) x 90 churn seeders. At
/// 256KiB pieces a 16MiB write cache holds only 64 pieces; 90 peers
/// (spread round = each peer claims different pieces) over-pressure it
/// deterministically — unfixed code stalls piece-verified within seconds
/// under this pressure (the observed failure shape); fixed code should
/// download fully to Completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_pressure_500_pieces_completes() {
    let end = pressure_run(500, Duration::from_secs(900)).await;
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
}

/// Design acceptance surface: a >=5000-piece long run (1.31GB) with
/// churn peers — verified retention keeps growing to completion. Run
/// manually on a release build:
/// `cargo test -p taiji-core --test cache_pressure --release -- --ignored --nocapture`
#[ignore = "long run (1.31GB download + write to disk); the gate runs the fast face — \
this test is designed for manual runs in the 60-90min layer"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn longrun_5000_pieces_completes() {
    let end = pressure_run(5000, Duration::from_secs(1800)).await;
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
}
