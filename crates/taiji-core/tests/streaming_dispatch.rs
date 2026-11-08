//! Acceptance (duplex wire end to end): StreamingStrategy + playhead
//! advancement — the peer's piece supply order matches the EDF
//! expectation.
//!
//! Fixture: an 8MiB single-file v1 torrent (512 pieces x 16KiB), a
//! controlled inbound peer (full bitfield ad + script-served requests).
//! The playhead sits at piece 480, window 8 pieces (the bps tier).
//! Assertions:
//!
//! 1. **the first request = piece 480** (the playhead's piece; not
//!    piece 0 — distinct from purely sequential; not a shuffled order —
//!    distinct from rarest-first);
//! 2. the prefix sequence = the EDF outward expansion (dist ties broken
//!    by ascending flat order): 480, 479, 481, 478, 482, 477, 483 (with
//!    the head/tail 2MiB class-0 covering the whole file, the distance
//!    order is the EDF order);
//! 3. **playhead advancement = repeated calls**: after issuing
//!    playhead(100), new requests land near the new playhead (dist <= 5)
//!    — the scheduler re-routes immediately.
//!
//! The scripted serving cadence (serving only the first SERVE_LIMIT
//! requests, resuming after the advance) clamps the expansion speed,
//! keeping assertion (3) race-free (before the advance the expansion is
//! nowhere near the piece-100 region).

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

const PIECE: usize = 16384;
const PIECES: usize = 512; // 8MiB
const PLAYHEAD_PIECE: u32 = 480;
/// Window-8-pieces tier: bps x 30s = 8 x 16KiB.
const BPS_8PIECES: u64 = (8 * PIECE / 30) as u64 + 1;
/// Scripted serving quota (before the advance); full serving resumes
/// after it.
const SERVE_LIMIT: usize = 10;

fn content() -> Vec<u8> {
    const P: &[u8] = b"taiji-p86-streaming-dispatch-";
    P.iter().cycle().take(PIECES * PIECE).copied().collect()
}

/// Controlled peer: handshake -> full bitfield -> reads frames, records
/// requests -> answers with pieces per the quota.
async fn run_peer(
    addr: std::net::SocketAddr,
    content: Arc<Vec<u8>>,
    requests: Arc<Mutex<Vec<u32>>>,
    advanced: Arc<std::sync::atomic::AtomicBool>,
) {
    let t0 = std::time::Instant::now();
    let mut sock = loop {
        match TcpStream::connect(addr).await {
            Ok(s) => break s,
            Err(_) if t0.elapsed() < Duration::from_secs(10) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("connect: {e}"),
        }
    };
    let mut hs = [0u8; 68];
    hs[0] = 19;
    hs[1..20].copy_from_slice(b"BitTorrent protocol");
    hs[27] = 0x04; // fast
    hs[28..48].copy_from_slice(&[11u8; 20]); // = FaceConfig::info_hash
    hs[48..68].copy_from_slice(&[9u8; 20]);
    sock.write_all(&hs).await.unwrap_or_else(|e| panic!("{e}"));
    let mut echo = [0u8; 68];
    sock.read_exact(&mut echo)
        .await
        .unwrap_or_else(|e| panic!("handshake echo: {e}"));

    // Full bitfield (512 bits = 64 bytes, MSB = piece 0).
    let mut frame = vec![0, 0, 0, 1 + (PIECES / 8) as u8];
    frame.push(5u8);
    frame.extend_from_slice(&[0xFFu8; PIECES / 8]);
    sock.write_all(&frame)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // Reciprocity economics: unchoke (the dispatcher sends zero requests
    // to peers that choke us — aria2 fillPiece direct translation;
    // supply peers must let requests through).
    sock.write_all(&[0, 0, 0, 1, 1])
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let mut served = 0usize;
    loop {
        // Read one frame (len prefix + body).
        let mut len_buf = [0u8; 4];
        if sock.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut body = vec![0u8; len];
        if sock.read_exact(&mut body).await.is_err() {
            break;
        }
        if body[0] != 6 {
            continue; // only requests matter
        }
        let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
        let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
        let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
        requests.lock().await.push(index);
        let may_serve = served < SERVE_LIMIT || advanced.load(std::sync::atomic::Ordering::Relaxed);
        if may_serve {
            served += 1;
            let off = index as usize * PIECE + begin as usize;
            let mut resp = Vec::with_capacity(13 + length as usize);
            resp.extend_from_slice(&(9 + length).to_be_bytes());
            resp.push(7u8);
            resp.extend_from_slice(&index.to_be_bytes());
            resp.extend_from_slice(&begin.to_be_bytes());
            resp.extend_from_slice(&content[off..off + length as usize]);
            if sock.write_all(&resp).await.is_err() {
                break;
            }
        }
    }
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bh-p86-stream-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    dir
}

#[tokio::test]
async fn streaming_dispatch_playhead_drives_request_order() {
    let content = Arc::new(content());
    let dir = tmp_dir("order");
    // Probe port: bind first, then release (the engine binds that port).
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("probe bind: {e}"));
    let port = probe.local_addr().unwrap_or_else(|e| panic!("{e}")).port();
    drop(probe);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    // Dead tracker: discovery stays silent (all peers arrive via the
    // controlled inbound connection).
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("dead bind: {e}"));
    let tracker = format!(
        "http://{}/announce",
        dead.local_addr().unwrap_or_else(|e| panic!("{e}"))
    );

    let expected: Vec<ExpectedPieceHash> = content
        .chunks(PIECE)
        .map(|c| ExpectedPieceHash::V1(Sha1::digest(c).into()))
        .collect();
    let face = FaceConfig {
        kind: FaceKind::V1,
        info_hash: [11u8; 20],
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..PIECES).map(|k| (k * PIECE) as u64).collect(),
        piece_bytes: vec![PIECE as u64; PIECES],
        expected,
        plan_file_lengths: vec![(PIECES * PIECE) as u64],
        progress_file_lens: vec![(PIECES * PIECE) as u64],
        cross: Vec::new(),
        hash_files: None,
    };
    let cfg = EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: tracker,
        listen_port: port,
        piece_len: PIECE as u32,
        layout: taiji_store::layout::Layout::plan_v1_padded(
            &[taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from("blob.bin"),
                length: (PIECES * PIECE) as u64,
                padding: false,
            }],
            PIECE as u32,
        )
        .unwrap_or_else(|e| panic!("{e}")),
        dest: dir.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile.
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![face],
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
    let root = CancellationToken::new();
    let (engine, _join) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig::default(),
        &root,
        taiji_bt::utp::PeerConnectionType::default(),
    );

    // Combination switch (issued before the peer connects — the engine's
    // command loop consumes it first): the streaming policy + playhead
    // at piece 480.
    engine
        .set_scheduler_policy("streaming".parse().unwrap_or_else(|e| panic!("{e}")))
        .await
        .unwrap_or_else(|e| panic!("policy: {e}"));
    engine
        .set_streaming_playhead(
            0,
            u64::from(PLAYHEAD_PIECE) * PIECE as u64,
            Some(BPS_8PIECES),
        )
        .await
        .unwrap_or_else(|e| panic!("playhead: {e}"));

    let requests = Arc::new(Mutex::new(Vec::<u32>::new()));
    let advanced = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let peer = run_peer(addr, content.clone(), requests.clone(), advanced.clone());
    tokio::spawn(peer);

    // (1)+(2): wait for the first 7 requests -> exactly the EDF expansion
    // order.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let n = requests.lock().await.len();
        if n >= 7 || std::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got = requests.lock().await.clone();
    assert!(
        got.len() >= 7,
        "the prefix arrived in time under the script quota clamp; got {got:?}"
    );
    assert_eq!(
        got[0], PLAYHEAD_PIECE,
        "(1) the first request = the playhead's piece"
    );
    assert_eq!(
        &got[..7],
        &[480, 479, 481, 478, 482, 477, 483],
        "(2) EDF outward expansion (distance ties break by flat ascending order); got {got:?}"
    );

    // (3): advance the playhead to piece 100 -> new requests land near
    // the new playhead.
    engine
        .set_streaming_playhead(0, 100 * PIECE as u64, Some(BPS_8PIECES))
        .await
        .unwrap_or_else(|e| panic!("playhead advance: {e}"));
    let at_advance = got.len();
    advanced.store(true, std::sync::atomic::Ordering::Relaxed);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let hit = loop {
        let near_new_head = requests.lock().await[at_advance..].iter().any(|&i| {
            let d = i.abs_diff(100);
            d <= 5
        });
        if near_new_head || std::time::Instant::now() > deadline {
            break near_new_head;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        hit,
        "(3) after the advance, requests redirect near the new playhead"
    );

    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), root.cancelled()).await;
    let _ = std::fs::remove_dir_all(&dir);
}
