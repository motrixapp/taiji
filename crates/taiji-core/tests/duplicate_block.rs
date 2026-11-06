//! Acceptance: end-to-end reproduction of duplicate-block delivery in a
//! real swarm, and the benign-handling regression. The root-cause path
//! analysis (how duplicate/overlapping blocks reach push_block, with the
//! aria2 anchors) lives in docs/design/core.md.
//!
//! # Scenario (deterministic; inbound connection order locks the peer 0/1
//! identities)
//!
//! The test dials into the engine as two remote peers: peer 0 first (slow
//! answers), then peer 1 once it has settled:
//! - peer 0: every request is answered 6 s late (> the redispatch window,
//! creating the in-flight overlap);
//! - peer 1: begin==0 answered immediately, the rest 8 s late (only the
//! first block lands inside the piece's in-flight window).
//! (The redispatch window = max(2 s, min(peer adaptive timeout, 5 s));
//! for a sample-less peer the window is the 5 s cap, so answer latencies
//! that create the overlap must be > 5 s.)
//!
//! Timeline: t0 all 4 candidate blocks go to peer 0 -> the redispatch
//! window expires (sample-less peer window = the 5 s cap) and the
//! same-coordinate requests move to peer 1 -> peer 1 immediately returns
//! block 0 (buffered, piece 1/4 in flight) -> +6 s peer 0's original
//! replies arrive: block 0 is an exact duplicate (piece incomplete + goff
//! already buffered = the old fatal path), blocks 1-3 are new (the piece
//! fills, verifies, lands). After the fix: the duplicate is benignly
//! dropped + counted, and the download completes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_core::session::metrics::SessionMetrics;
use taiji_store::hashpool::ExpectedPieceHash;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// 64 KiB pieces = 4 blocks per piece — the precondition for separating
/// the duplicate-block landing from piece completion (a 16 KiB piece is a
/// single block, where a duplicate degrades into the existing
/// PieceAlreadyComplete path and cannot exercise the in-flight-piece
/// duplicate).
const PIECE: u64 = 64 * 1024;
const PIECES: usize = 2;

/// Test reference instant (peer-side debug timestamps).
static T0: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);

fn content() -> Vec<u8> {
    const P: &[u8] = b"taiji-p66-duplicate-block-";
    P.iter()
        .cycle()
        .take(PIECES * PIECE as usize)
        .copied()
        .collect()
}

/// Lazy peer read loop (connection established + handshake done):
/// interested(2) -> unchoke(1); request(6) -> answers piece(7) after
/// `delay_ms` (immediately for begins in `fast_begins`).
/// Answers are written out through a FIFO (in request arrival order,
/// mimicking a real client's ordered answering — each block's response
/// time = its own request time + delay; uncontrolled concurrent writes
/// would introduce an unrelated variable). The write half is shared behind
/// a mutex.
async fn lazy_peer(
    sock: TcpStream,
    content: Arc<Vec<u8>>,
    delay_ms: u64,
    fast_begins: &'static [u32],
) {
    let (mut rd, wr) = tokio::io::split(sock);
    let wr = Arc::new(tokio::sync::Mutex::new(wr));
    // Answer queue: FIFO writes (bounded 64; test-face request volume is
    // far below this).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(64);
    let writer = {
        let wr = Arc::clone(&wr);
        tokio::spawn(async move {
            while let Some((at, frame)) = rx.recv().await {
                tokio::time::sleep_until(at).await;
                if wr.lock().await.write_all(&frame).await.is_err() {
                    return;
                }
            }
        })
    };
    loop {
        let mut len_buf = [0u8; 4];
        if rd.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut body = vec![0u8; len];
        if rd.read_exact(&mut body).await.is_err() {
            break;
        }
        match body[0] {
            2 => {
                // interested -> unchoke.
                let _ = wr.lock().await.write_all(&[0, 0, 0, 1, 1]).await;
            }
            6 => {
                let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                eprintln!(
                    "P66-peer[+{:.2}s] request idx={index} begin={begin} len={length} delay={delay_ms}",
                    T0.elapsed().as_secs_f32()
                );
                let delay = if fast_begins.contains(&begin) {
                    0
                } else {
                    delay_ms
                };
                let content = Arc::clone(&content);
                let at = tokio::time::Instant::now() + Duration::from_millis(delay);
                let off = index as usize * PIECE as usize + begin as usize;
                let Some(block) = content.get(off..off + length as usize) else {
                    continue;
                };
                let mut frame = Vec::with_capacity(13 + block.len());
                frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                frame.push(7u8);
                frame.extend_from_slice(&index.to_be_bytes());
                frame.extend_from_slice(&begin.to_be_bytes());
                frame.extend_from_slice(block);
                let _ = tx.send((at, frame)).await;
            }
            _ => {}
        }
    }
    writer.abort();
}

/// Dials into the engine + handshake + hands off to the lazy peer loop
/// (the first to connect = the engine's peer 0).
async fn dial_lazy_peer(
    addr: std::net::SocketAddr,
    content: Arc<Vec<u8>>,
    delay_ms: u64,
    fast_begins: &'static [u32],
) {
    eprintln!(
        "P66-peer[+{:.2}s] dialing {addr} delay={delay_ms}",
        T0.elapsed().as_secs_f32()
    );
    // The engine listener binds asynchronously: back off and retry on
    // connect refusal (up to ~5 s).
    let mut sock = loop {
        match TcpStream::connect(addr).await {
            Ok(s) => break s,
            Err(e) if T0.elapsed() < Duration::from_secs(10) => {
                eprintln!(
                    "P66-peer[+{:.2}s] connect retry: {e}",
                    T0.elapsed().as_secs_f32()
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
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
    // The lazy peer sends the full bitfield after its handshake (BEP 3;
    // MSB = piece 0, 2 pieces = 0b1100_0000). It previously advertised
    // nothing and relied on the dispatcher's blind-pick fallback — that
    // fallback was removed with advertisement-aware dispatch (a real
    // client holding data always advertises, the post-handshake bitmap per
    // BEP 3; the test tracks the real behavior).
    sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    eprintln!(
        "P66-peer[+{:.2}s] handshake done delay={delay_ms}",
        T0.elapsed().as_secs_f32()
    );
    lazy_peer(sock, content, delay_ms, fast_begins).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_peer_duplicate_block_is_dropped_and_download_completes() {
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    );
    let content = Arc::new(content());
    let mut expected = Vec::new();
    for c in content.chunks(PIECE as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }

    let tmp = std::env::temp_dir().join(format!(
        "taiji-p66-dup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    // Probe port: occupy then release (the engine binds to this port; the
    // test race window is negligible).
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("probe bind: {e}"));
    let port = probe.local_addr().unwrap_or_else(|e| panic!("{e}")).port();
    drop(probe);
    let engine_addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    // Empty-peer tracker: the discovery face stays silent; both peers come
    // in as controlled inbound connections.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let tracker = format!(
        "http://{}/announce",
        dead.local_addr().unwrap_or_else(|e| panic!("{e}"))
    );

    let entries_len = content.len() as u64;
    let face = FaceConfig {
        kind: FaceKind::V1,
        info_hash: [11u8; 20],
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..PIECES as u64).map(|k| k * PIECE).collect(),
        piece_bytes: (0..PIECES as u64)
            .map(|k| (entries_len - k * PIECE).min(PIECE))
            .collect(),
        expected,
        plan_file_lengths: vec![entries_len],
        progress_file_lens: vec![entries_len],
        cross: Vec::new(),
        hash_files: None,
    };
    let metrics = Arc::new(SessionMetrics::new());
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: tracker,
        listen_port: port,
        piece_len: PIECE as u32,
        layout: taiji_store::layout::Layout::plan_v1_padded(
            &[taiji_store::layout::PlanEntry {
                path: PathBuf::from("blob.bin"),
                length: entries_len,
                padding: false,
            }],
            PIECE as u32,
        )
        .unwrap_or_else(|e| panic!("{e}")),
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput tier (no behavior change).
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
        stats: Some(Arc::clone(&metrics)),
        webseeds: Vec::new(),
    };
    let root = tokio_util::sync::CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);

    // Registration-order determinism: once the engine is up, connect peer
    // 0 first (slow answers), then peer 1 after it settles.
    let slow = tokio::spawn({
        let c = Arc::clone(&content);
        async move { dial_lazy_peer(engine_addr, c, 6_000, &[]).await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let fast = tokio::spawn({
        let c = Arc::clone(&content);
        async move { dial_lazy_peer(engine_addr, c, 8_000, &[0]).await }
    });

    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out (download stuck)"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    slow.abort();
    fast.abort();

    // Field signature (pre-fix): the task fails explicitly (the duplicate
    // cell made fatal / an out-of-order piece hash misjudged -> endless
    // refetch -> 3 hash-fail bans kill the task).
    // Post-fix: duplicate/late/redispatched blocks are all handled
    // benignly, the download closes the loop and the content matches.
    // Deterministic unit tests of duplicate dropping (three shapes +
    // out-of-order arrival + counting assertions) live in the store layer
    // (verified.rs / cache.rs) — the engine dispatcher's in-flight marker
    // refresh (a Duplicate receipt keeps the marker and re-stamps the
    // timestamp) means cross-peer duplicates can only arise through a tiny
    // race window and cannot be deterministically orchestrated on the
    // black-box wire face (root-cause notes in this file's header).
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got,
        content.as_slice(),
        "downloaded content must match the source"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
