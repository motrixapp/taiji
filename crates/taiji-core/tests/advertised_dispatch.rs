//! Acceptance: peer-advertisement-aware dispatching (wire level, duplex
//! inbound connections).
//!
//! The legacy dispatcher fell back to blind sequential selection
//! (`unwrap_or(current)`) when no peer bitmap evidence existed and
//! requested pieces the peer **never advertised**; real always-seeding
//! clients answer such requests with FIN. After the fix the dispatch
//! candidate set = the peer's advertised bitmap (accumulated
//! bitfield/HAVE) ∩ locally incomplete pieces
//! ([`taiji_core::engine`] `select_advertised_piece`; upstream anchors:
//! libtorrent `request_blocks.cpp` + `piece_picker.cpp` — picking only
//! draws candidates from `c.get_bitfield()`; aria2
//! `DefaultPieceStorage.cc` filters through `peer->getBitfield()`).
//!
//! # Scenarios (table-driven + end to end)
//!
//! Engine + a single controlled inbound peer (2 pieces x 16 KiB, one
//! block per piece):
//! - **silent peer** (no bitfield/HAVE) -> zero request frames within
//!   the window;
//! - **bitfield advertising only piece 1** -> requests land only on
//!   piece 1; unadvertised piece 0 gets zero requests (old behavior:
//!   blind-picking piece 0 is the regression this test pins);
//! - **HAVE advertising only piece 0** -> requests land only on piece 0
//!   (HAVE enters the candidate set immediately);
//! - **single-peer end to end**: bitfield {1} -> serve piece 1 -> after
//!   piece 1 settles send HAVE(0) -> engine requests piece 0
//!   immediately -> serve -> EngineEnd::Completed — every piece comes
//!   from that peer, and piece-0 requests are asserted to happen only
//!   after HAVE(0).

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const PIECE: usize = 16_384; // 1 block per piece
const PIECES: usize = 2;

fn content() -> Vec<u8> {
    const P: &[u8] = b"taiji-p67-adv-dispatch-";
    P.iter().cycle().take(PIECES * PIECE).copied().collect()
}

/// Advertisement form (table-driven row).
#[derive(Clone, Copy)]
enum Advertise {
    /// Silent after the handshake (no bitfield/HAVE — treated as
    /// have_none per BEP 3).
    Silent,
    /// Send a bitfield after the handshake (`&[1]` = only piece 1; the
    /// frame uses the shortest byte form, MSB = piece 0).
    Bitfield(&'static [u32]),
    /// Send HAVE(index) after the handshake.
    Have(u32),
}

/// Peer behavior script.
struct Script {
    advertise: Advertise,
    /// Whether to serve requests (answer with piece frames).
    serve: bool,
    /// After the piece-1 frame has been delivered to the engine, whether
    /// to follow with HAVE(0) and serve piece 0 (end-to-end scenario).
    reveal_after_piece1: bool,
}

/// One observed peer request (wire-level observation).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Req {
    index: u32,
    /// Whether this request happened after HAVE(0) was sent
    /// (reveal-scenario assertion).
    after_reveal: bool,
}

/// Dial into the engine + handshake + advertise/answer per the script;
/// records the observed requests.
async fn run_peer(
    addr: std::net::SocketAddr,
    content: Arc<Vec<u8>>,
    script: Script,
    requests: Arc<Mutex<Vec<Req>>>,
) {
    // The engine listener binds asynchronously: back off and retry on
    // connection refusal (up to ~10s).
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

    let mut revealed = false; // whether HAVE(0) has been sent
    match script.advertise {
        Advertise::Silent => {}
        Advertise::Bitfield(set) => {
            // BEP 3 bitfield: shortest byte form, MSB = piece 0, trailing
            // bits zero.
            let mut bits = vec![0u8; PIECES.div_ceil(8)];
            for &i in set {
                bits[i as usize / 8] |= 0x80 >> (i % 8);
            }
            let mut frame = vec![0, 0, 0, 1 + bits.len() as u8];
            frame.push(5u8);
            frame.extend_from_slice(&bits);
            sock.write_all(&frame)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        Advertise::Have(index) => {
            // BEP 3: HAVE = id 4 (len 5); BITFIELD = id 5.
            sock.write_all(&[0, 0, 0, 5, 4])
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            sock.write_all(&index.to_be_bytes())
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
    }

    let piece_frame = |index: u32, begin: u32| {
        let off = index as usize * PIECE + begin as usize;
        let block = &content[off..off + PIECE];
        let mut f = Vec::with_capacity(13 + block.len());
        f.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
        f.push(7u8);
        f.extend_from_slice(&index.to_be_bytes());
        f.extend_from_slice(&begin.to_be_bytes());
        f.extend_from_slice(block);
        f
    };

    loop {
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
        match body[0] {
            2 => {
                // interested -> unchoke.
                sock.write_all(&[0, 0, 0, 1, 1]).await.ok();
            }
            6 => {
                let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                requests.lock().await.push(Req {
                    index,
                    after_reveal: revealed,
                });
                if !script.serve {
                    continue;
                }
                let frame = piece_frame(index, begin);
                sock.write_all(&frame).await.ok();
                // End-to-end scenario: after piece 1 is served, follow
                // with HAVE(0). The engine's piece-1 verification lags,
                // so wait briefly before revealing to keep the
                // "piece-0 request is later than HAVE" assertion
                // time-resolvable.
                if script.reveal_after_piece1 && index == 1 && !revealed {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    // BEP 3 HAVE(0): id 4, len 5.
                    sock.write_all(&[0, 0, 0, 5, 4]).await.ok();
                    sock.write_all(&0u32.to_be_bytes()).await.ok();
                    revealed = true;
                }
            }
            _ => {}
        }
    }
}

/// Engine + single-peer fixture: spawns the engine (dead tracker) and
/// returns the engine address plus the root token.
async fn spawn_engine(
    tmp: &std::path::Path,
    expected: Vec<ExpectedPieceHash>,
    entries_len: u64,
) -> (
    std::net::SocketAddr,
    tokio_util::sync::CancellationToken,
    tokio::task::JoinHandle<EngineEnd>,
) {
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
        .unwrap_or_else(|e| panic!("{e}"));
    let tracker = format!(
        "http://{}/announce",
        dead.local_addr().unwrap_or_else(|e| panic!("{e}"))
    );
    let face = FaceConfig {
        kind: FaceKind::V1,
        info_hash: [11u8; 20],
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..PIECES as u64).map(|k| k * PIECE as u64).collect(),
        piece_bytes: (0..PIECES as u64)
            .map(|k| (entries_len - k * PIECE as u64).min(PIECE as u64))
            .collect(),
        expected,
        plan_file_lengths: vec![entries_len],
        progress_file_lens: vec![entries_len],
        cross: Vec::new(),
        hash_files: None,
    };
    let cfg = EngineConfig {
        initial_selection: None,
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: tracker,
        listen_port: port,
        piece_len: PIECE as u32,
        layout: taiji_store::layout::Layout::plan_v1_padded(
            &[taiji_store::layout::PlanEntry {
                path: std::path::PathBuf::from("blob.bin"),
                length: entries_len,
                padding: false,
            }],
            PIECE as u32,
        )
        .unwrap_or_else(|e| panic!("{e}")),
        dest: tmp.to_path_buf(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile (no behavior change).
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
    let root = tokio_util::sync::CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);
    (addr, root, engine)
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let tmp = std::env::temp_dir().join(format!(
        "taiji-p67-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));
    tmp
}

/// Table-driven: the peer's advertised set decides where requests land —
/// unadvertised pieces get zero requests.
/// Row 2 pins the defect eradicated in this module: when the peer
/// advertises only piece 1, the old blind-select fallback would request
/// piece 0, and real always-seeding clients reject such requests with
/// FIN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_land_only_on_advertised_pieces() {
    let content = Arc::new(content());
    let rows: Vec<(&str, Advertise, Vec<u32>)> = vec![
        // (name, advertisement form, allowed request piece set)
        ("silent peer advertises nothing", Advertise::Silent, vec![]),
        (
            "bitfield advertises piece 1 only",
            Advertise::Bitfield(&[1]),
            vec![1],
        ),
        ("HAVE advertises piece 0 only", Advertise::Have(0), vec![0]),
    ];
    for (name, advertise, allowed) in rows {
        let tmp = tmp_dir("table");
        let mut expected = Vec::new();
        for c in content.chunks(PIECE) {
            expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
        }
        let (addr, root, engine) = spawn_engine(&tmp, expected, content.len() as u64).await;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let peer = tokio::spawn(run_peer(
            addr,
            Arc::clone(&content),
            Script {
                advertise,
                serve: false,
                reveal_after_piece1: false,
            },
            Arc::clone(&requests),
        ));
        // Observation window: registration + advertisement + >=3 rounds
        // of 1s dispatch ticks. With a non-empty allowed set, also wait
        // until a request for an advertised piece actually arrives (ads
        // dispatch immediately, sub-second).
        let wait = if allowed.is_empty() {
            Duration::from_secs(4)
        } else {
            Duration::from_secs(6)
        };
        let deadline = tokio::time::Instant::now() + wait;
        while tokio::time::Instant::now() < deadline {
            let got = requests.lock().await;
            if !allowed.is_empty() && allowed.iter().any(|a| got.iter().any(|r| r.index == *a)) {
                break;
            }
            drop(got);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let got = requests.lock().await.clone();
        root.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), engine).await;
        peer.abort();
        let illicit: Vec<u32> = got
            .iter()
            .filter(|r| !allowed.contains(&r.index))
            .map(|r| r.index)
            .collect();
        assert!(
            illicit.is_empty(),
            "row `{name}`: requests for unadvertised pieces {illicit:?} (all: {got:?})"
        );
        assert_eq!(
            !got.is_empty(),
            !allowed.is_empty(),
            "row `{name}`: expected requests {allowed:?}, got {got:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

/// End to end (duplex): a single-peer swarm where every piece comes from
/// that peer — bitfield {1} serves piece 1; after piece 1 settles send
/// HAVE(0) -> the engine requests piece 0 immediately -> serve ->
/// Completed. Piece-0 requests are asserted to happen only after HAVE(0)
/// (advertisements join the candidate set immediately).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_peer_swarm_completes_from_advertised_pieces() {
    let content = Arc::new(content());
    let tmp = tmp_dir("e2e");
    let mut expected = Vec::new();
    for c in content.chunks(PIECE) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let (addr, root, engine) = spawn_engine(&tmp, expected, content.len() as u64).await;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let peer = tokio::spawn(run_peer(
        addr,
        Arc::clone(&content),
        Script {
            advertise: Advertise::Bitfield(&[1]), // only piece 1 advertised
            serve: true,
            reveal_after_piece1: true,
        },
        Arc::clone(&requests),
    ));
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out (download stuck)"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    peer.abort();
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got,
        content.as_slice(),
        "downloaded content must match the source"
    );

    let got = requests.lock().await.clone();
    assert!(
        got.iter().any(|r| r.index == 1),
        "piece 1 (bitfield-advertised) must receive requests"
    );
    assert!(
        got.iter().any(|r| r.index == 0),
        "piece 0 (revealed by HAVE) must receive requests"
    );
    assert!(
        got.iter().all(|r| r.index != 0 || r.after_reveal),
        "every piece 0 request must happen after HAVE(0) (advertisement-aware \
         immediacy): {got:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
