//! MSE engine wiring (engine-face regression).
//!
//! 1. `require_crypto_rejects_legacy_inbound`: with `--bt-require-crypto`,
//!    an inbound legacy handshake on the engine face is rejected
//!    (`bt::mse::accept_any` sniffing routes it ->
//!    `AcceptError::LegacyRejected`, cross-check
//!    `ReceiverMSEHandshakeCommand.cc`) — the connection is closed right
//!    after the peer sends its handshake, with no reply bytes;
//! 2. `forced_encryption_local_seeder_loop`: the forced-encryption local
//!    seeder chain closes the loop — the tracker returns the seeder -> the
//!    engine's outbound `bt::mse::connect` initiator negotiation (provide
//!    excludes plain) -> the BT handshake over the encrypted stream -> the
//!    ARC4 data face completes the single-piece download (Completed +
//!    matching content);
//! 3. `mse_inbound_duplex_handshake`: an inbound MSE client -> the engine
//!    sniffs and accepts -> the BT handshake completes over the encrypted
//!    stream -> the engine sends Interested (duplex proof).

use std::net::SocketAddr;
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::{Handshake, Reserved};
use taiji_bt::piece_id::Addressing;
use taiji_bt::{mse, peer};
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_io::mse::{self as io_mse, CryptoLevel, CryptoPolicy};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: u32 = 16384;
const INFO_HASH: [u8; 20] = [0x5a; 20];
/// Face content = an all-zero single piece (the expected SHA-1 matches the
/// seeder's served content).
const CONTENT: [u8; PIECE_LEN as usize] = [0u8; PIECE_LEN as usize];
const PEER_ID_ENGINE: [u8; 20] = *b"-TJ0001-ENGINEENGIN1";
const PEER_ID_CLIENT: [u8; 20] = *b"-TJ0001-CLIENT----42";

/// Test-face `Result` unwrap (lint forbids unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Unique tmp directory (pid + nanoseconds).
fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p40-mse-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// Single-piece v1 face config (expected = the whole-piece SHA-1 of
/// CONTENT).
fn v1_face_config() -> FaceConfig {
    FaceConfig {
        kind: FaceKind::V1,
        info_hash: INFO_HASH,
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: vec![0],
        piece_bytes: vec![u64::from(PIECE_LEN)],
        expected: vec![ExpectedPieceHash::V1(Sha1::digest(CONTENT).into())],
        plan_file_lengths: vec![u64::from(PIECE_LEN)],
        progress_file_lens: vec![u64::from(PIECE_LEN)],
        cross: Vec::new(),
        hash_files: None,
    }
}

/// Mock HTTP tracker: announce replies with interval=60 + an optional
/// seeder address (compact peers form). With Some(addr) the engine dials
/// the seeder via the tracker's Peers event.
async fn mock_tracker(seeder: Option<SocketAddr>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut chunk = [0u8; 512];
                loop {
                    if sock.read(&mut chunk).await.unwrap_or(0) == 0 {
                        break;
                    }
                    req.extend_from_slice(&chunk);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                // bencode dict keys ascending: interval < peers. peers is
                // 0 or 1 compact entry (4B IPv4 + 2B port).
                let mut peers = Vec::from(&b"5:peers0:e"[..]);
                if let Some(s) = seeder {
                    let SocketAddr::V4(v4) = s else {
                        panic!("test expects IPv4 seeder");
                    };
                    let mut compact = Vec::new();
                    compact.extend_from_slice(&v4.ip().octets());
                    compact.extend_from_slice(&v4.port().to_be_bytes());
                    peers = Vec::new();
                    peers.extend_from_slice(b"5:peers");
                    peers.extend_from_slice(compact.len().to_string().as_bytes());
                    peers.push(b':');
                    peers.extend_from_slice(&compact);
                    peers.push(b'e');
                }
                let mut body = Vec::from(&b"d8:intervali60e"[..]);
                body.extend_from_slice(&peers);
                let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

/// Reserves a free TCP port (binds then releases; the test needs to know
/// the engine's listening port — with the production listen_port=0 path
/// the port is opaque to outsiders).
async fn reserve_tcp_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let port = l.local_addr().unwrap_or_else(|e| panic!("{e}")).port();
    drop(l);
    port
}

async fn engine_cfg(port: u16, crypto: CryptoPolicy, seeder: Option<SocketAddr>) -> EngineConfig {
    let tracker = mock_tracker(seeder).await;
    EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: PEER_ID_ENGINE,
        announce: format!("http://{tracker}/announce"),
        listen_port: port,
        piece_len: PIECE_LEN,
        layout: ok(
            Layout::plan_v1_padded(
                &[PlanEntry {
                    path: std::path::PathBuf::from("blob.bin"),
                    length: u64::from(PIECE_LEN),
                    padding: false,
                }],
                PIECE_LEN,
            ),
            "layout",
        ),
        dest: tmp_dir("dest"),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput tier (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config()],
        crypto,
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        // Pre-existing test faces keep peer exchange off (zero change to
        // existing wire behavior).
        peer_exchange: false,
        // No ut_metadata serve face (BEP 10 out of scope here).
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,   // no NAT face in tests (EngineConfig::nat default)
        stats: None, // no metrics fed in tests (EngineConfig::stats default)
        webseeds: Vec::new(),
    }
}

fn require_crypto() -> CryptoPolicy {
    CryptoPolicy {
        require_crypto: true,
        min_level: CryptoLevel::Plain,
    }
}

/// 68B legacy handshake bytes (the peer's reserved carries no DHT bit).
fn legacy_handshake_bytes() -> Vec<u8> {
    Handshake {
        reserved: Reserved::aria2_default(),
        info_hash: INFO_HASH,
        peer_id: PEER_ID_CLIENT,
    }
    .encode()
    .to_vec()
}

/// Acceptance criterion 2: the require-crypto engine-face integration —
/// legacy inbound is rejected. After the peer sends its legacy handshake:
/// no reply bytes at all, and the engine closes the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn require_crypto_rejects_legacy_inbound() {
    let port = reserve_tcp_port().await;
    let root = CancellationToken::new();
    let engine = DownloadEngine::spawn(engine_cfg(port, require_crypto(), None).await, &root);

    // Once the engine has bound, strike it with the legacy handshake.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("connect engine: {e}"));
    sock.write_all(&legacy_handshake_bytes())
        .await
        .unwrap_or_else(|e| panic!("write legacy handshake: {e}"));

    // Rejection shape: the connection closes (EOF) or a read error, and a
    // 68B handshake reply never appears.
    let mut got = Vec::new();
    let mut chunk = [0u8; 128];
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() <= deadline,
            "engine did not close legacy inbound within 5s"
        );
        match tokio::time::timeout(Duration::from_millis(500), sock.read(&mut chunk)).await {
            Ok(Ok(0)) => break, // EOF: the rejection path (stream dropped).
            Ok(Ok(n)) => {
                got.extend_from_slice(&chunk[..n]);
                assert!(
                    got.len() < 68,
                    "under require-crypto the legacy inbound received a suspected \
                     handshake reply ({} bytes)",
                    got.len()
                );
            }
            Ok(Err(_)) => break, // connection error: equally a rejection face.
            Err(_) => {}         // single read timeout: keep waiting for the sniff/close.
        }
    }

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    ok(end, "engine join");
    let _ = std::fs::remove_dir_all(tmp_dir("cleanup"));
}

/// MSE seeder: TCP accept -> `io_mse::receive` (responder negotiation,
/// cross-check ReceiverMSEHandshakeCommand) -> server-side BT handshake
/// over the encrypted stream -> a minimal serve loop (interested ->
/// unchoke; request -> piece).
async fn run_mse_seeder(listener: tokio::net::TcpListener) {
    let (sock, _) = listener
        .accept()
        .await
        .unwrap_or_else(|e| panic!("accept: {e}"));
    let (negotiated, matched) = ok(
        io_mse::receive(
            sock,
            &[INFO_HASH],
            CryptoPolicy::optional(),
            Duration::from_secs(10),
        )
        .await,
        "mse receive",
    );
    assert_eq!(matched, 0);
    assert_eq!(
        negotiated.crypto,
        CryptoLevel::Arc4,
        "the require-crypto engine offers only ARC4 (provide excludes plain)"
    );
    let (mut stream, hs) = ok(
        peer::handshake_accept(
            negotiated.stream,
            &INFO_HASH,
            &PEER_ID_ENGINE,
            Reserved::aria2_default(),
            Duration::from_secs(10),
        )
        .await,
        "bt handshake accept over MSE",
    );
    assert_eq!(hs.peer_id, PEER_ID_ENGINE);
    // The seeder sends the full bitfield after its handshake (BEP 3; one
    // piece = 0b1000_0000). It previously advertised nothing and relied on
    // the dispatcher's blind-pick fallback — that fallback was removed with
    // advertisement-aware dispatch (cross-check libtorrent
    // request_blocks.cpp).
    let _ = stream.write_all(&[0, 0, 0, 2, 5, 0b1000_0000]).await;
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).await.is_err() {
            break;
        }
        match body[0] {
            2 => {
                // interested -> unchoke (BEP 3).
                let _ = stream.write_all(&[0, 0, 0, 1, 1]).await;
            }
            6 => {
                // request -> piece: header = id + index + begin (4+4,
                // echoed from the request frame), payload = CONTENT (the
                // BEP 3 piece frame shape).
                let mut frame = Vec::with_capacity(13 + CONTENT.len());
                frame.extend_from_slice(&((9 + CONTENT.len()) as u32).to_be_bytes());
                frame.push(7u8);
                frame.extend_from_slice(&body[1..9]);
                frame.extend_from_slice(&CONTENT);
                if stream.write_all(&frame).await.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
}

/// Engine-face regression: the forced-encryption local seeder chain closes
/// the loop — tracker Peers -> outbound MSE (require-crypto) -> the ARC4
/// data face -> Completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forced_encryption_local_seeder_loop() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let seeder = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let seeder_addr = seeder.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let seeder_task = tokio::spawn(run_mse_seeder(seeder));

    let port = reserve_tcp_port().await;
    let root = CancellationToken::new();
    let cfg = engine_cfg(port, require_crypto(), Some(seeder_addr)).await;
    let dest = cfg.dest.clone();
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = ok(end, "engine join");
    assert!(
        matches!(end, EngineEnd::Completed),
        "the forced-encryption closed loop must complete the download: got {end:?}"
    );

    let got = std::fs::read(dest.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got, CONTENT,
        "the MSE data-face download must match the source"
    );

    // The seeder's serve loop exits by itself once the engine winds down
    // (connection closed).
    let _ = tokio::time::timeout(Duration::from_secs(5), seeder_task).await;
    let _ = std::fs::remove_dir_all(dest);
}

/// Acceptance: MSE inbound duplex — a client MSE initiator -> the engine
/// sniffs and accepts -> the BT handshake completes over the encrypted
/// stream -> the engine sends Interested (proof of ciphertext carrying in
/// the engine -> client direction).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mse_inbound_duplex_handshake() {
    let port = reserve_tcp_port().await;
    let root = CancellationToken::new();
    // Optional crypto (the default face): inbound MSE is accepted as usual
    // (SPEC section 6.1, "accept both inbound").
    let engine = DownloadEngine::spawn(
        engine_cfg(port, CryptoPolicy::optional(), None).await,
        &root,
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("connect engine: {e}"));
    // Initiator negotiation (cross-check InitiatorMSEHandshakeCommand):
    // optional provides plain+arc4; the responder (the engine) may
    // legitimately choose plain or arc4 on its optional face.
    let negotiated = ok(
        io_mse::initiate(
            sock,
            INFO_HASH,
            CryptoPolicy::optional(),
            Duration::from_secs(10),
        )
        .await,
        "mse initiate",
    );
    let (mut stream, theirs) = ok(
        peer::handshake_exchange(
            negotiated.stream,
            &INFO_HASH,
            &PEER_ID_CLIENT,
            Reserved::aria2_default(),
            Duration::from_secs(10),
        )
        .await,
        "bt handshake exchange over MSE",
    );
    assert_eq!(
        theirs.peer_id, PEER_ID_ENGINE,
        "the engine's handshake reply identity"
    );

    // The engine's first message after attach = Interested (the
    // attach_peer registration order); reading it proves the engine-side
    // MSE ciphertext carrying + BT message face are duplex-capable.
    let mut frame = [0u8; 5];
    let _read = ok(
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut frame)).await,
        "read interested frame",
    );
    assert_eq!(
        frame,
        [0, 0, 0, 1, 2],
        "the engine's first message = Interested (BEP3 id=2)"
    );

    // The client sends PORT (BEP 5 id=9; the engine's DHT is off ->
    // port_tx None -> silently dropped; the connection must not drop or
    // trip).
    let mut port_frame = Vec::new();
    port_frame.extend_from_slice(&3u32.to_be_bytes());
    port_frame.push(9u8);
    port_frame.extend_from_slice(&6881u16.to_be_bytes());
    let _ = stream.write_all(&port_frame).await;
    // The connection stays alive: reading engine-direction again must not
    // EOF immediately (a keepalive period may carry no messages — a short
    // timeout probe showing the connection was not closed is enough).
    let mut probe = [0u8; 1];
    let closed = matches!(
        tokio::time::timeout(Duration::from_millis(300), stream.read(&mut probe)).await,
        Ok(Ok(0)) | Ok(Err(_))
    );
    assert!(
        !closed,
        "a PORT message must not drop the connection (silently dropped while DHT is off)"
    );

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    ok(end, "engine join");
    let _ = std::fs::remove_dir_all(tmp_dir("cleanup"));
}

/// Keeps the mse/peer module references alive (the module-level re-export
/// wiring face is the face under test).
#[test]
fn wired_modules_are_reachable() {
    let _ = mse::announce_crypto_param(CryptoPolicy::optional());
}
