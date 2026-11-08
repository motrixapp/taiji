//! Acceptance: discovery-source address hygiene wiring assertions
//! (tracker arm; audit / regression).
//!
//! Scenario (full engine_loop shape, all in-process): the fake tracker's
//! announce response carries —
//! 1. **positive control**: a real loopback peer (allowed class) -> the
//!    engine must dial and connect (proof that the announce ->
//!    handle_tracker_event -> spawn_peer_dial chain is alive; zero
//!    regression for allowed addresses);
//! 2. **negative 1 (v4 unspecified `0.0.0.0:<port>`)**: the kernel lands
//!    0.0.0.0 connections back on the local loopback — without the
//!    hygiene check the engine would dial into the sentinel listener;
//!    after the fix the hygiene check rejects and the sentinel sees zero
//!    connections (established connections linger in the accept backlog,
//!    so delayed observation still works -> the assertion is independent
//!    of injection timing);
//! 3. **negative 2 (v6 loopback `[::1]:<port>`)**: rejected via the
//!    `security::is_global_v6` classification (RFC 4291 §2.5.3);
//! 4. **negative 3 (v6 link-local `[fe80::1]:<port>`)**: rejected class
//!    (RFC 4291 §2.5.6; same rule as libtorrent peer_list.cpp) — in a
//!    no-route shape the connection is unreachable anyway; asserted as a
//!    classification-path check (weak observation, regression guard).
//!
//! The vehicle is the HTTP response's `peers6` field (the UDP 18-byte
//! vehicle merges into the same arm at the actor event surface — the
//! parse point is untouched; the consumption arm applies hygiene
//! uniformly).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: u32 = 16384;
/// Sentinel zero-connection observation window (negative connections
/// linger in the accept backlog and stay observable; the window only
/// needs to be on the order of the engine's dial delay).
const QUIET_WINDOW: Duration = Duration::from_secs(2);
/// Positive-control connection budget.
const POSITIVE_BUDGET: Duration = Duration::from_secs(20);

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-p122-tracker-hygiene-";
    P.iter().cycle().take(PIECE_LEN as usize).copied().collect()
}

fn v1_face_config(info_hash: [u8; 20], expected: Vec<ExpectedPieceHash>) -> FaceConfig {
    let content_len = PIECE_LEN as u64;
    FaceConfig {
        kind: FaceKind::V1,
        info_hash,
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: vec![0],
        piece_bytes: vec![content_len],
        expected,
        plan_file_lengths: vec![content_len],
        progress_file_lens: vec![content_len],
        cross: Vec::new(),
        hash_files: None,
    }
}

/// Shaped announce response (hand-assembled bencode; peers is a binary
/// byte string, no string formatting). `peers` = 6B per entry (BEP 3
/// compact), `peers6` = 18B per entry (BEP 32).
fn announce_body(peers: &[(Ipv4Addr, u16)], peers6: &[(Ipv6Addr, u16)]) -> Vec<u8> {
    let mut compact = Vec::new();
    for (ip, port) in peers {
        compact.extend_from_slice(&ip.octets());
        compact.extend_from_slice(&port.to_be_bytes());
    }
    let mut compact6 = Vec::new();
    for (ip, port) in peers6 {
        compact6.extend_from_slice(&ip.octets());
        compact6.extend_from_slice(&port.to_be_bytes());
    }
    let mut raw = Vec::from(&b"d8:intervali3600e5:peers"[..]);
    raw.extend_from_slice(compact.len().to_string().as_bytes());
    raw.push(b':');
    raw.extend_from_slice(&compact);
    raw.extend_from_slice(b"6:peers6");
    raw.extend_from_slice(compact6.len().to_string().as_bytes());
    raw.push(b':');
    raw.extend_from_slice(&compact6);
    raw.push(b'e');
    let mut out = Vec::new();
    out.extend_from_slice(
        format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len()).as_bytes(),
    );
    out.extend_from_slice(&raw);
    out
}

/// Fake tracker: answers every announce with the same shaped response.
async fn fake_tracker(body: Vec<u8>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("tracker bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
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
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

/// Positive-control peer: counts on handshake (the observation surface
/// for the announce -> arm -> dial chain's liveness), answers the
/// handshake and keeps the connection.
async fn spawn_positive_peer(ih: [u8; 20]) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("peer bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                assert_eq!(
                    &hs[28..48],
                    &ih,
                    "the handshake info_hash must match this swarm"
                );
                counter.fetch_add(1, Ordering::Relaxed);
                let mut resp = [0u8; 68];
                resp[0] = 19;
                resp[1..20].copy_from_slice(b"BitTorrent protocol");
                resp[27] = 0x04; // fast
                resp[28..48].copy_from_slice(&[9u8; 20]);
                resp[48..68].copy_from_slice(b"PEER------PEER------");
                let _ = sock.write_all(&resp).await;
                // Hold: read and discard frames until the peer closes.
                let mut sink = [0u8; 512];
                while sock.read(&mut sink).await.unwrap_or(0) > 0 {}
            });
        }
    });
    (addr, hits)
}

/// Silent sentinel: an observation surface that never accepts (without
/// the hygiene check, dialed connections linger in the accept backlog —
/// delayed observation is independent of injection timing).
async fn spawn_sentinel(bind: &str) -> (SocketAddr, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .unwrap_or_else(|e| panic!("sentinel bind {bind}: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    (addr, listener)
}

/// Sentinel zero-connection assertion: accept must not become ready
/// within the observation window.
async fn assert_zero_connections(listener: tokio::net::TcpListener, what: &str) {
    let deadline = tokio::time::Instant::now() + QUIET_WINDOW;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await {
            Err(_) => {} // no connection within the window (timeout = expected shape)
            Ok(Ok((_, peer))) => panic!(
                "{what} must be rejected by the hygiene check (observed a {peer} connection)"
            ),
            Ok(Err(e)) => panic!("{what} accept error: {e}"),
        }
    }
}

/// Tracker-arm wiring assertion: rejected-class addresses in the shaped
/// response get zero dials (sentinel zero connections), allowed-class
/// addresses connect as usual (positive control; embedded proof of zero
/// regression in the existing chain).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tracker_arm_hygiene_rejects_bogon_and_dials_legit() {
    let ih: [u8; 20] = Sha1::digest(b"p122-tracker-hygiene").into();
    let content = test_content();
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }

    // Positive-control peer (loopback real address = allowed class).
    let (pos, pos_hits) = spawn_positive_peer(ih).await;
    let IpAddr::V4(pos_v4) = pos.ip() else {
        panic!("test expects IPv4 loopback pos peer");
    };
    // Negative sentinel 1: v4 unspecified-address injection (0.0.0.0
    // lands back on the local loopback — the observable shape).
    let (neg_v4_addr, neg_v4_listener) = spawn_sentinel("127.0.0.1:0").await;
    // Negative sentinels 2+3: v6 loopback / link-local injection (the
    // peers6 vehicle).
    let (neg_v6_addr, neg_v6_listener) = spawn_sentinel("[::1]:0").await;

    // The mapped wrapper in peers6 (::ffff:127.0.0.1 -> pos): after
    // normalization it dials pos with the allowed class (chain proof;
    // the fix unifies wrapper and real-address family handling).
    let mapped_pos = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
    let link_local = Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let tracker = fake_tracker(announce_body(
        &[
            (Ipv4Addr::UNSPECIFIED, neg_v4_addr.port()),
            (pos_v4, pos.port()),
        ],
        &[
            (Ipv6Addr::LOCALHOST, neg_v6_addr.port()),
            (link_local, neg_v6_addr.port()),
            (mapped_pos, pos.port()),
        ],
    ))
    .await;

    let tmp = std::env::temp_dir().join(format!(
        "taiji-p122-tracker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));
    let layout = Layout::plan_v1_padded(
        &[PlanEntry {
            path: std::path::PathBuf::from("blob.bin"),
            length: content.len() as u64,
            padding: false,
        }],
        PIECE_LEN,
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let root = CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-HYGIENEHYGN1",
        announce: format!("http://{tracker}/announce"),
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config(ih, expected)],
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

    // Positive control: allowed-class addresses must dial and connect as
    // usual (chain liveness proof; also ensures the announce/dial batch
    // has happened before the sentinel assertions start — any
    // rejected-class leak would already sit in the backlog).
    let deadline = tokio::time::Instant::now() + POSITIVE_BUDGET;
    while pos_hits.load(Ordering::Relaxed) == 0 {
        if tokio::time::Instant::now() > deadline {
            root.cancel();
            panic!(
                "the positive-control peer did not connect within budget \
                 (broken announce → arm → dial chain)"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), engine).await;

    // Negative assertions: rejected-class addresses get zero dials
    // (sentinel zero connections).
    assert_zero_connections(neg_v4_listener, "v4 unspecified-address 0.0.0.0 injection").await;
    assert_zero_connections(neg_v6_listener, "v6 loopback/link-local injection").await;
    let _ = std::fs::remove_dir_all(&tmp);
}
