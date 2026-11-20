//! Acceptance (multi-listen phase): the `taiji.listen-interfaces`
//! declarative listen face — a real engine serving BT handshakes on
//! BOTH loopback faces (127.0.0.1 + [::1], the same port, the
//! dual-stack expansion shape), plus the default-unset zero-change
//! guard at the config level.
//!
//! The parse -> expand -> diff pipeline against injected interface
//! tables is unit-covered in the engine crate (`taiji_engine::listen`);
//! this file exercises the assembled face set end to end: an engine
//! configured with two listen-interface entries must accept and
//! handshake an inbound peer on each face's own address.

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{
    DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind, listen::ListenInterface,
};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;
const INFO_HASH: [u8; 20] = [7u8; 20];

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-listen-iface-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// v1-only single-face config (the engine_loop fixture shape).
fn v1_face_config(expected: Vec<ExpectedPieceHash>, content_len: u64) -> FaceConfig {
    FaceConfig {
        kind: FaceKind::V1,
        info_hash: INFO_HASH,
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

fn spec(s: &str) -> ListenInterface {
    let (mut out, errs) = taiji_core::engine::listen::parse_listen_interfaces(s);
    assert!(
        errs.is_empty(),
        "fixture spec `{s}` must parse cleanly: {errs:?}"
    );
    assert_eq!(out.len(), 1);
    out.remove(0)
}

/// Reserves one free port (bind :0, read, drop — the standard race
/// window; the engine re-binds within the same test task).
async fn free_port(bind: &str) -> u16 {
    let l = tokio::net::TcpListener::bind((bind, 0))
        .await
        .unwrap_or_else(|e| panic!("reserve on {bind}: {e}"));
    l.local_addr().unwrap_or_else(|e| panic!("{e}")).port()
}

/// The [::1] loopback socket address (SocketAddr form — no name
/// resolution; some sandboxed environments reject the string-form
/// getaddrinfo path for ::1 while the raw sockaddr binds fine).
fn lo6(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], port))
}

/// One inbound BT handshake against `addr`: connects (retrying while
/// the engine's assembly races the client — each refused connect is
/// retried until the deadline), sends the 68-byte handshake, and
/// asserts the engine answers with a handshake carrying the same
/// info_hash (the per-face "serves" proof — no tracker/DHT needed, the
/// face's own accept path + sniffing task do the work).
async fn handshake_face(addr: std::net::SocketAddr, label: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut sock = loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(s) => break s,
            Err(e) if tokio::time::Instant::now() < deadline => {
                // The engine assembly races the client; retry.
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = e;
            }
            Err(e) => panic!("{label}: connect {addr} kept failing: {e}"),
        }
    };
    let mut hs = [0u8; 68];
    hs[0] = 19;
    hs[1..20].copy_from_slice(b"BitTorrent protocol");
    hs[28..48].copy_from_slice(&INFO_HASH);
    hs[48..68].copy_from_slice(b"TESTPEERTESTPEER0000");
    sock.write_all(&hs)
        .await
        .unwrap_or_else(|e| panic!("{label}: send handshake: {e}"));
    let mut resp = [0u8; 68];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut resp))
        .await
        .unwrap_or_else(|_| {
            panic!("{label}: the engine handshake never arrived (face not serving on {addr})")
        })
        .unwrap_or_else(|e| panic!("{label}: read handshake: {e}"));
    assert_eq!(
        &resp[1..20],
        b"BitTorrent protocol",
        "{label}: protocol string"
    );
    assert_eq!(
        resp[28..48],
        INFO_HASH,
        "{label}: the engine echoes the face info_hash"
    );
}

/// Both loopback faces of one multi-listen engine serve inbound BT
/// handshakes on their own addresses (127.0.0.1 + [::1], same port —
/// the common `--taiji-listen-interfaces 127.0.0.1:P,[::1]:P` shape).
/// Environments without v6 (or where the second loopback alias is
/// unbindable) fall back to the two-v4-alias form (127.0.0.1 +
/// 127.0.0.2 — the whole 127/8 is loopback on macOS/Linux), which
/// additionally exercises the same-family secondary-face path; a
/// printed skip reason discloses whatever arm the environment cannot
/// run.
#[tokio::test]
async fn multi_listen_faces_serve_handshake_per_face() {
    // SocketAddr form throughout (the string form goes through
    // getaddrinfo, which some sandboxed test environments reject for
    // ::1 even though the raw sockaddr binds fine).
    let v6_ok = tokio::net::TcpListener::bind(lo6(0)).await.is_ok();
    let v4_alias_ok = tokio::net::TcpListener::bind(("127.0.0.2", 0))
        .await
        .is_ok();
    let second = if v6_ok {
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else if v4_alias_ok {
        eprintln!(
            "no IPv6 environment: the second face uses the 127.0.0.2 loopback alias \
             (the two-v4-alias form — also covers the same-family secondary-face path)"
        );
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2))
    } else {
        eprintln!(
            "no IPv6 and no 127.0.0.2 alias: only the single v4 face arm can run \
             (environment limitation, disclosed)"
        );
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    let dual = second != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let content = test_content();
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.extend_from_slice(&Sha1::digest(c));
    }
    let tmp = std::env::temp_dir().join(format!(
        "taiji-listen-iface-{}-{}",
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

    // One port for both faces (the same-port rule; the port is free at
    // this instant — the engine binds it right away).
    let port = free_port("127.0.0.1").await;
    let second_spec = match second {
        std::net::IpAddr::V6(_) => format!("[::1]:{port}"),
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
    };
    let specs = if dual {
        vec![spec(&format!("127.0.0.1:{port}")), spec(&second_spec)]
    } else {
        vec![spec(&format!("127.0.0.1:{port}"))]
    };

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        clock: Default::default(),
        rng: Default::default(),
        initial_selection: None,
        preset_progress: None,
        tracker_options: taiji_bt::tracker::TrackerOptions::default(),
        egress: None,
        // The option under test: the engine listens on one face per
        // entry (loopback v4 + loopback v6, same port).
        listen_interfaces: specs,
        peer_id: *b"-TJ0001-LISTENFACE10",
        announce: String::new(),
        listen_port: port,
        piece_len: PIECE_LEN,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config(roots, content.len() as u64)],
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

    // Both faces must serve: an inbound handshake per face address,
    // each answered with the engine's handshake (info_hash echo). The
    // engine idles (no tracker/DHT) — the accept paths are exercised
    // directly.
    handshake_face(
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
        "primary face (127.0.0.1)",
    )
    .await;
    if dual {
        handshake_face(std::net::SocketAddr::new(second, port), "second face").await;
    }

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(10), engine)
        .await
        .unwrap_or_else(|_| panic!("engine join timeout after cancel"));
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    // A cancelled idle engine ends through the shutdown path — never
    // Failed (assembly stood up: faces bound, actors spawned).
    assert!(
        !matches!(end, EngineEnd::Failed(_)),
        "idle multi-listen engine must not fail: {end:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Default-unset zero-change guard (config level): the fresh session
/// global carries an empty listen-interfaces table — the standing
/// single-wildcard listen shape. The whole existing suite is the
/// behavioral zero-drift proof; this pins the option default at the
/// session boundary (the engine-side `engine_config` default is pinned
/// by the engine crate's config tests).
#[test]
fn default_session_global_listen_interfaces_empty() {
    assert!(
        taiji_core::session::GlobalOptions::default()
            .listen_interfaces
            .is_empty(),
        "default = empty = the standing single-listen shape (zero change)"
    );
}

/// Ingress verification (the phase-3 accept-path face): with the
/// egress bind armed at `127.0.0.1`, an inbound connection arriving on
/// `[::1]` (the default dual-stack listener's v6 arm — its local
/// address `::1` is not on the egress allowlist) is rejected at the
/// door and counted (`taiji_peer_blocked_ingress_total`); the same
/// engine still serves the matching-local-address arm (127.0.0.1).
/// Without an egress bind nothing is verified — that arm is the
/// `multi_listen_faces_serve_handshake_per_face` test above (egress
/// None, both loopback families served) plus the standing suite.
#[tokio::test]
async fn egress_bind_rejects_and_counts_off_allowlist_inbound() {
    let v6_ok = tokio::net::TcpListener::bind(lo6(0)).await.is_ok();
    if !v6_ok {
        eprintln!(
            "no IPv6 environment: the [::1] rejection arm cannot run; \
             the 127.0.0.1 admit arm still runs (environment limitation, disclosed)"
        );
    }
    let content = test_content();
    let tmp = std::env::temp_dir().join(format!(
        "taiji-listen-ingress-{}-{}",
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
    let metrics = std::sync::Arc::new(taiji_core::engine::metrics::SessionMetrics::new());
    let port = free_port("127.0.0.1").await;
    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        clock: Default::default(),
        rng: Default::default(),
        initial_selection: None,
        preset_progress: None,
        tracker_options: taiji_bt::tracker::TrackerOptions::default(),
        // The option under test: the egress bind arms the ingress
        // verification (allowlist = exactly this address).
        egress: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        listen_interfaces: Vec::new(),
        peer_id: *b"-TJ0001-LISTENINGRES",
        announce: String::new(),
        listen_port: port,
        piece_len: PIECE_LEN,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config(roots, content.len() as u64)],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: Some(std::sync::Arc::clone(&metrics)),
        webseeds: Vec::new(),
    };
    let engine = DownloadEngine::spawn(cfg, &root);

    if v6_ok {
        // The rejected arm: connect to [::1], send the handshake — no
        // handshake may come back (the connection is dropped at the
        // accept door; EOF/reset, never an info_hash echo), and the
        // rejection is counted exactly once.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut sock = loop {
            match tokio::net::TcpStream::connect(lo6(port)).await {
                Ok(s) => break s,
                Err(e) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let _ = e;
                }
                Err(e) => panic!("[::1] connect kept failing: {e}"),
            }
        };
        let mut hs = [0u8; 68];
        hs[0] = 19;
        hs[1..20].copy_from_slice(b"BitTorrent protocol");
        hs[28..48].copy_from_slice(&INFO_HASH);
        hs[48..68].copy_from_slice(b"TESTPEERTESTPEER0000");
        sock.write_all(&hs)
            .await
            .unwrap_or_else(|e| panic!("send handshake on [::1]: {e}"));
        let mut resp = [0u8; 68];
        let read = tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut resp)).await;
        assert!(
            read.is_err() || read.unwrap_or_else(|e| panic!("read [::1]: {e}")).is_err(),
            "the off-allowlist inbound must NOT be answered with a handshake"
        );
        // The counter (one feed point per rejected connection): poll
        // briefly — the rejection happens at accept time, already
        // before the handshake write above was consumed.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while metrics.peer_blocked_ingress() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the [::1] rejection was never counted"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            metrics.peer_blocked_ingress(),
            1,
            "exactly one ingress rejection counted"
        );
    }

    // The admitted arm: local address 127.0.0.1 == the egress address
    // — the engine answers with its handshake (the serving proof).
    handshake_face(
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
        "admitted face (127.0.0.1 == egress)",
    )
    .await;
    if !v6_ok {
        assert_eq!(
            metrics.peer_blocked_ingress(),
            0,
            "no rejection counted on the admit-only environment"
        );
    }

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(10), engine)
        .await
        .unwrap_or_else(|_| panic!("engine join timeout after cancel"));
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        !matches!(end, EngineEnd::Failed(_)),
        "idle engine must not fail: {end:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
