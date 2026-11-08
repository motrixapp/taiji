//! Acceptance: DHT engine wiring (SPEC section 6.7).
//!
//! 1. `in_process_dht_swarm_announce_peers_found_dial`: full in-process
//!    DHT swarm chain — an independent DHT node B (real UDP/demux) plus a
//!    third-party announce injection -> engine bootstrap(entry=B) ->
//!    `DhtHandle::announce` -> get_peers iteration hits the values ->
//!    `DhtEvent::PeersFound` -> dial the seeder after dedup -> BT
//!    handshake + PORT message -> single-piece download Completed
//!    (announce -> PeersFound -> connection);
//! 2. `udp_tracker_announce_via_demux`: regression for the udp carrier
//!    swap — a UDP tracker announce (BEP 15 connect -> announce) rides
//!    both directions through the UdpDemux tracker channel (literal-IP
//!    udp:// URL), and the peer from the tracker reply is dialed;
//! 3. `dht_state_roundtrip`: `DhtEvent::Persist` -> UpsertDhtState ->
//!    restart `LoadDhtState` -> `load_dht_restore_state` ->
//!    `DhtRestoreState` -> node ID continuous across restarts
//!    (DHTSetup.cc keeps the persisted ID).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::dht::message::{
    QueryBody, QueryMessage, ResponseBody, WantFamilies, decode_message, encode_message,
};
use taiji_bt::dht::{
    self as dht_mod, DhtEngineConfig, DhtFamily, DhtTransport, NodeId, forward_outbound,
    spawn_dht_engine,
};
use taiji_bt::peer_wire::{Handshake, Reserved};
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{
    DhtWireConfig, DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind,
    load_dht_restore_state,
};
use taiji_io::udp_demux::{self, DemuxConfig};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use taiji_store::persist::PersistWriter;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const PIECE_LEN: u32 = 16384;
const INFO_HASH: [u8; 20] = [0x42; 20];
/// Face content = one piece of fixed bytes (seeder serves the same bytes
/// as `expected`).
const CONTENT: [u8; PIECE_LEN as usize] = [0x5a; PIECE_LEN as usize];
const PEER_ID_ENGINE: [u8; 20] = *b"-TJ0001-ENGINEENGIN1";
/// Test-face `Result` unwrap (lint forbids unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// `dht_state.node_id` column (BLOB) -> 20B array.
fn arr20(v: &[u8]) -> [u8; 20] {
    <[u8; 20]>::try_from(v).unwrap_or_else(|_| panic!("node_id must be 20 bytes"))
}

/// Unique tmp directory (pid + nanoseconds).
fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p40-dht-{}-{}-{}",
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

/// Single-piece v1 face config.
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

/// Mock HTTP tracker: announce replies with interval=60 + optional peer
/// (compact).
async fn mock_tracker(peer: Option<SocketAddr>) -> SocketAddr {
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
                let mut peers = Vec::from(&b"5:peers0:e"[..]);
                if let Some(p) = peer {
                    let SocketAddr::V4(v4) = p else {
                        panic!("test expects IPv4");
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

/// Reserves a free TCP port (a knowable engine listen_port).
async fn reserve_tcp_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let port = l.local_addr().unwrap_or_else(|e| panic!("{e}")).port();
    drop(l);
    port
}

/// Standalone DHT node (bt::dht engine over a real loopback UDP/demux
/// carrier; topology same as the bt::dht engine tests' spawn_udp_engine).
async fn spawn_dht_node(
    cfg: DhtEngineConfig,
) -> (dht_mod::DhtHandle, SocketAddr, CancellationToken) {
    let shutdown = CancellationToken::new();
    let (channels, demux) = ok(
        udp_demux::spawn(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DemuxConfig::default(),
            shutdown.clone(),
        )
        .await,
        "bind node demux",
    );
    let bound = demux.bound_addr();
    let (event_tx, _event_rx) = mpsc::channel(64);
    let (out_tx, out_rx) = mpsc::channel(256);
    let transport = DhtTransport {
        inbound: channels.dht,
        outbound: out_tx,
    };
    let (handle, _join) =
        spawn_dht_engine(DhtFamily::V4, bound.port(), cfg, transport, None, event_tx);
    forward_outbound(out_rx, demux);
    (handle, bound, shutdown)
}

/// Drives the engine's internal timer table at millisecond scale
/// (bootstrap retries / announce resends); transaction timeout and record
/// sanitization stay loose (loopback replies arrive in microseconds —
/// shortening them would only create late drops, and the 30 min peer
/// record TTL never fires on a test time scale).
fn fast_engine_cfg() -> DhtEngineConfig {
    DhtEngineConfig {
        message_timeout: Duration::from_secs(3),
        bootstrap_ping_retry: 2,
        refresh_check_interval: Duration::from_millis(500),
        peer_announce_check_interval: Duration::from_millis(500),
        token_rotate_interval: Duration::from_secs(600),
        autosave_interval: Duration::from_millis(300),
        peer_announce_interval: Duration::from_millis(500),
        peer_announce_purge_interval: Duration::from_secs(600),
        // Defaults for newer fields (this file issues single-digit query
        // volume; zero behavior change).
        ..DhtEngineConfig::default()
    }
}

/// Seeder: BT handshake (asserts the reserved DHT bit + PORT message) ->
/// unchoke -> serves the single piece. Returns the snapshot channel for
/// (handshake received, PORT port received).
async fn run_dht_seeder(
    listener: tokio::net::TcpListener,
    report: Arc<Mutex<(Option<Handshake>, Option<u16>)>>,
) {
    let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
    let mut hs = [0u8; 68];
    ok(sock.read_exact(&mut hs).await, "seeder read handshake");
    let handshake = ok(Handshake::decode(&hs), "seeder decode handshake");
    assert_eq!(
        handshake.info_hash, INFO_HASH,
        "the swarm identity of the DHT-established connection"
    );
    assert!(
        handshake.reserved.supports_dht(),
        "a DHT-enabled engine handshake must carry reserved[7]&0x01"
    );
    // Server handshake reply (BEP 3; reserved = fast + ext + DHT bit).
    let mut resp = [0u8; 68];
    resp[0] = 19;
    resp[1..20].copy_from_slice(b"BitTorrent protocol");
    resp[25] = 0x10; // extended
    resp[27] = 0x05; // fast | dht
    resp[28..48].copy_from_slice(&INFO_HASH);
    resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
    ok(sock.write_all(&resp).await, "seeder write handshake");
    // The seeder sends the full bitfield right after its handshake (BEP 3;
    // one piece = 0b1000_0000). It previously advertised nothing and relied
    // on the dispatcher's blind-pick fallback — that fallback was removed
    // with advertisement-aware dispatch (cross-check libtorrent
    // request_blocks.cpp); the test tracks the real behavior.
    ok(
        sock.write_all(&[0, 0, 0, 2, 5, 0b1000_0000]).await,
        "seeder write bitfield",
    );
    // Serve loop: interested -> unchoke; PORT -> record; request -> piece.
    let mut port_seen = None;
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
                let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
            }
            9 => {
                // PORT (BEP 5): carried after the handshake
                // (DefaultBtInteractive.cc).
                port_seen = Some(u16::from_be_bytes([body[1], body[2]]));
            }
            6 => {
                let mut frame = Vec::with_capacity(13 + CONTENT.len());
                frame.extend_from_slice(&((9 + CONTENT.len()) as u32).to_be_bytes());
                frame.push(7u8);
                frame.extend_from_slice(&body[1..9]);
                frame.extend_from_slice(&CONTENT);
                if sock.write_all(&frame).await.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
    let mut r = report.lock().unwrap_or_else(|e| e.into_inner());
    *r = (Some(handshake), port_seen);
}

/// Third-party announce injection (against B): get_peers fetches the
/// token, then announce_peer records the seeder address (KRPC queries
/// built with the bt::dht codec, BEP 5 message order).
async fn announce_to_node(node: SocketAddr, target: [u8; 20], seeder_port: u16) {
    let sock = ok(UdpSocket::bind("127.0.0.1:0").await, "announcer bind");
    let my_id = NodeId([0x11; 20]);
    // 1) get_peers -> fetch the token.
    let query = QueryMessage {
        transaction_id: vec![1, 2, 3, 4],
        sender_id: my_id,
        body: QueryBody::GetPeers {
            info_hash: NodeId(target),
            want: WantFamilies::default(),
        },
        version: None,
    };
    let wire = ok(
        encode_message(&dht_mod::DhtMessage::Query(query)),
        "encode get_peers",
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let token = loop {
        assert!(
            std::time::Instant::now() <= deadline,
            "get_peers to node timed out"
        );
        let _ = sock.send_to(&wire, node).await;
        let mut buf = [0u8; 2048];
        let n = match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf))
            .await
        {
            Ok(Ok((n, _))) => n,
            _ => continue,
        };
        if let Ok(dht_mod::DhtMessage::Response(resp)) = decode_message(&buf[..n])
            && resp.transaction_id == vec![1, 2, 3, 4]
            && let ResponseBody::GetPeers { token, .. } = resp.body
        {
            break token;
        }
    };
    // 2) announce_peer (records the seeder address after token check,
    // BEP 5).
    let query = QueryMessage {
        transaction_id: vec![5, 6, 7, 8],
        sender_id: my_id,
        body: QueryBody::AnnouncePeer {
            info_hash: NodeId(target),
            port: seeder_port,
            token,
            implied_port: Some(false),
        },
        version: None,
    };
    let wire = ok(
        encode_message(&dht_mod::DhtMessage::Query(query)),
        "encode announce_peer",
    );
    let _ = sock.send_to(&wire, node).await;
    // announce_peer carries no distinct reply payload (id-only response):
    // wait for the record to take effect.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Acceptance test 3: full in-process DHT swarm chain (announce ->
/// PeersFound -> connection -> PORT -> download completed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_process_dht_swarm_announce_peers_found_dial() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    // Seeder (TCP listener; reports handshake/PORT observations).
    let seeder = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let report: Arc<Mutex<(Option<Handshake>, Option<u16>)>> = Arc::new(Mutex::new((None, None)));
    let seeder_task = tokio::spawn({
        let report = Arc::clone(&report);
        async move { run_dht_seeder(seeder, report).await }
    });

    // DHT node B (standalone instance outside the engine; bootstrap
    // entry).
    let (_node_b, node_b_addr, node_b_shutdown) = spawn_dht_node(fast_engine_cfg()).await;

    // Inject the announce first and confirm B has recorded it (a single
    // engine announce then hits — deterministic).
    announce_to_node(node_b_addr, INFO_HASH, seeder_addr.port()).await;

    // Engine: v1 face + DHT enabled (entry = B; millisecond timers).
    let tracker = mock_tracker(None).await;
    let port = reserve_tcp_port().await;
    let dht_cfg = DhtWireConfig {
        enabled: true,
        entry_points_v4: vec![format!("127.0.0.1:{}", node_b_addr.port())],
        entry_points_v6: Vec::new(),
        engine: fast_engine_cfg(),
        announce_interval: Duration::from_millis(600),
    };
    let root = CancellationToken::new();
    let cfg = EngineConfig {
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
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: dht_cfg,
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
    };
    let dest = cfg.dest.clone();
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(180), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = ok(end, "engine join");
    assert!(
        matches!(end, EngineEnd::Completed),
        "the download must complete via the DHT-discovered peer: got {end:?}"
    );

    // Connection evidence: the seeder saw a handshake with the DHT bit +
    // a PORT message (port = the engine's DHT UDP port = the listen port,
    // same port for TCP/UDP).
    //
    // The report is written only after the seeder's serve loop exits
    // (engine Completed winding down -> connection closed -> seeder reads
    // EOF -> break -> write report). There is no happens-before between
    // "engine Completed returned" and "seeder has written the report", so
    // waiting on the seeder task establishes the observation sync (the
    // timeout is only a safe upper bound for the join). The behavior under
    // test is unchanged.
    let _ = tokio::time::timeout(Duration::from_secs(15), seeder_task).await;
    let observed = report.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (hs, dht_port) = observed;
    assert!(
        hs.is_some(),
        "the seeder must receive the engine handshake (DHT-established connection)"
    );
    let port_val = dht_port.unwrap_or_else(|| panic!("the seeder must receive the PORT message"));
    assert_ne!(port_val, 0, "the PORT payload is our own DHT port");
    assert_eq!(
        port_val, port,
        "the PORT payload = listen-port (TCP/UDP share the port)"
    );

    let got = std::fs::read(dest.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got, CONTENT,
        "content downloaded via the DHT-discovered peer matches"
    );

    // The seeder task was joined in the observation sync above; no abort
    // needed.
    node_b_shutdown.cancel();
    let _ = std::fs::remove_dir_all(dest);
}

/// Acceptance test 4: tracker UDP announce regression after the udp
/// carrier swap — BEP 15 connect -> announce rides the UdpDemux tracker
/// channel both ways, and the peer from the reply is dialed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_tracker_announce_via_demux() {
    // Seeder listener (the peer the tracker replies with; the engine
    // dialing it proves the demux downstream path).
    let seeder = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder.local_addr().unwrap_or_else(|e| panic!("{e}"));

    // Mock UDP tracker (BEP 15): connect (magic/action=0) -> reply conn
    // id; announce (action=1) -> record info_hash + reply interval/peers.
    let tx = Arc::new(Mutex::new(0u32));
    let udp = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}")),
    );
    let tracker_addr = udp.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let seen_announces: Arc<Mutex<Vec<[u8; 20]>>> = Arc::new(Mutex::new(Vec::new()));
    let tracker_task = tokio::spawn({
        let udp = Arc::clone(&udp);
        let seen = Arc::clone(&seen_announces);
        async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    return;
                };
                // connect request = magic(8)+action(4)+txid(4); announce
                // request = connection_id(8)+action(4)+txid(4)+... (BEP 15:
                // action always sits at [8..12]; whether the header starts
                // with the magic distinguishes the request type).
                let magic: [u8; 8] = [0, 0, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80];
                let head: [u8; 8] = buf[..8].try_into().unwrap_or([0xff; 8]);
                if head != magic && head != 0x1234_5678_9abc_u64.to_be_bytes() {
                    continue;
                }
                if n < 16 {
                    continue;
                }
                let action = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let txid = [buf[12], buf[13], buf[14], buf[15]];
                match action {
                    0 => {
                        // connect reply: action + txid + connection_id.
                        let mut reply = Vec::new();
                        reply.extend_from_slice(&0u32.to_be_bytes());
                        reply.extend_from_slice(&txid);
                        reply.extend_from_slice(&0x1234_5678_9abc_u64.to_be_bytes());
                        let _ = udp.send_to(&reply, from).await;
                    }
                    1 => {
                        // announce reply: action + txid + interval +
                        // leechers + seeds + peers (compact).
                        let ih: [u8; 20] = buf[16..36].try_into().unwrap_or([0; 20]);
                        seen.lock().unwrap_or_else(|e| e.into_inner()).push(ih);
                        let SocketAddr::V4(v4) = seeder_addr else {
                            panic!("test expects IPv4");
                        };
                        let mut reply = Vec::new();
                        reply.extend_from_slice(&1u32.to_be_bytes());
                        reply.extend_from_slice(&txid);
                        reply.extend_from_slice(&60u32.to_be_bytes());
                        reply.extend_from_slice(&0u32.to_be_bytes());
                        reply.extend_from_slice(&1u32.to_be_bytes());
                        reply.extend_from_slice(&v4.ip().octets());
                        reply.extend_from_slice(&v4.port().to_be_bytes());
                        let _ = udp.send_to(&reply, from).await;
                    }
                    _ => {}
                }
                let mut t = tx.lock().unwrap_or_else(|e| e.into_inner());
                *t += 1;
            }
        }
    });

    let port = reserve_tcp_port().await;
    let root = CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: PEER_ID_ENGINE,
        announce: format!("udp://{tracker_addr}/announce"),
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
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: DhtWireConfig::default(),
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
    };
    let engine = DownloadEngine::spawn(cfg, &root);

    // The tracker side saw the announce (outbound rides the demux ->
    // shared socket).
    let announced = {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if std::time::Instant::now() > deadline {
                break false;
            }
            if !seen_announces
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
            {
                break true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    assert!(
        announced,
        "the UDP tracker announce must reach the tracker via the demux"
    );

    // The peer from the tracker reply is dialed (inbound demux tracker
    // channel -> actor -> Peers).
    let dialed = tokio::time::timeout(Duration::from_secs(15), seeder.accept()).await;
    assert!(
        dialed.is_ok(),
        "the tracker reply's peer must be dialed by the engine via the demux fan-out"
    );

    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(30), engine).await;
    tracker_task.abort();
    let _ = std::fs::remove_dir_all(tmp_dir("cleanup"));
}

/// Acceptance test 5: dht_state restart roundtrip — Persist -> row ->
/// read back after restart -> restored node ID continuous.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dht_state_roundtrip() {
    // sqlite + engine (DHT enabled, autosave 300 ms, unreachable entry =
    // the table is saved even when empty).
    let db = tmp_dir("db").join("taiji.sqlite3");
    let (persist, _writer) = ok(PersistWriter::spawn(db.clone()).await, "persist spawn");
    let tracker = mock_tracker(None).await;
    let port = reserve_tcp_port().await;
    let dht_cfg = DhtWireConfig {
        enabled: true,
        entry_points_v4: vec!["127.0.0.1:9".to_string()], // discard port, unreachable.
        entry_points_v6: Vec::new(),
        engine: fast_engine_cfg(),
        announce_interval: Duration::from_secs(600),
    };
    let root = CancellationToken::new();
    let cfg = EngineConfig {
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
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: dht_cfg,
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
    };
    let engine = DownloadEngine::spawn_with(
        cfg,
        taiji_core::engine::TrackerWireConfig {
            tiers: Vec::new(),
            persist: Some(("8000000000000042".to_string(), persist.clone())),
            guard: None,
        },
        &root,
    );
    // autosave (300 ms) + the bootstrap failure path run; then shutdown
    // (halt-save).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(40), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));

    // The v4 row persisted by session 1 (node_id = the engine's local ID;
    // autosave/halt fires at least once).
    let row = tokio::time::timeout(Duration::from_secs(5), persist.load_dht_state("v4"))
        .await
        .unwrap_or_else(|_| panic!("load timed out"))
        .ok()
        .flatten();
    let row = row.unwrap_or_else(|| panic!("the dht_state v4 row must exist after autosave/halt"));
    assert_eq!(row.node_id.len(), 20, "node_id is 20 bytes");
    assert!(
        !row.routing_table.is_empty(),
        "the routing_table's own BLOB is non-empty (an empty table still encodes a header)"
    );

    // Restart read-back: row -> DhtRestoreState (node_id reused,
    // DHTSetup.cc).
    let restore = load_dht_restore_state(&persist, DhtFamily::V4)
        .await
        .unwrap_or_else(|| panic!("load_dht_restore_state must restore the row payload"));
    assert_eq!(
        restore.node_id,
        NodeId(arr20(&row.node_id)),
        "the restored node ID = the persisted node ID"
    );

    // Feed the payload into a bt::dht engine: the snapshot node ID is
    // continuous (the read-back face reaches through to the protocol
    // stack).
    let (handle, _addr, shutdown) = spawn_dht_node(fast_engine_cfg()).await;
    let _ = handle; // spawn_dht_node has no restore injection face — verified by the independent spawn below
    drop(handle);
    shutdown.cancel();
    let (restore_handle, _ev_rx) = {
        let shutdown2 = CancellationToken::new();
        let (channels, demux) = ok(
            udp_demux::spawn(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                DemuxConfig::default(),
                shutdown2,
            )
            .await,
            "bind restore demux",
        );
        let bound = demux.bound_addr();
        let (ev_tx, ev_rx) = mpsc::channel(64);
        let (out_tx, out_rx) = mpsc::channel(256);
        let (h, _j) = spawn_dht_engine(
            DhtFamily::V4,
            bound.port(),
            fast_engine_cfg(),
            DhtTransport {
                inbound: channels.dht,
                outbound: out_tx,
            },
            Some(restore),
            ev_tx,
        );
        forward_outbound(out_rx, demux);
        (h, ev_rx)
    };
    let snap = tokio::time::timeout(Duration::from_secs(5), restore_handle.snapshot())
        .await
        .unwrap_or_else(|_| panic!("snapshot timed out"))
        .ok()
        .unwrap_or_else(|| panic!("snapshot ok"));
    assert_eq!(
        snap.node_id,
        arr20(&row.node_id),
        "the restored engine's node ID = the previous session's persisted ID \
         (roundtrip closed)"
    );
}

/// Keeps the HashSet import referenced (single-peer dedup engine behavior
/// is covered by test 1's chain; the multi-source dedup window lives in
/// engine.rs DialDedup unit tests).
#[allow(dead_code)]
fn _dedup_type_referenced(_s: &HashSet<u8>) {}

// ===========================================================================
// Discovery source-address hygiene — DHT arm wiring assertions.
// ===========================================================================

/// Fake DHT node (raw UDP/KRPC): answers get_peers with attacker-chosen
/// values — a real bt::dht node's peer records only ever carry announcer
/// source addresses (the local topology is always loopback), so arbitrary
/// value shapes cannot be injected; this fake node makes malicious values
/// a testable input. Message order cross-checked against BEP 5
/// (ping/find_node/get_peers responses; the token is arbitrary — only the
/// later announce_peer check consumes it, not the PeersFound path).
async fn spawn_fake_dht_node(
    values: Vec<SocketAddr>,
) -> (
    SocketAddr,
    CancellationToken,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    let shutdown = CancellationToken::new();
    let sock = ok(UdpSocket::bind("127.0.0.1:0").await, "fake node bind");
    let addr = ok(sock.local_addr(), "fake node addr");
    let my_id = NodeId([0x77; 20]);
    let get_peers_hits = std::sync::Arc::new(AtomicUsize::new(0));
    let hits = std::sync::Arc::clone(&get_peers_hits);
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    got = sock.recv_from(&mut buf) => {
                        let Ok((n, src)) = got else { return };
                        let Ok(dht_mod::DhtMessage::Query(q)) = decode_message(&buf[..n])
                        else {
                            continue;
                        };
                        let body = match q.body {
                            QueryBody::Ping => ResponseBody::Ping,
                            QueryBody::FindNode { .. } => {
                                ResponseBody::FindNode { nodes: Vec::new() }
                            }
                            QueryBody::GetPeers { .. } => {
                                hits.fetch_add(1, AtomicOrdering::Relaxed);
                                ResponseBody::GetPeers {
                                    token: vec![0xAA, 0xBB],
                                    nodes: Vec::new(),
                                    values: values.clone(),
                                }
                            }
                            QueryBody::AnnouncePeer { .. } => ResponseBody::Ping,
                        };
                        let resp = dht_mod::DhtMessage::Response(
                            taiji_bt::dht::message::ResponseMessage {
                                transaction_id: q.transaction_id,
                                responder_id: my_id,
                                body,
                                requester_endpoint: None,
                                version: None,
                            },
                        );
                        if let Ok(frame) = encode_message(&resp) {
                            let _ = sock.send_to(&frame, src).await;
                        }
                    }
                }
            }
        }
    });
    (addr, shutdown, get_peers_hits)
}

/// Sentinel zero-connection assertion: accept must not become ready
/// within the window (without the hygiene check the dialed connection
/// would sit in the accept backlog — observing the delay is independent
/// of injection timing).
async fn assert_sentinel_zero_connections(listener: tokio::net::TcpListener, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await {
            Err(_) => {} // no connection within the window (timeout = expected)
            Ok(Ok((_, peer))) => panic!(
                "{what} must be rejected by the hygiene check (observed a {peer} connection)"
            ),
            Ok(Err(e)) => panic!("{what} accept error: {e}"),
        }
    }
}

/// DHT arm wiring assertion: get_peers values inject {v4 unspecified
/// address (observable kernel fallback to loopback), v6 loopback} plus a
/// positive loopback control — reject-class addresses dial nothing
/// (sentinel zero connections), allow-class connects and completes the
/// single-piece download as usual (announce -> PeersFound -> in-arm
/// hygiene -> dial, proving the whole chain stays alive; zero regression
/// on the existing chain is built in).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dht_peers_found_hygiene_rejects_bogon_values_p122() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // Positive-control seeder (loopback truth, allow class).
    let seeder = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let report: Arc<Mutex<(Option<Handshake>, Option<u16>)>> = Arc::new(Mutex::new((None, None)));
    let seeder_task = tokio::spawn({
        let report = Arc::clone(&report);
        async move { run_dht_seeder(seeder, report).await }
    });
    // Negative sentinel: v4 unspecified address (0.0.0.0 -> the
    // observable kernel fallback to this host).
    let neg_v4 = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let neg_v4_port = neg_v4.local_addr().unwrap_or_else(|e| panic!("{e}")).port();

    // Malicious values injection (fake node). A v4-carried get_peers
    // response may only carry 6B (v4) values per BEP 32 (the codec guards
    // mixed lists by same-address-family, same rule as aria2/libtorrent) —
    // the v6 loopback shape is asserted in the tracker arm (peers6), so
    // this injects the v4 reject class + the positive-control truth.
    let values = vec![SocketAddr::from(([0, 0, 0, 0], neg_v4_port)), seeder_addr];
    let (fake_node, fake_shutdown, get_peers_hits) = spawn_fake_dht_node(values).await;

    // Engine: v1 face + DHT enabled (entry = fake node; millisecond
    // timers).
    let tracker = mock_tracker(None).await;
    let port = reserve_tcp_port().await;
    let dht_cfg = DhtWireConfig {
        enabled: true,
        entry_points_v4: vec![format!("127.0.0.1:{}", fake_node.port())],
        entry_points_v6: Vec::new(),
        engine: fast_engine_cfg(),
        announce_interval: Duration::from_millis(600),
    };
    let root = CancellationToken::new();
    let cfg = EngineConfig {
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
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config()],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: dht_cfg,
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    let dest = cfg.dest.clone();
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "engine timed out (fake node get_peers hits = {})",
                get_peers_hits.load(std::sync::atomic::Ordering::Relaxed)
            )
        });
    root.cancel();
    let end = ok(end, "engine join");
    assert!(
        matches!(end, EngineEnd::Completed),
        "positive control: allow-class addresses in values must connect and \
         complete the download as usual: got {end:?}"
    );
    // Seeder task join (observation sync, same as test 1 — guards against
    // report write-ordering races).
    let seeder_join = tokio::time::timeout(Duration::from_secs(15), seeder_task).await;
    assert!(
        matches!(seeder_join, Ok(Ok(()))),
        "the seeder task must finish cleanly (all handshake/PORT assertions passed)"
    );

    // Non-vacuousness proof: the engine's lookup actually reached the fake
    // node (the get_peers injection was consumed).
    assert!(
        get_peers_hits.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "the fake node must receive get_peers queries (liveness of the values injection path)"
    );
    // Negative assertion: reject-class addresses dial nothing (sentinel
    // zero connections).
    assert_sentinel_zero_connections(
        neg_v4,
        "DHT values v4 unspecified-address 0.0.0.0 injection",
    )
    .await;
    fake_shutdown.cancel();
    let _ = std::fs::remove_dir_all(dest);
}

// ---------------------------------------------------------------------------
// DHT runtime hot toggle (SetDhtEnabled engine command face)
// ---------------------------------------------------------------------------

/// Revival sequence e2e (engine-face anchored): DHT off + trackerless ->
/// the engine stalls (no discovery source at all) -> `SetDhtEnabled(true)`
/// hot-enables -> the DHT engine warms up + an immediate announce
/// registers -> PeersFound -> dial the seeder -> download completes. The
/// engine is never rebuilt (existing connections/progress untouched —
/// same rule as libtorrent apply_settings).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_enable_revives_stalled_trackerless_engine() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    // Seeder (the DHT discovery target).
    let seeder = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let seeder_task = tokio::spawn(run_dht_seeder(seeder, Arc::new(Mutex::new((None, None)))));

    // DHT node B (bootstrap entry) + pre-injected announce (the engine's
    // first announce after hot-enable hits immediately — deterministic).
    let (_node_b, node_b_addr, node_b_shutdown) = spawn_dht_node(fast_engine_cfg()).await;
    announce_to_node(node_b_addr, INFO_HASH, seeder_addr.port()).await;

    // Engine: v1 face + DHT off + trackerless (empty announce + empty
    // tiers = the stalled shape; the hot-toggle target).
    let port = reserve_tcp_port().await;
    let dht_cfg = DhtWireConfig {
        enabled: false,
        entry_points_v4: vec![format!("127.0.0.1:{}", node_b_addr.port())],
        entry_points_v6: Vec::new(),
        engine: fast_engine_cfg(),
        announce_interval: Duration::from_millis(600),
    };
    let root = CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: PEER_ID_ENGINE,
        announce: String::new(),
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
        dest: tmp_dir("hot-enable"),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config()],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: dht_cfg,
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    let dest = cfg.dest.clone();
    let (handle, engine) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig::default(),
        &root,
        taiji_bt::utp::PeerConnectionType::default(),
    );

    // Hot enable (double send = two Oks, idempotent).
    ok(handle.enable_dht().await, "hot enable dht");
    ok(handle.enable_dht().await, "hot enable dht (idempotent)");

    // Revival assertion: announce registers -> PeersFound -> connection ->
    // single piece completes.
    let end = tokio::time::timeout(Duration::from_secs(120), engine)
        .await
        .unwrap_or_else(|_| panic!("engine did not revive after hot enable"));
    root.cancel();
    let end = ok(end, "engine join");
    assert!(
        matches!(end, EngineEnd::Completed),
        "after hot-enable the engine must revive via DHT discovery and complete \
         the download: got {end:?}"
    );
    let got = std::fs::read(dest.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got, CONTENT,
        "content downloaded via the DHT-discovered peer matches"
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), seeder_task).await;
    node_b_shutdown.cancel();
    let _ = std::fs::remove_dir_all(dest);
}

/// Hot-disable + re-enable arms (idempotence / reversibility): a DHT-on
/// engine -> `SetDhtEnabled(false)` = Ok (unwires after halt-save) ->
/// repeated disable = Ok (idempotent) -> re-enable = Ok (the cold-wiring
/// gate is reusable — repeated toggles within one engine lifetime,
/// mirroring libtorrent apply_settings flipping any number of times).
/// Disable-face behavior (announce removal / handshake-bit clearing) is
/// covered by halt-save/gate unit paths; this test pins command-face
/// reversibility.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_disable_then_reenable_is_reversible_and_idempotent() {
    let (_node_b, node_b_addr, node_b_shutdown) = spawn_dht_node(fast_engine_cfg()).await;
    let port = reserve_tcp_port().await;
    let dht_cfg = DhtWireConfig {
        enabled: true,
        entry_points_v4: vec![format!("127.0.0.1:{}", node_b_addr.port())],
        entry_points_v6: Vec::new(),
        engine: fast_engine_cfg(),
        announce_interval: Duration::from_millis(600),
    };
    let root = CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: PEER_ID_ENGINE,
        announce: String::new(),
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
        dest: tmp_dir("hot-toggle"),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config()],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: dht_cfg,
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    let dest = cfg.dest.clone();
    let (handle, engine) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig::default(),
        &root,
        taiji_bt::utp::PeerConnectionType::default(),
    );
    // Disable -> idempotent disable -> re-enable -> idempotent re-enable:
    // four Oks in a row (reversible + idempotent).
    ok(handle.disable_dht().await, "hot disable");
    ok(handle.disable_dht().await, "hot disable (idempotent)");
    ok(handle.enable_dht().await, "re-enable after disable");
    ok(handle.enable_dht().await, "re-enable (idempotent)");
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(15), engine).await;
    node_b_shutdown.cancel();
    let _ = std::fs::remove_dir_all(dest);
}

/// BEP 27 hard-gate regression (runtime enable on a private engine is
/// always rejected — libtorrent torrent.cpp `priv()` cannot be overridden
/// by flags/session switches); the disable face is not gated (no DHT to
/// disable = idempotent Ok). DHT interaction of a torrentless private
/// engine is pinned by existing engine-interaction tests; this test only
/// pins the runtime-enable gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_enable_is_rejected_for_private_engine_bep27() {
    let port = reserve_tcp_port().await;
    let dht_cfg = DhtWireConfig {
        enabled: false,
        entry_points_v4: Vec::new(),
        entry_points_v6: Vec::new(),
        engine: fast_engine_cfg(),
        announce_interval: Duration::from_millis(600),
    };
    let root = CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: PEER_ID_ENGINE,
        announce: String::new(),
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
        dest: tmp_dir("hot-private"),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config()],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: dht_cfg,
        private: true,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    let dest = cfg.dest.clone();
    let (handle, engine) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig::default(),
        &root,
        taiji_bt::utp::PeerConnectionType::default(),
    );
    match handle.enable_dht().await {
        Err(e) => assert!(
            e.to_string().contains("BEP27"),
            "the private-engine rejection must anchor the BEP27 text: {e}"
        ),
        Ok(()) => panic!("runtime enable on a private engine must be rejected (BEP27 hard gate)"),
    }
    // Disable arm is not gated (idempotent Ok — already disabled).
    ok(handle.disable_dht().await, "disable on private (no-op)");
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(15), engine).await;
    let _ = std::fs::remove_dir_all(dest);
}
