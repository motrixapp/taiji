//! Discovery-metrics benchmark harness (bridges the upstream discovery
//! metrics; same precedent as `dht_10k_perf.rs`).
//!
//! The `#[ignore]` benchmarks compile under a plain `cargo test` but do
//! not run; the bench script drives them with `--release --ignored
//! --nocapture` and parses the `DISCOVERY_BENCH {scenario} {json}` metric
//! line into baseline reports. Metrics are T0-T4 timestamps plus four
//! derived quantities, as defined in the metrics doc.
//!
//! Four scenarios (all in-process/loopback, never leaving the host;
//! fixtures mirror `tests/magnet_chain.rs`):
//!
//! 1. `magnet`: full magnet cold-start chain T0-T4 (local fake tracker +
//! full seeder + in-place engine upgrade through download completion);
//! 2. `tracker`: tracker announce success rate / latency (driven directly
//! through `bt::tracker::actor`, the real announce component behind the
//! engine's per-swarm face);
//! 3. `dht`: DHT bootstrap latency + get_peers first-response latency
//! (three in-process DHT instances);
//! 4. `pex`: PEX contribution rate, measured at two levels:
//! - protocol wire swarm (raw metric, kept as the comparison baseline):
//! real ut_pex codec/negotiation over loopback TCP, consumed by the
//! harness itself;
//! - engine level (post-wiring): a real `DownloadEngine` discovers the
//! announcer via the tracker, consumes the ut_pex frames into
//! connection management, and the engine-level contribution counters
//! are read from SessionMetrics (pex-sourced / total discovered).
//!
//! Iterations: env var `DISCOVERY_BENCH_ITERS` (default 12; acceptance
//! requires >= 10).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, to_string};
use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use taiji_bt::dht::{
    DhtEngineConfig, DhtEvent, DhtFamily, DhtHandle, DhtSnapshot, DhtSwarmKind, DhtTarget,
    DhtTransport, EVENT_CHANNEL_CAPACITY, spawn_dht_engine,
};
use taiji_bt::peer_wire::{ExtHandshake, Handshake, Message, Reserved};
use taiji_bt::pex::{PexCandidate, PexMessage, PexPeer, UploadOnly};
use taiji_bt::piece_id::Addressing;
use taiji_bt::tracker::TrackerOptions;
use taiji_bt::tracker::actor::{
    SwarmView, TrackerActorConfig, TrackerActorEvent, TrackerCommand, UdpTransport,
    spawn_tracker_actor,
};
use taiji_bt::ut_metadata::{self, UtMetadata};
use taiji_core::engine::EngineEnd;
use taiji_core::engine::{DownloadEngine, EngineConfig, FaceConfig, FaceKind};
use taiji_core::gid::GidAllocator;
use taiji_core::magnet::{
    MagnetEnd, MagnetEngine, MagnetOptions, MagnetTaskConfig, MetadataPhaseConfig,
};
use taiji_core::session::SessionMetrics;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Piece length (16 KiB = merkle BLOCK_SIZE; harness payload = 2 pieces =
/// 32 KiB).
const L: u64 = 16384;
/// Default iteration count (`DISCOVERY_BENCH_ITERS` overrides; acceptance
/// requires >= 10).
const DEFAULT_ITERS: usize = 12;
/// Per-iteration budget for the magnet scenario (25 s metadata deadline +
/// upgrade-download slack).
const MAGNET_ITER_BUDGET: Duration = Duration::from_secs(90);
/// Event-wait budget (announce / PeersFound / PEX message).
const EVENT_BUDGET: Duration = Duration::from_secs(10);
/// Announce commands per actor in scenario B.
const ANNOUNCES_PER_ITER: usize = 5;
/// PEX-delivered peer count in scenario D (the `added` list; leaf seeder
/// count).
const PEX_DELIVERED: usize = 5;
/// Magnet harness payload pieces (4 x 16 KiB = 64 KiB).
const MAGNET_PIECES: u64 = 4;
/// Per-piece seeder delivery stagger (piece k is delayed by k x STAGGER) —
/// widens the observable window between T3 (first piece verified) and T4
/// (completion): with two pieces verifying in the same window the gap is
/// <1 ms and polling is unreliable; staggered, the window is
/// ~(n-1) x STAGGER, reliable for T3 polling (<=5 ms resolution).
/// Harness-side delivery rhythm, not protocol semantics.
const PIECE_STAGGER: Duration = Duration::from_millis(300);
/// T3 polling resolution (declared <=5 ms).
const T3_POLL: Duration = Duration::from_millis(2);

// ===== Common fixtures =====

/// Unwraps a test-face `Result` (workspace lint forbids unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

fn ms_since(origin: Instant, at: Instant) -> f64 {
    at.saturating_duration_since(origin).as_secs_f64() * 1000.0
}

fn ms_between(start: Instant, end: Instant) -> f64 {
    end.saturating_duration_since(start).as_secs_f64() * 1000.0
}

/// Iteration count (env-var override).
fn iters() -> usize {
    match std::env::var("DISCOVERY_BENCH_ITERS") {
        Ok(v) => v.parse::<usize>().unwrap_or(DEFAULT_ITERS).max(1),
        Err(_) => DEFAULT_ITERS,
    }
}

/// Unique tmp directory (pid + nanosecond tag; on-disk face of the magnet
/// scenario).
fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p63-{}-{}-{}",
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

/// Grabs a free port (binds then releases).
async fn free_port() -> u16 {
    let l = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "bind :0",
    );
    ok(l.local_addr(), "listener addr").port()
}

/// First-touch recorder (set once; shared across tasks, std Mutex lock
/// held across no await).
type FirstAt = Arc<Mutex<Option<Instant>>>;

fn record_once(slot: &FirstAt, at: Instant) {
    let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(at);
    }
}

fn read_first(slot: &FirstAt) -> Option<Instant> {
    *slot.lock().unwrap_or_else(|e| e.into_inner())
}

/// Deterministic content (MAGNET_PIECES pieces).
fn bench_content() -> Vec<u8> {
    (0..MAGNET_PIECES as usize * L as usize)
        .map(|i| (i * 31 % 251) as u8)
        .collect()
}

fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
}

/// v1 info dict bytes + btih (SHA-1 over the raw info bytes, BEP 3).
fn build_v1_info(content: &[u8], name: &[u8]) -> (Vec<u8>, [u8; 20]) {
    let pieces: Vec<u8> = content.chunks(L as usize).flat_map(Sha1::digest).collect();
    let info = dict(vec![
        (b"length", Value::Int(content.len() as i64)),
        (b"name", Value::Bytes(name.to_vec())),
        (b"piece length", Value::Int(L as i64)),
        (b"pieces", Value::Bytes(pieces)),
    ]);
    let info_bytes = ok(bencode::encode(&info), "info encode");
    let btih: [u8; 20] = Sha1::digest(&info_bytes).into();
    (info_bytes, btih)
}

/// Reads one frame (4B big-endian length prefix + body; empty body =
/// keepalive).
async fn read_frame(sock: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await.ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Some(Vec::new());
    }
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body).await.ok()?;
    Some(body)
}

/// Frame read with a budget (None = EOF or timeout; keeps the harness
/// from hanging when the peer goes silent).
async fn read_frame_t(sock: &mut tokio::net::TcpStream, budget: Duration) -> Option<Vec<u8>> {
    tokio::time::timeout(budget, read_frame(sock))
        .await
        .ok()
        .flatten()
}

/// 68B handshake response bytes (ext + fast capability bits; same shape
/// as the magnet_chain seeder).
fn handshake_response(info_hash: &[u8; 20], peer_id: &[u8; 20]) -> [u8; 68] {
    let mut resp = [0u8; 68];
    resp[0] = 19;
    resp[1..20].copy_from_slice(b"BitTorrent protocol");
    resp[25] = 0x10; // extended (BEP 10)
    resp[27] = 0x04; // fast
    resp[28..48].copy_from_slice(info_hash);
    resp[48..68].copy_from_slice(peer_id);
    resp
}

// ===== Scenario A harness: fake tracker + full seeder (magnet_chain shape
// + observation points) ====

/// Fake tracker: accept loop; answers each announce with `peers` (compact,
/// BEP 3); records the first moment a response containing a non-empty
/// peers list is written (T1 observation point).
async fn fake_tracker(peers: Vec<SocketAddr>, first_served: FirstAt) -> (String, JoinHandle<()>) {
    let listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "tracker bind",
    );
    let addr = ok(listener.local_addr(), "tracker addr");
    let mut peers_bytes = Vec::new();
    for p in &peers {
        let std::net::IpAddr::V4(v4) = p.ip() else {
            continue;
        };
        peers_bytes.extend_from_slice(&v4.octets());
        peers_bytes.extend_from_slice(&p.port().to_be_bytes());
    }
    let join = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Reply as soon as the HTTP header end is seen (the request
            // body is not parsed — announce parameters ride on the tracker
            // actor's reqwest; the harness only answers with peers).
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
            // bencode dict keys ascending: interval < peers.
            let mut raw = Vec::new();
            raw.extend_from_slice(b"d8:intervali600e5:peers");
            raw.extend_from_slice(peers_bytes.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers_bytes);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            let served_at = Instant::now();
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(&raw).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
            if !peers_bytes.is_empty() {
                record_once(&first_served, served_at);
            }
        }
    });
    (format!("http://{addr}/announce"), join)
}

/// Full-seeder parameters (v1 face).
struct SeederSpec {
    /// Info dict bytes (ut_metadata serve payload).
    metadata: Arc<Vec<u8>>,
    /// v1 data stream.
    stream: Arc<Vec<u8>>,
    v1_hash: [u8; 20],
    /// Per-piece delivery stagger (a request for piece k is answered after
    /// k x stagger; harness delivery rhythm widening the T3-T4 window, see
    /// PIECE_STAGGER).
    stagger: Duration,
}

/// Full seeder: accept loop; per connection handshake -> ext handshake
/// (BEP 10, advertising ut_metadata=2 + metadata_size) -> per-request
/// service (interested -> unchoke; request -> piece; ext_id 2 -> ut_metadata
/// data). T2 observation point = handshake response written out
/// (`first_handshake`).
async fn spawn_full_seeder(
    listener: tokio::net::TcpListener,
    spec: SeederSpec,
    first_handshake: FirstAt,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let metadata = Arc::clone(&spec.metadata);
            let stream = Arc::clone(&spec.stream);
            let v1_hash = spec.v1_hash;
            let stagger = spec.stagger;
            let first_handshake = Arc::clone(&first_handshake);
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                let ih: [u8; 20] = hs[28..48].try_into().unwrap_or([0u8; 20]);
                if ih != v1_hash {
                    return; // wrong swarm
                }
                let resp = handshake_response(&ih, b"SEEDERSEEDERSEEDER00");
                if sock.write_all(&resp).await.is_err() {
                    return;
                }
                record_once(&first_handshake, Instant::now());
                // Ext handshake (ut_metadata=2 + metadata_size; BEP 10/9).
                let ext = ExtHandshake {
                    m_ut_metadata: Some(2),
                    metadata_size: Some(metadata.len() as u32),
                    ..ExtHandshake::default()
                };
                let payload = match ext.encode() {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let mut frame = Vec::with_capacity(5 + payload.len());
                frame.extend_from_slice(((1 + 1 + payload.len()) as u32).to_be_bytes().as_slice());
                frame.push(20u8);
                frame.push(0u8);
                frame.extend_from_slice(&payload);
                if sock.write_all(&frame).await.is_err() {
                    return;
                }
                // Advertise the full bitfield after the handshake (BEP 3).
                // The piece count must be rounded up: truncating division
                // would skip advertising trailing partial pieces and, under
                // advertisement-aware dispatch, this seeder would be judged
                // "holds nothing" and never fetched from (the magnet_chain
                // livelock root cause). Zero pieces (pure metadata fixture)
                // sends nothing — an empty BEP 3 bitfield is treated as a
                // protocol error and disconnected.
                let n_pieces = stream.len().div_ceil(L as usize);
                if n_pieces > 0 {
                    let mut bits = vec![0u8; n_pieces.div_ceil(8)];
                    for i in 0..n_pieces {
                        bits[i / 8] |= 0x80 >> (i % 8);
                    }
                    let mut bf = Vec::with_capacity(5 + bits.len());
                    bf.extend_from_slice(((1 + bits.len()) as u32).to_be_bytes().as_slice());
                    bf.push(5u8);
                    bf.extend_from_slice(&bits);
                    if sock.write_all(&bf).await.is_err() {
                        return;
                    }
                }
                loop {
                    let mut len_buf = [0u8; 4];
                    if sock.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len == 0 {
                        continue;
                    }
                    let mut body = vec![0u8; len];
                    if sock.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    match body[0] {
                        2 => {
                            // interested -> unchoke.
                            let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                        }
                        6 => {
                            // request(index, begin, length) -> piece.
                            if body.len() < 13 {
                                return;
                            }
                            let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                            let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                            let length =
                                u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                            let off = index as u64 * L + u64::from(begin);
                            let end = (off + u64::from(length)) as usize;
                            if end > stream.len() {
                                continue;
                            }
                            // Per-piece delivery stagger (harness rhythm;
                            // piece 0 is answered immediately).
                            if stagger > Duration::ZERO {
                                tokio::time::sleep(stagger * index).await;
                            }
                            let block = stream[off as usize..end].to_vec();
                            let mut frame = Vec::with_capacity(13 + block.len());
                            frame.extend_from_slice(&((9 + block.len()) as u32).to_be_bytes());
                            frame.push(7u8);
                            frame.extend_from_slice(&index.to_be_bytes());
                            frame.extend_from_slice(&begin.to_be_bytes());
                            frame.extend_from_slice(&block);
                            if sock.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        20 => {
                            // Extended: ext_id 0 = peer handshake (ignored);
                            // ext_id 2 = ut_metadata request -> data.
                            if body.len() < 2 || body[1] != 2 {
                                continue;
                            }
                            let Ok(UtMetadata::Request { index }) = UtMetadata::decode(&body[2..])
                            else {
                                continue;
                            };
                            let reply = match ut_metadata::serve_request(&metadata, index) {
                                Ok(ut_metadata::ServeOutcome::Data {
                                    index,
                                    total_size,
                                    data,
                                }) => UtMetadata::Data {
                                    index,
                                    total_size,
                                    data,
                                },
                                Ok(ut_metadata::ServeOutcome::Reject { index }) => {
                                    UtMetadata::Reject { index }
                                }
                                Err(_) => return, // out of range -> disconnect
                            };
                            let payload = match reply.encode() {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            let mut frame = Vec::with_capacity(5 + payload.len());
                            frame.extend_from_slice(
                                ((1 + 1 + payload.len()) as u32).to_be_bytes().as_slice(),
                            );
                            frame.push(20u8);
                            frame.push(2u8);
                            frame.extend_from_slice(&payload);
                            if sock.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
    })
}

/// Magnet task config (test shape: short backoff + small dial cap; same
/// shape as magnet_chain test_config; DHT/LSD off -> tracker-only
/// discovery, making T1 unambiguous).
fn magnet_config(
    magnet_uri: String,
    dest: std::path::PathBuf,
    listen_port: u16,
) -> MagnetTaskConfig {
    MagnetTaskConfig {
        gid: GidAllocator::new().allocate(),
        magnet_uri,
        dest,
        peer_id: *b"-TJ0001-MAGNETMAGNE1",
        options: MagnetOptions::default(),
        phase: MetadataPhaseConfig {
            listen_port,
            max_metadata_peers: 4,
            discovery_round: Duration::from_millis(400),
            metadata_deadline: Some(Duration::from_secs(25)),
            dht_bootstrap_budget: Duration::from_millis(300),
        },
        dht: None,
        dht_entry_points: vec![],
        dht_enabled: false,
        lsd: None,
        seed: taiji_core::seed::SeedPolicy::default(),
        seed_after_complete: false,
        persist: None,
        select_file: None,
        limiter: None,
        hook: None,
        web: None,
        stats: None,
        // Benchmarks carry no ban face (None = no gate).
        ip_guard: None,
        webseeding_enabled: true,
    }
}

/// One scenario A iteration: magnet cold-start full chain T0-T4.
/// Returns (t1_ms, t2_ms, t3_ms, t4_ms, t3t4_ms); relative/derived
/// definitions live in the metrics doc.
async fn magnet_iter() -> Result<(f64, f64, f64, f64, f64), String> {
    let content = bench_content();
    let (info_bytes, btih) = build_v1_info(&content, b"bench.bin");
    let tmp = tmp_dir("magnet");

    let seeder_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "seeder bind",
    );
    let seeder_addr = ok(seeder_listener.local_addr(), "seeder addr");

    // T1 observation point (tracker side) + T2 observation point (seeder
    // side).
    let t1_at: FirstAt = Arc::new(Mutex::new(None));
    let (tracker_url, tracker_join) = fake_tracker(vec![seeder_addr], Arc::clone(&t1_at)).await;
    let t2_at: FirstAt = Arc::new(Mutex::new(None));
    let seeder_join = spawn_full_seeder(
        seeder_listener,
        SeederSpec {
            metadata: Arc::new(info_bytes),
            stream: Arc::new(content),
            v1_hash: btih,
            stagger: PIECE_STAGGER,
        },
        Arc::clone(&t2_at),
    )
    .await;

    let listen_port = free_port().await;
    let cfg = magnet_config(
        format!("magnet:?xt=urn:btih:{}&tr={}", hex(&btih), tracker_url),
        tmp.clone(),
        listen_port,
    );

    let root = CancellationToken::new();
    let t0 = Instant::now();
    let (join, mut upgrade_rx) = MagnetEngine::spawn_with_upgrade_notify(cfg, &root);

    // T3 observation task: once the upgrade handle (EngineHandle) arrives,
    // poll the live completed amount — the first PieceVerified advances
    // completed_length > 0 (resolution T3_POLL).
    let poll_t3 = tokio::spawn(async move {
        let handle = upgrade_rx.recv().await?;
        let deadline = Instant::now() + MAGNET_ITER_BUDGET;
        while Instant::now() < deadline {
            match handle.query_status().await {
                Ok(s) if s.completed_length > 0 => return Some(Instant::now()),
                Ok(_) => tokio::time::sleep(T3_POLL).await,
                Err(_) => return None, // engine wound down (failure path or done)
            }
        }
        None
    });

    let joined = tokio::time::timeout(MAGNET_ITER_BUDGET, join).await;
    let result = async {
        let end = match joined {
            Ok(Ok(end)) => end,
            Ok(Err(e)) => return Err(format!("magnet task join: {e}")),
            Err(_) => return Err("magnet iteration budget timed out".into()),
        };
        let t4 = Instant::now();
        let MagnetEnd::Upgraded { end, .. } = end else {
            return Err(format!("expected the Upgraded terminal, got {end:?}"));
        };
        if !matches!(end, EngineEnd::Completed) {
            return Err(format!(
                "the engine did not complete after the upgrade: {end:?}"
            ));
        }
        let t3 = match ok(poll_t3.await, "t3 poll join") {
            Some(at) => at,
            None => return Err("T3 never observed (completed_length never advanced)".into()),
        };
        let t1 = read_first(&t1_at)
            .ok_or("T1 never observed (the tracker never served a peers response)")?;
        let t2 = read_first(&t2_at)
            .ok_or("T2 never observed (the seeder never completed the handshake)")?;
        Ok((
            ms_since(t0, t1),
            ms_since(t0, t2),
            ms_since(t0, t3),
            ms_since(t0, t4),
            ms_between(t3, t4),
        ))
    }
    .await;

    // Unconditional teardown: cancel the task tree + drop harness handles
    // + clean up on-disk state.
    root.cancel();
    tracker_join.abort();
    seeder_join.abort();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

// ===== Scenario B harness: tracker actor driven directly =====

/// Static SwarmView (same shape as the actor unit-test FixedView: total
/// 1000 / incomplete / numwant=50).
struct BenchView;

impl SwarmView for BenchView {
    fn total_length(&self) -> u64 {
        1000
    }
    fn completed_length(&self) -> u64 {
        0
    }
    fn session_uploaded(&self) -> u64 {
        0
    }
    fn session_downloaded(&self) -> u64 {
        0
    }
    fn all_download_finished(&self) -> bool {
        false
    }
    fn less_than_min_peers(&self) -> bool {
        true
    }
}

/// One scenario B iteration: the tracker actor announces repeatedly
/// against the local fake tracker.
/// Returns (attempts, success, latency ms list). Failed announces
/// (AnnounceFailed / timeout) count in the success-rate denominator
/// without aborting the iteration; only a broken harness returns Err.
async fn tracker_iter() -> Result<(usize, usize, Vec<f64>), String> {
    let dead_peer: SocketAddr = ok("127.0.0.1:6881".parse(), "dead peer addr");
    let recorder: FirstAt = Arc::new(Mutex::new(None));
    let (tracker_url, tracker_join) = fake_tracker(vec![dead_peer], recorder).await;

    let (ev_tx, mut ev_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    // HTTP-only actor: the UDP carrier gets dummy channels (no UDP packets
    // leave the process).
    let (udp_out, _udp_out_rx) = mpsc::channel(1);
    let (_udp_in_tx, udp_in) = mpsc::channel(1);
    let transport = UdpTransport {
        outbound: udp_out,
        inbound: udp_in,
    };
    let cfg = TrackerActorConfig {
        info_hash: [0x63; 20],
        peer_id: *b"-TJ0001-TRKRTRKRTRKR",
        listen_port: free_port().await,
        options: TrackerOptions::default(),
        require_crypto: false,
        private: false,
        tiers: vec![(0, tracker_url)],
        scrape_hashes: vec![],
    };
    let cmd_tx = ok(
        spawn_tracker_actor(cfg, Arc::new(BenchView), ev_tx, transport),
        "tracker actor",
    );

    let mut attempts = 0usize;
    let mut success = 0usize;
    let mut latencies = Vec::new();
    for _ in 0..ANNOUNCES_PER_ITER {
        attempts += 1;
        let (reply_tx, reply_rx) = oneshot::channel();
        ok(
            cmd_tx
                .send(TrackerCommand::Announce { reply: reply_tx })
                .await,
            "announce cmd",
        );
        let _ = ok(reply_rx.await, "announce ack");
        let sent = Instant::now();
        let deadline = sent + EVENT_BUDGET;
        let mut ok_attempt = false;
        while !ok_attempt {
            let ev =
                tokio::time::timeout_at(tokio::time::Instant::from(deadline), ev_rx.recv()).await;
            match ev {
                Err(_) => break, // event timeout = this attempt failed (in denominator)
                Ok(None) => return Err("the tracker actor exited unexpectedly".into()),
                Ok(Some(TrackerActorEvent::Peers { peers, .. })) if !peers.is_empty() => {
                    latencies.push(ms_between(sent, Instant::now()));
                    ok_attempt = true;
                }
                Ok(Some(TrackerActorEvent::AnnounceFailed { .. })) => {
                    break; // single failure (in denominator)
                }
                Ok(Some(_)) => {} // IntervalUpdated/ScrapeResult/Halted ignored
            }
        }
        if ok_attempt {
            success += 1;
        }
    }

    drop(cmd_tx); // command channel closed -> actor run exits
    tracker_join.abort();
    Ok((attempts, success, latencies))
}

// ===== Scenario C harness: three in-process DHT instances (magnet_chain
// shape) ====

/// In-process DHT instance (loopback UdpDemux + DhtEngine).
/// Returns (handle, events, bound addr, lifetime token).
async fn spawn_dht_instance() -> (
    DhtHandle,
    mpsc::Receiver<DhtEvent>,
    SocketAddr,
    CancellationToken,
) {
    let shutdown = CancellationToken::new();
    let (channels, demux) = ok(
        taiji_io::udp_demux::spawn(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            taiji_io::udp_demux::DemuxConfig::default(),
            shutdown.clone(),
        )
        .await,
        "demux bind",
    );
    let bound = demux.bound_addr();
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (out_tx, mut out_rx) = mpsc::channel(256);
    let (handle, _join) = spawn_dht_engine(
        DhtFamily::V4,
        bound.port(),
        DhtEngineConfig::default(),
        DhtTransport {
            inbound: channels.dht,
            outbound: out_tx,
        },
        None,
        event_tx,
    );
    // Engine outbound -> single demux writer (topology).
    let fwd_demux = demux.clone();
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            let _ = fwd_demux.send_packet(pkt.to, pkt.data).await;
        }
    });
    (handle, event_rx, bound, shutdown)
}

async fn dht_snapshot(handle: &DhtHandle) -> DhtSnapshot {
    ok(handle.snapshot().await, "dht snapshot")
}

/// Polls the snapshot until the condition holds (timeout = Err, no
/// panic).
async fn wait_snapshot(
    handle: &DhtHandle,
    limit: Duration,
    cond: impl Fn(&DhtSnapshot) -> bool,
) -> Result<(), String> {
    let start = Instant::now();
    loop {
        let snap = dht_snapshot(handle).await;
        if cond(&snap) {
            return Ok(());
        }
        if start.elapsed() > limit {
            return Err(format!(
                "snapshot condition not met (limit {limit:?}): {snap:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One scenario C iteration: DHT bootstrap latency + get_peers
/// first-response latency.
/// Returns (reached entry count, bootstrap_ms, get_peers_first_ms,
/// peers_found).
async fn dht_iter(i: usize) -> Result<(usize, f64, f64, usize), String> {
    let ih: [u8; 20] = Sha1::digest(format!("p63-dht-{i}").as_bytes()).into();
    let target = ok(DhtTarget::new(ih, DhtSwarmKind::V1, false), "dht target");

    // Swarm preseeding (not measured): a node already in the swarm
    // announce_peers against the hub to create the record.
    let (hub, _hub_ev, hub_addr, hub_tok) = spawn_dht_instance().await;
    let (seed_dht, _seed_ev, _seed_addr, seed_tok) = spawn_dht_instance().await;
    let preset = async {
        ok(seed_dht.bootstrap(vec![hub_addr]).await, "seed bootstrap");
        ok(
            seed_dht.announce(target, free_port().await).await,
            "seed announce",
        );
        wait_snapshot(&hub, Duration::from_secs(5), |s| s.peer_record_keys >= 1).await
    };
    if let Err(e) = preset.await {
        hub_tok.cancel();
        seed_tok.cancel();
        return Err(format!("swarm preseeding failed: {e}"));
    }

    // Node under test: bootstrap (measurement 1) -> get_peers first
    // response (measurement 2).
    let (leech, mut leech_ev, _leech_addr, leech_tok) = spawn_dht_instance().await;
    let t = Instant::now();
    let boot = leech.bootstrap(vec![hub_addr]).await;
    let bootstrap_ms = ms_between(t, Instant::now());
    let result = async {
        let reached = ok(boot, "bootstrap") as usize;
        let t = Instant::now();
        ok(leech.get_peers(target).await, "get_peers");
        let deadline = Instant::now() + EVENT_BUDGET;
        loop {
            let ev = tokio::time::timeout_at(tokio::time::Instant::from(deadline), leech_ev.recv())
                .await;
            match ev {
                Err(_) => {
                    return Err(
                        "get_peers first response timed out (PeersFound never arrived)".into(),
                    );
                }
                Ok(None) => return Err("the DHT engine exited unexpectedly".into()),
                Ok(Some(DhtEvent::PeersFound { peers, .. })) => {
                    let first_ms = ms_between(t, Instant::now());
                    return Ok((reached, bootstrap_ms, first_ms, peers.len()));
                }
                Ok(Some(_)) => {} // Persist and other events ignored
            }
        }
    }
    .await;

    // Teardown: command channel closed (actor exits) + demux tokens
    // cancelled.
    drop(leech);
    drop(seed_dht);
    drop(hub);
    leech_tok.cancel();
    seed_tok.cancel();
    hub_tok.cancel();
    result
}

// ===== Scenario D harness: protocol wire swarm (PEX contribution) ====

/// Handshake-level seeders (S2..S6): accept -> handshake response -> read
/// and ignore frames (hold).
async fn spawn_leaf_seeder(listener: tokio::net::TcpListener, ih: [u8; 20]) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                let got_ih: [u8; 20] = hs[28..48].try_into().unwrap_or([0u8; 20]);
                if got_ih != ih {
                    return; // wrong swarm
                }
                let resp = handshake_response(&got_ih, b"LEAFSEEDERLEAFSEED00");
                if sock.write_all(&resp).await.is_err() {
                    return;
                }
                while read_frame(&mut sock).await.is_some() {}
            });
        }
    })
}

/// PEX announcer (S1): handshake -> read the peer's ext handshake
/// (negotiation: send only if the peer advertised a ut_pex msg id, same
/// rule as `DefaultBtInteractive.cc`) -> read interested -> send ut_pex
/// `added` (fresh-admission semantics live in PexMessage) -> hold.
async fn spawn_pex_announcer(
    listener: tokio::net::TcpListener,
    ih: [u8; 20],
    pex_addrs: Vec<SocketAddr>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let addrs = pex_addrs.clone();
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                let got_ih: [u8; 20] = hs[28..48].try_into().unwrap_or([0u8; 20]);
                if got_ih != ih {
                    return; // wrong swarm
                }
                let resp = handshake_response(&got_ih, b"PEXSEEDERPEXSEEDER00");
                if sock.write_all(&resp).await.is_err() {
                    return;
                }
                // Peer ext handshake (BEP 10 negotiation).
                let mut peer_pex_id = None;
                while peer_pex_id.is_none() {
                    let Some(body) = read_frame_t(&mut sock, EVENT_BUDGET).await else {
                        return;
                    };
                    if body.is_empty() {
                        continue;
                    }
                    if let Message::Extended { ext_id: 0, payload } =
                        match Message::decode_body(&body) {
                            Ok(m) => m,
                            Err(_) => continue,
                        }
                        && let Ok(ext) = ExtHandshake::decode(&payload)
                    {
                        peer_pex_id = ext.m_ut_pex;
                    }
                }
                // interested (opens the data face; this scenario serves no
                // pieces).
                let _ = read_frame_t(&mut sock, EVENT_BUDGET).await;
                // ut_pex added = leaf addresses (fresh-admission semantics
                // live in the protocol code).
                let Some(peer_id) = peer_pex_id else { return };
                let mut msg = PexMessage::new();
                let now = Instant::now();
                for addr in &addrs {
                    msg.add_fresh_peer(
                        &PexCandidate::fresh(PexPeer::new(*addr, UploadOnly::Yes), now),
                        now,
                    );
                }
                // The Message::Extended encoder adds the [id][ext_id]
                // prefix itself — the payload carries only the dict
                // (encode_frame output includes the ext_id byte for raw
                // frame construction, unused here).
                let Ok(payload) = msg.encode() else { return };
                let frame = Message::Extended {
                    ext_id: peer_id,
                    payload: payload.into(),
                }
                .encode();
                if sock.write_all(&frame).await.is_err() {
                    return;
                }
                while read_frame(&mut sock).await.is_some() {}
            });
        }
    })
}

/// One scenario D iteration: protocol-face PEX contribution. Returns
/// (tracker_peers=1, pex_advertised, pex_delivered (verified by dial +
/// handshake), hs_to_pex_ms, dial_ms list).
async fn pex_iter() -> Result<(usize, usize, usize, f64, Vec<f64>), String> {
    let ih: [u8; 20] = Sha1::digest(b"p63-pex-target").into();

    // Leaf seeders (S2..S6): listening before the PEX message goes out
    // (the dial-verification targets).
    let mut leaf_joins = Vec::new();
    let mut leaf_addrs = Vec::new();
    for _ in 0..PEX_DELIVERED {
        let listener = ok(
            tokio::net::TcpListener::bind("127.0.0.1:0").await,
            "leaf bind",
        );
        leaf_addrs.push(ok(listener.local_addr(), "leaf addr"));
        leaf_joins.push(spawn_leaf_seeder(listener, ih).await);
    }
    let s1_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "s1 bind",
    );
    let s1_addr = ok(s1_listener.local_addr(), "s1 addr");
    let s1_join = spawn_pex_announcer(s1_listener, ih, leaf_addrs.clone()).await;

    // Leecher (harness consumer face): wire handshake -> BEP 10
    // negotiation -> ut_pex decode -> dial verification.
    let result = async {
        let hs = Handshake {
            reserved: Reserved::aria2_default(),
            info_hash: ih,
            peer_id: *b"-TJ0001-PEXLEECH0000",
        };
        let t0 = Instant::now();
        let mut sock = ok(tokio::net::TcpStream::connect(s1_addr).await, "connect S1");
        ok(sock.write_all(&hs.encode()).await, "hs write");
        let mut resp = [0u8; 68];
        ok(sock.read_exact(&mut resp).await, "hs read");
        ok(Handshake::decode(&resp), "S1 handshake decode");
        let t_hs = Instant::now();

        // Our ext handshake: advertise ut_pex=1 (the harness builds the
        // enabled face; the engine today does not advertise ut_pex).
        let my_ext = ExtHandshake {
            m_ut_pex: Some(1),
            ..ExtHandshake::default()
        };
        let payload = ok(my_ext.encode(), "ext handshake encode");
        ok(
            sock.write_all(&Message::Extended { ext_id: 0, payload }.encode())
                .await,
            "ext handshake write",
        );
        ok(
            sock.write_all(&Message::Interested.encode()).await,
            "interested write",
        );

        // Read frames until ut_pex (decoded via the real protocol-face
        // PexMessage::decode).
        let mut pex_peers: Vec<PexPeer> = Vec::new();
        while pex_peers.is_empty() {
            let Some(body) = read_frame_t(&mut sock, EVENT_BUDGET).await else {
                return Err(
                    "the PEX message never arrived or the S1 connection broke (budget 10s)".into(),
                );
            };
            if body.is_empty() {
                continue;
            }
            let Ok(msg) = Message::decode_body(&body) else {
                continue;
            };
            if let Message::Extended { payload, .. } = msg
                && let Ok(pex) = PexMessage::decode(&payload)
            {
                pex_peers = pex.fresh_peers().to_vec();
            }
        }
        let hs_to_pex_ms = ms_between(t_hs, Instant::now());
        let advertised = pex_peers.len();

        // Dial verification: connect + handshake each PEX-delivered address
        // (deliverability).
        let mut dial_ms = Vec::new();
        let mut delivered = 0usize;
        for peer in &pex_peers {
            let t = Instant::now();
            // connect budget (nested Result: outer Elapsed, inner io).
            let Ok(Ok(mut s)) =
                tokio::time::timeout(EVENT_BUDGET, tokio::net::TcpStream::connect(peer.addr)).await
            else {
                continue;
            };
            if s.write_all(&hs.encode()).await.is_err() {
                continue;
            }
            let mut r = [0u8; 68];
            if tokio::time::timeout(EVENT_BUDGET, s.read_exact(&mut r))
                .await
                .is_err()
            {
                continue;
            }
            if Handshake::decode(&r).is_err() {
                continue;
            }
            delivered += 1;
            dial_ms.push(ms_between(t, Instant::now()));
        }
        let _ = ms_since(t0, t_hs); // keeps the T-chain semantics: handshake done relative to connect start
        Ok((1usize, advertised, delivered, hs_to_pex_ms, dial_ms))
    }
    .await;

    s1_join.abort();
    for j in leaf_joins {
        j.abort();
    }
    result
}

// ===== Scenario D engine leg: real engine consumes ut_pex -> contribution
// counters =====

/// Per-iteration engine-leg budget (announce tick 1 s + dialing + PEX
/// delivery polling).
const ENGINE_LEG_BUDGET: Duration = Duration::from_secs(15);
/// Engine-leg payload pieces (2 = 32 KiB; the download never advances —
/// leaves serve no pieces, only the discovery face is measured).
const ENGINE_PIECES: u64 = 2;
/// Engine-leg PEX delivery target (same shape as the protocol leg: 5 leaf
/// addresses).
const ENGINE_PEX_DELIVERED: usize = PEX_DELIVERED;

/// Engine-leg single v1 face config (engine_loop.rs shape; flat piece
/// space).
fn engine_leg_face(ih: [u8; 20]) -> (FaceConfig, Vec<u8>) {
    let content: Vec<u8> = (0..ENGINE_PIECES as usize * L as usize)
        .map(|i| (i * 17 % 233) as u8)
        .collect();
    let mut expected = Vec::new();
    for c in content.chunks(L as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let n = expected.len() as u64;
    let total = content.len() as u64;
    let face = FaceConfig {
        kind: FaceKind::V1,
        info_hash: ih,
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..n).map(|k| k * L).collect(),
        piece_bytes: (0..n).map(|k| (total - k * L).min(L)).collect(),
        expected,
        plan_file_lengths: vec![total],
        progress_file_lens: vec![total],
        cross: Vec::new(),
        hash_files: None,
    };
    (face, content)
}

fn engine_leg_layout(total: u64) -> Layout {
    let entries = vec![PlanEntry {
        path: "pex-engine-blob.bin".into(),
        length: total,
        padding: false,
    }];
    ok(Layout::plan_v1_padded(&entries, L as u32), "layout")
}

/// One engine-leg iteration: a fake tracker lets the engine
/// (peer_exchange=true, real connection management) consume S1's ut_pex
/// until the SessionMetrics engine-level contribution counters converge.
/// Returns (discovered_total, discovered_pex, t0_to_pex_ms, leaf_accepts).
///
/// Note (loopback topology boundary): the engine's "one connection per IP"
/// guard (shared with the DHT/tracker sources, PEX included, not bypassed
/// — asserted in `tests/pex_engine.rs`) collapses leaf dials on a single
/// loopback IP; the engine-leg reading is taken at the discovery-count
/// point (after the self-connect guard, before dedup/guard) — discovery
/// is not connection establishment.
async fn pex_engine_iter(i: usize) -> Result<(usize, usize, f64, usize), String> {
    let ih: [u8; 20] = Sha1::digest(format!("p64-engine-pex-{i}").as_bytes()).into();

    // Leaf seeders (handshake-level hold; the discovery-count targets).
    let mut leaf_joins = Vec::new();
    let mut leaf_addrs = Vec::new();
    let leaf_accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for _ in 0..ENGINE_PEX_DELIVERED {
        let listener = ok(
            tokio::net::TcpListener::bind("127.0.0.1:0").await,
            "leaf bind",
        );
        leaf_addrs.push(ok(listener.local_addr(), "leaf addr"));
        let accepts = Arc::clone(&leaf_accepts);
        leaf_joins.push(tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                let got_ih: [u8; 20] = hs[28..48].try_into().unwrap_or([0u8; 20]);
                let resp = handshake_response(&got_ih, b"LEAFSEEDERLEAFSEED00");
                if sock.write_all(&resp).await.is_err() {
                    return;
                }
                accepts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                while read_frame(&mut sock).await.is_some() {}
            }
        }));
    }
    // S1 announcer (same harness as the protocol leg: delivers `added`
    // after observing the peer's advertisement).
    let s1_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "s1 bind",
    );
    let s1_addr = ok(s1_listener.local_addr(), "s1 addr");
    let s1_join = spawn_pex_announcer(s1_listener, ih, leaf_addrs.clone()).await;

    // Fake tracker: the engine discovers S1 via the tracker source (the
    // tracker term of the denominator).
    let t1_dummy: FirstAt = Arc::new(Mutex::new(None));
    let (tracker_url, tracker_join) = fake_tracker(vec![s1_addr], t1_dummy).await;

    let (face, content) = engine_leg_face(ih);
    let tmp = tmp_dir("pex-engine");
    let metrics = Arc::new(SessionMetrics::new());
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: *b"-TJ0001-PEXENGBENCH1",
        announce: tracker_url,
        listen_port: 0,
        piece_len: L as u32,
        layout: engine_leg_layout(content.len() as u64),
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
        peer_exchange: true,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: Some(Arc::clone(&metrics)),
        webseeds: Vec::new(),
    };

    let root = CancellationToken::new();
    let t0 = Instant::now();
    let engine = DownloadEngine::spawn(cfg, &root);
    let result = async {
        // Poll the engine-level contribution counters until every PEX
        // delivery has landed (engine-level reading).
        let leaves = ENGINE_PEX_DELIVERED as u64;
        let (pex, total) = loop {
            let (pex, total) = metrics.discovered_peers();
            if pex >= leaves {
                break (pex, total);
            }
            if t0.elapsed() > ENGINE_LEG_BUDGET {
                let (p, t) = metrics.discovered_peers();
                return Err(format!(
                    "engine-level PEX count never reached full (budget {ENGINE_LEG_BUDGET:?}): \
                     pex={p} total={t}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let t0_to_pex_ms = ms_since(t0, Instant::now());
        let accepts = leaf_accepts.load(std::sync::atomic::Ordering::Relaxed);
        Ok((
            usize::try_from(total).unwrap_or(0),
            usize::try_from(pex).unwrap_or(0),
            t0_to_pex_ms,
            accepts,
        ))
    }
    .await;

    root.cancel();
    let _ = tokio::time::timeout(ENGINE_LEG_BUDGET, engine).await;
    s1_join.abort();
    for j in leaf_joins {
        j.abort();
    }
    tracker_join.abort();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

// ===== Benchmark entry points (#[ignore]; the bench script runs them with
// --ignored) ====

/// Scenario A: magnet cold start T0-T4.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_bench_magnet_cold_start() {
    let n = iters();
    let mut rows = Vec::new();
    for i in 0..n {
        let row = match magnet_iter().await {
            Ok((t1, t2, t3, t4, t3t4)) => json!({
                "iter": i, "t1_ms": t1, "t2_ms": t2, "t3_ms": t3,
                "t4_ms": t4, "t3t4_ms": t3t4,
            }),
            Err(e) => json!({"iter": i, "error": e}),
        };
        println!("bench magnet iter {}: {row}", i);
        rows.push(row);
    }
    let doc = json!({"n": n, "rows": rows});
    println!(
        "DISCOVERY_BENCH magnet {}",
        to_string(&doc).unwrap_or_else(|_| "{\"n\":0,\"rows\":[]}".into())
    );
}

/// Scenario B: tracker announce success rate + latency.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_bench_tracker_announce() {
    let n = iters();
    let mut rows = Vec::new();
    for i in 0..n {
        let row = match tracker_iter().await {
            Ok((attempts, success, latencies)) => json!({
                "iter": i, "attempts": attempts, "success": success,
                "latencies_ms": latencies,
            }),
            Err(e) => json!({"iter": i, "error": e}),
        };
        println!("bench tracker iter {}: {row}", i);
        rows.push(row);
    }
    let doc = json!({"n": n, "rows": rows});
    println!(
        "DISCOVERY_BENCH tracker {}",
        to_string(&doc).unwrap_or_else(|_| "{\"n\":0,\"rows\":[]}".into())
    );
}

/// Scenario C: DHT bootstrap latency + get_peers first response.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_bench_dht_bootstrap() {
    let n = iters();
    let mut rows = Vec::new();
    for i in 0..n {
        let row = match dht_iter(i).await {
            Ok((reached, bootstrap_ms, first_ms, peers)) => json!({
                "iter": i, "reached": reached, "bootstrap_ms": bootstrap_ms,
                "get_peers_first_ms": first_ms, "peers_found": peers,
            }),
            Err(e) => json!({"iter": i, "error": e}),
        };
        println!("bench dht iter {}: {row}", i);
        rows.push(row);
    }
    let doc = json!({"n": n, "rows": rows});
    println!(
        "DISCOVERY_BENCH dht {}",
        to_string(&doc).unwrap_or_else(|_| "{\"n\":0,\"rows\":[]}".into())
    );
}

/// Scenario D: PEX contribution (two levels: protocol face + engine
/// level).
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_bench_pex_contribution() {
    let n = iters();
    let mut rows = Vec::new();
    for i in 0..n {
        // Protocol leg (raw metric, kept as the comparison baseline).
        let mut row = match pex_iter().await {
            Ok((tracker_peers, advertised, delivered, hs_to_pex_ms, dial_ms)) => json!({
                "iter": i,
                "tracker_peers": tracker_peers,
                "pex_advertised": advertised, "pex_delivered": delivered,
                "hs_to_pex_ms": hs_to_pex_ms, "dial_ms": dial_ms,
            }),
            Err(e) => json!({"iter": i, "error": e}),
        };
        // Engine leg (post-wiring reading).
        match pex_engine_iter(i).await {
            Ok((total, pex, t0_to_pex_ms, accepts)) => {
                row["engine_discovered_total"] = json!(total);
                row["engine_discovered_pex"] = json!(pex);
                row["engine_t0_to_pex_ms"] = json!(t0_to_pex_ms);
                row["engine_leaf_accepts"] = json!(accepts);
            }
            Err(e) => {
                row["engine_error"] = json!(e);
            }
        }
        println!("bench pex iter {}: {row}", i);
        rows.push(row);
    }
    let doc = json!({"n": n, "rows": rows});
    println!(
        "DISCOVERY_BENCH pex {}",
        to_string(&doc).unwrap_or_else(|_| "{\"n\":0,\"rows\":[]}".into())
    );
}
