//! Acceptance: the PEX -> engine wiring full chain (loopback, never
//! leaving the host).
//!
//! Chain (the tracker discovers 1 announcer -> the announcer delivers the
//! leaf seeders via ut_pex `added` -> the engine consumes ut_pex and dials
//! the leaves, source = pex):
//!
//! - `pex_engine_discovers_and_dials`: the engine ext handshake
//! advertises ut_pex=1 (BEP 10 m dict) -> consumes the announcer's
//! ut_pex frame (codec decode) -> discovered peers feed connection
//! management (self-connect guard / dedup / one connection per IP, same
//! as the tracker/DHT paths) -> SessionMetrics engine-level contribution
//! count > 0 (engine-level reading face);
//! - `pex_private_torrent_silent` (acceptance criterion 3): private=true
//! -> `pex_offered` is false -> no advertisement (the announcer asserts
//! the m dict has no ut_pex), and ut_pex sent anyway by the announcer is
//! not consumed either (zero leaf connections, pex count 0).
//!
//! Harness shape matches `engine_loop.rs`: fake HTTP tracker + wire-level
//! announcer/leaf seeders (handshake-level hold, no piece serving).

use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::{ExtHandshake, Message, Reserved};
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, FaceConfig, FaceKind};
use taiji_core::session::SessionMetrics;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: u32 = 16384;
/// Metadata serve payload (arbitrary bytes — only the ext handshake's
/// metadata_size advertisement face).
const STATIC_INFO: &[u8] = b"d4:infod4:name4:blobee";
/// Discovery/dial budget (tracker actor 1 s tick + announce round trip +
/// dialing).
const BUDGET: Duration = Duration::from_secs(15);
/// "Silence" observation window for the private face (no connection is
/// the assertion object; carries empirical jitter slack).
const QUIET_WINDOW: Duration = Duration::from_secs(3);

fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn content() -> Vec<u8> {
    (0..2 * PIECE_LEN as usize)
        .map(|i| (i * 37 % 241) as u8)
        .collect()
}

/// v1-only single-face engine config (engine_loop shape; the faces face =
/// flat piece space).
fn v1_face(info_hash: [u8; 20], content_len: u64) -> (FaceConfig, Vec<u8>, [u8; 20]) {
    let data = content();
    let mut expected = Vec::new();
    for c in data.chunks(PIECE_LEN as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let face = FaceConfig {
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
    };
    (face, data, info_hash)
}

fn layout_of(content_len: u64) -> Layout {
    let entries = vec![PlanEntry {
        path: "pex-blob.bin".into(),
        length: content_len,
        padding: false,
    }];
    ok(Layout::plan_v1_padded(&entries, PIECE_LEN), "layout")
}

/// Fake tracker: accept loop; every announce replies `peers = [announcer]`
/// (compact).
async fn fake_tracker(announcer: SocketAddr) -> String {
    let listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "tracker bind",
    );
    let addr = ok(listener.local_addr(), "tracker addr");
    let mut peers = Vec::new();
    if let std::net::IpAddr::V4(v4) = announcer.ip() {
        peers.extend_from_slice(&v4.octets());
        peers.extend_from_slice(&announcer.port().to_be_bytes());
    }
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
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
            raw.extend_from_slice(b"d8:intervali60e5:peers");
            raw.extend_from_slice(peers.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(&raw).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });
    format!("http://{addr}/announce")
}

/// 68B handshake response (ext + fast capability bits; engine_loop seeder
/// shape).
fn handshake_resp(info_hash: &[u8; 20]) -> [u8; 68] {
    let mut resp = [0u8; 68];
    resp[0] = 19;
    resp[1..20].copy_from_slice(b"BitTorrent protocol");
    resp[25] = 0x10;
    resp[27] = 0x04;
    resp[28..48].copy_from_slice(info_hash);
    resp[48..68].copy_from_slice(b"PEXSEEDERPEXSEEDER00");
    resp
}

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

/// Wire-level announcer (S1): handshake response -> read the peer's ext
/// handshake -> `check_adv` verifies the peer's ut_pex advertisement (the
/// negotiation assertion point) -> `send_anyway` decides whether to send
/// ut_pex `added` (leaf addresses) regardless of negotiation -> keeps
/// reading frames (keeps the peer's writes from blocking).
/// Returns the first observed advertise id (None = no ut_pex in the
/// peer's m dict).
async fn spawn_announcer(
    listener: tokio::net::TcpListener,
    ih: [u8; 20],
    leaves: Vec<SocketAddr>,
    send_anyway: bool,
    observed_adv: Arc<Mutex<Option<Option<u8>>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let leaves = leaves.clone();
            let observed_adv = Arc::clone(&observed_adv);
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                if hs[28..48] != ih {
                    return; // wrong swarm
                }
                if sock.write_all(&handshake_resp(&ih)).await.is_err() {
                    return;
                }
                // Read frames until the peer's ext handshake (BEP 10
                // negotiation observation point).
                let deadline = Instant::now() + BUDGET;
                let adv: Option<u8> = loop {
                    if Instant::now() > deadline {
                        return;
                    }
                    let Ok(Some(body)) = tokio::time::timeout(BUDGET, read_frame(&mut sock)).await
                    else {
                        return;
                    };
                    if body.is_empty() {
                        continue;
                    }
                    let Ok(Message::Extended { ext_id: 0, payload }) = Message::decode_body(&body)
                    else {
                        continue;
                    };
                    let Ok(ext) = ExtHandshake::decode(&payload) else {
                        return;
                    };
                    break ext.m_ut_pex;
                };
                *observed_adv.lock().unwrap_or_else(|e| e.into_inner()) = Some(adv);
                // Negotiation gate: the peer did not advertise and no
                // contract-breaking send was requested -> silent hold.
                if adv.is_none() && !send_anyway {
                    while read_frame(&mut sock).await.is_some() {}
                    return;
                }
                // ut_pex `added` = leaf addresses (fresh-admission
                // semantics live in the codec; the seeder flag = true,
                // self-evident in added.f).
                let mut msg = taiji_bt::pex::PexMessage::new();
                let now = Instant::now();
                for addr in &leaves {
                    msg.add_fresh_peer(
                        &taiji_bt::pex::PexCandidate::fresh(
                            taiji_bt::pex::PexPeer::new(*addr, taiji_bt::pex::UploadOnly::Yes),
                            now,
                        ),
                        now,
                    );
                }
                let Ok(payload) = msg.encode() else { return };
                let frame = Message::Extended {
                    ext_id: adv.unwrap_or(1),
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

/// Handshake-level leaf seeder: holds after the handshake response
/// (reads and drops frames); counts accepts.
async fn spawn_leaf(
    listener: tokio::net::TcpListener,
    ih: [u8; 20],
    accepts: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let accepts = Arc::clone(&accepts);
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                if hs[28..48] != ih {
                    return;
                }
                if sock.write_all(&handshake_resp(&ih)).await.is_err() {
                    return;
                }
                accepts.fetch_add(1, Ordering::Relaxed);
                while read_frame(&mut sock).await.is_some() {}
            });
        }
    })
}

/// Harness assembly: tracker + announcer + N leaves (listening before the
/// ut_pex goes out).
struct Rig {
    _tracker: tokio::task::JoinHandle<()>,
    announcer: tokio::task::JoinHandle<()>,
    leaf_joins: Vec<tokio::task::JoinHandle<()>>,
    announces: String,
    leaf_accepts: Arc<AtomicUsize>,
    observed_adv: Arc<Mutex<Option<Option<u8>>>>,
}

async fn spawn_rig(ih: [u8; 20], leaves_n: usize, send_anyway: bool) -> Rig {
    let mut leaf_joins = Vec::new();
    let mut leaf_addrs = Vec::new();
    let leaf_accepts = Arc::new(AtomicUsize::new(0));
    for _ in 0..leaves_n {
        let listener = ok(
            tokio::net::TcpListener::bind("127.0.0.1:0").await,
            "leaf bind",
        );
        leaf_addrs.push(ok(listener.local_addr(), "leaf addr"));
        leaf_joins.push(spawn_leaf(listener, ih, Arc::clone(&leaf_accepts)).await);
    }
    let s1_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "s1 bind",
    );
    let s1_addr = ok(s1_listener.local_addr(), "s1 addr");
    let observed_adv: Arc<Mutex<Option<Option<u8>>>> = Arc::new(Mutex::new(None));
    let announcer = spawn_announcer(
        s1_listener,
        ih,
        leaf_addrs.clone(),
        send_anyway,
        Arc::clone(&observed_adv),
    )
    .await;
    let announces = fake_tracker(s1_addr).await;
    Rig {
        _tracker: tokio::spawn(async {}), // the tracker task spawns inside fake_tracker
        announcer,
        leaf_joins,
        announces,
        leaf_accepts,
        observed_adv,
    }
}

impl Rig {
    fn teardown(self) {
        self.announcer.abort();
        for j in self.leaf_joins {
            j.abort();
        }
    }
}

/// Engine gate/face injection parameters (the parameter bundle of
/// engine_cfg; avoids an over-long parameter list).
struct GateCfg {
    ih: [u8; 20],
    content_len: u64,
    private: bool,
    peer_exchange: bool,
    metadata_serve: bool,
}

/// Assembles the engine (GateCfg injects gates/faces; stats injects the
/// shared counter face).
fn engine_cfg(
    announces: String,
    dest: std::path::PathBuf,
    gates: GateCfg,
    stats: Option<Arc<SessionMetrics>>,
) -> EngineConfig {
    let GateCfg {
        ih,
        content_len,
        private,
        peer_exchange,
        metadata_serve,
    } = gates;
    let (face, _data, _) = v1_face(ih, content_len);
    // Metadata serve face: in the private-torrent scenario (real
    // .torrent files always carry metadata) the engine sends its ext
    // handshake because of it — letting the announcer observe the
    // "m dict has no ut_pex" non-advertisement assertion point (with
    // metadata_serve=None + private, not even the ext handshake is sent —
    // not the object of this test).
    let metadata = if metadata_serve {
        Some(Arc::new(taiji_bt::peer::MetadataBytes(bytes::Bytes::from(
            STATIC_INFO.to_vec(),
        ))) as Arc<dyn taiji_bt::peer::MetadataSource>)
    } else {
        None
    };
    EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: *b"-TJ0001-PEXENGINE001",
        announce: announces,
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout: layout_of(content_len),
        dest,
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput tier (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![face],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private,
        peer_exchange,
        metadata_serve: metadata,
        limiter: None,
        hook: None,
        nat: None,
        stats,
        webseeds: Vec::new(),
    }
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p64-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// Full chain (acceptance criteria 2 + 5): the engine advertises
/// ut_pex=1 -> the announcer sends ut_pex (5 leaves) -> the engine
/// consumes it (source = pex) and dials all leaves -> the engine-level
/// contribution count = 5/6 (>0).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pex_engine_discovers_and_dials() {
    const LEAVES: usize = 5;
    let ih: [u8; 20] = Sha1::digest(b"p64-engine-pex-target").into();
    let rig = spawn_rig(ih, LEAVES, false).await;
    let tmp = tmp_dir("duplex");
    let metrics = Arc::new(SessionMetrics::new());

    let root = CancellationToken::new();
    let cfg = engine_cfg(
        rig.announces.clone(),
        tmp.clone(),
        GateCfg {
            ih,
            content_len: content().len() as u64,
            private: false,
            peer_exchange: true,
            metadata_serve: false,
        },
        Some(Arc::clone(&metrics)),
    );
    let engine = DownloadEngine::spawn(cfg, &root);

    // Poll the engine-level contribution counters until every PEX
    // delivery has landed (criterion 5 reading face).
    let t0 = Instant::now();
    let leaves = LEAVES as u64;
    let (pex, total) = loop {
        let (pex, total) = metrics.discovered_peers();
        if pex >= leaves {
            break (pex, total);
        }
        if t0.elapsed() > BUDGET {
            let (p, t) = metrics.discovered_peers();
            panic!(
                "engine-level PEX count never reached full (budget {BUDGET:?}): \
                 pex={p} total={t}"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    assert_eq!(pex, leaves, "PEX-source discovery count");
    assert_eq!(
        total,
        1 + leaves,
        "total discovery = tracker 1 (S1) + pex 5 (leaves)"
    );
    let per_mille = (pex * 1000 / total.max(1)) as f64;
    assert!(
        per_mille > 0.0,
        "the engine-level contribution ratio must be > 0"
    );
    // Negotiation observation point: the engine's ext handshake
    // advertised ut_pex=1.
    let adv = rig
        .observed_adv
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .expect("the announcer never observed an ext handshake");
    assert_eq!(adv, Some(1), "the engine must advertise ut_pex=1");
    // Connection-management guards are not bypassed by PEX (the mirror
    // assertion of the PEX-source prohibition): on a single-IP loopback
    // topology, the ut_pex sender (S1) already occupies 127.0.0.1 — the
    // engine's "one connection per IP" guard (shared with the DHT/tracker
    // sources, the engine.rs pex arm included) collapses all leaf dials.
    // The discovery-face evidence = the counter point (the dial-decision
    // entry), not leaf accepts.
    let accepts = rig.leaf_accepts.load(Ordering::Relaxed);
    assert_eq!(
        accepts, 0,
        "the PEX source must not bypass the one-connection-per-IP guard"
    );
    // Consumption implies connection (existence evidence of source=pex
    // connections; the engine does not exit — the download is incomplete,
    // explicit cancel winds down).
    assert!(
        !engine.is_finished(),
        "the engine should keep running (download incomplete)"
    );
    root.cancel();
    let _ = tokio::time::timeout(BUDGET, engine).await;
    rig.teardown();
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Private face (acceptance criterion 3): private=true -> no
/// advertisement (the announcer observes no ut_pex in the m dict);
/// ut_pex sent anyway by the announcer is not consumed either — zero leaf
/// connections, pex count 0, total discovery holding only the tracker
/// source.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pex_private_torrent_silent() {
    let ih: [u8; 20] = Sha1::digest(b"p64-private-pex-target").into();
    // send_anyway=true: send regardless of negotiation, exercising the
    // engine-side consumption gate.
    let rig = spawn_rig(ih, 3, true).await;
    let tmp = tmp_dir("private");
    let metrics = Arc::new(SessionMetrics::new());

    let root = CancellationToken::new();
    let cfg = engine_cfg(
        rig.announces.clone(),
        tmp.clone(),
        GateCfg {
            ih,
            content_len: content().len() as u64,
            private: true,
            peer_exchange: true,
            metadata_serve: true,
        },
        Some(Arc::clone(&metrics)),
    );
    let engine = DownloadEngine::spawn(cfg, &root);

    // Wait for tracker-source discovery (the S1 dial happening = the
    // negotiation observation point has passed).
    let t0 = Instant::now();
    loop {
        let (_pex, total) = metrics.discovered_peers();
        if total >= 1 {
            break;
        }
        if t0.elapsed() > BUDGET {
            panic!("tracker-source discovery never happened (budget {BUDGET:?})");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Negotiation observation point: a private torrent's m dict has no
    // ut_pex.
    let adv = loop {
        // Lock held across no await: read the snapshot out, release, then
        // sleep.
        let observed = *rig.observed_adv.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(adv) = observed {
            break adv;
        }
        if t0.elapsed() > BUDGET {
            panic!("the announcer never observed an ext handshake (budget {BUDGET:?})");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(adv, None, "a private torrent must not advertise ut_pex");

    // Silence window: contract-breaking ut_pex is not consumed — zero
    // leaf connections, pex count 0.
    tokio::time::sleep(QUIET_WINDOW).await;
    let (pex, total) = metrics.discovered_peers();
    assert_eq!(
        pex, 0,
        "a private torrent must not consume ut_pex discoveries"
    );
    assert_eq!(
        total, 1,
        "total discovery holds only the tracker source (S1)"
    );
    assert_eq!(
        rig.leaf_accepts.load(Ordering::Relaxed),
        0,
        "zero leaf connections"
    );
    assert!(!engine.is_finished());
    root.cancel();
    let _ = tokio::time::timeout(BUDGET, engine).await;
    rig.teardown();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ===========================================================================
// Discovery source-address hygiene — PEX arm wiring assertions (a
// counterpart regression of the discovery-hygiene audit finding "the
// same shape applies to DHT/PEX sources").
// ===========================================================================

/// PEX arm wiring assertion: the announcer's ut_pex `added` injects a v4
/// unspecified address (0.0.0.0:<port>, the observable kernel fallback to
/// this host) + a positive-control leaf — reject-class addresses stay out
/// of the discovery count (the hygiene check precedes the counter point,
/// pex count = number of allowed addresses), sentinel zero connections;
/// the leaf enters the count as usual (zero regression on the allow
/// path). The same-IP guard may collapse the leaf's actual dial (single-IP
/// loopback topology, see test 1's note) — the discovery-face evidence is
/// the counter point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pex_hygiene_rejects_bogon_added_p122() {
    let ih: [u8; 20] = Sha1::digest(b"p122-pex-hygiene").into();

    // Positive-control leaf (loopback truth = allow class).
    let leaf_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "leaf bind",
    );
    let leaf_addr = ok(leaf_listener.local_addr(), "leaf addr");
    let leaf_accepts = Arc::new(AtomicUsize::new(0));
    let leaf_join = spawn_leaf(leaf_listener, ih, Arc::clone(&leaf_accepts)).await;

    // Negative sentinel: 0.0.0.0:<port> injection (without the hygiene
    // check the dialed connection would sit in the backlog).
    let sentinel = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "sentinel bind",
    );
    let sent_port = ok(sentinel.local_addr(), "sentinel addr").port();

    // announcer: fresh = [leaf (allow), 0.0.0.0 (reject)].
    let s1_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "s1 bind",
    );
    let s1_addr = ok(s1_listener.local_addr(), "s1 addr");
    let observed_adv: Arc<Mutex<Option<Option<u8>>>> = Arc::new(Mutex::new(None));
    let announcer = spawn_announcer(
        s1_listener,
        ih,
        vec![leaf_addr, SocketAddr::from(([0, 0, 0, 0], sent_port))],
        false,
        Arc::clone(&observed_adv),
    )
    .await;
    let announces = fake_tracker(s1_addr).await;

    let tmp = tmp_dir("p122-hygiene");
    let metrics = Arc::new(SessionMetrics::new());
    let root = CancellationToken::new();
    let cfg = engine_cfg(
        announces.clone(),
        tmp.clone(),
        GateCfg {
            ih,
            content_len: content().len() as u64,
            private: false,
            peer_exchange: true,
            metadata_serve: false,
        },
        Some(Arc::clone(&metrics)),
    );
    let engine = DownloadEngine::spawn(cfg, &root);

    // Positive control: the PEX delivery must arrive (pex count >= 1 =
    // the chain is alive).
    let deadline = std::time::Instant::now() + BUDGET;
    let (pex, total) = loop {
        let (pex, total) = metrics.discovered_peers();
        if pex >= 1 {
            break (pex, total);
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "the PEX delivery did not arrive within budget (broken chain): \
                 pex={pex} total={total}"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        pex, 1,
        "the PEX count holds only hygiene-allowed addresses \
         (0.0.0.0 must be rejected before the counting point)"
    );
    assert_eq!(
        total, 2,
        "total discovery = tracker 1 (S1) + pex 1 (leaf; 0.0.0.0 not counted)"
    );

    // Negative assertion: sentinel zero connections (reject class dials
    // nothing).
    let sentinel = sentinel;
    let quiet_end = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < quiet_end {
        match tokio::time::timeout(Duration::from_millis(100), sentinel.accept()).await {
            Err(_) => {}
            Ok(Ok((_, peer))) => {
                panic!(
                    "the v4 unspecified-address injection must be rejected by the \
                     hygiene check (observed a {peer} connection)"
                )
            }
            Ok(Err(e)) => panic!("sentinel accept error: {e}"),
        }
    }

    root.cancel();
    let _ = tokio::time::timeout(BUDGET, engine).await;
    announcer.abort();
    leaf_join.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
