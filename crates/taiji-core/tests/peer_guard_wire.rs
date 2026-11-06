//! Acceptance: filter-point integration (accept rejection / dial skip /
//! online disconnect) + the two ban event chains (protocol violation and
//! hash verification failure) + the peer_ban/ipfilter restart roundtrip.
//!
//! Chain (per case): build a v1-only metainfo locally -> engine (guard
//! snapshot injected) -> fake peer / fake tracker -> assert the IpGuard
//! snapshot and the peer_ban/ipfilter table state.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use taiji_bt::peer_policy::{IpGuard, IpGuardHandle};
use taiji_core::engine::{DownloadEngine, EngineEnd, TrackerWireConfig};
use taiji_core::metainfo::Metainfo;
use taiji_store::persist::PersistWriter;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const L: u64 = 16384;
const PEER_ID: [u8; 20] = *b"-TJ0001-GUARDGUARD01";
const GID: &str = "8000000000000030";
/// Dead tracker (port 1: announce always fails, no peers — a quiet
/// swarm).
const DEAD_TRACKER: &str = "http://127.0.0.1:1/announce";

fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
    pairs.sort_by(|a, a2| a.0.cmp(a2.0));
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
}

/// v1-only metainfo (real SHA-1 pieces, 16 KiB piece length).
fn build_v1_torrent(content: &[u8], announce: &str, name: &str) -> Vec<u8> {
    let pieces: Vec<u8> = content.chunks(L as usize).flat_map(Sha1::digest).collect();
    let info = dict(vec![
        (b"length", Value::Int(content.len() as i64)),
        (b"name", Value::Bytes(name.as_bytes().to_vec())),
        (b"piece length", Value::Int(L as i64)),
        (b"pieces", Value::Bytes(pieces)),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(announce.as_bytes().to_vec())),
        (b"info", info),
    ]);
    bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"))
}

fn v1_info_hash(meta: &Metainfo) -> [u8; 20] {
    let h = meta
        .meta
        .identity
        .v1
        .unwrap_or_else(|| panic!("v1 identity"));
    let mut t = [0u8; 20];
    t.copy_from_slice(&h);
    t
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p30-{}-{}-{}",
        tag,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

fn epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Probes a free port (binds then releases; the usual test convention,
/// with a tiny race window).
fn probe_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("probe: {e}"))
        .local_addr()
        .unwrap_or_else(|e| panic!("probe: {e}"))
        .port()
}

/// Polls until the condition holds (100 ms steps; panics on timeout).
async fn wait_until(mut cond: impl FnMut() -> bool, budget: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + budget;
    while !cond() {
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout: {what}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Handshake frame (peer -> engine; reserved = ext + fast, aligned with
/// the engine's outbound face).
fn handshake(info_hash: [u8; 20]) -> Vec<u8> {
    let mut h = vec![19u8];
    h.extend_from_slice(b"BitTorrent protocol");
    h.extend_from_slice(&[0, 0, 0, 0, 0, 0x10, 0, 0x04]);
    h.extend_from_slice(&info_hash);
    h.extend_from_slice(b"PEER-THE-PEER-000001");
    h
}

/// Wire frame: `u32 BE len + id + payload`.
fn frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + payload.len());
    f.extend_from_slice(&((1 + payload.len()) as u32).to_be_bytes());
    f.push(id);
    f.extend_from_slice(payload);
    f
}

/// Serializes the engine port window: under parallel cases the
/// "probe -> engine bind" sequence races (two cases probe the same port
/// -> one bind fails -> the connection lands on the other's engine ->
/// the handshake gets closed). The gate is held through probe -> spawn
/// -> listener ready (while the engine is binding, the kernel cannot
/// hand the port to another case's probe).
async fn port_gate() -> tokio::sync::MutexGuard<'static, ()> {
    static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    GATE.lock().await
}

/// Waits for the engine listener to come up (run() binds asynchronously;
/// the probe connection sends no data — the engine's handshake timeout
/// closes it by itself, no side effects).
async fn wait_listening(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let probe = tokio::net::TcpStream::connect(("127.0.0.1", port)).await;
        match probe {
            Ok(_s) => {
                // The probe connection stays open (the fd is deliberately
                // leaked): closing it immediately would RST the not-yet-
                // accepted queued connection on macOS kqueue, poisoning the
                // subsequent accept (a bad fd that reads no data; the same
                // platform issue as Go golang#39946).
                std::mem::forget(_s);
                return;
            }
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("engine listener not up within 5s");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Completes a bidirectional handshake with the engine and returns the
/// socket (the peer can then send and receive message frames).
async fn connect_peer(port: u16, info_hash: [u8; 20]) -> tokio::net::TcpStream {
    wait_listening(port).await;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("peer connect: {e}"));
    s.write_all(&handshake(info_hash))
        .await
        .unwrap_or_else(|e| panic!("peer handshake send: {e}"));
    let mut resp = [0u8; 68];
    s.read_exact(&mut resp)
        .await
        .unwrap_or_else(|e| panic!("peer handshake recv: {e}"));
    s
}

/// Unsolicited piece frame (piece 1 of a two-piece torrent: dispatch
/// always picks piece 0, so this coordinate can never be in the pending
/// set -> necessarily unsolicited).
fn unsolicited_piece_of_piece1() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&vec![0u8; L as usize]);
    frame(7u8, &payload)
}

/// Fake tracker: answers each announce with the seeder address (v4
/// compact) and counts announces.
async fn fake_tracker(seeder: SocketAddr, announces: Arc<AtomicUsize>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("tracker bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
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
            announces.fetch_add(1, Ordering::SeqCst);
            let SocketAddr::V4(v4) = seeder else {
                panic!("test expects IPv4 seeder");
            };
            let mut peers = Vec::new();
            peers.extend_from_slice(&v4.ip().octets());
            peers.extend_from_slice(&v4.port().to_be_bytes());
            let mut raw = Vec::new();
            raw.extend_from_slice(b"d8:intervali60e5:peers");
            raw.extend_from_slice(peers.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&raw).await;
            let _ = sock.shutdown().await;
        }
    });
    addr
}

/// Test fixture: the torrent parent row (the tracker table needs its FK;
/// peer_ban/ipfilter have no FK — this just keeps the DB shape aligned
/// with production).
fn insert_fixture_torrent(db: &std::path::Path) {
    let conn = rusqlite::Connection::open(db).unwrap_or_else(|e| panic!("{e}"));
    conn.execute(
        "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind, created_at, updated_at)
         VALUES (?1, 'fixture', 'downloading', 0, '/tmp/fixture', '{}', 'v1', 0, 0)",
        [GID],
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

/// Corrupt seeder: after the handshake, answers every request with a piece
/// whose content is wrong (triggers v1 whole-piece verification failure ->
/// the PieceDropped attribution chain). Returns the EOF observer (peer-side
/// evidence of the engine disconnecting after the ban).
async fn corrupt_seeder(
    listener: tokio::net::TcpListener,
    info_hash: [u8; 20],
    eof_seen: Arc<std::sync::atomic::AtomicBool>,
) {
    let (mut sock, _) = listener
        .accept()
        .await
        .unwrap_or_else(|e| panic!("seeder accept: {e}"));
    let mut hs = [0u8; 68];
    sock.read_exact(&mut hs)
        .await
        .unwrap_or_else(|e| panic!("seeder read hs: {e}"));
    let mut resp = [0u8; 68];
    resp[0] = 19;
    resp[1..20].copy_from_slice(b"BitTorrent protocol");
    resp[25] = 0x10;
    resp[27] = 0x04;
    resp[28..48].copy_from_slice(&info_hash);
    resp[48..68].copy_from_slice(b"BADSEEDBADSEEDBAD001");
    sock.write_all(&resp)
        .await
        .unwrap_or_else(|e| panic!("seeder write hs: {e}"));
    // The corrupt seeder sends the full bitfield after its handshake
    // (BEP 3; 3 pieces = 0b1110_0000) — a real bad peer must advertise
    // holding data (otherwise nothing can be delivered), advertisement-
    // aware dispatch requests from it as usual, and the corruption defense
    // (hash-failure sliding-window ban) is the object under test. It
    // previously advertised nothing and relied on the dispatcher's
    // blind-pick fallback; that fallback was removed with
    // advertisement-aware dispatch.
    sock.write_all(&frame(5u8, &[0b1110_0000]))
        .await
        .unwrap_or_else(|e| panic!("seeder write bitfield: {e}"));
    // Reciprocity: unchoke (dispatch sends zero requests to a peer that
    // chokes us — direct translation of aria2 fillPiece; the bad peer must
    // be allowed to serve requests, the corruption defense (hash-failure
    // sliding-window ban) is the object under test).
    sock.write_all(&frame(1u8, &[]))
        .await
        .unwrap_or_else(|e| panic!("seeder write unchoke: {e}"));
    loop {
        let mut len_buf = [0u8; 4];
        match sock.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(_) => {
                // The engine disconnected (the ban message-level filter
                // point) or the test is winding down.
                eof_seen.store(true, Ordering::SeqCst);
                return;
            }
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut body = vec![0u8; len];
        if sock.read_exact(&mut body).await.is_err() {
            eof_seen.store(true, Ordering::SeqCst);
            return;
        }
        if body[0] == 6 && body.len() >= 13 {
            // request -> answer with bad data (necessarily mismatching the
            // expected hash).
            let mut payload = Vec::with_capacity(8 + body.len() - 13);
            payload.extend_from_slice(&body[1..9]);
            payload.extend_from_slice(&vec![0xFFu8; body.len() - 13]);
            let _ = sock.write_all(&frame(7u8, &payload)).await;
        }
    }
}

/// Asserts the inbound connection is rejected (accept filter point): the
/// connection closes (EOF/RST) and no handshake response bytes ever
/// arrive. The peer's handshake write may RST because the engine closed
/// first — a write failure is equally evidence of rejection.
async fn assert_inbound_rejected(port: u16, ih: [u8; 20], what: &str) {
    wait_listening(port).await;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = s.write_all(&handshake(ih)).await;
    let mut buf = [0u8; 68];
    let n = match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
        Err(_) => panic!("{what}: inbound not rejected within 5s (engine answered?)"),
        Ok(Ok(n)) => n,
        Ok(Err(_)) => 0, // ECONNRESET: the engine already closed (unread data -> RST)
    };
    assert_eq!(n, 0, "{what}: engine must not answer filtered peer");
}

/// Criterion 4 (two filter points): blocklist deny across the loopback —
/// (1) the tracker has replied with the seeder address but the engine
/// never dials (IpGuard checked before dial); (2) a loopback inbound
/// connection is closed before the handshake (IpGuard checked at
/// accept).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocklist_blocks_dial_and_accept() {
    let tmp = tmp_dir("blocklist");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let accepts = Arc::new(AtomicUsize::new(0));
    let seeder_accepts = Arc::clone(&accepts);
    let seeder_task = tokio::spawn(async move {
        // The seeder only counts TCP accepts (any engine dial = +1).
        while let Ok((_s, _)) = seeder_listener.accept().await {
            seeder_accepts.fetch_add(1, Ordering::SeqCst);
        }
    });
    let announces = Arc::new(AtomicUsize::new(0));
    let tracker_addr = fake_tracker(seeder_addr, Arc::clone(&announces)).await;

    let torrent = build_v1_torrent(
        &vec![0u8; L as usize],
        &format!("http://{tracker_addr}/announce"),
        "guard.bin",
    );
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));

    // IpGuard snapshot: deny the whole loopback (eMule dat parse -> rules
    // -> snapshot; isomorphic to the import hot-update path).
    let guard = IpGuardHandle::new(IpGuard::default());
    let parsed = taiji_bt::peer_policy::parse_emule_dat("deny,127.0.0.0,127.255.255.255\n");
    assert_eq!(parsed.rules.len(), 1);
    guard.store(IpGuard::new(parsed.rules.iter().copied(), []));

    let wire = TrackerWireConfig {
        tiers: vec![],
        persist: None,
        guard: Some(guard.clone()),
    };
    let root = CancellationToken::new();
    let _port = {
        let _g = port_gate().await;
        let p = probe_port();
        let cfg = taiji_core::engine::engine_config(
            &meta,
            tmp.clone(),
            p,
            PEER_ID,
            taiji_core::engine::CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("cfg: {e}"));
        let engine = DownloadEngine::spawn_with(cfg, wire, &root);
        wait_listening(p).await;
        (p, engine)
    };
    let (port, engine) = _port;

    // (1) The announce has arrived (tracker count > 0) while seeder
    // accepts stay 0: the engine got the peer address but never dialed =
    // the dial filter point works.
    wait_until(
        || announces.load(Ordering::SeqCst) > 0,
        Duration::from_secs(15),
        "tracker announce never arrived",
    )
    .await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "blocked IP must not be dialed"
    );

    // (2) Inbound: the loopback peer's connection is closed outright (no
    // handshake bytes answered).
    assert_inbound_rejected(port, v1_info_hash(&meta), "accept filter").await;

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(5), engine).await;
    assert!(matches!(end, Ok(Ok(EngineEnd::Cancelled)) | Err(_)));
    seeder_task.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Criterion 4 (message-level filter point + protocol-violation chain):
/// two peers of the same IP are online; P1 sends an unsolicited piece
/// (protocol violation) -> P1 disconnects + the IP is auto-banned (with
/// an until, a peer_ban row lands) + P2 (same IP, not in violation) is
/// disconnected immediately.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_violation_bans_ip_and_disconnects_peers() {
    let tmp = tmp_dir("violation");
    let db = tmp.join("taiji.sqlite3");
    // Spawn the writer first (applies migrations, creates tables), then
    // insert the torrent parent row (FK for tracker rows).
    let (persist, writer_join) = PersistWriter::spawn(db.clone())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    insert_fixture_torrent(&db);

    // Two-piece torrent: piece 1 is never requested (dispatch always
    // picks the first incomplete piece = piece 0).
    let content = vec![3u8; 2 * L as usize];
    let torrent = build_v1_torrent(&content, DEAD_TRACKER, "viol.bin");
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("{e}"));
    let ih = v1_info_hash(&meta);

    let guard = IpGuardHandle::new(IpGuard::default());
    let wire = TrackerWireConfig {
        tiers: vec![],
        persist: Some((GID.to_string(), persist.clone())),
        guard: Some(guard.clone()),
    };
    let root = CancellationToken::new();
    let (port, engine) = {
        let _g = port_gate().await;
        let p = probe_port();
        let cfg = taiji_core::engine::engine_config(
            &meta,
            tmp.clone(),
            p,
            PEER_ID,
            taiji_core::engine::CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("cfg: {e}"));
        let engine = DownloadEngine::spawn_with(cfg, wire, &root);
        wait_listening(p).await;
        (p, engine)
    };

    // Two peers on the same IP (loopback) complete the handshake and
    // register.
    let mut p1 = connect_peer(port, ih).await;
    let mut p2 = connect_peer(port, ih).await;
    tokio::time::sleep(Duration::from_millis(800)).await; // registration converges

    // P1: unsolicited piece -> PeerEnd::Violation -> Violation event ->
    // immediate ban.
    p1.write_all(&unsolicited_piece_of_piece1())
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // P1 disconnects (violation end state; reading engine-first
    // bitfield/interested bytes is also legal).
    let mut sink1 = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), p1.read_to_end(&mut sink1))
        .await
        .unwrap_or_else(|_| panic!("violator not disconnected within 5s"))
        .unwrap_or_else(|e| panic!("{e}"));

    // The ban takes effect (snapshot hot-updated): until > now.
    let loopback: IpAddr = "127.0.0.1".parse().unwrap_or_else(|e| panic!("{e}"));
    wait_until(
        || guard.load().blocks(loopback, epoch_secs()).is_some(),
        Duration::from_secs(5),
        "violation ban not visible in IpGuard snapshot",
    )
    .await;

    // Message-level filter point: P2 (same IP, not in violation) is
    // disconnected immediately.
    let mut sink2 = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), p2.read_to_end(&mut sink2))
        .await
        .unwrap_or_else(|_| panic!("same-ip connected peer not disconnected within 5s"))
        .unwrap_or_else(|e| panic!("{e}"));

    // peer_ban row lands: reading back active yields exactly one loopback
    // row.
    let rows = persist
        .load_active_peer_bans(epoch_secs())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rows.len(), 1, "one active ban row: {rows:?}");
    assert_eq!(rows[0].ip, "127.0.0.1");
    assert!(
        !rows[0].reason.is_empty(),
        "a ban is never silent: reason is required (§2.6)"
    );

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(5), engine).await;
    assert!(matches!(end, Ok(Ok(EngineEnd::Cancelled)) | Err(_)));
    drop(persist);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer_join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Criteria 2/4 (hash-failure event chain): the corrupt seeder repeatedly
/// serves wrong pieces -> v1 whole-piece verification failures attributed
/// (sliding window >= 3 within 10 min) -> auto ban + online disconnect
/// (the seeder side observes EOF).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hash_failures_slide_window_into_ban() {
    let tmp = tmp_dir("hashban");

    // Corrupt seeder (starts listening first; its addr goes to the
    // tracker's reply for the engine).
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));

    // Three-piece torrent (48 KiB).
    let content = vec![7u8; 3 * L as usize];
    let announces = Arc::new(AtomicUsize::new(0));
    let tracker_addr = fake_tracker(seeder_addr, Arc::clone(&announces)).await;
    let torrent = build_v1_torrent(
        &content,
        &format!("http://{tracker_addr}/announce"),
        "corrupt.bin",
    );
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("{e}"));
    let ih = v1_info_hash(&meta);

    let eof_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seeder_task = tokio::spawn(corrupt_seeder(seeder_listener, ih, Arc::clone(&eof_seen)));

    let guard = IpGuardHandle::new(IpGuard::default());
    let wire = TrackerWireConfig {
        tiers: vec![],
        persist: None,
        guard: Some(guard.clone()),
    };
    let root = CancellationToken::new();
    let _engine = {
        let _g = port_gate().await;
        let p = probe_port();
        let cfg = taiji_core::engine::engine_config(
            &meta,
            tmp.clone(),
            p,
            PEER_ID,
            taiji_core::engine::CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("cfg: {e}"));
        let engine = DownloadEngine::spawn_with(cfg, wire, &root);
        wait_listening(p).await;
        engine
    };

    // Engine dials -> bad piece -> PieceDropped attribution -> sliding
    // window reaches 3 (2 s redispatch cadence) -> ban. Budget 40 s
    // (3 failures x >= 2 s spacing + announce round trips).
    wait_until(
        || {
            guard
                .load()
                .blocks(seeder_addr.ip(), epoch_secs())
                .is_some()
        },
        Duration::from_secs(40),
        "corrupt seeder not banned within budget (sliding window)",
    )
    .await;

    // Message-level filter point: the banned seeder's connection is torn
    // down by the engine (peer-side EOF).
    wait_until(
        || eof_seen.load(Ordering::SeqCst),
        Duration::from_secs(10),
        "banned seeder connection not disconnected",
    )
    .await;

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(5), _engine).await;
    assert!(matches!(end, Ok(Ok(EngineEnd::Cancelled)) | Err(_)));
    let _ = seeder_task.await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Varying corrupt seeder (the smart_ban synthetic adversarial face):
/// answers every request with error content that **changes each time** —
/// the same peer yields two different digests for the same block across
/// attempts (both failures are recorded) => the smart_ban digest
/// contradiction self-proofs and locates + bans within the 2nd piece
/// cycle (the sliding window would need 3 failures; the ban reason's
/// `smart-ban:` prefix distinguishes the two defenses). Returns the EOF
/// observer.
async fn varying_corrupt_seeder(
    listener: tokio::net::TcpListener,
    info_hash: [u8; 20],
    eof_seen: Arc<std::sync::atomic::AtomicBool>,
) {
    let (mut sock, _) = listener
        .accept()
        .await
        .unwrap_or_else(|e| panic!("seeder accept: {e}"));
    let mut hs = [0u8; 68];
    sock.read_exact(&mut hs)
        .await
        .unwrap_or_else(|e| panic!("seeder read hs: {e}"));
    let mut resp = [0u8; 68];
    resp[0] = 19;
    resp[1..20].copy_from_slice(b"BitTorrent protocol");
    resp[25] = 0x10;
    resp[27] = 0x04;
    resp[28..48].copy_from_slice(&info_hash);
    resp[48..68].copy_from_slice(b"VARSEEDVARSEEDVAR001");
    sock.write_all(&resp)
        .await
        .unwrap_or_else(|e| panic!("seeder write hs: {e}"));
    // BEP 3 full bitfield + unchoke (preconditions for advertisement-aware
    // dispatch and the choke gate — same shape as the existing
    // corrupt_seeder).
    sock.write_all(&frame(5u8, &[0b1110_0000]))
        .await
        .unwrap_or_else(|e| panic!("seeder write bitfield: {e}"));
    sock.write_all(&frame(1u8, &[]))
        .await
        .unwrap_or_else(|e| panic!("seeder write unchoke: {e}"));
    let mut served: u32 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match sock.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(_) => {
                eof_seen.store(true, Ordering::SeqCst);
                return;
            }
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut body = vec![0u8; len];
        if sock.read_exact(&mut body).await.is_err() {
            eof_seen.store(true, Ordering::SeqCst);
            return;
        }
        if body[0] == 6 && body.len() >= 13 {
            // request -> answer with varying bad data: the n-th serve uses
            // the 0xA0+n byte pattern, different every time (necessarily
            // mismatching the expected hash, and the two failures'
            // digests necessarily differ — the driver of the contradiction
            // self-proof). The payload length uses the request's length
            // field (body[9..13]) — real data delivery is a precondition
            // of this test (the existing corrupt_seeder in this file uses
            // the fixed `body.len()-13` = always-zero-byte empty piece, an
            // adjacent quirk; this seeder does not copy that shape).
            let want_len = u32::from_be_bytes([body[9], body[10], body[11], body[12]]) as usize;
            served = served.wrapping_add(1);
            let fill = 0xA0u8.wrapping_add(served as u8);
            let mut payload = Vec::with_capacity(8 + want_len);
            payload.extend_from_slice(&body[1..9]);
            payload.extend_from_slice(&vec![fill; want_len]);
            let _ = sock.write_all(&frame(7u8, &payload)).await;
        }
    }
}

/// Criterion (smart_ban acceptance): a synthetic adversarial swarm — a
/// malicious peer injects bad blocks that mutate each attempt, and
/// smart_ban locates + bans within <= 2 piece cycles (the `smart-ban:`
/// reason prefix = evidence that the self-proof path fired, distinct
/// from the sliding-window reason). Good peers are never falsely banned —
/// pinned by the ledger-layer mixed scenario
/// (engine::ban::tests::mixed_swarm_decision_table_good_peer_never_flagged;
/// a single-peer wire-layer variant cannot state the good peer within one
/// case).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smart_ban_contradiction_bans_within_two_piece_cycles() {
    let tmp = tmp_dir("smartban");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));

    // Three-piece torrent (48 KiB; one 16 KiB piece = one block — a single
    // delivery is a whole piece).
    let content = vec![7u8; 3 * L as usize];
    let announces = Arc::new(AtomicUsize::new(0));
    let tracker_addr = fake_tracker(seeder_addr, Arc::clone(&announces)).await;
    let torrent = build_v1_torrent(
        &content,
        &format!("http://{tracker_addr}/announce"),
        "vary.bin",
    );
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));
    let ih = v1_info_hash(&meta);

    let eof_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seeder_task = tokio::spawn(varying_corrupt_seeder(
        seeder_listener,
        ih,
        Arc::clone(&eof_seen),
    ));

    let guard = IpGuardHandle::new(IpGuard::default());
    let wire = TrackerWireConfig {
        tiers: vec![],
        persist: None,
        guard: Some(guard.clone()),
    };
    let root = CancellationToken::new();
    let _engine = {
        let _g = port_gate().await;
        let p = probe_port();
        let cfg = taiji_core::engine::engine_config(
            &meta,
            tmp.clone(),
            p,
            PEER_ID,
            taiji_core::engine::CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("cfg: {e}"));
        let engine = DownloadEngine::spawn_with(cfg, wire, &root);
        wait_listening(p).await;
        engine
    };

    // Budget 30 s: cycle-1 failure (evidence recorded) -> 2 s redispatch
    // window -> cycle-2 failure (digest contradiction) -> ban +
    // disconnect. The reason must carry the smart-ban prefix (if the
    // sliding window banned first, the reason would read "hash
    // verification failures..." — this assertion also proves the
    // contradiction self-proof fires before 3 failures = <= 2 piece
    // cycles).
    wait_until(
        || {
            matches!(
                guard.load().blocks(seeder_addr.ip(), epoch_secs()),
                Some(taiji_bt::peer_policy::IpBlock::Banned(ref r))
                    if r.starts_with("smart-ban:")
            )
        },
        Duration::from_secs(30),
        "varying corrupt seeder not smart-banned within budget",
    )
    .await;

    // Effect face: after the ban the connection is torn down by the
    // engine (peer-side EOF).
    wait_until(
        || eof_seen.load(Ordering::SeqCst),
        Duration::from_secs(10),
        "smart-banned seeder connection not disconnected",
    )
    .await;

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(5), _engine).await;
    assert!(matches!(end, Ok(Ok(EngineEnd::Cancelled)) | Err(_)));
    let _ = seeder_task.await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Criterion 5 (roundtrip): session 1 violation ban + eMule blocklist
/// import (ipfilter table rows) -> engine restart (session 2, same DB +
/// fresh guard snapshot) -> the active ban and static rules read back and
/// take effect: the guard blocks loopback + a deny-range hit + inbound
/// connections rejected before the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ban_and_blocklist_roundtrip_across_engine_restart() {
    let tmp = tmp_dir("roundtrip");
    let db = tmp.join("taiji.sqlite3");

    // ---- Session 1: violation ban + blocklist import ----
    let content = vec![5u8; 2 * L as usize];
    let torrent = build_v1_torrent(&content, DEAD_TRACKER, "rt.bin");
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("{e}"));
    let ih = v1_info_hash(&meta);

    // Spawn the writer first (applies migrations, creates tables), then
    // insert the torrent parent row (FK for tracker rows).
    let (persist1, writer1) = PersistWriter::spawn(db.clone())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    insert_fixture_torrent(&db);
    let guard1 = IpGuardHandle::new(IpGuard::default());
    let wire1 = TrackerWireConfig {
        tiers: vec![],
        persist: Some((GID.to_string(), persist1.clone())),
        guard: Some(guard1.clone()),
    };
    let root1 = CancellationToken::new();
    let (port, engine1) = {
        let _g = port_gate().await;
        let p = probe_port();
        let cfg1 = taiji_core::engine::engine_config(
            &meta,
            tmp.clone(),
            p,
            PEER_ID,
            taiji_core::engine::CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("cfg: {e}"));
        let engine1 = DownloadEngine::spawn_with(cfg1, wire1, &root1);
        wait_listening(p).await;
        (p, engine1)
    };

    let mut p1 = connect_peer(port, ih).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    p1.write_all(&unsolicited_piece_of_piece1())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let loopback: IpAddr = "127.0.0.1".parse().unwrap_or_else(|e| panic!("{e}"));
    wait_until(
        || guard1.load().blocks(loopback, epoch_secs()).is_some(),
        Duration::from_secs(5),
        "session-1 violation ban not visible",
    )
    .await;

    // eMule blocklist import (a non-loopback range; whole-table replace
    // lands in the ipfilter table + hot-updates the snapshot).
    let dat = tmp.join("guarding.dat");
    std::fs::write(&dat, "deny,010.009.009.000,010.009.009.255\n")
        .unwrap_or_else(|e| panic!("{e}"));
    let report =
        taiji_core::peer_guard::import_emule_blocklist(&dat, Some(&persist1), &guard1, &[])
            .await
            .unwrap_or_else(|e| panic!("import: {e}"));
    assert_eq!(report.total_rules, 1);
    assert_eq!(report.skipped, 0);

    root1.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), engine1).await;
    drop(persist1);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer1).await;

    // ---- Session 2 (kill-restart simulation): same DB + a fresh guard
    // snapshot ----
    let (persist2, writer2) = PersistWriter::spawn(db.clone())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let guard2 = IpGuardHandle::new(IpGuard::default());
    let wire2 = TrackerWireConfig {
        tiers: vec![],
        persist: Some((GID.to_string(), persist2.clone())),
        guard: Some(guard2.clone()),
    };
    let root2 = CancellationToken::new();
    let (port2, engine2) = {
        let _g = port_gate().await;
        let p = probe_port();
        let cfg2 = taiji_core::engine::engine_config(
            &meta,
            tmp.clone(),
            p,
            PEER_ID,
            taiji_core::engine::CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("cfg2: {e}"));
        let engine2 = DownloadEngine::spawn_with(cfg2, wire2, &root2);
        wait_listening(p).await;
        (p, engine2)
    };

    // Startup read-back (active unexpired bans + ipfilter rules) -> the
    // snapshot takes effect.
    wait_until(
        || guard2.load().blocks(loopback, epoch_secs()).is_some(),
        Duration::from_secs(10),
        "ban readback after restart failed",
    )
    .await;
    let remote: IpAddr = "10.9.9.5".parse().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        guard2.load().blocks(remote, epoch_secs()),
        Some(taiji_bt::peer_policy::IpBlock::Denied),
        "the ipfilter rule reads back as effective (zero-filled dat line)"
    );

    // The ban really takes effect after restart: an inbound loopback
    // connection is rejected before the handshake (no handshake bytes
    // answered).
    assert_inbound_rejected(port2, ih, "restart accept filter").await;

    root2.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), engine2).await;
    drop(persist2);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer2).await;
    let _ = std::fs::remove_dir_all(&tmp);
}
