//! Acceptance: end-to-end recovery event surface (taiji.recoveryStarted /
//! taiji.recoveryCompleted — emission point -> HookRunner relay slot ->
//! payload assertions). Events fire at points the engine state machine
//! already has; the RPC surface only consumes the forwarded engine half,
//! and this test closes that loop.
//!
//! Per case: build a v2-only metainfo **missing piece layers** locally
//! (parse degrades to layer_missing — the missing-layer gate's live
//! production path) -> fake tracker -> mock seeder (answers hash request
//! (21) with a freshly computed leaf layer as `hashes` (22); piece data
//! plane serves correct and corrupt variants) -> engine activates ->
//! assert:
//!
//! 1. Converged success: Started exactly once (payload files = [1]) ->
//!    admission/promotion -> Completed exactly once (same payload
//!    order) -> download finishes and the file matches byte for byte
//!    (the whole chain really runs beneath the events — nothing
//!    synthetic).
//! 2. Gate-stuck ("started without completed"): the seeder keeps
//!    returning bad layers -> Started fires, Completed never appears in
//!    the window (there is no failure terminal state; budget exhaustion
//!    keeps the state recovering, so completed-exactly-once stays clean).
//!
//! Protocol source: BEP 52 hash exchange (recovery's whole-file base
//! layer fetch is the same hash-request surface as lazy fetch). The
//! fixture mirrors corruption_injection.rs; the only differences are the
//! removed `piece layers` key and assertions against the event sequence.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use taiji_bt::bencode::{self, Value};
use taiji_core::engine::{DownloadEngine, EngineEnd};
use taiji_core::hook::{HookRunner, HookSet};
use taiji_core::metainfo::Metainfo;
use taiji_core::session::{RecoveryEventKind, RecoveryNotice};
use taiji_store::merkle;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Piece length: 64 KiB (4 blocks per piece); the 128 KiB file spans 2
/// pieces. Multi-piece on purpose: single-piece files never register
/// recovery (BEP 52).
const P: u64 = 64 * 1024;
const BLOCK: u64 = 16 * 1024;

fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
}

/// v2-only metainfo with **no top-level piece layers** — the only
/// construction difference for the layer-missing shape (parse degrades
/// to layer_missing).
fn build_torrent(content: &[u8], announce: &str) -> Vec<u8> {
    let bpp = (P / BLOCK) as usize;
    let piece_roots: Vec<[u8; 32]> = content
        .chunks(P as usize)
        .map(|c| {
            let blocks: Vec<[u8; 32]> = c.chunks(BLOCK as usize).map(merkle::block_hash).collect();
            merkle::root_from_block_hashes(&blocks)
        })
        .collect();
    let root = merkle::file_root_from_piece_roots(&piece_roots, bpp);
    let file_entry = dict(vec![(
        b"",
        dict(vec![
            (b"length", Value::Int(content.len() as i64)),
            (b"pieces root", Value::Bytes(root.to_vec())),
        ]),
    )]);
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![(b"v2.bin".to_vec(), file_entry)]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(P as i64)),
    ]);
    // No "piece layers" key — the parse side degrades to layer_missing.
    let top = dict(vec![
        (b"announce", Value::Bytes(announce.as_bytes().to_vec())),
        (b"info", info),
    ]);
    bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"))
}

/// Captures recovery events (test-side consumer of the HookRunner
/// recovery-notify slot).
#[derive(Clone, Default)]
struct EventCapture {
    events: Arc<Mutex<Vec<RecoveryNotice>>>,
}

impl EventCapture {
    fn push(&self, ev: RecoveryNotice) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(ev);
    }

    fn snapshot(&self) -> Vec<RecoveryNotice> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Wait until the capture count reaches `n` (bounded window; on
    /// timeout the assertion dumps the events seen so far).
    async fn wait_len(&self, n: usize, what: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while self.snapshot().len() < n {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timeout waiting for {what}; got {:?}",
                self.snapshot()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Mock seeder: serves the v2 piece space and answers hash requests with
/// leaf layers. With `corrupt_hashes = true` it flips one bit in the
/// `hashes` (22) payload, so whole-file convergence always fails (drives
/// the gate-stuck scenario).
async fn seeder(listener: tokio::net::TcpListener, content: Arc<Vec<u8>>, corrupt_hashes: bool) {
    let (mut sock, _) = listener
        .accept()
        .await
        .unwrap_or_else(|e| panic!("accept: {e}"));
    let mut hs = [0u8; 68];
    sock.read_exact(&mut hs)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut resp = [0u8; 68];
    resp[0] = 19;
    resp[1..20].copy_from_slice(b"BitTorrent protocol");
    resp[25] = 0x10; // extended
    resp[27] = 0x04; // fast
    resp[29] = 0x10; // v2 capability bit (BEP 52)
    resp[28..48].copy_from_slice(&hs[28..48]);
    resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
    sock.write_all(&resp)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // Full bitfield ad (this fixture has 2 pieces = 0b1100_0000); a real
    // client that holds data always advertises.
    sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
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
                21 => {
                    // Answer hash requests by computing on the fly
                    // (proof = 0 asserted; any base layer — recovery
                    // fetches the piece-root layer, base = log2(bpp) = 2
                    // for 2 pieces x 4 blocks; lazy fetch reads the leaf
                    // layer, base 0).
                    if body.len() < 49 {
                        break;
                    }
                    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                    let base = be32(&body[33..]);
                    let index = be32(&body[37..]);
                    let length = be32(&body[41..]);
                    let proof = be32(&body[45..]);
                    assert_eq!(proof, 0, "the fixture issues no proof requests");
                    assert!(
                        length.is_power_of_two() && (2..=512).contains(&length),
                        "BEP52 MUST (power of two >= 2) / SHOULD (<= 512): {length}"
                    );
                    // A base-layer node is the merged root of 2^base
                    // consecutive leaves; leaves past EOF are zero-filled
                    // (the server pads, the requester truncates).
                    let span = 1u64 << base;
                    let mut hashes = Vec::with_capacity(length as usize);
                    for i in index..index + length {
                        let leaves: Vec<[u8; 32]> = (0..span)
                            .map(|k| {
                                let s = (u64::from(i) * span + k) * BLOCK;
                                if s >= content.len() as u64 {
                                    return [0u8; 32];
                                }
                                let e = (s + BLOCK).min(content.len() as u64) as usize;
                                Sha256::digest(&content[s as usize..e]).into()
                            })
                            .collect();
                        let node = if base == 0 {
                            leaves[0]
                        } else {
                            merkle::root_from_block_hashes(&leaves)
                        };
                        hashes.push(node);
                    }
                    if corrupt_hashes {
                        // Hostile peer: flipping one bit in any hash must
                        // break whole-file convergence (SHA-256
                        // collision resistance).
                        hashes[0][0] ^= 0x01;
                    }
                    let mut frame = Vec::with_capacity(49 + 32 * hashes.len());
                    frame.extend_from_slice(&((49 + 32 * hashes.len()) as u32).to_be_bytes());
                    frame.push(22u8);
                    frame.extend_from_slice(&body[1..49]);
                    for h in hashes {
                        frame.extend_from_slice(&h);
                    }
                    if sock.write_all(&frame).await.is_err() {
                        break;
                    }
                }
                6 => {
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let req_len = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let off = index as u64 * P + u64::from(begin);
                    let end = off + u64::from(req_len);
                    let block = content[off as usize..end as usize].to_vec();
                    let mut frame = Vec::with_capacity(13 + block.len());
                    frame.extend_from_slice(&((9 + block.len()) as u32).to_be_bytes());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(&block);
                    if sock.write_all(&frame).await.is_err() {
                        break;
                    }
                }
                _ => {}
            }
        }
    });
    // Keep the listener alive until the test ends.
    tokio::time::sleep(Duration::from_secs(120)).await;
}

async fn fake_tracker(seeder: SocketAddr) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
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
        let std::net::IpAddr::V4(v4) = seeder.ip() else {
            panic!("test expects IPv4");
        };
        let mut peers = Vec::new();
        peers.extend_from_slice(&v4.octets());
        peers.extend_from_slice(&seeder.port().to_be_bytes());
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
    });
    addr
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p136-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// Event-sequence assertions shared by both cases: Started/Completed each
/// exactly once, in that order, payload = {files: [1]} (1-based client
/// file order).
fn assert_event_sequence(events: &[RecoveryNotice], expect_completed: bool) {
    let kinds: Vec<RecoveryEventKind> = events.iter().map(|e| e.kind).collect();
    if expect_completed {
        assert_eq!(
            kinds,
            vec![RecoveryEventKind::Started, RecoveryEventKind::Completed],
            "started/completed each exactly once and in order: {events:?}"
        );
    } else {
        assert_eq!(
            kinds,
            vec![RecoveryEventKind::Started],
            "the gate-stuck scenario: no completed after started: {events:?}"
        );
    }
    for ev in events {
        assert_eq!(
            ev.files,
            vec![1],
            "the payload file set = the 1-based client file order (anchored to \
             the getFiles index): {ev:?}"
        );
    }
}

/// Converged-success end to end: layer-missing activation -> Started
/// exactly once -> recovery converges the whole file into the store ->
/// gate promotes -> Completed exactly once -> download finishes and the
/// file matches byte for byte (the recovery->download chain really runs
/// beneath the events; the notices are not synthetic).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_events_fire_exactly_once_on_convergence() {
    let content: Vec<u8> = (0..2 * P as usize).map(|i| (i * 13 % 251) as u8).collect();
    let tmp = tmp_dir("converge");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let tracker_addr = fake_tracker(seeder_addr).await;

    let torrent = build_torrent(&content, &format!("http://{tracker_addr}/announce"));
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));
    // Confirm the layer-missing shape: piece_layer absent, pieces root
    // present.
    let f = &meta.meta.files[0];
    assert!(
        f.pieces_root.is_some() && f.piece_layer.is_none(),
        "a layer-missing fixture"
    );
    assert_eq!(meta.meta.kind, taiji_bt::filetree::SwarmKind::V2Only);

    tokio::spawn(seeder(seeder_listener, Arc::new(content.clone()), false));

    let capture = EventCapture::default();
    let root = tokio_util::sync::CancellationToken::new();
    let mut cfg = taiji_core::engine::engine_config(
        &meta,
        tmp.clone(),
        0,
        *b"-TJ0001-ENGINEENGIN1",
        taiji_core::engine::CompletionMode::ReturnOnComplete,
    )
    .unwrap_or_else(|e| panic!("engine_config: {e}"));
    // Mount the event surface on the relay slot — the same HookRunner
    // seam the actor path uses; the test holds the capture closure
    // directly.
    cfg.hook = Some(Arc::new(
        HookRunner::new(
            Arc::new(HookSet::default()),
            taiji_core::gid::Gid::from_u64(0x8000_0000_0000_0042),
            1,
            "v2.bin".into(),
        )
        .with_recovery_notify({
            let capture = capture.clone();
            Arc::new(move |notice| capture.push(notice))
        }),
    ));
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out; events {:?}", capture.snapshot()))
        .unwrap_or_else(|e| panic!("join: {e}"));
    root.cancel();
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // Event sequence: Started then Completed, each exactly once.
    assert_event_sequence(&capture.snapshot(), true);

    // The recovery->download chain really ran beneath the events: the
    // file matches byte for byte.
    let got = std::fs::read(tmp.join("v2.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got, content,
        "the download must match the source after layer-missing convergence"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Gate-stuck end to end ("started without completed"): the seeder keeps
/// returning bad layers -> convergence always fails and re-staging waits
/// for new peers (no failure terminal state) -> Started fires and
/// Completed never appears within the window (completed-exactly-once
/// semantics stay clean).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_stuck_emits_started_without_completed() {
    let content: Vec<u8> = (0..2 * P as usize).map(|i| (i * 7 % 251) as u8).collect();
    let tmp = tmp_dir("stuck");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let tracker_addr = fake_tracker(seeder_addr).await;

    let torrent = build_torrent(&content, &format!("http://{tracker_addr}/announce"));
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));

    tokio::spawn(seeder(seeder_listener, Arc::new(content), true));

    let capture = EventCapture::default();
    let root = tokio_util::sync::CancellationToken::new();
    let mut cfg = taiji_core::engine::engine_config(
        &meta,
        tmp.clone(),
        0,
        *b"-TJ0001-ENGINEENGIN1",
        taiji_core::engine::CompletionMode::ReturnOnComplete,
    )
    .unwrap_or_else(|e| panic!("engine_config: {e}"));
    cfg.hook = Some(Arc::new(
        HookRunner::new(
            Arc::new(HookSet::default()),
            taiji_core::gid::Gid::from_u64(0x8000_0000_0000_0043),
            1,
            "v2.bin".into(),
        )
        .with_recovery_notify({
            let capture = capture.clone();
            Arc::new(move |notice| capture.push(notice))
        }),
    ));
    let engine = DownloadEngine::spawn(cfg, &root);

    // Started exactly once (fires on layer-missing activation, whether
    // or not convergence later succeeds).
    capture.wait_len(1, "taiji.recoveryStarted").await;
    // Observation window: while the bad-layer re-stage/refetch budget is
    // being spent, Completed must not appear.
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_event_sequence(&capture.snapshot(), false);

    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine did not stop on cancel"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Cancelled), "got {end:?}");

    let _ = std::fs::remove_dir_all(&tmp);
}
