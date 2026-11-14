//! Engine-level dual-tier tracker wiring.
//!
//! Full-chain assertions (reference: aria2 `TrackerWatcherCommand.cc`
//! announce orchestration + stop semantics):
//! 1. tier0 (404 fake tracker) started fails -> tier1 succeeds next (BEP
//!    12);
//! 2. event sequence: started -> ... -> Stop -> stopped -> Halted
//!    (noMoreAnnounce in the actor, `DefaultBtAnnounce.cc`) -> the engine
//!    returns `EngineEnd::Cancelled` (torn down only after the stop
//!    sequence completes);
//! 3. tracker table persistence: the tier0 row carries last_error; the
//!    tier1 row carries
//!    enabled/last_interval/next_announce_at/last_ok_at/seeds/leechers.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::Connection;
use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{
    DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind, TrackerWireConfig,
};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use taiji_store::persist::PersistWriter;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;
/// GID with the top bit set, 16-hex form (test fixture).
const GID: &str = "8000000000000009";
const INFO_HASH: [u8; 20] = [0x42; 20];

/// Fake tracker: local TCP mock (accept loop; dispatches the response by
/// path and records every request path for event-sequence assertions).
struct MockTracker {
    addr: std::net::SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl MockTracker {
    async fn start(handler: impl Fn(&str) -> (String, Vec<u8>) + Send + Sync + 'static) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let handler = Arc::new(handler);
        let log = Arc::new(Mutex::new(Vec::new()));
        let tasks = vec![tokio::spawn({
            let log = Arc::clone(&log);
            async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let handler = Arc::clone(&handler);
                    let log = Arc::clone(&log);
                    tokio::spawn(async move {
                        // Read the request head (reqwest HTTP/1.1; end of
                        // headers = request complete).
                        let mut req = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            let Ok(n) = sock.read(&mut chunk).await else {
                                return;
                            };
                            if n == 0 {
                                break;
                            }
                            req.extend_from_slice(&chunk[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let text = String::from_utf8_lossy(&req).into_owned();
                        let request_line = text.lines().next().unwrap_or("").to_string();
                        let path = request_line.split(' ').nth(1).unwrap_or("").to_string();
                        log.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(path.clone());
                        let (status, body) = handler(&path);
                        let head = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&body).await;
                        let _ = sock.shutdown().await;
                    });
                }
            }
        })];
        MockTracker { addr, log, tasks }
    }

    fn url(&self) -> String {
        format!("http://{}/announce", self.addr)
    }

    /// Snapshot of the recorded request paths.
    fn paths(&self) -> Vec<String> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The announce event-parameter sequence across request paths
    /// (eventless periodic requests are not counted).
    fn event_sequence(&self) -> Vec<String> {
        self.paths()
            .iter()
            .filter_map(|p| {
                for kv in p.split(['?', '&']) {
                    if let Some(v) = kv.strip_prefix("event=") {
                        return Some(v.to_string());
                    }
                }
                None
            })
            .collect()
    }

    fn requests(&self) -> usize {
        self.paths().len()
    }
}

fn v1_face_config() -> FaceConfig {
    // Single-piece face; this test writes no data (no seeder) — it only
    // drives the announce surface.
    let content_len: u64 = u64::from(PIECE_LEN);
    FaceConfig {
        kind: FaceKind::V1,
        info_hash: INFO_HASH,
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: vec![0],
        piece_bytes: vec![u64::from(PIECE_LEN)],
        expected: vec![ExpectedPieceHash::V1(
            Sha1::digest(b"0".repeat(PIECE_LEN as usize)).into(),
        )],
        plan_file_lengths: vec![content_len],
        progress_file_lens: vec![content_len],
        cross: Vec::new(),
        hash_files: None,
    }
}

/// Unique tmp path (pid + nanosecond tag).
fn tmp_path(tag: &str, ext: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "taiji-tracker-wire-{}-{}-{}.{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0),
        ext
    ))
}

/// Test-side Result unwrapping (lint forbids unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

#[tokio::test]
async fn dual_tier_failover_then_stop_sequence_persists_tracker_rows() {
    // tier0: always 404; tier1: announce success (interval/min interval
    // 60) + BEP 48 scrape (seeds=42, leechers=3).
    let bad = MockTracker::start(move |_path| ("404 Not Found".into(), Vec::new())).await;
    let good = MockTracker::start(move |path| {
        if path.starts_with("/scrape") {
            // BEP 48: files dict, key = raw 20B info_hash.
            let mut body = Vec::from(&b"d5:filesd20:"[..]);
            body.extend_from_slice(&INFO_HASH);
            body.extend_from_slice(b"d8:completei42e10:downloadedi7e10:incompletei3eeee");
            ("200 OK".into(), body)
        } else {
            // bencode dict keys ascending: interval < min interval <
            // peers.
            (
                "200 OK".into(),
                Vec::from(&b"d8:intervali60e12:min intervali60e5:peers0:e"[..]),
            )
        }
    })
    .await;

    // sqlite: migrations + the FK fixture parent row (tracker.gid ->
    // torrent.gid).
    let db = tmp_path("db", "sqlite3");
    let (persist, _writer) = ok(PersistWriter::spawn(db.clone()).await, "persist spawn");
    {
        let conn = ok(Connection::open(&db), "fixture conn");
        ok(
            conn.execute(
                "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind, created_at, updated_at)
                 VALUES (?1, 'fixture', 'downloading', 0, '/tmp/fixture', '{}', 'v1', 0, 0)",
                [GID],
            ),
            "fixture torrent",
        );
    }

    // Engine (v1 single face; tiers = two-tier; persistence injected).
    let dest = tmp_path("dest", "d");
    std::fs::create_dir_all(&dest).unwrap_or_else(|e| panic!("{e}"));
    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        initial_selection: None,
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: String::new(),
        listen_port: 0,
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
        dest: dest.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config()],
        // New fields at defaults: optional encryption + DHT off + public
        // (keeps this module's wired test surface behavior-unchanged).
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        // No peer exchange on this legacy test surface (wire behavior
        // unchanged).
        peer_exchange: false,
        // No ut_metadata serve surface (the mini-seeder test face does
        // not need it; the magnet full-chain test mounts one via
        // engine_config defaults).
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,   // no NAT on the test face (EngineConfig::nat default unchanged)
        stats: None, // no metrics fed on the test face (EngineConfig::stats default unchanged)
        webseeds: Vec::new(),
    };
    let tracker = TrackerWireConfig {
        tiers: vec![(0, bad.url()), (1, good.url())],
        persist: Some((GID.to_string(), persist)),
        guard: None,
    };
    let engine = DownloadEngine::spawn_with(cfg, tracker, &root);

    // Wait for tier1 to see started (tier0 failed over; the actor ticks
    // at 1s granularity).
    let started = {
        let mut ok = false;
        for _ in 0..200 {
            if good
                .event_sequence()
                .first()
                .is_some_and(|e| e == "started")
            {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ok
    };
    assert!(
        started,
        "tier1 must receive the started announce (tier0 failed over)"
    );
    // Failure precedes success: tier0 has requests and (as of now) no
    // event parameter.
    assert!(
        bad.requests() >= 1,
        "tier0 must be attempted first (the BEP12 tier failover origin)"
    );
    assert_eq!(
        bad.event_sequence(),
        vec!["started".to_string()],
        "tier0 = a single started attempt (failover after the 404 failure, no further events)"
    );

    // User stop: Stop -> stopped announce (tier1) -> Halted -> engine
    // exits.
    root.cancel();
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    let end = ok(end, "engine join");
    assert!(
        matches!(end, EngineEnd::Cancelled),
        "the engine must not exit before the shutdown sequence completes: got {end:?}"
    );

    // Event sequence: started -> stopped (no periodic requests within
    // the 60s min interval).
    assert_eq!(
        good.event_sequence(),
        vec!["started".to_string(), "stopped".to_string()],
        "tier1 event sequence = started → stopped (BEP12/aria2 shutdown semantics)"
    );

    // Tracker-table assertions: row registration + attribution fields.
    let conn = ok(Connection::open(&db), "readback conn");
    /// SELECT column-order tuple (enabled + 8 nullable fields; same
    /// shape as the store-side comparison tuple).
    type Row = (
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let q = |tier: i64, url: &str| -> Row {
        ok(
            conn.query_row(
                "SELECT enabled, last_interval, last_min_interval, next_announce_at,
                        last_error, last_ok_at, seeds, leechers
                 FROM tracker WHERE gid = ?1 AND tier = ?2 AND url = ?3",
                rusqlite::params![GID, tier, url],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            ),
            "tracker row readback",
        )
    };
    // tier0: row present, enabled=1, last_error records the 404 refusal.
    let (enabled0, _, _, _, err0, ok0, _, _) = q(0, &bad.url());
    assert_eq!(enabled0, 1, "row registered with enabled=1");
    assert!(
        err0.is_some(),
        "tier0's last_error must record the failure (404)"
    );
    assert!(ok0.is_none(), "tier0 has no success timestamp");
    // tier1: the success row — interval/min-interval persisted + success
    // timestamp + scrape cache.
    let (enabled1, interval1, min1, next1, err1, ok1, seeds, leechers) = q(1, &good.url());
    assert_eq!(enabled1, 1);
    assert_eq!(
        (interval1, min1),
        (Some(60), Some(60)),
        "interval persisted"
    );
    assert!(
        next1.is_some(),
        "next_announce_at = success time + interval"
    );
    assert!(err1.is_none(), "the success row clears last_error");
    assert!(ok1.is_some(), "last_ok_at is present");
    assert_eq!((seeds, leechers), (Some(42), Some(3)), "BEP48 scrape cache");

    for t in bad.tasks {
        t.abort();
    }
    for t in good.tasks {
        t.abort();
    }
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_file(&db);
}
