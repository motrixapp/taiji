//! Engine-level regression vehicles for two field-observed defects: the
//! truncate-on-fresh-add defect and the premature completed-announce
//! defect (test shape reuses recheck_restore.rs's row seeding +
//! fake-tracker vehicle, all in-process).
//!
//! - Truncate-on-fresh-add: preset data + a fresh add (no progress row in the store) ->
//! engine allocation must not truncate the on-disk file (observed in
//! the field: after addUri, `file allocation done effect= Truncated`
//! and the file SHA changed).
//! - Premature completed announce: the event chain of a seed-only task (restored bitmap full) —
//! the completed state must already be visible before the first
//! announce (SwarmSnapshot initialization), only started is sent (on
//! the wire this is STARTED_AFTER_COMPLETION), and completed is never
//! sent (observed in the field: completed(up=0) 1s after started ->
//! inflated snatch counts on the site).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_core::session::{GlobalOptions, SessionActor, SessionOptions};
use taiji_store::persist::{PersistWriter, TorrentProgressRow, TorrentRow};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const PIECE_LEN: u32 = 16384;
const GID: &str = "80000000000000d1";

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-pt131-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// Test-side Result unwrapping (lint forbids unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn tmp_root(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bh-pt131-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    ok(std::fs::create_dir_all(&d), "mkdir");
    d
}

/// bencode byte string `<len>:<bytes>`.
fn bstr(b: &[u8]) -> Vec<u8> {
    let mut out = format!("{}:", b.len()).into_bytes();
    out.extend_from_slice(b);
    out
}

/// Single-file v1 torrent (2 pieces) -> (bytes, infohash).
fn build_v1_torrent(announce: &str, content: &[u8]) -> (Vec<u8>, [u8; 20]) {
    let mut pieces = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        pieces.extend_from_slice(&Sha1::digest(c));
    }
    let mut info = Vec::new();
    info.extend_from_slice(b"d");
    info.extend_from_slice(&bstr(b"length"));
    info.extend_from_slice(format!("i{}e", content.len()).as_bytes());
    info.extend_from_slice(&bstr(b"name"));
    info.extend_from_slice(&bstr(b"blob.bin"));
    info.extend_from_slice(&bstr(b"piece length"));
    info.extend_from_slice(format!("i{}e", PIECE_LEN).as_bytes());
    info.extend_from_slice(&bstr(b"pieces"));
    info.extend_from_slice(format!("{}:", pieces.len()).as_bytes());
    info.extend_from_slice(&pieces);
    info.extend_from_slice(b"e");
    let mut raw = Vec::new();
    raw.extend_from_slice(b"d");
    raw.extend_from_slice(&bstr(b"announce"));
    raw.extend_from_slice(&bstr(announce.as_bytes()));
    raw.extend_from_slice(&bstr(b"info"));
    raw.extend_from_slice(&info);
    raw.extend_from_slice(b"e");
    let ih: [u8; 20] = Sha1::digest(&info).into();
    (raw, ih)
}

/// Seeds the store: a queued row (optional progress row).
async fn seed_row(
    db: &std::path::Path,
    raw_torrent: &[u8],
    ih: &[u8; 20],
    dir: &std::path::Path,
    progress: Option<TorrentProgressRow>,
) {
    let (handle, join) = ok(PersistWriter::spawn(db.to_path_buf()).await, "spawn writer");
    let row = TorrentRow {
        gid: GID.into(),
        name: "blob.bin".into(),
        state: "queued".into(),
        queue_pos: 1,
        dir: dir.display().to_string(),
        config_json: format!(r#"{{"dir":"{}"}}"#, dir.display()),
        kind: "v1".into(),
        v1_infohash: Some(ih.to_vec()),
        v2_infohash: None,
        is_private: false,
        metadata: Some(raw_torrent.to_vec()),
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    assert_eq!(
        ok(handle.upsert_torrent(row, Vec::new()).await, "torrent row"),
        taiji_store::persist::PersistOutcome::Written
    );
    if let Some(p) = progress {
        assert_eq!(
            ok(handle.upsert_torrent_progress(p).await, "progress row"),
            taiji_store::persist::PersistOutcome::Written
        );
    }
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer exit",
    );
}

/// Announce recording handle (shared by the multi-request accept loop).
#[derive(Clone)]
struct Records(Arc<Mutex<Vec<String>>>);

impl Records {
    fn snapshot(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Fake tracker (consumes a caller-bound listener — the announce URL and
/// port must match): a multi-request accept loop that records each
/// announce's path+query. Announce answers interval=3600 + empty peers
/// (zero download interference, no periodic re-announce); scrape answers
/// empty files. Returns the records handle and the service task handle.
async fn spawn_mock_tracker(listener: TcpListener) -> (Records, tokio::task::JoinHandle<()>) {
    let records = Records(Arc::new(Mutex::new(Vec::new())));
    let records_in = records.clone();
    let join = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let records = records_in.clone();
            tokio::spawn(async move {
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
                let body: &[u8] = if path.starts_with("/announce") {
                    if let Ok(mut r) = records.0.lock() {
                        r.push(path);
                    }
                    // interval=3600: a single announce wave, no periodic
                    // interference.
                    b"d8:intervali3600e5:peerslee"
                } else {
                    // scrape (the same-host side surface after a
                    // successful announce): empty files.
                    b"d5:filesdee"
                };
                let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (records, join)
}

/// Text-parameter extraction from an announce path+query (info_hash /
/// peer_id are raw percent-encoded bytes and are not extracted).
fn query_param<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    let q = path.split_once('?')?.1;
    let prefix = format!("{key}=");
    q.split('&').find_map(|kv| kv.strip_prefix(&prefix))
}

async fn spawn_session(
    db: &std::path::Path,
) -> (
    taiji_core::session::SessionHandle,
    tokio::task::JoinHandle<()>,
    taiji_store::persist::PersistHandle,
    tokio::task::JoinHandle<()>,
) {
    let (writer, wjoin) = ok(
        PersistWriter::spawn(db.to_path_buf()).await,
        "spawn writer 2",
    );
    let (handle, actor_join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer.clone()),
    );
    (handle, actor_join, writer, wjoin)
}

async fn shutdown_session(
    handle: taiji_core::session::SessionHandle,
    actor_join: tokio::task::JoinHandle<()>,
    writer: taiji_store::persist::PersistHandle,
    wjoin: tokio::task::JoinHandle<()>,
) {
    handle.shutdown().await;
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(3), actor_join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(1), wjoin).await;
}

/// Truncate-on-fresh-add regression (field scenario: preset data -> addUri(dir = the
/// data directory) -> the old implementation truncated on allocation and
/// the file SHA changed): a fresh add (no progress row, no peers — the
/// announce points at a closed port) + complete data already on disk ->
/// the bytes must survive untouched through the observation window (the
/// allocation switched to open semantics; byte-level assertions live in
/// the taiji-store torrent_writer unit tests).
#[tokio::test]
async fn reseed_existing_data_survives_fresh_add() {
    let content = test_content();
    let (raw, ih) = build_v1_torrent("http://127.0.0.1:1/announce", &content);
    let root = tmp_root("def1");
    let dir = root.join("dl");
    ok(std::fs::create_dir_all(&dir), "mkdir dl");
    ok(
        std::fs::write(dir.join("blob.bin"), &content),
        "preset data",
    );

    let db = root.join("taiji.sqlite3");
    seed_row(&db, &raw, &ih, &dir, None).await;
    let (handle, actor_join, writer, wjoin) = spawn_session(&db).await;

    // Observation window 5s: engine spin-up + store pipeline
    // construction (where the old implementation's allocation truncation
    // happened; afterwards the content could not be recovered from
    // downloads). Sampling every 100ms; any sample differing from the
    // original content fails.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let got = ok(std::fs::read(dir.join("blob.bin")), "read back");
        assert_eq!(
            got, content,
            "a fresh add must not truncate or corrupt existing on-disk data"
        );
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    shutdown_session(handle, actor_join, writer, wjoin).await;
    let _ = std::fs::remove_dir_all(&root);
}

/// Premature completed-announce regression (field scenario: an import-bootstrapped seed-only
/// seeder sent completed(up=0) 1s after its first started, inflating
/// site snatch counts): a task restored with a full bitmap -> only
/// started is sent (completion precedes it = STARTED_AFTER_COMPLETION),
/// zero completed within the observation window; and the started carries
/// left=0 (snapshot initialization correct).
#[tokio::test]
async fn seed_only_restored_task_never_sends_completed() {
    let content = test_content();
    // Bind the tracker first (announce URL and port match).
    let listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "bind tracker",
    );
    let addr = ok(listener.local_addr(), "tracker addr");
    let (raw, ih) = build_v1_torrent(&format!("http://{addr}/announce"), &content);
    let root = tmp_root("def4");
    let dir = root.join("dl");
    ok(std::fs::create_dir_all(&dir), "mkdir dl");
    ok(std::fs::write(dir.join("blob.bin"), &content), "seed data");

    let db = root.join("taiji.sqlite3");
    seed_row(
        &db,
        &raw,
        &ih,
        &dir,
        Some(TorrentProgressRow {
            gid: GID.into(),
            piece_length: i64::from(PIECE_LEN),
            v1_bitfield: Some(vec![0b1100_0000]), // both pieces full
            v2_file_bits: None,
            upload_at_startup: 0,
            downloaded_total: 0,
            uploaded_total: 8388608,
            active_time_s: 30,
            seed_time_s: 5,
        }),
    )
    .await;

    let (records, tracker_join) = spawn_mock_tracker(listener).await;
    let (handle, actor_join, writer, wjoin) = spawn_session(&db).await;

    // Wait for >=1 started (15s cap; engine spin-up + first announce),
    // then keep observing to an 8s total window. Assertions: started is
    // present, zero completed, and the started carries left=0.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if records
            .snapshot()
            .iter()
            .any(|p| query_param(p, "event") == Some("started"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the engine never sent a started announce to the tracker: {:?}",
            records.snapshot()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(8)).await;

    let announces = records.snapshot();
    let started: Vec<&String> = announces
        .iter()
        .filter(|p| query_param(p, "event") == Some("started"))
        .collect();
    assert!(
        !started.is_empty(),
        "started must be present: {announces:?}"
    );
    assert_eq!(
        query_param(started[0], "left"),
        Some("0"),
        "a seed-only task's first announce must carry left = 0 \
         (the restored bitmap precedes the snapshot): {:?}",
        started[0]
    );
    assert!(
        !announces
            .iter()
            .any(|p| query_param(p, "event") == Some("completed")),
        "a seed-only task must not send completed (it inflates \
         snatch counts): {announces:?}"
    );

    shutdown_session(handle, actor_join, writer, wjoin).await;
    tracker_join.abort();
    let _ = std::fs::remove_dir_all(&root);
}
