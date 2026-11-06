//! Acceptance: engine-level vehicle for startup recheck (re-entering the
//! checking state).
//!
//! Scenario = an importer-degraded / user-marked `state='checking'` row:
//! the bitmap claims both pieces present, on disk piece 0 is correct and
//! piece 1 is corrupt. After the session bootstrap rechecks:
//! 1. the progress-row bitmap = measured reality (piece 0 kept, piece 1
//! cleared) — the bitmap never over-claims;
//! 2. the row state advances to queued (the active set is re-enterable);
//! 3. counter history (upload_at_startup / downloaded_total) is
//! preserved untouched;
//! 4. the engine restores from the bitmap and fetches only piece 1 (the
//! seeder asserts piece 0 is never requested) -> the file is
//! complete, downloaded_total = base + one piece.
//!
//! The executing half of SPEC §10 "tasks that fail bitmap verification
//! degrade to re-Checking" + SPEC §5.4 checking behavior; process-level
//! kill windows are covered by the process-level crash-matrix script.

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_core::session::{GlobalOptions, SessionActor, SessionOptions};
use taiji_store::persist::{PersistWriter, TorrentProgressRow, TorrentRow};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;
const GID: &str = "80000000000000c1";

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-recheck-";
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
        "bh-recheck-{tag}-{}-{}",
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

/// Seeds the database (checking row + over-claiming bitmap + counter
/// history).
async fn seed_checking_rows(
    db: &std::path::Path,
    raw_torrent: &[u8],
    ih: &[u8; 20],
    dir: &std::path::Path,
    bits: Vec<u8>,
) {
    let (handle, join) = ok(PersistWriter::spawn(db.to_path_buf()).await, "spawn writer");
    let row = TorrentRow {
        gid: GID.into(),
        name: "blob.bin".into(),
        state: "checking".into(),
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
    assert_eq!(
        ok(
            handle
                .upsert_torrent_progress(TorrentProgressRow {
                    gid: GID.into(),
                    piece_length: i64::from(PIECE_LEN),
                    v1_bitfield: Some(bits),
                    v2_file_bits: None,
                    upload_at_startup: 4096,
                    downloaded_total: 100,
                    uploaded_total: 8192,
                    active_time_s: 30,
                    seed_time_s: 5,
                })
                .await,
            "progress row"
        ),
        taiji_store::persist::PersistOutcome::Written
    );
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer exit",
    );
}

/// Disk contents: piece 0 correct + piece 1 corrupt.
fn write_corrupt_data(dir: &std::path::Path, content: &[u8]) {
    let mut file = content.to_vec();
    file[PIECE_LEN as usize] ^= 0xff;
    ok(
        std::fs::write(dir.join("blob.bin"), &file),
        "write corrupt data",
    );
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

/// Cases 1-3 (no engine surface): the recheck corrects the bitmap,
/// advances the row state to queued, and preserves the counters.
#[tokio::test]
async fn recheck_corrects_bitfield_and_advances_state() {
    let content = test_content();
    let (raw, ih) = build_v1_torrent("http://127.0.0.1:1/announce", &content);
    let root = tmp_root("correct");
    let dir = root.join("dl");
    ok(std::fs::create_dir_all(&dir), "mkdir dl");
    write_corrupt_data(&dir, &content);

    let db = root.join("taiji.sqlite3");
    seed_checking_rows(&db, &raw, &ih, &dir, vec![0b1100_0000]).await;

    let (handle, actor_join, writer, wjoin) = spawn_session(&db).await;
    // Bootstrap runs on the actor's first pass; poll until the row
    // leaves checking (the progress row is written back before the state
    // advance, see finish_recheck ordering), 10s cap.
    let mut state = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let snap = ok(writer.load_torrents_at_startup().await, "load rows");
        if let Some(s) = snap.first() {
            state = s.row.state.clone();
            if state != "checking" {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bootstrap did not clear checking state (last: {state})"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let progress = ok(writer.load_torrent_progress(GID).await, "load progress")
        .unwrap_or_else(|| panic!("progress row must exist"));
    // The recheck advances to queued; the engine may already have
    // spawned in a polling gap (downloading) — either is evidence that
    // checking was re-entered and released.
    assert!(
        state == "queued" || state == "downloading",
        "the row state must leave checking (queued/downloading), got {state}"
    );
    assert_eq!(
        progress.v1_bitfield,
        Some(vec![0b1000_0000]),
        "the measured bitmap: piece 0 kept, the corrupt piece 1 cleared"
    );
    assert_eq!(progress.v2_file_bits, None);
    // Counter history preserved (a recheck is not a download; it must
    // not touch counters).
    assert_eq!(progress.upload_at_startup, 4096);
    assert_eq!(progress.downloaded_total, 100);
    assert_eq!(progress.uploaded_total, 8192);
    assert_eq!(progress.active_time_s, 30);
    assert_eq!(progress.seed_time_s, 5);

    handle.shutdown().await;
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(3), actor_join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(1), wjoin).await;
    let _ = std::fs::remove_dir_all(&root);
}

/// Case 4 (engine surface): the engine restores from the recheck bitmap
/// and fetches only piece 1 (the seeder asserts piece 0 is never
/// requested) -> the file is complete; downloaded_total = base + one
/// piece (the final value lands via the shutdown flush).
#[tokio::test]
async fn recheck_then_engine_redownloads_only_corrupt_piece() {
    // Bind the fake tracker first (the torrent announce points at it);
    // the seeder follows.
    let tracker_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "bind tracker",
    );
    let tracker_addr = ok(tracker_listener.local_addr(), "tracker addr");
    let seeder_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "bind seeder",
    );
    let seeder_addr = ok(seeder_listener.local_addr(), "seeder addr");

    let content = test_content();
    let (raw, ih) = build_v1_torrent(&format!("http://{tracker_addr}/announce"), &content);
    let root = tmp_root("engine");
    let dir = root.join("dl");
    ok(std::fs::create_dir_all(&dir), "mkdir dl");
    write_corrupt_data(&dir, &content);

    // Fake tracker: answers compact peers = the seeder address (one
    // request, one answer, then exits).
    tokio::spawn(async move {
        let (mut sock, _) = match tracker_listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            req.extend_from_slice(&chunk[..n]);
        }
        let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
            return;
        };
        let mut peers = Vec::new();
        peers.extend_from_slice(&v4.octets());
        peers.extend_from_slice(&seeder_addr.port().to_be_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(b"d8:intervali60e5:peers");
        body.extend_from_slice(peers.len().to_string().as_bytes());
        body.push(b':');
        body.extend_from_slice(&peers);
        body.push(b'e');
        let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(&body).await;
    });
    // Mini-seeder: request -> piece; piece 0 is never requested (the
    // recheck-measured bitmap).
    tokio::spawn(async move {
        let (mut sock, _) = match seeder_listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let mut hs = [0u8; 68];
        if sock.read_exact(&mut hs).await.is_err() {
            return;
        }
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10;
        resp[27] = 0x04;
        resp[28..48].copy_from_slice(&ih);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        if sock.write_all(&resp).await.is_err() {
            return;
        }
        // After the handshake the mini-seeder sends a full bitfield per
        // BEP 3 (2 pieces = 0b1100_0000). It used to send no ad and rely
        // on the dispatcher's blind-select fallback; that fallback went
        // away with ad-aware dispatch. This peer already holds piece 0
        // (restored by the recheck bitmap), so under the ad {0,1}
        // selection still lands only on piece 1 and the "piece 0 is
        // never re-downloaded" assert stays valid (upstream anchor:
        // libtorrent request_blocks.cpp — picking only draws candidates
        // from the peer bitfield).
        if sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000]).await.is_err() {
            return;
        }
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
                6 => {
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    assert_ne!(
                        index, 0,
                        "piece 0 was confirmed by the recheck; it must not be re-downloaded"
                    );
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * PIECE_LEN as usize + begin as usize;
                    let block = content[offset..offset + length as usize].to_vec();
                    let mut frame = Vec::new();
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
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

    let db = root.join("taiji.sqlite3");
    seed_checking_rows(&db, &raw, &ih, &dir, vec![0b1100_0000]).await;
    let (handle, actor_join, writer, wjoin) = spawn_session(&db).await;

    // Poll until the file is complete (recheck -> engine restores the
    // bitmap -> only piece 1 refetched, the full chain), 30s cap.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if ok(std::fs::read(dir.join("blob.bin")), "read back") == test_content() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "engine did not repair corrupt piece after recheck"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Shutdown triggers the engine's final flush; then verify the
    // counters (only piece 1 refetched: base 100 + 16384). Engine
    // teardown includes the stopped sequence and the DHT halt-save and
    // can run past the actor drain budget — poll for the final flush
    // (15s cap).
    handle.shutdown().await;
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(3), actor_join).await;
    // Hardening: the poll criterion asserts the final values themselves
    // (counter and bitfield satisfied in the same sample). The original
    // criterion `downloaded_total > 100` was a proxy — piece-1 byte
    // counters are bumped before hash verification flips the bitmap
    // (piece completion accounting is async to block writes), and an
    // intermediate shutdown flush may carry the counter without the
    // final bitmap, letting the poll break early and the final bitmap
    // assertion read a stale value. Wait directly for the final values
    // (50ms re-check steps). Window 15s -> 30s: the shutdown flush is
    // serialized behind the stopped persistence + DHT halt-save + engine
    // drain, and a single step can be starved for seconds under
    // full-repo parallel load.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let progress;
    loop {
        let p = ok(writer.load_torrent_progress(GID).await, "load progress")
            .unwrap_or_else(|| panic!("progress row must exist"));
        if p.downloaded_total >= 100 + i64::from(PIECE_LEN)
            && p.v1_bitfield == Some(vec![0b1100_0000])
        {
            progress = p;
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "engine final progress flush did not land (downloaded_total stays {}, \
             bitfield {:?})",
            p.downloaded_total,
            p.v1_bitfield
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        progress.downloaded_total,
        100 + i64::from(PIECE_LEN),
        "only the corrupt piece was refetched (direct evidence of a lossless recheck bitmap)"
    );
    assert_eq!(
        progress.v1_bitfield,
        Some(vec![0b1100_0000]),
        "the final bitmap is all ones"
    );
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(1), wjoin).await;
    let _ = std::fs::remove_dir_all(&root);
}
