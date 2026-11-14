//! Acceptance: the engine-level vehicle for crash recovery / startup
//! rebuild (test-level vehicle; process-level random kill matrices are
//! covered by the process-level crash-matrix script).
//!
//! Test 1 (restore means complete): an all-ones bitmap in the store ->
//! the engine is Completed right after spawn (no seeder is connectable —
//! completion comes from bitmap restore, not the network), and the
//! cleanup path matches the online-completion one.
//!
//! Test 2 (partial bitmap resume): piece 0 already on disk + the store
//! bitmap records only piece 0 -> the engine downloads only piece 1 ->
//! the file is complete; the progress row's `downloaded_total` == one
//! piece's bytes (piece 0 was not re-downloaded — direct evidence that
//! bitmap restore is lossless); the in-flight block bitmap is not
//! restored (intentional deviation, DefaultBtProgressInfoFile.cc;
//! correctness is guaranteed by the verify-before-write crash
//! consistency model).

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{
    DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind, TrackerWireConfig,
};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use taiji_store::persist::{PersistWriter, TorrentProgressRow, TorrentRow};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: u32 = 16384;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-crash-recovery-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

fn v1_face_config(
    info_hash: [u8; 20],
    expected: Vec<ExpectedPieceHash>,
    content_len: u64,
) -> FaceConfig {
    FaceConfig {
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
    }
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bh-p38-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("mkdir: {e}"));
    d
}

fn tmp_db(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "bh-p38-{tag}-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// Test-side Result unwrapping (lint forbids unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// The single v1 torrent fixture parameters (shared by both tests).
struct Fixture {
    content: Vec<u8>,
    roots: Vec<ExpectedPieceHash>,
    layout: Layout,
    info_hash: [u8; 20],
}

fn fixture() -> Fixture {
    let content = test_content();
    let mut roots = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        roots.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = ok(Layout::plan_v1_padded(&entries, PIECE_LEN), "layout");
    // The info_hash is only a handshake match key here (it just has to
    // match the seeder's echo).
    let info_hash = [7u8; 20];
    Fixture {
        content,
        roots,
        layout,
        info_hash,
    }
}

/// Seeds the store: the torrent parent row + a progress row carrying the
/// given bitmap (restore-means-complete shape).
async fn seed_db_full_bitfield(db: &std::path::Path, gid: &str, done_bits: Vec<u8>) {
    let (handle, join) = ok(PersistWriter::spawn(db.to_path_buf()).await, "spawn writer");
    let row = TorrentRow {
        gid: gid.to_string(),
        name: "blob.bin".into(),
        state: "downloading".into(),
        queue_pos: 1,
        dir: "/tmp".into(),
        config_json: "{}".into(),
        kind: "v1".into(),
        v1_infohash: Some([9u8; 20].to_vec()),
        v2_infohash: None,
        is_private: false,
        metadata: None,
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
                    gid: gid.to_string(),
                    piece_length: i64::from(PIECE_LEN),
                    v1_bitfield: Some(done_bits),
                    v2_file_bits: None,
                    upload_at_startup: 0,
                    downloaded_total: 0,
                    uploaded_total: 0,
                    active_time_s: 0,
                    seed_time_s: 0,
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

/// Engine config (announce injectable; no ut_metadata/rate limit/hook on
/// this test surface).
fn engine_config(fx: &Fixture, dest: std::path::PathBuf, announce: String) -> EngineConfig {
    EngineConfig {
        initial_selection: None,
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce,
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout: fx.layout.clone(),
        dest,
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config(
            fx.info_hash,
            fx.roots.clone(),
            fx.content.len() as u64,
        )],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        // No peer exchange on this legacy test surface (wire behavior
        // unchanged).
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,   // no NAT on the test face (EngineConfig::nat default unchanged)
        stats: None, // no metrics fed on the test face (EngineConfig::stats default unchanged)
        webseeds: Vec::new(),
    }
}

/// Restore means complete: an all-ones bitmap -> Completed right after
/// spawn (no seeder; the announce points at an unreachable port — port 1
/// refuses immediately).
#[tokio::test]
async fn restored_full_bitfield_completes_without_download() {
    let fx = fixture();
    let dest = tmp_dir("resume-full");
    let db = tmp_db("resume-full");
    let gid = "80000000000000a1";
    seed_db_full_bitfield(&db, gid, vec![0b1100_0000]).await;

    let (handle, join) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let root = CancellationToken::new();
    let cfg = engine_config(&fx, dest.clone(), "http://127.0.0.1:1/announce".into());
    let engine = DownloadEngine::spawn_with(
        cfg,
        TrackerWireConfig {
            persist: Some((gid.to_string(), handle.clone())),
            ..TrackerWireConfig::default()
        },
        &root,
    );
    let end = ok(
        tokio::time::timeout(Duration::from_secs(15), engine).await,
        "engine",
    );
    root.cancel();
    let end = ok(end, "join");
    assert!(
        matches!(end, EngineEnd::Completed),
        "restore-as-complete must land Completed directly, got {end:?}"
    );
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer exit",
    );
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_file(&db);
}

/// Partial bitmap resume: piece 0 in the store + on disk, only piece 1
/// downloads (fake tracker + mini-seeder, engine_loop shape) -> the file
/// is complete + downloaded_total == one piece (piece 0 not
/// re-downloaded).
#[tokio::test]
async fn partial_bitfield_resume_downloads_only_remaining_pieces() {
    let fx = fixture();
    let dest = tmp_dir("resume-partial");
    let db = tmp_db("resume-partial");
    let gid = "80000000000000a2";

    // Piece 0 pre-written to disk (bytes the bitmap claims must really
    // be on disk — the restore-semantics precondition).
    let mut file = vec![0u8; fx.content.len()];
    file[..PIECE_LEN as usize].copy_from_slice(&fx.content[..PIECE_LEN as usize]);
    ok(std::fs::write(dest.join("blob.bin"), &file), "seed piece 0");
    seed_db_full_bitfield(&db, gid, vec![0b1000_0000]).await;

    // Mini-seeder (engine_loop shape: hand-written handshake + request
    // -> piece).
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let seeder_content = fx.content.clone();
    tokio::spawn(async move {
        let (mut sock, _) = seeder_listener
            .accept()
            .await
            .unwrap_or_else(|e| panic!("accept: {e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("hs read: {e}"));
        assert_eq!(&hs[28..48], &[7u8; 20], "the engine handshake's info_hash");
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10;
        resp[27] = 0x04;
        resp[28..48].copy_from_slice(&[7u8; 20]);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("hs write: {e}"));
        // After the handshake the seeder sends a full bitfield per BEP 3
        // (2 pieces = 0b1100_0000). It used to send no ad and rely on the
        // dispatcher's blind-select fallback; that fallback went away
        // with ad-aware dispatch.
        sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
            .await
            .unwrap_or_else(|e| panic!("bitfield write: {e}"));
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
                    sock.write_all(&[0, 0, 0, 1, 1])
                        .await
                        .unwrap_or_else(|e| panic!("unchoke: {e}"));
                }
                6 => {
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    // Resume assertion: the seeder is never asked for
                    // piece 0 (the bitmap already records it).
                    assert_ne!(
                        index, 0,
                        "piece 0 was restored; it must not be re-downloaded (lossless bitmap)"
                    );
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * PIECE_LEN as usize + begin as usize;
                    let block = seeder_content[offset..offset + length as usize].to_vec();
                    let mut frame = Vec::new();
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(&block);
                    sock.write_all(&frame)
                        .await
                        .unwrap_or_else(|e| panic!("piece write: {e}"));
                }
                _ => {}
            }
        }
    });

    // Fake tracker: answers compact peers = the seeder address
    // (simplified engine_loop shape).
    let tracker_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let tracker_addr = tracker_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let seeder_ip = seeder_addr;
    tokio::spawn(async move {
        let (mut sock, _) = tracker_listener
            .accept()
            .await
            .unwrap_or_else(|e| panic!("accept: {e}"));
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock
                .read(&mut chunk)
                .await
                .unwrap_or_else(|e| panic!("read: {e}"));
            if n == 0 {
                break;
            }
            req.extend_from_slice(&chunk[..n]);
        }
        let std::net::IpAddr::V4(v4) = seeder_ip.ip() else {
            panic!("expects IPv4");
        };
        let mut peers = Vec::new();
        peers.extend_from_slice(&v4.octets());
        peers.extend_from_slice(&seeder_ip.port().to_be_bytes());
        let mut raw = Vec::new();
        raw.extend_from_slice(b"d8:intervali60e5:peers");
        raw.extend_from_slice(peers.len().to_string().as_bytes());
        raw.push(b':');
        raw.extend_from_slice(&peers);
        raw.push(b'e');
        let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
        sock.write_all(head.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        sock.write_all(&raw)
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
    });

    let (handle, join) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let root = CancellationToken::new();
    let cfg = engine_config(&fx, dest.clone(), format!("http://{tracker_addr}/announce"));
    let engine = DownloadEngine::spawn_with(
        cfg,
        TrackerWireConfig {
            persist: Some((gid.to_string(), handle.clone())),
            ..TrackerWireConfig::default()
        },
        &root,
    );
    let end = ok(
        tokio::time::timeout(Duration::from_secs(30), engine).await,
        "engine",
    );
    root.cancel();
    let end = ok(end, "join");
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // The file is complete (restored piece 0 + newly downloaded piece 1).
    let got = ok(std::fs::read(dest.join("blob.bin")), "read back");
    assert_eq!(got, fx.content, "the content must be complete after resume");

    // Progress-row final values: downloaded_total == one piece (piece 0
    // was not re-downloaded); the bitmap all ones.
    let loaded = ok(handle.load_torrent_progress(gid).await, "load progress");
    let row = loaded.unwrap_or_else(|| panic!("progress row must exist"));
    assert_eq!(
        row.downloaded_total,
        i64::from(PIECE_LEN),
        "only piece 1 was downloaded (direct evidence of a lossless bitmap restore)"
    );
    assert_eq!(
        row.v1_bitfield,
        Some(vec![0b1100_0000]),
        "the final bitmap is all ones"
    );
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer exit",
    );
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_file(&db);
}
