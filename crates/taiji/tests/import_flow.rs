//! Full-chain integration tests for the migration importer.
//!
//! Carrier: the real binary (CARGO_BIN_EXE_taiji) + a synthetic
//! fork-schema fixture (DDL cross-checked against upstream
//! `Sqlite3Migrations.cc`) + hand-built `.aria2` control files (byte
//! layout cross-checked against upstream `DefaultBtProgressInfoFile.cc`).
//! Deregistration goes through a mock aria2 JSON-RPC endpoint (bare
//! HTTP/1.1, same shape as rpc_smoke) verifying the two-step
//! `aria2.remove` + `aria2.purgeDownloadResult` semantics (SPEC §9.3).

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// Test-only Result unwrap helper (lints ban unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Unique temp directory.
fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bh-import-e2e-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.subsec_nanos())
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

/// Single-file v1 torrent (2 pieces x 16KiB) -> (bytes, infohash, infohash hex).
fn build_v1_torrent() -> (Vec<u8>, [u8; 20], String) {
    // Keys in lexicographic order (length < name < piece length < pieces).
    let mut info = Vec::new();
    info.extend_from_slice(b"d");
    info.extend_from_slice(&bstr(b"length"));
    info.extend_from_slice(b"i32768e");
    info.extend_from_slice(&bstr(b"name"));
    info.extend_from_slice(&bstr(b"migrated.bin"));
    info.extend_from_slice(&bstr(b"piece length"));
    info.extend_from_slice(b"i16384e");
    info.extend_from_slice(&bstr(b"pieces"));
    let mut pieces = b"40:".to_vec();
    pieces.extend_from_slice(&[0xab; 40]);
    info.extend_from_slice(&pieces);
    info.extend_from_slice(b"e");
    let mut raw = Vec::new();
    raw.extend_from_slice(b"d");
    raw.extend_from_slice(&bstr(b"announce"));
    raw.extend_from_slice(&bstr(b"http://t.invalid/announce"));
    raw.extend_from_slice(&bstr(b"info"));
    raw.extend_from_slice(&info);
    raw.extend_from_slice(b"e");
    let ih: [u8; 20] = {
        use sha1::{Digest, Sha1};
        Sha1::digest(&info).into()
    };
    let hex = ih.iter().map(|b| format!("{b:02x}")).collect::<String>();
    (raw, ih, hex)
}

/// `.aria2` control-file construction (upstream byte layout; in-flight pieces optional).
fn build_ctrl(
    ih: &[u8; 20],
    upload: u64,
    bitfield: &[u8],
    in_flight: Vec<(u32, u32, Vec<u8>)>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0x00, 0x01]); // version 0001
    b.extend_from_slice(&[0, 0, 0, 1]); // extension BT
    b.extend_from_slice(&20u32.to_be_bytes()); // infoHashLength
    b.extend_from_slice(ih); // infoHash
    b.extend_from_slice(&16384u32.to_be_bytes()); // pieceLength
    b.extend_from_slice(&32768u64.to_be_bytes()); // totalLength
    b.extend_from_slice(&upload.to_be_bytes()); // uploadLength
    b.extend_from_slice(&(bitfield.len() as u32).to_be_bytes()); // bitfieldLength
    b.extend_from_slice(bitfield); // bitfield
    b.extend_from_slice(&(in_flight.len() as u32).to_be_bytes()); // numInFlightPiece
    for (index, length, bf) in in_flight {
        b.extend_from_slice(&index.to_be_bytes()); // index
        b.extend_from_slice(&length.to_be_bytes()); // length
        b.extend_from_slice(&(bf.len() as u32).to_be_bytes()); // bitfieldLength
        b.extend_from_slice(&bf); // piece bitfield
    }
    b
}

/// `.aria2` non-BT (HTTP/FTP) control-file construction (byte layout
/// per upstream `DefaultBtProgressInfoFile.cc` save non-BT branch:
/// extension 0, infoHashLength 0, uploadLength 0).
fn build_http_ctrl(piece_length: u32, total_length: u64, bitfield: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0x00, 0x01]); // version 0001
    b.extend_from_slice(&0u32.to_be_bytes()); // extension non-BT (bit0 = 0)
    b.extend_from_slice(&0u32.to_be_bytes()); // infoHashLength = 0
    b.extend_from_slice(&piece_length.to_be_bytes()); // pieceLength
    b.extend_from_slice(&total_length.to_be_bytes()); // totalLength
    b.extend_from_slice(&0u64.to_be_bytes()); // uploadLength always 0 for non-BT
    b.extend_from_slice(&(bitfield.len() as u32).to_be_bytes()); // bitfieldLength
    b.extend_from_slice(bitfield);
    b.extend_from_slice(&0u32.to_be_bytes()); // numInFlightPiece = 0 (no in-flight pieces)
    b
}

/// Synthetic fork-schema db (DDL per upstream Sqlite3Migrations.cc,
/// user_version=1) seeded with one BT task (serialized carries
/// dir + pause=true; bitfield 0xC0; upload 4096).
fn seed_fork_db(path: &Path, gid: &str, ih: &[u8; 20], dir: &str) {
    let conn = ok(rusqlite::Connection::open(path), "open fork fixture");
    ok(
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE task (gid TEXT PRIMARY KEY, state TEXT NOT NULL, serialized TEXT NOT NULL,
               belongs_to TEXT, following TEXT, followed_by TEXT, metadata_uri TEXT, bt_local_path TEXT,
               queue_position INTEGER NOT NULL, digest BLOB NOT NULL, created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL);
             CREATE INDEX idx_task_state ON task(state);
             CREATE INDEX idx_task_queue_position ON task(queue_position);
             CREATE TABLE task_progress (gid TEXT PRIMARY KEY, ctrl_version INTEGER NOT NULL DEFAULT 1,
               is_torrent INTEGER NOT NULL DEFAULT 0, info_hash BLOB, piece_length INTEGER NOT NULL,
               total_length INTEGER NOT NULL, upload_length INTEGER NOT NULL DEFAULT 0,
               bitfield BLOB NOT NULL, in_flight_blob BLOB NOT NULL DEFAULT X'', digest BLOB NOT NULL,
               updated_at INTEGER NOT NULL,
               FOREIGN KEY (gid) REFERENCES task(gid) ON DELETE CASCADE);
             CREATE TABLE download_history (id INTEGER PRIMARY KEY AUTOINCREMENT, gid TEXT NOT NULL);
             PRAGMA user_version = 1;",
        ),
        "seed schema",
    );
    let serialized = format!(" dir={dir}\n pause=true\n");
    ok(
        conn.execute(
            "INSERT INTO task (gid, state, serialized, queue_position, digest, created_at, updated_at)
             VALUES (?1, 'paused', ?2, 3, x'00', 0, 0)",
            rusqlite::params![gid, serialized],
        ),
        "seed task",
    );
    let bf = [0b1100_0000u8]; // both pieces done
    ok(
        conn.execute(
            "INSERT INTO task_progress (gid, is_torrent, info_hash, piece_length, total_length,
                                        upload_length, bitfield, digest, updated_at)
             VALUES (?1, 1, ?2, 16384, 32768, 4096, ?3, x'00', 0)",
            rusqlite::params![gid, ih.as_slice(), bf.as_slice()],
        ),
        "seed progress",
    );
}

/// Run `taiji import <args>`; returns (exit code, stdout).
fn run_import(args: &[String]) -> (i32, String) {
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = ok(
        Command::new(env!("CARGO_BIN_EXE_taiji"))
            .arg("import")
            .args(&refs)
            .stderr(Stdio::inherit())
            .output(),
        "run taiji import",
    );
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Run `taiji import <args>` capturing stderr (the assertion surface
/// for guard/infrastructure rejections); returns (exit code, stdout,
/// stderr).
fn run_import_captured(args: &[String]) -> (i32, String, String) {
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = ok(
        Command::new(env!("CARGO_BIN_EXE_taiji"))
            .arg("import")
            .args(&refs)
            .output(),
        "run taiji import",
    );
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Byte digest of the main db file (the zero-write meter for dry-run).
fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = ok(std::fs::read(path), "read db file");
    let mut h = Sha256::new();
    h.update(&bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// WAL sidecar (-wal/-shm) presence check (zero-write = main file and both sidecars untouched).
fn wal_sidecars(path: &Path) -> bool {
    ["-wal", "-shm"].iter().any(|suffix| {
        let mut s = path.as_os_str().to_os_string();
        s.push(suffix);
        Path::new(&s).exists()
    })
}

/// user_version readback (asserts the migration ledger position).
fn user_version_of(path: &Path) -> i64 {
    let conn = ok(rusqlite::Connection::open(path), "open for user_version");
    ok(
        conn.query_row("PRAGMA user_version", [], |r| r.get(0)),
        "user_version",
    )
}

/// Legacy 0.1.x-shaped target db (user_version=2): WAL + session_kv +
/// a pre-seeded dedup key, cleanly closed (no sidecars — the offline
/// precondition for the pre-import backup).
fn seed_legacy_v2_target(path: &Path, kv: &[(&str, &str)]) {
    let conn = ok(rusqlite::Connection::open(path), "open v2 target");
    ok(
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE session_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        ),
        "seed v2 schema",
    );
    for (k, v) in kv {
        ok(
            conn.execute(
                "INSERT INTO session_kv (key, value) VALUES (?1, ?2)",
                rusqlite::params![k, v],
            ),
            "seed kv",
        );
    }
    ok(
        conn.pragma_update(None, "user_version", 2),
        "pin user_version=2",
    );
}

/// Mock aria2 JSON-RPC endpoint: records the method/token sequence and
/// replies with a success result; returns (port, record handle).
fn spawn_mock_aria2() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = ok(TcpListener::bind("127.0.0.1:0"), "bind mock");
    let port = ok(listener.local_addr(), "local_addr").port();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen_cloned = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            let Some((_, body)) = text.split_once("\r\n\r\n") else {
                continue;
            };
            let method = body
                .split("\"method\":\"")
                .nth(1)
                .and_then(|m| m.split('"').next())
                .unwrap_or("?")
                .to_string();
            let token_ok = body.contains("\"params\":[\"token:sekret\"");
            if let Ok(mut g) = seen_cloned.lock() {
                g.push(method.clone());
                g.push(format!("token_ok={token_ok}"));
            }
            let result = if method == "aria2.purgeDownloadResult" {
                "OK"
            } else {
                "1"
            };
            let payload =
                format!("{{\"jsonrpc\":\"2.0\",\"id\":\"taiji-import\",\"result\":\"{result}\"}}");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });
    (port, seen)
}

/// Full chain: dry-run (no db writes) -> import (rows written, checked
/// column by column, plus the deregistration list) -> re-import
/// (blocked by imported_from).
#[test]
fn dry_run_import_and_dedup_full_chain() {
    let root = tmp_dir("chain");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let (raw, ih, hex) = build_v1_torrent();
    // Metadata candidate 1 (the bt-save-metadata spot: <dir>/<hex>.torrent).
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    // `.aria2` face: a control file for the same torrent (all pieces
    // done + 1 in-flight piece + upload counter) -> full import
    // (queued).
    ok(
        std::fs::write(
            dl.join("migrated.bin.aria2"),
            build_ctrl(
                &ih,
                777,
                &[0b1100_0000],
                vec![(1, 16384, vec![0b1000_0000])],
            ),
        ),
        "write ctrl",
    );
    ok(
        std::fs::write(dl.join("migrated.bin"), b"data"),
        "write target",
    );
    // Non-BT control file (valid HTTP face) -> BT face skips it + HTTP face flagged as orphan.
    ok(
        std::fs::write(dl.join("http.aria2"), build_http_ctrl(1024, 0, &[])),
        "write non-bt",
    );
    // Fork db: the serialized dir points at dl (candidate 1 hit).
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db(
        &fork_db,
        "0000000000000042",
        &ih,
        dl.to_str().unwrap_or("."),
    );
    let target = root.join("taiji.sqlite3");

    let common = [
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--from-aria2-dir".to_string(),
        dl.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
    ];
    let args_with = |extra: &[&str]| -> Vec<String> {
        common
            .iter()
            .cloned()
            .chain(extra.iter().map(|s| s.to_string()))
            .collect()
    };

    // ---- dry-run: report + deregistration list, zero db writes ----
    let (code, out) = run_import(&args_with(&["--dry-run"]));
    assert_eq!(code, 0, "dry-run exit: {out}");
    assert!(out.contains("taiji import (dry-run)"), "{out}");
    assert!(
        out.contains("state=paused"),
        "the fork pause surface: {out}"
    );
    assert!(out.contains("state=queued"), "the ctrl task queued: {out}");
    assert!(
        out.contains("not a BitTorrent control file"),
        "non-BT skipped: {out}"
    );
    assert!(
        out.contains("0000000000000042"),
        "the deregistration list carries the fork GID: {out}"
    );
    assert!(out.contains("deregister via aria2 RPC"), "{out}");
    assert!(!target.exists(), "dry-run must not create the target db");

    // ---- real run: import + per-column row assertions ----
    let (code, out) = run_import(&args_with(&[]));
    assert_eq!(code, 0, "import exit: {out}");
    assert!(out.contains("[imported]"), "{out}");
    assert!(
        out.contains("0000000000000042"),
        "the deregistration list: {out}"
    );
    {
        let conn = ok(rusqlite::Connection::open(&target), "open target");
        // torrent rows: new GIDs (high bit 1); state/kind/infohash/config_json.
        let rows: Vec<(String, String, String, Vec<u8>, String)> = {
            let mut stmt = ok(
                conn.prepare(
                    "SELECT gid, state, kind, v1_infohash, config_json FROM torrent ORDER BY state",
                ),
                "prepare torrent query",
            );
            let rows = ok(
                stmt.query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                }),
                "query torrent rows",
            );
            ok(rows.collect(), "collect torrent rows")
        };
        assert_eq!(rows.len(), 2, "one row each for fork + ctrl: {rows:?}");
        for (gid, state, kind, v1, cfg) in &rows {
            assert_eq!(gid.len(), 16, "{gid}");
            let high = u64::from_str_radix(gid, 16)
                .map(|v| v & 0x8000_0000_0000_0000 != 0)
                .unwrap_or(false);
            assert!(high, "a new GID's high bit must be set: {gid}");
            assert_eq!(kind, "v1", "{state}");
            assert_eq!(v1.as_slice(), ih.as_slice());
            if state == "paused" {
                assert!(
                    cfg.contains("\"dir\":\""),
                    "config_json = the serialized dir surface: {cfg}"
                );
            }
        }
        assert_eq!(
            rows[0].1, "paused",
            "the fork pause surface (serialized pause=true)"
        );
        assert_eq!(rows[1].1, "queued", "the ctrl task has no pause surface");
        // Progress rows: fork source upload 4096 / ctrl source upload
        // 777; both bitmaps 0xC0; downloaded_total 32768 derived from
        // the bitmap.
        let progress: Vec<(i64, i64, i64, Option<Vec<u8>>)> = {
            let mut stmt = ok(
                conn.prepare(
                    "SELECT upload_at_startup, uploaded_total, downloaded_total, v1_bitfield
                     FROM torrent_progress ORDER BY upload_at_startup",
                ),
                "prepare progress query",
            );
            let rows = ok(
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))),
                "query progress rows",
            );
            ok(rows.collect(), "collect progress rows")
        };
        assert_eq!(
            progress,
            vec![
                (777, 777, 32768, Some(vec![0b1100_0000])),
                (4096, 4096, 32768, Some(vec![0b1100_0000])),
            ],
            "fork/ctrl progress rows column by column (upload_length -> upload_at_startup \
             + uploaded_total; ORDER BY upload_at_startup)"
        );
        // Trackers rebuilt from metadata (tier 0 = announce; one row per task).
        let tracker_count: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM tracker WHERE url = 'http://t.invalid/announce' AND tier = 0",
                [],
                |r| r.get(0),
            ),
            "count trackers",
        );
        assert_eq!(tracker_count, 2);
        // session_kv dedup markers (one per fork/ctrl task).
        let kv_count: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM session_kv WHERE key LIKE 'imported_from:%'",
                [],
                |r| r.get(0),
            ),
            "count kv",
        );
        assert_eq!(kv_count, 2);
    }

    // ---- re-import: imported_from blocks (dry-run idempotent) ----
    let (code, out) = run_import(&args_with(&["--dry-run"]));
    assert_eq!(code, 0, "re-dry-run exit: {out}");
    assert!(out.contains("already imported"), "{out}");
    assert!(out.contains("0 planned"), "{out}");
    // A real run is blocked the same way and adds no rows.
    let (code, out) = run_import(&args_with(&[]));
    assert_eq!(code, 0, "re-import exit: {out}");
    assert!(out.contains("0 planned"), "{out}");
    {
        let conn = ok(rusqlite::Connection::open(&target), "reopen target");
        let count: i64 = ok(
            conn.query_row("SELECT COUNT(*) FROM torrent", [], |r| r.get(0)),
            "count torrents after re-import",
        );
        assert_eq!(count, 2, "a repeated import must not produce new rows");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Deregistration: `--purge-via-aria2` drives remove (per GID) +
/// purgeDownloadResult (once) through the mock aria2 endpoint; the
/// token is sent as the `token:SECRET` prefix (the aria2 client
/// convention).
#[test]
fn purge_via_aria2_calls_remove_and_purge() {
    let root = tmp_dir("purge");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let (raw, ih, hex) = build_v1_torrent();
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db(
        &fork_db,
        "0000000000000099",
        &ih,
        dl.to_str().unwrap_or("."),
    );
    let target = root.join("taiji.sqlite3");
    let (port, seen) = spawn_mock_aria2();
    let args = vec![
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
        "--purge-via-aria2".to_string(),
        format!("http://token:sekret@127.0.0.1:{port}/jsonrpc"),
        "--yes".to_string(),
    ];
    let (code, out) = run_import(&args);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("aria2 purge done: 1 active removed"), "{out}");
    let seen = ok(seen.lock(), "lock seen");
    assert!(
        seen.windows(2)
            .any(|w| w[0] == "aria2.remove" && w[1] == "token_ok=true"),
        "the remove call should carry the token: {seen:?}"
    );
    assert!(
        seen.windows(2)
            .any(|w| w[0] == "aria2.purgeDownloadResult" && w[1] == "token_ok=true"),
        "purgeDownloadResult should carry the token: {seen:?}"
    );
    assert_eq!(
        seen.iter().filter(|m| m.as_str() == "aria2.remove").count(),
        1,
        "exactly one remove per GID: {seen:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Seed row: (gid, serialized, optional progress(piece_length,
/// total_length, upload, first bitfield byte)).
type HttpSeedRow<'a> = (&'a str, &'a str, Option<(i32, i64, i64, u8)>);

/// http_task assertion row: (url, mirrors_json, state, dir, out,
/// block_size, block_count, total_done, validator_digest IS NULL,
/// block_bitmap).
type HttpRowSnapshot = (
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
);

/// Synthetic fork-schema db seeded with HTTP/FTP task rows
/// (is_torrent=0; serialized = first line with TAB-separated URIs +
/// leading-space option lines; progress optional — None = no
/// task_progress row, the weak-resume shape).
fn seed_fork_db_http(path: &Path, rows: &[HttpSeedRow<'_>]) {
    let conn = ok(rusqlite::Connection::open(path), "open fork fixture");
    ok(
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE task (gid TEXT PRIMARY KEY, state TEXT NOT NULL, serialized TEXT NOT NULL,
               belongs_to TEXT, following TEXT, followed_by TEXT, metadata_uri TEXT, bt_local_path TEXT,
               queue_position INTEGER NOT NULL, digest BLOB NOT NULL, created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL);
             CREATE INDEX idx_task_state ON task(state);
             CREATE INDEX idx_task_queue_position ON task(queue_position);
             CREATE TABLE task_progress (gid TEXT PRIMARY KEY, ctrl_version INTEGER NOT NULL DEFAULT 1,
               is_torrent INTEGER NOT NULL DEFAULT 0, info_hash BLOB, piece_length INTEGER NOT NULL,
               total_length INTEGER NOT NULL, upload_length INTEGER NOT NULL DEFAULT 0,
               bitfield BLOB NOT NULL DEFAULT X'', in_flight_blob BLOB NOT NULL DEFAULT X'',
               digest BLOB NOT NULL, updated_at INTEGER NOT NULL,
               FOREIGN KEY (gid) REFERENCES task(gid) ON DELETE CASCADE);
             CREATE TABLE download_history (id INTEGER PRIMARY KEY AUTOINCREMENT, gid TEXT NOT NULL);
             PRAGMA user_version = 1;",
        ),
        "seed schema",
    );
    for (i, (gid, serialized, progress)) in rows.iter().enumerate() {
        ok(
            conn.execute(
                "INSERT INTO task (gid, state, serialized, queue_position, digest, created_at, updated_at)
                 VALUES (?1, 'active', ?2, ?3, x'00', 0, 0)",
                rusqlite::params![gid, serialized, i as i64],
            ),
            "seed http task",
        );
        if let Some((piece_length, total_length, _upload, bitfield)) = progress {
            ok(
                conn.execute(
                    "INSERT INTO task_progress (gid, is_torrent, piece_length, total_length,
                                                bitfield, digest, updated_at)
                     VALUES (?1, 0, ?2, ?3, ?4, x'00', 0)",
                    // bitfield must be a BLOB (the fork writes a BLOB
                    // column; an integer binding is rejected by type).
                    rusqlite::params![gid, piece_length, total_length, [*bitfield].as_slice()],
                ),
                "seed http progress",
            );
        }
    }
}

/// HTTP face, one command: full-coverage bitmap mapping lands in the
/// db -> re-import dedup + same-(dir,out) conflict decision (skip by
/// default / rename explicit) -> pre-import backup "keep, never
/// overwrite" semantics.
#[test]
fn http_face_import_second_import_and_path_conflict() {
    let root = tmp_dir("httpface");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let dir_str = dl.to_str().unwrap_or(".");
    // Row A: multi-URI + option list + 3 x 1MiB pieces (first two
    // done). Bitmap full-coverage mapping: block granularity = 1MiB
    // (power-of-two-aligned branch); blocks 0/1 land, block 2 (the
    // in-flight piece) is dropped; total_done = 2MiB.
    let serialized_a = format!(
        "http://127.0.0.1:9/a.bin\thttp://mirror.invalid/a.bin\t\n \
         header=X-A: 1\n \
         header=X-B: 2\n \
         out=a.bin\n \
         dir={dir_str}\n \
         user-agent=fork-agent/1\n"
    );
    // Row B: same dir+out (the re-import conflict carrier); no progress row = weak resume.
    let serialized_b = format!("http://127.0.0.1:9/a.bin\n dir={dir_str}\n out=a.bin\n");
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db_http(
        &fork_db,
        &[
            (
                "00000000000000aa",
                &serialized_a,
                Some((1_048_576, 3_145_728, 0, 0b1100_0000u8)),
            ),
            ("00000000000000ab", &serialized_b, None),
        ],
    );
    let target = root.join("taiji.sqlite3");
    let common = [
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
    ];
    let args_with = |extra: &[&str]| -> Vec<String> {
        common
            .iter()
            .cloned()
            .chain(extra.iter().map(|s| s.to_string()))
            .collect()
    };

    // ---- First import (default skip): A lands (bitmap/options/mirrors), B conflict-skipped ----
    let (code, out) = run_import(&args_with(&[]));
    assert_eq!(code, 0, "first import exit: {out}");
    assert!(
        out.contains("pre-import backup: none needed"),
        "the target db missing on first import = no backup needed: {out}"
    );
    assert!(out.contains("state=queued"), "row A planned: {out}");
    assert!(
        out.contains("path conflict"),
        "B conflict-skipped (the default decision): {out}"
    );
    assert!(
        out.contains("1 skipped"),
        "the B conflict skip count: {out}"
    );
    {
        let conn = ok(rusqlite::Connection::open(&target), "open target");
        let mut rows: Vec<HttpRowSnapshot> = {
            let mut stmt = ok(
                conn.prepare(
                    "SELECT url, mirrors_json, state, dir, out, block_size, block_count,
                            total_done, validator_digest IS NULL, block_bitmap
                     FROM http_task",
                ),
                "prepare http query",
            );
            let rows = ok(
                stmt.query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                }),
                "query http rows",
            );
            ok(rows.collect(), "collect http rows")
        };
        assert_eq!(
            rows.len(),
            1,
            "exactly one http_task row under the default skip decision: {rows:?}"
        );
        let (
            url,
            mirrors,
            state,
            r_dir,
            r_out,
            block_size,
            block_count,
            total_done,
            vd_null,
            bitmap,
        ) = rows.remove(0);
        assert_eq!(
            url, "http://127.0.0.1:9/a.bin",
            "url = the first URI: {url}"
        );
        assert!(
            mirrors.contains("http://mirror.invalid/a.bin"),
            "mirrors_json = the serialized multi-URI restoration: {mirrors}"
        );
        assert_eq!(state, "queued", "fork active -> queued: {state}");
        assert_eq!(r_dir, dir_str);
        assert_eq!(r_out, "a.bin", "the serialized out= surface A: {r_out}");
        assert_eq!(
            block_size, 1_048_576,
            "block granularity = the piece's largest power-of-two factor: {block_size}"
        );
        assert_eq!(block_count, 3, "{block_count}");
        assert_eq!(
            total_done, 2_097_152,
            "fully covered block bytes: {total_done}"
        );
        assert_eq!(
            vd_null, 0,
            "the mapping face seeds the validator digest (re-verified at activation)"
        );
        assert_eq!(
            bitmap,
            Some(vec![0b0000_0011]),
            "blocks 0/1 land, block 2 dropped (block_bitmap LSB-first, isomorphic to \
             grid.rs; the source piece bitmap MSB-first 0xC0)"
        );
        let cfg: String = ok(
            conn.query_row("SELECT config_json FROM http_task", [], |r| r.get(0)),
            "config_json",
        );
        assert!(
            cfg.contains("\"user-agent\",\"fork-agent/1\"")
                && cfg.contains("\"header\",\"X-A: 1\""),
            "the option list migrates verbatim: {cfg}"
        );
        let kv: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM session_kv WHERE key LIKE 'imported_from:%'",
                [],
                |r| r.get(0),
            ),
            "count kv",
        );
        assert_eq!(kv, 1, "only actually-landed tasks carry the dedup marker");
    }

    // ---- Second import (default skip): A dedup-blocked, B still
    // conflict-skipped; the target db now exists with no backup yet ->
    // this is where .v1.bak is produced (the first run had no target
    // db to back up) ----
    let (code, out) = run_import(&args_with(&[]));
    assert_eq!(code, 0, "second import exit: {out}");
    assert!(
        out.contains("pre-import backup: ") && out.contains("(created)"),
        "when the target db exists, .v1.bak is created before the real import: {out}"
    );
    assert!(out.contains("already imported"), "A dedup-blocked: {out}");
    assert!(out.contains("0 planned"), "{out}");
    {
        let conn = ok(rusqlite::Connection::open(&target), "reopen target");
        let count: i64 = ok(
            conn.query_row("SELECT COUNT(*) FROM http_task", [], |r| r.get(0)),
            "count http rows after re-import",
        );
        assert_eq!(count, 1, "a repeated import must not produce new rows");
    }
    // ---- Third import: .v1.bak is kept, never overwritten ----
    let (code, out) = run_import(&args_with(&[]));
    assert_eq!(code, 0, "third import exit: {out}");
    assert!(
        out.contains("kept existing (never overwritten)"),
        "an existing .v1.bak is kept, never overwritten: {out}"
    );

    // ---- rename decision (fresh target db): conflicts renamed per aria2 candidates ----
    let target2 = root.join("taiji2.sqlite3");
    let mut rename_args = common.to_vec();
    rename_args.pop(); // old target path value
    rename_args.pop(); // --sqlite3-db-path flag
    rename_args.push("--sqlite3-db-path".to_string());
    rename_args.push(target2.display().to_string());
    rename_args.push("--on-path-conflict".to_string());
    rename_args.push("rename".to_string());
    let refs: Vec<&str> = rename_args.iter().map(|s| s.as_str()).collect();
    let out = ok(
        Command::new(env!("CARGO_BIN_EXE_taiji"))
            .arg("import")
            .args(&refs)
            .stderr(Stdio::inherit())
            .output(),
        "run rename import",
    );
    assert_eq!(out.status.code(), Some(0));
    let out = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.contains("2 planned"),
        "the rename decision lands both tasks: {out}"
    );
    assert!(out.contains("renamed a.bin -> a.1.bin"), "{out}");
    {
        let conn = ok(rusqlite::Connection::open(&target2), "open target2");
        let mut outs: Vec<String> = {
            let mut stmt = ok(
                conn.prepare("SELECT out FROM http_task ORDER BY queue_pos"),
                "prepare outs",
            );
            let rows = ok(stmt.query_map([], |r| r.get::<_, String>(0)), "query outs");
            ok(rows.collect(), "collect outs")
        };
        outs.sort();
        assert_eq!(
            outs,
            vec!["a.1.bin".to_string(), "a.bin".to_string()],
            "{outs:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Dry-run on a legacy 0.1.x target (user_version=2) is zero-write:
/// the ledger must stay 2, the main file's bytes unchanged, no
/// `.v1.bak`, no WAL sidecars. (The old implementation migrated
/// v2->v3 in place via PersistWriter::spawn, so a dry-run-first flow
/// poisoned the `.v1.bak` rollback anchor into an "already migrated"
/// snapshot.)
#[test]
fn dry_run_on_legacy_v2_target_is_zero_write() {
    let root = tmp_dir("dryv2");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let (raw, ih, hex) = build_v1_torrent();
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db(
        &fork_db,
        "0000000000000042",
        &ih,
        dl.to_str().unwrap_or("."),
    );
    // Target = a 0.1.x-shaped db, pre-seeded with the dedup key for
    // this fork task (canonical path per the collector's source_key
    // rule).
    let target = root.join("taiji.sqlite3");
    let canonical_fork = ok(std::fs::canonicalize(&fork_db), "canonical fork db");
    let dedup_key = format!(
        "imported_from:db:{}#0000000000000042",
        canonical_fork.display()
    );
    seed_legacy_v2_target(&target, &[(&dedup_key, "80000000000000aa")]);
    assert!(!wal_sidecars(&target), "the seeded db is closed cleanly");
    let before = sha256_hex(&target);

    let args = vec![
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
        "--dry-run".to_string(),
    ];
    let (code, out, _err) = run_import_captured(&args);
    assert_eq!(code, 0, "dry-run exit: {out}");
    assert!(
        out.contains("already imported"),
        "the read-only dedup query takes effect: {out}"
    );
    // Four zero-write assertions: ledger position, main-file bytes, no backup, no sidecars.
    assert_eq!(
        user_version_of(&target),
        2,
        "dry-run must not advance the migration ledger"
    );
    assert_eq!(sha256_hex(&target), before, "dry-run writes zero bytes");
    assert!(
        !Path::new(&format!("{}.v1.bak", target.display())).exists(),
        "dry-run makes no pre-import backup"
    );
    assert!(!wal_sidecars(&target), "dry-run leaves no WAL sidecars");
    let _ = std::fs::remove_dir_all(&root);
}

/// Same-path guard + target-shape guard: a `--sqlite3-db-path`
/// canonically equal to `--from-aria2-db` (including spelling
/// variants) is rejected with the fork db untouched; a target that is
/// actually a fork-schema db (task/task_progress tables present) is
/// rejected before open/backup/migrate — the fork store is never
/// written.
#[test]
fn same_path_and_fork_shaped_target_are_rejected() {
    let root = tmp_dir("samepath");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let (raw, ih, hex) = build_v1_torrent();
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db(
        &fork_db,
        "0000000000000042",
        &ih,
        dl.to_str().unwrap_or("."),
    );
    let fork_bytes = ok(std::fs::read(&fork_db), "read fork bytes");

    // -- case A: literally the same path --
    let args = vec![
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        fork_db.display().to_string(),
    ];
    let (code, _out, err) = run_import_captured(&args);
    assert_eq!(code, 1, "the same path must be rejected");
    assert!(
        err.contains("same database file"),
        "the rejection reason goes to stderr: {err}"
    );
    assert_eq!(
        ok(std::fs::read(&fork_db), "reread fork"),
        fork_bytes,
        "the rejection path leaves the fork db untouched"
    );

    // -- case B: spelling-variant same path (`/./` segment, canonicalize-normalized) --
    let spelled = format!("{}/./fork.sqlite3", root.display());
    let args = vec![
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        spelled,
    ];
    let (code, _out, err) = run_import_captured(&args);
    assert_eq!(code, 1, "a spelling-variant same path is rejected too");
    assert!(err.contains("same database file"), "{err}");
    assert_eq!(
        ok(std::fs::read(&fork_db), "reread fork"),
        fork_bytes,
        "the rejection path leaves the fork db untouched"
    );

    // -- case C: target points at a fork-schema db (different path,
    // task/task_progress tables present) — backup/checkpoint and
    // migration would write it, so it must be rejected beforehand --
    let fork_as_target = root.join("fork-as-target.sqlite3");
    {
        let conn = ok(
            rusqlite::Connection::open(&fork_as_target),
            "open fake target",
        );
        ok(
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE task (gid TEXT PRIMARY KEY);
                 CREATE TABLE task_progress (gid TEXT PRIMARY KEY);
                 PRAGMA user_version = 1;",
            ),
            "seed fork-shaped target",
        );
    }
    let target_bytes = ok(std::fs::read(&fork_as_target), "read target bytes");
    let args = vec![
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        fork_as_target.display().to_string(),
    ];
    let (code, _out, err) = run_import_captured(&args);
    assert_eq!(code, 1, "a fork-shaped target must be rejected");
    assert!(
        err.contains("fork"),
        "the rejection reason goes to stderr: {err}"
    );
    assert_eq!(
        ok(std::fs::read(&fork_as_target), "reread target"),
        target_bytes,
        "the rejection path leaves the fork-shaped target untouched"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A dedup-key read failure must not degrade silently: with the
/// session_kv table missing (injected read failure), the import face
/// must fail the task (unknown dedup state = refuse re-import —
/// silently treating it as "not imported" would overwrite live task
/// rows with import-time state), and the dry-run face must refuse
/// explicitly instead of pretending dedup is verifiable.
#[test]
fn dedup_kv_read_failure_fails_tasks_instead_of_silent_reimport() {
    let root = tmp_dir("kvfail");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let dir_str = dl.to_str().unwrap_or(".");
    let (raw, ih, hex) = build_v1_torrent();
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    let fork_db = root.join("fork.sqlite3");
    // HTTP + BT faces share the fork db (one command): seed the HTTP row, then the BT row.
    seed_fork_db_http(
        &fork_db,
        &[(
            "00000000000000aa",
            &format!("http://127.0.0.1:9/kvfail.bin\n dir={dir_str}\n out=kvfail.bin\n"),
            None,
        )],
    );
    {
        let conn = ok(rusqlite::Connection::open(&fork_db), "reopen fork db");
        ok(
            conn.execute(
                "INSERT INTO task (gid, state, serialized, queue_position, digest, created_at, updated_at)
                 VALUES ('0000000000000042', 'paused', ?1, 9, x'00', 0, 0)",
                rusqlite::params![format!(" dir={dir_str}\n pause=true\n")],
            ),
            "seed bt task",
        );
        let bf = [0b1100_0000u8];
        ok(
            conn.execute(
                "INSERT INTO task_progress (gid, is_torrent, info_hash, piece_length, total_length,
                                            upload_length, bitfield, digest, updated_at)
                 VALUES ('0000000000000042', 1, ?1, 16384, 32768, 4096, ?2, x'00', 0)",
                rusqlite::params![ih.as_slice(), bf.as_slice()],
            ),
            "seed bt progress",
        );
    }
    let target = root.join("taiji.sqlite3");
    let common: Vec<String> = [
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
    ]
    .to_vec();
    // First import: one row each for BT + HTTP.
    let (code, out) = run_import(&common);
    assert_eq!(code, 0, "first import: {out}");
    // Simulate live-task evolution + inject the kv read failure (drop session_kv).
    {
        let conn = ok(rusqlite::Connection::open(&target), "open target");
        ok(
            conn.execute("UPDATE torrent SET state = 'seeding'", []),
            "evolve torrent row",
        );
        ok(
            conn.execute("UPDATE http_task SET state = 'downloading'", []),
            "evolve http row",
        );
        ok(
            conn.execute("DROP TABLE session_kv", []),
            "inject kv read failure",
        );
    }
    // Re-import: dedup state unknown -> both tasks fail (never re-import over live rows).
    let (code, out, err) = run_import_captured(&common);
    assert_eq!(
        code, 2,
        "a kv read failure = the task-failure surface: {out}{err}"
    );
    assert_eq!(
        out.matches("refusing to plan").count(),
        2,
        "both the BT and HTTP faces fail explicitly (no silent degradation to not-imported; \
         the tracing warning shares the topic but the report rows are the count of record): {out}"
    );
    assert!(
        out.contains("0 planned"),
        "failed tasks must not enter the plan: {out}"
    );
    {
        let conn = ok(rusqlite::Connection::open(&target), "reopen target");
        let state: String = ok(
            conn.query_row("SELECT state FROM torrent", [], |r| r.get(0)),
            "torrent state",
        );
        assert_eq!(
            state, "seeding",
            "the live task row must not be overwritten by the import state \
             after the kv read failure"
        );
        let (n, state): (i64, String) = ok(
            conn.query_row("SELECT COUNT(*), MAX(state) FROM http_task", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            }),
            "http rows",
        );
        assert_eq!(
            (n, state.as_str()),
            (1, "downloading"),
            "the HTTP row likewise is not overwritten"
        );
    }
    // Dry-run face: the dedup read failure is an explicit refusal (infrastructure error).
    let mut dry_args = common.clone();
    dry_args.push("--dry-run".to_string());
    let (code, _out, err) = run_import_captured(&dry_args);
    assert_eq!(
        code, 1,
        "the dry-run dedup read failure must be an explicit refusal"
    );
    assert!(
        err.contains("cannot read target db"),
        "the rejection reason goes to stderr: {err}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ---- Fork-liveness probing, the explicit ack flag, and import reports ----

/// Run `taiji import <args>` with injected environment (PATH
/// redirection simulates lsof absence); returns (exit code, stdout,
/// stderr).
fn run_import_with_envs(args: &[String], envs: &[(&str, &Path)]) -> (i32, String, String) {
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_taiji"));
    cmd.arg("import").args(&refs).envs(envs.iter().copied());
    let out = ok(cmd.output(), "run taiji import");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// All `<target>.import-report-<timestamp>.txt` files (name order = time order).
fn import_reports(target: &Path) -> Vec<PathBuf> {
    let dir = target.parent().unwrap_or(Path::new("."));
    let prefix = format!(
        "{}.import-report-",
        target.file_name().and_then(|n| n.to_str()).unwrap_or("?")
    );
    let mut out: Vec<PathBuf> = ok(std::fs::read_dir(dir), "read target dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".txt"))
        })
        .collect();
    out.sort();
    out
}

/// Live fork (WAL mode does not hold the lock): a child process holds
/// the fork db fd — the lock probe (layer 1) passes but the fd scan
/// (layer 2) hits, so import refuses and reports the pid; the ack
/// flag does NOT exempt layer 2; once the holder exits, the same
/// command goes through.
#[test]
fn live_fork_fd_holder_refuses_import_reporting_pid() {
    let root = tmp_dir("livefork");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let (raw, ih, hex) = build_v1_torrent();
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db(
        &fork_db,
        "0000000000000042",
        &ih,
        dl.to_str().unwrap_or("."),
    );
    let target = root.join("taiji.sqlite3");
    let base = [
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
        "--dry-run".to_string(),
    ];

    // Live holder: a child process holds the db file via stdin (visible to
    // the kernel right after spawn).
    let holder = ok(std::fs::File::open(&fork_db), "open holder fd");
    let mut child = ok(
        std::process::Command::new("sleep")
            .arg("60")
            .stdin(Stdio::from(holder))
            .spawn(),
        "spawn fd holder",
    );
    let child_pid = child.id().to_string();

    // Layer-2 refusal: reports the pid, exit 1 (pre-check rejection).
    let (code, out, err) = run_import_captured(&base);
    assert_eq!(code, 1, "a live fork must be refused with 1: {out}{err}");
    assert!(
        err.contains("held open by live process(es)"),
        "the rejection surface goes to stderr: {err}"
    );
    assert!(
        err.contains(&child_pid),
        "the holder process pid {child_pid} must be reported: {err}"
    );
    assert!(
        !out.contains("taiji import"),
        "the refusal happens before collection/reporting: {out}"
    );

    // The flag does not exempt layer 2: same command + --i-know-fork-is-closed still refused.
    let mut with_flag = base.to_vec();
    with_flag.push("--i-know-fork-is-closed".to_string());
    let (code, _out, err) = run_import_captured(&with_flag);
    assert_eq!(code, 1, "the flag must not exempt a liveness hit: {err}");
    assert!(err.contains(&child_pid), "{err}");

    ok(child.kill(), "kill holder");
    let _ = child.wait();
    // Holder exited -> layer 2 clean -> the same command dry-runs normally.
    let (code, out, err) = run_import_captured(&base);
    assert_eq!(
        code, 0,
        "after the holder exits the command must be allowed through: {out}{err}"
    );
    assert!(out.contains("taiji import (dry-run)"), "{out}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Ack-flag positive/negative cases (macOS: PATH redirection simulates
/// the tool missing = unprovable; Linux procfs has no tool-absent
/// state, so those cases live in core pure-function unit tests):
/// unprovable -> refuse by default with the flag named in the
/// message; passing the flag = accept responsibility and proceed.
#[cfg(target_os = "macos")]
#[test]
fn i_know_fork_is_closed_flag_releases_unprovable_state_only() {
    let root = tmp_dir("ackflag");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let (raw, ih, hex) = build_v1_torrent();
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db(
        &fork_db,
        "0000000000000042",
        &ih,
        dl.to_str().unwrap_or("."),
    );
    let target = root.join("taiji.sqlite3");
    // Empty bin dir = no lsof in the child environment -> fd scan is Uncertain (unprovable).
    let empty_bin = root.join("empty-bin");
    ok(std::fs::create_dir_all(&empty_bin), "mkdir empty-bin");
    let base = [
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
        "--dry-run".to_string(),
    ];

    // Negative: unprovable -> refuse by default, message points at the flag.
    let (code, out, err) = run_import_with_envs(&base, &[("PATH", empty_bin.as_path())]);
    assert_eq!(code, 1, "unprovable must be refused by default: {out}{err}");
    assert!(
        err.contains("cannot prove the fork is closed"),
        "the rejection surface goes to stderr: {err}"
    );
    assert!(
        err.contains("--i-know-fork-is-closed"),
        "the message points at the flag: {err}"
    );

    // Positive: explicit ack -> proceed (dry-run completes + report written).
    let mut ack = base.to_vec();
    ack.push("--i-know-fork-is-closed".to_string());
    let (code, out, err) = run_import_with_envs(&ack, &[("PATH", empty_bin.as_path())]);
    assert_eq!(
        code, 0,
        "after accepting responsibility the dry-run must complete: {out}{err}"
    );
    assert!(out.contains("taiji import (dry-run)"), "{out}");
    let reports = import_reports(&target);
    assert_eq!(
        reports.len(),
        1,
        "the responsibility-accepted dry-run must also land a report: {reports:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Report files: dry-run and real import each write one
/// `<db>.import-report-<ts>.txt` (content = the full stdout report;
/// stdout also prints the path).
#[test]
fn import_report_written_for_dry_run_and_real_run() {
    let root = tmp_dir("report");
    let dl = root.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let (raw, ih, hex) = build_v1_torrent();
    ok(
        std::fs::write(dl.join(format!("{hex}.torrent")), &raw),
        "write meta",
    );
    ok(
        std::fs::write(
            dl.join("migrated.bin.aria2"),
            build_ctrl(&ih, 777, &[0b1100_0000], vec![]),
        ),
        "write ctrl",
    );
    ok(
        std::fs::write(dl.join("migrated.bin"), b"data"),
        "write data",
    );
    let fork_db = root.join("fork.sqlite3");
    seed_fork_db(
        &fork_db,
        "0000000000000042",
        &ih,
        dl.to_str().unwrap_or("."),
    );
    let target = root.join("taiji.sqlite3");
    let common = [
        "--from-aria2-db".to_string(),
        fork_db.display().to_string(),
        "--from-aria2-dir".to_string(),
        dl.display().to_string(),
        "--sqlite3-db-path".to_string(),
        target.display().to_string(),
    ];

    // ---- dry-run: report written + stdout prints the path ----
    let (code, out) = run_import(&args_with_dry(&common));
    assert_eq!(code, 0, "dry-run exit: {out}");
    let reports = import_reports(&target);
    assert_eq!(
        reports.len(),
        1,
        "dry-run lands exactly one report: {reports:?}"
    );
    let dry_report = &reports[0];
    let dry_text = ok(std::fs::read_to_string(dry_report), "read dry report");
    assert!(dry_text.contains("taiji import (dry-run)"), "{dry_text}");
    assert!(
        dry_text.contains("0000000000000042"),
        "the task row is in the report: {dry_text}"
    );
    assert!(
        dry_text.contains("planned ("),
        "the summary line is in the report: {dry_text}"
    );
    assert!(dry_text.contains("deregister via aria2 RPC"), "{dry_text}");
    assert!(
        dry_text.contains(&format!("import report: {}", dry_report.display())),
        "the stdout path line = the report's own receipt \
         (the full-text consistency anchor): {dry_text}"
    );
    assert!(
        out.contains(&format!("import report: {}", dry_report.display())),
        "stdout prints the report path in sync: {out}"
    );

    // ---- real import: a second report (with the landed-result rows) ----
    let (code, out) = run_import(&common);
    assert_eq!(code, 0, "import exit: {out}");
    let reports = import_reports(&target);
    assert_eq!(
        reports.len(),
        2,
        "one report each for dry-run/real import: {reports:?}"
    );
    let real_text = ok(std::fs::read_to_string(&reports[1]), "read real report");
    assert!(
        real_text.contains("taiji import\n") || real_text.contains("taiji import \n"),
        "the real-import report header (no dry-run marker): {real_text}"
    );
    assert!(
        real_text.contains("[imported]"),
        "the landed-result rows: {real_text}"
    );
    assert!(
        real_text.contains("pre-import backup:"),
        "the real-import backup line is in the report: {real_text}"
    );
    assert!(
        out.contains(&format!("import report: {}", reports[1].display())),
        "stdout prints the report path in sync: {out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Helper: append `--dry-run` to a common arg array.
fn args_with_dry(common: &[String]) -> Vec<String> {
    common
        .iter()
        .cloned()
        .chain(["--dry-run".to_string()])
        .collect()
}
