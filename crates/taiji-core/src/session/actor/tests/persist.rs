// ---- Crash recovery and startup rebuild ----

use rusqlite::params;
use taiji_store::persist::{PersistWriter, TorrentRow as StoreTorrentRow};

fn tmp_db(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "bh-p38-{tag}-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ))
}

fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Task registration persisted -> saveSession -> kill simulation
/// (handle drop) -> restart bootstrap -> GID/row/file rows intact +
/// GID reserve -> state transitions (unpause -> activation) -> graceful
/// shutdown teardown (unfinished queued row) with zero loss.
#[tokio::test]
async fn torrent_row_roundtrip_survives_restart_with_gid_reserve() {
    let db = tmp_db("roundtrip");
    let dir = temp_dir("roundtrip");

    // ---- session 1: paused registration + saveSession + kill
    // simulation ----
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let bytes = build_v2_torrent(&vec![0xACu8; 128 * 1024], &dead_tracker());
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    // Registration persists immediately (a paused row; a 1-row file
    // set).
    match call(&handle, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession must be accepted, got {other:?}"),
    }
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback 1");
        let (state, name): (String, String) = ok(
            conn.query_row(
                "SELECT state, name FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ),
            "row 1",
        );
        assert_eq!(state, "paused");
        assert_eq!(name, "v2.bin");
        let n: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM torrent_file WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get(0),
            ),
            "files 1",
        );
        assert_eq!(n, 1);
    }
    // Kill simulation: drop all handles (the actor's graceful shutdown
    // teardown is part of this assertion face — after the shutdown
    // flush the row is still there).
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // ---- session 2: bootstrap rebuild + GID reserve + lifecycle ----
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    // Bootstrap -> the paused item queued (visible in tellWaiting, same
    // GID).
    let mut restored = false;
    for _ in 0..100 {
        let waiting = status_list(
            &call(
                &handle2,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        if waiting.len() == 1 && waiting[0].gid == gid && waiting[0].status == StatusKind::Paused {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        restored,
        "the same-GID paused task must be restored after restart"
    );
    // A new task's GID must not collide with the restored GID (the
    // reserve face; a collision in this random space is a bug).
    let bytes_b = build_v2_torrent_named(&vec![0xBBu8; 128 * 1024], &dead_tracker(), "v2-b.bin");
    let gid_b = gid_of(
        &call(
            &handle2,
            SessionCommand::AddTorrent {
                torrent: bytes_b,
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    assert_ne!(gid_b, gid, "GID reserve deduped across restart");
    // Unpause the restored task -> activation (the dead tracker still
    // lets the engine run) -> row state downloading.
    assert_eq!(
        call(
            &handle2,
            SessionCommand::Unpause {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(gid))
    );
    let mut activated = false;
    for _ in 0..100 {
        let active =
            status_list(&call(&handle2, SessionCommand::TellActive { keys: Vec::new() }).await);
        if active.iter().any(|v| v.gid == gid) {
            activated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(activated, "the task activates after unpause");
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback 2");
        let state: String = ok(
            conn.query_row(
                "SELECT state FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get(0),
            ),
            "state 2",
        );
        assert_eq!(state, "downloading", "the activated state persisted");
    }
    // Graceful shutdown: the unfinished task keeps a recoverable row
    // (A was activated -> shutdown-interrupted -> queued to resume; B
    // is still user-paused -> paused stays).
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback 3");
        for (g, want) in [(gid, "queued"), (gid_b, "paused")] {
            let state: String = ok(
                conn.query_row(
                    "SELECT state FROM torrent WHERE gid = ?1",
                    params![g.to_string()],
                    |r| r.get(0),
                ),
                "row after shutdown",
            );
            assert_eq!(state, want, "row state after shutdown ({g})");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Missing metadata (an unfinished magnet) -> the recovery face returns
/// to the metadata state and re-runs ut_metadata (SPEC §5.4); a row
/// with no magnet_uri -> degrades to an error result row (never
/// pretending to be recoverable).
#[tokio::test]
async fn metadata_missing_row_falls_back_to_metadata_state() {
    let db = tmp_db("metadata-fallback");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");

    // Row A: metadata missing + magnet_uri (back to the metadata state
    // and re-run).
    let mut row_a = StoreTorrentRow {
            gid: "80000000000000b1".into(),
            name: "b1".into(),
            state: "metadata".into(),
            queue_pos: 1,
            dir: std::env::temp_dir().display().to_string(),
            config_json: r#"{"magnet_uri":"magnet:?xt=urn:btih:1111111111111111111111111111111111111111&tr=http://127.0.0.1:1/announce"}"#.into(),
            kind: String::new(),
            v1_infohash: Some([0x11; 20].to_vec()),
            v2_infohash: None,
            is_private: false,
            metadata: None,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        };
    let _ = &mut row_a;
    assert_eq!(
        ok(
            writer.upsert_torrent(row_a.clone(), Vec::new()).await,
            "row a"
        ),
        taiji_store::persist::PersistOutcome::Written
    );
    // Row B: metadata missing and no magnet_uri (unrecoverable -> an
    // error result row).
    let row_b = StoreTorrentRow {
        gid: "80000000000000b2".into(),
        name: "b2".into(),
        state: "downloading".into(),
        queue_pos: 2,
        dir: "/tmp".into(),
        config_json: "{}".into(),
        kind: "v1".into(),
        v1_infohash: None,
        v2_infohash: None,
        is_private: false,
        metadata: None,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    assert_eq!(
        ok(writer.upsert_torrent(row_b, Vec::new()).await, "row b"),
        taiji_store::persist::PersistOutcome::Written
    );
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // Restart: bootstrap rebuilds.
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer2.clone()));
    // A -> a metadata-state task activates (the magnet metadata phase
    // runs; visible during the active window before the explicit
    // failure under the dead tracker).
    let mut a_active = false;
    for _ in 0..100 {
        let active =
            status_list(&call(&handle, SessionCommand::TellActive { keys: Vec::new() }).await);
        if active
            .iter()
            .any(|v| v.gid.to_string() == "80000000000000b1")
        {
            a_active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        a_active,
        "a row missing metadata must return to the metadata state and refetch metadata"
    );
    // B -> degraded to an error result row (never queued).
    let _ = tokio::time::timeout(
        Duration::from_millis(300),
        tokio::time::sleep(Duration::from_millis(200)),
    )
    .await;
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback");
        let state: String = ok(
            conn.query_row(
                "SELECT state FROM torrent WHERE gid = '80000000000000b2'",
                [],
                |r| r.get(0),
            ),
            "row b state",
        );
        assert_eq!(
            state, "error",
            "an unrecoverable row degrades to an error result"
        );
        // A keeps its active-set row (metadata).
        let state_a: String = ok(
            conn.query_row(
                "SELECT state FROM torrent WHERE gid = '80000000000000b1'",
                [],
                |r| r.get(0),
            ),
            "row a state",
        );
        assert_eq!(state_a, "metadata");
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_file(&db);
}

/// An extreme `seed_time_min` (1e30) in config_json — the bootstrap
/// replay must not panic. Before the fix:
/// `Duration::from_secs_f64(cfg.seed_time_min * 60.0)` exceeded
/// u64::MAX seconds -> the actor task died -> every RPC answered
/// SessionClosed, and the row stayed in the store, so every restart
/// reproduced it (a persistent DoS / crash loop). After the fix: an
/// invalid seed setting is skipped (Duration::ZERO + warn) and the task
/// recovers normally.
#[tokio::test]
async fn bootstrap_survives_poisoned_seed_time_config() {
    let db = tmp_db("seed-time-poison");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let bytes = build_v2_torrent(&vec![0x5Eu8; 128 * 1024], &dead_tracker());
    let row = StoreTorrentRow {
        gid: "8000000000000e30".into(),
        name: "v2.bin".into(),
        state: "paused".into(),
        queue_pos: 1,
        dir: std::env::temp_dir().display().to_string(),
        config_json: r#"{"seed_time_min":1e30}"#.into(),
        kind: "v2".into(),
        v1_infohash: None,
        v2_infohash: None,
        is_private: false,
        metadata: Some(bytes),
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    ok(writer.upsert_torrent(row, Vec::new()).await, "seed row");
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // Restart: bootstrap loads the poisoned row (before the fix this
    // path panicked -> the actor died).
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer2.clone()));
    let mut restored = false;
    for _ in 0..100 {
        let waiting = status_list(
            &call(
                &handle,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        if waiting
            .iter()
            .any(|v| v.gid.to_string() == "8000000000000e30")
        {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        restored,
        "a poisoned seed_time_min row must be restored as waiting (must not kill the session actor)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_file(&db);
}

/// The recovery-face domain checks for a poisoned seed_ratio in
/// config_json (three rows in one test): A, a regression anchor — a
/// legal seed_ratio=2.0 recovers as-is; B, null (the existing poison
/// shape where the legacy import arm projected NaN/inf to null through
/// serde_json) — must not blow up the whole deserialization (dir kept,
/// the criterion treated as 0); C, -1.0 (finite but out of domain) —
/// the recovery consumption point's domain check skips the criterion
/// (warn + 0), dir kept. Without the checks: B's from_json fails whole
/// -> unwrap_or_default -> dir lost to "" (the destination drifts);
/// C's seed-ratio passes through, echoing "-1" (SeedCheck::build
/// silently swallows criteria <= 0).
#[tokio::test]
async fn bootstrap_domain_checks_poisoned_seed_ratio_config() {
    let db = tmp_db("seed-ratio-poison");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let bytes = build_v2_torrent(&vec![0x5Eu8; 128 * 1024], &dead_tracker());
    let mk = |gid: &str, cfg_json: &str| StoreTorrentRow {
        gid: gid.into(),
        name: "v2.bin".into(),
        state: "paused".into(),
        queue_pos: 1,
        dir: std::env::temp_dir().display().to_string(),
        config_json: cfg_json.into(),
        kind: "v2".into(),
        v1_infohash: None,
        v2_infohash: None,
        is_private: false,
        metadata: Some(bytes.clone()),
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    ok(
        writer
            .upsert_torrent(
                mk(
                    "8000000000000e31",
                    r#"{"dir":"/dl/anchor","seed_ratio":2.0}"#,
                ),
                Vec::new(),
            )
            .await,
        "anchor row",
    );
    ok(
        writer
            .upsert_torrent(
                mk(
                    "8000000000000e32",
                    r#"{"dir":"/dl/keep","seed_ratio":null}"#,
                ),
                Vec::new(),
            )
            .await,
        "null row",
    );
    ok(
        writer
            .upsert_torrent(
                mk("8000000000000e33", r#"{"dir":"/dl/neg","seed_ratio":-1.0}"#),
                Vec::new(),
            )
            .await,
        "neg row",
    );
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // Restart: bootstrap loads all three rows (a poisoned row must not
    // kill the actor and must not lose the whole config).
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer2.clone()));
    let echo_of = async |gid: &str| {
        let r = call(&handle, SessionCommand::GetOption { gid: gid.into() }).await;
        match r {
            Ok(CommandReply::Options(m)) => m,
            other => panic!("expected Options reply for {gid}, got {other:?}"),
        }
    };
    let mut restored = 0;
    for _ in 0..100 {
        let waiting = status_list(
            &call(
                &handle,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        restored = waiting
            .iter()
            .filter(|v| v.gid.to_string().starts_with("8000000000000e3"))
            .count();
        if restored == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        restored, 3,
        "all three rows (including the poisoned seed_ratio row) must be restored"
    );

    // A, the regression anchor: a legal seed_ratio recovers as-is.
    let a = echo_of("8000000000000e31").await;
    assert_eq!(a.get("seed-ratio").map(String::as_str), Some("2"));
    assert_eq!(a.get("dir").map(String::as_str), Some("/dl/anchor"));
    // B null: dir kept ("" without the check), criterion treated as 0.
    let b = echo_of("8000000000000e32").await;
    assert_eq!(
        b.get("dir").map(String::as_str),
        Some("/dl/keep"),
        "a null seed_ratio must not lose the whole config (dir must be kept)"
    );
    assert_eq!(b.get("seed-ratio").map(String::as_str), Some("0"));
    // C -1.0: an out-of-domain value skips the criterion (without the
    // check it passes through echoing "-1"), dir kept.
    let c = echo_of("8000000000000e33").await;
    assert_eq!(
        c.get("dir").map(String::as_str),
        Some("/dl/neg"),
        "an out-of-domain seed_ratio row must keep its dir"
    );
    assert_eq!(
        c.get("seed-ratio").map(String::as_str),
        Some("0"),
        "an out-of-domain seed_ratio must be restored as 0 (never passed through)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_file(&db);
}

/// Without a persistence injection, saveSession fails explicitly
/// (never pretending success).
#[tokio::test]
async fn save_session_without_persistence_fails_explicitly() {
    let (handle, join) = SessionActor::spawn();
    match call(&handle, SessionCommand::SaveSession).await {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("saveSession"), "{message}");
        }
        other => panic!("expected explicit failure, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// remove = DeleteTorrent (a row-level delete; the FK cascade is
/// covered by the store tests).
#[tokio::test]
async fn remove_deletes_torrent_row() {
    let db = tmp_db("remove");
    let dir = temp_dir("remove");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let bytes = build_v2_torrent(&vec![0xCu8; 128 * 1024], &dead_tracker());
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback 1");
        let n: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get(0),
            ),
            "row exists",
        );
        assert_eq!(n, 1);
    }
    assert_eq!(
        call(
            &handle,
            SessionCommand::Remove {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(gid))
    );
    // remove -> row deletion (SPEC §5.3 has no removed state; aria2
    // does not persist removed tasks).
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback 2");
        let n: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get(0),
            ),
            "row gone",
        );
        assert_eq!(n, 0, "remove must DeleteTorrent");
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(1), wjoin).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}
/// Full-persistence saveSession (a compatibility-method promise):
/// HTTP task rows are flushed into the store with saveSession
/// (including mirror state inside the 2s debounce window), readable
/// back from an independent connection after the checkpoint.
#[tokio::test]
async fn save_session_flushes_http_task_rows() {
    let db = temp_dir("http-savess").join("s.sqlite3");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer.clone()));
    let add = SessionCommand::AddUri {
        uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
        options: BTreeMap::from([
            (
                "dir".to_string(),
                temp_dir("http-savess").display().to_string(),
            ),
            ("pause".to_string(), "true".to_string()),
        ]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);
    match call(&handle, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession: {other:?}"),
    }
    // Read back from an independent connection: the http_task row is in
    // the store (state = the row state registered at add time).
    let conn = ok(rusqlite::Connection::open(&db), "open readback");
    let (state, url): (String, String) = conn
        .query_row(
            "SELECT state, url FROM http_task WHERE gid = ?1",
            [gid.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or_else(|e| panic!("http row readback: {e}"));
    assert_eq!(state, "paused", "add with pause = the row state paused");
    assert_eq!(url, "http://127.0.0.1:1/f.bin");
    drop(conn);
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(1), wjoin).await;
    let _ = std::fs::remove_dir_all(temp_dir("http-savess"));
}

/// Recheck completion with a progress-row read failure must still requeue.
/// Before the fix, finish_recheck's Err arm returned after the checking
/// registry had already been left at the function head — the task dropped
/// out of every queue view (queue/known_gids/resolve_gid) until restart.
/// Fault injection rides the store's own error face: torrent_progress
/// dropped from an independent connection makes the writer's
/// load_torrent_progress read fail ("no such table" -> StoreError); no
/// production seam is added.
#[tokio::test]
async fn recheck_progress_read_failure_still_requeues() {
    let db = tmp_db("recheck-read-fail");
    let dir = temp_dir("recheck-read-fail");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let bytes = build_v2_torrent(&vec![0x71u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    // Fault injection: the writer's connection is idle (a paused task, no
    // engine), so the independent connection's DROP lands deterministically;
    // the next load_torrent_progress read fails natively.
    {
        let conn = ok(rusqlite::Connection::open(&db), "open fault conn");
        ok(conn.busy_timeout(Duration::from_secs(2)), "busy timeout");
        ok(
            conn.execute("DROP TABLE torrent_progress", []),
            "drop progress table",
        );
    }
    // forceRecheck on the reserved-paused task: checking bookkeeping +
    // immediate spawn (the missing payload file makes the recheck itself
    // conclude quickly; the completion then hits the injected read fault).
    assert_eq!(
        call(
            &handle,
            SessionCommand::ForceRecheck {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(gid))
    );
    // Post-fix: the read failure degrades (bitfield write-back skipped) and
    // the lifecycle tail still runs — requeue at the head with the pause
    // intent preserved. Pre-fix: the early return stranded the task (never
    // visible in tellWaiting again).
    wait_until(async || {
        let waiting = status_list(
            &call(
                &handle,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        waiting
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Paused)
    })
    .await;
    // The row state advanced too (persist_transition executed on the same
    // unconditional tail).
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback");
        let state: String = ok(
            conn.query_row(
                "SELECT state FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get(0),
            ),
            "row state",
        );
        assert_eq!(
            state, "paused",
            "row state must still advance past checking on a read failure"
        );
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// fires, a full flush happens — the `--save-session` text export face
/// has already hit disk before shutdown (the session-text counterpart of
/// the aria2 "every SEC seconds" semantics; the reference
/// `OptionHandlerFactory.cc` default 0 = disabled). This test
/// covers the present arm of the assembly decision table (interval > 0 +
/// persistence present): the first tick comes after one full period
/// (`interval_at` pacing — bootstrap just flushed at startup, no
/// duplicate), and the 1.4s budget covers the 1s first tick plus
/// scheduling jitter. The absent arm (interval = 0 / persistence absent
/// → the arm is not assembled and suspends at zero cost) is carried
/// separately by the assembly-condition boolean face and by the
/// save_session explicit-failure-without-store face
/// (`save_session_without_persistence_fails_explicitly`).
#[tokio::test]
async fn save_session_interval_periodic_save_writes_text() {
    let db = tmp_db("save-interval");
    let dir = temp_dir("save-interval");
    let session_file = dir.join("session.txt");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        save_session: Some(session_file.clone()),
        save_session_interval_secs: 1,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    tokio::time::sleep(Duration::from_millis(1400)).await;
    assert!(
        session_file.exists(),
        "after the periodic-save beat fires, the --save-session text must be on disk"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(1), wjoin).await;
    let _ = std::fs::remove_dir_all(temp_dir("save-interval"));
    let _ = std::fs::remove_file(&db);
}
