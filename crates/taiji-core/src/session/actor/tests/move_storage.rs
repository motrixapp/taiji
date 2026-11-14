// ---- taiji.moveStorage ----

use crate::session::persist::MovePending;

/// Hex gid parse (test-side helper; Gid carries no FromStr face).
fn gid_from_hex(gid_hex: &str) -> Gid {
    Gid::from_u64(u64::from_str_radix(gid_hex, 16).unwrap_or_else(|e| panic!("hex gid: {e}")))
}

/// The waiting face contains the gid (the pause-requeue completion
/// signal from outside the actor).
async fn waiting_contains(handle: &SessionHandle, gid: Gid) -> bool {
    matches!(
        call(
            handle,
            SessionCommand::TellWaiting {
                offset: 0,
                num: 100,
                keys: Vec::new(),
            },
        )
        .await,
        Ok(CommandReply::StatusList(_))
    ) && status_list(
        &call(
            handle,
            SessionCommand::TellWaiting {
                offset: 0,
                num: 100,
                keys: Vec::new(),
            },
        )
        .await,
    )
    .iter()
    .any(|v| v.gid == gid)
}

/// HTTP waiting task with on-disk progress: the move lands the `.part`
/// at the new dir, the row flips, and the resumed download completes
/// byte-identical at the new location.
#[tokio::test]
async fn move_storage_http_waiting_part_moves_and_resumes() {
    let dir_a = temp_dir("mvst-http-a");
    let dir_b = temp_dir("mvst-http-b");
    let db = tmp_db("mvst-http");
    let body: Arc<Vec<u8>> = Arc::new((0..1024u32 * 1024).map(|i| (i % 251) as u8).collect());
    // slow = the interruptible window (32KiB chunks / 30ms spacing).
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
    let global = GlobalOptions {
        dir: dir_a.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir_a.display().to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                    ("max-connection-per-server".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // Progress lands (the row's bitmap = at least one block), then the
    // task pauses into the waiting face with the .part on disk.
    wait_until(|| async {
        http_row_progress_of(&db, &gid_hex).is_some_and(|(_state, bitmap, total_done, _)| {
            bitmap.as_deref().is_some_and(|b| !b.is_empty()) || total_done > 0
        })
    })
    .await;
    call(
        &handle,
        SessionCommand::Pause {
            gid: gid.to_string(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    wait_until(|| async { waiting_contains(&handle, gid).await }).await;
    // The .part exists at dir A before the move.
    let part_a = dir_a.join("f.bin.part");
    assert!(part_a.exists(), "part must exist before the move");
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid_hex.clone(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("moveStorage must accept, got {other:?}"),
    }
    // The move completes asynchronously: .part at B, gone from A, and
    // the row's dir flipped.
    // Condition-waited (no fixed sleep): the .part lands at B and the
    // row's dir flips in the same MoveDone consume.
    wait_until(|| async { dir_b.join("f.bin.part").exists() }).await;
    wait_until(|| async {
        http_row_dir(&db, &gid_hex).is_some_and(|d| d == dir_b.display().to_string())
    })
    .await;
    assert!(!part_a.exists(), "source part must be gone after the move");
    // Resume: the download completes at the new dir, byte-identical.
    call(
        &handle,
        SessionCommand::Unpause {
            gid: gid.to_string(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let final_b = dir_b.join("f.bin");
    wait_until(|| async { final_b.exists() }).await;
    let written = std::fs::read(&final_b).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        &written,
        body.as_slice(),
        "resumed payload is byte-identical"
    );
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

/// Active-task move: the quiesce tears the driver down (the changeOption
/// restart path), the payload moves, and the task reactivates and
/// completes at the new dir — the whole chain invisible to completion.
#[tokio::test]
async fn move_storage_http_active_quiesces_moves_reactivates() {
    let dir_a = temp_dir("mvst-act-a");
    let dir_b = temp_dir("mvst-act-b");
    let db = tmp_db("mvst-act");
    let body: Arc<Vec<u8>> = Arc::new((0..1024u32 * 1024).map(|i| (i % 197) as u8).collect());
    // slow = the interruptible window (32KiB chunks / 30ms spacing).
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
    let global = GlobalOptions {
        dir: dir_a.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("g.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir_a.display().to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                    ("max-connection-per-server".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    wait_until(|| async {
        http_row_progress_of(&db, &gid_hex).is_some_and(|(_state, bitmap, total_done, _)| {
            bitmap.as_deref().is_some_and(|b| !b.is_empty()) || total_done > 0
        })
    })
    .await;
    assert!(dir_a.join("g.bin.part").exists(), "active part on disk");
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid_hex.clone(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("active moveStorage must accept, got {other:?}"),
    }
    let final_b = dir_b.join("g.bin");
    wait_until(|| async { final_b.exists() }).await;
    let written = std::fs::read(&final_b).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        &written,
        body.as_slice(),
        "moved task completes byte-identical"
    );
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

/// BT single-file torrent: the payload file moves with the dir and the
/// row/mirror commit; the magnet family is a dir-only swap.
#[tokio::test]
async fn move_storage_torrent_waiting_moves_payload_and_row() {
    let dir_a = temp_dir("mvst-bt-a");
    let dir_b = temp_dir("mvst-bt-b");
    let db = tmp_db("mvst-bt");
    let global = GlobalOptions {
        dir: dir_a.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let bytes = build_v2_torrent(&vec![7u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir_a)).await);
    let gid_hex = gid.to_string();
    // Single-file v2 torrent: the payload root is the file name from
    // the metainfo. Write a partial payload at the old root directly
    // (a waiting task's pre-existing data — the move-if-exists face).
    let name = torrent_file_name(&db, &gid_hex);
    let payload_a = dir_a.join(&name);
    std::fs::write(&payload_a, vec![7u8; 4096]).unwrap_or_else(|e| panic!("{e:?}"));
    call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid_hex.clone(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    // Condition-waited: the journal clears + dir commits in the same
    // MoveDone consume as the payload landing.
    wait_until(|| async {
        let cfg = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
        cfg.move_pending.is_none() && cfg.dir == dir_b.display().to_string()
    })
    .await;
    assert!(dir_b.join(&name).exists(), "payload landed at B");
    assert!(!payload_a.exists(), "source payload gone");
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

/// Kill-recovery (the rename window): the journal landed and the rename
/// committed, but the process died before the row commit — bootstrap's
/// close-out finishes the bookkeeping (CommitFinished arm) and the task
/// restores at the new dir.
#[tokio::test]
async fn move_storage_journal_closeout_finishes_committed_move() {
    let dir_a = temp_dir("mvst-r1-a");
    let dir_b = temp_dir("mvst-r1-b");
    let db = tmp_db("mvst-r1");
    let bytes = build_v2_torrent(&vec![9u8; 128 * 1024], &dead_tracker());
    // Session 1: create the task + row, stop the actor, then hand-fake
    // the crash state (journal + renamed payload + stale old dir).
    {
        let global = GlobalOptions {
            dir: dir_a.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "w");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        let gid = gid_of(&call(&handle, torrent_cmd(bytes.clone(), &dir_a)).await);
        let gid_hex = gid.to_string();
        handle.shutdown().await;
        ok(writer.await, "w join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
        // The crash window: the rename committed (payload at B, source
        // gone) but the process died before the row commit — journal in
        // the row, row dir still old.
        let name = torrent_file_name(&db, &gid_hex);
        std::fs::rename(dir_a.join(&name), dir_b.join(&name)).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(!dir_a.join(&name).exists(), "source gone (rename landed)");
        let cfg_json = read_config_json(&db, &gid);
        let mut cfg = PersistedTaskConfig::from_json(&cfg_json);
        cfg.move_pending = Some(MovePending {
            from_dir: dir_a.display().to_string(),
            to_dir: dir_b.display().to_string(),
        });
        write_config_json(&db, &gid, &cfg.to_json());
    }
    // Session 2: bootstrap closes the journal out.
    {
        let global = GlobalOptions {
            dir: dir_a.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "w2");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        handle.shutdown().await;
        ok(writer.await, "w2 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a2 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    let conn = ok(rusqlite::Connection::open(&db), "db");
    let (dir_col, cfg_json): (String, String) = ok(
        conn.query_row("SELECT dir, config_json FROM torrent", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        }),
        "row",
    );
    assert_eq!(
        dir_col,
        dir_b.display().to_string(),
        "close-out commits the dir"
    );
    let cfg = PersistedTaskConfig::from_json(&cfg_json);
    assert!(cfg.move_pending.is_none(), "close-out clears the journal");
    assert_eq!(cfg.dir, dir_b.display().to_string());
}

/// Kill-recovery (the copy window): a half-copied temp sits next to the
/// destination with the source intact — the close-out redoes the copy
/// from the intact source (the fsmove idempotent-redo contract).
#[tokio::test]
async fn move_storage_journal_closeout_redoes_partial_copy() {
    let dir_a = temp_dir("mvst-r2-a");
    let dir_b = temp_dir("mvst-r2-b");
    let db = tmp_db("mvst-r2");
    let bytes = build_v2_torrent(&vec![5u8; 128 * 1024], &dead_tracker());
    let gid_hex;
    {
        let global = GlobalOptions {
            dir: dir_a.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "w");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir_a)).await);
        gid_hex = gid.to_string();
        handle.shutdown().await;
        ok(writer.await, "w join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    // The crash state: full source at A, a stale half temp at B, the
    // journal in the row.
    let name = torrent_file_name(&db, &gid_hex);
    std::fs::write(dir_a.join(&name), vec![5u8; 32 * 1024]).unwrap_or_else(|e| panic!("{e:?}"));
    std::fs::write(
        dir_b.join(format!("{name}.taiji-move-{gid_hex}.tmp")),
        vec![5u8; 1024],
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let gid = gid_from_hex(&gid_hex);
    let cfg_json = read_config_json(&db, &gid);
    let mut cfg = PersistedTaskConfig::from_json(&cfg_json);
    cfg.move_pending = Some(MovePending {
        from_dir: dir_a.display().to_string(),
        to_dir: dir_b.display().to_string(),
    });
    write_config_json(&db, &gid, &cfg.to_json());
    {
        let global = GlobalOptions {
            dir: dir_a.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "w2");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        handle.shutdown().await;
        ok(writer.await, "w2 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a2 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    let moved = std::fs::read(dir_b.join(&name)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(moved.len(), 32 * 1024, "redo copies the full source");
    assert!(!dir_a.join(&name).exists(), "source cleared after the redo");
    assert!(
        !dir_b
            .join(format!("{name}.taiji-move-{gid_hex}.tmp"))
            .exists(),
        "stale temp cleaned"
    );
}

/// The rejection face: results, unknown gids, nested targets, and
/// in-flight duplicates all refuse without touching disk.
#[tokio::test]
async fn move_storage_rejections() {
    let dir_a = temp_dir("mvst-rej-a");
    let dir_b = temp_dir("mvst-rej-b");
    let (handle, join) = SessionActor::spawn();
    // Unknown gid: resolution error first (the aria2 face).
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: GidAllocator::new().allocate().to_string(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("is not found"), "{message}");
        }
        other => panic!("unknown gid must fail resolution, got {other:?}"),
    }
    let bytes = build_v2_torrent(&vec![1u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir_a)).await);
    // Nested target: refused.
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid.to_string(),
            dir: dir_a.join("inner").display().to_string(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("nested"), "{message}");
        }
        other => panic!("nested target must refuse, got {other:?}"),
    }
    // A stopped (result) gid: refused with the changeOption wording.
    call(
        &handle,
        SessionCommand::Remove {
            gid: gid.to_string(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    wait_until(|| async {
        matches!(
            call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: 100,
                    keys: Vec::new(),
                },
            )
            .await,
            Ok(CommandReply::StatusList(_))
        ) && status_list(
            &call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: 100,
                    keys: Vec::new(),
                },
            )
            .await,
        )
        .iter()
        .any(|v| v.gid == gid)
    })
    .await;
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid.to_string(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("Cannot move storage"), "{message}");
        }
        other => panic!("result gid must refuse, got {other:?}"),
    }
    handle.shutdown().await;
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

// ---- local helpers ----

/// The http_task row's dir column (direct sqlite probe).
fn http_row_dir(db: &std::path::Path, gid_hex: &str) -> Option<String> {
    let conn = ok(rusqlite::Connection::open(db), "open db");
    conn.query_row(
        "SELECT dir FROM http_task WHERE gid = ?1",
        params![gid_hex],
        |r| r.get(0),
    )
    .ok()
}

/// The first torrent_file row's file name (the payload root source).
fn torrent_file_name(db: &std::path::Path, gid_hex: &str) -> String {
    let conn = ok(rusqlite::Connection::open(db), "open db");
    let path: String = ok(
        conn.query_row(
            "SELECT path FROM torrent_file WHERE gid = ?1 ORDER BY file_index LIMIT 1",
            params![gid_hex],
            |r| r.get(0),
        ),
        "file row",
    );
    path.rsplit('/').next().unwrap_or(&path).to_string()
}

/// config_json overwrite (the crash-state fakes).
fn write_config_json(db: &std::path::Path, gid: &Gid, json: &str) {
    let conn = ok(rusqlite::Connection::open(db), "open db");
    ok(
        conn.execute(
            "UPDATE torrent SET config_json = ?1 WHERE gid = ?2",
            params![json, gid.to_string()],
        ),
        "update",
    );
}

/// The in-flight interleaving refusals: a second moveStorage,
/// forceRecheck and changeOption(dir) all reject while the mover runs
/// (the run loop's biased select serves these commands before the
/// MoveDone event, so the window is deterministic).
#[tokio::test]
async fn move_storage_in_flight_interleavings_refuse() {
    let dir_a = temp_dir("mvst-ilv-a");
    let dir_b = temp_dir("mvst-ilv-b");
    let db = tmp_db("mvst-ilv");
    let global = GlobalOptions {
        dir: dir_a.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let bytes = build_v2_torrent(&vec![3u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir_a)).await);
    let gid_hex = gid.to_string();
    let name = torrent_file_name(&db, &gid_hex);
    std::fs::write(dir_a.join(&name), vec![3u8; 8192]).unwrap_or_else(|e| panic!("{e}"));
    let first = call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid_hex.clone(),
            dir: dir_b.display().to_string(),
        },
    )
    .await;
    assert!(matches!(first, Ok(CommandReply::Accepted)), "{first:?}");
    // Second move while the first is in flight (before MoveDone is
    // served): refused.
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid_hex.clone(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("already in flight"), "{message}");
        }
        other => panic!("duplicate move must refuse, got {other:?}"),
    }
    // forceRecheck while moving: refused (the recheck reads the payload
    // at the old dir).
    match call(
        &handle,
        SessionCommand::ForceRecheck {
            gid: gid_hex.clone(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("storage move in flight"), "{message}");
        }
        other => panic!("forceRecheck during move must refuse, got {other:?}"),
    }
    // changeOption(dir) while moving: refused (the commit is
    // authoritative for the dir).
    match call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid_hex.clone(),
            options: BTreeMap::from([("dir".to_string(), "/tmp/mvst-ilv-other".to_string())]),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("storage move in flight"), "{message}");
        }
        other => panic!("changeOption dir during move must refuse, got {other:?}"),
    }
    // The move itself still completes.
    wait_until(|| async {
        PersistedTaskConfig::from_json(&read_config_json(&db, &gid))
            .move_pending
            .is_none()
    })
    .await;
    assert!(dir_b.join(&name).exists(), "payload landed");
    handle.shutdown().await;
    ok(writer.await, "writer join");
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    );
}

/// Wording refusals: same-dir target; an ACTIVE dir-only family (an
/// unpaused magnet in its metadata fetch) must refuse the inline swap;
/// the paused magnet accepts it.
#[tokio::test]
async fn move_storage_same_dir_and_active_dir_only_refuse() {
    let dir_a = temp_dir("mvst-sd-a");
    let dir_b = temp_dir("mvst-sd-b");
    let (handle, join) = SessionActor::spawn();
    let bytes = build_v2_torrent(&vec![2u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir_a)).await);
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: gid.to_string(),
            dir: dir_a.display().to_string(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.contains("target equals the current dir"),
                "{message}"
            );
        }
        other => panic!("same-dir move must refuse, got {other:?}"),
    }
    // Active magnet (metadata fetch under way, dead tracker): the
    // dir-only fast path must not run under a live engine.
    let magnet_uri = format!(
        "magnet:?xt=urn:btih:6666666666666666666666666666666666666666&tr={}",
        dead_tracker()
    );
    let active = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![magnet_uri],
                options: BTreeMap::from([("dir".to_string(), dir_a.display().to_string())]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: active.to_string(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("task is active"), "{message}");
        }
        other => panic!("active dir-only move must refuse, got {other:?}"),
    }
    // Paused magnet: the waiting-face dir-only swap accepts.
    let paused = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![
                    "magnet:?xt=urn:btih:5555555555555555555555555555555555555555".to_string(),
                ],
                options: BTreeMap::from([
                    ("dir".to_string(), dir_a.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: paused.to_string(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("paused magnet dir swap must accept, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    );
}

/// HTTP-face crash close-out (the torrent r1 twin): journal landed in
/// the http row, the .part already renamed to the new dir, the process
/// died before the row commit — bootstrap's close-out commits the row.
#[tokio::test]
async fn move_storage_http_journal_closeout_commits_dir() {
    let dir_a = temp_dir("mvst-rh-a");
    let dir_b = temp_dir("mvst-rh-b");
    let db = tmp_db("mvst-rh");
    let body: Arc<Vec<u8>> = Arc::new((0..1024u32 * 1024).map(|i| (i % 211) as u8).collect());
    // slow = the interruptible window (32KiB chunks / 30ms spacing).
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
    let gid_hex;
    {
        let global = GlobalOptions {
            dir: dir_a.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "w");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        let gid = gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![origin.url("h.bin")],
                    options: BTreeMap::from([
                        ("dir".to_string(), dir_a.display().to_string()),
                        ("http-block-size".to_string(), "256K".to_string()),
                        ("max-connection-per-server".to_string(), "1".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        );
        gid_hex = gid.to_string();
        wait_until(|| async {
            http_row_progress_of(&db, &gid_hex).is_some_and(|(_s, bitmap, done, _)| {
                bitmap.as_deref().is_some_and(|b| !b.is_empty()) || done > 0
            })
        })
        .await;
        call(
            &handle,
            SessionCommand::Pause {
                gid: gid_hex.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
        wait_until(|| async { waiting_contains(&handle, gid).await }).await;
        assert!(
            dir_a.join("h.bin.part").exists(),
            "paused mid-download: the .part must be on disk (completion raced the pause)"
        );
        handle.shutdown().await;
        ok(writer.await, "w join");
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a join",
        );
    }
    // The crash window: rename the .part to B by hand, journal the row,
    // keep row dir at A.
    std::fs::rename(dir_a.join("h.bin.part"), dir_b.join("h.bin.part"))
        .unwrap_or_else(|e| panic!("{e}"));
    let conn = ok(rusqlite::Connection::open(&db), "db");
    let config_json: String = ok(
        conn.query_row(
            "SELECT config_json FROM http_task WHERE gid = ?1",
            params![gid_hex],
            |r| r.get(0),
        ),
        "row",
    );
    let mut cfg = http_task::HttpPersistConfig::from_json(&config_json);
    cfg.move_pending = Some(MovePending {
        from_dir: dir_a.display().to_string(),
        to_dir: dir_b.display().to_string(),
    });
    ok(
        conn.execute(
            "UPDATE http_task SET config_json = ?1 WHERE gid = ?2",
            params![cfg.to_json(), gid_hex],
        ),
        "journal write",
    );
    {
        let global = GlobalOptions {
            dir: dir_a.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "w2");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        handle.shutdown().await;
        ok(writer.await, "w2 join");
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a2 join",
        );
    }
    let row_dir = http_row_dir(&db, &gid_hex).unwrap_or_else(|| panic!("row present"));
    assert_eq!(
        row_dir,
        dir_b.display().to_string(),
        "close-out commits the dir"
    );
    let conn = ok(rusqlite::Connection::open(&db), "db2");
    let config_json: String = ok(
        conn.query_row(
            "SELECT config_json FROM http_task WHERE gid = ?1",
            params![gid_hex],
            |r| r.get(0),
        ),
        "row2",
    );
    assert!(
        http_task::HttpPersistConfig::from_json(&config_json)
            .move_pending
            .is_none(),
        "close-out clears the journal"
    );
    assert!(dir_b.join("h.bin.part").exists(), "part stays at B");
}
