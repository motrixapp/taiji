/// taiji.renameFile domain tests (the move_storage discipline applied
/// to one file's path): waiting-face journal → fenced rename → row
/// commit, the rejection table, restart replay, and the crash
/// close-out. The multi-file fixture is the shared
/// `multi_file_v1_torrent_with_pad` (3 real files + 1 BEP47 pad,
/// wire paths `part0.bin` / `.pad/16384` / `part1.bin` / `part2.bin`
/// under the `name` root).
use crate::session::persist::RenamePending;

/// The waiting face end-to-end: journal → on-disk rename → metainfo
/// view swap → torrent_file row + config_json commit; the GetFiles
/// echo follows the new wire path.
#[tokio::test]
async fn rename_file_waiting_moves_payload_and_row() {
    let dir = temp_dir("rn-wait");
    let db = tmp_db("rn-wait");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: multi_file_v1_torrent_with_pad(&dead_tracker(), "rn-wait"),
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();
    // A partial payload at the wire path under the multi-file root.
    let root = dir.join("rn-wait");
    std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("{e:?}"));
    std::fs::write(root.join("part0.bin"), vec![1u8; 4096]).unwrap_or_else(|e| panic!("{e:?}"));
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: g.clone(),
            old_path: "part0.bin".into(),
            new_path: "renamed-0.bin".into(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("waiting renameFile must accept, got {other:?}"),
    }
    // Condition-waited: the commit clears the journal and records the
    // durable map entry in the same row upsert.
    wait_until(|| async {
        let cfg = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
        cfg.rename_pending.is_none()
            && cfg
                .file_renames
                .get(&0)
                .is_some_and(|p| p == &PathBuf::from("renamed-0.bin"))
    })
    .await;
    assert!(
        root.join("renamed-0.bin").exists(),
        "payload landed at the renamed path"
    );
    assert!(!root.join("part0.bin").exists(), "source payload gone");
    // GetFiles echo (paths are dir-joined absolute faces — the wire
    // view resolves through resolve_file_paths): file 1 carries the
    // new path; the other files are untouched (the wire coordinate
    // system never flattens — no display drift for untouched files).
    let files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        files[0].path,
        dir.join("renamed-0.bin").display().to_string(),
        "view follows the rename"
    );
    assert_eq!(
        files[2].path,
        dir.join("part1.bin").display().to_string(),
        "untouched file unchanged"
    );
    assert_eq!(
        files[3].path,
        dir.join("part2.bin").display().to_string(),
        "untouched file unchanged"
    );
    // The row projection: torrent_file.path follows the view.
    let conn = ok(rusqlite::Connection::open(&db), "db");
    let row_path: String = ok(
        conn.query_row(
            "SELECT path FROM torrent_file WHERE gid = ?1 AND file_index = 0",
            params![g],
            |r| r.get(0),
        ),
        "file row",
    );
    assert_eq!(row_path, "renamed-0.bin", "row path follows the view");
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

/// The client faces of getFiles are dir-joined absolute paths — the
/// rename face accepts them back (strip-the-dir), and the target may
/// move across subdirectories inside the payload root (the qB
/// leaf-name face's superset).
#[tokio::test]
async fn rename_file_absolute_input_and_subdir_move() {
    let dir = temp_dir("rn-abs");
    let db = tmp_db("rn-abs");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: multi_file_v1_torrent_with_pad(&dead_tracker(), "rn-abs"),
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();
    let root = dir.join("rn-abs");
    std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("{e:?}"));
    std::fs::write(root.join("part2.bin"), vec![3u8; 1024]).unwrap_or_else(|e| panic!("{e:?}"));
    // oldPath = the absolute dir-joined face getFiles hands back (the
    // wire path under the dir); newPath = an absolute face under the
    // same dir with a new subdirectory.
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: g.clone(),
            old_path: dir.join("part2.bin").display().to_string(),
            new_path: dir.join("moved/part-2.bin").display().to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("absolute-face renameFile must accept, got {other:?}"),
    }
    wait_until(|| async { root.join("moved/part-2.bin").exists() }).await;
    assert!(
        !root.join("part2.bin").exists(),
        "source gone after the subdir move"
    );
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

/// The rejection face: unknown wire paths, pad files, unsafe targets
/// (`..` escapes, absolute outsiders), in-use and overlapping targets,
/// non-torrent families, and unknown gids — all refuse without
/// touching disk; renaming onto the current path is the idempotent
/// success (the qB/libtorrent settled-rename face).
#[tokio::test]
async fn rename_file_rejections() {
    let dir = temp_dir("rn-rej");
    let db = tmp_db("rn-rej");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: multi_file_v1_torrent_with_pad(&dead_tracker(), "rn-rej"),
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();
    let root = dir.join("rn-rej");
    std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("{e:?}"));
    std::fs::write(root.join("part0.bin"), vec![1u8; 512]).unwrap_or_else(|e| panic!("{e:?}"));

    let cases: Vec<(&str, &str, &str)> = vec![
        ("no-such.bin", "x.bin", "no file matches path 'no-such.bin'"),
        // Pad entries are BEP47 placeholders, not files.
        (".pad/16384", "x.bin", "no file matches path '.pad/16384'"),
        // Escapes reject on the safety face.
        ("part0.bin", "../escape.bin", "unsafe path"),
        ("part0.bin", "/etc/evil.bin", "outside the task dir"),
        // Collision faces.
        ("part0.bin", "part1.bin", "target path already in use"),
    ];
    for (old, new, needle) in cases {
        let message = match call(
            &handle,
            SessionCommand::RenameFile {
                gid: g.clone(),
                old_path: old.to_string(),
                new_path: new.to_string(),
            },
        )
        .await
        {
            Err(SessionError::Failed { message }) => message,
            Ok(r) => panic!("{old} -> {new} must reject, got {r:?}"),
            Err(e) => panic!("{old} -> {new} must reject as Failed, got {e:?}"),
        };
        assert!(message.contains(needle), "{old} -> {new}: {message}");
    }
    // The overlap faces need a nested sibling first: park part1.bin
    // under "d/", then both nesting directions around it refuse.
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: g.clone(),
            old_path: "part1.bin".into(),
            new_path: "d/part1.bin".into(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("nesting renameFile must accept, got {other:?}"),
    }
    wait_until(|| async {
        let cfg = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
        cfg.rename_pending.is_none()
            && cfg
                .file_renames
                .get(&2)
                .is_some_and(|p| p == &PathBuf::from("d/part1.bin"))
    })
    .await;
    for (old, new) in [("part0.bin", "d"), ("part0.bin", "d/part1.bin/x")] {
        let message = match call(
            &handle,
            SessionCommand::RenameFile {
                gid: g.clone(),
                old_path: old.to_string(),
                new_path: new.to_string(),
            },
        )
        .await
        {
            Err(SessionError::Failed { message }) => message,
            Ok(r) => panic!("{old} -> {new} must reject, got {r:?}"),
            Err(e) => panic!("{old} -> {new} must reject as Failed, got {e:?}"),
        };
        assert!(
            message.contains("target path overlaps another file path"),
            "{old} -> {new}: {message}"
        );
    }
    // The idempotent face: the current path is a settled rename.
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: g.clone(),
            old_path: "part0.bin".into(),
            new_path: "part0.bin".into(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("same-path renameFile must accept, got {other:?}"),
    }
    assert!(
        root.join("part0.bin").exists(),
        "idempotent rename never touches disk"
    );
    // Non-torrent family: a magnet task rejects on the family face.
    let magnet = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![
                    "magnet:?xt=urn:btih:1111111111111111111111111111111111111111".to_string(),
                ],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: magnet.to_string(),
            old_path: "a".into(),
            new_path: "b".into(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("Cannot rename file"), "{message}");
        }
        other => panic!("magnet renameFile must reject, got {other:?}"),
    }
    // Unknown gid: the resolve face precedes everything.
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: "deadbeef".into(),
            old_path: "a".into(),
            new_path: "b".into(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("is not found"), "{message}");
        }
        other => panic!("unknown gid must fail resolution, got {other:?}"),
    }
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

/// Restart replay: the durable `file_renames` map re-applies onto the
/// freshly parsed metainfo (identity untouched — the row's metadata
/// BLOB and infohash columns never move), and a second rename on the
/// restored task works on the restored coordinate system.
#[tokio::test]
async fn rename_file_persists_across_restart() {
    let dir = temp_dir("rn-restart");
    let db = tmp_db("rn-restart");
    let bytes = multi_file_v1_torrent_with_pad(&dead_tracker(), "rn-restart");
    let gid;
    {
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn w1");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        gid = gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes,
                    options: BTreeMap::from([
                        ("dir".to_string(), dir.display().to_string()),
                        ("pause".to_string(), "true".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        );
        match call(
            &handle,
            SessionCommand::RenameFile {
                gid: gid.to_string(),
                old_path: "part0.bin".into(),
                new_path: "first-rename.bin".into(),
            },
        )
        .await
        {
            Ok(CommandReply::Accepted) => {}
            other => panic!("renameFile must accept, got {other:?}"),
        }
        wait_until(|| async {
            PersistedTaskConfig::from_json(&read_config_json(&db, &gid))
                .rename_pending
                .is_none()
        })
        .await;
        handle.shutdown().await;
        ok(writer.await, "w1 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a1 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    // Session 2: the restored view carries the rename.
    {
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn w2");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        let files = files_of(
            &call(
                &handle,
                SessionCommand::GetFiles {
                    gid: gid.to_string(),
                },
            )
            .await,
        );
        assert_eq!(
            files[0].path,
            dir.join("first-rename.bin").display().to_string(),
            "restart replays renames"
        );
        // A second rename on the restored coordinate system: the old
        // face is the restored path.
        match call(
            &handle,
            SessionCommand::RenameFile {
                gid: gid.to_string(),
                old_path: "first-rename.bin".into(),
                new_path: "second-rename.bin".into(),
            },
        )
        .await
        {
            Ok(CommandReply::Accepted) => {}
            other => panic!("second renameFile must accept, got {other:?}"),
        }
        wait_until(|| async {
            let cfg = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
            cfg.file_renames
                .get(&0)
                .is_some_and(|p| p == &PathBuf::from("second-rename.bin"))
        })
        .await;
        let files = files_of(
            &call(
                &handle,
                SessionCommand::GetFiles {
                    gid: gid.to_string(),
                },
            )
            .await,
        );
        assert_eq!(
            files[0].path,
            dir.join("second-rename.bin").display().to_string(),
            "echo follows the second rename"
        );
        // Identity never moved across both renames and the restart.
        let conn = ok(rusqlite::Connection::open(&db), "db");
        let v1: Option<Vec<u8>> = ok(
            conn.query_row(
                "SELECT v1_infohash FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get(0),
            ),
            "infohash",
        );
        assert!(v1.is_some_and(|h| h.len() == 20), "infohash column intact");
        handle.shutdown().await;
        ok(writer.await, "w2 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a2 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
}

/// Kill-recovery: the journal landed and the on-disk rename committed,
/// but the process died before the row commit — bootstrap's close-out
/// finishes the bookkeeping (idempotent redo + map record + journal
/// clear) and the restored view carries the rename. The mirrored
/// crash window — journal landed, rename not yet fired — redoes the
/// disk move the same way (the never-settled arm of the idempotent
/// face).
#[tokio::test]
async fn rename_file_journal_closeout_redoes_and_commits() {
    let dir = temp_dir("rn-crash");
    let db = tmp_db("rn-crash");
    let bytes = multi_file_v1_torrent_with_pad(&dead_tracker(), "rn-crash");
    let gid;
    {
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn w1");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        gid = gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes,
                    options: BTreeMap::from([
                        ("dir".to_string(), dir.display().to_string()),
                        ("pause".to_string(), "true".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        );
        handle.shutdown().await;
        ok(writer.await, "w1 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a1 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    // The crash window: the journal landed, the rename never fired —
    // the payload still sits at the old path.
    let root = dir.join("rn-crash");
    std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("{e:?}"));
    std::fs::write(root.join("part1.bin"), vec![2u8; 2048]).unwrap_or_else(|e| panic!("{e:?}"));
    let mut cfg = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
    cfg.rename_pending = Some(RenamePending {
        index: 2,
        new_path: PathBuf::from("crash-recovered.bin"),
        from_disk: root.join("part1.bin").display().to_string(),
        to_disk: root.join("crash-recovered.bin").display().to_string(),
    });
    write_config_json(&db, &gid, &cfg.to_json());
    // Session 2: bootstrap's close-out redoes the rename and commits.
    {
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn w2");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        wait_until(|| async { root.join("crash-recovered.bin").exists() }).await;
        assert!(
            !root.join("part1.bin").exists(),
            "close-out redoes the disk rename"
        );
        let cfg = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
        assert!(cfg.rename_pending.is_none(), "close-out clears the journal");
        assert!(
            cfg.file_renames
                .get(&2)
                .is_some_and(|p| p == &PathBuf::from("crash-recovered.bin")),
            "close-out records the durable map entry"
        );
        let files = files_of(
            &call(
                &handle,
                SessionCommand::GetFiles {
                    gid: gid.to_string(),
                },
            )
            .await,
        );
        assert_eq!(
            files[2].path,
            dir.join("crash-recovered.bin").display().to_string(),
            "restored view carries the close-out rename"
        );
        handle.shutdown().await;
        ok(writer.await, "w2 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a2 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
}

/// Cross-family composition: a renamed task still moves cleanly — the
/// move's payload-root derivation (`metainfo.name`, untouched by a
/// file rename) walks the whole root to the new dir with the renamed
/// file inside, and the restored view keeps both facts.
#[tokio::test]
async fn rename_file_then_move_storage_composes() {
    let dir_a = temp_dir("rn-x-a");
    let dir_b = temp_dir("rn-x-b");
    let db = tmp_db("rn-x");
    let global = GlobalOptions {
        dir: dir_a.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: multi_file_v1_torrent_with_pad(&dead_tracker(), "rn-x"),
                options: BTreeMap::from([
                    ("dir".to_string(), dir_a.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();
    let root = dir_a.join("rn-x");
    std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("{e:?}"));
    std::fs::write(root.join("part0.bin"), vec![1u8; 256]).unwrap_or_else(|e| panic!("{e:?}"));
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: g.clone(),
            old_path: "part0.bin".into(),
            new_path: "renamed.bin".into(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("renameFile must accept, got {other:?}"),
    }
    wait_until(|| async {
        PersistedTaskConfig::from_json(&read_config_json(&db, &gid))
            .rename_pending
            .is_none()
    })
    .await;
    assert!(root.join("renamed.bin").exists(), "rename settled");
    // Then move the whole payload: the root subtree (with the renamed
    // file) lands at B.
    call(
        &handle,
        SessionCommand::MoveStorage {
            gid: g.clone(),
            dir: dir_b.display().to_string(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let moved = dir_b.join("rn-x/renamed.bin");
    wait_until(|| async { moved.exists() }).await;
    let files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        files[0].path,
        dir_b.join("renamed.bin").display().to_string(),
        "view keeps the rename after the move"
    );
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}
