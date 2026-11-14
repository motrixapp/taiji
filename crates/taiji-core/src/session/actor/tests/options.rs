// ---- Option face ----
// Upstream anchor mapping: docs/design/core.md

#[tokio::test]
async fn get_global_option_never_echoes_rpc_secret() {
    // Criterion 4 (core half): with a secret set, the echo must not contain rpc-secret.
    let global = GlobalOptions {
        rpc_secret: Some("super-secret-value".into()),
        ..Default::default()
    };
    let (handle, _join) = SessionActor::spawn_with(SessionOptions { global });
    match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(map)) => {
            assert!(
                !map.contains_key("rpc-secret"),
                "rpc-secret leaked: {map:?}"
            );
            assert_eq!(
                map.get("max-concurrent-downloads").map(String::as_str),
                Some("5")
            );
        }
        other => panic!("expected Options, got {other:?}"),
    }
    // changeGlobalOption: the accepted subset applies + unknown keys are ignored.
    let patch = BTreeMap::from([
        ("max-concurrent-downloads".to_string(), "2".to_string()),
        ("enable-dht".to_string(), "false".to_string()),
        ("not-a-real-option".to_string(), "x".to_string()),
    ]);
    assert_eq!(
        call(
            &handle,
            SessionCommand::ChangeGlobalOption { options: patch }
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(map)) => {
            assert_eq!(
                map.get("max-concurrent-downloads").map(String::as_str),
                Some("2")
            );
            assert_eq!(map.get("enable-dht").map(String::as_str), Some("false"));
            assert!(!map.contains_key("not-a-real-option"));
        }
        other => panic!("expected Options, got {other:?}"),
    }
}

/// changeUri: upstream file-entry semantics restored — a BT task is a no-op
/// with counts [0,0] and announceList untouched (the tracker-hijack-delete
/// regression); an out-of-range fileIndex = the upstream verbatim copy; a
/// result-domain GID = the upstream verbatim "Cannot remove URIs from
/// GID#%s"; HTTP tasks take the same no-op shape.
#[tokio::test]
async fn change_uri_upstream_file_entry_semantics() {
    let global = GlobalOptions {
        max_concurrent_downloads: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("uri");
    let bytes_a = build_v2_torrent(&vec![3u8; 128 * 1024], &dead_tracker());
    let bytes_b = build_v2_torrent_named(&vec![4u8; 128 * 1024], &dead_tracker(), "v2-b.bin");
    let a = gid_of(&call(&handle, torrent_cmd(bytes_a, &dir)).await);
    let b = gid_of(&call(&handle, torrent_cmd(bytes_b, &dir)).await);

    // Baseline announceList (a single tier = dead_tracker; waiting tasks read the jobs projection).
    let baseline = match call(
        &handle,
        SessionCommand::TellStatus {
            gid: b.to_string(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => {
            v.bittorrent
                .unwrap_or_else(|| panic!("bittorrent"))
                .announce_list
        }
        other => panic!("tellStatus failed, got {other:?}"),
    };
    assert_eq!(baseline, vec![vec![dead_tracker()]]);

    // BT task: del hits the existing tracker + add two -> a [0,0] no-op
    // (file entries keep no URI ledger — upstream removeUri never matches;
    // FileEntry.cc).
    match call(
        &handle,
        SessionCommand::ChangeUri {
            gid: b.to_string(),
            file_index: 1,
            del_uris: vec![dead_tracker()],
            add_uris: vec!["http://x/1".into(), "http://x/2".into()],
            pos: None,
        },
    )
    .await
    {
        Ok(CommandReply::UriChange { deleted, added }) => {
            assert_eq!((deleted, added), (0, 0));
        }
        other => panic!("expected UriChange, got {other:?}"),
    }

    // Regression: announceList is untouched by changeUri (zero tier mutation).
    let after = match call(
        &handle,
        SessionCommand::TellStatus {
            gid: b.to_string(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => {
            v.bittorrent
                .unwrap_or_else(|| panic!("bittorrent"))
                .announce_list
        }
        other => panic!("tellStatus failed, got {other:?}"),
    };
    assert_eq!(after, baseline);

    // fileIndex out of range (a single-file v2 torrent has 1 entry) -> the
    // upstream verbatim message (RpcMethodImpl.cc).
    match call(
        &handle,
        SessionCommand::ChangeUri {
            gid: b.to_string(),
            file_index: 2,
            del_uris: vec![],
            add_uris: vec![],
            pos: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, "fileIndex is out of range");
        }
        other => panic!("expected out-of-range error, got {other:?}"),
    }

    // HTTP task: the same no-op shape (one file entry; the live source
    // ledger lives in the driver — no source-change seam at the engine
    // face).
    let http = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".into()],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::ChangeUri {
            gid: http.to_string(),
            file_index: 1,
            del_uris: vec!["http://127.0.0.1:1/f.bin".into()],
            add_uris: vec![],
            pos: None,
        },
    )
    .await
    {
        Ok(CommandReply::UriChange { deleted, added }) => {
            assert_eq!((deleted, added), (0, 0));
        }
        other => panic!("expected UriChange, got {other:?}"),
    }

    // Result-domain GID (forceRemove on an active task lands it in the
    // result domain and out of jobs) -> the upstream verbatim
    // "Cannot remove URIs from GID#%s" (RpcMethodImpl.cc; findGroup
    // excludes terminal states, so the same miss arm applies).
    call(&handle, SessionCommand::ForceRemove { gid: a.to_string() })
        .await
        .unwrap_or_else(|e| panic!("forceRemove failed: {e}"));
    match call(
        &handle,
        SessionCommand::ChangeUri {
            gid: a.to_string(),
            file_index: 1,
            del_uris: vec![],
            add_uris: vec![],
            pos: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, format!("Cannot remove URIs from GID#{a}"));
        }
        other => panic!("expected gid-miss error, got {other:?}"),
    }

    // Fully unknown GID: the resolve face ("GID %s is not found", the
    // str2Gid-family message — the same parameter-face boundary as
    // changePosition).
    let missing = GidAllocator::new().allocate();
    match call(
        &handle,
        SessionCommand::ChangeUri {
            gid: missing.to_string(),
            file_index: 1,
            del_uris: vec![],
            add_uris: vec![],
            pos: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, format!("GID {missing} is not found"));
        }
        other => panic!("expected not-found error, got {other:?}"),
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// taiji.addTracker/removeTracker: an active task = immediate effect via
/// the SetTrackers engine coupling (dual projection: the getServers tracker
/// table + the tellStatus announceList); a waiting task = a payload edit
/// (visible in announceList); terminal / metadata-phase / HTTP tasks =
/// explicit gate rejection; delete-all = the pure DHT face (an empty
/// announceList, legal); an idempotent replay returns 0.
#[tokio::test]
async fn taiji_tracker_edit_three_states_announce_and_gates() {
    let global = GlobalOptions {
        max_concurrent_downloads: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("trk-edit");
    let bytes_a = build_v2_torrent(&vec![7u8; 128 * 1024], &dead_tracker());
    let bytes_b = build_v2_torrent_named(&vec![8u8; 128 * 1024], &dead_tracker(), "v2-b.bin");
    let a = gid_of(&call(&handle, torrent_cmd(bytes_a, &dir)).await);
    let b = gid_of(&call(&handle, torrent_cmd(bytes_b, &dir)).await);
    let builtin = dead_tracker();
    let (u1, u2, ux) = (
        "udp://trk1.example:6969/announce".to_string(),
        "http://trk2.example/announce".to_string(),
        "wss://trk-x.example/announce".to_string(),
    );

    // ---- Active task A (wait for A to appear in the engine) ----
    let mut active = false;
    for _ in 0..100 {
        let act = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
        if act.len() == 1 && act[0].gid == a {
            active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(active, "A should be the active task");

    // Default = append at the table tail (one independent tier per URL);
    // the SetTrackers engine coupling waits for the receipt — afterwards
    // both faces show it: the tellStatus announceList (jobs projection) and
    // getServers (the engine shadow table).
    match call(
        &handle,
        SessionCommand::AddTracker {
            gid: a.to_string(),
            urls: vec![u1.clone(), u2.clone()],
            position: None,
        },
    )
    .await
    {
        Ok(CommandReply::TrackerChange { removed, added }) => {
            assert_eq!((removed, added), (0, 2));
        }
        other => panic!("expected TrackerChange, got {other:?}"),
    }
    let announce_of = |gid: Gid| {
        let handle = &handle;
        async move {
            match call(
                handle,
                SessionCommand::TellStatus {
                    gid: gid.to_string(),
                    keys: vec![],
                },
            )
            .await
            {
                Ok(CommandReply::TorrentStatus(v)) => {
                    v.bittorrent
                        .unwrap_or_else(|| panic!("bittorrent"))
                        .announce_list
                }
                other => panic!("tellStatus failed, got {other:?}"),
            }
        }
    };
    assert_eq!(
        announce_of(a).await,
        vec![vec![builtin.clone()], vec![u1.clone()], vec![u2.clone()]],
        "append face: the built-in announce pre-seeds tier 0, each new URL gets its own tier"
    );
    wait_servers(&handle, &a, &[builtin.as_str(), &u1, &u2]).await;

    // position = the tier insertion point (out of range clamps to the tail; existing tiers shift).
    match call(
        &handle,
        SessionCommand::AddTracker {
            gid: a.to_string(),
            urls: vec![ux.clone()],
            position: Some(1),
        },
    )
    .await
    {
        Ok(CommandReply::TrackerChange {
            removed: 0,
            added: 1,
        }) => {}
        other => panic!("expected insert-1, got {other:?}"),
    }
    assert_eq!(
        announce_of(a).await,
        vec![
            vec![builtin.clone()],
            vec![ux.clone()],
            vec![u1.clone()],
            vec![u2.clone()],
        ],
        "position=1 inserts as tier 1, existing tiers shift down"
    );

    // removeTracker: exact-match tier deletion (the engine face is cleaned in step).
    match call(
        &handle,
        SessionCommand::RemoveTracker {
            gid: a.to_string(),
            urls: vec![u1.clone(), "http://no-such/announce".into()],
        },
    )
    .await
    {
        Ok(CommandReply::TrackerChange { removed, added }) => {
            assert_eq!(
                (removed, added),
                (1, 0),
                "a miss does not count into removed"
            );
        }
        other => panic!("expected TrackerChange, got {other:?}"),
    }
    assert_eq!(
        announce_of(a).await,
        vec![vec![builtin.clone()], vec![ux.clone()], vec![u2.clone()]],
    );
    // Engine face: the u1 row disappears with SetTrackers (poll until
    // absent — announce orchestration is asynchronous; the table-rebuild
    // receipt lands first but queries cross a bounded channel).
    let mut cleared = false;
    for _ in 0..100 {
        if let Ok(CommandReply::Servers(rows)) =
            call(&handle, SessionCommand::GetServers { gid: a.to_string() }).await
        {
            if rows.iter().all(|r| r.url != u1) {
                cleared = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        cleared,
        "the engine tracker table should no longer contain the deleted URL"
    );

    // Delete-all = the pure DHT face (an empty announceList is legal;
    // deleting again = idempotent 0).
    match call(
        &handle,
        SessionCommand::RemoveTracker {
            gid: a.to_string(),
            urls: vec![builtin.clone(), ux.clone(), u2.clone()],
        },
    )
    .await
    {
        Ok(CommandReply::TrackerChange {
            removed: 3,
            added: 0,
        }) => {}
        other => panic!("expected remove-all, got {other:?}"),
    }
    assert_eq!(
        announce_of(a).await,
        Vec::<Vec<String>>::new(),
        "empty tiers = the pure DHT face"
    );
    match call(
        &handle,
        SessionCommand::RemoveTracker {
            gid: a.to_string(),
            urls: vec![u2.clone()],
        },
    )
    .await
    {
        Ok(CommandReply::TrackerChange {
            removed: 0,
            added: 0,
        }) => {}
        other => panic!("expected idempotent 0/0, got {other:?}"),
    }

    // ---- Waiting task B (the concurrency slot is held by A; B stays in the reserved domain) ----
    match call(
        &handle,
        SessionCommand::AddTracker {
            gid: b.to_string(),
            urls: vec![u1.clone()],
            position: None,
        },
    )
    .await
    {
        Ok(CommandReply::TrackerChange {
            removed: 0,
            added: 1,
        }) => {}
        other => panic!("waiting-task edit failed, got {other:?}"),
    }
    assert_eq!(
        announce_of(b).await,
        vec![vec![builtin.clone()], vec![u1.clone()]],
        "a waiting task's payload edit is immediately visible (the tellStatus waiting-domain projection)"
    );

    // ---- Shape gates: magnet metadata phase / .torrent-URL metadata
    // phase / HTTP / terminal / unknown GID (rejected calls mutate nothing)
    // ----
    let magnet = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["magnet:?xt=urn:btih:9999999999999999999999999999999999999999".into()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    for (gid, method, want) in [
        (
            magnet.to_string(),
            "taiji.addTracker",
            "taiji.addTracker: tracker edit requires a torrent task \
                 (metadata tasks are not editable before upgrade)",
        ),
        (
            magnet.to_string(),
            "taiji.removeTracker",
            "taiji.removeTracker: tracker edit requires a torrent task \
                 (metadata tasks are not editable before upgrade)",
        ),
    ] {
        let cmd = if method == "taiji.addTracker" {
            SessionCommand::AddTracker {
                gid: gid.clone(),
                urls: vec![u2.clone()],
                position: None,
            }
        } else {
            SessionCommand::RemoveTracker {
                gid: gid.clone(),
                urls: vec![u2.clone()],
            }
        };
        match call(&handle, cmd).await {
            Err(SessionError::Failed { message }) => assert_eq!(message, want, "{method}"),
            other => panic!("{method}: expected metadata-phase reject, got {other:?}"),
        }
    }
    // .torrent-URL metadata phase (paused so the fetcher never starts — the shape stays stable).
    let turl = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/meta.torrent".into()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::AddTracker {
            gid: turl.to_string(),
            urls: vec![u2.clone()],
            position: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => assert_eq!(
            message,
            "taiji.addTracker: tracker edit requires a torrent task \
                 (metadata tasks are not editable before upgrade)"
        ),
        other => panic!("expected torrent-url metadata reject, got {other:?}"),
    }
    // HTTP task: no tracker face.
    let http = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".into()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::AddTracker {
            gid: http.to_string(),
            urls: vec![u2.clone()],
            position: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => assert_eq!(
            message,
            format!("taiji.addTracker: requires a torrent task (GID#{http})")
        ),
        other => panic!("expected http reject, got {other:?}"),
    }
    // Terminal (result domain): forceRemove lands A in the result domain
    // and out of jobs — the payload is removed and the result row is never
    // rebuilt, so an edit can never apply: explicit rejection (accepting
    // would be a disguise).
    call(&handle, SessionCommand::ForceRemove { gid: a.to_string() })
        .await
        .unwrap_or_else(|e| panic!("forceRemove failed: {e}"));
    for method in ["taiji.addTracker", "taiji.removeTracker"] {
        let cmd = if method == "taiji.addTracker" {
            SessionCommand::AddTracker {
                gid: a.to_string(),
                urls: vec![u2.clone()],
                position: None,
            }
        } else {
            SessionCommand::RemoveTracker {
                gid: a.to_string(),
                urls: vec![u2.clone()],
            }
        };
        match call(&handle, cmd).await {
            Err(SessionError::Failed { message }) => assert_eq!(
                message,
                format!(
                    "{method}: task GID#{a} is already finished \
                         (download results are not editable)"
                ),
                "{method}"
            ),
            other => panic!("{method}: expected terminal reject, got {other:?}"),
        }
    }
    // Unknown GID: the resolve face (the str2Gid-family message).
    let missing = GidAllocator::new().allocate();
    match call(
        &handle,
        SessionCommand::AddTracker {
            gid: missing.to_string(),
            urls: vec![u2.clone()],
            position: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, format!("GID {missing} is not found"));
        }
        other => panic!("expected not-found error, got {other:?}"),
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// taiji.addTracker persistence roundtrip: a waiting (paused) task's tier
/// edits -> config_json persisted -> after a restart announceList restores
/// to the edited shape (the "edits survive a restart" promise).
#[tokio::test]
async fn taiji_tracker_edit_config_roundtrip_survives_restart() {
    let db = tmp_db("trk-roundtrip");
    let dir = temp_dir("trk-roundtrip");
    let builtin = dead_tracker();
    let u1 = "udp://rt1.example:6969/announce".to_string();
    let u2 = "http://rt2.example/announce".to_string();
    // ---- Session 1: paused task + tracker edit (config_json persisted) ----
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let a = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent(&vec![9u8; 128 * 1024], &builtin),
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
        SessionCommand::AddTracker {
            gid: a.to_string(),
            urls: vec![u1.clone(), u2.clone()],
            position: None,
        },
    )
    .await
    {
        Ok(CommandReply::TrackerChange {
            removed: 0,
            added: 2,
        }) => {}
        other => panic!("expected TrackerChange, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // ---- Session 2: restart recovery (announceList = the edited table) ----
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    let mut restored = false;
    for _ in 0..100 {
        match call(
            &handle2,
            SessionCommand::TellStatus {
                gid: a.to_string(),
                keys: vec![],
            },
        )
        .await
        {
            Ok(CommandReply::TorrentStatus(v)) => {
                let list = v
                    .bittorrent
                    .unwrap_or_else(|| panic!("bittorrent"))
                    .announce_list;
                assert_eq!(
                    list,
                    vec![vec![builtin.clone()], vec![u1.clone()], vec![u2.clone()]],
                    "after restart announceList = the edited table (the config_json round trip)"
                );
                restored = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            other => panic!("tellStatus failed, got {other:?}"),
        }
    }
    assert!(restored, "a paused task should be restored across restart");
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// changeOption: a waiting task's seed-ratio edit merges into the payload
/// (Accepted); an active task takes restart semantics (requeued at the
/// front, respawned with the merged payload on reactivation); an unknown
/// GID fails explicitly (aria2 "Cannot change option for GID#%s").
#[tokio::test]
async fn change_option_subset_and_restart_semantics() {
    let global = GlobalOptions {
        max_concurrent_downloads: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("opt");
    let bytes_a = build_v2_torrent(&vec![5u8; 128 * 1024], &dead_tracker());
    let bytes_b = build_v2_torrent_named(&vec![6u8; 128 * 1024], &dead_tracker(), "v2-b.bin");
    let a = gid_of(&call(&handle, torrent_cmd(bytes_a, &dir)).await);
    let b = gid_of(&call(&handle, torrent_cmd(bytes_b, &dir)).await);

    assert_eq!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: b.to_string(),
                options: BTreeMap::from([
                    ("seed-ratio".to_string(), "3.0".to_string()),
                    ("unknown-option".to_string(), "ignored".to_string()),
                ]),
            }
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    // Active-task changeOption -> restart semantics: requeue at the front
    // and reactivate (ahead of newer tasks — restart clears paused and
    // fillup activates first).
    assert_eq!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: a.to_string(),
                options: BTreeMap::from([("seed-ratio".to_string(), "2.0".to_string())]),
            }
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    // After the restart A is active again (same GID); B still waits.
    let mut restarted = false;
    for _ in 0..200 {
        let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
        let waiting = status_list(
            &call(
                &handle,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        if active.len() == 1 && active[0].gid == a && waiting.len() == 1 && waiting[0].gid == b {
            restarted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        restarted,
        "changeOption on active task must restart in place (same GID)"
    );

    let missing = GidAllocator::new().allocate();
    assert!(matches!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: missing.to_string(),
                options: BTreeMap::new(),
            }
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// getOption echo-key declaration audit (the enforcement guard for "never
/// fabricate undeclared keys"): the full key set produced by the four Job
/// shapes + the result domain + the HTTP persistence/runtime family
/// projections is checked name by name against the options declaration
/// table (ARIA2_OPTION_NAMES union DECLARED_OPTION_DIFFS — the same
/// governance discipline as getGlobalOption's
/// `global_option_echo_keys_are_fully_declared`: a new echo key without a
/// declaration is red).
#[test]
fn get_option_echo_keys_are_fully_declared() {
    let declared = |k: &str| crate::session::options::option_name_declared(k);
    let hooks = || HookSet {
        on_download_start: Some("/hooks/start.sh".into()),
        ..HookSet::default()
    };
    let meta = crate::metainfo::Metainfo::parse(&build_v2_torrent(
        &vec![0u8; 128 * 1024],
        &dead_tracker(),
    ))
    .unwrap_or_else(|e| panic!("metainfo: {e}"));
    let tj = TorrentJob {
        metainfo: Arc::new(meta),
        tiers: Vec::new(),
        dir: PathBuf::from("/t"),
        seed: SeedPolicy::default(),
        total_len: 128 * 1024,
        attrs_top: (None, None, None),
        max_download_limit: 1,
        max_upload_limit: 2,
        hooks: Arc::new(hooks()),
        selected_files: Some(vec![0, 2]),
        file_priorities: None,
        holepunch: true,
        scheduler_policy: crate::engine::SchedulerPolicy::default(),
        disk_tier: None,
        bt_disable_dht: None,
        // BEP19 switch: the explicitly-off arm enters the echo face (a
        // default None does not echo — the declaration audit below covers
        // the taiji-only keys).
        enable_http_seeding: Some(false),
    };
    let mj = MagnetJob {
        magnet_uri: "magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into(),
        scheduler_policy: crate::engine::SchedulerPolicy::default(),
        dest: PathBuf::from("/m"),
        options: crate::magnet::MagnetOptions {
            known_private: false,
            task_trackers: None,
            holepunch: true,
            bt_save_metadata: true,
            bt_metadata_only: false,
            follow_torrent: true,
            pause_metadata: false,
            bt_load_saved_metadata: false,
            bt_peer_connection_type: Default::default(),
        },
        seed: SeedPolicy::default(),
        btih: None,
        btmh: None,
        tiers: Vec::new(),
        selected_files: Some(vec![0]),
        max_download_limit: 0,
        max_upload_limit: 0,
        hooks: Arc::new(hooks()),
        upgraded: false,
        bt_disable_dht: None,
        enable_http_seeding: None,
    };
    let hj = HttpJob {
        uris: vec!["http://a/x".into()],
        dir: PathBuf::from("/h"),
        out: Some("x.bin".into()),
        max_download_limit: 0,
        max_upload_limit: 0,
        hooks: Arc::new(hooks()),
        opts: http_task::HttpTaskOpts::default(),
        restore: None,
        mirror: None,
        cookies: Vec::new(),
        cookie_seed: Vec::new(),
        submitted: std::time::Instant::now(),
    };
    for (label, echo) in [
        (
            "torrent",
            commands::task_option_echo(Some(&Job::Torrent(Box::new(tj)))),
        ),
        (
            "magnet",
            commands::task_option_echo(Some(&Job::Magnet(Box::new(mj)))),
        ),
        (
            "torrent_url",
            commands::task_option_echo(Some(&Job::TorrentUrl {
                url: "http://a/t.torrent".into(),
                dir: PathBuf::from("/u"),
                seed: SeedPolicy::default(),
                max_download_limit: 0,
                max_upload_limit: 0,
                hooks: Arc::new(hooks()),
                select_file: Some(vec![1]),
                bt_disable_dht: None,
                enable_http_seeding: None,
            })),
        ),
        (
            "http",
            commands::task_option_echo(Some(&Job::Http(Box::new(hj)))),
        ),
    ] {
        assert!(!echo.is_empty(), "{label}: the echo face is non-empty");
        for k in echo.keys() {
            assert!(
                declared(k),
                "getOption echo key {k:?} ({label}) is not registered in the declaration table"
            );
        }
    }
    // Result-domain projection + the HTTP persistence/runtime families (the
    // default payload already covers all always-present keys; Option-slot
    // keys are audited by the shape cases above).
    let cfg = PersistedTaskConfig {
        magnet_flags: None,
        dir: "/r".into(),
        seed_ratio: 1.5,
        seed_time_min: 2.0,
        max_download_limit: 3,
        max_upload_limit: 4,
        selected_files: Some(vec![1]),
        file_priorities: None,
        ..Default::default()
    };
    for k in commands::torrent_result_option_echo(&cfg).keys() {
        assert!(
            declared(k),
            "result-domain echo key {k:?} is not registered in the declaration table"
        );
    }
    for k in commands::http_persist_option_echo(&http_task::HttpPersistConfig::default()).keys() {
        assert!(
            declared(k),
            "HTTP persist-family echo key {k:?} is not registered in the declaration table"
        );
    }
    for k in commands::http_runtime_option_echo(&http_task::HttpTaskOpts::default()).keys() {
        assert!(
            declared(k),
            "HTTP runtime-family echo key {k:?} is not registered in the declaration table"
        );
    }
}

/// getOption echoes the accepted subset: every accepted key given at add
/// echoes back with the same key and value, and reading after changeOption
/// returns the merged value. Cross-validation baseline (read-only
/// reference = the aria2-1.37.0 checkout):
/// - GetOptionRpcMethod::process (RpcMethodImpl.cc): three-domain task
/// location + the pushRequestOption string-value table shape;
/// - value form = the minimal numeric form (the existing
/// format_seed_ratio/format_minutes convention; the reference echoes the
/// add-time literal — the "1M" vs "1048576" numeric-equivalent form
/// difference is filed under the getOption diff declaration);
/// - `bt-max-peers` parses as accepted but has no per-task payload — the
/// echo face honestly omits it and never fabricates undeclared keys.
#[tokio::test]
async fn get_option_echoes_accepted_subset_across_job_shapes() {
    use taiji_store::persist::PersistWriter;
    let db = tmp_db("getopt");
    let dir = temp_dir("getopt");
    // Echo assertions compare &str (clippy unwrap_used: temp_dir is named
    // literally, so it must be UTF-8; non-UTF-8 is an environment error and
    // panics explicitly instead of unwrapping).
    let Some(dir_str) = dir.to_str() else {
        panic!("temp dir should be utf-8");
    };
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 2,
        enable_dht: false,
        enable_dht6: false,
        bt_lsd: false,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));

    // ---- Active domain (torrent task; a dead tracker keeps it active —
    // the same fixture convention as the change_option series) ----
    let a = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent(&vec![3u8; 128 * 1024], &dead_tracker()),
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("seed-ratio".to_string(), "2.5".to_string()),
                    ("seed-time".to_string(), "90".to_string()),
                    ("max-download-limit".to_string(), "1M".to_string()),
                    ("max-upload-limit".to_string(), "512K".to_string()),
                    (
                        "on-download-start".to_string(),
                        "/hooks/start.sh".to_string(),
                    ),
                    ("select-file".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    // No-tr magnet (takes the second concurrency slot and activates -> an
    // explicit Error terminal; the result-domain fixture).
    let e = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["magnet:?xt=urn:btih:2222222222222222222222222222222222222222".into()],
                options: BTreeMap::from([
                    ("seed-ratio".to_string(), "0.5".to_string()),
                    ("max-download-limit".to_string(), "64K".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let options_of = |r: &CmdResult| -> BTreeMap<String, String> {
        match r {
            Ok(CommandReply::Options(m)) => m.clone(),
            other => panic!("expected Options reply, got {other:?}"),
        }
    };
    let echo_a = options_of(&call(&handle, SessionCommand::GetOption { gid: a.to_string() }).await);
    assert_eq!(echo_a.get("dir").map(String::as_str), Some(dir_str));
    assert_eq!(echo_a.get("seed-ratio").map(String::as_str), Some("2.5"));
    assert_eq!(echo_a.get("seed-time").map(String::as_str), Some("90"));
    // Active-task rate limits = the live bucket values (activation starts
    // torrent_set at the same values — the echo face is the effective
    // face).
    assert_eq!(
        echo_a.get("max-download-limit").map(String::as_str),
        Some("1048576")
    );
    assert_eq!(
        echo_a.get("max-upload-limit").map(String::as_str),
        Some("524288")
    );
    assert_eq!(
        echo_a.get("on-download-start").map(String::as_str),
        Some("/hooks/start.sh")
    );
    assert_eq!(echo_a.get("select-file").map(String::as_str), Some("1"));
    assert!(
        !echo_a.contains_key("bt-max-peers"),
        "bt-max-peers has no per-task source of truth — never fabricated (gap ledger item 2)"
    );
    assert!(
        !echo_a.contains_key("on-download-pause"),
        "an unset hook slot key is absent by default (the same rule as the reference: undefined keys never echo)"
    );

    // ---- Reserved domain (torrent task) + changeOption merge read-back
    // (reading after changeOption = the merged value) ----
    let b = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent_named(
                    &vec![4u8; 128 * 1024],
                    &dead_tracker(),
                    "v2-b.bin",
                ),
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let echo_b0 =
        options_of(&call(&handle, SessionCommand::GetOption { gid: b.to_string() }).await);
    // Keys not given = the payload baseline projection (the global
    // fallback's effective face — a declared diff).
    assert_eq!(
        echo_b0.get("seed-ratio").map(String::as_str),
        Some("1"),
        "the minimal form of the global default 1.0 (the format_seed_ratio convention)"
    );
    assert_eq!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: b.to_string(),
                options: BTreeMap::from([
                    ("seed-ratio".to_string(), "3.0".to_string()),
                    ("max-download-limit".to_string(), "2M".to_string()),
                    ("select-file".to_string(), "1".to_string()),
                ]),
            }
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    let echo_b1 =
        options_of(&call(&handle, SessionCommand::GetOption { gid: b.to_string() }).await);
    assert_eq!(
        echo_b1.get("seed-ratio").map(String::as_str),
        Some("3"),
        "the changeOption merged value (waiting task)"
    );
    assert_eq!(
        echo_b1.get("max-download-limit").map(String::as_str),
        Some("2097152")
    );
    assert_eq!(echo_b1.get("select-file").map(String::as_str), Some("1"));

    // ---- Reserved domain (magnet task family echo) ----
    let c = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!(
                    "magnet:?xt=urn:btih:3333333333333333333333333333333333333333&tr={}",
                    dead_tracker()
                )],
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("bt-save-metadata".to_string(), "true".to_string()),
                    ("follow-torrent".to_string(), "false".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let echo_c = options_of(&call(&handle, SessionCommand::GetOption { gid: c.to_string() }).await);
    assert_eq!(
        echo_c.get("bt-save-metadata").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        echo_c.get("bt-metadata-only").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        echo_c.get("follow-torrent").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        echo_c.get("pause-metadata").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        echo_c.get("bt-load-saved-metadata").map(String::as_str),
        Some("false")
    );

    // ---- Reserved domain (HTTP task family: a full audit of the runtime +
    // persistence key sets — every key accepted at add is checked) ----
    let d = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:9/x.bin".into()],
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("out".to_string(), "go.bin".to_string()),
                    ("max-download-limit".to_string(), "128K".to_string()),
                    ("timeout".to_string(), "30".to_string()),
                    ("connect-timeout".to_string(), "15".to_string()),
                    ("max-tries".to_string(), "3".to_string()),
                    ("retry-wait".to_string(), "7".to_string()),
                    ("user-agent".to_string(), "taiji-getopt/1".to_string()),
                    ("header".to_string(), "X-A: b\nX-B: c".to_string()),
                    ("http-user".to_string(), "u1".to_string()),
                    ("http-passwd".to_string(), "p1".to_string()),
                    (
                        "all-proxy".to_string(),
                        "http://proxy.example:8080".to_string(),
                    ),
                    ("check-certificate".to_string(), "false".to_string()),
                    ("split".to_string(), "3".to_string()),
                    ("min-split-size".to_string(), "1M".to_string()),
                    ("max-connection-per-server".to_string(), "8".to_string()),
                    ("http-stall-window".to_string(), "9".to_string()),
                    ("http-scheduler".to_string(), "static".to_string()),
                    ("http-max-chunk".to_string(), "8M".to_string()),
                    ("http-protocol".to_string(), "h1".to_string()),
                    ("http2-stream-window".to_string(), "262144".to_string()),
                    ("http2-connection-window".to_string(), "1048576".to_string()),
                    ("http2-max-connections".to_string(), "4".to_string()),
                    ("http2-keep-alive-interval".to_string(), "30".to_string()),
                    ("http-batch-budget".to_string(), "24".to_string()),
                    ("ftp-user".to_string(), "fu".to_string()),
                    ("ftp-passwd".to_string(), "fp".to_string()),
                    ("ftp-ssl".to_string(), "implicit".to_string()),
                    ("ftp-reuse-connection".to_string(), "false".to_string()),
                    ("http-incomplete-suffix".to_string(), ".part".to_string()),
                    (
                        "checksum".to_string(),
                        "sha-1=1234567890abcdef1234567890abcdef12345678".to_string(),
                    ),
                    ("remote-time".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let echo_d = options_of(&call(&handle, SessionCommand::GetOption { gid: d.to_string() }).await);
    let expect_d: &[(&str, &str)] = &[
        ("out", "go.bin"),
        ("max-download-limit", "131072"),
        ("timeout", "30"),
        ("connect-timeout", "15"),
        ("max-tries", "3"),
        ("retry-wait", "7"),
        ("user-agent", "taiji-getopt/1"),
        ("header", "X-A: b\nX-B: c"),
        ("http-user", "u1"),
        ("http-passwd", "p1"),
        ("all-proxy", "http://proxy.example:8080"),
        ("check-certificate", "false"),
        ("split", "3"),
        ("min-split-size", "1048576"),
        ("max-connection-per-server", "8"),
        ("http-stall-window", "9"),
        ("http-scheduler", "static"),
        ("http-max-chunk", "8388608"),
        ("http-protocol", "h1"),
        ("http2-stream-window", "262144"),
        ("http2-connection-window", "1048576"),
        ("http2-max-connections", "4"),
        ("http2-keep-alive-interval", "30"),
        ("http-batch-budget", "24"),
        ("ftp-user", "fu"),
        ("ftp-passwd", "fp"),
        ("ftp-ssl", "implicit"),
        ("ftp-reuse-connection", "false"),
        ("http-incomplete-suffix", ".part"),
        ("checksum", "sha-1=1234567890abcdef1234567890abcdef12345678"),
        ("remote-time", "true"),
    ];
    for (k, v) in expect_d {
        assert_eq!(
            echo_d.get(*k).map(String::as_str),
            Some(*v),
            "HTTP task accepted key {k:?} echoes"
        );
    }

    // ---- Result domain (the no-tr magnet's explicit Error terminal ->
    // read back from the download_result row's config_json) ----
    let mut e_ended = false;
    for _ in 0..200 {
        let stopped = status_list(
            &call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        if stopped
            .iter()
            .any(|v| v.gid == e && v.status == StatusKind::Error)
        {
            e_ended = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(e_ended, "no-tr magnet must end with explicit Error result");
    let echo_e = options_of(&call(&handle, SessionCommand::GetOption { gid: e.to_string() }).await);
    assert_eq!(
        echo_e.get("seed-ratio").map(String::as_str),
        Some("0.5"),
        "result-row config_json read back (implementation landing: a stopped task reads the result row)"
    );
    assert_eq!(
        echo_e.get("max-download-limit").map(String::as_str),
        Some("65536")
    );
    assert_eq!(echo_e.get("dir").map(String::as_str), Some(dir_str));

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// getOption error paths and result-domain boundaries:
/// - unknown-name / illegal-GID messages verbatim against the reference
/// str2Gid family (RpcMethodImpl.cc "GID %s is not found" /
/// "Invalid GID %s" — resolve_gid is already the same shape);
/// - terminal tasks without a persisted shape -> an empty map (the result
/// table carries no option snapshot and there is no row to read — the
/// honest face; the reference's always-present `dr->option` is a declared
/// diff);
/// - a waiting-domain task that is removed leaves the GID universe (the
/// reference removes waiting items the same way — no DownloadResult) ->
/// the same str2Gid miss message.
#[tokio::test]
async fn get_option_error_faces_and_removed_result_domain() {
    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions {
            enable_dht: false,
            enable_dht6: false,
            bt_lsd: false,
            ..Default::default()
        },
    });
    let dir = temp_dir("getopt-err");
    // Error paths: verbatim messages.
    let missing = GidAllocator::new().allocate();
    match call(
        &handle,
        SessionCommand::GetOption {
            gid: missing.to_string(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, format!("GID {} is not found", missing));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    match call(&handle, SessionCommand::GetOption { gid: "xyz".into() }).await {
        Err(SessionError::Failed { message }) => assert_eq!(message, "Invalid GID xyz"),
        other => panic!("expected Failed, got {other:?}"),
    }
    // Terminal domain (no persistence): the no-tr magnet's explicit Error
    // terminal -> an honest empty map.
    let f = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["magnet:?xt=urn:btih:4444444444444444444444444444444444444444".into()],
                options: BTreeMap::from([("seed-ratio".to_string(), "0.5".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let mut f_ended = false;
    for _ in 0..200 {
        let stopped = status_list(
            &call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        if stopped
            .iter()
            .any(|v| v.gid == f && v.status == StatusKind::Error)
        {
            f_ended = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(f_ended, "no-tr magnet must end with explicit Error result");
    match call(&handle, SessionCommand::GetOption { gid: f.to_string() }).await {
        Ok(CommandReply::Options(m)) => {
            assert!(
                m.is_empty(),
                "a terminal task with no persisted shape = an empty map presented, got {m:?}"
            );
        }
        other => panic!("expected Options, got {other:?}"),
    }
    // Waiting-domain remove: the task leaves the GID universe immediately
    // (no DownloadResult — the reference removes waiting items the same
    // way), so the same str2Gid miss message applies.
    let g = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent(&vec![5u8; 128 * 1024], &dead_tracker()),
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    assert_eq!(
        call(&handle, SessionCommand::Remove { gid: g.to_string() }).await,
        Ok(CommandReply::Gid(g))
    );
    match call(&handle, SessionCommand::GetOption { gid: g.to_string() }).await {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, format!("GID {g} is not found"));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The terminal-domain HTTP half: a completed HTTP task reads back through
/// is_http -> load_http_task from the http_task row's config_json (the
/// http_persist_option_echo key set — the ".part" default suffix persisted
/// at creation and the remote-time given at addUri echo as-is; checksum
/// unset = key absent, the same rule as the reference `option->defined`).
/// Previously the result-domain case covered only magnet/torrent paths —
/// zero behavior coverage for the HTTP row read-back.
#[tokio::test]
async fn get_option_result_domain_reads_back_http_row() {
    let dir = temp_dir("getopt-http-result");
    let db = tmp_db("getopt-http-result");
    let origin = spawn_mock_origin(Arc::new(vec![9u8; 64 * 1024]), true, true, false).await;
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("opt.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("remote-time".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    wait_until(async || {
        status_list(
            &call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        )
        .iter()
        .any(|v| v.gid == gid && v.status == StatusKind::Complete)
    })
    .await;
    match call(
        &handle,
        SessionCommand::GetOption {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Options(m)) => {
            assert_eq!(
                m.get("http-incomplete-suffix"),
                Some(&".part".to_string()),
                "the creation-time persisted default suffix echoes: {m:?}"
            );
            assert_eq!(
                m.get("remote-time"),
                Some(&"true".to_string()),
                "the addUri-given persisted bool echoes: {m:?}"
            );
            assert!(
                !m.contains_key("checksum"),
                "checksum unset = the key is absent: {m:?}"
            );
        }
        other => panic!("expected Options, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// changeOption's HTTP scheduling group (option-group wiring): out-of-range
/// / illegal values are rejected explicitly before any payload merge
/// (`taiji.option.invalid` — the max-connection-per-server domain 1..=64
/// rejects without clamping); legal values merge incrementally into the
/// task payload (Accepted; effective under restart semantics).
#[test]
fn http_sched_patch_validation_matrix() {
    let opts_of = |kv: &[(&str, &str)]| {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    // Empty payload = no increments.
    let p = http_sched_patch(&opts_of(&[])).unwrap_or_else(|e| panic!("empty: {e}"));
    assert_eq!(
        (
            p.split,
            p.min_split_size,
            p.max_conn_per_server,
            p.stall_window,
            p.scheduler
        ),
        (None, None, None, None, None)
    );
    // Legal values extracted key by key.
    let p = http_sched_patch(&opts_of(&[
        ("split", "3"),
        ("min-split-size", "4M"),
        ("max-connection-per-server", "16"),
        ("http-stall-window", "9"),
        ("http-scheduler", "static"),
        ("http-max-chunk", "2M"),
    ]))
    .unwrap_or_else(|e| panic!("valid: {e}"));
    assert_eq!(p.split, Some(3));
    assert_eq!(p.min_split_size, Some(4 * 1024 * 1024));
    assert_eq!(p.max_conn_per_server, Some(16));
    assert_eq!(p.stall_window, Some(Duration::from_secs(9)));
    assert_eq!(
        p.scheduler,
        Some(taiji_http::scheduler::SchedulerMode::Static)
    );
    assert_eq!(p.max_chunk, Some(2 * 1024 * 1024));
    // Out-of-range/illegal values are rejected wholesale (no clamping, no
    // silent fallback to defaults); http-block-size is immutable per task —
    // any explicit value is rejected. The http-stall-window domain floor =
    // several heartbeat periods (STALL_WINDOW_MIN_SECS = 3s; a one-period
    // floor would let a single heartbeat jitter forge stall evidence).
    for (key, val) in [
        ("max-connection-per-server", "0"),
        ("max-connection-per-server", "65"),
        ("max-connection-per-server", "x"),
        ("split", "0"),
        ("split", "-1"),
        ("http-stall-window", "0"),
        ("http-stall-window", "1"),
        ("http-stall-window", "2"),
        ("min-split-size", "4X"),
        ("http-scheduler", "guided"),
        ("http-scheduler", "STATIC"),
        ("http-block-size", "256K"),
        ("http-block-size", "4M"),
        ("http-max-chunk", "x"),
    ] {
        assert!(
            http_sched_patch(&opts_of(&[(key, val)])).is_err(),
            "{key}={val} must be rejected"
        );
    }
    // Exactly at the domain floor: 3s (3 heartbeat periods) accepted.
    let p = http_sched_patch(&opts_of(&[("http-stall-window", "3")]))
        .unwrap_or_else(|e| panic!("floor: {e}"));
    assert_eq!(p.stall_window, Some(Duration::from_secs(3)));
}

/// `--split` value domain capped at the upper bound (1..=
/// taiji_http::scheduler::MAX_SPLIT (4096); out-of-range rejected, not
/// clamped). Why the bound: under static scheduling the first wave
/// unconditionally spawns `--split` workers per source (the WorkerPool::
/// fixed ring), so split is the task-magnification factor — without a
/// bound, 1000000 -> a million tasks and 4294967295 -> four billion tasks
/// (OOM / process death); the `as u32` truncation face (4294967296 -> 0) is
/// closed by the same gate. Creation (addUri) and changeOption increments
/// share this parser (one validation point).
#[test]
fn split_value_domain_caps_at_upper_bound() {
    // In-domain acceptance (the lower bound 1, common values, exactly the upper bound).
    for (v, want) in [("1", 1u32), ("64", 64), ("4096", 4096)] {
        match parse_split_value(v) {
            Ok(n) => assert_eq!(n, want, "--split={v} accepted in-domain"),
            Err(e) => panic!("--split={v} an in-domain value must not be rejected: {e}"),
        }
    }
    // Out-of-range rejection (the u32 truncation faces u32::MAX+1/+2 and
    // the magnification face 1000000 first — the defect shape's primary
    // evidence is truncation/magnification).
    for v in ["4294967296", "4294967297", "1000000", "4097", "0", "-1"] {
        match parse_split_value(v) {
            Err(SessionError::Failed { message }) => assert!(
                message.starts_with("taiji.option.invalid"),
                "--split={v} rejection wording: {message}"
            ),
            other => {
                panic!("--split={v} out of range must be rejected (no truncation), got {other:?}")
            }
        }
    }
    // The changeOption increment face shares the gate (same parser):
    // out-of-range rejected wholesale.
    let opts_of = |kv: &[(&str, &str)]| {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    for v in ["4097", "1000000", "4294967296"] {
        assert!(
            http_sched_patch(&opts_of(&[("split", v)])).is_err(),
            "a split={v} scheduling increment out of range must be rejected"
        );
    }
}

/// changeOption's HTTP scheduling group at the session face: a legal
/// increment on a paused task is Accepted; out-of-range values Err (the
/// session-level negative close-out).
#[tokio::test]
async fn http_change_option_sched_group_accepts_and_rejects() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-sched-opt");
    let body = Arc::new(vec![7u8; 64 * 1024]);
    let origin = spawn_mock_origin(body, true, true, false).await;
    // pause=true: the task stays ReservedPaused (changeOption's accepted
    // domain, no race with activation).
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("sched.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    // Out-of-range values are rejected explicitly.
    let result = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: std::collections::BTreeMap::from([(
                "max-connection-per-server".to_string(),
                "65".to_string(),
            )]),
        },
    )
    .await;
    assert!(
        matches!(result, Err(SessionError::Failed { .. })),
        "{result:?}"
    );
    // A legal increment is Accepted.
    assert_eq!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: gid.to_string(),
                options: std::collections::BTreeMap::from([
                    ("max-connection-per-server".to_string(), "16".to_string()),
                    ("http-stall-window".to_string(), "9".to_string()),
                    ("split".to_string(), "3".to_string()),
                    ("min-split-size".to_string(), "4M".to_string()),
                ]),
            },
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rejected changeOption calls mutate nothing + absent-key merge: a payload
/// with a persistence-family key and one out-of-range key is rejected
/// wholesale and the row's config_json must not be half-applied (pre-fix:
/// scheduling-group validation ran after the payload merge, so a rejected
/// call had already silently reset absent keys like `--checksum`); a legal
/// call merges only its present keys onto the baseline (the existing
/// checksum/suffix kept).
#[tokio::test]
async fn http_change_option_rejected_call_leaves_no_mutation() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-copt-nomut");
    let body = Arc::new(vec![7u8; 64 * 1024]);
    let origin = spawn_mock_origin(body, true, true, false).await;
    let digest = "ab".repeat(32);
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("mut.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                    ("checksum".to_string(), format!("sha-256={digest}")),
                ]),
                position: None,
            },
        )
        .await,
    );
    // No persistence in this half: the row lives only in the in-memory
    // mirror, so the row-level assertions use the persisted session below;
    // this half pins the rejection semantics itself.
    // Out-of-range key (http-block-size is immutable per task) -> Err.
    let rejected = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: std::collections::BTreeMap::from([
                ("http-block-size".to_string(), "1M".to_string()),
                ("remote-time".to_string(), "true".to_string()),
            ]),
        },
    )
    .await;
    assert!(
        matches!(rejected, Err(SessionError::Failed { .. })),
        "{rejected:?}"
    );
    // Cross-key out-of-range (max-chunk below the block granularity) -> Err.
    let rejected2 = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: std::collections::BTreeMap::from([(
                "http-max-chunk".to_string(),
                "1K".to_string(),
            )]),
        },
    )
    .await;
    assert!(
        matches!(rejected2, Err(SessionError::Failed { .. })),
        "{rejected2:?}"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);

    // ---- Persisted shape: observable row-config_json no-mutation + absent-key merge ----
    let dir2 = temp_dir("http-copt-nomut-db");
    let db = tmp_db("http-copt-nomut-db");
    let origin2 = spawn_mock_origin(Arc::new(vec![7u8; 64 * 1024]), true, true, true).await;
    let global = GlobalOptions {
        dir: dir2.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle2,
            SessionCommand::AddUri {
                uris: vec![origin2.url("f.bin")],
                options: std::collections::BTreeMap::from([(
                    "checksum".to_string(),
                    format!("sha-256={digest}"),
                )]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // Precondition: checksum persisted with the row (remote_time defaults
    // false). The row state is advanced by the driver (queued -> probing)
    // and takes no part in the mutation assertions.
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(_, cfg)| cfg.contains("sha-256"))
            .unwrap_or(false)
    })
    .await;
    let (_, cfg_before) = http_row_of(&db, &gid_hex).unwrap_or_else(|| panic!("row"));
    // Rejected call (an out-of-range key plus a legal persistence key in
    // one payload) -> zero row-payload mutation.
    let rejected = call(
        &handle2,
        SessionCommand::ChangeOption {
            gid: gid_hex.clone(),
            options: std::collections::BTreeMap::from([
                ("http-block-size".to_string(), "4M".to_string()),
                ("remote-time".to_string(), "true".to_string()),
            ]),
        },
    )
    .await;
    assert!(
        matches!(rejected, Err(SessionError::Failed { .. })),
        "{rejected:?}"
    );
    let (_, cfg_after) = http_row_of(&db, &gid_hex).unwrap_or_else(|| panic!("row"));
    assert_eq!(
        cfg_after, cfg_before,
        "the rejected call mutates nothing (the row payload byte-identical)"
    );
    // Absent-key merge: a legal call carrying only remote-time -> checksum kept.
    let accepted = call(
        &handle2,
        SessionCommand::ChangeOption {
            gid: gid_hex.clone(),
            options: std::collections::BTreeMap::from([(
                "remote-time".to_string(),
                "true".to_string(),
            )]),
        },
    )
    .await;
    assert!(
        matches!(accepted, Ok(CommandReply::Accepted)),
        "{accepted:?}"
    );
    let (_, cfg) = http_row_of(&db, &gid_hex).unwrap_or_else(|| panic!("row"));
    assert!(
        cfg.contains("sha-256") && cfg.contains("\"remote_time\":true"),
        "absent-key merge (checksum kept + remote-time written): {cfg}"
    );
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir2);
    let _ = std::fs::remove_file(&db);
}

// ---- Tracker three-layer configuration architecture ----

/// getGlobalOption echo read (await form; used directly by assertions).
async fn global_echo(handle: &SessionHandle) -> BTreeMap<String, String> {
    match call(handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(m)) => m,
        other => panic!("expected Options reply, got {other:?}"),
    }
}

/// Polls getServers until the URL set contains every wanted entry (the
/// engine tracker-table snapshot = the mirror rows after set_trackers is
/// accepted; 3s budget, fails on timeout).
async fn wait_servers(
    handle: &SessionHandle,
    gid: &Gid,
    want: &[&str],
) -> std::collections::BTreeSet<String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(CommandReply::Servers(views)) = call(
            handle,
            SessionCommand::GetServers {
                gid: gid.to_string(),
            },
        )
        .await
        {
            let urls: std::collections::BTreeSet<String> =
                views.iter().map(|v| v.url.clone()).collect();
            if want.iter().all(|w| urls.contains(*w)) {
                return urls;
            }
        }
        if Instant::now() >= deadline {
            panic!("engine tracker table did not reach {want:?} in time");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn change_global(pairs: &[(&str, &str)]) -> SessionCommand {
    SessionCommand::ChangeGlobalOption {
        options: pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    }
}

/// Three-layer merge injection (the activation face) + changeGlobalOption
/// hot reload reaching in-flight and later tasks (engine tracker-table
/// snapshot evidence) + the union-dedup echo.
#[tokio::test]
async fn global_tracker_hot_reload_reaches_running_and_later_tasks() {
    let dir = temp_dir("p62-hot");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let builtin = dead_tracker();
    let gid = gid_of(
        &call(
            &handle,
            torrent_cmd(build_v2_torrent(&vec![0x61u8; 128 * 1024], &builtin), &dir),
        )
        .await,
    );

    // Layer one (the built-in announce) on the activation face: the
    // initial table = the single built-in tier.
    let urls = wait_servers(&handle, &gid, &[builtin.as_str()]).await;
    assert_eq!(
        urls.len(),
        1,
        "with an empty global set only the built-in announce (identity merge)"
    );

    // changeGlobalOption bt-tracker imports two (whitespace/empty-segment tolerant).
    assert_eq!(
        call(
            &handle,
            change_global(&[(
                "bt-tracker",
                " udp://g1.example:6969/announce , ,udp://g2.example:1337/announce "
            )])
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    // In-flight hot push: built-in + global imports (a second tier appended, layer one prefixed).
    let urls = wait_servers(
        &handle,
        &gid,
        &[
            builtin.as_str(),
            "udp://g1.example:6969/announce",
            "udp://g2.example:1337/announce",
        ],
    )
    .await;
    assert_eq!(
        urls.len(),
        3,
        "in-flight tasks take effect = the three-layer merged effective table"
    );

    // Later tasks: the activation face merges the global set naturally.
    let gid2 = gid_of(
        &call(
            &handle,
            torrent_cmd(
                build_v2_torrent_named(&vec![0x62u8; 128 * 1024], &builtin, "v2-b.bin"),
                &dir,
            ),
        )
        .await,
    );
    let urls = wait_servers(
        &handle,
        &gid2,
        &[
            builtin.as_str(),
            "udp://g1.example:6969/announce",
            "udp://g2.example:1337/announce",
        ],
    )
    .await;
    assert_eq!(
        urls.len(),
        3,
        "later tasks take effect = merged at activation"
    );

    // Echo = the global set comma-joined (bt-tracker-file unset = an empty
    // string; the full-table shape is pinned by the session options echo
    // tests).
    let echo = global_echo(&handle).await;
    assert_eq!(
        echo.get("bt-tracker").map(String::as_str),
        Some("udp://g1.example:6969/announce,udp://g2.example:1337/announce")
    );
    assert_eq!(echo.get("bt-tracker-file").map(String::as_str), Some(""));
    assert_eq!(
        call(
            &handle,
            change_global(&[("bt-tracker", "udp://g1.example:6969/announce")])
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(m)) => {
            assert_eq!(
                m.get("bt-tracker").map(String::as_str),
                Some("udp://g1.example:6969/announce,udp://g2.example:1337/announce"),
                "union dedup: a repeated import produces no duplicate entries"
            );
        }
        other => panic!("expected Options reply, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Persistence roundtrip: CLI injection (the bt-tracker comma list + the
/// bt-tracker-file ngosang file) imports at startup into the store (table
/// order = rowid import order); after a restart the global set restores
/// (the getGlobalOption echo = the stored set).
#[tokio::test]
async fn global_tracker_roundtrip_survives_restart() {
    let db = tmp_db("p62-roundtrip");
    let dir = temp_dir("p62-roundtrip");
    // ngosang-format fixture (comment and blank lines included).
    let mut list_path = dir.clone();
    list_path.push("trackers_all.txt");
    ok(
        std::fs::write(
            &list_path,
            b"# ngosang/trackerslist fixture

udp://file.example:6969/announce
https://file2.example/announce
",
        ),
        "write fixture",
    );
    let cli_url = "udp://cli.example:1337/announce";
    // ---- Session 1: CLI-injected import -> persisted ----
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let global = GlobalOptions {
        dir: dir.clone(),
        bt_tracker: vec![cli_url.to_string()],
        bt_tracker_file: Some(list_path.clone()),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    // Bootstrap runs before the command loop: the first query already
    // sees the import (the store + file union).
    let echo = global_echo(&handle).await;
    assert_eq!(
        echo.get("bt-tracker").map(String::as_str),
        Some(
            "udp://cli.example:1337/announce,udp://file.example:6969/announce,https://file2.example/announce"
        ),
        "startup import = the CLI comma list + the file parse (union, import order)"
    );
    assert_eq!(
        echo.get("bt-tracker-file").map(String::as_str),
        Some(list_path.display().to_string().as_str()),
        "the bt-tracker-file echo = the set path"
    );
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback db");
        let mut stmt = ok(
            conn.prepare("SELECT url FROM global_tracker ORDER BY rowid"),
            "prepare global_tracker",
        );
        let rows = ok(
            stmt.query_map([], |r| r.get::<_, String>(0)),
            "query global_tracker",
        );
        let urls: Vec<String> = rows.filter_map(|r| r.ok()).collect();
        assert_eq!(
            urls,
            vec![
                cli_url.to_string(),
                "udp://file.example:6969/announce".to_string(),
                "https://file2.example/announce".to_string(),
            ],
            "the global_tracker table writes and reads consistently (rowid order = import order)"
        );
    }
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // ---- Session 2: restart with default options -> the stored set restores ----
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    let echo = global_echo(&handle2).await;
    assert_eq!(
        echo.get("bt-tracker").map(String::as_str),
        Some(
            "udp://cli.example:1337/announce,udp://file.example:6969/announce,https://file2.example/announce"
        ),
        "after restart the global set must be restored (the store's rowid order)"
    );
    assert_eq!(
        echo.get("bt-tracker-file").map(String::as_str),
        Some(""),
        "without re-setting bt-tracker-file the echo is an empty string"
    );
    // The restored set reaches later tasks (merged at activation).
    let builtin = dead_tracker();
    let gid = gid_of(
        &call(
            &handle2,
            torrent_cmd(build_v2_torrent(&vec![0x63u8; 128 * 1024], &builtin), &dir),
        )
        .await,
    );
    wait_servers(
        &handle2,
        &gid,
        &[
            builtin.as_str(),
            "udp://cli.example:1337/announce",
            "udp://file.example:6969/announce",
            "https://file2.example/announce",
        ],
    )
    .await;
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// The end-to-end half (the parser-face evidence lives in
/// bt::trackerslist::tests::import_1200_urls_under_1s_and_1mib): a
/// 1200-entry global import through the changeGlobalOption full chain
/// (union + single-transaction store write + in-flight hot push) in <1s;
/// the imported set's memory (total URL string bytes) <1MiB.
#[tokio::test]
async fn bulk_import_1200_trackers_under_1s() {
    let dir = temp_dir("p62-bulk");
    let (writer, wjoin) = ok(
        PersistWriter::spawn(tmp_db("p62-bulk")).await,
        "spawn writer",
    );
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let builtin = dead_tracker();
    let gid = gid_of(
        &call(
            &handle,
            torrent_cmd(
                build_v2_torrent_named(&vec![0x64u8; 128 * 1024], &builtin, "v2-b.bin"),
                &dir,
            ),
        )
        .await,
    );
    wait_servers(&handle, &gid, &[builtin.as_str()]).await;

    // A synthetic 1200-entry comma list (ngosang trackers_all magnitude; ~50B per entry).
    let mut comma = String::new();
    let mut want: Vec<String> = Vec::new();
    for i in 0..1200 {
        let u = format!("udp://bulk-{i}.example:6969/announce");
        want.push(u);
    }
    comma.push_str(&want.join(","));
    let bytes: usize = want.iter().map(|u| u.len()).sum();
    assert!(
        bytes < 1024 * 1024,
        "the imported set's memory (total string bytes {bytes}B) must be <1MiB"
    );
    let t0 = Instant::now();
    assert_eq!(
        call(&handle, change_global(&[("bt-tracker", comma.as_str())])).await,
        Ok(CommandReply::Accepted)
    );
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "a 1200-entry end-to-end import (union + store write + hot push) must be <1s, got {elapsed:?}"
    );
    // In-flight effect under the two-level caps: the global set caps at
    // 1024 and a single task's engine table at MAX_TRACKER_TIERS (256,
    // including the built-in slot) -> the engine reaches the builtin plus
    // the first 255 imports; the performance criterion (<1s) is unchanged.
    let per_task = crate::session::options::MAX_TRACKER_TIERS - 1; // minus the built-in slot
    let capped = &want[..per_task.min(want.len())];
    let mut want_refs: Vec<&str> = capped.iter().map(|s| s.as_str()).collect();
    want_refs.push(builtin.as_str());
    let urls = wait_servers(&handle, &gid, &want_refs).await;
    assert_eq!(
        urls.len(),
        crate::session::options::MAX_TRACKER_TIERS,
        "the engine table = the task-level tier cap (builtin + 255 imports)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Scheduler policy switch face + config_json persistence roundtrip ----

/// Unwraps a SchedulerPolicy reply.
fn policy_of(r: CmdResult) -> crate::engine::SchedulerPolicy {
    match r {
        Ok(CommandReply::SchedulerPolicy { policy }) => policy,
        other => panic!("expected SchedulerPolicy reply, got {other:?}"),
    }
}

/// Session 1 = paused registration (no engine; the session-side storage
/// path) -> the default read-back is rarest_first -> set accepted ->
/// sequential accepted + read back -> the default policy writes no
/// config_json bytes (the existing payload has zero drift) -> saveSession
/// -> kill simulation; session 2 = the bootstrap rebuild reads back
/// unchanged. Additionally, a legacy payload (config_json carrying a
/// non-default policy) injected directly into the stored row reads back
/// losslessly from the mirror after a restart (forward-compatibility
/// evidence — payload migration is not needed when wiring).
#[tokio::test]
async fn scheduler_policy_set_get_and_config_json_roundtrip() {
    let db = tmp_db("p85-policy");
    let dir = temp_dir("p85-policy");

    // ---- Session 1: register + set/get + persist ----
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent(&vec![0xC1u8; 128 * 1024], &dead_tracker()),
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );

    // Default read-back = rarest_first (zero change to the existing task face).
    assert_eq!(
        policy_of(
            call(
                &handle,
                SessionCommand::GetSchedulerPolicy {
                    gid: gid.to_string(),
                },
            )
            .await
        )
        .name(),
        "rarest_first"
    );
    // set (rarest_first) accepted (paused with no engine = the session-side
    // storage path; the activation-chain dispatch path is covered end to
    // end by scheduler_policy.rs on the engine side).
    let rarest: crate::engine::SchedulerPolicy =
        "rarest_first".parse().unwrap_or_else(|e| panic!("{e}"));
    match call(
        &handle,
        SessionCommand::SetSchedulerPolicy {
            gid: gid.to_string(),
            policy: rarest,
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("set rarest_first must be accepted, got {other:?}"),
    }
    // sequential accepted + read back unchanged.
    let seq: crate::engine::SchedulerPolicy =
        "sequential".parse().unwrap_or_else(|e| panic!("{e}"));
    match call(
        &handle,
        SessionCommand::SetSchedulerPolicy {
            gid: gid.to_string(),
            policy: seq.clone(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("sequential must be accepted, got {other:?}"),
    }
    assert_eq!(
        policy_of(
            call(
                &handle,
                SessionCommand::GetSchedulerPolicy {
                    gid: gid.to_string(),
                },
            )
            .await
        )
        .name(),
        "sequential"
    );
    match call(&handle, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession, got {other:?}"),
    }
    {
        let conn = ok(rusqlite::Connection::open(&db), "open 1");
        let (state, config_json): (String, String) = ok(
            conn.query_row(
                "SELECT state, config_json FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ),
            "row 1",
        );
        assert_eq!(state, "paused");
        assert!(
            config_json.contains(r#""policy":"sequential""#),
            "sequential lands in config_json (non-default policies persist): {config_json}"
        );
    }
    // Kill simulation: drop all handles (the shutdown close-out rewrites
    // the whole row mirror — the payload injection must run after session 1
    // has fully exited).
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    // Inject the legacy payload directly (forward compatibility: the
    // read-back chain carries a non-default policy losslessly — no payload
    // migration needed when wiring).
    {
        let conn = ok(rusqlite::Connection::open(&db), "open 1b");
        let (config_json,): (String,) = ok(
            conn.query_row(
                "SELECT config_json FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| Ok((r.get(0)?,)),
            ),
            "row 1b",
        );
        let mut cfg = PersistedTaskConfig::from_json(&config_json);
        cfg.scheduler_policy = Some(seq);
        ok(
            conn.execute(
                "UPDATE torrent SET config_json = ?1 WHERE gid = ?2",
                params![cfg.to_json(), gid.to_string()],
            ),
            "inject p86-era payload",
        );
    }

    // ---- Session 2: bootstrap rebuild -> read back unchanged (non-default policy lossless) ----
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    let policy = policy_of(
        call(
            &handle2,
            SessionCommand::GetSchedulerPolicy {
                gid: gid.to_string(),
            },
        )
        .await,
    );
    assert_eq!(
        policy.name(),
        "sequential",
        "the config_json payload policy is restored through the bootstrap mirror (roundtrip)"
    );
    drop(handle2);
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// The activation chain's tier resolution (build_engine_config ->
/// EngineConfig.disk_policy) — the config_json `disk_tier` override end to
/// end: None / an unknown name -> the throughput default tier; a legal
/// name -> the corresponding tier parameter table.
#[test]
fn build_engine_config_resolves_disk_tier_override() {
    use std::path::PathBuf;
    use std::sync::Arc;

    let content = vec![0u8; 128 * 1024];
    let raw = build_v2_torrent(&content, "http://tracker.invalid/announce");
    let meta = match crate::metainfo::Metainfo::parse(&raw) {
        Ok(m) => Arc::new(m),
        Err(e) => panic!("parse: {e}"),
    };
    let build = |tier: Option<&str>| {
        build_engine_config(
            Arc::clone(&meta),
            PathBuf::from("/dl"),
            [0u8; 20],
            SeedPolicy::default(),
            false,
            6881,
            taiji_bt::mse::CryptoPolicy::optional(),
            tier.map(str::to_string),
            true,
            taiji_bt::tracker::TrackerOptions::default(),
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .disk_policy
    };
    // None -> the throughput default tier (zero behavior change).
    assert_eq!(build(None), taiji_store::disk_policy::DiskPolicy::default());
    // Override -> the corresponding tier parameter table.
    assert_eq!(
        build(Some("hdd-sequential")),
        taiji_store::disk_policy::DiskTier::HddSequential.policy()
    );
    assert_eq!(
        build(Some("ssd-protect")),
        taiji_store::disk_policy::DiskTier::SsdProtect.policy()
    );
    // Unknown name -> falls back to the default tier (a warn is observable on the resolve side).
    assert_eq!(
        build(Some("turbo")),
        taiji_store::disk_policy::DiskPolicy::default()
    );
}

// ===== HttpTask dispatch arm =====

/// Mock HTTP origin (raw TCP; in-process, no external dependencies).
/// Behavior:
/// - `serve_range`: true = Range requests get 206 + Content-Range (the
/// probe verdict holds, segmentable); false = Range ignored, always 200
/// (the downgrade shape);
/// - `with_length`: false = 200 without Content-Length + connection-close
/// delimiting (the EOF downgrade shape);
/// - `stall`: true = hang after reading the request header without
/// answering (probe-phase stall — the active-hold face for numActive
/// measure tests).
///
/// e2e: the bt-sequential-download option's three faces (add projection /
/// echo / changeOption Reserved acceptance and Active rejection) + the
/// magnet upgrade chain.
#[tokio::test]
async fn bt_sequential_download_option_faces() {
    let db = tmp_db("s02-seq");
    let dir = temp_dir("s02-seq");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent(&vec![0x5Au8; 128 * 1024], &dead_tracker()),
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("bt-sequential-download".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();

    // add projection: the task policy = sequential (the option key is a compatibility projection).
    assert_eq!(
        policy_of(
            call(
                &handle,
                SessionCommand::GetSchedulerPolicy { gid: g.clone() }
            )
            .await
        )
        .name(),
        "sequential",
        "the add face bt-sequential-download=true projects the policy"
    );

    // changeOption Reserved: reset to false -> the policy returns to rarest_first.
    match call(
        &handle,
        SessionCommand::ChangeOption {
            gid: g.clone(),
            options: BTreeMap::from([("bt-sequential-download".to_string(), "false".to_string())]),
        },
    )
    .await
    {
        Ok(_) => {}
        other => panic!("changeOption reserved must be accepted, got {other:?}"),
    }
    assert_eq!(
        policy_of(
            call(
                &handle,
                SessionCommand::GetSchedulerPolicy { gid: g.clone() }
            )
            .await
        )
        .name(),
        "rarest_first",
        "the changeOption reset projection"
    );

    // Set true again + saveSession -> config_json carries "sequential" (the persistence face).
    let _ = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: g.clone(),
            options: BTreeMap::from([("bt-sequential-download".to_string(), "true".to_string())]),
        },
    )
    .await;
    match call(&handle, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession, got {other:?}"),
    }
    {
        let conn = ok(rusqlite::Connection::open(&db), "open 1");
        let (config_json,): (String,) = ok(
            conn.query_row(
                "SELECT config_json FROM torrent WHERE gid = ?1",
                params![g],
                |r| Ok((r.get(0)?,)),
            ),
            "row",
        );
        assert!(
            config_json.contains(r#""policy":"sequential""#),
            "sequential lands in config_json: {config_json}"
        );
    }

    // getOption echo: projected from the policy (true).
    match call(&handle, SessionCommand::GetOption { gid: g.clone() }).await {
        Ok(CommandReply::Options(m)) => {
            assert_eq!(
                m.get("bt-sequential-download").map(String::as_str),
                Some("true")
            );
        }
        other => panic!("getOption, got {other:?}"),
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_file(&db);
}

/// The multi-URI RPC entry's option face (FTP family value domains):
/// ftp-user/passwd/ssl/pasv/reuse-connection legal values accepted;
/// `--ftp-pasv=false` (active mode) and out-of-domain `--ftp-ssl` values
/// rejected at the task (taiji.option.invalid, declared-diff semantics).
#[tokio::test]
async fn ftp_option_faces_accept_and_reject_at_session_level() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("ftp-opt");
    let base = [("dir".to_string(), dir.display().to_string())];
    let add = |extra: &[(&str, &str)]| {
        let mut options: BTreeMap<String, String> = base.iter().cloned().collect();
        for (k, v) in extra {
            options.insert((*k).to_string(), (*v).to_string());
        }
        SessionCommand::AddUri {
            uris: vec!["ftp://127.0.0.1:1/f.bin".to_string()],
            options,
            position: None,
        }
    };
    // Legal values accepted (a GID reply — the task is created; nothing
    // about activation or transport dispatch).
    let accepted: &[&[(&str, &str)]] = &[
        &[("ftp-user", "u"), ("ftp-passwd", "p")],
        &[("ftp-ssl", "none")],
        &[("ftp-ssl", "auth")],
        &[("ftp-ssl", "implicit")],
        &[("ftp-pasv", "true")],
        &[("ftp-reuse-connection", "false")],
    ];
    for extra in accepted {
        let r = call(&handle, add(extra)).await;
        assert!(
            matches!(r, Ok(CommandReply::Gid(_))),
            "acceptance failed {extra:?}: {r:?}"
        );
    }
    // Value-domain rejections.
    for (extra, why) in [
        (
            &[("ftp-pasv", "false")][..],
            "active-mode PORT not implemented",
        ),
        (&[("ftp-ssl", "fast")][..], "out of the tri-state domain"),
        (&[("ftp-reuse-connection", "maybe")][..], "not a bool"),
    ] {
        let r = call(&handle, add(extra)).await;
        match r {
            Err(SessionError::Failed { message }) => assert!(
                message.starts_with("taiji.option.invalid"),
                "--{extra:?} must be value-domain-rejected ({why}): {message}"
            ),
            other => panic!("--{extra:?} must be rejected ({why}), got {other:?}"),
        }
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Option error-semantics close-out: changeOption on an HTTP task with a
/// known per-task option whose value is out of domain = wholesale rejection
/// (`taiji.option.invalid`, no clamping, no silent fallback); legal values
/// apply = the runtime family into hj.opts (consumed by restart) + dir
/// effective for non-activated tasks.
#[tokio::test]
async fn change_option_http_known_keys_reject_out_of_domain_values() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-opterr");
    let add = SessionCommand::AddUri {
        uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
        options: BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("pause".to_string(), "true".to_string()),
        ]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);
    // Known key + out-of-domain value -> rejection (the error message
    // carries the taiji.option.invalid code prefix).
    for (key, value) in [
        ("checksum", "not-a-checksum"),
        ("remote-time", "maybe"),
        ("http-incomplete-suffix", "part"),
        ("timeout", "abc"),
        ("max-tries", "-1"),
        ("ftp-ssl", "sometimes"),
        ("all-proxy", "socks5://127.0.0.1:1080"),
    ] {
        let r = call(
            &handle,
            SessionCommand::ChangeOption {
                gid: gid.to_string(),
                options: BTreeMap::from([(key.to_string(), value.to_string())]),
            },
        )
        .await;
        match r {
            Err(SessionError::Failed { message }) => {
                assert!(
                    message.starts_with("taiji.option.invalid:"),
                    "{key}={value} must be rejected with the code prefix: {message}"
                );
            }
            other => panic!("{key}={value}: expected rejection, got {other:?}"),
        }
    }
    // Unknown keys ignored as usual (the reference's "unacceptable options ignored" rule).
    let r = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: BTreeMap::from([("not-an-aria2-option".to_string(), "1".to_string())]),
        },
    )
    .await;
    assert!(matches!(r, Ok(CommandReply::Accepted)), "{r:?}");
    // Legal values apply: dir effective for non-activated tasks + the
    // runtime family into the payload (no error reply).
    let new_dir = temp_dir("http-opterr-new");
    let r = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: BTreeMap::from([
                ("dir".to_string(), new_dir.display().to_string()),
                ("timeout".to_string(), "90".to_string()),
                (
                    "checksum".to_string(),
                    format!("sha-256={}", "a".repeat(64)),
                ),
            ]),
        },
    )
    .await;
    assert!(matches!(r, Ok(CommandReply::Accepted)), "{r:?}");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&new_dir);
}

#[tokio::test]
async fn metadata_intent_is_durable_at_admission_and_survives_restart() {
    let db = tmp_db("metadata-intent");
    let dir = temp_dir("metadata-intent");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "writer");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );
    let flags = BTreeMap::from([
        ("pause".to_string(), "true".to_string()),
        ("bt-metadata-only".to_string(), "true".to_string()),
        ("bt-save-metadata".to_string(), "true".to_string()),
        ("follow-torrent".to_string(), "false".to_string()),
        ("pause-metadata".to_string(), "true".to_string()),
        ("bt-load-saved-metadata".to_string(), "true".to_string()),
    ]);
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into()],
                options: flags.clone(),
                position: None,
            },
        )
        .await,
    );
    let rows = ok(
        writer.load_torrents_at_startup().await,
        "read admitted rows",
    );
    let row = rows
        .iter()
        .find(|snapshot| snapshot.row.gid == gid.to_string())
        .unwrap_or_else(|| panic!("admitted row missing"));
    let persisted = PersistedTaskConfig::from_json(&row.row.config_json);
    assert!(
        persisted
            .magnet_flags
            .as_ref()
            .is_some_and(|flags| flags.only),
        "must be durable before the first saveSession"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(handle);
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let (writer, wjoin) = ok(
        PersistWriter::spawn(db.clone()).await,
        "writer after restart",
    );
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                ..Default::default()
            },
        },
        Some(writer.clone()),
    );
    let mut restored = None;
    for _ in 0..100 {
        if let Ok(CommandReply::Options(options)) = call(
            &handle,
            SessionCommand::GetOption {
                gid: gid.to_string(),
            },
        )
        .await
        {
            restored = Some(options);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let restored = restored.unwrap_or_else(|| panic!("metadata task not restored"));
    for (key, value) in flags.iter().filter(|(key, _)| key.as_str() != "pause") {
        assert_eq!(restored.get(key), Some(value), "{key} changed on restart");
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(handle);
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_file(db);
}
