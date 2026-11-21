/// changeUri domain tests (the real ledger faces): the BT webseed
/// ledger (edit + echo + persist + restart replay), the HTTP source
/// list (edit + row sync + restart restore), and the active-task
/// quiesce round-trip.
use crate::session::persist::PersistedTaskConfig;

/// BT face: waiting-task edits persist as the authoritative ledger,
/// echo through getUris/getFiles, replay across a restart, and the
/// admission gate refuses non-http(s) additions without counting.
#[tokio::test]
async fn change_uri_bt_ledger_edit_persist_and_restart() {
    let dir = temp_dir("cu-bt");
    let db = tmp_db("cu-bt");
    let bytes = multi_file_v1_torrent_with_pad(&dead_tracker(), "cu-bt");
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
        let g = gid.to_string();
        // Add two at position 0 (sequential inserts land in order) +
        // one refused scheme (not counted).
        match call(
            &handle,
            SessionCommand::ChangeUri {
                gid: g.clone(),
                file_index: 1,
                del_uris: vec![],
                add_uris: vec![
                    "http://w1.example/seed".into(),
                    "https://w2.example/seed".into(),
                    "ftp://refused-not-a-webseed/".into(),
                ],
                pos: Some(0),
            },
        )
        .await
        {
            Ok(CommandReply::UriChange { deleted, added }) => {
                assert_eq!((deleted, added), (0, 2), "two admitted, ftp refused");
            }
            other => panic!("changeUri must accept, got {other:?}"),
        }
        // Ledger order: position-0 inserts land in order at the head.
        match call(&handle, SessionCommand::GetUris { gid: g.clone() }).await {
            Ok(CommandReply::Uris(entries)) => {
                let urls: Vec<&str> = entries.iter().map(|e| e.uri.as_str()).collect();
                assert_eq!(
                    urls,
                    vec!["http://w1.example/seed", "https://w2.example/seed"]
                );
                assert!(
                    entries.iter().all(|e| e.status == UriStatus::Waiting),
                    "never-activated = all waiting"
                );
            }
            other => panic!("expected Uris, got {other:?}"),
        }
        // getFiles echoes the same task-level ledger on every file (the
        // declared qB/libtorrent shape).
        let files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
        assert_eq!(files.len(), 4);
        for file in &files {
            assert_eq!(file.uris.len(), 2, "every file carries the ledger");
        }
        // del one (exact match, one per entry) -> [1, 0]; a repeated del
        // that matches nothing counts 0.
        match call(
            &handle,
            SessionCommand::ChangeUri {
                gid: g.clone(),
                file_index: 2,
                del_uris: vec!["http://w1.example/seed".into()],
                add_uris: vec![],
                pos: None,
            },
        )
        .await
        {
            Ok(CommandReply::UriChange { deleted, added }) => {
                assert_eq!((deleted, added), (1, 0));
            }
            other => panic!("changeUri del must accept, got {other:?}"),
        }
        // config_json carries the authoritative post-edit ledger.
        let cfg = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
        assert_eq!(
            cfg.webseeds,
            Some(vec!["https://w2.example/seed".to_string()]),
            "the edited ledger persists"
        );
        handle.shutdown().await;
        ok(writer.await, "w1 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a1 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    // Session 2: the ledger replays.
    {
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn w2");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        match call(
            &handle,
            SessionCommand::GetUris {
                gid: gid.to_string(),
            },
        )
        .await
        {
            Ok(CommandReply::Uris(entries)) => {
                let urls: Vec<&str> = entries.iter().map(|e| e.uri.as_str()).collect();
                assert_eq!(urls, vec!["https://w2.example/seed"], "restart replays");
            }
            other => panic!("expected Uris, got {other:?}"),
        }
        handle.shutdown().await;
        ok(writer.await, "w2 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a2 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
}

/// HTTP face: waiting-task edits rewrite the source list, the row's
/// url/mirrors_json follow, and a restart restores the edited set.
#[tokio::test]
async fn change_uri_http_source_edit_row_sync_and_restart() {
    let dir = temp_dir("cu-http");
    let db = tmp_db("cu-http");
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
                SessionCommand::AddUri {
                    uris: vec![
                        "http://127.0.0.1:9/first.bin".into(),
                        "http://127.0.0.1:9/second.bin".into(),
                    ],
                    options: BTreeMap::from([
                        ("dir".to_string(), dir.display().to_string()),
                        ("pause".to_string(), "true".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        );
        // Replace the first source with a new one: [1, 1].
        match call(
            &handle,
            SessionCommand::ChangeUri {
                gid: gid.to_string(),
                file_index: 1,
                del_uris: vec!["http://127.0.0.1:9/first.bin".into()],
                add_uris: vec!["http://127.0.0.1:9/third.bin".into()],
                pos: None,
            },
        )
        .await
        {
            Ok(CommandReply::UriChange { deleted, added }) => {
                assert_eq!((deleted, added), (1, 1));
            }
            other => panic!("changeUri must accept, got {other:?}"),
        }
        // The row follows: url = the new first source, mirrors_json =
        // the new manifest.
        let conn = ok(rusqlite::Connection::open(&db), "db");
        let (row_url, mirrors): (String, Option<String>) = ok(
            conn.query_row(
                "SELECT url, mirrors_json FROM http_task WHERE gid = ?1",
                params![gid.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ),
            "http row",
        );
        assert_eq!(
            row_url, "http://127.0.0.1:9/second.bin",
            "row url = the new first source"
        );
        let manifest: Vec<String> = mirrors
            .as_deref()
            .and_then(|m| serde_json::from_str::<Vec<serde_json::Value>>(m).ok())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.get("url").and_then(|u| u.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let urls: Vec<&str> = manifest.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "http://127.0.0.1:9/second.bin",
                "http://127.0.0.1:9/third.bin"
            ],
            "mirrors manifest follows the edit"
        );
        handle.shutdown().await;
        ok(writer.await, "w1 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a1 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    // Session 2: the edited set restores.
    {
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn w2");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        match call(
            &handle,
            SessionCommand::GetUris {
                gid: gid.to_string(),
            },
        )
        .await
        {
            Ok(CommandReply::Uris(entries)) => {
                let urls: Vec<&str> = entries.iter().map(|e| e.uri.as_str()).collect();
                assert_eq!(
                    urls,
                    vec![
                        "http://127.0.0.1:9/second.bin",
                        "http://127.0.0.1:9/third.bin"
                    ],
                    "restart restores the edited source set"
                );
            }
            other => panic!("expected Uris, got {other:?}"),
        }
        handle.shutdown().await;
        ok(writer.await, "w2 join");
        ok(
            tokio::time::timeout(Duration::from_secs(5), join).await,
            "a2 join",
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
}

/// BT active face: the edit rides the changeOption restart path — the
/// task quiesces, re-activates at the front, and the URI face flips
/// to "used" (the engine attached the set).
#[tokio::test]
async fn change_uri_bt_active_edit_reactivates() {
    let dir = temp_dir("cu-act");
    let db = tmp_db("cu-act");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    // pause=true intake then unpause -> the task activates (dead
    // tracker keeps it resident-active with no peers).
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent(&vec![5u8; 128 * 1024], &dead_tracker()),
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    call(
        &handle,
        SessionCommand::Unpause {
            gid: gid.to_string(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("unpause: {e:?}"));
    let g = gid.to_string();
    wait_until(|| async {
        matches!(
            call(&handle, SessionCommand::TellStatus { gid: g.clone(), keys: vec![] }).await,
            Ok(CommandReply::TorrentStatus(v)) if v.status == StatusKind::Active
        )
    })
    .await;
    // Edit while running: accepted, and the task returns to active
    // (quiesce -> requeue at the front -> reactivation).
    match call(
        &handle,
        SessionCommand::ChangeUri {
            gid: g.clone(),
            file_index: 1,
            del_uris: vec![],
            add_uris: vec!["http://w.example/seed".into()],
            pos: None,
        },
    )
    .await
    {
        Ok(CommandReply::UriChange { deleted, added }) => {
            assert_eq!((deleted, added), (0, 1));
        }
        other => panic!("active changeUri must accept, got {other:?}"),
    }
    wait_until(|| async {
        matches!(
            call(&handle, SessionCommand::TellStatus { gid: g.clone(), keys: vec![] }).await,
            Ok(CommandReply::TorrentStatus(v)) if v.status == StatusKind::Active
        )
    })
    .await;
    // The engine is resident again -> the URI face is "used".
    match call(&handle, SessionCommand::GetUris { gid: g.clone() }).await {
        Ok(CommandReply::Uris(entries)) => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].uri, "http://w.example/seed");
            assert_eq!(entries[0].status, UriStatus::Used, "activated = used");
        }
        other => panic!("expected Uris, got {other:?}"),
    }
    handle.shutdown().await;
    ok(writer.await, "writer join");
    ok(
        tokio::time::timeout(Duration::from_secs(5), join).await,
        "actor join",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}
