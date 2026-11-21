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

/// A retained checkpoint survives an explicit URL/path edit and process restart;
/// a different content validator still refuses to alter the retained file.
#[tokio::test]
async fn change_uri_retained_http_checkpoint_rebinds_only_matching_content() {
    use crate::session::http::{ValidatorFacts, validator_digest};
    use crate::session::persist::import_http::{RetainedHttpContext, request_uri_hash};
    const BS: usize = 4 * 1024 * 1024;
    for changed in [false, true] {
        let dir = temp_dir("cu-retained");
        let db = dir.join("taiji.sqlite3");
        let body = vec![37; BS + 1024 * 1024];
        let mut retained = body.clone();
        retained[BS..].fill(0);
        let part = part_path_of(&dir, "payload.bin");
        ok(tokio::fs::write(&part, &retained).await, "seed part");
        let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
        let old = "http://127.0.0.1:1/old";
        let new = origin.url("new");
        let gid = Gid::from_u64(0x8000000000000925);
        let facts = ValidatorFacts {
            final_url_path: "/old".into(),
            total_len: Some(body.len() as u64),
            etag: None,
            last_modified: Some(
                if changed {
                    "Mon, 31 Aug 2026 12:00:00 GMT"
                } else {
                    LAST_MODIFIED_MOCK
                }
                .into(),
            ),
            encoding_ok: true,
        };
        let mut row = seeded_http_row(&gid.to_string(), old, &dir, "payload.bin");
        row.state = "paused".into();
        row.block_size = BS as i64;
        row.block_count = Some(2);
        row.block_bitmap = Some(vec![1]);
        row.total_done = BS as i64;
        row.probe_json = Some(ok(serde_json::to_string(&facts), "facts"));
        row.validator_digest = Some(ok(validator_digest(&facts), "digest"));
        row.config_json = HttpPersistConfig {
            retain_request_context: true,
            http_resume_context: Some(RetainedHttpContext {
                source_hash: request_uri_hash(old),
                resource_hash: request_uri_hash(old),
                output_path: dir.join("payload.bin").display().to_string(),
                validator_kind: "last-modified".into(),
                validator: facts.last_modified.clone().unwrap_or_default(),
                total_length: body.len() as i64,
            }),
            ..Default::default()
        }
        .to_json();
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "writer");
        ok(persist.upsert_http_task(row).await, "seed checkpoint");
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (handle, join) = SessionActor::spawn_with_persist(
            SessionOptions {
                global: global.clone(),
            },
            Some(persist),
        );
        ok(
            call(
                &handle,
                SessionCommand::ChangeUri {
                    gid: gid.to_string(),
                    file_index: 1,
                    del_uris: vec![old.into()],
                    add_uris: vec![new.clone()],
                    pos: Some(0),
                },
            )
            .await,
            "edit source",
        );
        handle.shutdown().await;
        ok(join.await, "actor exit");
        ok(writer.await, "writer exit");
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "restart writer");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
        ok(
            call(
                &handle,
                SessionCommand::Unpause {
                    gid: gid.to_string(),
                },
            )
            .await,
            "unpause",
        );
        let expected = if changed {
            StatusKind::Error
        } else {
            StatusKind::Complete
        };
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
            .any(|view| view.gid == gid && view.status == expected)
        })
        .await;
        if changed {
            assert_eq!(ok(tokio::fs::read(&part).await, "retained bytes"), retained);
            assert!(
                origin
                    .ranges
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .all(|range| *range == (0, 0))
            );
        } else {
            assert_eq!(
                ok(
                    tokio::fs::read(dir.join("payload.bin")).await,
                    "completed bytes"
                ),
                body
            );
            let ranges = origin.ranges.lock().unwrap_or_else(|e| e.into_inner());
            assert!(ranges.iter().any(|(start, _)| *start == BS as u64));
            assert!(
                ranges
                    .iter()
                    .all(|(start, end)| (*start, *end) == (0, 0) || *start >= BS as u64)
            );
        }
        handle.shutdown().await;
        ok(join.await, "actor exit");
        ok(writer.await, "writer exit");
        ok(tokio::fs::remove_dir_all(&dir).await, "cleanup");
    }
}
