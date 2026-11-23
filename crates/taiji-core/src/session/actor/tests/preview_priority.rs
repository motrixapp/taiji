#[tokio::test]
async fn preview_priority_survives_paused_torrent_restart_and_can_be_cleared() {
    let db = tmp_db("preview-priority");
    let dir = temp_dir("preview-priority");
    let mut saved_gid = None;
    for round in 0..2 {
        let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "preview writer");
        let (handle, join) = SessionActor::spawn_with_persist(
            SessionOptions {
                global: GlobalOptions {
                    dir: dir.clone(),
                    enable_dht: false,
                    enable_dht6: false,
                    ..Default::default()
                },
            },
            Some(writer.clone()),
        );
        let gid = if let Some(gid) = saved_gid {
            gid
        } else {
            gid_of(
                &call(
                    &handle,
                    SessionCommand::AddTorrent {
                        torrent: build_v2_torrent(&vec![13u8; 128 * 1024], &dead_tracker()),
                        options: BTreeMap::from([
                            ("pause".into(), "true".into()),
                            ("bt-prioritize-piece".into(), "head=10M,tail=10M".into()),
                        ]),
                        position: None,
                    },
                )
                .await,
            )
        };
        saved_gid = Some(gid);
        let read = ok(
            call(
                &handle,
                SessionCommand::GetOption {
                    gid: gid.to_string(),
                },
            )
            .await,
            "preview options",
        );
        if let CommandReply::Options(options) = read {
            assert_eq!(
                options.get("bt-prioritize-piece").map(String::as_str),
                Some("head=10485760,tail=10485760")
            );
            assert_eq!(
                options.get("bt-sequential-download").map(String::as_str),
                Some("false")
            );
        } else {
            panic!("expected option snapshot")
        }
        let saved = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
        assert!(
            matches!(saved.scheduler_policy, Some(crate::engine::SchedulerPolicy::RarestFirst(ref params)) if params.preview.is_some())
        );
        if round == 1 {
            ok(
                call(
                    &handle,
                    SessionCommand::ChangeOption {
                        gid: gid.to_string(),
                        options: BTreeMap::from([("bt-prioritize-piece".into(), "".into())]),
                    },
                )
                .await,
                "clear preview",
            );
            let saved = PersistedTaskConfig::from_json(&read_config_json(&db, &gid));
            assert!(saved.scheduler_policy.is_none());
        }
        handle.shutdown().await;
        ok(join.await, "preview session shutdown");
        drop(handle);
        drop(writer);
        let _ = wjoin.await;
    }
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_file(db);
}
