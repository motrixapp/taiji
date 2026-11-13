#[tokio::test]
async fn magnet_selection_barrier_and_atomic_confirmation_survive_restart() {
    let db = tmp_db("selection-barrier");
    let dir = temp_dir("selection-barrier");
    let gid = "7000000000000001";
    let bytes = multi_file_v1_torrent_with_pad(&dead_tracker(), "unconfirmed");
    let cfg = PersistedTaskConfig {
        dir: dir.display().to_string(),
        selection_pending: true,
        ..Default::default()
    };
    let (row, files) = seeded_row(gid, &bytes, &cfg, 1);
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "writer");
    ok(writer.upsert_torrent(row, files).await, "parked metadata");
    drop(writer);
    let _ = wjoin.await;
    for round in 0..2 {
        let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "writer");
        let (handle, join) =
            SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer.clone()));
        assert_eq!(status_of(&handle, gid).await.status, StatusKind::Paused);
        assert_eq!(
            ok(
                call(
                    &handle,
                    SessionCommand::GetTorrentMetadata { gid: gid.into() }
                )
                .await,
                "metadata"
            ),
            CommandReply::TorrentMetadata {
                data: bytes.clone(),
                awaiting_selection: true
            }
        );
        ok(
            call(&handle, SessionCommand::UnpauseAll).await,
            "resume all",
        );
        assert!(
            call(&handle, SessionCommand::Unpause { gid: gid.into() })
                .await
                .is_err()
        );
        assert_eq!(status_of(&handle, gid).await.status, StatusKind::Paused);
        assert!(!dir.join("unconfirmed").exists());
        if round == 1 {
            let selection = BTreeMap::from([
                ("dir".into(), dir.join("chosen").display().to_string()),
                ("select-file".into(), "2".into()),
                (
                    "motrix-output-paths".into(),
                    r#"{"2":"renamed.bin"}"#.into(),
                ),
            ]);
            let mut invalid = selection.clone();
            invalid.insert("select-file".into(), "99".into());
            assert!(
                call(
                    &handle,
                    SessionCommand::ConfirmTorrentSelection {
                        gid: gid.into(),
                        options: invalid
                    }
                )
                .await
                .is_err()
            );
            let conn = ok(rusqlite::Connection::open(&db), "fault connection");
            ok(conn.execute_batch("CREATE TRIGGER fail_selection BEFORE UPDATE ON torrent BEGIN SELECT RAISE(ABORT, 'selection disk failure'); END"), "fault trigger");
            assert!(
                call(
                    &handle,
                    SessionCommand::ConfirmTorrentSelection {
                        gid: gid.into(),
                        options: selection.clone()
                    }
                )
                .await
                .is_err()
            );
            assert_eq!(status_of(&handle, gid).await.status, StatusKind::Paused);
            assert!(
                PersistedTaskConfig::from_json(&read_config_json(
                    &db,
                    &Gid::from_u64(0x7000000000000001)
                ))
                .selection_pending
            );
            ok(
                conn.execute_batch("DROP TRIGGER fail_selection"),
                "remove fault",
            );
            let accepted = call(
                &handle,
                SessionCommand::ConfirmTorrentSelection {
                    gid: gid.into(),
                    options: selection.clone(),
                },
            )
            .await;
            assert_eq!(gid_of(&accepted).to_string(), gid);
            // Lost responses are replayable while live, without an add or a re-fetch.
            assert_eq!(
                gid_of(
                    &call(
                        &handle,
                        SessionCommand::ConfirmTorrentSelection {
                            gid: gid.into(),
                            options: selection
                        }
                    )
                    .await
                )
                .to_string(),
                gid
            );
            let saved = PersistedTaskConfig::from_json(&read_config_json(
                &db,
                &Gid::from_u64(0x7000000000000001),
            ));
            assert!(!saved.selection_pending);
            assert_eq!(saved.selected_files, Some(vec![1]));
            assert_eq!(
                saved.output_paths.get(&2),
                Some(&PathBuf::from("renamed.bin"))
            );
            assert_eq!(count_rows(&db), 1);
        }
        ok(call(&handle, SessionCommand::Shutdown).await, "shutdown");
        drop(handle);
        let _ = join.await;
        drop(writer);
        let _ = wjoin.await;
    }
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_file(db);
}
