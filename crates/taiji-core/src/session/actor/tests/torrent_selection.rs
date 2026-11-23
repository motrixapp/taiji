#[tokio::test]
async fn native_selection_has_bounded_metadata_capacity_when_payload_queue_is_full() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let dir = temp_dir("selection-admission");
    let torrent = multi_file_v1_torrent_with_pad(&dead_tracker(), "selection-admission");
    let metainfo = ok(Metainfo::parse(&torrent), "metadata source");
    let identity: String = metainfo
        .meta
        .identity
        .v1
        .unwrap_or_else(|| panic!("v1 identity"))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "metadata source listener",
    );
    let address = ok(listener.local_addr(), "metadata source address");
    let (release, wait) = oneshot::channel();
    let source = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "metadata source accept");
        let mut stream = BufReader::new(stream);
        loop {
            let mut line = String::new();
            let read = ok(stream.read_line(&mut line).await, "metadata source request");
            assert!(read > 0);
            if line == "\r\n" {
                break;
            }
        }
        ok(wait.await, "release metadata source");
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            torrent.len()
        );
        ok(
            stream.write_all(head.as_bytes()).await,
            "metadata source header",
        );
        ok(stream.write_all(&torrent).await, "metadata source body");
    });
    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions {
            max_concurrent_downloads: 1,
            enable_dht: false,
            enable_dht6: false,
            ..Default::default()
        },
    });
    let payload = gid_of(
        &call(
            &handle,
            torrent_cmd(
                build_v2_torrent(&vec![23u8; 128 * 1024], &dead_tracker()),
                &dir,
            ),
        )
        .await,
    );
    let mut metadata = Vec::new();
    for index in 1..=6 {
        let mut options = BTreeMap::from([
            (
                "dir".into(),
                dir.join(format!("metadata-{index}")).display().to_string(),
            ),
            ("motrix-await-selection".into(), "true".into()),
        ]);
        if index == 6 {
            options.insert("pause".into(), "true".into());
        }
        let uri = if index == 1 {
            format!("magnet:?xt=urn:btih:{identity}&xs=http%3A%2F%2F{address}%2Fmetadata.torrent")
        } else {
            format!("magnet:?xt=urn:btih:{index:040x}&tr=http%3A%2F%2F127.0.0.1%3A9%2Fannounce")
        };
        metadata.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![uri],
                    options,
                    position: None,
                },
            )
            .await,
        ));
    }
    assert_eq!(
        status_of(&handle, &payload.to_string()).await.status,
        StatusKind::Active
    );
    for gid in &metadata[..4] {
        assert_eq!(
            status_of(&handle, &gid.to_string()).await.status,
            StatusKind::Active
        );
    }
    assert_eq!(
        status_of(&handle, &metadata[4].to_string()).await.status,
        StatusKind::Waiting
    );
    assert_eq!(
        status_of(&handle, &metadata[5].to_string()).await.status,
        StatusKind::Paused
    );
    for (gid, expected, admitted) in [
        (metadata[0], crate::magnet::ResolutionState::Resolving, true),
        (metadata[4], crate::magnet::ResolutionState::Queued, false),
        (metadata[5], crate::magnet::ResolutionState::Paused, false),
    ] {
        let reply = call(
            &handle,
            SessionCommand::GetMagnetResolution {
                gid: gid.to_string(),
            },
        )
        .await;
        let Ok(CommandReply::MagnetResolution(snapshot)) = reply else {
            panic!("resolution: {reply:?}")
        };
        assert_eq!(snapshot.state, expected);
        assert_eq!(snapshot.info_validated_us, None);
        assert_eq!(
            snapshot
                .milestones
                .contains_key(&crate::magnet::ResolutionMilestone::Admitted),
            admitted
        );
    }
    assert!(release.send(()).is_ok());
    wait_until(async || {
        status_of(&handle, &metadata[4].to_string()).await.status == StatusKind::Active
    })
    .await;
    ok(source.await, "metadata source complete");
    assert_eq!(
        status_of(&handle, &metadata[0].to_string()).await.status,
        StatusKind::Paused
    );
    let reply = call(
        &handle,
        SessionCommand::GetMagnetResolution {
            gid: metadata[0].to_string(),
        },
    )
    .await;
    let Ok(CommandReply::MagnetResolution(snapshot)) = reply else {
        panic!("parked resolution: {reply:?}");
    };
    let validated_ms = snapshot
        .info_validated_us
        .unwrap_or_else(|| panic!("validated info"))
        / 1000;
    use crate::magnet::ResolutionMilestone;
    assert!(snapshot.milestones[&ResolutionMilestone::InfoVerified] <= validated_ms);
    assert!(validated_ms <= snapshot.milestones[&ResolutionMilestone::MetadataReady]);
    assert_eq!(
        status_of(&handle, &payload.to_string()).await.status,
        StatusKind::Active
    );
    handle.shutdown().await;
    ok(join.await, "session shutdown");
    let _ = std::fs::remove_dir_all(dir);
}

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
                awaiting_selection: true,
                manifest: Box::new(
                    taiji_domain::torrent_manifest::TorrentManifest::from_metainfo(&ok(
                        Metainfo::parse(&bytes),
                        "manifest metadata"
                    ))
                )
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
                ("bt-prioritize-piece".into(), "head=10M,tail=10M".into()),
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
                            options: selection.clone()
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
            assert!(
                matches!(saved.scheduler_policy, Some(crate::engine::SchedulerPolicy::RarestFirst(ref params)) if params.preview == Some(taiji_engine::preview::PreviewPieces { head: 10 * 1024 * 1024, tail: 10 * 1024 * 1024 }))
            );
            let mut changed_preview = selection.clone();
            changed_preview.insert("bt-prioritize-piece".into(), "head=1M".into());
            assert!(
                call(
                    &handle,
                    SessionCommand::ConfirmTorrentSelection {
                        gid: gid.into(),
                        options: changed_preview
                    }
                )
                .await
                .is_err()
            );
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
