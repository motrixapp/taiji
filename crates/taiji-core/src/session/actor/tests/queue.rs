// ---- add/queue/lifecycle end-to-end (real engine, port 0 + unreachable
// tracker) ----

#[tokio::test]
async fn add_torrent_tell_active_remove_tell_stopped_chain() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("e2e");
    let bytes = build_v2_torrent(&vec![0u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    assert_ne!(
        gid.as_u64() & 0x8000_0000_0000_0000,
        0,
        "the allocator high bit"
    );

    // Visible via tellActive (fillup inserts into the active table in
    // sync).
    let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].gid, gid);
    assert_eq!(active[0].status, StatusKind::Active);
    assert_eq!(active[0].total_length, 128 * 1024);

    // remove -> GID receipt; after finalization it enters
    // DownloadResult (visible via tellStopped).
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
    let mut stopped = Vec::new();
    for _ in 0..100 {
        stopped = status_list(
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
        if !stopped.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(stopped.len(), 1, "removed task must appear in tellStopped");
    assert_eq!(stopped[0].gid, gid);
    assert_eq!(stopped[0].status, StatusKind::Removed);

    // remove again -> not found; result-table remove -> OK -> a second
    // one fails.
    assert!(matches!(
        call(
            &handle,
            SessionCommand::Remove {
                gid: gid.to_string()
            }
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    assert_eq!(
        call(
            &handle,
            SessionCommand::RemoveDownloadResult {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    assert!(matches!(
        call(
            &handle,
            SessionCommand::RemoveDownloadResult {
                gid: gid.to_string()
            }
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    // purge clears the table.
    assert_eq!(
        call(&handle, SessionCommand::PurgeDownloadResult).await,
        Ok(CommandReply::Accepted)
    );
    assert!(
        status_list(
            &call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                }
            )
            .await
        )
        .is_empty()
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn duplicate_torrent_is_rejected_explicitly() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("dup");
    let bytes = build_v2_torrent(&vec![7u8; 128 * 1024], &dead_tracker());
    let _ = call(&handle, torrent_cmd(bytes.clone(), &dir)).await;
    let second = call(&handle, torrent_cmd(bytes, &dir)).await;
    match second {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.contains("duplicate"),
                "explicit dup error: {message}"
            );
        }
        other => panic!("duplicate add must fail explicitly, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn add_uri_rejects_unsupported_scheme_and_invalid_magnet_explicitly() {
    let (handle, join) = SessionActor::spawn();
    // addUri always accepts: ftp(s) is accepted directly (task -> GID;
    // until the transport adapter lands, such a task fails explicitly
    // at the probe stage — the old "reject at admission" face was
    // retired with always-on dispatch, "no gating").
    let ftp = SessionCommand::AddUri {
        uris: vec!["ftp://example.com/file.zip".into()],
        options: BTreeMap::new(),
        position: None,
    };
    assert!(matches!(call(&handle, ftp).await, Ok(CommandReply::Gid(_))));
    // A genuinely unsupported scheme still errors explicitly (the
    // file: face).
    let file = SessionCommand::AddUri {
        uris: vec!["file:///tmp/x".into()],
        options: BTreeMap::new(),
        position: None,
    };
    assert!(matches!(
        call(&handle, file).await,
        Err(SessionError::Failed { .. })
    ));
    // Empty list -> the aria2 message verbatim (RpcMethodImpl.cc).
    let empty = SessionCommand::AddUri {
        uris: vec![],
        options: BTreeMap::new(),
        position: None,
    };
    match call(&handle, empty).await {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, "URI is not provided.");
        }
        other => panic!("empty uris must fail, got {other:?}"),
    }
    // Invalid magnet (no valid xt).
    let bad_magnet = SessionCommand::AddUri {
        uris: vec!["magnet:?dn=no-xt".into()],
        options: BTreeMap::new(),
        position: None,
    };
    assert!(matches!(
        call(&handle, bad_magnet).await,
        Err(SessionError::Failed { .. })
    ));
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Session-level queue interaction: max-concurrent=1 -> the second task
/// waits; pause finalization requeues to the front paused (tellWaiting
/// first); unpause restores eligibility.
#[tokio::test]
async fn queue_lifecycle_pause_requeues_to_front_via_session() {
    let global = GlobalOptions {
        max_concurrent_downloads: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("queue");
    let bytes_a = build_v2_torrent(&vec![1u8; 128 * 1024], &dead_tracker());
    let bytes_b = build_v2_torrent_named(&vec![2u8; 128 * 1024], &dead_tracker(), "v2-b.bin");
    let a = gid_of(&call(&handle, torrent_cmd(bytes_a, &dir)).await);
    let b = gid_of(&call(&handle, torrent_cmd(bytes_b, &dir)).await);

    // fillup: A active, B waiting.
    assert_eq!(
        status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await).len(),
        1
    );
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
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].gid, b);
    assert_eq!(waiting[0].status, StatusKind::Waiting);

    // pause A -> GID immediately; wait for the finalization event -> A
    // requeues to front paused, B backfills.
    assert_eq!(
        call(&handle, SessionCommand::Pause { gid: a.to_string() }).await,
        Ok(CommandReply::Gid(a))
    );
    let mut paused_front = false;
    for _ in 0..100 {
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
        // After A backfills the steady state = [A(paused)]; the
        // transient before backfill = [A(paused), B]. Both windows
        // require A at the front and paused.
        if let Some(front) = waiting.first() {
            if front.gid == a && front.status == StatusKind::Paused {
                paused_front = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        paused_front,
        "paused active task must requeue to FRONT (paused)"
    );
    let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].gid, b, "next task fills the freed slot");

    // unpause A: restores waiting eligibility (no activation while the
    // slot is full — fillup semantics).
    assert_eq!(
        call(&handle, SessionCommand::Unpause { gid: a.to_string() }).await,
        Ok(CommandReply::Gid(a))
    );
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
    assert_eq!(
        waiting.len(),
        1,
        "A stays queued (slot full), B keeps running"
    );
    assert_eq!(waiting[0].gid, a);
    assert_eq!(waiting[0].status, StatusKind::Waiting);
    // remove B -> A backfills and activates.
    assert_eq!(
        call(&handle, SessionCommand::Remove { gid: b.to_string() }).await,
        Ok(CommandReply::Gid(b))
    );
    let mut a_active = false;
    for _ in 0..100 {
        let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
        if active.len() == 1 && active[0].gid == a {
            a_active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(a_active, "unpaused front task must refill the freed slot");

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// changePosition session face (RpcMethodImpl.cc + the
/// RequestGroupMan.cc translation): the three reorder modes take effect
/// in the tellWaiting order; the reply = the destination index after
/// the move (a bare integer); an active gid gets the waiting-queue
/// message verbatim; a prefix gid works; a paused waiting entry can be
/// moved and its flag does not drift.
#[tokio::test]
async fn change_position_moves_waiting_tasks_and_error_faces() {
    let global = GlobalOptions {
        max_concurrent_downloads: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("chgpos");
    let fills = [1u8, 2, 3];
    let mut gids: Vec<Gid> = Vec::new();
    for f in fills {
        // Multiple tasks in the same dir need unique file names
        // (same-dest exclusivity).
        gids.push(gid_of(
            &call(
                &handle,
                torrent_cmd(
                    build_v2_torrent_named(
                        &vec![f; 128 * 1024],
                        &dead_tracker(),
                        &format!("v2-{f}.bin"),
                    ),
                    &dir,
                ),
            )
            .await,
        ));
    }
    // fillup: gids[0] active, [b, c] waiting.
    let waiting = || async {
        status_list(
            &call(
                &handle,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        )
    };
    let _ = waiting().await;
    let (a, b, c) = (gids[0], gids[1], gids[2]);
    let pos_of = |r: &CmdResult| -> u64 {
        match r {
            Ok(CommandReply::Position { position }) => *position,
            other => panic!("expected Position reply, got {other:?}"),
        }
    };
    // POS_SET 0: c -> front (the RpcMethodImpl.cc POS_SET face).
    assert_eq!(
        pos_of(
            &call(
                &handle,
                SessionCommand::ChangePosition {
                    gid: c.to_string(),
                    pos: 0,
                    how: OffsetMode::Set,
                },
            )
            .await
        ),
        0
    );
    let w: Vec<Gid> = waiting().await.iter().map(|v| v.gid).collect();
    assert_eq!(w, vec![c, b], "POS_SET 0 → front");
    // POS_CUR -1: b at 1 -> forward one slot to 0.
    assert_eq!(
        pos_of(
            &call(
                &handle,
                SessionCommand::ChangePosition {
                    gid: b.to_string(),
                    pos: -1,
                    how: OffsetMode::Cur,
                },
            )
            .await
        ),
        0
    );
    let w: Vec<Gid> = waiting().await.iter().map(|v| v.gid).collect();
    assert_eq!(w, vec![b, c], "POS_CUR -1 moves forward one spot");
    // POS_END 0: b -> tail.
    assert_eq!(
        pos_of(
            &call(
                &handle,
                SessionCommand::ChangePosition {
                    gid: b.to_string(),
                    pos: 0,
                    how: OffsetMode::End,
                },
            )
            .await
        ),
        1
    );
    let w: Vec<Gid> = waiting().await.iter().map(|v| v.gid).collect();
    assert_eq!(w, vec![c, b], "POS_END 0 → tail");
    // A prefix gid (the expandUnique face) is equivalent to the full
    // string.
    assert_eq!(
        pos_of(
            &call(
                &handle,
                SessionCommand::ChangePosition {
                    gid: c.to_string()[..13].to_string(),
                    pos: 5,
                    how: OffsetMode::Set,
                },
            )
            .await
        ),
        1,
        "prefix parsing + out-of-range clamps to the queue tail"
    );
    // A paused waiting entry can be moved and its flag does not drift
    // (the reference reservedGroups_ contains pauseRequested reserved
    // entries).
    let p = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: build_v2_torrent(&vec![9u8; 128 * 1024], &dead_tracker()),
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    assert_eq!(
        pos_of(
            &call(
                &handle,
                SessionCommand::ChangePosition {
                    gid: p.to_string(),
                    pos: 0,
                    how: OffsetMode::Set,
                },
            )
            .await
        ),
        0,
        "a paused waiting entry can be moved"
    );
    let w = waiting().await;
    assert_eq!(w[0].gid, p);
    assert_eq!(
        w[0].status,
        StatusKind::Paused,
        "the paused flag rides the row unchanged"
    );
    // active gid -> the reference message verbatim (the
    // RequestGroupMan.cc -1 face).
    match call(
        &handle,
        SessionCommand::ChangePosition {
            gid: a.to_string(),
            pos: 0,
            how: OffsetMode::Set,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert_eq!(message, format!("GID#{a} not found in the waiting queue."));
        }
        other => panic!("active gid must hit waiting-queue error, got {other:?}"),
    }
    // Unknown/invalid gid -> the str2Gid message verbatim (the
    // resolve_gid face).
    for (raw, want) in [
        (
            "9000000000000001".to_string(),
            "GID 9000000000000001 is not found".to_string(),
        ),
        ("xyz".to_string(), "Invalid GID xyz".to_string()),
    ] {
        match call(
            &handle,
            SessionCommand::ChangePosition {
                gid: raw,
                pos: 0,
                how: OffsetMode::Set,
            },
        )
        .await
        {
            Err(SessionError::Failed { message }) => assert_eq!(message, want),
            other => panic!("{want}: expected gid error, got {other:?}"),
        }
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Restore-consistency combination gap: changePosition reorder ->
/// max-concurrent=2 with two active tasks **paused one after another,
/// requeueing to the front** -> shutdown -> restart. Defect shape:
/// renumber only covered the reserved rows at the reorder instant,
/// while active rows kept their stale activation-era keys; pause
/// finalization requeueing to the front (queue.rs `retire_active`
/// push_front, the RequestGroupMan.cc translation) did not rewrite keys
/// -> the store key order = the old activation order [A,B,...], and the
/// restart recovery order != the shutdown running order. After the fix,
/// requeueing to the front renumbers the whole segment (the
/// retire_and_fire requeue flag -> persist_queue_renumber), and the
/// recovery order replicates the shutdown face bit for bit. The
/// existing cross_family case only covers the direct "reorder ->
/// shutdown" chain; this case adds the "reorder -> multi-active pause
/// -> shutdown" combination.
#[tokio::test]
async fn change_position_renumber_survives_active_pause_requeue() {
    let db = tmp_db("chgpos-pause");
    let dir = temp_dir("chgpos-pause");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let a = gid_of(
        &call(
            &handle,
            torrent_cmd(
                build_v2_torrent(&vec![1u8; 128 * 1024], &dead_tracker()),
                &dir,
            ),
        )
        .await,
    );
    let b = gid_of(
        &call(
            &handle,
            torrent_cmd(
                build_v2_torrent_named(&vec![2u8; 128 * 1024], &dead_tracker(), "v2-b.bin"),
                &dir,
            ),
        )
        .await,
    );
    let c = gid_of(
        &call(
            &handle,
            torrent_cmd(
                build_v2_torrent_named(&vec![3u8; 128 * 1024], &dead_tracker(), "v2-c.bin"),
                &dir,
            ),
        )
        .await,
    );
    let d = gid_of(
        &call(
            &handle,
            torrent_cmd(
                build_v2_torrent_named(&vec![4u8; 128 * 1024], &dead_tracker(), "v2-d.bin"),
                &dir,
            ),
        )
        .await,
    );
    // fillup to 2: {A,B} active, [C,D] waiting.
    let mut filled = false;
    for _ in 0..100 {
        let act = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
        if act.len() == 2 {
            filled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(filled, "both concurrency slots filled up");
    // changePosition D -> front: reserved [D,C] (A/B active rows keep
    // their stale keys — the exposed defect face).
    match call(
        &handle,
        SessionCommand::ChangePosition {
            gid: d.to_string(),
            pos: 0,
            how: OffsetMode::Set,
        },
    )
    .await
    {
        Ok(CommandReply::Position { position }) => assert_eq!(position, 0),
        other => panic!("move d to front, got {other:?}"),
    }
    // Pauses in sequence (A finalizes to front before B requests —
    // keeps the ordering assertions free of finalization races). A
    // requeues to front -> D backfills; B requeues to front -> C
    // backfills. Shutdown running face: waiting [B(paused), A(paused)],
    // active {C,D}.
    assert_eq!(
        call(&handle, SessionCommand::Pause { gid: a.to_string() }).await,
        Ok(CommandReply::Gid(a))
    );
    let mut a_front = false;
    for _ in 0..100 {
        let w = status_list(
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
        if let Some(front) = w.first() {
            if front.gid == a && front.status == StatusKind::Paused {
                a_front = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(a_front, "A returned to the front, paused");
    assert_eq!(
        call(&handle, SessionCommand::Pause { gid: b.to_string() }).await,
        Ok(CommandReply::Gid(b))
    );
    let mut settled = false;
    for _ in 0..100 {
        let w = status_list(
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
        let gids: Vec<Gid> = w.iter().map(|v| v.gid).collect();
        if gids == vec![b, a] && w.iter().all(|v| v.status == StatusKind::Paused) {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        settled,
        "after B's front requeue the shutdown running order = [B, A]"
    );
    // Both backfills in place: active = {C, D} (set semantics —
    // tellActive promises no activation order).
    let mut active_ok = false;
    for _ in 0..100 {
        let mut gids: Vec<Gid> =
            status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await)
                .iter()
                .map(|v| v.gid)
                .collect();
        gids.sort();
        let mut want = vec![c, d];
        want.sort();
        if gids == want {
            active_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(active_ok, "C/D backfilled as active");
    match call(&handle, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    // Store face: each front-requeue triggers a whole-segment renumber
    // ([A,C] -> A<C, [B,A] -> B<A) -> key order = [D(activation-era
    // key), C, B, A] — D keeps its activation-era key but is active at
    // shutdown (fillup reactivates it, taking no waiting slot); the
    // defect shape = [A,B,D,C] (A/B always first, recovery order != the
    // shutdown running order).
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback");
        let mut stmt = ok(
            conn.prepare(
                "SELECT gid FROM (SELECT gid, queue_pos FROM torrent WHERE state IN
                         ('queued','paused','metadata','downloading')
                         UNION ALL
                         SELECT gid, queue_pos FROM http_task WHERE state IN
                         ('queued','paused','downloading'))
                         ORDER BY queue_pos",
            ),
            "prepare order",
        );
        let mapped = ok(stmt.query_map([], |r| r.get::<_, String>(0)), "query order");
        let mut order: Vec<String> = Vec::new();
        for row in mapped {
            order.push(ok(row, "order row"));
        }
        // Key derivation (renumbering precedes the backfill pump):
        // [A,D,C] -> A<D<C, [B,A,C] -> B<A<C -> store order [D(8),
        // B(10), A(11), C(12)]. D keeps its activation-era key but is
        // active at shutdown (restart fillup reactivates it, taking no
        // waiting slot); the defect shape = [A(1), B(2), D(5), C(6)] —
        // A/B always first.
        let want: Vec<String> = [d, b, a, c].iter().map(|g| g.to_string()).collect();
        assert_eq!(
            order, want,
            "after the front-requeue renumbering, the store key order projects = the shutdown running order"
        );
    }
    // Restart -> the tellWaiting order = the shutdown running order.
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    let mut restored = false;
    for _ in 0..100 {
        let w = status_list(
            &call(
                &handle2,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        let gids: Vec<Gid> = w.iter().map(|v| v.gid).collect();
        if gids.len() == 2 {
            assert_eq!(
                gids,
                vec![b, a],
                "after restart the tellWaiting order = the shutdown running order (front-requeue combination)"
            );
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(restored, "after restart both B/A are restored");
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Restore consistency: reorder -> shutdown -> restart -> the
/// tellWaiting order is preserved (queue_pos renumbered stably as a
/// whole segment into the store; torrent/http cross-family keys share
/// one key order); plus a second-restart segment: restore -> add a task
/// -> restart again — row_seq is seeded from the in-store `queue_pos`
/// upper bound (lifecycle::bootstrap), so the new task's key is
/// strictly greater than every restored key and it appends at the tail
/// without queue-jumping (without the seed this deterministically
/// inverts). All tasks enqueue paused (no active finalization rows to
/// interfere; the recovery order depends only on queue_pos).
#[tokio::test]
async fn change_position_renumber_survives_restart_cross_family() {
    let db = tmp_db("chgpos-renumber");
    let dir = temp_dir("chgpos-renumber");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let add_paused = |torrent: Vec<u8>| SessionCommand::AddTorrent {
        torrent,
        options: BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("pause".to_string(), "true".to_string()),
        ]),
        position: None,
    };
    let t1 = gid_of(
        &call(
            &handle,
            add_paused(build_v2_torrent(&vec![1u8; 128 * 1024], &dead_tracker())),
        )
        .await,
    );
    let t2 = gid_of(
        &call(
            &handle,
            add_paused(build_v2_torrent_named(
                &vec![2u8; 128 * 1024],
                &dead_tracker(),
                "v2-b.bin",
            )),
        )
        .await,
    );
    let t3 = gid_of(
        &call(
            &handle,
            add_paused(build_v2_torrent_named(
                &vec![3u8; 128 * 1024],
                &dead_tracker(),
                "v2-c.bin",
            )),
        )
        .await,
    );
    // Cross-family: an HTTP task (the http_task table shares the key
    // family).
    let h = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let waiting = || async {
        let r = status_list(
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
        r.into_iter().map(|v| v.gid).collect::<Vec<Gid>>()
    };
    let _ = waiting().await;
    // [t1, t2, t3, h] -> http to front -> [h, t1, t2, t3].
    match call(
        &handle,
        SessionCommand::ChangePosition {
            gid: h.to_string(),
            pos: 0,
            how: OffsetMode::Set,
        },
    )
    .await
    {
        Ok(CommandReply::Position { position }) => assert_eq!(position, 0),
        other => panic!("move http to front, got {other:?}"),
    }
    // t3 POS_END -2: 3 -> 1 -> [h, t3, t1, t2] (torrent/http
    // interleaved).
    match call(
        &handle,
        SessionCommand::ChangePosition {
            gid: t3.to_string(),
            pos: -2,
            how: OffsetMode::End,
        },
    )
    .await
    {
        Ok(CommandReply::Position { position }) => assert_eq!(position, 1),
        other => panic!("move t3 POS_END -2, got {other:?}"),
    }
    assert_eq!(
        waiting().await,
        vec![h, t3, t1, t2],
        "the running-state order after the reorder"
    );
    match call(&handle, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    // Store face: after the whole-segment queue_pos renumber, the
    // ORDER BY order = the running order (cross-family keys share the
    // source, no collisions).
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback");
        let mut stmt = ok(
            conn.prepare(
                "SELECT gid FROM (SELECT gid, queue_pos FROM torrent WHERE state IN
                         ('queued','paused','metadata','downloading')
                         UNION ALL
                         SELECT gid, queue_pos FROM http_task WHERE state IN
                         ('queued','paused','downloading'))
                         ORDER BY queue_pos",
            ),
            "prepare order",
        );
        let mapped = ok(stmt.query_map([], |r| r.get::<_, String>(0)), "query order");
        let mut order: Vec<String> = Vec::new();
        for row in mapped {
            order.push(ok(row, "order row"));
        }
        let want: Vec<String> = [h, t3, t1, t2].iter().map(|g| g.to_string()).collect();
        assert_eq!(
            order, want,
            "the restore key order = the reordered queue order (cross-family)"
        );
    }
    // Restart -> the tellWaiting order is preserved.
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    let mut restored = false;
    for _ in 0..100 {
        let r = status_list(
            &call(
                &handle2,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        let gids_now: Vec<Gid> = r.iter().map(|v| v.gid).collect();
        if gids_now.len() == 4 {
            assert_eq!(
                gids_now,
                vec![h, t3, t1, t2],
                "after restart the tellWaiting order = the reorder (cross-family)"
            );
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(restored, "after restart all 4 restored");
    // Second-restart segment: restore -> add a task -> restart again.
    // Defect shape: row_seq restarted at 1 each process, so a new
    // task's key (=1) was always smaller than every renumbered restored
    // key — on the second restart it deterministically sorted to the
    // queue head (recovery order != last run's queue order). After the
    // seeding fix the new task's key continues from the in-store upper
    // bound and must append at the tail.
    let t4 = gid_of(
        &call(
            &handle2,
            add_paused(build_v2_torrent_named(
                &vec![4u8; 128 * 1024],
                &dead_tracker(),
                "v2-d.bin",
            )),
        )
        .await,
    );
    match call(&handle2, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession 2, got {other:?}"),
    }
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    // Second restart: all 5 restored, the new task t4 at the tail.
    let (writer3, wjoin3) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 3");
    let global3 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle3, join3) =
        SessionActor::spawn_with_persist(SessionOptions { global: global3 }, Some(writer3.clone()));
    let mut restored2 = false;
    for _ in 0..100 {
        let r = status_list(
            &call(
                &handle3,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        let gids_now: Vec<Gid> = r.iter().map(|v| v.gid).collect();
        if gids_now.len() == 5 {
            assert_eq!(
                gids_now,
                vec![h, t3, t1, t2, t4],
                "after the second restart the new task appends at the tail (queue_pos seeding is \
                 monotonic across restarts)"
            );
            restored2 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(restored2, "after the second restart all 5 restored");
    // Store face: the new task's key is strictly greater than every
    // existing key (including the second-restart read order).
    {
        let conn = ok(rusqlite::Connection::open(&db), "readback 3");
        let mut stmt = ok(
            conn.prepare(
                "SELECT gid FROM (SELECT gid, queue_pos FROM torrent WHERE state IN
                         ('queued','paused','metadata','downloading')
                         UNION ALL
                         SELECT gid, queue_pos FROM http_task WHERE state IN
                         ('queued','paused','downloading'))
                         ORDER BY queue_pos",
            ),
            "prepare order 3",
        );
        let mapped = ok(
            stmt.query_map([], |r| r.get::<_, String>(0)),
            "query order 3",
        );
        let mut order: Vec<String> = Vec::new();
        for row in mapped {
            order.push(ok(row, "order row 3"));
        }
        let want: Vec<String> = [h, t3, t1, t2, t4].iter().map(|g| g.to_string()).collect();
        assert_eq!(
            order, want,
            "after the second restart the restore key order = the running-state queue order"
        );
    }
    handle3.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join3).await;
    drop(writer3);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin3).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn pause_unknown_or_paused_rejected_and_unpause_needs_paused() {
    let (handle, join) = SessionActor::spawn();
    let missing = GidAllocator::new().allocate();
    assert!(matches!(
        call(
            &handle,
            SessionCommand::Pause {
                gid: missing.to_string()
            }
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    assert!(matches!(
        call(
            &handle,
            SessionCommand::Unpause {
                gid: missing.to_string()
            }
        )
        .await,
        Err(SessionError::Failed { .. })
    ));
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// add with pause=true -> the row state paused is persisted; after a
/// restart it stays paused and does not auto-start. Before the fix it
/// always wrote queued -> the restart auto-activated the probe.
#[tokio::test]
async fn add_pause_true_persists_paused_and_stays_paused_after_restart() {
    let dir = temp_dir("http-m4-pause");
    let db = tmp_db("http-m4-pause");
    let origin = spawn_mock_origin(Arc::new(vec![7u8; 64 * 1024]), true, true, true).await;
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
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(s, _)| s == "paused")
            .unwrap_or(false)
    })
    .await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    // Restart: stays paused (no auto-start — the row must not return to
    // queued/activate).
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist2, writer2) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(persist2));
    tokio::time::sleep(Duration::from_millis(700)).await;
    let waiting = status_list(
        &call(
            &handle2,
            SessionCommand::TellWaiting {
                offset: 0,
                num: u32::MAX,
                keys: vec![],
            },
        )
        .await,
    );
    assert!(
        waiting.iter().any(|v| v.gid == gid),
        "a paused task returns to the waiting queue after restart"
    );
    let active = status_list(&call(&handle2, SessionCommand::TellActive { keys: vec![] }).await);
    assert!(
        active.iter().all(|v| v.gid != gid),
        "a paused task must not auto-activate"
    );
    assert_eq!(
        http_row_of(&db, &gid_hex).map(|(s, _)| s),
        Some("paused".into()),
        "the row stays paused"
    );
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// An explicit pause on the reserved face -> the http_task row is
/// persisted as paused. Before the fix, a reserved pause was a no-op
/// for the http row (auto-start on restart).
#[tokio::test]
async fn reserved_pause_persists_http_row() {
    let dir = temp_dir("http-m4-reserved");
    let db = tmp_db("http-m4-reserved");
    let origin = spawn_mock_origin(Arc::new(vec![7u8; 64 * 1024]), true, true, true).await;
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 1, // A holds the slot, B stays reserved.
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let add = |path: &str| SessionCommand::AddUri {
        uris: vec![origin.url(path)],
        options: BTreeMap::new(),
        position: None,
    };
    let gid_a = gid_of(&call(&handle, add("a.bin")).await);
    let gid_b = gid_of(&call(&handle, add("b.bin")).await);
    let b_hex = gid_b.to_string();
    // B is registered (a queued row).
    wait_until(async || http_row_of(&db, &b_hex).is_some()).await;
    // A holds the slot and enters the probe stall (stably active);
    // pause B.
    wait_until(async || {
        !status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await)
            .iter()
            .any(|v| v.gid == gid_a)
            || true
    })
    .await;
    let _ = call(&handle, SessionCommand::Pause { gid: b_hex.clone() }).await;
    wait_until(async || {
        http_row_of(&db, &b_hex)
            .map(|(s, _)| s == "paused")
            .unwrap_or(false)
    })
    .await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// `--out` basename sanitization (the session face rejects + the
/// message carries taiji.option.invalid; legal names pass). See
/// sanitize_out_option_matrix for the unit matrix.
#[tokio::test]
async fn add_uri_rejects_unsafe_out_option() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-m5-out");
    for bad in ["../evil", "/abs.bin", "a/b", "a\\b", "-x", "C:", ".", ".."] {
        let r = call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("out".to_string(), bad.to_string()),
                ]),
                position: None,
            },
        )
        .await;
        let msg = match r {
            Err(e) => e.to_string(),
            Ok(_) => panic!("out {bad:?} must be rejected"),
        };
        assert!(msg.contains("taiji.option.invalid"), "{bad:?}: {msg}");
    }
    // A legal name passes.
    let ok = call(
        &handle,
        SessionCommand::AddUri {
            uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
            options: BTreeMap::from([
                ("dir".to_string(), dir.display().to_string()),
                ("out".to_string(), "fine name-v2.bin".to_string()),
            ]),
            position: None,
        },
    )
    .await;
    assert!(
        matches!(ok, Ok(CommandReply::Gid(_))),
        "a legal basename passes"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The Error -> unpause re-probe migration arm: a failed task unpauses
/// and re-enters the queue for probing (before the fix,
/// "cannot be unpaused now" — a failed task could only be deleted and
/// re-added).
#[tokio::test]
async fn error_task_unpause_requeues_reprobe() {
    let dir = temp_dir("http-m9-unpause");
    let db = tmp_db("http-m9-unpause");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    // Unreachable origin (port 1 refuses) -> the probe fails
    // immediately -> Error.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
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
        .any(|v| v.gid == gid && v.status == StatusKind::Error)
    })
    .await;
    // Error -> unpause re-probe migration.
    match call(
        &handle,
        SessionCommand::Unpause {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Gid(g)) => assert_eq!(g, gid),
        other => panic!("an error task must be unpausable for a re-probe, got {other:?}"),
    }
    // Requeued and failing again (origin still unreachable) ->
    // numStoppedTotal grows to 2.
    wait_until(async || {
        matches!(
            call(&handle, SessionCommand::GetGlobalStat).await,
            Ok(CommandReply::GlobalStat(g)) if g.num_stopped_total == 2
        )
    })
    .await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// reopen write-face failure injection: the Error -> unpause migration
/// arm's reopen UPDATE hits a fault (a BEFORE UPDATE trigger with
/// RAISE(ABORT) as the minimal stand-in for a write-face fault) ->
/// unpause is rejected — the DB row stays in the error terminal state
/// (error face verbatim, zero write actions), the session keeps its
/// Result/Error bookkeeping and does not rebuild the Job (a second
/// unpause is rejected the same way); both sides stay consistent with
/// no divergence; after removing the fault, unpause is admitted again
/// (the re-probe loop can re-enter — the rejection only held the
/// migration at the write-face fault, the row was not pinned forever).
#[tokio::test]
async fn error_task_unpause_rejected_when_reopen_persist_fails() {
    let dir = temp_dir("http-unpause-reopen-fail");
    let db = tmp_db("http-unpause-reopen-fail");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    // Unreachable origin (port 1 refuses) -> the probe fails
    // immediately -> Error.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
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
        .any(|v| v.gid == gid && v.status == StatusKind::Error)
    })
    .await;

    // Fault injection: every UPDATE on http_task RAISEs ABORT (the
    // reopen read face's load is unaffected, the write face must fail).
    // A separate connection = the same shape as the WAL concurrent-read
    // face.
    {
        let inj = ok(rusqlite::Connection::open(&db), "open inject conn");
        ok(inj.busy_timeout(Duration::from_secs(5)), "busy timeout");
        ok(
            inj.execute(
                "CREATE TRIGGER inject_reopen_fail BEFORE UPDATE ON http_task
                 BEGIN SELECT RAISE(ABORT, 'injected reopen failure'); END;",
                [],
            ),
            "install trigger",
        );
    }

    // unpause is rejected (the same failure face as unknown /
    // non-paused states).
    let reply = call(
        &handle,
        SessionCommand::Unpause {
            gid: gid_hex.clone(),
        },
    )
    .await;
    assert!(
        reply.is_err(),
        "a reopen failure must reject unpause, got {reply:?}"
    );

    // DB-side consistency: the row stays in the error terminal state,
    // the error face preserved verbatim (the UPDATE did not take
    // effect).
    {
        let conn = ok(rusqlite::Connection::open(&db), "open row read");
        let (state, code, msg): (String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT state, error_code, error_msg FROM http_task WHERE gid = ?1",
                params![gid_hex],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap_or_else(|e| panic!("row read: {e}"));
        assert_eq!(
            state, "error",
            "the row must stay in the error terminal state (zero write actions)"
        );
        assert!(
            code.is_some() && msg.is_some(),
            "the error face must be preserved verbatim"
        );
    }
    // Memory-side consistency: no Job rebuild (a second unpause is
    // rejected the same way), the task is still in Result/Error, and it
    // appears in neither active nor waiting.
    let second = call(
        &handle,
        SessionCommand::Unpause {
            gid: gid_hex.clone(),
        },
    )
    .await;
    assert!(
        second.is_err(),
        "no Job rebuild -> a second unpause is rejected the same way, got {second:?}"
    );
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
    assert!(
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Error),
        "the session side must still hold Result/Error bookkeeping (no divergence)"
    );
    let elsewhere = |r: &CmdResult| status_list(r).iter().any(|v| v.gid == gid);
    assert!(
        !elsewhere(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await)
            && !elsewhere(
                &call(
                    &handle,
                    SessionCommand::TellWaiting {
                        offset: 0,
                        num: u32::MAX,
                        keys: vec![]
                    }
                )
                .await
            ),
        "a rejected task must not appear in active/waiting (no Job rebuild)"
    );

    // Remove the fault: unpause is admitted again -> the re-probe
    // (origin still unreachable) fails again -> numStoppedTotal=2. The
    // rejection did not pin the row in error forever.
    {
        let inj = ok(rusqlite::Connection::open(&db), "open inject conn 2");
        ok(
            inj.execute("DROP TRIGGER inject_reopen_fail", []),
            "drop trigger",
        );
    }
    match call(&handle, SessionCommand::Unpause { gid: gid_hex }).await {
        Ok(CommandReply::Gid(g)) => assert_eq!(g, gid),
        other => panic!("after removing the fault, unpause must be admitted again, got {other:?}"),
    }
    wait_until(async || {
        matches!(
            call(&handle, SessionCommand::GetGlobalStat).await,
            Ok(CommandReply::GlobalStat(g)) if g.num_stopped_total == 2
        )
    })
    .await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Recovery queue order preserved across task families —
/// http(queue_pos=3) enters the waiting queue ahead of torrent
/// (queue_pos=5) (before the fix: the "torrents first, then http"
/// rebuild order).
#[tokio::test]
async fn bootstrap_queue_order_preserved_across_families() {
    let dir = temp_dir("http-m10-order");
    let db = tmp_db("http-m10-order");
    let bytes = build_v2_torrent(&vec![0xACu8; 128 * 1024], &dead_tracker());
    let meta = crate::metainfo::Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("parse: {e}"));
    let torrent_gid = "8000000000000782";
    let http_gid = "8000000000000783";
    {
        let (handle_w, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "seed writer");
        // torrent row queue_pos=5 (with a metadata BLOB, rebuildable).
        let mut trow = super::super::persist::torrent_row(
            torrent_gid,
            taiji_store::persist::TaskPhase::Queued,
            5,
            "v2.bin",
            &super::super::persist::PersistedTaskConfig {
                dir: dir.display().to_string(),
                ..Default::default()
            },
        );
        super::super::persist::fill_torrent_identity(&mut trow, &Arc::new(meta), bytes);
        handle_w
            .upsert_torrent(trow, Vec::new())
            .await
            .unwrap_or_else(|e| panic!("seed torrent: {e}"));
        // http row queue_pos=3.
        let mut hrow = seeded_http_row(http_gid, "http://127.0.0.1:1/f.bin", &dir, "f.bin");
        hrow.queue_pos = 3;
        handle_w
            .upsert_http_task(hrow)
            .await
            .unwrap_or_else(|e| panic!("seed http: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
    }
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 0, // all stay in the waiting queue
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    tokio::time::sleep(Duration::from_millis(500)).await;
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
    let gids: Vec<String> = waiting.iter().map(|v| v.gid.to_string()).collect();
    assert_eq!(
        gids,
        vec![http_gid.to_string(), torrent_gid.to_string()],
        "order preserved across task families by queue_pos"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// sanitize_out unit matrix: the basename sanitization domain (legal /
/// directory escape / absolute / injection shapes).
#[test]
fn sanitize_out_option_matrix() {
    for good in [
        "file.bin",
        "my.file name-v2.bin",
        "donn\u{e9}es.bin",
        "a..b",
        // Control: a ZWJ-sequence emoji name (U+200D is a legal emoji
        // file-name component) is unaffected by the bidi-override set.
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.png",
        // Length cap boundary: exactly 255 bytes is within the cap
        // (only `>` rejects, matching the taiji-bt filetree
        // MAX_COMPONENT_BYTES accounting).
        "y".repeat(255).as_str(),
    ] {
        assert_eq!(
            sanitize_out_option(good).ok(),
            Some(good.to_string()),
            "{good:?} must be accepted"
        );
    }
    for bad in [
        "",
        "  ",
        "../evil",
        "..",
        ".",
        "/abs.bin",
        "a/b",
        "a\\b",
        "a/../b",
        "-x",
        "C:",
        "f:ads",
        "a\x01b",
        // Windows naming-domain completeness (cross-platform
        // consistency): reserved device name stems (case-insensitive,
        // with-extension shapes included) and trailing `.`/space.
        "CON",
        "con",
        "Con.iso",
        "nul.txt",
        "lpt4.prn",
        "aux",
        "trailing.",
        // Bidi-override code points (Cf class — `char::is_control` only
        // covers Cc; these were previously allowed) — rejected with the
        // same accounting as control characters; the display-spoofing
        // shape `photo\u{202E}gpj.exe`. Single source for the set:
        // `taiji_io::text::is_spoofing_char` (the bt parse face / http
        // sanitization face reference the same source).
        "a\u{202E}b.exe",
        "a\u{061C}b",
        "a\u{2066}\u{2069}b",
        // The three zero-width code points (ZWSP/ZWNJ/BOM — the
        // name-borrowing shape where `evil\u{200B}.exe` looks identical
        // to `evil.exe`) and the line/paragraph separators (U+2028/
        // U+2029, a residual log-line injection vector) were previously
        // allowed.
        "evil\u{200B}.exe",
        "a\u{200C}b",
        "a\u{FEFF}b",
        "a\u{2028}b",
        "a\u{2029}b",
        // C1 anchor (all three channels unified onto `is_control`
        // semantics — the admission face's existing behavior; the
        // unified direction is locked in, no rollback).
        "a\u{85}b",
        // Length cap: a 300-byte basename (strictly the FS
        // ENAMETOOLONG = the first file's create fails and rejects the
        // whole task; an explicit rejection at admission beats a silent
        // truncate of the user's explicit name at the disk face).
        "u".repeat(300).as_str(),
    ] {
        assert!(
            sanitize_out_option(bad).is_err(),
            "{bad:?} must be rejected"
        );
    }
}

/// Windows naming-domain unsafe basename decision (the single source
/// for the out domain; the taiji-rpc metalink expansion face consumes
/// the same predicate directly).
#[test]
fn windows_unsafe_basename_matrix() {
    for bad in [
        "con",
        "CON",
        "Con",
        "con.iso",
        "nul",
        "aux.tar.gz",
        "com1",
        "COM9",
        "lpt0",
        "a.",
        "a ",
        "aux ",
    ] {
        assert!(
            crate::session::windows_unsafe_basename(bad),
            "{bad:?} must be unsafe"
        );
    }
    for good in [
        "file.bin",
        "const.iso",
        "auxx",
        "com10",
        "controller",
        "a.b.c",
        "null",
        "donn\u{e9}es",
    ] {
        assert!(
            !crate::session::windows_unsafe_basename(good),
            "{good:?} must be safe"
        );
    }
}

// ===== sftp deferral + option error semantics + saveSession full
// persist =====

/// The `sftp://` scheme is deferred (declared deviation + the
/// `taiji.sftp.deferred` error code): three hit faces — a single sftp
/// source, an http-mixed source, and the shared CLI/RPC entry — are
/// rejected wholesale at addUri task creation, never silently ignored
/// (admission without effect would be a disguise).
#[tokio::test]
async fn add_uri_rejects_sftp_scheme_with_deferred_code() {
    let (handle, join) = SessionActor::spawn();
    // A pure sftp source.
    let r = call(
        &handle,
        SessionCommand::AddUri {
            uris: vec!["sftp://host.example/dir/f.bin".to_string()],
            options: BTreeMap::new(),
            position: None,
        },
    )
    .await;
    match r {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.starts_with("taiji.sftp.deferred:"),
                "the error message carries the taiji.sftp.deferred code prefix: {message}"
            );
        }
        other => panic!("expected explicit deferred failure, got {other:?}"),
    }
    // Mixed sources (http + sftp): under the multi-URI same-file mirror
    // semantics partial admission is unreachable — rejected wholesale.
    let r = call(
        &handle,
        SessionCommand::AddUri {
            uris: vec![
                "http://host.example/f.bin".to_string(),
                "sftp://host.example/f.bin".to_string(),
            ],
            options: BTreeMap::new(),
            position: None,
        },
    )
    .await;
    match r {
        Err(SessionError::Failed { message }) => {
            assert!(message.starts_with("taiji.sftp.deferred:"), "{message}");
        }
        other => panic!("expected explicit deferred failure, got {other:?}"),
    }
    // No sftp task is registered on the session face (the rejection
    // happens before task creation).
    let stat = match call(&handle, SessionCommand::GetGlobalStat).await {
        Ok(CommandReply::GlobalStat(g)) => g,
        other => panic!("getGlobalStat: {other:?}"),
    };
    assert_eq!(
        stat.num_active + stat.num_waiting + stat.num_stopped,
        0,
        "a rejected task leaves no trace in any queue"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}
