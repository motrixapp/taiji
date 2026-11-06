// ---- Event bus: publish-point coverage (reference = the RequestGroupMan
// notifyDownloadEvent call sites + the WebSocketSessionMan six event
// names) ----

/// Drain currently delivered events (the raw material of the
/// non-blocking polling face).
fn drain_events(rx: &mut tokio::sync::broadcast::Receiver<SessionEvent>) -> Vec<SessionEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Poll until `done` holds for a gid's event sequence; returns that
/// gid's events (in kind order).
async fn kinds_until<F>(
    rx: &mut tokio::sync::broadcast::Receiver<SessionEvent>,
    gid: Gid,
    mut done: F,
) -> Vec<EventKind>
where
    F: FnMut(&[EventKind]) -> bool,
{
    let mut acc: Vec<SessionEvent> = Vec::new();
    for _ in 0..300 {
        acc.extend(drain_events(rx));
        let ks: Vec<EventKind> = acc
            .iter()
            .filter(|e| e.gid == gid)
            .map(|e| e.kind)
            .collect();
        if done(&ks) {
            return ks;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("event sequence never reached; got {acc:?} for gid {gid}");
}

/// Start = group activation (RequestGroupMan.cc): addTorrent fillup
/// activation publishes exactly one Start, nothing else.
#[tokio::test]
async fn start_event_published_once_on_activation() {
    let (handle, join) = SessionActor::spawn();
    let mut rx = handle.subscribe_events();
    let dir = temp_dir("ev-start");
    let bytes = build_v2_torrent(&vec![0u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    let ks = kinds_until(&mut rx, gid, |k| !k.is_empty()).await;
    assert_eq!(ks, vec![EventKind::Start], "activation = exactly one Start");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Pause = the pause teardown back to the queue front: pausing an
/// active task publishes one Pause after teardown; the restart branch
/// (changeOption) does not publish — locked by the stability side of
/// the existing change_option tests (no Pause event after restart; see
/// the steady state asserted by
/// change_option_subset_and_restart_semantics).
#[tokio::test]
async fn pause_event_published_on_pause_requeue() {
    let global = GlobalOptions {
        max_concurrent_downloads: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let mut rx = handle.subscribe_events();
    let dir = temp_dir("ev-pause");
    let bytes_a = build_v2_torrent(&vec![1u8; 128 * 1024], &dead_tracker());
    let bytes_b = build_v2_torrent_named(&vec![2u8; 128 * 1024], &dead_tracker(), "v2-b.bin");
    let a = gid_of(&call(&handle, torrent_cmd(bytes_a, &dir)).await);
    let _b = gid_of(&call(&handle, torrent_cmd(bytes_b, &dir)).await);
    assert_eq!(
        call(&handle, SessionCommand::Pause { gid: a.to_string() }).await,
        Ok(CommandReply::Gid(a))
    );
    let ks = kinds_until(&mut rx, a, |k| k.contains(&EventKind::Pause)).await;
    assert_eq!(ks, vec![EventKind::Start, EventKind::Pause]);
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stop = remove's REMOVED teardown (the third executeStopHook branch);
/// forceRemove publishes one Stop directly, and the aborted watcher's
/// late Failed teardown is absorbed by the orphan guard (no fabricated
/// Error appended).
#[tokio::test]
async fn remove_and_force_remove_publish_stop_without_spurious_error() {
    for force in [false, true] {
        let (handle, join) = SessionActor::spawn();
        let mut rx = handle.subscribe_events();
        let dir = temp_dir("ev-remove");
        let bytes = build_v2_torrent(&vec![3u8; 128 * 1024], &dead_tracker());
        let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
        // Wait for activation (Start in hand) before removing.
        kinds_until(&mut rx, gid, |k| !k.is_empty()).await;
        let cmd = if force {
            SessionCommand::ForceRemove {
                gid: gid.to_string(),
            }
        } else {
            SessionCommand::Remove {
                gid: gid.to_string(),
            }
        };
        assert_eq!(call(&handle, cmd).await, Ok(CommandReply::Gid(gid)));
        // The first kinds_until already consumed Start; Stop arrives
        // here and the sequence is exactly one.
        let ks = kinds_until(&mut rx, gid, |k| k.contains(&EventKind::Stop)).await;
        assert_eq!(ks, vec![EventKind::Stop]);
        // The force path: leave a window for the aborted watcher's late
        // events and assert no fabricated Error / duplicate events.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let tail = drain_events(&mut rx);
        assert!(
            tail.iter().all(|e| e.gid != gid),
            "no post-Stop events for removed gid (orphan guard): {tail:?}"
        );
        handle.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Error = the explicit-failure teardown (the second executeStopHook
/// branch): a tr-less magnet ends on the explicit-failure face -> one
/// Error.
#[tokio::test]
async fn error_event_published_on_explicit_failure() {
    let (handle, join) = SessionActor::spawn();
    let mut rx = handle.subscribe_events();
    let magnet = SessionCommand::AddUri {
        uris: vec!["magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into()],
        options: BTreeMap::new(),
        position: None,
    };
    let gid = gid_of(&call(&handle, magnet).await);
    let ks = kinds_until(&mut rx, gid, |k| k.contains(&EventKind::Error)).await;
    assert_eq!(ks, vec![EventKind::Start, EventKind::Error]);
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// BtComplete + Complete = the BT completion double-fire
/// (DefaultPieceStorage.cc's BtComplete first; the FINISHED teardown's
/// Complete second — the event order matches aria2). mini-seeder closed
/// loop + bt-detach-seed-only=true (completion turns to seed-only) + a
/// short seed-time so the seeding period converges (a Detached ->
/// Complete result).
#[tokio::test]
async fn bt_complete_and_complete_double_fire_on_download_done() {
    let content = seed_content();
    let seeder_addr = mini_seeder(content.clone()).await;
    let tracker = loopback_tracker(seeder_addr).await;
    let global = GlobalOptions {
        bt_detach_seed_only: true,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let mut rx = handle.subscribe_events();
    let dir = temp_dir("ev-btcomplete");
    let bytes =
        downloadable_v1_torrent(&content, &format!("http://{tracker}/announce"), "blob.bin");
    // seed-time = 0.01 minutes (0.6s): reset at completion,
    // TimeSeedCriteria satisfied within the 1s tick -> seeding converges
    // immediately (the Detached teardown).
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("seed-time".to_string(), "0.01".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let ks = kinds_until(&mut rx, gid, |k| k.contains(&EventKind::Complete)).await;
    assert_eq!(
        ks,
        vec![EventKind::Start, EventKind::BtComplete, EventKind::Complete],
        "BT completion double-fires: BtComplete then Complete (aria2 order)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Multi-subscriber broadcast via [`SessionHandle::subscribe_events`]
/// (the same face as WS multi-session): both subscribers receive the
/// same event stream.
#[tokio::test]
async fn multiple_subscribers_each_receive_events_via_handle() {
    let (handle, join) = SessionActor::spawn();
    let mut rx_a = handle.subscribe_events();
    let mut rx_b = handle.subscribe_events();
    let dir = temp_dir("ev-multi");
    let bytes = build_v2_torrent(&vec![4u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    for rx in [&mut rx_a, &mut rx_b] {
        let ks = kinds_until(rx, gid, |k| !k.is_empty()).await;
        assert_eq!(ks, vec![EventKind::Start]);
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A slow subscriber never blocks the session (the session half of the
/// bus backpressure rule): the subscriber never reads and the task
/// lifecycle still completes (remove -> visible in tellStopped); the
/// backlog drains afterwards within capacity.
#[tokio::test]
async fn unread_subscriber_never_blocks_session_lifecycle() {
    let (handle, join) = SessionActor::spawn();
    let mut idle_rx = handle.subscribe_events(); // never read
    let dir = temp_dir("ev-slow");
    let bytes = build_v2_torrent(&vec![5u8; 128 * 1024], &dead_tracker());
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
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
    let mut stopped = false;
    for _ in 0..100 {
        let views = status_list(
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
        if views
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Removed)
        {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        stopped,
        "session lifecycle completes with an unread subscriber"
    );
    // The backlog is readable afterwards (Start/Stop both present).
    let ks: Vec<EventKind> = drain_events(&mut idle_rx)
        .iter()
        .filter(|e| e.gid == gid)
        .map(|e| e.kind)
        .collect();
    assert_eq!(ks, vec![EventKind::Start, EventKind::Stop]);
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}
