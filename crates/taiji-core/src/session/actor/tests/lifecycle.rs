// ---- Frozen seam and method face ----

#[test]
fn method_surface_is_frozen() {
    // The message enum covers every SPEC §8.2 method name. The list
    // below is verbatim from docs/SPEC.md §8.2 plus addMetalink
    // (feature gate — with the `metalink` feature off the whole name is
    // not registered; `cargo test -p taiji-core` exercises the off
    // half).
    const SPEC_8_2: &[&str] = &[
        "addUri",
        "addTorrent",
        "tellStatus",
        "getFiles",
        "getPeers",
        "getServers",
        "getUris",
        "pause",
        "forcePause",
        "unpause",
        // forceRecheck: on-disk recheck scheduling (absent from the
        // upstream/fork registration face — a taiji capability
        // extension; dual naming in the RPC_METHODS note).
        "forceRecheck",
        "pauseAll",
        // forcePauseAll (closed out; the reference's registered name
        // enters the promised table — mechanical completion follows the
        // same note rule).
        "forcePauseAll",
        "unpauseAll",
        "remove",
        "forceRemove",
        "purgeDownloadResult",
        "removeDownloadResult",
        "changeUri",
        // changePosition (closed out; the reference's registered name
        // enters the promised table — mechanical completion follows the
        // same note rule).
        "changePosition",
        "changeOption",
        // getOption (closed out; the reference's registered name enters
        // the promised table — mechanical completion follows the same
        // note rule).
        "getOption",
        "changeGlobalOption",
        "getGlobalOption",
        "getGlobalStat",
        "getVersion",
        "getSessionInfo",
        "tellActive",
        "tellWaiting",
        "tellStopped",
        "saveSession",
        "shutdown",
        "forceShutdown",
        "system.listMethods",
        "system.multicall",
        "system.listNotifications",
        #[cfg(feature = "metalink")]
        "addMetalink",
        "taiji.moveStorage",
        "taiji.renameFile",
        // (the taiji.* extension namespace, per the SPEC §8.2 extension
        // rules — this table grows with the method face, and the SPEC
        // §8.2 sync is handled by the scheduler's decision face).
        // Resolution: the taiji.* face is uniformly camelCase; the six
        // old snake_case names were renamed without aliases.
        "taiji.banAddr",
        "taiji.unbanAddr",
        "taiji.listBans",
        // (the taiji.* extension namespace; a set write face / a
        // read-only get — mechanical completion follows the same note
        // rule).
        "taiji.setSchedulerPolicy",
        "taiji.getSchedulerPolicy",
        // (the taiji.* namespace; the file multi-level priority write
        // face — mechanical completion follows the same note).
        "taiji.setFilePriority",
        // (the taiji.* extension namespace; the stream-while-downloading
        // playhead write face — mechanical completion follows the same
        // note rule).
        "taiji.setStreamingPlayhead",
        // (the taiji.* namespace; the disk_tier face get query / set
        // write + the parameterless getCapabilities query — mechanical
        // completion follows the same note).
        "taiji.notifyNetworkChange",
        "taiji.getTorrentMetadata",
        "taiji.confirmTorrentSelection",
        "taiji.getHttpOutput",
        "taiji.finalizeHttp",
        "taiji.getDiskTier",
        "taiji.setDiskTier",
        "taiji.getCapabilities",
        // (the taiji.* namespace; the dynamic tracker edit write face —
        // mechanical completion follows the same note).
        "taiji.addTracker",
        "taiji.removeTracker",
        // (the taiji.* namespace; the task-level cookie pass-through
        // write face — mechanical completion follows the same note).
        "taiji.addUriWithCookies",
        "taiji.setTaskCookies",
        // (the taiji.* namespace; the createTorrent write face —
        // mechanical completion follows the same note).
        "taiji.createTorrent",
        // (the taiji.* namespace; the media line's four methods:
        // addMedia/probeMedia write faces (probe =
        // the action face), getMediaFormats the read-only query,
        // stopRecording the registration+dispatch face whose LIVE
        // execution lands in 0.4 — mechanical completion follows the
        // same note rule).
        "taiji.addMedia",
        "taiji.probeMedia",
        "taiji.getMediaFormats",
        "taiji.stopRecording",
        // (the taiji.* namespace; the media line's fifth face —
        // the destructive archive clear, read_only=false —
        // the frozen-list extension rides the same review rule).
        "taiji.clearMediaArchive",
    ];
    assert_eq!(RPC_METHODS.len(), SPEC_8_2.len());
    for (got, want) in RPC_METHODS.iter().zip(SPEC_8_2) {
        assert_eq!(got, want, "RPC surface drifted from SPEC §8.2");
    }
}

#[tokio::test]
async fn get_version_roundtrip_smoke() {
    let (handle, _join) = SessionActor::spawn();
    match call(&handle, SessionCommand::GetVersion).await {
        Ok(CommandReply::Version { version }) => {
            assert!(version.starts_with("taiji/"), "frozen prefix: {version}");
        }
        other => panic!("getVersion must return Version, got {other:?}"),
    }
}

/// Unimplemented methods (multicall etc., handled at the RPC layer)
/// uniformly answer NotSupported with the method name verbatim from the
/// RPC surface. The query face and saveSession are both implemented
/// (moved out of this list; without a persistence injection saveSession
/// fails explicitly — see the save_session case).
#[tokio::test]
async fn unimplemented_commands_still_answer_not_supported() {
    let (handle, join) = SessionActor::spawn();
    let g = || GidAllocator::new().allocate();
    // Once implemented, tellStatus/getFiles/getPeers/getServers/
    // getUris/getGlobalStat have real semantics (covered separately by
    // the local-seeder closed-loop tests); the remaining unimplemented
    // face is below.
    let cases: Vec<(SessionCommand, &'static str)> = vec![
        (SessionCommand::SystemListMethods, "system.listMethods"),
        (SessionCommand::SystemMulticall, "system.multicall"),
        (
            SessionCommand::SystemListNotifications,
            "system.listNotifications",
        ),
    ];
    for (cmd, method) in cases {
        match call(&handle, cmd).await {
            Err(SessionError::NotSupported { method: m }) => {
                assert_eq!(m, method, "method name must match RPC surface verbatim");
                assert!(
                    RPC_METHODS.contains(&m),
                    "{m} must be on the frozen surface"
                );
            }
            other => panic!("{method} must answer NotSupported, got {other:?}"),
        }
    }
    // addMetalink: no SessionCommand variant (execution lives at the
    // RPC consumption seam; the parser face taiji-metalink stays out of
    // the core dependency graph). Its registration state is pinned by
    // method_surface_is_frozen's dual-feature list.
    // taiji.moveStorage is a real capability now: the gid
    // argument first goes through expandUnique (the aria2 str2Gid
    // pre-step order) — an unknown GID answers not found first; a
    // known GID enters the move face (covered separately by the
    // move_storage tests). renameFile keeps the always-not_supported
    // capability face with the same gid-first order.
    match call(
        &handle,
        SessionCommand::MoveStorage {
            gid: g().to_string(),
            dir: "/tmp".into(),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("is not found"), "{message}");
        }
        other => panic!("unknown gid must fail resolution, got {other:?}"),
    }
    let dir = temp_dir("p2ext");
    let bytes = build_v2_torrent(&vec![0u8; 128 * 1024], &dead_tracker());
    let live = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    match call(
        &handle,
        SessionCommand::RenameFile {
            gid: live.to_string(),
            old_path: "a".into(),
            new_path: "b".into(),
        },
    )
    .await
    {
        Err(SessionError::NotSupported { method: m }) => {
            assert!(RPC_METHODS.contains(&m), "{m} must be on the surface");
        }
        other => panic!("renameFile must answer NotSupported, got {other:?}"),
    }
    handle.shutdown().await;
    let joined = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(joined.is_ok(), "actor must exit after shutdown command");
}

#[tokio::test]
async fn shutdown_command_propagates_and_exits_within_budget() {
    let (handle, join) = SessionActor::spawn();
    let t0 = Instant::now();
    handle.shutdown().await;
    let joined = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(
        joined.is_ok(),
        "session actor must exit within 1s of shutdown"
    );
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
}

#[tokio::test]
async fn handle_drop_gracefully_stops_actor() {
    let (handle, join) = SessionActor::spawn();
    drop(handle);
    let joined = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(joined.is_ok(), "actor must exit within 1s of handle drop");
}

#[tokio::test]
async fn get_session_info_is_random_hex_and_per_session() {
    let (a, _ja) = SessionActor::spawn();
    let (b, _jb) = SessionActor::spawn();
    let id_a = match call(&a, SessionCommand::GetSessionInfo).await {
        Ok(CommandReply::SessionInfo { session_id }) => session_id,
        other => panic!("expected SessionInfo, got {other:?}"),
    };
    let id_b = match call(&b, SessionCommand::GetSessionInfo).await {
        Ok(CommandReply::SessionInfo { session_id }) => session_id,
        other => panic!("expected SessionInfo, got {other:?}"),
    };
    assert_eq!(id_a.len(), 32, "16 random bytes → 32 hex chars");
    assert!(id_a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(id_a, id_b, "session ids must be random per session");
}
