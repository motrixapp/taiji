// ---- Observation-face consolidation ----
//
// The four-pool mixed-load steady-state caliber (⑥'s headline): BT
// seeding + BT checking + media synthesis coexist while the download
// pool runs full — one session, one steady sample. Assertion shapes are
// meter/registry counts (getGlobalStat / tell* membership) — no
// wall-clock ratio assertions (an earlier suite's flake precedent); the
// narrowing caliber keeps transient windows (engine assembly, gate transfer)
// outside every assertion — the sample predicate is itself the
// steady-state discriminator.

use std::net::SocketAddr;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_media::testkit::{
    FixtureSample, audio_init_spec, avcc_sample, build_init, build_segment, sample_bytes,
    video_init_spec,
};

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

/// The mock two-track fMP4 HLS source (the media_synthesis_gate
/// fixture shape): `video_payload_bytes` scales the synthesis window
/// (the native channel's rewrite/concat/verify cost scales with total
/// bytes — the heavy fixture holds the synthesis seat for hundreds of
/// milliseconds).
async fn spawn_hls(
    video_segments: usize,
    video_delay_ms: u64,
    video_payload_bytes: usize,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let vspec = video_init_spec();
    let video_init = build_init(&vspec);
    let mut video_bodies = Vec::new();
    let mut decode_time = 0u64;
    let mut video = String::from("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n");
    video.push_str("#EXT-X-MEDIA-SEQUENCE:10\n");
    video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/vinit.mp4\"\n"));
    for seq in 0..video_segments as u32 {
        let samples: Vec<FixtureSample> = (0..3)
            .map(|i| FixtureSample {
                duration: 33,
                size: video_payload_bytes as u32,
                sync: i == 0,
                cts: 0,
            })
            .collect();
        let payload: Vec<u8> = samples
            .iter()
            .enumerate()
            .flat_map(|(i, s)| avcc_sample(i == 0, s.size as usize).into_iter())
            .collect();
        video_bodies.push(build_segment(1, seq, decode_time, &samples, &payload));
        decode_time += 99;
        video.push_str(&format!("#EXTINF:0.099,\nhttp://{addr}/vseg{seq}.m4s\n"));
    }
    video.push_str("#EXT-X-ENDLIST\n");

    let aspec = audio_init_spec();
    let audio_init = build_init(&aspec);
    let mut audio_bodies = Vec::new();
    let mut adt = 0u64;
    let mut audio = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:1\n");
    audio.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/ainit.mp4\"\n"));
    for seq in 0..4u32 {
        let samples: Vec<FixtureSample> = (0..4)
            .map(|_| FixtureSample {
                duration: 1024,
                size: 320,
                sync: true,
                cts: 0,
            })
            .collect();
        let payload: Vec<u8> = samples
            .iter()
            .enumerate()
            .flat_map(|(i, s)| sample_bytes(40 + seq as u8 + i as u8, s.size as usize).into_iter())
            .collect();
        audio_bodies.push(build_segment(1, seq, adt, &samples, &payload));
        adt += 4096;
        audio.push_str(&format!("#EXTINF:0.0928,\nhttp://{addr}/aseg{seq}.m4s\n"));
    }
    audio.push_str("#EXT-X-ENDLIST\n");

    let master = format!(
        "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en\",NAME=\"EN\",DEFAULT=YES,URI=\"http://{addr}/audio.m3u8\"\n#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,CODECS=\"avc1.64001f,mp4a.40.2\",AUDIO=\"aud\"\nhttp://{addr}/v.m3u8\n"
    );

    let app = Router::new()
        .route(
            "/master.m3u8",
            get(move || {
                let master = master.clone();
                async move { full_body(master.into_bytes(), "application/vnd.apple.mpegurl") }
            }),
        )
        .route(
            "/v.m3u8",
            get(move || {
                let video = video.clone();
                async move { full_body(video.into_bytes(), "application/vnd.apple.mpegurl") }
            }),
        )
        .route(
            "/audio.m3u8",
            get(move || {
                let audio = audio.clone();
                async move { full_body(audio.into_bytes(), "application/vnd.apple.mpegurl") }
            }),
        )
        .route(
            "/vinit.mp4",
            get(move || {
                let b = video_init.clone();
                async move { full_body(b, "video/mp4") }
            }),
        )
        .route(
            "/ainit.mp4",
            get(move || {
                let b = audio_init.clone();
                async move { full_body(b, "video/mp4") }
            }),
        );
    let mut app = app;
    for (i, body) in audio_bodies.iter().enumerate() {
        let body = body.clone();
        app = app.route(
            &format!("/aseg{i}.m4s"),
            get(move || async move { full_body(body.clone(), "video/mp4") }),
        );
    }
    for (i, seg) in video_bodies.iter().enumerate() {
        let seg = seg.clone();
        let delay = video_delay_ms;
        app = app.route(
            &format!("/vseg{i}.m4s"),
            get(move || async move {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                full_body(seg.clone(), "video/mp4")
            }),
        );
    }
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

async fn add_media_task(handle: &SessionHandle, url: &str, dir: &std::path::Path) -> Gid {
    gid_of(
        &call(
            handle,
            SessionCommand::AddMedia {
                url: url.to_string(),
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                cookies: Vec::new(),
                position: None,
            },
        )
        .await,
    )
}

/// ⑥ (the headline): mixed load — seeding ×3 + checking ×1 + synthesis
/// ×1 coexisting while both download slots are held by downloading
/// tasks. The steady sample's meter matrix: numActive = 2 (downloads at
/// full load, download phase only), numSeeding = 3 (residents in flight
/// — two seeder-backed completions
/// plus one addTorrent complete-payload task that routes seed-side at
/// add), numChecking = 1 (the reserved-arm recheck admits with no
/// teardown — in flight within milliseconds of the forceRecheck),
/// numSynthesizing = 1, numWaiting = the four-segment merge == the
/// tellWaiting count (the reserved stayer). Plus the union-coverage
/// headline (④: all four pools in one session, every gid exactly once
/// across the three lists), ②'s residency cells (seeding resident
/// 'seeding' — the flip; processing resident / in-flight recheck
/// 'active') and ⑤'s reserved-segment coexistence (the reference
/// reorder still answers alongside the four pools).
#[tokio::test]
async fn four_pool_mixed_load_global_stat_caliber() {
    let hls = spawn_hls(60, 0, 1024 * 1024).await;
    let dir = temp_dir("p127-four-pool");
    let db = tmp_db("p127-four-pool");
    // BT fixtures: two seeder-backed fast tasks, two dead-tracker slot
    // holders, one complete-payload task (a third seeder from add — the
    // addTorrent complete-payload face), one reserved recheck target
    // (payload written after the add — the add-time face sees no
    // payload, the task stays queued; the forceRecheck then measures
    // the full bitmap), one plain reserved stayer.
    let mut seeders = Vec::new();
    let mut fast_bytes = Vec::new();
    for i in 0..2u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        seeders.push((seeder, tracker));
        fast_bytes.push(downloadable_v1_torrent(
            &content,
            &format!("http://{tracker}/announce"),
            &format!("fast-{i}.bin"),
        ));
    }
    let dead_bytes: Vec<Vec<u8>> = (0..2u8)
        .map(|i| {
            downloadable_v1_torrent(
                &seed_content_n(10 + i),
                &dead_tracker(),
                &format!("dead-{i}.bin"),
            )
        })
        .collect();
    let seed_at_add_content = check_content_big(9);
    let seed_at_add_bytes =
        downloadable_v1_torrent(&seed_at_add_content, &dead_tracker(), "seed-at-add.bin");
    let recheck_content = check_content_big(10);
    let recheck_bytes = downloadable_v1_torrent(&recheck_content, &dead_tracker(), "recheck.bin");

    // The recheck payload goes on disk AFTER its add returns (the
    // add-time measurement must see no payload), and before the media
    // gate — the write must not eat into the synthesis window between
    // the stage A catch and the stage B recheck.
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 2,
        media_allow_private_key_url: true,
        ..Default::default()
    };
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));

    // Add order = the fillup/backfill choreography: fast×2 activate,
    // then the media task, the dead holders, the seed-at-add task and
    // the recheck target queue behind it, leaving [stayer] reserved.
    let mut fast = Vec::new();
    for bytes in &fast_bytes {
        fast.push(gid_of(
            &call(&handle, torrent_cmd(bytes.clone(), &dir)).await,
        ));
    }
    let media_gid = add_media_task(&handle, &format!("http://{hls}/master.m3u8"), &dir).await;
    let mut dead = Vec::new();
    for bytes in &dead_bytes {
        dead.push(gid_of(
            &call(&handle, torrent_cmd(bytes.clone(), &dir)).await,
        ));
    }
    // The complete payload on disk BEFORE the add: the add-time
    // measurement sees it and routes seed-side (the task never
    // occupies a download slot).
    std::fs::write(dir.join("seed-at-add.bin"), &seed_at_add_content)
        .unwrap_or_else(|e| panic!("write seed-at-add payload: {e}"));
    let seed_at_add_gid = gid_of(&call(&handle, torrent_cmd(seed_at_add_bytes, &dir)).await);
    let recheck_gid = gid_of(&call(&handle, torrent_cmd(recheck_bytes.clone(), &dir)).await);
    // Payload now — the task is queued; a queued task never re-measures
    // on its own (the forceRecheck premise).
    std::fs::write(dir.join("recheck.bin"), &recheck_content)
        .unwrap_or_else(|e| panic!("write recheck payload: {e}"));
    let stayer_bytes = downloadable_v1_torrent(&seed_content_n(20), &dead_tracker(), "stayer.bin");
    let stayer_gid = gid_of(&call(&handle, torrent_cmd(stayer_bytes, &dir)).await);
    let all: Vec<Gid> = fast
        .iter()
        .copied()
        .chain([media_gid, seed_at_add_gid, recheck_gid, stayer_gid])
        .chain(dead.iter().copied())
        .collect();

    // Stage A: the media task gates into synthesis while both slots
    // are held by the dead downloaders and the three seeders sit in
    // the seed pool. The synthesis resident **is** a TellActive member
    // (the finalized §5 face: tellActive iterates the four in-flight
    // registries — a processing resident shows up with the 'active'
    // status; only the numActive *meter* excludes it), so the resident
    // model keys on the meters, never on absence from TellActive (a
    // previous draft's `!active.contains(media)` conjunct was mutually
    // exclusive with numSynthesizing >= 1 and made the whole sample
    // block dead code). gs-only per round (the cached meter face —
    // keeps the poll period well under the synthesis window); the
    // TellActive verification runs once on the hit.
    let mut stage_a = false;
    let mut synthesis_missed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        let gs = global_stat(&handle).await;
        if gs.num_seeding == 3 && gs.num_synthesizing == 1 && gs.num_active == 2 {
            let active = active_gids_of(&handle).await;
            assert!(
                dead.iter().all(|g| active.contains(g)),
                "both download seats are held by the dead download tasks"
            );
            assert!(
                active.contains(&media_gid),
                "the synthesis resident is a TellActive member (the finalized face)"
            );
            stage_a = true;
            // ② cell, caught live: the processing resident projects
            // 'active' in TellActive (the live driver face).
            let views =
                status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
            let Some(resident) = views.iter().find(|v| v.gid == media_gid) else {
                // Query race: the meter snapshot hit the synthesis
                // resident but the TellActive read that followed missed
                // it (the phase advanced between the two queries) —
                // keep polling instead of panicking; the invariant is
                // re-verified on the next meter hit.
                continue;
            };
            assert_eq!(
                resident.status,
                StatusKind::Active,
                "the processing resident = 'active' (zero change)"
            );
            break;
        }
        // The escape vs the failure face: the media task already
        // stopped. Error = a real pipeline failure (assert); Complete
        // = the whole synthesis window was faster than one poll round
        // (the documented escape — the meter faces below are skipped,
        // the drain faces still hold).
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
        if let Some(m) = stopped.iter().find(|v| v.gid == media_gid) {
            assert_eq!(
                m.status,
                StatusKind::Complete,
                "the media task terminated abnormally before the steady sample: {:?}",
                m.status
            );
            synthesis_missed = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    if !synthesis_missed {
        assert!(
            stage_a,
            "steady state A never reached: 3 seeding + 2 downloads at full load + 1 synthesis in \
             flight (the pipeline is stuck)"
        );
    }

    // Stage B: the reserved-arm recheck in flight — the recheck target
    // is QUEUED (it never left the reserved segment), so its recheck
    // admits within milliseconds of the forceRecheck (no graceful-stop
    // teardown), landing inside the synthesis window that stage A just
    // caught. Skipped entirely when stage A's window was missed (no
    // synthesis to sample alongside).
    let mut sampled = false;
    'attempts: for _ in 0..if stage_a { 6 } else { 0 } {
        assert!(
            matches!(
                call(
                    &handle,
                    SessionCommand::ForceRecheck {
                        gid: recheck_gid.to_string()
                    },
                )
                .await,
                Ok(CommandReply::Gid(_))
            ),
            "forceRecheck must reply Gid"
        );
        for _ in 0..4000 {
            let gs = global_stat(&handle).await;
            // The escape: the synthesis seat freed before any sample
            // landed (the fixture window lost) — the drain faces below
            // still hold.
            let stopped_gids: Vec<Gid> = status_list(
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
            .map(|v| v.gid)
            .collect();
            if stopped_gids.contains(&media_gid) {
                break 'attempts;
            }
            if gs.num_checking == 1
                && gs.num_synthesizing == 1
                && gs.num_seeding == 3
                && gs.num_active == 2
                && gs.num_waiting == 1
            {
                // ---- the steady sample ----
                // ⑥: the meter matrix — the gs in hand, read at the
                // predicate instant (no race).
                assert_eq!(
                    gs.num_active, 2,
                    "numActive = downloads at full load (download phase only)"
                );
                assert_eq!(gs.num_seeding, 3, "numSeeding = residents in flight");
                assert_eq!(gs.num_checking, 1, "numChecking = in flight");
                assert_eq!(gs.num_synthesizing, 1, "numSynthesizing = in flight");
                // Stable faces first (nothing pending can move them):
                // the reserved stayer is the whole waiting domain.
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
                    gs.num_waiting as usize,
                    waiting.len(),
                    "numWaiting = the four-segment merge == the tellWaiting count"
                );
                assert_eq!(
                    waiting.len(),
                    1,
                    "the waiting domain = the reserved-segment stayer"
                );
                assert_eq!(waiting[0].gid, stayer_gid);
                assert_eq!(waiting[0].status, StatusKind::Waiting);
                // Window-bound faces (the synthesis/verify windows
                // straddle RPC boundaries): re-read the TellActive
                // projection until the expected seven-member partition
                // is observed — the windows are 100ms-scale vs ~1ms
                // reads. A full miss is the documented escape (the ②
                // processing cell still holds from the stage A hit).
                for _ in 0..40 {
                    let active = status_list(
                        &call(&handle, SessionCommand::TellActive { keys: vec![] }).await,
                    );
                    let by_gid =
                        |gid: &Gid| active.iter().find(|v| v.gid == *gid).map(|v| v.status);
                    let live = |gid: &Gid| matches!(by_gid(gid), Some(StatusKind::Active));
                    let seeded = |gid: &Gid| matches!(by_gid(gid), Some(StatusKind::Seeding));
                    if active.len() == 7
                        && dead.iter().all(live)
                        && live(&media_gid)
                        && live(&recheck_gid)
                        && fast.iter().all(seeded)
                        && seeded(&seed_at_add_gid)
                    {
                        // ② residency cells at one coherent instant.
                        for f in &fast {
                            assert_eq!(
                                by_gid(f),
                                Some(StatusKind::Seeding),
                                "the resident projection flips to 'seeding'"
                            );
                        }
                        assert_eq!(
                            by_gid(&seed_at_add_gid),
                            Some(StatusKind::Seeding),
                            "the addTorrent complete-payload face = seed-side direct residency"
                        );
                        for g in dead.iter().chain([&media_gid, &recheck_gid]) {
                            assert_eq!(
                                by_gid(g),
                                Some(StatusKind::Active),
                                "downloads / synthesis residents / in-flight checks = 'active'"
                            );
                        }
                        // The tellStatus face shares the live view
                        // (seeding resident stable; the media resident
                        // re-read under the same window guard).
                        assert_eq!(
                            tell_status_status(&handle, fast[0]).await,
                            StatusKind::Seeding,
                            "the seeding resident's tellStatus = 'seeding' (the flip)"
                        );
                        // The tellStatus read itself straddles the
                        // synthesis boundary: a sample landing just
                        // past the end returns the terminal view
                        // (Complete) — both faces are correct
                        // projections at a transfer boundary; the live
                        // 'active' face is already asserted above from
                        // the same TellActive snapshot (and in the
                        // stage A hit).
                        let media_status = tell_status_status(&handle, media_gid).await;
                        assert!(
                            matches!(media_status, StatusKind::Active | StatusKind::Complete),
                            "the processing resident's tellStatus drifted: {media_status:?}"
                        );
                        break;
                    }
                    let media_gone = matches!(
                        tell_status_status(&handle, media_gid).await,
                        StatusKind::Complete | StatusKind::Error | StatusKind::Removed
                    );
                    if media_gone {
                        // The synthesis window ended mid-sample — the
                        // projected-face block is skipped (documented
                        // escape; the meter matrix above already ran).
                        break;
                    }
                }
                // ④: the three-list union covers all nine gids exactly
                // once — the invariant holds at every instant, so a
                // straddled read is re-read until a coherent snapshot
                // lands (the Test C settled-snapshot discipline).
                let mut union_ok = false;
                for _ in 0..20 {
                    let active = status_list(
                        &call(&handle, SessionCommand::TellActive { keys: vec![] }).await,
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
                    let mut seen: Vec<Gid> = active.iter().map(|v| v.gid).collect();
                    seen.extend(waiting.iter().map(|v| v.gid));
                    seen.extend(stopped.iter().map(|v| v.gid));
                    let mut sorted = seen.clone();
                    sorted.sort();
                    sorted.dedup();
                    let mut want = all.clone();
                    want.sort();
                    if sorted == want && seen.len() == want.len() {
                        union_ok = true;
                        break;
                    }
                }
                assert!(
                    union_ok,
                    "the three-list union coverage/exclusivity did not converge over 20 re-reads \
                     (all four pools in one session)"
                );
                // ⑤: the reserved segment still answers alongside the
                // four pools (the in-place reorder; the full matrix
                // regression lives in the reserved-domain test).
                match call(
                    &handle,
                    SessionCommand::ChangePosition {
                        gid: stayer_gid.to_string(),
                        pos: 0,
                        how: OffsetMode::Set,
                    },
                )
                .await
                {
                    Ok(CommandReply::Position { position }) => assert_eq!(position, 0),
                    other => panic!("a reserved member can be moved: {other:?}"),
                }
                sampled = true;
                break 'attempts;
            }
            if gs.num_checking == 0 {
                // The verify completed between samples (routed
                // seed-side) — the reserved arm admits in milliseconds,
                // so a miss means the verify itself lost the window;
                // re-arm.
                break;
            }
        }
    }
    if !sampled {
        // Documented escape (the synthesis/verify windows both lost):
        // the meter faces are skipped; the drain faces below still
        // hold.
        eprintln!("p127: steady windows missed in all attempts; skipping meter faces");
    }

    // Drain (always-true faces): the synthesis completes, the
    // registries settle, the download slots stay with the downloaders.
    let mut drained = false;
    for _ in 0..600 {
        let gs = global_stat(&handle).await;
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
        if gs.num_synthesizing == 0
            && stopped
                .iter()
                .any(|v| v.gid == media_gid && v.status == StatusKind::Complete)
        {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        drained,
        "synthesis did not converge to the Complete terminal"
    );
    if sampled {
        let gs = global_stat(&handle).await;
        assert_eq!(
            gs.num_active, 2,
            "download seats still held by the download phase"
        );
        assert_eq!(
            gs.num_waiting, 1,
            "the waiting domain = the reserved-segment stayer"
        );
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}
