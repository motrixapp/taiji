// ---- Seed pool ----
//
// Acceptance faces (①–⑨): mixed-load slot isolation, the
// SeedingStarted/Ended two-order terminal, the park/unpark round trip,
// 'seeding'-row restart routing by the measured bitmap, the steady-state
// sampling discipline, the transition-edge sweep, and the seed-budget
// boundary. Assertion shapes are meter/registry counts (getGlobalStat
// numActive, tellActive/tellWaiting membership) — no wall-clock ratio
// assertions (an earlier suite's flake precedent; banned here).

/// Distinct 2-piece content per task (mini_seeder serves exactly two
/// pieces — its bitfield frame is the hardcoded 0xC0).
fn seed_content_n(n: u8) -> Vec<u8> {
    let pat: Vec<u8> = format!("taiji-p124-seed{n}-").into_bytes();
    pat.iter()
        .cycle()
        .take(2 * SEED_PIECE_LEN as usize)
        .copied()
        .collect()
}

/// A task whose measured download is complete, tellStatus-visible.
async fn download_complete(handle: &SessionHandle, gid: Gid) -> bool {
    matches!(
        call(
            handle,
            SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: vec![],
            },
        )
        .await,
        Ok(CommandReply::TorrentStatus(v))
        if v.total_length == 2 * SEED_PIECE_LEN && v.completed_length == v.total_length
    )
}

async fn active_gids_of(handle: &SessionHandle) -> Vec<Gid> {
    status_list(&call(handle, SessionCommand::TellActive { keys: vec![] }).await)
        .into_iter()
        .map(|v| v.gid)
        .collect()
}

async fn num_active(handle: &SessionHandle) -> u64 {
    match call(handle, SessionCommand::GetGlobalStat).await {
        Ok(CommandReply::GlobalStat(stat)) => stat.num_active,
        _ => u64::MAX,
    }
}

async fn waiting_views(handle: &SessionHandle) -> Vec<TorrentStatusView> {
    status_list(
        &call(
            handle,
            SessionCommand::TellWaiting {
                offset: 0,
                num: u32::MAX,
                keys: vec![],
            },
        )
        .await,
    )
}

/// The two-state default + the read-side clamp (§4.1.2): is not
/// merged at implementation time -> 16; [0,4096] clamped at the single
/// consumption point; 0 = unlimited passes through.
#[test]
fn seed_budget_default_two_state_and_clamp() {
    let g = GlobalOptions::default();
    assert_eq!(
        g.max_concurrent_seeds, 16,
        "the default converges to 16 while  is unmerged"
    );
    assert_eq!(g.seed_budget(), 16);
    let unlimited = GlobalOptions {
        max_concurrent_seeds: 0,
        ..Default::default()
    };
    assert_eq!(unlimited.seed_budget(), 0, "0 = unlimited passes through");
    let over = GlobalOptions {
        max_concurrent_seeds: 5000,
        ..Default::default()
    };
    assert_eq!(over.seed_budget(), 4096, "the domain ceiling 4096 clamps");
}

/// Measured-bitmap completeness matrix (§4.1.4's routing predicate).
#[test]
fn progress_row_complete_matrix() {
    use crate::metainfo::{MetaFile, TorrentMeta};
    use taiji_store::persist::TorrentProgressRow;
    let mk_meta = |files: &[(u64, bool)]| TorrentMeta {
        identity: crate::metainfo::TorrentIdentity {
            v1: Some([1; 20]),
            v2: None,
        },
        kind: taiji_bt::filetree::SwarmKind::V1Only,
        piece_length: 16 * 1024,
        files: files
            .iter()
            .map(|&(len, pad)| MetaFile {
                path: std::path::PathBuf::from("f.bin"),
                length: len,
                padding: pad,
                pieces_root: None,
                piece_layer: None,
                v1_offset: Some(0),
            })
            .collect(),
    };
    let row = |piece_len: i64, v1: Option<Vec<u8>>, v2: Option<Vec<u8>>| TorrentProgressRow {
        gid: "aa".into(),
        piece_length: piece_len,
        v1_bitfield: v1,
        v2_file_bits: v2,
        upload_at_startup: 0,
        downloaded_total: 0,
        uploaded_total: 0,
        active_time_s: 0,
        seed_time_s: 0,
    };
    let meta = mk_meta(&[(2 * 16 * 1024, false)]);
    // v1: full / partial / absent / piece-length mismatch.
    assert!(progress_row_complete(
        &meta,
        &row(16 * 1024, Some(vec![0xC0]), None)
    ));
    assert!(!progress_row_complete(
        &meta,
        &row(16 * 1024, Some(vec![0x40]), None)
    ));
    assert!(!progress_row_complete(&meta, &row(16 * 1024, None, None)));
    assert!(!progress_row_complete(
        &meta,
        &row(64 * 1024, Some(vec![0xC0]), None)
    ));
    // v2: a 2-piece file's segment fully set / one bit clear / a stale
    // stored count below the expected piece count / a missing segment.
    let v2_seg = |count: u32, bits: u8| {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&count.to_be_bytes());
        b.push(bits);
        b
    };
    assert!(progress_row_complete(
        &meta,
        &row(16 * 1024, None, Some(v2_seg(2, 0xC0)))
    ));
    assert!(!progress_row_complete(
        &meta,
        &row(16 * 1024, None, Some(v2_seg(2, 0x40)))
    ));
    assert!(!progress_row_complete(
        &meta,
        &row(16 * 1024, None, Some(v2_seg(1, 0x80)))
    ));
    // A segment set whose file_index 0 entry is missing (only an
    // alien file_index 1 segment present) = the real file is
    // unmeasured = incomplete.
    let alien_only = {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&2u32.to_be_bytes());
        b.push(0xC0);
        b
    };
    assert!(!progress_row_complete(
        &meta,
        &row(16 * 1024, None, Some(alien_only))
    ));
    // A zero-length file never blocks completeness.
    let meta_z = mk_meta(&[(2 * 16 * 1024, false), (0, false)]);
    assert!(progress_row_complete(
        &meta_z,
        &row(16 * 1024, Some(vec![0xC0]), None)
    ));
}

/// ① + ⑤: mixed load — three completions flip to seeding residents,
/// two dead-tracker downloads hold the download slots; the download-slot
/// count (numActive, seeding excluded) never exceeds
/// max-concurrent-downloads and is saturated in the steady state, the
/// third download starting as soon as the first completion released its
/// slot. Sampled at every poll iteration (the invariant holds at each
/// meter reading; transient assembly windows are never inside an
/// assertion because the sampled faces are post-transfer states).
#[tokio::test]
async fn mixed_load_seeding_does_not_occupy_download_slots() {
    // Three fast (seeder-backed) torrents + two dead-tracker downloads.
    let mut seeders = Vec::new();
    let mut torrents = Vec::new();
    for i in 0..3u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        seeders.push((seeder, tracker));
        let dir = temp_dir(&format!("p124-mix-{i}"));
        torrents.push((
            downloadable_v1_torrent(
                &content,
                &format!("http://{tracker}/announce"),
                &format!("blob-{i}.bin"),
            ),
            dir,
        ));
    }
    let global = GlobalOptions {
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let mut fast = Vec::new();
    for (bytes, dir) in &torrents {
        let gid = gid_of(&call(&handle, torrent_cmd(bytes.clone(), dir)).await);
        fast.push(gid);
    }
    let mut dead = Vec::new();
    for i in 0..2u8 {
        let dir = temp_dir(&format!("p124-mix-dead{i}"));
        let bytes = downloadable_v1_torrent(
            &seed_content_n(10 + i),
            &dead_tracker(),
            &format!("dead-{i}.bin"),
        );
        let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
        dead.push(gid);
    }
    // Convergence: all three fast tasks complete and seed; both dead
    // tasks hold the two download slots; the slot count stays within
    // the budget at every sample.
    let mut steady = false;
    for _ in 0..600 {
        let active = active_gids_of(&handle).await;
        let n = num_active(&handle).await;
        assert!(n <= 2, "download seats always <= 2 (sampled {n})");
        let mut fast_seeding = 0;
        for g in &fast {
            if download_complete(&handle, *g).await {
                fast_seeding += 1;
            }
        }
        let dead_active = dead.iter().filter(|g| active.contains(g)).count();
        if fast_seeding == 3 && dead_active == 2 && active.len() == 5 && n == 2 {
            // tellActive projects the seeding residents alongside the
            // downloads (active semantics); the *slot* count (numActive)
            // counts only the two downloads.
            steady = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        steady,
        "steady state never reached: 3 seeding + 2 downloads at full load"
    );
    // The parked face is empty and no completion entered results (all
    // three seed on).
    assert!(waiting_views(&handle).await.is_empty());
    match call(
        &handle,
        SessionCommand::TellStopped {
            offset: 0,
            num: u32::MAX,
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::StatusList(v)) => {
            assert!(v.is_empty(), "seeding residents never enter results")
        }
        other => panic!("tellStopped: {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
}

/// ② (the live order) + ⑧ (the SeedingStarted edge): with a short
/// seed-time (0.05 min = 3s, the events.rs convergence precedent —
/// seed-ratio 0 here means *no* criteria, i.e. seed forever) a completed
/// task transfers to the seed pool (residence observed: tellActive-visible
/// while the download-slot meter reads zero), the engine's SeedCheck then
/// breaks with SeedStopped, and the terminal is Complete + results with
/// both registries empty. The short seed window pins the live
/// SeedingStarted-before-Ended order; the Ended-first order is pinned
/// table-driven in queue.rs —
/// begin_seeding_releases_slot_and_is_idempotent's retire-then-late-
/// transfer rows (both orders share one terminal; see §4.1.6).
#[tokio::test]
async fn seeding_transfer_then_seed_stop_completes_with_results() {
    let content = seed_content_n(0);
    let seeder = mini_seeder(content.clone()).await;
    let tracker = loopback_tracker(seeder).await;
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("p124-seedstop");
    let bytes = downloadable_v1_torrent(&content, &format!("http://{tracker}/announce"), "s.bin");
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes,
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("seed-time".to_string(), "0.05".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    // Seeding residence observed: the completed task is tellActive-visible
    // (live engine) while the download-slot meter reads zero — the
    // seeding steady-state signature. The 3s seed window gives the poll
    // loop ~60 samples inside it (§9's seeding-residency sampling face).
    let mut saw_seeding = false;
    // Terminal: Complete in results; both pools empty. The in-loop meter
    // only bounds the slot count (the single task may legitimately hold
    // its own download slot until the SeedingStarted transfer lands; the
    // completion→transfer consumption window is the declared transient —
    // (transient windows never enter assertions). The zero-slot steady state is asserted at the
    // terminal, where both pools have drained.
    let mut done = false;
    for _ in 0..600 {
        if !saw_seeding {
            let active = active_gids_of(&handle).await;
            saw_seeding = active.contains(&gid) && num_active(&handle).await == 0;
        }
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
        if let Some(v) = stopped.iter().find(|v| v.gid == gid) {
            assert_eq!(v.status, StatusKind::Complete, "SeedStopped -> Complete");
            assert_eq!(v.completed_length, 2 * SEED_PIECE_LEN);
            done = true;
            break;
        }
        assert!(
            num_active(&handle).await <= 1,
            "a single task's download seat is at most its own"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        done,
        "the seeding close-out never reached the Complete terminal"
    );
    assert!(
        saw_seeding,
        "the seeding-residency signature was never observed (tellActive yes + numActive 0)"
    );
    assert!(
        num_active(&handle).await == 0,
        "download seats drop to zero at the terminal"
    );
    assert!(
        active_gids_of(&handle).await.is_empty(),
        "both the active and seeding terminal faces are empty"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
}

/// ⑨ (budget boundary, live) + ⑧ (seed_wait promotion edge): with
/// max-concurrent-seeds = 1 the second completion parks in seed_wait —
/// visible in tellWaiting with the 'seeding' extended status, occupying
/// no running slot; removing the resident promotes the parked member
/// back into the seed pool without touching the download side. The
/// session is persist-backed: the reactivation engine assembles from the
/// **complete bitmap** the stop teardown persisted (§4.1.2's assembly
/// premise) — the single-connection mini-seeders are dead by promotion
/// time, and a bitmap-less engine would legitimately re-download (no
/// deadlock in production swarms, but not what this test pins).
#[tokio::test]
async fn seed_budget_full_parks_then_promotes_on_release() {
    let db = tmp_db("p124-budget");
    let mut torrents = Vec::new();
    for i in 0..2u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        let dir = temp_dir(&format!("p124-budget-{i}"));
        torrents.push((
            downloadable_v1_torrent(
                &content,
                &format!("http://{tracker}/announce"),
                &format!("b-{i}.bin"),
            ),
            dir,
        ));
    }
    let global = GlobalOptions {
        max_concurrent_seeds: 1,
        ..Default::default()
    };
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let mut gids: Vec<Gid> = Vec::new();
    for (bytes, dir) in &torrents {
        gids.push(gid_of(
            &call(&handle, torrent_cmd(bytes.clone(), dir)).await,
        ));
    }
    // Convergence: exactly one seeding resident, exactly one parked. The
    // in-loop meter only bounds the slots (both tasks legitimately hold
    // their download slots while downloading; the graceful-stop window of
    // the budget-parked task keeps its slot until the Ended consume) —
    // the zero-slot steady state is asserted once the split is observed.
    let mut split = None;
    for _ in 0..600 {
        let active = active_gids_of(&handle).await;
        let resident: Vec<Gid> = gids
            .iter()
            .copied()
            .filter(|g| active.contains(g))
            .collect();
        let waiting = waiting_views(&handle).await;
        let parked: Vec<Gid> = waiting
            .iter()
            .filter(|v| v.status == StatusKind::Seeding)
            .map(|v| v.gid)
            .collect();
        if resident.len() == 1 && parked.len() == 1 {
            // Registry mutual exclusion (the unique-membership slice): the resident is not
            // waiting, the parked is neither tellActive-visible (it left
            // `running` at its Ended — the seed_wait_deferred ∩ running
            // window converges there, the deferred-side clause) nor on
            // the download side; the slot meter reads zero.
            assert!(!waiting.iter().any(|v| resident.contains(&v.gid)));
            assert!(
                !active.contains(&parked[0]),
                "the parked member has left running"
            );
            assert_eq!(
                num_active(&handle).await,
                0,
                "both tasks complete, zero download seats"
            );
            assert!(download_complete(&handle, resident[0]).await);
            split = Some((resident[0], parked[0]));
            break;
        }
        assert!(
            num_active(&handle).await <= 2,
            "the two tasks' download seats are at most their own one each"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let Some((resident, parked)) = split else {
        panic!("under budget 1, 1 resident + 1 parked never formed");
    };
    assert_ne!(resident, parked);
    // Release the seed slot (forceRemove on the resident — the seeding
    // arm's immediate detach): the parked member must reactivate into
    // the seed pool in the same command's pump (release-then-backfill,
    // no idle beat), still without a download slot.
    assert!(
        matches!(
            call(
                &handle,
                SessionCommand::ForceRemove {
                    gid: resident.to_string()
                }
            )
            .await,
            Ok(CommandReply::Gid(_))
        ),
        "forceRemove (the Seeding arm) must reply Gid"
    );
    let mut promoted = false;
    for _ in 0..600 {
        let active = active_gids_of(&handle).await;
        if active.contains(&parked)
            && download_complete(&handle, parked).await
            && num_active(&handle).await == 0
        {
            promoted = true;
            break;
        }
        assert_eq!(
            num_active(&handle).await,
            0,
            "reactivation never goes through a download seat"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        promoted,
        "after the seed seat's release, the seed_wait member did not reactivate immediately"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ③: the park/unpark round trip — pause requeues the seeding resident
/// to the front as paused, unpause reactivates it on the seed side; the
/// download-slot meter reads zero at every sample of the whole round
/// trip. Persist-backed: the unpause engine assembles from the complete
/// bitmap the pause teardown persisted (§4.1.2's assembly premise — the
/// single-connection mini-seeder is dead by unpause time).
#[tokio::test]
async fn park_unpark_round_trip_download_slots_unchanged() {
    let db = tmp_db("p124-park");
    let content = seed_content_n(0);
    let seeder = mini_seeder(content.clone()).await;
    let tracker = loopback_tracker(seeder).await;
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer.clone()),
    );
    let dir = temp_dir("p124-park");
    let bytes = downloadable_v1_torrent(&content, &format!("http://{tracker}/announce"), "p.bin");
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    // Complete → seeding residence.
    let mut seeding = false;
    for _ in 0..600 {
        if download_complete(&handle, gid).await
            && active_gids_of(&handle).await.contains(&gid)
            && num_active(&handle).await == 0
        {
            seeding = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seeding, "never reached the seeding residency");
    // Park: pause → the Ended consume requeues to the front paused.
    assert!(matches!(
        call(
            &handle,
            SessionCommand::Pause {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(_))
    ));
    let mut parked = false;
    for _ in 0..600 {
        assert_eq!(
            num_active(&handle).await,
            0,
            "download seats stay zero throughout the park"
        );
        let waiting = waiting_views(&handle).await;
        if let Some(v) = waiting.iter().find(|v| v.gid == gid) {
            assert_eq!(
                v.status,
                StatusKind::Paused,
                "the seeding resident's pause -> front paused"
            );
            assert_eq!(waiting[0].gid, gid, "requeued to the front");
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(parked, "after pause it did not return to the paused queue");
    // Unpark: reactivate back into the seed pool (no download slot).
    assert!(matches!(
        call(
            &handle,
            SessionCommand::Unpause {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(_))
    ));
    let mut reseeded = false;
    for _ in 0..600 {
        assert_eq!(
            num_active(&handle).await,
            0,
            "download seats stay zero throughout the unpark"
        );
        if download_complete(&handle, gid).await && active_gids_of(&handle).await.contains(&gid) {
            reseeded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        reseeded,
        "after unpause it did not reactivate back into seeding"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ⑧ (the forceRecheck Seeding edge, updated for the check pool): the
/// seed slot releases at request time — a parked member promotes in the
/// command's own pump — and the rechecked task parks into check_pending
/// (the budget-gated face; the Ended is swallowed, no results).
/// With the full measured bitmap the RecheckDone routes to the **seed
/// side** (the checking→seeding edge); the seed budget is held by the
/// promoted member, so the rechecked task lands in seed_wait — visible
/// with the 'seeding' status, occupying no slot of any pool.
#[tokio::test]
async fn force_recheck_seeding_releases_slot_and_parks_member_promotes() {
    let db = tmp_db("p124-frc");
    let mut torrents = Vec::new();
    for i in 0..2u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        let dir = temp_dir(&format!("p124-frc-{i}"));
        torrents.push((
            downloadable_v1_torrent(
                &content,
                &format!("http://{tracker}/announce"),
                &format!("f-{i}.bin"),
            ),
            dir,
        ));
    }
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        max_concurrent_seeds: 1,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let mut gids: Vec<Gid> = Vec::new();
    for (bytes, dir) in &torrents {
        gids.push(gid_of(
            &call(&handle, torrent_cmd(bytes.clone(), dir)).await,
        ));
    }
    // One resident + one parked.
    let mut resident = None;
    for _ in 0..600 {
        let active = active_gids_of(&handle).await;
        let residents: Vec<Gid> = gids
            .iter()
            .copied()
            .filter(|g| active.contains(g))
            .collect();
        let parked = waiting_views(&handle)
            .await
            .iter()
            .filter(|v| v.status == StatusKind::Seeding)
            .count();
        if residents.len() == 1 && parked == 1 {
            resident = Some(residents[0]);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let resident = resident.unwrap_or_else(|| panic!("1 resident + 1 parked never formed"));
    // forceRecheck on the seeding resident: accepted; the seed slot
    // releases immediately (the parked member promotes in the same
    // command's pump_all).
    assert!(matches!(
        call(
            &handle,
            SessionCommand::ForceRecheck {
                gid: resident.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(_))
    ));
    let Some(parked_other) = gids.iter().copied().find(|g| *g != resident) else {
        panic!("the second gid is missing");
    };
    let mut promoted = false;
    for _ in 0..600 {
        if active_gids_of(&handle).await.contains(&parked_other)
            && download_complete(&handle, parked_other).await
            && num_active(&handle).await == 0
        {
            promoted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        promoted,
        "forceRecheck's immediate seed-seat release never triggered the seed_wait promotion"
    );
    // War-2 routing: the rechecked resident's measured bitmap is full →
    // the seed side; the seed slot is held by the promoted member, so it
    // parks in seed_wait ('seeding' in tellWaiting) — no download slot,
    // no results, the transitional check-pending window already drained.
    let mut parked_back = false;
    for _ in 0..600 {
        let waiting = waiting_views(&handle).await;
        if waiting
            .iter()
            .any(|v| v.gid == resident && v.status == StatusKind::Seeding)
        {
            parked_back = true;
            break;
        }
        assert_eq!(
            num_active(&handle).await,
            0,
            "zero download seats throughout routing"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        parked_back,
        "the recheck's full bitmap did not route seed-side (seed budget full -> seed_wait)"
    );
    assert!(
        waiting_views(&handle)
            .await
            .iter()
            .all(|v| v.status != StatusKind::Checking),
        "the check_pending parking window has drained (promotion means in flight)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ④: the 'seeding' row state across restart + the measured-bitmap
/// three-branch routing + the seed_time_s re-anchor (counter
/// continuity — a meter assertion, not a wall-clock ratio).
#[tokio::test]
async fn seeding_restart_routes_by_measured_bitmap_and_reanchors_seed_time() {
    let db = tmp_db("p124-restart");
    let dir = temp_dir("p124-restart");
    let content = seed_content_n(0);
    let seeder_addr = mini_seeder(content.clone()).await;
    let tracker = loopback_tracker(seeder_addr).await;
    let bytes = downloadable_v1_torrent(&content, &format!("http://{tracker}/announce"), "r.bin");

    // Session 1: complete → seeding → a couple of seed seconds →
    // graceful shutdown (the row must persist 'seeding').
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer.clone()),
    );
    let gid = gid_of(&call(&handle, torrent_cmd(bytes.clone(), &dir)).await);
    let mut seeding = false;
    for _ in 0..600 {
        if download_complete(&handle, gid).await && num_active(&handle).await == 0 {
            seeding = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seeding, "session 1 never reached the seeding residency");
    tokio::time::sleep(Duration::from_millis(2100)).await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;

    let state_of = || {
        let conn = ok(rusqlite::Connection::open(&db), "open db");
        ok(
            conn.query_row(
                "SELECT state FROM torrent WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get::<_, String>(0),
            ),
            "state",
        )
    };
    let seed_time_of = || {
        let conn = ok(rusqlite::Connection::open(&db), "open db");
        ok(
            conn.query_row(
                "SELECT seed_time_s FROM torrent_progress WHERE gid = ?1",
                params![gid.to_string()],
                |r| r.get::<_, i64>(0),
            ),
            "seed_time_s",
        )
    };
    assert_eq!(
        state_of(),
        "seeding",
        "the seeding resident's row persists 'seeding' at shutdown"
    );
    let seed_time_1 = seed_time_of();
    assert!(
        seed_time_1 >= 1,
        "the seed clock has accumulated (got {seed_time_1}s)"
    );

    // Session 2 (branch 1: full bitmap + seed slot available): the task
    // reactivates on the seed side — tellActive-visible, no download
    // slot.
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer2.clone()),
    );
    let mut seeded_restart = false;
    for _ in 0..600 {
        if active_gids_of(&handle2).await.contains(&gid)
            && download_complete(&handle2, gid).await
            && num_active(&handle2).await == 0
        {
            seeded_restart = true;
            break;
        }
        assert_eq!(
            num_active(&handle2).await,
            0,
            "restart routing takes no download seat"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        seeded_restart,
        "a full-bitmap 'seeding' row did not route to the seed side"
    );
    // The seed-time baseline re-anchors: after more seed seconds the
    // persisted counter continues from the restored baseline.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin2).await;
    let seed_time_2 = seed_time_of();
    assert!(
        seed_time_2 > seed_time_1,
        "seed_time_s keeps accumulating across restarts ({seed_time_1} -> {seed_time_2})"
    );
    assert_eq!(
        state_of(),
        "seeding",
        "the row still stays 'seeding' at the second shutdown"
    );

    // Branch 2 (bitmap not full): corrupt the measured bitmap → the
    // restart routes to the download side (waiting/active, incomplete).
    {
        let conn = ok(rusqlite::Connection::open(&db), "open db 3");
        ok(
            conn.execute(
                "UPDATE torrent_progress SET v1_bitfield = x'40' WHERE gid = ?1",
                params![gid.to_string()],
            ),
            "corrupt bitmap",
        );
    }
    let (writer3, wjoin3) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 3");
    let (handle3, join3) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer3.clone()),
    );
    let mut download_side = false;
    for _ in 0..600 {
        if let Ok(CommandReply::TorrentStatus(v)) = call(
            &handle3,
            SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: vec![],
            },
        )
        .await
        {
            // 1 of 2 pieces restored: the engine re-downloads the rest
            // (no seeder in this session — it stays incomplete on the
            // download side).
            if v.completed_length == SEED_PIECE_LEN {
                download_side = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        download_side,
        "a partial-bitmap 'seeding' row did not route to the download side"
    );
    assert_eq!(
        state_of(),
        "downloading",
        "the download-side row state was rewritten"
    );
    handle3.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join3).await;
    drop(writer3);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin3).await;
}

/// ④ (branch 3: full bitmap + seed budget full): the excess 'seeding'
/// rows park in seed_wait across restart — visible in tellWaiting with
/// the 'seeding' status, occupying no running slot of any pool.
#[tokio::test]
async fn seeding_restart_overflow_parks_when_budget_full() {
    let db = tmp_db("p124-overflow");
    let mut torrents = Vec::new();
    for i in 0..2u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        let dir = temp_dir(&format!("p124-ov-{i}"));
        torrents.push((
            downloadable_v1_torrent(
                &content,
                &format!("http://{tracker}/announce"),
                &format!("o-{i}.bin"),
            ),
            dir,
        ));
    }
    // Session 1: unlimited budget — both complete and seed.
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer.clone()),
    );
    let mut gids: Vec<Gid> = Vec::new();
    for (bytes, dir) in &torrents {
        gids.push(gid_of(
            &call(&handle, torrent_cmd(bytes.clone(), dir)).await,
        ));
    }
    for gid in &gids {
        let mut seeding = false;
        for _ in 0..600 {
            if download_complete(&handle, *gid).await {
                seeding = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(seeding, "session 1 never completed");
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
    // Session 2: budget narrowed to 1 (narrowing does not preempt — the narrowing
    // converges by parking the excess at restart routing, no eviction).
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global = GlobalOptions {
        max_concurrent_seeds: 1,
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer2.clone()));
    let mut split = false;
    for _ in 0..600 {
        let active = active_gids_of(&handle2).await;
        let residents = gids.iter().filter(|g| active.contains(g)).count();
        let parked = waiting_views(&handle2)
            .await
            .iter()
            .filter(|v| v.status == StatusKind::Seeding)
            .count();
        if residents == 1 && parked == 1 && num_active(&handle2).await == 0 {
            split = true;
            break;
        }
        assert_eq!(
            num_active(&handle2).await,
            0,
            "restart routing takes zero download seats"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        split,
        "restart under budget 1: 1 resident + 1 parked never formed"
    );
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin2).await;
}

// ---- Observation-face consolidation ----

/// Full getGlobalStat view (the ⑥ caliber matrix's read face).
async fn global_stat(handle: &SessionHandle) -> GlobalStatView {
    match call(handle, SessionCommand::GetGlobalStat).await {
        Ok(CommandReply::GlobalStat(g)) => g,
        other => panic!("getGlobalStat: {other:?}"),
    }
}

async fn tell_status_status(handle: &SessionHandle, gid: Gid) -> StatusKind {
    match call(
        handle,
        SessionCommand::TellStatus {
            gid: gid.to_string(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => v.status,
        other => panic!("tellStatus: {other:?}"),
    }
}

/// ② (seeding cells) + ③ + ④'s coverage slice + ⑤'s seed-segment move
/// + ⑥'s getGlobalStat caliber, one mixed BT load (the mixed_load
/// sampling discipline — meter/registry counts, no wall-clock ratios):
/// max-concurrent-seeds = 1 splits three fast completions into one
/// seeding resident + two seed_wait parks; two dead-tracker downloads
/// hold both slots (downloads at full load).
#[tokio::test]
async fn global_stat_caliber_mixed_load_seed_park_and_coverage() {
    let mut seeders = Vec::new();
    let mut torrents = Vec::new();
    for i in 0..3u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        seeders.push((seeder, tracker));
        let dir = temp_dir(&format!("p127-mix-{i}"));
        torrents.push((
            downloadable_v1_torrent(
                &content,
                &format!("http://{tracker}/announce"),
                &format!("blob-{i}.bin"),
            ),
            dir,
        ));
    }
    let global = GlobalOptions {
        max_concurrent_downloads: 2,
        max_concurrent_seeds: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let mut fast = Vec::new();
    for (bytes, dir) in &torrents {
        fast.push(gid_of(
            &call(&handle, torrent_cmd(bytes.clone(), dir)).await,
        ));
    }
    let mut dead = Vec::new();
    for i in 0..2u8 {
        let dir = temp_dir(&format!("p127-mix-dead{i}"));
        let bytes = downloadable_v1_torrent(
            &seed_content_n(10 + i),
            &dead_tracker(),
            &format!("dead-{i}.bin"),
        );
        dead.push(gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await));
    }
    let all: Vec<Gid> = fast.iter().copied().chain(dead.iter().copied()).collect();

    // Converge on the steady split: both dead downloads active (the
    // two slots), exactly one fast task resident in tellActive, the
    // other two parked in tellWaiting ('seeding').
    let mut steady = None;
    for _ in 0..600 {
        let active = active_gids_of(&handle).await;
        let waiting = waiting_views(&handle).await;
        let resident: Vec<Gid> = fast
            .iter()
            .filter(|g| active.contains(g))
            .copied()
            .collect();
        let parked: Vec<Gid> = waiting
            .iter()
            .filter(|v| v.status == StatusKind::Seeding)
            .map(|v| v.gid)
            .collect();
        let dead_active = dead.iter().filter(|g| active.contains(g)).count();
        if resident.len() == 1 && parked.len() == 2 && dead_active == 2 && active.len() == 3 {
            steady = Some((resident[0], parked));
            break;
        }
        assert!(
            num_active(&handle).await <= 2,
            "download seats always <= 2 (sampled {})",
            num_active(&handle).await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let Some((resident, parked)) = steady else {
        panic!(
            "steady state never reached: 1 seeding resident + 2 seed_wait parks + 2 downloads at full load"
        );
    };

    // ⑥: the getGlobalStat caliber at the steady sample.
    let gs = global_stat(&handle).await;
    assert_eq!(
        gs.num_active, 2,
        "numActive = the full download-seat load (seeding counts zero)"
    );
    assert_eq!(
        gs.num_seeding, 1,
        "numSeeding = residents in flight (seed_wait not counted)"
    );
    assert_eq!(gs.num_checking, 0, "no check load");
    assert_eq!(gs.num_synthesizing, 0, "no synthesis load");
    assert_eq!(
        gs.num_waiting, 2,
        "numWaiting = the four-segment merge (seed_wait included)"
    );
    assert_eq!(
        gs.num_waiting as usize,
        waiting_views(&handle).await.len(),
        "numWaiting and tellWaiting share the same caliber"
    );

    // ②: the resident flips to 'seeding' in tellStatus, the same value
    // in tellActive (the shared live face).
    assert_eq!(
        tell_status_status(&handle, resident).await,
        StatusKind::Seeding,
        "the resident's status projection flips = 'seeding'"
    );
    let active_views =
        status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    let res_view = active_views
        .iter()
        .find(|v| v.gid == resident)
        .unwrap_or_else(|| panic!("the resident is in tellActive"));
    assert_eq!(
        res_view.status,
        StatusKind::Seeding,
        "the tellActive resident = 'seeding' (the shared live face)"
    );

    // ② + ③: the parked members project 'seeding' in tellWaiting and
    // never appear in tellActive (table-driven set caliber: the three FIFO
    // members have zero occurrences).
    let waiting = waiting_views(&handle).await;
    for p in &parked {
        let w = waiting
            .iter()
            .find(|v| v.gid == *p)
            .unwrap_or_else(|| panic!("the parked member is visible"));
        assert_eq!(
            w.status,
            StatusKind::Seeding,
            "a seed_wait park = 'seeding'"
        );
        assert!(
            !active_views.iter().any(|v| v.gid == *p),
            "seed_wait members never appear in tellActive"
        );
    }

    // ④ (slice): tellActive ∪ tellWaiting ∪ tellStopped covers all
    // five gids exactly once (mutually exclusive, no duplicates; parked
    // members are never invisible).
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
    let mut seen: Vec<Gid> = active_views.iter().map(|v| v.gid).collect();
    seen.extend(waiting.iter().map(|v| v.gid));
    seen.extend(stopped.iter().map(|v| v.gid));
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    let mut want = all.clone();
    want.sort();
    assert_eq!(sorted, want, "the three-list union covers the full set");
    assert_eq!(
        seen.len(),
        want.len(),
        "the three lists are mutually exclusive, no duplicates"
    );

    // ⑤: the segment-local move inside the seed segment (reserved is
    // empty — the tellWaiting order IS the seed segment here). The
    // reply position is in the segment's own index space.
    let pos_of = |r: &CmdResult| -> u64 {
        match r {
            Ok(CommandReply::Position { position }) => *position,
            other => panic!("expected Position reply, got {other:?}"),
        }
    };
    assert_eq!(
        pos_of(
            &call(
                &handle,
                SessionCommand::ChangePosition {
                    gid: parked[1].to_string(),
                    pos: 0,
                    how: OffsetMode::Set,
                },
            )
            .await
        ),
        0,
        "POS_SET 0 -> the segment front"
    );
    let w: Vec<Gid> = waiting_views(&handle).await.iter().map(|v| v.gid).collect();
    assert_eq!(
        w,
        vec![parked[1], parked[0]],
        "the in-segment reorder took effect"
    );
    assert_eq!(
        pos_of(
            &call(
                &handle,
                SessionCommand::ChangePosition {
                    gid: parked[1].to_string(),
                    pos: 99,
                    how: OffsetMode::Set,
                },
            )
            .await
        ),
        1,
        "clamped across the segment boundary to this segment's tail (the reply = the in-segment index)"
    );
    // ⑤: the seeding resident (a non-waiting member) -> the reference text.
    match call(
        &handle,
        SessionCommand::ChangePosition {
            gid: resident.to_string(),
            pos: 0,
            how: OffsetMode::Set,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert_eq!(
                message,
                format!("GID#{resident} not found in the waiting queue.")
            );
        }
        other => panic!("a non-waiting member must be rejected, got {other:?}"),
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
}
