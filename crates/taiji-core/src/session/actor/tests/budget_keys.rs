// ---- Four-pool budget option keys (the five-piece wiring) ----
//
// The three budget fields + read-side accessors get their
// accepted/echo/hot-reload faces. Acceptance faces:
// the three-key acceptance matrix (field projection + accessor reading
// + echo same-value, out-of-domain row clamps, lenient ignore of
// invalid values), the changeGlobalOption hot-reload trigger (the
// check-pool narrowing never preempts in-flight rechecks, seed-pool
// widening reactivates seed_wait FIFO without a download slot), the
// steady-sample download-slot predicate after the budget hot changes,
// the bt-detach-seed-only any-value constant-behavior pin, and the
// `-j` shrink non-preemption pin. Assertion shapes are meter/registry
// counts — no wall-clock ratio assertions (an earlier suite's flake
// precedent; banned here).

async fn echo_of(handle: &SessionHandle, key: &str) -> String {
    match call(handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(m)) => m.get(key).cloned().unwrap_or_default(),
        other => panic!("getGlobalOption: {other:?}"),
    }
}

async fn patch_global(handle: &SessionHandle, key: &str, value: &str) {
    assert_eq!(
        call(
            handle,
            SessionCommand::ChangeGlobalOption {
                options: BTreeMap::from([(key.to_string(), value.to_string())]),
            },
        )
        .await,
        Ok(CommandReply::Accepted),
        "{key} hot change should be Accepted (the lenient face, zero new error codes)"
    );
}

/// ① the three-key acceptance matrix (table-driven, pure): a valid
/// value projects onto the GlobalOptions field, the budget accessor
/// reads the same number, and the getGlobalOption echo returns the
/// same value; an out-of-domain numeric clamps at the row (the
/// max-concurrent-downloads apply-side clamp precedent — the read-side
/// accessors double-clamp); a non-numeric value ignores leniently
/// (field unchanged, zero error, the gatherChangeableGlobalOption
/// rule — zero new error codes).
#[test]
fn budget_keys_acceptance_matrix_clamp_and_echo() {
    // (key, value, expected field, accessor).
    type Accessor = fn(&GlobalOptions) -> usize;
    let rows: &[(&str, &str, usize, Accessor)] = &[
        ("max-concurrent-seeds", "24", 24, |g| g.seed_budget()),
        ("max-concurrent-checks", "3", 3, |g| g.check_budget()),
        ("media-synthesis-concurrency", "4", 4, |g| {
            g.synthesis_budget()
        }),
    ];
    for (key, val, field, accessor) in rows {
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([((*key).to_string(), (*val).to_string())]),
        );
        let projected = match *key {
            "max-concurrent-seeds" => g.max_concurrent_seeds,
            "max-concurrent-checks" => g.max_concurrent_checks,
            "media-synthesis-concurrency" => g.media_synthesis_concurrency,
            other => panic!("unknown key {other:?}"),
        };
        assert_eq!(&projected, field, "{key} field projection");
        // Accessor reading agrees with the field (the in-domain value
        // passes both clamps untouched).
        assert_eq!(accessor(&g), projected, "{key} accessor reading agrees");
        // Echo face same value.
        let echo = global_option_echo(&g);
        assert_eq!(
            echo.get(*key).map(String::as_str),
            Some(*val),
            "{key} echo same value"
        );
    }

    // Out-of-domain row clamps (the apply-side single clamp; the
    // read-side accessors are the same-domain second fence).
    let clamp_rows: &[(&str, &str, usize, Accessor)] = &[
        // seeds: 0 = unlimited passes through; the 4096 defensive cap
        // clamps (the read-side [0,4096] domain).
        ("max-concurrent-seeds", "0", 0, |g| g.max_concurrent_seeds),
        ("max-concurrent-seeds", "5000", 4096, |g| {
            g.max_concurrent_seeds
        }),
        // checks: no unlimited state, lower clamp 1, upper 16.
        ("max-concurrent-checks", "0", 1, |g| g.max_concurrent_checks),
        ("max-concurrent-checks", "99", 16, |g| {
            g.max_concurrent_checks
        }),
        // synthesis: the same [1,16] domain.
        ("media-synthesis-concurrency", "0", 1, |g| {
            g.media_synthesis_concurrency
        }),
        ("media-synthesis-concurrency", "99", 16, |g| {
            g.media_synthesis_concurrency
        }),
    ];
    for (key, val, expected, accessor) in clamp_rows {
        let mut g = GlobalOptions::default();
        apply_global_patch(
            &mut g,
            &BTreeMap::from([((*key).to_string(), (*val).to_string())]),
        );
        assert_eq!(
            accessor(&g),
            *expected,
            "{key}={val} row-level clamp into the value domain"
        );
        // The echo carries the clamped effective value (echo = the
        // field, never the raw input).
        let echo = global_option_echo(&g);
        assert_eq!(
            echo.get(*key).map(String::as_str),
            Some(expected.to_string().as_str()),
            "{key} echo = the clamped effective value"
        );
    }

    // Invalid values ignore leniently (the media-family row-note rule,
    // the gatherChangeableGlobalOption shape): the field keeps its
    // prior value and the call is not an error (apply_global_patch has
    // no error channel — the lenient ignore IS the rule; zero new
    // error codes on the RPC face, the Accepted reply is pinned live in
    // change_global's callers).
    let defaults: &[(&str, usize, Accessor)] = &[
        ("max-concurrent-seeds", 16, |g| g.max_concurrent_seeds),
        ("max-concurrent-checks", 2, |g| g.max_concurrent_checks),
        ("media-synthesis-concurrency", 2, |g| {
            g.media_synthesis_concurrency
        }),
    ];
    for (key, default, accessor) in defaults {
        for bad in ["abc", "", "-1", "2.5"] {
            let mut g = GlobalOptions::default();
            apply_global_patch(
                &mut g,
                &BTreeMap::from([((*key).to_string(), bad.to_string())]),
            );
            assert_eq!(
                accessor(&g),
                *default,
                "{key}={bad:?} ignored leniently — the field keeps its default"
            );
        }
    }
}

/// ② (the check-pool half): the changeGlobalOption hot reload is the
/// budget-change trigger (narrowing never preempts, release
/// backfills). Two wide rechecks in flight + one parked;
/// narrowing 2→1 evicts nobody (the two in flight run to completion),
/// and the parked third does not promote while a narrowed-slot holder
/// remains — the promotion fires only after the second in-flight
/// completes. Registry/meter counts throughout (num_checking, the
/// parked member's tellWaiting 'checking' face); the echo carries the
/// narrowed value.
#[tokio::test]
async fn budget_key_hot_change_check_narrow_never_preempts() {
    // Payloads staggered so the first completion leaves a wide (~1s)
    // observation window with the second still in flight: #1 = 32 MiB
    // (fast), #2 = 128 MiB (wide), #3 = tiny (the parked canary).
    let contents = [
        check_content_big(1),
        check_content_wide(2),
        seed_content_n(3),
    ];
    // The elastic-budget holder shape (see check.rs
    // force_recheck_budget_2's note): two holders keep the download
    // pool full (idle 0 — the elastic budget collapses to the base 2);
    // the three candidates queue in reserved and recheck through the
    // reserved arm (the original Active-deferred parking is
    // structurally gone under the elastic budget).
    let holder_dir = temp_dir("p143-bk-hold");
    let global = GlobalOptions {
        max_concurrent_checks: 2,
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    // Persist-backed: forceRecheck answers explicit Err without a
    // persistence form (the RecheckDone bitmap write-back needs the
    // row) — the check-budget shape.
    let db = tmp_db("p128-check-hot");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let mut holder_gids = Vec::new();
    for i in 0..2u8 {
        let bytes = downloadable_v1_torrent(
            &check_content_wide(50 + i),
            &dead_tracker(),
            &format!("bh{i}.bin"),
        );
        holder_gids.push(gid_of(
            &call(&handle, torrent_cmd(bytes, &holder_dir)).await,
        ));
    }
    let mut pool_full = false;
    for _ in 0..600 {
        if num_active(&handle).await == 2 {
            pool_full = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(pool_full, "the two holders did not fill the download pool");
    let dir = temp_dir("p128-check-hot");
    let mut gids = Vec::new();
    for (i, content) in contents.iter().enumerate() {
        let bytes = downloadable_v1_torrent(content, &dead_tracker(), &format!("c{i}.bin"));
        gids.push(gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await));
    }
    let mut all_queued = false;
    for _ in 0..600 {
        if tell_waiting(&handle).await.len() == 3 {
            all_queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_queued,
        "the three candidates did not park in reserved (download pool full)"
    );
    // Payloads after the adds (no add-time recheck; the tasks queue).
    for (i, content) in contents.iter().enumerate() {
        std::fs::write(dir.join(format!("c{i}.bin")), content)
            .unwrap_or_else(|e| panic!("write payload {i}: {e}"));
    }
    let (g1, g2, g3) = (gids[0], gids[1], gids[2]);
    // Two forceRechecks: both admit (budget 2).
    for g in [&g1, &g2] {
        assert!(matches!(
            call(&handle, SessionCommand::ForceRecheck { gid: g.to_string() }).await,
            Ok(CommandReply::Gid(_))
        ));
    }
    let mut two_in_flight = false;
    for _ in 0..3000 {
        if global_stat(&handle).await.num_checking == 2 {
            two_in_flight = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(two_in_flight, "the two rechecks are not both in flight");
    // The third parks (budget full at its deferred admission).
    assert!(matches!(
        call(
            &handle,
            SessionCommand::ForceRecheck {
                gid: g3.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(_))
    ));
    let mut parked = false;
    for _ in 0..3000 {
        if waiting_views(&handle)
            .await
            .iter()
            .any(|v| v.gid == g3 && v.status == StatusKind::Checking)
        {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        parked,
        "the 3rd did not park (tellWaiting status='checking')"
    );

    // The hot change 2->1 (via changeGlobalOption — the wiring face):
    // echo flips,
    // nobody is evicted (num_checking stays 2 — the over-subscribed
    // tolerance).
    patch_global(&handle, "max-concurrent-checks", "1").await;
    assert_eq!(
        echo_of(&handle, "max-concurrent-checks").await,
        "1",
        "echo face same value"
    );
    assert_eq!(
        global_stat(&handle).await.num_checking,
        2,
        "narrowing does not preempt: both in flight continue as usual"
    );
    // The fast #1 completes; the parked #3 must NOT promote while #2
    // (the narrowed-budget slot holder) is still in flight.
    let mut non_promotion_witnessed = false;
    for _ in 0..6000 {
        let gs = global_stat(&handle).await;
        let g3_parked = waiting_views(&handle)
            .await
            .iter()
            .any(|v| v.gid == g3 && v.status == StatusKind::Checking);
        if gs.num_checking == 1 && g3_parked {
            non_promotion_witnessed = true;
            break;
        }
        assert!(
            gs.num_checking <= 2,
            "the in-flight count stays <= the pre-narrow two (sampled {})",
            gs.num_checking
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        non_promotion_witnessed,
        "the narrowed window of \"#2 in flight + #3 parked\" was never observed (the 2nd no \
         longer promotes)"
    );
    // Drain: #2 completes → #3 promotes (budget 1, free slot) → all
    // three seed-side (full bitmaps), zero results, zero download
    // slots, num_checking back to 0.
    let mut drained = false;
    for _ in 0..3000 {
        let gs = global_stat(&handle).await;
        assert!(
            gs.num_checking <= 1,
            "after narrowing the budget is 1: at most 1 in flight (sampled {})",
            gs.num_checking
        );
        assert_eq!(
            num_active(&handle).await,
            2,
            "the check path consumes zero download slots (only the two holders)"
        );
        if gs.num_checking == 0
            && gs.num_seeding == 3
            && waiting_views(&handle).await.is_empty()
            && tell_stopped_gids(&handle).await.is_empty()
        {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        drained,
        "after narrowing not all converged: 3 residents + 0 in flight + 0 parked"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ② (the seed-pool half): widening the seed budget via
/// changeGlobalOption reactivates the seed_wait front **FIFO** and the
/// download-slot meter stays zero at every sample (the reactivation
/// never routes through a download slot). Budget 1 splits three
/// completions into 1 resident + 2 parked; 1→2 frees exactly one seat →
/// the FIFO front promotes, the tail stays parked.
/// Determinism note (the review finding): the park order = the
/// completion order (queue.rs `push_seed_wait` = push_back at the flip)
/// and equal-size payloads racing in parallel would make that order a
/// wall-clock bet — so the adds are **sequential with observed
/// parking**: each task reaches its registry face (resident / parked,
/// the tellWaiting 'seeding' segment read in order) before the next is
/// added. The order the FIFO assertions lean on is thus observed
/// structurally, never inferred from download racing.
#[tokio::test]
async fn budget_key_hot_change_seed_widen_reactivates_fifo_without_download_slot() {
    let mut torrents = Vec::new();
    for i in 0..3u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        let dir = temp_dir(&format!("p128-seed-hot-{i}"));
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
    // Persist-backed: the reactivation premise is the teardown's
    // persisted complete bitmap (the §4.1.2 assembly premise — the
    // The seed park/unpark + release shapes are persist-backed for the
    // same reason).
    let db = tmp_db("p128-seed-hot");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));

    // The 'seeding' segment of tellWaiting in its fixed FIFO order.
    async fn seed_segment(handle: &SessionHandle) -> Vec<Gid> {
        waiting_views(handle)
            .await
            .into_iter()
            .filter(|v| v.status == StatusKind::Seeding)
            .map(|v| v.gid)
            .collect()
    }

    // t0 completes first: with budget 1 it becomes the resident (its
    // flip lands while the seed pool has a free seat).
    let t0 = gid_of(&call(&handle, torrent_cmd(torrents[0].0.clone(), &torrents[0].1)).await);
    let mut resident = false;
    for _ in 0..1200 {
        if global_stat(&handle).await.num_seeding == 1
            && active_gids_of(&handle).await.contains(&t0)
            && download_complete(&handle, t0).await
        {
            resident = true;
            break;
        }
        assert!(
            num_active(&handle).await <= 1,
            "at most one download seat for this task (sampled {})",
            num_active(&handle).await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        resident,
        "t0 did not become the seeding resident (budget 1 free seat, direct entry)"
    );
    assert_eq!(
        num_active(&handle).await,
        0,
        "download seats drop to zero after the flip"
    );

    // t1 completes into a full pool: parks (the FIFO front, observed).
    let t1 = gid_of(&call(&handle, torrent_cmd(torrents[1].0.clone(), &torrents[1].1)).await);
    let mut parked1 = false;
    for _ in 0..1200 {
        if seed_segment(&handle).await == vec![t1] {
            parked1 = true;
            break;
        }
        assert!(
            num_active(&handle).await <= 1,
            "at most one download seat for this task (sampled {})",
            num_active(&handle).await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        parked1,
        "t1 did not park (budget full at 1, flipped into seed_wait)"
    );
    assert_eq!(global_stat(&handle).await.num_seeding, 1);
    assert_eq!(
        num_active(&handle).await,
        0,
        "parked members occupy no download seat"
    );

    // t2 completes into the still-full pool: parks behind t1 (the
    // observed order the FIFO assertions lean on).
    let t2 = gid_of(&call(&handle, torrent_cmd(torrents[2].0.clone(), &torrents[2].1)).await);
    let mut parked2 = false;
    for _ in 0..1200 {
        if seed_segment(&handle).await == vec![t1, t2] {
            parked2 = true;
            break;
        }
        assert!(
            num_active(&handle).await <= 1,
            "at most one download seat for this task (sampled {})",
            num_active(&handle).await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        parked2,
        "t2 did not park in order (the FIFO order [t1, t2] was never observed)"
    );
    assert_eq!(global_stat(&handle).await.num_seeding, 1);
    assert_eq!(
        num_active(&handle).await,
        0,
        "parked members occupy no download seat"
    );

    // The hot widen 1->2 (via changeGlobalOption): exactly one seat frees
    // → the observed FIFO front (t1) reactivates, the tail (t2) stays
    // parked, download slots stay zero throughout.
    patch_global(&handle, "max-concurrent-seeds", "2").await;
    assert_eq!(echo_of(&handle, "max-concurrent-seeds").await, "2");
    let mut widened = false;
    for _ in 0..1200 {
        let gs = global_stat(&handle).await;
        let active = active_gids_of(&handle).await;
        let seg = seed_segment(&handle).await;
        // The steady post-widen shape: 2 residents + exactly the tail
        // parked. The freshly-reactivated member assembles its engine
        // inside the seed slot — the content face converges with the
        // assembly, the slot/segment faces are assertive at every
        // sample.
        if gs.num_seeding == 2 && seg == vec![t2] {
            let mut all_complete = true;
            for g in [t0, t1] {
                if !download_complete(&handle, g).await {
                    all_complete = false;
                }
            }
            if all_complete && active.contains(&t1) {
                assert_eq!(
                    gs.num_active, 0,
                    "the download-seat count unchanged (zero occupancy throughout)"
                );
                widened = true;
                break;
            }
        }
        assert_eq!(
            num_active(&handle).await,
            0,
            "zero download-seat occupancy throughout the widen reactivation (sampled {})",
            num_active(&handle).await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        widened,
        "after the widen, 2 residents + tail parking never formed (the FIFO front t1 reactivation \
         did not occur)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ④ the bt-detach-seed-only constant-behavior pin (compat regression ①):
/// both accepted values (true/false) behave identically — a completed
/// download flips to a seeding resident and never occupies a download
/// slot (the four-pool model subsumed the option; the acceptance/echo
/// face is unchanged). Registry/meter counts; the per-value session is
/// fresh.
#[tokio::test]
async fn bt_detach_seed_only_any_value_seeds_off_the_download_slot() {
    for flag in [true, false] {
        let content = seed_content_n(7);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        let dir = temp_dir(&format!("p128-detach-{}", flag));
        let bytes =
            downloadable_v1_torrent(&content, &format!("http://{tracker}/announce"), "d.bin");
        let global = GlobalOptions {
            bt_detach_seed_only: flag,
            ..Default::default()
        };
        let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
        // The acceptance/echo face is unchanged (a zero-change accepted face): the
        // value echoes verbatim under both settings.
        assert_eq!(
            echo_of(&handle, "bt-detach-seed-only").await,
            flag.to_string(),
            "bt-detach-seed-only echo face (flag={flag})"
        );
        let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
        // Converge: completed + seeding resident + zero download slots.
        let mut seeded = false;
        for _ in 0..1200 {
            let active = active_gids_of(&handle).await;
            if download_complete(&handle, gid).await
                && active.contains(&gid)
                && tell_status_status(&handle, gid).await == StatusKind::Seeding
                && num_active(&handle).await == 0
            {
                seeded = true;
                break;
            }
            // Pre-completion samples: the task legitimately holds its
            // own download slot while downloading (the meter bound);
            // the zero-slot face is asserted only on the completed
            // sample above (the mixed-load sampling discipline).
            assert!(
                num_active(&handle).await <= 1,
                "flag={flag}: at most one download seat for this task"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            seeded,
            "flag={flag}: never reached the seeding resident (the always-true declared face lacks \
             an implementation backstop)"
        );
        // The registry face: numSeeding counts the resident, numActive
        // does not (identical for both values — the any-value pin).
        let gs = global_stat(&handle).await;
        assert_eq!(
            gs.num_seeding, 1,
            "flag={flag}: seed-seat bookkeeping consistent"
        );
        assert_eq!(
            gs.num_active, 0,
            "flag={flag}: zero download-seat credit consistent"
        );
        handle.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    }
}

/// ⑤ the `-j` shrink non-preemption pin (compat regression ②, aria2 same
/// posture): shrinking max-concurrent-downloads via changeGlobalOption
/// leaves both running downloads untouched (they run on), while a
/// newly-queued task stays reserved waiting for a seat. Dead trackers
/// make the running face stable; queue/registry counts only.
#[tokio::test]
async fn downloads_budget_shrink_does_not_preempt_active_tasks() {
    let global = GlobalOptions {
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("p128-j-shrink");
    let mut dead = Vec::new();
    for i in 0..3u8 {
        let bytes = downloadable_v1_torrent(
            &seed_content_n(10 + i),
            &dead_tracker(),
            &format!("dead-{i}.bin"),
        );
        dead.push(gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await));
    }
    // Two slots, three tasks: the first two run, the third waits.
    let mut running = false;
    for _ in 0..1200 {
        let active = active_gids_of(&handle).await;
        if dead[0..2].iter().all(|g| active.contains(g)) && num_active(&handle).await == 2 {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        running,
        "the two dead-tracker downloads did not fill both 2 seats"
    );
    let waiting = waiting_views(&handle).await;
    assert!(
        waiting
            .iter()
            .any(|v| v.gid == dead[2] && v.status == StatusKind::Waiting),
        "the 3rd task should wait reserved for a seat"
    );
    // The shrink 2->1 (via changeGlobalOption; echo carries it).
    patch_global(&handle, "max-concurrent-downloads", "1").await;
    assert_eq!(echo_of(&handle, "max-concurrent-downloads").await, "1");
    // Non-preemption: both pre-shrink actives keep running (they were
    // admitted under the old budget — aria2 same posture), the third
    // stays reserved, and no task flipped to paused.
    for _ in 0..20 {
        let active = active_gids_of(&handle).await;
        assert!(
            dead[0..2].iter().all(|g| active.contains(g)),
            "narrowing preempted existing active tasks (the aria2 same posture is broken)"
        );
        assert_eq!(
            num_active(&handle).await,
            2,
            "narrowing releases/preempts nothing: still 2 in flight"
        );
        let waiting = waiting_views(&handle).await;
        assert!(
            waiting
                .iter()
                .any(|v| v.gid == dead[2] && v.status == StatusKind::Waiting),
            "the new task stays reserved waiting for a seat (queue-count assertion)"
        );
        assert!(
            !waiting.iter().any(|v| v.status == StatusKind::Paused),
            "narrowing must not reclassify in-flight tasks as paused"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
}

/// ③ the steady-sample download-slot predicate after the three budget
/// hot changes: budgets arrive via
/// changeGlobalOption
/// (the wiring face, not direct construction), the mixed load —
/// seeding ×4 + checking drained + synthesis ×1 — coexists with the two
/// dead-tracker downloads holding the download slots at the steady
/// sample (no in-progress engine assembly/transfer window): numActive = 2
/// = full load and only
/// the download-phase tasks occupy the slots; the getGlobalStat caliber
/// matrix (numSeeding = residents, numChecking = in flight, numWaiting
/// = the four-segment merge == the tellWaiting count) reads green.
#[tokio::test]
async fn steady_sample_after_budget_hot_changes_download_slots_download_only() {
    // 60 segments x 2 MiB: the Processing/Verifying work scales with
    // bytes, so the synthesis window (the matrix's open end — see the
    // determinism note at the recheck fixtures below) is structurally
    // long.
    let hls = spawn_hls(60, 0, 2 * 1024 * 1024).await;
    let dir = temp_dir("p128-steady");
    // The four budgets ride changeGlobalOption (the echo face verifies
    // the acceptance), not the constructor.
    let global = GlobalOptions {
        dir: dir.clone(),
        media_allow_private_key_url: true,
        ..Default::default()
    };
    // Persist-backed (the forceRecheck face needs the persistence form;
    // the sibling budgets' mixed-load shapes are the same).
    let db = tmp_db("p128-steady");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    for (key, val) in [
        ("max-concurrent-downloads", "2"),
        ("max-concurrent-seeds", "4"),
        ("max-concurrent-checks", "2"),
        ("media-synthesis-concurrency", "2"),
    ] {
        patch_global(&handle, key, val).await;
        assert_eq!(echo_of(&handle, key).await, val, "{key} echo same value");
    }
    // BT fixtures: two seeder-backed fast tasks, two dead slot holders,
    // one complete-payload seed-at-add task, one recheck target
    // (payload after the add).
    let mut fast = Vec::new();
    for i in 0..2u8 {
        let content = seed_content_n(i);
        let seeder = mini_seeder(content.clone()).await;
        let tracker = loopback_tracker(seeder).await;
        let bytes = downloadable_v1_torrent(
            &content,
            &format!("http://{tracker}/announce"),
            &format!("fast-{i}.bin"),
        );
        fast.push(gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await));
    }
    let media_gid = add_media_task(&handle, &format!("http://{hls}/master.m3u8"), &dir).await;
    let mut dead = Vec::new();
    for i in 0..2u8 {
        let bytes = downloadable_v1_torrent(
            &seed_content_n(10 + i),
            &dead_tracker(),
            &format!("dead-{i}.bin"),
        );
        dead.push(gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await));
    }
    let seed_at_add_content = seed_content_n(9);
    let seed_at_add_bytes =
        downloadable_v1_torrent(&seed_at_add_content, &dead_tracker(), "seed-at-add.bin");
    std::fs::write(dir.join("seed-at-add.bin"), &seed_at_add_content)
        .unwrap_or_else(|e| panic!("write seed-at-add payload: {e}"));
    let seed_at_add_gid = gid_of(&call(&handle, torrent_cmd(seed_at_add_bytes, &dir)).await);
    // Determinism note (the review finding): the matrix window = [the
    // recheck routed (num_checking == 0) .. the synthesis ends
    // (num_synthesizing 1 → 0)] — the two ends must not race. The
    // recheck/seed-at-add payloads are tiny 2-piece contents (routing
    // converges in ms), while the media's segments are 2 MiB (the
    // Processing/Verifying work scales with bytes — the synthesis
    // window stretches well past any poll period). The wide-content
    // holder precedent in reverse: here the convergence
    // side is made fast, not the window holder slow-guessy.
    let recheck_content = seed_content_n(10);
    let recheck_bytes = downloadable_v1_torrent(&recheck_content, &dead_tracker(), "recheck.bin");
    let recheck_gid = gid_of(&call(&handle, torrent_cmd(recheck_bytes, &dir)).await);
    std::fs::write(dir.join("recheck.bin"), &recheck_content)
        .unwrap_or_else(|e| panic!("write recheck payload: {e}"));
    assert!(matches!(
        call(
            &handle,
            SessionCommand::ForceRecheck {
                gid: recheck_gid.to_string(),
            },
        )
        .await,
        Ok(CommandReply::Gid(_))
    ));
    // Steady sample (the four-pool choreography: fast×2 complete and
    // seed, media gates into synthesis, dead×2 hold both slots, the
    // recheck routes seed-side). The poll is gs-only per round (the
    // cached meter face keeps the poll period well under the synthesis
    // window — the four-pool shape); the expensive TellActive/
    // tellWaiting verification runs once on the hit. Transient windows
    // never enter an assertion — the matrix hit IS the settled steady
    // state (nothing left to transition but the synthesis finishing).
    let mut steady = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        let gs = global_stat(&handle).await;
        if gs.num_active == 2
            && gs.num_synthesizing == 1
            && gs.num_seeding == 4
            && gs.num_checking == 0
            && gs.num_waiting == 0
        {
            // The steady-sample slot predicate (③'s headline): the two
            // download slots are occupied exactly by the download-phase
            // tasks — the meter excludes the 4 seeding residents and
            // the 1 synthesis resident, and the dead downloaders (who
            // never complete) hold both seats. Finer-grained on-hit
            // TellActive/content reads would race the ms-scale
            // synthesis completion (the multi-RPC discipline:
            // meter matrix first, everything else table-driven or
            // suite-covered).
            let active = active_gids_of(&handle).await;
            assert!(
                dead.iter().all(|g| active.contains(g)),
                "both download seats are held by the dead download tasks (the steady-sample point)"
            );
            assert_eq!(
                gs.num_waiting, 0,
                "steady state has no parking (the recheck routed, media entered synthesis)"
            );
            steady = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        steady,
        "steady state never reached: 4 seeding + 1 synthesizing + 2 downloads at full load + \
         checking drained"
    );
    // The seeding residents' identities (stable at any post-hit point:
    // no seed criteria means they never leave the registry; only the
    // media's synthesis completion races, and the residents are not it).
    let active = active_gids_of(&handle).await;
    for g in fast.iter().chain([&seed_at_add_gid, &recheck_gid]) {
        assert!(
            active.contains(g),
            "seeding resident {g} is a TellActive member"
        );
    }
    // The media line closes out: the synthesis resident terminalizes
    // Done in results (the gated pipeline completes; the dead
    // downloaders never do — that's the point of the dead trackers).
    let mut media_done = false;
    let media_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < media_deadline {
        if status_list(
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
        .any(|v| v.gid == media_gid && v.status == StatusKind::Complete)
        {
            media_done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        media_done,
        "the media synthesis resident did not terminalize as Done"
    );
    // The caliber matrix regression slice (acceptance ⑥): numWaiting ==
    // tellWaiting count; numActive excludes seeding/synthesis.
    let gs = global_stat(&handle).await;
    assert_eq!(
        gs.num_waiting as usize,
        waiting_views(&handle).await.len(),
        "numWaiting = the four-segment merge == the tellWaiting count"
    );
    assert_eq!(gs.num_active, 2, "numActive = the full download-seat load");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}
