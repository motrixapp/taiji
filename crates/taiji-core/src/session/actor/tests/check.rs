// ---- Check pool ----
//
// Acceptance faces (①–⑥, ⑨, ⑩): bootstrap N 'checking' rows
// parked within the budget (meter/registry-count assertions — the
// in-flight meter = N − parked − routed; no wall-clock ratio assertions,
// an earlier suite's flake precedent; banned here), runtime concurrency
// ≤ check_budget, forceRecheck full-2-park-1 with FIFO promotion, the
// RecheckDone measured-bitmap two-branch routing (seed side / reserved),
// the steady-state download-slot isolation slice, the deferred-stop
// swallow (checking_deferred ∩ running → Ended consumed → check_pending,
// no results), and the promotion-trigger pump discipline. The queue-
// level table tests (park/admit FIFO, narrowing non-preemption)
// live in queue.rs's test module; the routing predicate matrix is
// testable pure (recheck.rs).

/// Distinct content per task (1024 x 16 KiB pieces = 16 MiB — verify
/// long enough that the parked window is reliably sampled; the fixture
/// writes are sequential and bounded).
fn check_content(tag: u8) -> Vec<u8> {
    let pat: Vec<u8> = format!("taiji-p125-check{tag:02x}-").into_bytes();
    pat.iter().cycle().take(16 * 1024 * 1024).copied().collect()
}

/// Doubled payload (32 MiB) — the test-③ slot holders: their verify must
/// outlast the stop-teardown stagger so the third member's parked window
/// is reliably sampled.
fn check_content_big(tag: u8) -> Vec<u8> {
    let pat: Vec<u8> = format!("taiji-p125-big{tag:02x}-").into_bytes();
    pat.iter().cycle().take(32 * 1024 * 1024).copied().collect()
}

/// The budget-park window holder (review hardening): a 128 MiB
/// payload — its verify (~0.5-1s) must structurally outlast the third
/// task's stop teardown, the park window's other bound. The 32 MiB
/// verify measures ~50 ms on Apple Silicon, the same order as a
/// teardown, so under full-suite load the third task could admit
/// straight into a freed slot (the park unobservable).
fn check_content_wide(tag: u8) -> Vec<u8> {
    let pat: Vec<u8> = format!("taiji-p127-wide{tag:02x}-").into_bytes();
    pat.iter()
        .cycle()
        .take(128 * 1024 * 1024)
        .copied()
        .collect()
}

async fn tell_waiting(handle: &SessionHandle) -> Vec<TorrentStatusView> {
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

async fn tell_active(handle: &SessionHandle) -> Vec<TorrentStatusView> {
    status_list(&call(handle, SessionCommand::TellActive { keys: vec![] }).await)
}

async fn tell_stopped_gids(handle: &SessionHandle) -> Vec<Gid> {
    status_list(
        &call(
            handle,
            SessionCommand::TellStopped {
                offset: 0,
                num: u32::MAX,
                keys: vec![],
            },
        )
        .await,
    )
    .into_iter()
    .map(|v| v.gid)
    .collect()
}

/// The default two-state face + the read-side [1,16] clamp (the
/// max-concurrent-downloads clamp precedent; the seed_budget
/// read-side shape — no parse/RPC face, direct construction
/// clamps at the single consumption point, never panics). No
/// "unlimited" state exists on this pool (the lower clamp 1).
#[test]
fn check_budget_default_domain_and_clamp() {
    let g = GlobalOptions::default();
    assert_eq!(
        g.max_concurrent_checks, 2,
        "default 2 (pread+hash IO/CPU overlap)"
    );
    assert_eq!(g.check_budget(), 2);
    let zero = GlobalOptions {
        max_concurrent_checks: 0,
        ..Default::default()
    };
    assert_eq!(
        zero.check_budget(),
        1,
        "below the domain clamps to 1 (no unlimited state)"
    );
    let over = GlobalOptions {
        max_concurrent_checks: 999,
        ..Default::default()
    };
    assert_eq!(over.check_budget(), 16, "the domain ceiling 16 clamps");
}

/// The RecheckDone routing predicate matrix (recheck.rs
/// `recheck_outcome_complete` — the in-card pure decision function): v1 full/partial/
/// absent/short-bitfield, v2 full/partial/stale-count/alien-segment,
/// suspended files, zero-length files, padding files.
#[test]
fn recheck_outcome_complete_matrix() {
    use crate::metainfo::{MetaFile, TorrentMeta};
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
    let outcome = |v1: Option<Vec<u8>>,
                   v2: Option<Vec<u8>>,
                   suspended: Vec<u32>|
     -> crate::session::RecheckOutcome {
        crate::session::RecheckOutcome {
            v1_bitfield: v1,
            v2_file_bits: v2,
            verified: 0,
            total: 0,
            suspended_files: suspended,
        }
    };
    let meta = mk_meta(&[(2 * 16 * 1024, false)]);
    // v1: full / one bit clear / absent / short bitfield (out-of-bounds
    // read = not set = incomplete).
    assert!(crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(Some(vec![0xC0]), None, vec![])
    ));
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(Some(vec![0x40]), None, vec![])
    ));
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(None, None, vec![])
    ));
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(Some(vec![]), None, vec![])
    ));
    // v2-only: a 2-piece file's segment fully set / one bit clear / a
    // stored count below the expected piece count / a missing segment
    // for the real file (only an alien file_index present).
    let v2_seg = |count: u32, bits: u8| {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&count.to_be_bytes());
        b.push(bits);
        b
    };
    assert!(crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(None, Some(v2_seg(2, 0xC0)), vec![])
    ));
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(None, Some(v2_seg(2, 0x40)), vec![])
    ));
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(None, Some(v2_seg(1, 0x80)), vec![])
    ));
    let alien_only = {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&2u32.to_be_bytes());
        b.push(0xC0);
        b
    };
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(None, Some(alien_only), vec![])
    ));
    // Suspended files: unmeasured content must not route to the seed
    // side — even a structurally full-looking bitmap is incomplete when
    // the suspension set is non-empty.
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta,
        &outcome(Some(vec![0xC0]), None, vec![0])
    ));
    // Zero-length files never block completeness (either face).
    let meta_z = mk_meta(&[(2 * 16 * 1024, false), (0, false)]);
    assert!(crate::session::recheck::recheck_outcome_complete(
        &meta_z,
        &outcome(Some(vec![0xC0]), None, vec![])
    ));
    assert!(crate::session::recheck::recheck_outcome_complete(
        &meta_z,
        &outcome(None, Some(v2_seg(2, 0xC0)), vec![])
    ));
    // Padding files are skipped by the v2 walk: only the real file's
    // segment needs to be present and full (no entry for the padding
    // file).
    let meta_pad = mk_meta(&[(2 * 16 * 1024, false), (16 * 1024, true)]);
    assert!(crate::session::recheck::recheck_outcome_complete(
        &meta_pad,
        &outcome(None, Some(v2_seg(2, 0xC0)), vec![])
    ));
    assert!(
        !crate::session::recheck::recheck_outcome_complete(
            &meta_pad,
            &outcome(Some(vec![0xC0]), None, vec![])
        ),
        "the v1 face has no padding concept: a 3-piece bitmap with only 2 set = incomplete"
    );
    // Zero piece length = the geometry collapsed = incomplete.
    let mut meta_bad = mk_meta(&[(2 * 16 * 1024, false)]);
    meta_bad.piece_length = 0;
    assert!(!crate::session::recheck::recheck_outcome_complete(
        &meta_bad,
        &outcome(Some(vec![0xC0]), None, vec![])
    ));
}

/// ① + ② + ⑤: bootstrap re-admission — four 'checking' rows park into
/// check_pending at restart; promotion = exactly the check budget (the
/// parked remainder stays tellWaiting-visible with status 'checking' —
/// the observation the pre-war serial inline recheck could never
/// produce, pinning "no per-row serial await"); the in-flight meter
/// (N − parked − routed) stays ≤ budget at every sample; the check pool
/// never occupies a download slot (numActive == 2 = the two dead
/// downloads only — the steady-state slice, the full load unchanged); every
/// row converges onto the seed side (complete payloads → full bitmaps →
/// the checking→seeding edge) with zero results entries. Meter
/// assertions only; the wall-clock face is deliberately unasserted.
#[tokio::test]
async fn bootstrap_checking_rows_park_within_budget_and_route_seed_side() {
    let db = tmp_db("p125-bootstrap");
    // Session 1: four complete-payload torrents added paused (no
    // initial recheck — the `!patch.pause` gate), then the rows are
    // flipped to 'checking' in the store (the crash-during-check state
    // the restart must recover).
    let mut torrents = Vec::new();
    for i in 0..4u8 {
        let content = check_content(i);
        let dir = temp_dir(&format!("p125-boot-{i}"));
        std::fs::write(dir.join(format!("c-{i}.bin")), &content)
            .unwrap_or_else(|e| panic!("write payload: {e}"));
        let bytes = downloadable_v1_torrent(&content, &dead_tracker(), &format!("c-{i}.bin"));
        torrents.push((bytes, dir));
    }
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
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([
                        ("dir".to_string(), dir.display().to_string()),
                        ("pause".to_string(), "true".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        ));
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
    {
        let conn = ok(rusqlite::Connection::open(&db), "open db");
        for gid in &gids {
            ok(
                conn.execute(
                    "UPDATE torrent SET state = 'checking' WHERE gid = ?1",
                    params![gid.to_string()],
                ),
                "flip state to checking",
            );
        }
    }

    // Session 2: check budget 2 — the four rows park and promote within
    // the budget; two dead-tracker downloads hold the download slots.
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global = GlobalOptions {
        max_concurrent_checks: 2,
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer2.clone()));
    let mut dead = Vec::new();
    for i in 0..2u8 {
        let dir = temp_dir(&format!("p125-boot-dead{i}"));
        let bytes = downloadable_v1_torrent(
            &check_content(10 + i),
            &dead_tracker(),
            &format!("dead-{i}.bin"),
        );
        dead.push(gid_of(&call(&handle2, torrent_cmd(bytes, &dir)).await));
    }
    // Phase 1 (tight loop, no sleep): the bootstrap rows admit within
    // the **elastic** budget (the elastic revision: base 2 + the download
    // pool's idle seats — at bootstrap no download is active yet, so
    // the effective cap is 2+2 = 4 and all four rows may run at once;
    // once the dead-tracker downloads activate, the idle face falls to
    // 0 and admissions gate at the base — in-flight checks are never
    // preempted). The pre-revision parked-projection face is covered by
    // the forceRecheck shapes (busy pool, holder-held); here the meter
    // bounds to the elastic cap.
    for _ in 0..3000 {
        let waiting = tell_waiting(&handle2).await;
        let parked: Vec<Gid> = waiting
            .iter()
            .filter(|v| v.status == StatusKind::Checking)
            .map(|v| v.gid)
            .collect();
        let active = tell_active(&handle2).await;
        let routed = gids
            .iter()
            .filter(|g| {
                active.iter().any(|v| {
                    v.gid == **g && v.total_length > 0 && v.completed_length == v.total_length
                })
            })
            .count();
        let in_flight = 4i64 - parked.len() as i64 - routed as i64;
        assert!(
            (0..=4).contains(&in_flight),
            "in-flight recheck count {in_flight} out of bounds (elastic cap 2+2; parked {} routed {routed})",
            parked.len()
        );
        assert!(
            num_active(&handle2).await <= 2,
            "checks/parking occupy no download seat"
        );
        if routed == 4 {
            break;
        }
    }

    // Phase 2 (relaxed drain): all four converge onto the seed side
    // (complete payloads → full measured bitmaps → the checking→seeding
    // edge, seed budget 16 admits all); the in-flight meter and the
    // download-slot isolation hold at every sample.
    let mut converged = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle2).await;
        let parked = waiting
            .iter()
            .filter(|v| v.status == StatusKind::Checking)
            .count();
        let active = tell_active(&handle2).await;
        let seeded = gids
            .iter()
            .filter(|g| {
                active.iter().any(|v| {
                    v.gid == **g && v.total_length > 0 && v.completed_length == v.total_length
                })
            })
            .count();
        let in_flight = 4i64 - parked as i64 - seeded as i64;
        assert!(
            (0..=2).contains(&in_flight),
            "in-flight {in_flight} out of bounds (budget 2; registry count drift parked {parked} + seeded {seeded})"
        );
        // Visibility: every check gid is tellActive- or tellWaiting-
        // visible (no invisible parked tasks).
        for g in &gids {
            assert!(
                active.iter().any(|v| v.gid == *g) || waiting.iter().any(|v| v.gid == *g),
                "gid {g} vanished from the projection face"
            );
        }
        assert!(
            num_active(&handle2).await <= 2,
            "download seats always <= 2"
        );
        assert!(
            tell_stopped_gids(&handle2).await.is_empty(),
            "the check path produces zero results"
        );
        if seeded == 4 && parked == 0 {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        converged,
        "the 4 'checking' rows did not all converge onto the seed side"
    );
    // Steady state (⑤): the download slots are held by exactly the two
    // dead downloads (the full load unchanged); the four seed residents are
    // tellActive-visible but slot-free.
    assert_eq!(
        num_active(&handle2).await,
        2,
        "steady download seats = the two download tasks at full load"
    );
    let active = tell_active(&handle2).await;
    for d in &dead {
        assert!(
            active.iter().any(|v| v.gid == *d),
            "download task {d} in flight"
        );
    }
    assert_eq!(
        active.len(),
        6,
        "4 seed-side residents + 2 downloads, all projected"
    );
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin2).await;
}

/// ③ + ④(full branch) + ⑨: forceRecheck with budget 2 — the first two
/// promote, the third parks (tellWaiting-visible, status 'checking');
/// when one completes, the parked member promotes **without any further
/// external event** (the RecheckDone arm's trailing pump_all —
/// release-then-backfill, no idle beat). Every rechecked task has a
/// full measured bitmap → each routes to the seed side direct (never a
/// results entry, never a download slot — the checking→seeding edge).
#[tokio::test]
async fn force_recheck_budget_2_parks_third_then_promotes_on_fifo() {
    let db = tmp_db("p125-full2");
    // Three unpaused adds with ABSENT payloads (payload_complete false →
    // no add-time recheck; the tasks activate and idle on the dead
    // trackers). The payloads are placed before the forceRechecks, which
    // ride the **Active-deferred arm** (force semantics — the parked
    // intent is always false): t1/t2 hold the two check slots (32 MiB
    // payloads — the verify outlasts the stop teardowns), t3 parks
    // deterministically between the third stop landing and the first
    // completion. Full measured bitmaps + no pause intent → every task
    // routes to the seed side (zero reserved dwell).
    // The elastic-budget shape: under the elastic budget (base + the
    // download pool's idle seats) the Active-deferred arm can never
    // park — each stopping task frees its own download seat, so its
    // deferred check always has a seat to borrow. The parking face is
    // exercised through the **reserved arm**: two dead-tracker holder
    // downloads keep the download pool full (idle 0 — the effective
    // check budget is exactly the base 2), three queued candidates
    // (absent payloads — parked in reserved behind the full pool) get
    // their payloads placed and forceRecheck into check_pending: two
    // admit, the third parks deterministically; FIFO promotion follows
    // as the wide (128 MiB) verifies complete. (The Active-deferred
    // arm keeps its coverage in force_recheck_active_deferred.)
    let mut holders = Vec::new();
    for i in 0..2u8 {
        let content = check_content_wide(30 + i);
        let dir = temp_dir(&format!("p143-hold-{i}"));
        holders.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("h-{i}.bin")),
            dir,
        ));
    }
    let mut torrents = Vec::new();
    for i in 0..2u8 {
        let content = check_content_wide(i);
        let dir = temp_dir(&format!("p125-f2-{i}"));
        torrents.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("s-{i}.bin")),
            dir,
            content,
            format!("s-{i}.bin"),
        ));
    }
    let tiny = seed_content_n(7);
    let tiny_dir = temp_dir("p125-f2-tiny");
    torrents.push((
        downloadable_v1_torrent(&tiny, &dead_tracker(), "t.bin"),
        tiny_dir,
        tiny,
        "t.bin".to_string(),
    ));
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        max_concurrent_checks: 2,
        // The cap at exactly the 2 holder downloads: idle 0 — the
        // elastic face collapses to the base budget (the parking
        // coverage keeps its pre-revision shape).
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let mut holder_gids = Vec::new();
    for (bytes, dir) in &holders {
        holder_gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
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
    // The three candidates: unpaused adds with ABSENT payloads (no
    // add-time recheck; the full download pool parks them in the
    // reserved queue — they never activate), payloads placed before
    // the forceRechecks so the rechecks measure full bitmaps and the
    // reserved arm carries a false pause intent (seed-side routing).
    let mut gids: Vec<Gid> = Vec::new();
    for (bytes, dir, _, _) in &torrents {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
        ));
    }
    let mut all_queued = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle).await;
        if num_active(&handle).await == 2
            && waiting
                .iter()
                .filter(|v| v.status == StatusKind::Waiting)
                .count()
                == 3
        {
            all_queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_queued,
        "the three candidates did not park in reserved (download pool full)"
    );
    for (_, dir, content, name) in &torrents {
        std::fs::write(dir.join(name), content).unwrap_or_else(|e| panic!("write payload: {e}"));
    }
    let (t1, t2, t3) = (gids[0], gids[1], gids[2]);
    // Reserved-arm forceRechecks (instant park/admit — no teardown):
    // with the download pool full the effective budget is the base 2,
    // so the third parks the moment its entry lands.
    for g in [&t1, &t2, &t3] {
        assert!(
            matches!(
                call(&handle, SessionCommand::ForceRecheck { gid: g.to_string() }).await,
                Ok(CommandReply::Gid(_))
            ),
            "forceRecheck must reply Gid"
        );
    }
    // t3 parked (budget full at its admission): tellWaiting-visible with
    // the 'checking' status (the in-flight meter reads 2 — ≤ budget).
    let mut parked_third = false;
    for _ in 0..3000 {
        let waiting = tell_waiting(&handle).await;
        if waiting
            .iter()
            .any(|v| v.gid == t3 && v.status == StatusKind::Checking)
        {
            parked_third = true;
            break;
        }
        // The verify race fallback: t3 promoted before any sample (a
        // verify failed early) — the terminal face below still pins the
        // promotion path; bail out to the drain.
        let active = tell_active(&handle).await;
        if active
            .iter()
            .any(|v| v.gid == t3 && v.completed_length == v.total_length)
        {
            break;
        }
    }
    assert!(
        parked_third,
        "the 3rd did not park under budget 2 (tellWaiting status='checking' never observed)"
    );
    // Drain: all three seed-side (full bitmaps), zero results, zero
    // download slots at every sample (④'s full branch + ⑤'s slice).
    let mut all_seeded = false;
    for _ in 0..600 {
        let active = tell_active(&handle).await;
        let seeded = gids
            .iter()
            .filter(|g| {
                active.iter().any(|v| {
                    v.gid == **g && v.total_length > 0 && v.completed_length == v.total_length
                })
            })
            .count();
        let waiting = tell_waiting(&handle).await;
        assert!(
            !waiting
                .iter()
                .any(|v| gids.contains(&v.gid) && v.status == StatusKind::Waiting),
            "full-bitmap routing must not linger in reserved"
        );
        assert_eq!(
            num_active(&handle).await,
            2,
            "seed-side direct entry takes zero download seats (only the two holders)"
        );
        assert!(
            tell_stopped_gids(&handle).await.is_empty(),
            "the check path produces zero results"
        );
        if seeded == 3 {
            all_seeded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_seeded,
        "the three rechecks did not all converge onto the seed side"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ④ (the not-full branch): a holey payload rechecks to a partial
/// bitmap → requeue reserved (the existing path) and reactivate on the
/// download side — never the seed side, never a results entry.
#[tokio::test]
async fn recheck_hole_routes_reserved_and_reactivates_download_side() {
    let db = tmp_db("p125-hole");
    let content = seed_content_n(3);
    let dir = temp_dir("p125-hole");
    let mut corrupted = content.clone();
    corrupted[SEED_PIECE_LEN as usize + 5] ^= 0xff;
    std::fs::write(dir.join("h.bin"), &corrupted).unwrap_or_else(|e| panic!("write payload: {e}"));
    let bytes = downloadable_v1_torrent(&content, &dead_tracker(), "h.bin");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer.clone()));
    // Unpaused add + a present (corrupted) payload → the addTorrent
    // complete-payload gate parks the initial verification into the
    // check pool (the active→checking admission face).
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    // The measured bitmap lands with the hole (piece 0 kept, piece 1
    // cleared) — the recheck ran through the check pool; the requeue
    // (unpaused — no intent to preserve) reactivates the download side
    // (dead tracker: stays active, incomplete). The seed side is never
    // entered and no results entry appears.
    let mut routed = false;
    for _ in 0..600 {
        let gid_hex = gid.to_string();
        if let Ok(Some(row)) = writer.load_torrent_progress(&gid_hex).await {
            if row.v1_bitfield == Some(vec![0b1000_0000]) && num_active(&handle).await == 1 {
                routed = true;
                break;
            }
        }
        assert!(
            tell_stopped_gids(&handle).await.is_empty(),
            "partial-bitmap routing produces zero results"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        routed,
        "the partial bitmap did not take the reserved side (hole bitmap + download-side reactivation)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ⑥ (the Active-deferred arm): forceRecheck on a running
/// task — graceful stop → the Ended is swallowed by the deferred
/// consume (never a results entry) → the task parks into check_pending
/// (visible while no download slot is held) → promoted within the
/// budget → the recheck measures the now-complete payload → the
/// checking→seeding edge. The task leaves `running` at the stop and
/// never re-enters the download side.
#[tokio::test]
async fn force_recheck_active_deferred_swallowed_into_check_pending() {
    let db = tmp_db("p125-defer");
    let content = check_content(9);
    let dir = temp_dir("p125-defer");
    // Add with an ABSENT payload (payload_complete false → no initial
    // recheck; the task activates and idles on the dead tracker), then
    // place the payload before forceRecheck so the deferred recheck
    // measures a full bitmap (slow enough to sample the parked window).
    let bytes = downloadable_v1_torrent(&content, &dead_tracker(), "d.bin");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer.clone()));
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    let mut running = false;
    for _ in 0..600 {
        if num_active(&handle).await == 1 {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(running, "the task did not activate (download seat 1)");
    std::fs::write(dir.join("d.bin"), &content).unwrap_or_else(|e| panic!("place payload: {e}"));
    assert!(matches!(
        call(
            &handle,
            SessionCommand::ForceRecheck {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(_))
    ));
    // Stop landed → the task left running (the Ended consumed it) and
    // must reappear in the check pool — parked ('checking' in
    // tellWaiting) or in-flight (tellActive) — never invisible, never a
    // result. The parked sample is the parked-face pin (the earlier
    // shape spawned the recheck straight from the Ended consume).
    let mut stopped = false;
    let mut saw_parked = false;
    for _ in 0..600 {
        if num_active(&handle).await == 0 {
            stopped = true;
        }
        if stopped {
            let waiting = tell_waiting(&handle).await;
            if waiting
                .iter()
                .any(|v| v.gid == gid && v.status == StatusKind::Checking)
            {
                saw_parked = true;
                break;
            }
            // Already promoted and rechecking (tellActive, slot-free) —
            // equally fine; the parked observation is best-effort inside
            // the verify window, the terminal face below is the hard
            // assert.
            let active = tell_active(&handle).await;
            if active.iter().any(|v| v.gid == gid) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        stopped,
        "the graceful stop never landed (download seats not zeroed)"
    );
    let _ = saw_parked;
    // Terminal: full measured bitmap → the seed side direct (budget 16
    // admits); zero results entries across the whole transition (the
    // Ended swallow); zero download slots.
    let mut seeded = false;
    for _ in 0..600 {
        let active = tell_active(&handle).await;
        if active
            .iter()
            .any(|v| v.gid == gid && v.total_length > 0 && v.completed_length == v.total_length)
            && num_active(&handle).await == 0
        {
            seeded = true;
            break;
        }
        assert!(
            tell_stopped_gids(&handle).await.is_empty(),
            "the Ended was swallowed by the deferred consume and must not enter results"
        );
        assert!(
            num_active(&handle).await == 0,
            "no download seat may be held after the stop"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seeded,
        "the deferred recheck did not converge onto the seed side"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// pauseAll covers the parked face (review-fix regression): under budget 1,
/// three Active-arm forceRechecks — 1 in flight, 2 parked — after pauseAll
/// every member's recheck must close out with a pause intent: a full bitmap
/// + pause intent -> requeue paused (the complete-content provenance mark),
/// the terminal state has all three in tellWaiting Paused, zero self-
/// activated seeding, zero results. Pre-fix the parked members missed the
/// mark: a full bitmap + no intent -> self-activate onto the seed side
/// (appearing in tellActive) — exactly the regression face this assertion
/// pins.
#[tokio::test]
async fn pause_all_covers_parked_check_pending_members() {
    let db = tmp_db("p125-pauseall");
    // Three unpaused adds with absent payloads (activate on the dead
    // trackers), payloads placed before the forceRechecks (full measured
    // bitmaps).
    let mut torrents = Vec::new();
    for i in 0..3u8 {
        let content = check_content_big(i);
        let dir = temp_dir(&format!("p125-pa-{i}"));
        torrents.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("p-{i}.bin")),
            dir,
            content,
            format!("p-{i}.bin"),
        ));
    }
    // The elastic-budget holder shape (see force_recheck_budget_2's
    // note): two dead-tracker holders keep the download pool full
    // (idle 0 — the elastic budget collapses to the base 1); the three
    // candidates queue in reserved behind the full pool and recheck
    // through the reserved arm: one in flight + two parked.
    let mut holders = Vec::new();
    for i in 0..2u8 {
        let content = check_content_big(30 + i);
        let dir = temp_dir(&format!("p143-pa-h{i}"));
        holders.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("ph-{i}.bin")),
            dir,
        ));
    }
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        max_concurrent_checks: 1,
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let mut holder_gids = Vec::new();
    for (bytes, dir) in &holders {
        holder_gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
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
    let mut gids: Vec<Gid> = Vec::new();
    for (bytes, dir, _, _) in &torrents {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
        ));
    }
    let mut all_queued = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle).await;
        if num_active(&handle).await == 2
            && waiting
                .iter()
                .filter(|v| v.status == StatusKind::Waiting)
                .count()
                == 3
        {
            all_queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_queued,
        "the three candidates did not park in reserved (download pool full)"
    );
    for (_, dir, content, name) in &torrents {
        std::fs::write(dir.join(name), content).unwrap_or_else(|e| panic!("write payload: {e}"));
    }
    for g in &gids {
        assert!(matches!(
            call(&handle, SessionCommand::ForceRecheck { gid: g.to_string() }).await,
            Ok(CommandReply::Gid(_))
        ));
    }
    // Deterministic split: one in flight + two parked ('checking' in
    // tellWaiting); the holders keep exactly 2 download slots (the
    // in-flight check holds no download slot).
    let mut split = false;
    for _ in 0..600 {
        let parked = tell_waiting(&handle)
            .await
            .iter()
            .filter(|v| v.status == StatusKind::Checking)
            .count();
        if parked == 2 && num_active(&handle).await == 2 {
            split = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(split, "budget 1 did not produce 1 in flight + 2 parked");
    assert!(matches!(
        call(&handle, SessionCommand::PauseAll).await,
        Ok(CommandReply::Accepted)
    ));
    // Terminal: every member requeued PAUSED (the intent reached the
    // in-flight registry AND the parked FIFO); none self-activated onto
    // the seed side (the pre-fix parked-face miss), none entered results.
    let mut all_paused = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle).await;
        let paused = gids
            .iter()
            .filter(|g| {
                waiting
                    .iter()
                    .any(|v| v.gid == **g && v.status == StatusKind::Paused)
            })
            .count();
        if paused == 3 {
            all_paused = true;
            break;
        }
        // (The in-flight member legitimately shows tellActive while its
        // recheck runs — the slot meter and the terminal face below are
        // the discriminators: the pre-fix parked-face miss would leave
        // the parked members unpaused on full bitmaps, self-activating
        // onto the seed side and never reaching the paused terminal.)
        // Upper bound, not equality: while the pause wave applies, a
        // holder transiently leaves the meter (state transition) and
        // num_active dips — the guard is that NO new download seat is
        // taken beyond the two holders.
        assert!(
            num_active(&handle).await <= 2,
            "zero download seats beyond the two holders"
        );
        assert!(
            tell_stopped_gids(&handle).await.is_empty(),
            "the check path produces zero results"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_paused,
        "after pauseAll the three members did not all requeue paused"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// unpauseAll clears leftover parked-face intents (review-fix regression,
/// the mirror of pause-all): under budget 1 + three members — at the
/// unpauseAll landing t1 has already requeued paused per its intent
/// (the reserved face, flipped by the reserved loop), t2 is in flight
/// (the checking face, covered by the existing loop), and **t3 is still
/// parked** (budget 1 is fully held by t2) — only the parked-face sweep
/// can clear its intent: partial bitmap -> requeue unpaused -> download-
/// side reactivation (dead tracker stays active). Pre-fix t3's intent
/// survived -> requeue paused left it stuck in the waiting queue.
#[tokio::test]
async fn unpause_all_clears_parked_check_pending_intent() {
    let db = tmp_db("p125-unpauseall");
    // Three unpaused adds with absent payloads; corrupt payloads placed
    // before the forceRechecks (the rechecks measure holes → the plain
    // requeue path, no full-bitmap carve-out in the mix).
    let mut torrents = Vec::new();
    for i in 0..3u8 {
        // 16 MiB payloads: the verify must outlast the teardown stagger
        // so the in-flight + parked split is a stable sampled state (a
        // 2-piece verify completes before the split can be observed).
        let content = check_content(20 + i);
        let mut corrupted = content.clone();
        corrupted[SEED_PIECE_LEN as usize + 5] ^= 0xff;
        let dir = temp_dir(&format!("p125-ua-{i}"));
        torrents.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("u-{i}.bin")),
            dir,
            corrupted,
            format!("u-{i}.bin"),
        ));
    }
    // The elastic-budget holder shape (see force_recheck_budget_2's
    // note): two dead-tracker holders keep the download pool full; the
    // three candidates queue in reserved and recheck through the
    // reserved arm — one in flight + two parked.
    let mut holders = Vec::new();
    for i in 0..2u8 {
        let content = check_content_big(40 + i);
        let dir = temp_dir(&format!("p143-ua-h{i}"));
        holders.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("uh-{i}.bin")),
            dir,
        ));
    }
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        max_concurrent_checks: 1,
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let mut holder_gids = Vec::new();
    for (bytes, dir) in &holders {
        holder_gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
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
    let mut gids: Vec<Gid> = Vec::new();
    for (bytes, dir, _, _) in &torrents {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
        ));
    }
    let mut all_queued = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle).await;
        if num_active(&handle).await == 2
            && waiting
                .iter()
                .filter(|v| v.status == StatusKind::Waiting)
                .count()
                == 3
        {
            all_queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_queued,
        "the three candidates did not park in reserved (download pool full)"
    );
    for (_, dir, payload, name) in &torrents {
        std::fs::write(dir.join(name), payload).unwrap_or_else(|e| panic!("write payload: {e}"));
    }
    for g in &gids {
        assert!(matches!(
            call(&handle, SessionCommand::ForceRecheck { gid: g.to_string() }).await,
            Ok(CommandReply::Gid(_))
        ));
    }
    // One in flight + two parked (the unpauseAll shape needs a member
    // still parked at that moment — with budget 1 the third member only
    // promotes after the second's completion).
    let mut split = false;
    for _ in 0..600 {
        let parked = tell_waiting(&handle)
            .await
            .iter()
            .filter(|v| v.status == StatusKind::Checking)
            .count();
        if parked == 2 && num_active(&handle).await == 2 {
            split = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(split, "budget 1 did not produce 1 in flight + 2 parked");
    assert!(matches!(
        call(&handle, SessionCommand::PauseAll).await,
        Ok(CommandReply::Accepted)
    ));
    // The in-flight member finishes first (hole → requeue PAUSED per the
    // intent); the parked member promotes carrying the intent.
    let mut first_paused = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle).await;
        if waiting
            .iter()
            .any(|v| gids.contains(&v.gid) && v.status == StatusKind::Paused)
        {
            first_paused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        first_paused,
        "the in-flight member did not requeue paused per its intent"
    );
    // unpauseAll: the reserved-paused member resumes AND the promoted
    // member's intent is cleared before its own completion.
    assert!(matches!(
        call(&handle, SessionCommand::UnpauseAll).await,
        Ok(CommandReply::Accepted)
    ));
    // Terminal: all three members requeued unpaused — queued behind
    // the full download pool (the holders hold both slots; the
    // download-side reactivation itself is queued, not active). No
    // member stays paused in the waiting queue (the pre-fix face
    // leaves the member that was still parked at unpauseAll stuck
    // paused — the stalled assert trips on the residue).
    let mut resumed = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle).await;
        let stalled = waiting
            .iter()
            .any(|v| gids.contains(&v.gid) && v.status == StatusKind::Paused);
        let unpaused = waiting
            .iter()
            .filter(|v| gids.contains(&v.gid) && v.status == StatusKind::Waiting)
            .count();
        // <= 2, not == 2: on slow hosts a holder can finish its
        // verification between polls and leave the meter before this
        // triple condition is observed — the regression surface is the
        // stuck-pause residue, not the exact meter reading.
        if num_active(&handle).await <= 2 && !stalled && unpaused == 3 {
            resumed = true;
            break;
        }
        assert!(
            tell_stopped_gids(&handle).await.is_empty(),
            "zero results on the verification path"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        resumed,
        "after unpauseAll the members did not all resume running (leftover intents stuck)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

/// ⑥'s checking cells (the budget-park shape of
/// force_recheck_budget_2_parks_third, sampled at the same catch):
/// numChecking = **in flight only** (the parked check_pending member is
/// not counted); numWaiting = the four-segment merge (== the
/// tellWaiting count, the parked 'checking' member included); numActive
/// = 0 (a recheck holds no download slot). Meter counts only — the
/// The no-wall-clock discipline.
#[tokio::test]
async fn global_stat_checking_caliber_inflight_only() {
    let db = tmp_db("p127-check-cal");
    // The budget_park setup verbatim: two 32 MiB payloads (the verify
    // outlasts the stop teardowns — a wide in-flight window for the
    // catch), one tiny third task that parks.
    let mut torrents = Vec::new();
    for i in 0..2u8 {
        let content = check_content_big(i);
        let dir = temp_dir(&format!("p127-cal-{i}"));
        torrents.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("s-{i}.bin")),
            dir,
            content,
            format!("s-{i}.bin"),
        ));
    }
    let tiny = seed_content_n(7);
    let tiny_dir = temp_dir("p127-cal-tiny");
    torrents.push((
        downloadable_v1_torrent(&tiny, &dead_tracker(), "t.bin"),
        tiny_dir,
        tiny,
        "t.bin".to_string(),
    ));
    // The elastic-budget holder shape (see force_recheck_budget_2's
    // note): two holders keep the download pool full; the three
    // candidates queue in reserved and recheck through the reserved arm.
    let mut holders = Vec::new();
    for i in 0..2u8 {
        let content = check_content_wide(40 + i);
        let dir = temp_dir(&format!("p143-cal-h{i}"));
        holders.push((
            downloadable_v1_torrent(&content, &dead_tracker(), &format!("ch-{i}.bin")),
            dir,
        ));
    }
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        max_concurrent_checks: 2,
        max_concurrent_downloads: 2,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let mut holder_gids = Vec::new();
    for (bytes, dir) in &holders {
        holder_gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
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
    let mut gids: Vec<Gid> = Vec::new();
    for (bytes, dir, _, _) in &torrents {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddTorrent {
                    torrent: bytes.clone(),
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                    position: None,
                },
            )
            .await,
        ));
    }
    let mut all_queued = false;
    for _ in 0..600 {
        let waiting = tell_waiting(&handle).await;
        if num_active(&handle).await == 2
            && waiting
                .iter()
                .filter(|v| v.status == StatusKind::Waiting)
                .count()
                == 3
        {
            all_queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_queued,
        "the three candidates did not park in reserved (download pool full)"
    );
    for (_, dir, content, name) in &torrents {
        std::fs::write(dir.join(name), content).unwrap_or_else(|e| panic!("write payload: {e}"));
    }
    let (t1, t2, t3) = (gids[0], gids[1], gids[2]);
    for g in [&t1, &t2, &t3] {
        assert!(
            matches!(
                call(&handle, SessionCommand::ForceRecheck { gid: g.to_string() }).await,
                Ok(CommandReply::Gid(_))
            ),
            "forceRecheck must reply Gid"
        );
    }
    // The catch (the full-rate poll): t3 parked ('checking' in
    // tellWaiting) while t1/t2 verify.
    let mut caught = false;
    for _ in 0..3000 {
        let waiting = tell_waiting(&handle).await;
        if waiting
            .iter()
            .any(|v| v.gid == t3 && v.status == StatusKind::Checking)
        {
            caught = true;
            break;
        }
        // The verify race fallback (the budget-park test's escape): t3
        // promoted before any sample — the caliber faces below are
        // then pinned by the parked-sample path of the sibling test;
        // bail out without a meter assertion.
        let active = tell_active(&handle).await;
        if active
            .iter()
            .any(|v| v.gid == t3 && v.completed_length == v.total_length)
        {
            break;
        }
    }
    if caught {
        // ⑥: the meter matrix inside the two-verify window.
        let gs = global_stat(&handle).await;
        assert_eq!(
            gs.num_checking, 2,
            "numChecking = in flight (check_pending parking not counted)"
        );
        assert_eq!(
            gs.num_active, 2,
            "checks take no download seats (numActive is the two holders only)"
        );
        let waiting = tell_waiting(&handle).await;
        assert_eq!(
            gs.num_waiting as usize,
            waiting.len(),
            "numWaiting = the four-segment merge == the tellWaiting count"
        );
        assert_eq!(waiting.len(), 1, "the parked member is in tellWaiting");
        assert_eq!(waiting[0].gid, t3);
        assert_eq!(waiting[0].status, StatusKind::Checking);
        // ③'s check_pending slice (E2E direct evidence): the parked
        // member never appears in tellActive — the in-flight twins do,
        // the parked member lives in tellWaiting's check segment only.
        assert!(
            !tell_active(&handle).await.iter().any(|v| v.gid == t3),
            "a check_pending parked member never appears in tellActive"
        );
    } else {
        eprintln!("p127: park window missed; skipping the parked-sample meter faces");
    }
    // Drain (the always-true faces): all three route seed-side, zero
    // results, zero download slots.
    let mut all_seeded = false;
    for _ in 0..600 {
        let active = tell_active(&handle).await;
        let seeded = gids
            .iter()
            .filter(|g| {
                active.iter().any(|v| {
                    v.gid == **g && v.total_length > 0 && v.completed_length == v.total_length
                })
            })
            .count();
        if seeded == 3 && tell_waiting(&handle).await.is_empty() {
            all_seeded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        all_seeded,
        "the three rechecks did not all converge onto the seed side"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(3), wjoin).await;
}

// ---- elastic check budget (read-side compute) ----

/// The elastic-budget arithmetic (pure; `pump_all` supplies the live
/// readings): effective check cap = own budget + the download pool's
/// idle seats this instant. Idle = cap − active (saturating; active can
/// only exceed cap between a hot-reload narrowing and task completion).
/// No state, no flags, no timers — a download appearing is just
/// `active` growing, the cap falls back the same tick (narrowing does not
/// preempt:
/// the admission gate never evicts in-flight checks).
#[test]
fn elastic_check_budget_table() {
    // The elastic cap: the elastic component caps at the base budget
    // (effective ≤ 2×base) and the download cap is read-side clamped
    // to the option domain high end (0..=64).
    // Idle pool, cap 5: idle 5 -> min(5, base 2) -> 2+2=4 (not 7 —
    // the conservative disk rationale survives; idle seats double the
    // ceiling at most).
    assert_eq!(elastic_check_budget(2, 5, 0), 4);
    // Partially busy: idle 3/2/1 below or at the cap component.
    assert_eq!(elastic_check_budget(2, 5, 2), 4);
    assert_eq!(elastic_check_budget(2, 5, 3), 4);
    assert_eq!(elastic_check_budget(2, 5, 4), 3);
    // Fully busy: base only (the instant-fallback face).
    assert_eq!(elastic_check_budget(2, 5, 5), 2);
    // Over-cap active (narrowing window): saturates to base.
    assert_eq!(elastic_check_budget(2, 5, 7), 2);
    // Zero download cap degenerates to base (no seats to lend).
    assert_eq!(elastic_check_budget(2, 0, 0), 2);
    // Out-of-domain cap (raw 100 from direct construction): clamped
    // to 64, idle still capped by base — the one-pump whole-FIFO
    // admission spike is structurally unreachable (2×base bound).
    assert_eq!(elastic_check_budget(2, 100, 0), 4);
    assert_eq!(
        elastic_check_budget(4, 100, 0),
        8,
        "the 2x base upper bound"
    );
}

/// Narrowing non-preemption under the elastic cap (the narrowing-never-
/// preempts
/// invariant at the admission gate): with the download pool idle, the
/// effective cap admits the parked backlog; downloads activating (the
/// cap falling back to base) admit nothing more and evict nothing —
/// the admitted checks run to completion, later admissions wait for
/// base slots.
#[test]
fn elastic_budget_narrowing_never_preempts_in_flight() {
    let g = |n: u64| crate::gid::Gid::from_u64(n);
    let mut q = crate::session::queue::QueueMan::new();
    // Base shape: 2 in flight (the base budget consumed) + 7 parked.
    for i in 0..2u64 {
        q.insert_checking(g(i), false);
    }
    for i in 0..7u64 {
        q.insert_check_pending(g(i + 100), false);
    }
    // Download pool idle: effective budget 2 + min(5, base 2) = 4
    // admits exactly 2 more (the F2 component cap).
    let budget = elastic_check_budget(2, 5, 0);
    let mut admitted = 0;
    while let Some(e) = q.admit_next_check(budget) {
        q.insert_checking(e.gid, e.paused); // the pump's post-admission move
        admitted += 1;
    }
    assert_eq!(
        admitted, 2,
        "cap 2+min(5,2): 2 more admitted on top of the 2 in flight"
    );
    assert_eq!(q.checking_len(), 4);
    // Downloads fully busy: base budget 2 against 4 in flight — zero
    // admissions, zero evictions (the elastic 2 return as checks
    // finish).
    let narrowed = elastic_check_budget(2, 5, 5);
    assert!(q.admit_next_check(narrowed).is_none());
    assert_eq!(q.checking_len(), 4, "zero in-flight members evicted");
}
