/// e2e (red-to-green): the many-small batch — 10 x 1MiB tasks (split=16 +
/// cap=16 + block=1M, factory `-j` = 5), with a dual assertion on in-batch
/// concurrency and wall time.
///
/// The serialization point is block granularity: a 1MiB file at a 1M block
/// is a single-extent task, so the `split` connection intent is
/// inexpressible there and batch parallelism is pinned at
/// min(-j, task count) x 1 connection. Assertions:
/// - the batch's concurrent Range peak >= min(split, cap) = 16 (pre-fix:
/// peak = 5, one connection per single-extent task);
/// - the batch wall time < half the factory-shape serial lower bound
/// (min(-j, N) tasks in parallel x single-connection rate; >= 2x better);
/// - every task completes and every file is byte-identical.
#[tokio::test]
async fn many_small_batch_per_file_parallel_ranges_beat_serial_wall() {
    const TOTAL: u64 = 1024 * 1024;
    const N: usize = 10;
    const SPLIT: u32 = 16;
    const PER_CONN_RATE_BPS: u64 = 136 * 1024; // optimistic upper bound on the origin: 4KiB per 30ms
    // Factory-shape serial lower bound: min(-j=5, N) tasks in parallel,
    // one connection each, ceil(N/5) waves run serially (the pre-fix batch
    // wall time approximated this value).
    let waves = N.div_ceil(5);
    let serial_secs = (waves as f64) * (TOTAL as f64 / PER_CONN_RATE_BPS as f64);
    let dir = temp_dir("http-many-small-batch");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, peak) = spawn_range_counting_origin(Arc::new(body.clone())).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let t0 = Instant::now();
    let mut gids = Vec::new();
    for i in 0..N {
        let gid = gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![format!("{base_url}/small{i}.bin")],
                    options: std::collections::BTreeMap::from([
                        ("split".to_string(), SPLIT.to_string()),
                        ("max-connection-per-server".to_string(), SPLIT.to_string()),
                        ("http-block-size".to_string(), "1M".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        );
        gids.push(gid);
    }
    // Every task reaches a terminal (complete) state.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut complete = Vec::new();
    while Instant::now() < deadline {
        complete = status_list(
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
        .into_iter()
        .filter(|v| v.status == StatusKind::Complete)
        .map(|v| v.gid)
        .collect();
        if complete.len() == N {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let wall = t0.elapsed();
    assert_eq!(
        complete.len(),
        N,
        "all small tasks must complete (missing {})",
        N - complete.len()
    );
    let peak_ranges = peak.peak();
    assert!(
        peak_ranges >= SPLIT as usize,
        "batch concurrent Range peak >= min(split,cap)={SPLIT} (pre-fix red face: a single-block \
         task's 1 connection x min(-j,N) tasks = 5), got {peak_ranges}"
    );
    assert!(
        wall.as_secs_f64() < serial_secs / 2.0,
        "batch wall clock {}s must be under half the shipped serial lower bound {}s (>=2x speedup)",
        wall.as_secs_f64(),
        serial_secs
    );
    // Final byte check: all tasks share one payload and must match bit for bit.
    for i in 0..N {
        let path = dir.join(format!("small{i}.bin"));
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(got, body, "small{i}.bin content matches bit for bit");
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ==== Batch aggregation scheduler (same-host transient batch group) e2e ====
// Upstream anchor mapping: docs/design/core.md

/// Dual-path peak origin: a path containing `/big` serves the big payload
/// with its own [`RangePeak`] counter, anything else the small payload with
/// another counter. The slow-write pacing matches
/// [`spawn_range_counting_origin`] (4KiB/30ms) — a computable in-flight
/// window for constructing contention.
async fn spawn_dual_range_origin(
    big: Arc<Vec<u8>>,
    small: Arc<Vec<u8>>,
) -> (std::net::SocketAddr, Arc<RangePeak>, Arc<RangePeak>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let peak_big = RangePeak::new();
    let peak_small = RangePeak::new();
    let (pb_t, ps_t) = (Arc::clone(&peak_big), Arc::clone(&peak_small));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (big, small, pb, ps) = (
                Arc::clone(&big),
                Arc::clone(&small),
                Arc::clone(&pb_t),
                Arc::clone(&ps_t),
            );
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&head).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let is_big = head.to_ascii_lowercase().contains("/big");
                    let body = if is_big { &big } else { &small };
                    let peak = if is_big { &pb } else { &ps };
                    let total = body.len() as u64;
                    let range = head
                        .to_ascii_lowercase()
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|v| {
                            let (s, e) = v.trim().split_once('-')?;
                            Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                        });
                    match range {
                        // Serving rule: e < total always answers 206 (the
                        // 0-0 probe must get 206, or the task is judged
                        // no-range and downgraded to one connection,
                        // idling the concurrency assertions); only
                        // data-plane requests (e > s) are counted.
                        Some((s, e)) if e < total => {
                            let counted = e > s;
                            if counted {
                                peak.open();
                            }
                            let end = (e as usize).min(total as usize - 1);
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes {s}-{end}/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Last-Modified: {LAST_MODIFIED_MOCK}\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: keep-alive\r\n\r\n",
                                end - s as usize + 1
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                if counted {
                                    peak.close();
                                }
                                return;
                            }
                            let slice = &body[s as usize..=end];
                            for chunk in slice.chunks(4 * 1024) {
                                if sock.write_all(chunk).await.is_err() {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(30)).await;
                            }
                            if counted {
                                peak.close();
                            }
                        }
                        _ => {
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                                 Last-Modified: {LAST_MODIFIED_MOCK}\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                            let _ = sock.shutdown().await;
                            return;
                        }
                    }
                }
            });
        }
    });
    (addr, peak_big, peak_small)
}

/// Feeds a group of tasks and waits for all to complete (the shared
/// batch e2e flow; returns the wall time).
async fn add_and_wait_complete(
    handle: &crate::session::actor::SessionHandle,
    base_url: &str,
    names: &[String],
    dir: &std::path::Path,
    opts: std::collections::BTreeMap<String, String>,
    timeout: Duration,
) -> (Duration, Vec<Gid>) {
    let t0 = Instant::now();
    let mut gids = Vec::new();
    for name in names {
        let gid = gid_of(
            &call(
                handle,
                SessionCommand::AddUri {
                    uris: vec![format!("{base_url}/{name}")],
                    options: opts.clone(),
                    position: None,
                },
            )
            .await,
        );
        gids.push(gid);
    }
    // TellStopped accumulation face: count only this round's gids (no cross-round mixing).
    let ids: std::collections::HashSet<Gid> = gids.iter().copied().collect();
    let all_done = |stopped: &[TorrentStatusView]| {
        stopped
            .iter()
            .filter(|v| ids.contains(&v.gid) && v.status == StatusKind::Complete)
            .count()
            == names.len()
    };
    let deadline = Instant::now() + timeout;
    loop {
        let stopped = status_list(
            &call(
                handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        if all_done(&stopped) || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stopped = status_list(
        &call(
            handle,
            SessionCommand::TellStopped {
                offset: 0,
                num: u32::MAX,
                keys: vec![],
            },
        )
        .await,
    );
    let complete = stopped
        .iter()
        .filter(|v| ids.contains(&v.gid) && v.status == StatusKind::Complete)
        .count();
    assert_eq!(
        complete,
        names.len(),
        "all batch-group tasks must complete ({}/{})",
        complete,
        names.len()
    );
    let _ = dir; // final file adjudication is the caller's job
    (t0.elapsed(), gids)
}

/// Case 1, batch-group lifecycle: group formation (multiple files on one
/// host join) -> cross-file stealing drives completion -> a finished file
/// leaves the group -> once all leave, the group dissolves and the budget
/// returns to the pool (active/queued back to zero, the registry entry
/// removed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_lifecycle_files_leave_and_budget_returns() {
    const TOTAL: u64 = 512 * 1024;
    const N: usize = 6;
    let dir = temp_dir("http-batch-lifecycle");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, _peak) = spawn_range_counting_origin(Arc::new(body.clone())).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let names: Vec<String> = (0..N).map(|i| format!("small{i}.bin")).collect();
    let (wall, _gids) = add_and_wait_complete(
        &handle,
        &base_url,
        &names,
        &dir,
        std::collections::BTreeMap::from([
            ("split".to_string(), "16".to_string()),
            ("max-connection-per-server".to_string(), "16".to_string()),
            ("http-block-size".to_string(), "1M".to_string()),
        ]),
        Duration::from_secs(60),
    )
    .await;
    // Final content check for every file (cross-file stealing must not
    // write the wrong owner's bytes).
    for name in &names {
        let path = dir.join(name);
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert_eq!(
            got, body,
            "{name} content matches bit for bit (steal write-back contract)"
        );
    }
    // Anchor that the concurrent data-plane path is really taken: a probe
    // judged no-range downgrades the task to one connection and the
    // assertion idles.
    assert!(
        _peak.peak() >= 2,
        "concurrent data-plane Ranges at the origin >= 2 during the batch group (got {})",
        _peak.peak()
    );
    // Group dissolved + budget back in the pool (observation seam: this
    // origin's host is exclusive).
    let host = format!("http://{addr}");
    let stats = http_task::small_batch_stats(&host);
    assert_eq!(stats.files, 0, "all files left the group (group dissolved)");
    assert_eq!(
        stats.active, 0,
        "budget back in the pool (active connections drop to zero)"
    );
    assert_eq!(stats.queued, 0, "queue emptied");
    assert!(
        wall.as_secs_f64() < 30.0,
        "batch-group wall clock {}s abnormal (fixture slow-write lower-bound check)",
        wall.as_secs_f64()
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Case 2, the contention-state aggregate connection peak stays within
/// budget: while the host cap is held by grid tasks, the batch group's
/// in-flight Range peak <= `--http-batch-budget` (the soft cap's CAS upper
/// bound; overflow attempts are all rejected while the host is full). The
/// big file's size dwarfs the small files' total, so the contention window
/// covers the small files' whole lifetime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_peak_within_budget_when_host_contended() {
    const BIG: u64 = 12 * 1024 * 1024; // 12 blocks @1M -> the grid path holds the cap
    const SMALL: u64 = 512 * 1024;
    const N_SMALL: usize = 3;
    const HOST_CAP: u32 = 6;
    const BUDGET: u32 = 3;
    let dir = temp_dir("http-batch-peak-budget");
    let big: Vec<u8> = (0..BIG as usize).map(|i| (i % 211) as u8).collect();
    let small: Vec<u8> = (0..SMALL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, peak_big, peak_small) =
        spawn_dual_range_origin(Arc::new(big.clone()), Arc::new(small.clone())).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    // Follower files (split=16 -> 16 ranges/16 workers per file): capped by
    // the ceiling as soon as they join (see the lead sequencing below).
    let follow_opts = std::collections::BTreeMap::from([
        ("split".to_string(), "16".to_string()),
        ("max-connection-per-server".to_string(), "16".to_string()),
        ("http-block-size".to_string(), "1M".to_string()),
        ("http-max-per-host".to_string(), HOST_CAP.to_string()),
        ("http-batch-budget".to_string(), BUDGET.to_string()),
    ]);
    // Lead file (hardened): split=2 -> 2 ranges/2 workers. Fast-path
    // dispatch requires min(split, cap) >= 2; split=1 is dispatched to the
    // grid path and never joins the batch group. Before the batch-form latch
    // (set by the second join, held open for the group's lifetime) only the
    // lead's workers can reserve without the ceiling ("pass-through"), and
    // that pass-through bound is structurally pinned to the lead's range
    // count = 2, independent of load duration. Pass-through workers count
    // into the group's active slots (gate_enter's CAS is visible before the
    // latch), so post-latch ceiling decisions already include the
    // pass-through share: the group's active peak = max(pass-through 2,
    // ceiling) = the budget, and pass-through never stacks above the
    // ceiling.
    let lead_opts = std::collections::BTreeMap::from([
        ("split".to_string(), "2".to_string()),
        ("max-connection-per-server".to_string(), "16".to_string()),
        ("http-block-size".to_string(), "1M".to_string()),
        ("http-max-per-host".to_string(), HOST_CAP.to_string()),
        ("http-batch-budget".to_string(), BUDGET.to_string()),
    ]);
    // The big file goes in first; wait until it is transferring and
    // holds the cap (the contention window opens).
    let big_opts = std::collections::BTreeMap::from([
        ("split".to_string(), "16".to_string()),
        ("max-connection-per-server".to_string(), "16".to_string()),
        ("http-block-size".to_string(), "1M".to_string()),
        ("http-max-per-host".to_string(), HOST_CAP.to_string()),
    ]);
    let big_gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!("{base_url}/big.bin")],
                options: big_opts,
                position: None,
            },
        )
        .await,
    );
    let big_gid_hex = big_gid.to_string();
    wait_until(async || {
        let st = match call(
            &handle,
            SessionCommand::TellStatus {
                gid: big_gid_hex.clone(),
                keys: vec![],
            },
        )
        .await
        {
            Ok(CommandReply::TorrentStatus(v)) => v,
            _ => return false,
        };
        st.connections >= 4 // transferring while holding the cap (grid intent 6 x host cap 6)
    })
    .await;
    peak_small.reset(); // defensively zero pre-contention noise
    // Join sequencing (hardened): the lead joins the group first (the join
    // order is pinned by polling — AddUri mailbox FIFO plus local probe
    // round trips make ordering likely, but under load a follower could
    // otherwise join first and leave the 16-worker file in the un-latched
    // window). The two followers joining triggers the second join -> the
    // latch sets -> all their workers' reservations are ceiling-bound. The
    // lead's 512KiB single connection takes ~3.8s (the fixture's
    // 30ms/4KiB pacing lower bound), far longer than the join interval, so
    // the batch form (files=3) outlives the followers.
    let host_key = format!("http://{addr}");
    let lead_name = "small0.bin".to_string();
    let lead_gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!("{base_url}/{lead_name}")],
                options: lead_opts,
                position: None,
            },
        )
        .await,
    );
    // Lead join wait (conditional poll, 30s bound — not a hard sleep):
    // under contention the host cap is held by the big file, so the lead's
    // probe itself queues for a host permit (freed only after the big
    // file's first block completes); the generic 5s wait_until window would
    // time out here.
    let join_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if http_task::small_batch_stats(&host_key).files >= 1 {
            break;
        }
        assert!(
            Instant::now() < join_deadline,
            "the lead file did not join the group within 30s (probe queued for a host permit \
             past timeout — the big file holding the cap for abnormally long)"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let names: Vec<String> = (1..N_SMALL).map(|i| format!("small{i}.bin")).collect();
    let mut small_gids = vec![lead_gid];
    for name in &names {
        let gid = gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![format!("{base_url}/{name}")],
                    options: follow_opts.clone(),
                    position: None,
                },
            )
            .await,
        );
        small_gids.push(gid);
    }
    // Joint observation (hardened): every 10ms the sampler captures the
    // origin's dual in-flight counters (big/small; the fixture's counting
    // excludes probe Ranges) in the same frame as the group active count
    // (including host-permit queuers). Layered assertions, each pinning one
    // invariant independent of observation-window load:
    // - L1 hard ceiling: in any frame, big+small in-flight <= HOST_CAP (the
    // deterministic per-connection acquire bound of the HostCap domain —
    // zero tolerance; broken HostCap wiring breaks this immediately);
    // - L2 polite share (the direct observation face of "in-flight Range
    // peak <= budget"): on contention-covered frames (big in-flight >=
    // HOST_CAP - BUDGET, i.e. host slack <= budget — the condition where
    // the ceiling fallback form holds), small in-flight <= BUDGET + 1.
    // The +1 is frame-drift tolerance from the sampler's non-atomic read
    // order, not pass-through tolerance (pass-through counts into the
    // group's active slots and does not stack). L1 plus the contention
    // definition mathematically imply small <= HOST_CAP - big <= BUDGET;
    // this assertion is an independent reading kept for a more
    // diagnosable failure message.
    // Group active (including permit queuers) must NOT be the criterion:
    // in the ceiling formula outside = host_active - group_active, queued
    // members without permits count into group_active but not host_active,
    // so a long group queue dilutes outside and the ceiling
    // max(budget, host_cap - outside) self-lifts toward the host cap. That
    // is intended work-conserving behavior (documented as "politeness, not
    // correctness"), not a ceiling failure; the ceiling's group semantics
    // are pinned by the taiji-http batch.rs unit tests (the gate_enter
    // series) and this e2e observes the L2 in-flight face instead.
    // The whole-run origin peak (the original assertion body) is demoted to
    // diagnostic output: under the work-conserving design the group may
    // legitimately fill host slack during idle windows (permit rotation
    // between big-file blocks), so the whole-run peak mixes
    // contention-unrelated frames — asserting on it was the original flake
    // source.
    let peak_active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worst_host_total = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worst_small_contended = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sampler_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let peak_active = Arc::clone(&peak_active);
        let worst_host_total = Arc::clone(&worst_host_total);
        let worst_small_contended = Arc::clone(&worst_small_contended);
        let stop = Arc::clone(&sampler_stop);
        let host_key = host_key.clone();
        let peak_big = Arc::clone(&peak_big);
        let peak_small = Arc::clone(&peak_small);
        tokio::spawn(async move {
            let cap: u32 = HOST_CAP;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let st = http_task::small_batch_stats(&host_key);
                let (big_cur, small_cur) = (peak_big.inflight(), peak_small.inflight());
                worst_host_total
                    .fetch_max(big_cur + small_cur, std::sync::atomic::Ordering::SeqCst);
                // Contention-covered frame (big in-flight >= HOST_CAP - BUDGET).
                let contended = big_cur as u32 + BUDGET >= cap;
                if contended {
                    worst_small_contended.fetch_max(small_cur, std::sync::atomic::Ordering::SeqCst);
                }
                if st.files >= 2 {
                    peak_active.fetch_max(st.active as usize, std::sync::atomic::Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };
    // Wait for all three to finish (90s bound; the same wait shape as add_and_wait_complete).
    let small_ids: std::collections::HashSet<Gid> = small_gids.iter().copied().collect();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
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
        let done = stopped
            .iter()
            .filter(|v| small_ids.contains(&v.gid) && v.status == StatusKind::Complete)
            .count();
        if done == N_SMALL || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sampler_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(1), sampler).await;
    let small_peak = peak_small.peak();
    let batch_form_peak = peak_active.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        batch_form_peak >= 1,
        "the batch form must actually occur (group active >= 1 — the anchor lesson where a probe \
         judged no-range downgraded the task to a single connection and the assertion idled, \
         2026-09-21)"
    );
    // L1: the host cap hard ceiling. +1 = the same sampler artifact L2
    // below already tolerates: worst_host_total sums two counters read
    // non-atomically, so a connection migrating between them inside one
    // sample frame is counted twice (observed 7 vs 6 once on the ubuntu
    // gates runner) — a measurement artifact, not a live-connection
    // overflow. A genuinely broken acquire bound shows up far above
    // +1 (the 16-intent face), which this bound still catches.
    let host_cap: usize = HOST_CAP as usize;
    let worst_total = worst_host_total.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        worst_total <= host_cap + 1,
        "L1 host-cap hard ceiling: same-frame in-flight big+small = {worst_total} > {} \
         (beyond the +1 sampler double-count tolerance — the HostCap \
         per-connection acquire bound is broken)",
        host_cap + 1
    );
    // L2: the polite share on contention-covered frames (+1 = the sampler's
    // non-atomic read-order tolerance; pass-through counts into the group's
    // active slots and does not stack). Diagnostic extra: the whole-run
    // small-file origin peak small_peak (legitimately mixed with
    // work-conserving use of host idle slack; for locating failures only,
    // never a criterion).
    let worst_small = worst_small_contended.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        worst_small <= BUDGET as usize + 1,
        "L2 contended-frame small-file in-flight {worst_small} > budget {BUDGET}+1 (violation = the \
         ceiling fallback is broken; diagnostics: whole-run small-file origin peak {small_peak}, \
         same-frame host in-flight peak {worst_total})"
    );
    // The big file must not starve behind the batch group (the mixed-load isolation half).
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let done = status_list(
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
        .into_iter()
        .any(|v| v.gid == big_gid && v.status == StatusKind::Complete);
        if done || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let big_done = status_list(
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
    .into_iter()
    .any(|v| v.gid == big_gid && v.status == StatusKind::Complete);
    assert!(
        big_done,
        "the big file (grid path) must not be starved by the batch group"
    );
    assert!(
        peak_big.peak() >= 4,
        "the big file's own concurrency is in-flight (contention face established)"
    );
    let got = std::fs::read(dir.join("big.bin")).unwrap_or_else(|e| panic!("read big: {e}"));
    assert_eq!(got, big, "big.bin content matches bit for bit");
    for i in 0..N_SMALL {
        let path = dir.join(format!("small{i}.bin"));
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("read small{i}: {e}"));
        assert_eq!(got, small, "small{i}.bin content matches bit for bit");
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Case 3 (loose criterion): the K-small-file batch group's throughput must
/// not drop significantly as K grows (K=8 aggregate throughput >= 0.6x K=2
/// — with the cross-file queue, more files mean more parallel units and
/// longer connection residency).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_throughput_monotonic_in_k() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-batch-monotonic");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, _peak) = spawn_range_counting_origin(Arc::new(body.clone())).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let opts = std::collections::BTreeMap::from([
        ("split".to_string(), "16".to_string()),
        ("max-connection-per-server".to_string(), "16".to_string()),
        ("http-block-size".to_string(), "1M".to_string()),
    ]);
    // K=2 round.
    let names2: Vec<String> = (0..2).map(|i| format!("k2-{i}.bin")).collect();
    let (wall2, _) = add_and_wait_complete(
        &handle,
        &base_url,
        &names2,
        &dir,
        opts.clone(),
        Duration::from_secs(60),
    )
    .await;
    // K=8 round (same origin, back to back — warm-pool/group-residency conditions held).
    let names8: Vec<String> = (0..8).map(|i| format!("k8-{i}.bin")).collect();
    let (wall8, _) = add_and_wait_complete(
        &handle,
        &base_url,
        &names8,
        &dir,
        opts.clone(),
        Duration::from_secs(90),
    )
    .await;
    let tput2 = (2.0 * TOTAL as f64) / wall2.as_secs_f64();
    let tput8 = (8.0 * TOTAL as f64) / wall8.as_secs_f64();
    assert!(
        tput8 >= tput2 * 0.6,
        "throughput monotonic (loose): K=8 throughput {tput8:.0}B/s >= K=2 {tput2:.0}B/s × 0.6 \
        (wall2={}s wall8={}s)",
        wall2.as_secs_f64(),
        wall8.as_secs_f64()
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Case 4, mixed-load isolation: a big file (grid path) and a small-file
/// batch group share one host — the big file's wall time <= 2.5x its solo
/// run (a loose anti-flake bound) and the small files all complete (no
/// mutual starvation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_load_large_grid_and_small_batch_no_starvation() {
    const BIG: u64 = 8 * 1024 * 1024; // 8 blocks @1M -> the grid path
    const SMALL: u64 = 512 * 1024;
    const N_SMALL: usize = 8;
    let dir = temp_dir("http-batch-mixed");
    let big: Vec<u8> = (0..BIG as usize).map(|i| (i % 211) as u8).collect();
    let small: Vec<u8> = (0..SMALL as usize).map(|i| (i % 199) as u8).collect();
    let opts = std::collections::BTreeMap::from([
        ("split".to_string(), "16".to_string()),
        ("max-connection-per-server".to_string(), "16".to_string()),
        ("http-block-size".to_string(), "1M".to_string()),
    ]);
    // Solo round: the big file alone (a fresh origin with the same
    // parameters keeps the per-connection rate comparable; the wall time is
    // read straight from add_and_wait_complete's timer).
    let solo_wall = {
        let (addr, _pb, _ps) =
            spawn_dual_range_origin(Arc::new(big.clone()), Arc::new(small.clone())).await;
        let global = GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        };
        let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
        let names = vec!["big/solo.bin".to_string()]; // the /big path routes to the big payload
        let (w, _) = add_and_wait_complete(
            &handle,
            &format!("http://{addr}"),
            &names,
            &dir,
            opts.clone(),
            Duration::from_secs(60),
        )
        .await;
        handle.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
        w
    };
    // Mixed round: the big file plus 8 small files injected at the same moment.
    let (addr, _pb, _ps) =
        spawn_dual_range_origin(Arc::new(big.clone()), Arc::new(small.clone())).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let t0 = Instant::now();
    let big_gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!("{base_url}/big.bin")],
                options: opts.clone(),
                position: None,
            },
        )
        .await,
    );
    for i in 0..N_SMALL {
        let _ = call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!("{base_url}/small{i}.bin")],
                options: opts.clone(),
                position: None,
            },
        )
        .await;
    }
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut big_done_at = None;
    let mut small_done;
    loop {
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
        let big_now = stopped
            .iter()
            .any(|v| v.gid == big_gid && v.status == StatusKind::Complete);
        if big_now && big_done_at.is_none() {
            big_done_at = Some(t0.elapsed());
        }
        small_done = stopped
            .iter()
            .filter(|v| v.status == StatusKind::Complete && v.gid != big_gid)
            .count();
        if (big_done_at.is_some() && small_done >= N_SMALL) || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mixed_big_wall = big_done_at
        .unwrap_or_else(|| panic!("big file never completed (mixed-load starvation face)"));
    assert_eq!(
        small_done, N_SMALL,
        "the small-file batch group all completed"
    );
    assert!(
        mixed_big_wall.as_secs_f64() <= solo_wall.as_secs_f64() * 2.5,
        "the big file's mixed-load wall clock {}s <= solo {}s × 2.5 (no mutual starvation, loose bound)",
        mixed_big_wall.as_secs_f64(),
        solo_wall.as_secs_f64()
    );
    // Final content check.
    let got = std::fs::read(dir.join("big.bin")).unwrap_or_else(|e| panic!("read big: {e}"));
    assert_eq!(got, big, "big.bin content matches bit for bit");
    for i in 0..N_SMALL {
        let path = dir.join(format!("small{i}.bin"));
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("read small{i}: {e}"));
        assert_eq!(got, small, "small{i}.bin content matches bit for bit");
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Counting origin with per-filename payloads (the regression face): every
/// file's content is distinct (the sha256(name) digest repeated). The batch
/// group's cross-file "wrong file's bytes" defect (the stealer's URI != the
/// piece owner's URI) only shows under distinct payloads — a shared-payload
/// fixture masks it silently (fixed by carrying the owner URI on the
/// piece).
async fn spawn_named_range_origin(
    payload_gen: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
) -> (std::net::SocketAddr, Arc<RangePeak>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let peak = RangePeak::new();
    let peak_t = Arc::clone(&peak);
    let payload_gen = std::sync::Arc::new(payload_gen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let peak = Arc::clone(&peak_t);
            let payload_gen = Arc::clone(&payload_gen);
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&head).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let lower = head.to_ascii_lowercase();
                    let name = lower
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/')
                        .to_string();
                    let body = payload_gen(&name);
                    let total = body.len() as u64;
                    let range = lower
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|v| {
                            let (s, e) = v.trim().split_once('-')?;
                            Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                        });
                    match range {
                        Some((s, e)) if e < total => {
                            let counted = e > s;
                            if counted {
                                peak.open();
                            }
                            let end = (e as usize).min(total as usize - 1);
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes {s}-{end}/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Last-Modified: {LAST_MODIFIED_MOCK}\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: keep-alive\r\n\r\n",
                                end - s as usize + 1
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                            let slice = &body[s as usize..=end];
                            for chunk in slice.chunks(4 * 1024) {
                                if sock.write_all(chunk).await.is_err() {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(30)).await;
                            }
                            if counted {
                                peak.close();
                            }
                        }
                        _ => {
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                                 Last-Modified: {LAST_MODIFIED_MOCK}\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                            let _ = sock.shutdown().await;
                            return;
                        }
                    }
                }
            });
        }
    });
    (addr, peak)
}

/// Case 1 regression: batch-group final adjudication under per-file
/// distinct payloads (byte correctness of cross-file stealing).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_distinct_payloads_byte_exact_across_steal() {
    const TOTAL: usize = 512 * 1024;
    const N: usize = 6;
    let dir = temp_dir("http-batch-distinct");
    // Per-file content = the sha256(name) digest repeated (distinct —
    // wrong-file bytes would mismatch).
    let payload_gen = |name: &str| -> Vec<u8> {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&*sha2_digest(name.as_bytes()));
        (0..TOTAL).map(|i| seed[i % 32]).collect()
    };
    let (addr, _peak) = spawn_named_range_origin(payload_gen).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let names: Vec<String> = (0..N).map(|i| format!("uniq{i}.bin")).collect();
    let (_wall, _gids) = add_and_wait_complete(
        &handle,
        &base_url,
        &names,
        &dir,
        std::collections::BTreeMap::from([
            ("split".to_string(), "16".to_string()),
            ("max-connection-per-server".to_string(), "16".to_string()),
            ("http-block-size".to_string(), "1M".to_string()),
        ]),
        Duration::from_secs(60),
    )
    .await;
    for name in &names {
        let want: Vec<u8> = {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&*sha2_digest(name.as_bytes()));
            (0..TOTAL).map(|i| seed[i % 32]).collect()
        };
        let path = dir.join(name);
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert_eq!(
            got, want,
            "{name} distinct payload matches bit for bit (steal URI contract regression face)"
        );
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// sha256 digest (a test-side helper; taiji-http already depends on sha2).
fn sha2_digest(data: &[u8]) -> std::sync::Arc<[u8; 32]> {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let out: [u8; 32] = h.finalize().into();
    std::sync::Arc::new(out)
}

// ===== Default per-host cap 64 + CLI/global option wiring =====

/// Assertion A (option face): the default session per-host cap is 64 —
/// visible directly in the getGlobalOption echo (HostCap init and the
/// option field share one source; both faces agree at spawn).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_per_host_cap_is_64_and_echoed() {
    let (handle, join) = SessionActor::spawn();
    match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(map)) => {
            assert_eq!(
                map.get("http-max-per-host").map(String::as_str),
                Some("64"),
                "the default per-host cap must echo 64 (raised in r7.1)"
            );
        }
        other => panic!("expected Options, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// Assertion A (behavior face): in the default shape (no http-max-per-host
/// from CLI/global/addUri), three same-host tasks with 16-connection intent
/// each (48 > the old default 32) must push the concurrent in-flight Range
/// peak past 32 — direct behavioral evidence for the default-cap raise from
/// 32 to 64 (a 32 hard-cap shape would pin the peak at <= 32).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_cap_64_admits_cross_task_concurrency_above_32() {
    const BS: u64 = 256 * 1024;
    const BLOCKS: u64 = 32; // 8MiB per task (32 blocks > 2 -> grid path, no batch group)
    const N_TASKS: usize = 3; // 3 x 16 = 48 connection intents > 32 (the old default cap)
    let total = BS * BLOCKS;
    let dir = temp_dir("http-p76-default-cap64");
    let body: Vec<u8> = (0..total).map(|i| (i % 199) as u8).collect();
    let (addr, peak) = spawn_range_counting_origin(Arc::new(body.clone())).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let names: Vec<String> = (0..N_TASKS).map(|i| format!("p76-{i}.bin")).collect();
    let (_wall, _gids) = add_and_wait_complete(
        &handle,
        &base_url,
        &names,
        &dir,
        std::collections::BTreeMap::from([
            ("split".to_string(), "16".to_string()),
            ("max-connection-per-server".to_string(), "16".to_string()),
            ("http-block-size".to_string(), "256K".to_string()),
        ]),
        Duration::from_secs(120),
    )
    .await;
    let seen = peak.peak();
    assert!(
        seen > 32,
        "under the default cap 64, same-host cross-task concurrent Range peak must exceed 32 \
         (48 intents; the old 32 hard-cap shape would pin it at <= 32), got {seen}"
    );
    assert!(
        seen <= 64,
        "the peak must not exceed the new default cap 64, got {seen}"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Assertion C: the addUri option `http-max-per-host` (last-set-wins, the
/// task-level override channel) takes priority over the session HostCap
/// init value (the CLI/global option injection face), in both directions:
/// lowering (init 8 -> addUri 2: the peak clamps to 2) and raising (init 2
/// -> addUri 8: the peak breaks 2). The effective value shows in the echo
/// (GetGlobalOption = HostCap::cap(), no drift).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_uri_per_host_override_wins_over_session_init_cap_both_directions() {
    const BS: u64 = 256 * 1024;
    const SMALL: u64 = 6 * BS; // 1.5MiB (6 blocks): converges in ~5.5s at cap 2
    let dir = temp_dir("http-p76-adduri-override");
    let body: Vec<u8> = (0..SMALL).map(|i| (i % 199) as u8).collect();
    let (addr, peak) = spawn_range_counting_origin(Arc::new(body.clone())).await;
    let base_url = format!("http://{addr}");

    // ---- Segment 1 (lowering override): init=8, addUri=2 -> the peak clamps to 2 ----
    let global1 = GlobalOptions {
        dir: dir.clone(),
        http_max_per_host: 8,
        ..Default::default()
    };
    let (h1, j1) = SessionActor::spawn_with(SessionOptions { global: global1 });
    let (_w1, _g1) = add_and_wait_complete(
        &h1,
        &base_url,
        &["down.bin".to_string()],
        &dir,
        std::collections::BTreeMap::from([
            ("split".to_string(), "16".to_string()),
            ("max-connection-per-server".to_string(), "16".to_string()),
            ("http-block-size".to_string(), "256K".to_string()),
            // Task-level override (the priority channel): pressed down to 2.
            ("http-max-per-host".to_string(), "2".to_string()),
        ]),
        Duration::from_secs(60),
    )
    .await;
    let seen1 = peak.peak();
    // The HostCap's unit is the *logical* per-host slot (one per active
    // worker, held across its fetch rounds): a mid-body abort/retry
    // leaves the origin writing the dying response's tail (4KiB/30ms
    // paced writes — the RST surfaces only at the next 30ms write tick)
    // while the retry's fresh connection already serves, so transient
    // *physical* sockets can reach cap+1 while logical slots stay
    // clamped (a gates run observed exactly this shape: peak 3 under
    // cap 2). The +1 slack tolerates one dying-tail overlap; anything
    // at or above cap*2 is real over-admission and still fails.
    assert!(
        seen1 > 1 && seen1 <= 3,
        "addUri=2 overrides init=8: concurrent Range peak must clamp at 2 \
         (+1 dying-retry-tail slack), got {seen1}"
    );
    // Effective-value echo (after the addUri override the echo = HostCap::cap(), no drift).
    match call(&h1, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(map)) => assert_eq!(
            map.get("http-max-per-host").map(String::as_str),
            Some("2"),
            "after the addUri override getGlobalOption must echo the effective value 2"
        ),
        other => panic!("expected Options, got {other:?}"),
    }
    h1.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), j1).await;
    // Drain in-flight requests to isolate the two segments' counts.
    let mut quiet = false;
    for _ in 0..250 {
        if peak.quiesced() {
            quiet = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        quiet,
        "in-flight requests must drain after segment 1 shuts down"
    );
    peak.reset();

    // ---- Segment 2 (raising override): init=2, addUri=8 -> the peak breaks 2 ----
    let global2 = GlobalOptions {
        dir: dir.clone(),
        http_max_per_host: 2,
        ..Default::default()
    };
    let (h2, j2) = SessionActor::spawn_with(SessionOptions { global: global2 });
    let (_w2, _g2) = add_and_wait_complete(
        &h2,
        &base_url,
        &["up.bin".to_string()],
        &dir,
        std::collections::BTreeMap::from([
            ("split".to_string(), "8".to_string()),
            ("max-connection-per-server".to_string(), "8".to_string()),
            ("http-block-size".to_string(), "256K".to_string()),
            // Task-level override (the priority channel): raised from init 2 to 8.
            ("http-max-per-host".to_string(), "8".to_string()),
        ]),
        Duration::from_secs(60),
    )
    .await;
    let seen2 = peak.peak();
    assert!(
        seen2 > 2,
        "addUri=8 overrides init=2: concurrent Range peak must break the init cap of 2 \
         (<=2 = a regression where the init swallowed the addUri raise), got {seen2}"
    );
    h2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), j2).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ==== e2e: fixed-chain activation overhead bound + batch time-weighted concurrency ====

/// Case 3-1, activation overhead bound (loose, anti-flake): submit N
/// many-small tasks concurrently across the whole window; assert that every
/// task's first connection is established (tellStatus connections >= 1 —
/// the observation anchor for the activation chain plus head:
/// probe/planning/prealloc/worker dispatch) within a loose bound of the
/// submission.
///
/// The bound is 1.8s: 16 tasks x 16-way probe/connect jitter can consume
/// the old 1.5s bound on a loaded box, so +300ms of full-load margin. The
/// serialization tax of a truly serialized activation chain is compound,
/// not linear — each later task's probe queues behind the earlier tasks'
/// in-flight connections on the same mock origin — so a serialized chain
/// still trips the 1.8s bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_small_activation_chain_overhead_bounded() {
    const TOTAL: u64 = 512 * 1024;
    const N: usize = 16;
    let dir = temp_dir("http-activation-bounded");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, _peak) = spawn_range_counting_origin(Arc::new(body)).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        // Full-window concurrency: queueing semantics (the default 5
        // slots) is not what this asserts — the activation chain itself
        // (pump -> activate -> drive head -> first connection) is.
        max_concurrent_downloads: N,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let opts = std::collections::BTreeMap::from([
        ("split".to_string(), "16".to_string()),
        ("max-connection-per-server".to_string(), "16".to_string()),
        ("http-block-size".to_string(), "1M".to_string()),
    ]);
    let t0 = Instant::now();
    let mut gids = Vec::new();
    for i in 0..N {
        gids.push(
            gid_of(
                &call(
                    &handle,
                    SessionCommand::AddUri {
                        uris: vec![format!("{base_url}/small{i}.bin")],
                        options: opts.clone(),
                        position: None,
                    },
                )
                .await,
            )
            .to_string(),
        );
    }
    // Every task's first connection established (loose polling: 50ms steps up to the 1.8s bound).
    let deadline = t0 + Duration::from_millis(1800);
    let mut connected = [false; N];
    loop {
        let mut all = true;
        for (i, gid) in gids.iter().enumerate() {
            if connected[i] {
                continue;
            }
            if let Ok(CommandReply::TorrentStatus(v)) = call(
                &handle,
                SessionCommand::TellStatus {
                    gid: gid.clone(),
                    keys: vec![],
                },
            )
            .await
            {
                if v.connections >= 1 {
                    connected[i] = true;
                }
            }
            if !connected[i] {
                all = false;
            }
        }
        if all || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let spread = t0.elapsed();
    let missing = connected.iter().filter(|c| !**c).count();
    assert_eq!(
        missing, 0,
        "{missing}/{N} tasks did not establish a first connection within 1.8s (activation-chain \
         regression: a serialized compound tax)"
    );
    assert!(
        spread <= Duration::from_millis(1800),
        "the whole-window N={N} first-connection spread {spread:?} exceeded the bound (loose \
         anti-flake semantics, see the test note)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Case 3-2, the batch group's time-weighted concurrency floor: while a
/// same-host many-small batch group lives (files >= 2; the gate face still
/// takes the group snapshot), the origin's in-flight concurrency,
/// time-weighted, stays >= 50% of the cap — a loose floor (task-switching
/// moments on the e2e mock swing widely; this anchors only the magnitude
/// regression of eliminated permit idling).
///
/// Measurement face (corrected): origin in-flight connections
/// (`RangePeak::inflight`, data-plane responses in flight) — no longer
/// `small_batch_stats().active` (gate reservations: includes workers
/// waiting for host permits and gate-holding residents, so the
/// waiting-worker regression stays green on that metric forever and the
/// assertion idles). Under the in-flight measure the regression directly
/// depresses the time weight (permits held by waiters keep real
/// transferrers from rising), so the red band is restored.
///
/// Supply dimension: N=6 x 512KiB / 16 splits = 96 extents of demand
/// against a host cap of 8, so the extent pool always dwarfs the cap; the
/// 4KiB/30ms slow write (32KiB per extent, ~240ms) keeps the batch
/// lifetime long enough to sample.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_time_weighted_concurrency_floor() {
    const TOTAL: u64 = 512 * 1024;
    const N: usize = 6;
    const HOST_CAP: u32 = 8;
    let dir = temp_dir("http-batch-timeweight");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, peak) = spawn_range_counting_origin(Arc::new(body)).await;
    let base_url = format!("http://{addr}");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let host_key = format!("http://{addr}");
    // Time-weighted sampler: while the batch form lives (files >= 2, gate
    // face), accumulate the origin's in-flight concurrency (the RangePeak
    // measure, not gate reservations) in 10ms steps.
    let active_sum = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let samples = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let (active_sum, samples, stop) = (
            Arc::clone(&active_sum),
            Arc::clone(&samples),
            Arc::clone(&stop),
        );
        let (host_key, peak) = (host_key.clone(), Arc::clone(&peak));
        tokio::spawn(async move {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if http_task::small_batch_stats(&host_key).files >= 2 {
                    active_sum
                        .fetch_add(peak.inflight() as u64, std::sync::atomic::Ordering::SeqCst);
                    samples.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };
    let names: Vec<String> = (0..N).map(|i| format!("small{i}.bin")).collect();
    let (_wall, _gids) = add_and_wait_complete(
        &handle,
        &base_url,
        &names,
        &dir,
        std::collections::BTreeMap::from([
            ("split".to_string(), "16".to_string()),
            ("max-connection-per-server".to_string(), "16".to_string()),
            ("http-block-size".to_string(), "1M".to_string()),
            ("http-max-per-host".to_string(), HOST_CAP.to_string()),
        ]),
        Duration::from_secs(90),
    )
    .await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(1), sampler).await;
    let n = samples.load(std::sync::atomic::Ordering::SeqCst);
    let sum = active_sum.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        n >= 20,
        "insufficient batch-form samples (n={n}) — the fixture shape is abnormal"
    );
    let tw = sum as f64 / n as f64;
    assert!(
        tw >= f64::from(HOST_CAP) * 0.5,
        "the batch-form origin in-flight concurrency time weight {tw:.2} fell below 50% of the cap \
         {HOST_CAP} (permit-idling regression: workers hold host permits while waiting for pieces — \
         proven directly on the in-flight measure)"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Security-review fix-round e2e ----

/// Fixture: a path-selective failure origin — data-plane requests hitting
/// `fail_path` always get 404 (the fast-fail shape: no server-supplied wait
/// value, so backoff follows the default exponential face); the probe
/// (`bytes=0-0`) always gets 206 (the segmentable verdict holds — the
/// precondition for batch/fast-path forms). Normal-path 206 bodies are
/// slow-written by quartile (quartile q: 4KiB per (10+150q)ms — q3 is
/// ~14.7s per extent), so owner workers park waiting for pieces as they
/// finish segments and become steal competitors when failed pieces requeue
/// (the construction for the cross-file attribution shape). Data-plane
/// request counts are recorded per path (bad/good split — the attribution
/// assertion face).
async fn spawn_path_failure_origin(
    body: Arc<Vec<u8>>,
    fail_path: &str,
) -> (
    std::net::SocketAddr,
    Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let counts: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let counts_t = Arc::clone(&counts);
    let fail_path = fail_path.to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (body, counts, fail_path) =
                (Arc::clone(&body), Arc::clone(&counts_t), fail_path.clone());
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let head = loop {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..pos + 4).collect();
                        break String::from_utf8_lossy(&head).into_owned();
                    }
                    let mut chunk = [0u8; 4096];
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let total = body.len() as u64;
                let range = head
                    .to_ascii_lowercase()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("range: bytes="))
                    .and_then(|v| {
                        let (s, e) = v.trim().split_once('-')?;
                        Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                    });
                let Some((s, e)) = range else { return };
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                if s == 0 && e == 0 {
                    // Probe: normal 206 (1-byte body).
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes 0-0/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: 1\r\n\r\n"
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&body[..1]).await.ok();
                    let _ = sock.shutdown().await;
                    return;
                }
                *counts
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .entry(path.clone())
                    .or_default() += 1;
                if path.contains(&fail_path) {
                    // Fast fail: 404, a retryable status -> the default exponential backoff.
                    sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .ok();
                } else {
                    let end = (e as usize).min(total as usize - 1);
                    let len = end - s as usize + 1;
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes {s}-{end}/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: {len}\r\n\r\n"
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    // Quartile-paced slow write: quartile completion pinned
                    // at 1s/7s/13s/19s (independent of split — ticks scaled
                    // by range length), so owner workers park progressively
                    // (from 1s/7s) and the file does not finish inside the
                    // failure-exhaustion window (~12.6s backoff chain),
                    // keeping parked competitors present throughout.
                    let quarter = (total / 4).max(1);
                    let q = (s / quarter).min(3);
                    let ticks = (((e - s) / (4 * 1024)) + 1).max(1);
                    let tick_ms = ((1000 + 6000 * q) / ticks).max(1);
                    for chunk in body[s as usize..=end].chunks(4 * 1024) {
                        if sock.write_all(chunk).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(tick_ms)).await;
                    }
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, counts)
}

/// Positive case (cross-file abort attribution in a batch group): two files
/// on one host form a batch (bad split=2, good split=8 — 10 workers
/// contending, SRPT cross-file stealing is the normal shape; good's
/// quartile slow write parks owner workers progressively, making them steal
/// competitors for the requeued failed piece, so cross-file exhaustion is
/// the routine shape). The bad file's data plane always 404s, and Range
/// failures exhaust to [`SMALL_PATH_FAILURE_CAP`] -> the abort must land on
/// the piece-OWNER file. Pre-fix the attribution broke both ways: the owner
/// worker drained all-Ok -> unconditional blocks_done=blocks_total -> the
/// zero-hole `.part` renamed to the final name and bad falsely recorded
/// Done; meanwhile the good worker that stole a bad failed piece reported
/// Err to its own driver, dragging good into Error. Post-fix assertions:
/// - bad -> Error (not Done — the abort is attributed to the owner via the
/// owner-matched Err return or the owner driver's post-drain
/// remaining()>0 check);
/// - good -> Done and byte-identical (it never carries the owner's error);
/// - the bad final name never appears (a truncated zero-hole file must not
/// be renamed to Done); the `.part` stays on disk (failure semantics).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_cross_file_abort_attributed_to_owner_file() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-batch-abort-own");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, counts) = spawn_path_failure_origin(Arc::new(body.clone()), "/bad.bin").await;
    let base_url = format!("http://{addr}");
    let (handle, join) = SessionActor::spawn();
    let opts = |split: &str| {
        std::collections::BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("split".to_string(), split.to_string()),
            ("max-connection-per-server".to_string(), split.to_string()),
        ])
    };
    let gid_bad = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!("{base_url}/bad.bin")],
                options: opts("2"),
                position: None,
            },
        )
        .await,
    );
    let gid_good = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!("{base_url}/good.bin")],
                options: opts("8"),
                position: None,
            },
        )
        .await,
    );

    // Both terminal states converge (good Done + bad Error; the
    // exhaustion backoff chain is ~13s, so the bound is relaxed).
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut stopped: Vec<TorrentStatusView>;
    loop {
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
        let good_done = stopped
            .iter()
            .any(|v| v.gid == gid_good && v.status == StatusKind::Complete);
        let bad_err = stopped
            .iter()
            .any(|v| v.gid == gid_bad && v.status == StatusKind::Error);
        if (good_done && bad_err) || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let bad = stopped
        .iter()
        .find(|v| v.gid == gid_bad)
        .unwrap_or_else(|| panic!("bad terminal state absent"));
    let good = stopped
        .iter()
        .find(|v| v.gid == gid_good)
        .unwrap_or_else(|| panic!("good terminal state absent"));
    assert_eq!(
        bad.status,
        StatusKind::Error,
        "the exhausted abort must be attributed to the owner file (Error not Done — a truncated \
         hole-free file must not be recorded as complete)"
    );
    assert_eq!(
        good.status,
        StatusKind::Complete,
        "a non-owner driver must not take the blame for the owner (in the steal shape the failing \
         worker usually belongs to good)"
    );
    // good byte-identical + no truncated-rename triangle.
    let got = std::fs::read(dir.join("good.bin")).unwrap_or_else(|e| panic!("read good: {e}"));
    assert_eq!(got, body, "good file matches bit for bit");
    assert!(
        !dir.join("bad.bin").exists(),
        "a failed file must not be renamed to its final name (a Prealloc hole-free truncated file \
         recorded as Done — a data-integrity red line)"
    );
    assert!(
        dir.join("bad.bin.part").exists(),
        "failure semantics: `.part` stays on disk (a manual-forensics face, not a resume face)"
    );
    let bad_reqs = counts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get("/bad.bin")
        .copied()
        .unwrap_or(0);
    assert!(
        bad_reqs >= 8,
        "the failure-exhaustion shape must actually occur (>= SMALL_PATH_FAILURE_CAP=8 data \
         requests, got {bad_reqs})"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Positive case 1 (batch-form RangeIgnored fast terminal): a small task
/// (512KiB, split=2 -> min(split,cap)=2 >= 2, hitting the fast-path batch
/// group); after the probe confirms the source is segmentable, data-plane
/// Range requests get 200 (capability drift) -> the batch failure arm must
/// terminate in one shot: the task fails explicitly with
/// `taiji.http.range_ignored` and data-plane requests number exactly 1
/// (pre-fix the batch arm lacked a fast terminal — RangeIgnored burned the
/// whole retry cap and ended as an abort with >= 2 data requests). The
/// final name never appears (the 200 body is never written to disk — the
/// fetch rejects before reading the body).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_range_ignored_fails_fast_single_request() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-batch-b2-200");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_drifting_origin(Arc::new(body.clone()), 200).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Error)
    })
    .await;

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let msg = entry.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.contains("taiji.http.range_ignored"),
        "the error message must carry the range_ignored explicit semantics: {msg:?}"
    );
    assert_eq!(
        origin.data_request_count(),
        1,
        "a deterministic protocol contradiction in the batch-group shape must not burn the retry \
         cap (exactly 1 data request — the fast-terminal arm)"
    );
    assert!(
        !dir.join("f.bin").exists(),
        "a failed task's final name must not appear (no truncated rename)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Positive case 2 (batch-form Retry-After priority): a small task in batch
/// form (512KiB, split=2 -> two extents fetching concurrently). The first 2
/// data-plane requests get 429 + `Retry-After: 1` -> the batch failure
/// arm's backoff must take the server value (clamped to 1s, replacing the
/// default 200ms exponential — pre-fix the batch arm always used 200ms).
/// Assertions: the gap from the 2nd to the 3rd data request is >= 900ms
/// (both extents fetch first at nearly the same moment, so the gap anchors
/// at the throttle window closing), the task completes, and the content is
/// byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_retry_after_is_honored_between_attempts() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-batch-b3-honor");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 251) as u8).collect();
    let origin = spawn_throttled_origin(Arc::new(body.clone()), Some("1".into()), 2).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Complete)
    })
    .await;

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        got, body,
        "content matches bit for bit after throttle recovery"
    );
    // Two extents fetching concurrently: req0/req1 land near the same
    // moment (inside the 429 window); the anchor for the server value
    // taking effect is the throttle-window closing gap (req1 -> req2, the
    // first successful refetch). If the default 200ms cadence had not been
    // replaced by the server value, this assertion goes red.
    let gap = origin
        .data_request_gap(1)
        .unwrap_or_else(|| panic!("need >= 3 data requests (two extents both 429 -> refetch)"));
    assert!(
        gap >= Duration::from_millis(900),
        "the batch-group retry interval must honor Retry-After: 1 (got {gap:?})"
    );
    assert!(
        gap < Duration::from_secs(35),
        "the interval must not exceed the clamp magnitude (the 30s cap + jitter headroom; got {gap:?})"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fixture: an extent-0 drift origin — the probe (`bytes=0-0`) gets a
/// normal 206; data-plane requests starting at 0 (the first extent) get a
/// 200 (capability drift -> RangeIgnored fatal, triggering the grid path's
/// fatal_b2 exit); other starts get a 206 slow-written at 4KiB/2ms (other
/// workers' long transfers stay in flight — constructing detached workers
/// that exist at the fail moment; without teardown they would keep claiming
/// extents and firing new requests). Data-plane request arrival times are
/// recorded (the zero-follow-up-request assertion face).
async fn spawn_extent0_drifting_origin(body: Arc<Vec<u8>>) -> FlakyOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let data_requests: Arc<std::sync::Mutex<Vec<std::time::Instant>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let data_requests_t = Arc::clone(&data_requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (body, data_requests) = (Arc::clone(&body), Arc::clone(&data_requests_t));
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let head = loop {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..pos + 4).collect();
                        break String::from_utf8_lossy(&head).into_owned();
                    }
                    let mut chunk = [0u8; 4096];
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let total = body.len() as u64;
                let range = head
                    .to_ascii_lowercase()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("range: bytes="))
                    .and_then(|v| {
                        let (s, e) = v.trim().split_once('-')?;
                        Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                    });
                let Some((s, e)) = range else { return };
                if s == 0 && e == 0 {
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes 0-0/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: 1\r\n\r\n"
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&body[..1]).await.ok();
                    let _ = sock.shutdown().await;
                    return;
                }
                data_requests
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(std::time::Instant::now());
                if s == 0 {
                    // First extent: after a 500ms delay, answer a 200
                    // header (capability drift — no body; the worker
                    // rejects at the header). The delay keeps the other
                    // workers' slow transfers deterministically present at
                    // the fatal moment (without teardown they would keep
                    // claiming extents — a deterministic construction, not
                    // a scheduling race).
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n");
                    sock.write_all(resp.as_bytes()).await.ok();
                    let _ = sock.shutdown().await;
                    return;
                }
                let end = (e as usize).min(total as usize - 1);
                let len = end - s as usize + 1;
                let resp = format!(
                    "HTTP/1.1 206 Partial Content\r\n\
                     Content-Range: bytes {s}-{end}/{total}\r\n\
                     Accept-Ranges: bytes\r\nContent-Length: {len}\r\n\r\n"
                );
                sock.write_all(resp.as_bytes()).await.ok();
                for chunk in body[s as usize..=end].chunks(4 * 1024) {
                    if sock.write_all(chunk).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    FlakyOrigin {
        addr,
        data_requests,
    }
}

/// Positive case 1 (fail-exit teardown of the worker pool): when the grid
/// path's fatal_b2 exit (RangeIgnored terminates in one shot) fires, the
/// other 15 workers are still slow-transferring — pre-fix, fail returned
/// directly and detached workers kept claiming extents and firing requests
/// (bandwidth drained on after the task was already error); post-fix the
/// unified teardown (abort + join + `.part` close) completes before the
/// error row, so from the moment Error is observable the origin sees zero
/// follow-up data requests (a precise 1.5s window equality assertion —
/// teardown is join semantics, not probabilistic). The final name never
/// appears (failure semantics).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grid_fail_teardown_stops_detached_workers_zero_requests() {
    const TOTAL: u64 = 16 * 1024 * 1024;
    let dir = temp_dir("http-r3-teardown");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_extent0_drifting_origin(Arc::new(body.clone())).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "16".to_string()),
                    ("max-connection-per-server".to_string(), "16".to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                    ("min-split-size".to_string(), "256K".to_string()),
                    ("http-scheduler".to_string(), "static".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Error)
    })
    .await;
    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let msg = entry.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.contains("taiji.http.range_ignored"),
        "fatal_b2 exit trigger face: {msg:?}"
    );
    assert!(
        origin.data_request_count() >= 2,
        "the detached-worker shape is present (fatal worker + at least one in-flight worker, got {})",
        origin.data_request_count()
    );
    // Time-window assertion: from the moment Error is observable, zero
    // follow-up data requests reach the origin for 1.5s (teardown =
    // abort + join — deterministic, not probabilistic).
    let baseline = origin.data_request_count();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let after = origin.data_request_count();
    assert_eq!(
        after, baseline,
        "after the fail, detached workers must stop hitting the origin (teardown face missing: \
         {after} > {baseline})"
    );
    assert!(
        !dir.join("f.bin").exists(),
        "a failed task's final name must not appear (no truncated rename)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Positive case 2 (forceRemove tears down the batch registry): two small
/// tasks on one host form a batch (2MiB each, 2 extents, 4KiB/30ms slow
/// write — a batch window of ~8s). Once the batch form is established,
/// forceRemove both -> the drivers are hard-aborted (the future drops at
/// await points), so leaving the group must be backstopped by the Drop
/// guard (the token is cancelled first so in-flight workers exit in
/// order). Assertion: the SMALL_BATCH registry entries clear (files == 0) —
/// pre-fix they leaked forever (the group never dissolved and pieces kept
/// being stolen into the removed tasks' `.part`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn force_remove_leaves_small_batch_registry_empty() {
    const TOTAL: u64 = 2 * 1024 * 1024;
    let dir = temp_dir("http-r3-forcerm");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let (addr, _peak) = spawn_range_counting_origin(Arc::new(body)).await;
    let base_url = format!("http://{addr}");
    let host_key = format!("http://{addr}");
    let (handle, join) = SessionActor::spawn();
    let opts = std::collections::BTreeMap::from([
        ("dir".to_string(), dir.display().to_string()),
        ("split".to_string(), "2".to_string()),
        ("max-connection-per-server".to_string(), "2".to_string()),
    ]);
    let mut gids: Vec<Gid> = Vec::new();
    for name in ["a.bin", "b.bin"] {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![format!("{base_url}/{name}")],
                    options: opts.clone(),
                    position: None,
                },
            )
            .await,
        ));
    }

    // forceRemove only after the batch form is established (files >= 2; form window ~8s, bound 6s).
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if http_task::small_batch_stats(&host_key).files >= 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the batch form was not established (files={}) — the fixture shape is abnormal",
            http_task::small_batch_stats(&host_key).files
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for gid in &gids {
        assert_eq!(
            call(
                &handle,
                SessionCommand::ForceRemove {
                    gid: gid.to_string()
                }
            )
            .await,
            Ok(CommandReply::Gid(*gid))
        );
    }
    // The registry clears (the Drop guard backstops leaving the group;
    // 3s bound — the hard abort's teardown is asynchronous, but the guard
    // drops synchronously with the future).
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if http_task::small_batch_stats(&host_key).files == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "batch-group registry entries linger after forceRemove (files={}) — the leave-group \
             Drop guard is missing",
            http_task::small_batch_stats(&host_key).files
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Positive case (a rejected addUri must not mutate the session cap): an
/// illegal `out` (a path component escaping `--dir` — the outside-directory
/// write red line) plus a legal `http-max-per-host` -> the task is rejected
/// AND the session HostCap registry is not mutated (the getGlobalOption
/// echo pinned at the default 64 — the live echo = HostCap::cap()).
/// Pre-fix set_cap ran before out sanitizing, so a rejected operation left
/// a global side effect (one field, all hosts). Positive control: a legal
/// addUri (paused, no network face) with cap 9 is accepted and the echo
/// becomes 9.
#[tokio::test]
async fn rejected_add_uri_does_not_mutate_session_host_cap() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-r4-cap-atomic");
    fn echo_cap(map: &std::collections::BTreeMap<String, String>) -> &str {
        map.get("http-max-per-host")
            .map(String::as_str)
            .unwrap_or_default()
    }
    let baseline = match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(map)) => echo_cap(&map).to_string(),
        other => panic!("expected Options, got {other:?}"),
    };
    assert_eq!(baseline, "64", "the default cap echoes 64 (r7.1)");

    // Rejection face: illegal out + legal cap -> addUri rejected.
    let rejected = call(
        &handle,
        SessionCommand::AddUri {
            uris: vec!["http://dead.test/f.bin".into()],
            options: std::collections::BTreeMap::from([
                ("dir".to_string(), dir.display().to_string()),
                ("out".to_string(), "../escape.bin".to_string()),
                ("http-max-per-host".to_string(), "9".to_string()),
            ]),
            position: None,
        },
    )
    .await;
    assert!(
        matches!(rejected, Err(SessionError::Failed { .. })),
        "an illegal out must be rejected at the task level (got {rejected:?})"
    );
    // The cap is not mutated (pre-fix the echo here was 9 — the rejected
    // operation's residual side effect).
    match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(map)) => assert_eq!(
            echo_cap(&map),
            "64",
            "a rejected addUri must not mutate the session cap (a single HostCap field applies to all hosts)"
        ),
        other => panic!("expected Options, got {other:?}"),
    }

    // Positive control: a legal addUri (paused — no network face) with cap
    // 9 is accepted and the effective-cap echo becomes 9 (the
    // last-set-wins channel semantics unchanged).
    assert!(matches!(
        call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://dead.test/g.bin".into()],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                    ("http-max-per-host".to_string(), "9".to_string()),
                ]),
                position: None,
            },
        )
        .await,
        Ok(CommandReply::Gid(_))
    ));
    match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(map)) => assert_eq!(
            echo_cap(&map),
            "9",
            "an accepted addUri cap adjustment must take effect (echo = HostCap::cap())"
        ),
        other => panic!("expected Options, got {other:?}"),
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ===== Per-task retry-backoff jitter fuzz (spreading the synchronized
// retry storm of multiple tasks failing on one source) =====

/// Shared throttle origin: the probe (`bytes=0-0`) gets a normal 206;
/// data-plane Range requests get 429 without Retry-After on the first
/// request per path (the default-pacing arm: the existing 200ms fixed
/// backoff plus additive jitter), then a normal 206 (the task converges to
/// Done — a permanent 429 would be re-pulled by the supervisor forever and
/// never turn terminal inside the test window). Requests are attributed by
/// URL path with arrival times recorded (the per-task retry-phase assertion
/// face for multiple tasks on one origin).
struct SharedThrottleOrigin {
    addr: std::net::SocketAddr,
    /// Data-plane request log: (path, arrival time).
    log: Arc<std::sync::Mutex<Vec<(String, Instant)>>>,
}

async fn spawn_shared_throttle_origin(body: Arc<Vec<u8>>) -> SharedThrottleOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let log: Arc<std::sync::Mutex<Vec<(String, Instant)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let throttled: Arc<std::sync::Mutex<std::collections::HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let (log_t, throttled_t) = (Arc::clone(&log), Arc::clone(&throttled));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (body, log, throttled) = (
                Arc::clone(&body),
                Arc::clone(&log_t),
                Arc::clone(&throttled_t),
            );
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&head).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let lower = head.to_ascii_lowercase();
                    let range = lower
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|v| {
                            let (s, e) = v.trim().split_once('-')?;
                            Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                        });
                    let Some((s, e)) = range else { return };
                    let total = body.len() as u64;
                    if s == 0 && e == 0 {
                        // Probe: 206 with one byte (the segmentable verdict
                        // holds — the data-plane 429 is throttling, not a
                        // capability gap).
                        let resp = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Range: bytes 0-0/{total}\r\n\
                             Accept-Ranges: bytes\r\nContent-Length: 1\r\n\r\n"
                        );
                        sock.write_all(resp.as_bytes()).await.ok();
                        sock.write_all(&body[..1]).await.ok();
                        continue;
                    }
                    let path = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("?")
                        .to_string();
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push((path.clone(), Instant::now()));
                    // First data request per path gets 429 (afterwards normal 206).
                    if throttled
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(path)
                    {
                        sock.write_all(
                            b"HTTP/1.1 429 Too Many Requests\r\n\
                             Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                        )
                        .await
                        .ok();
                        continue;
                    }
                    let end = (e as usize).min(total as usize - 1);
                    let len = end - s as usize + 1;
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes {s}-{end}/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: {len}\r\n\
                         Connection: keep-alive\r\n\r\n"
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    let slice = body[s as usize..=end].to_vec();
                    sock.write_all(&slice).await.ok();
                }
            });
        }
    });
    SharedThrottleOrigin { addr, log }
}

impl SharedThrottleOrigin {
    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path)
    }
}

/// Positive case (the synonym of aria2's fuzzDelay): N (=4) tasks fail on
/// the same source at the same moment (the shared throttle origin; each
/// task's first data request 429 without Retry-After) -> each task's first
/// retry time is distinct (per-task first-retry gaps show sample variance >
/// 0 — the additive jitter spreads the phases of the synchronized retry
/// storm; without it the N gaps are near-identical), then 206 recovers and
/// the tasks end Done. The gap lower bound = the 200ms base (jitter only
/// adds — pinning the existing lower-bound semantics e2e); the upper bound
/// is relaxed to 2s (mock timing margin so loaded-box scheduling jitter
/// does not flake).
#[tokio::test]
async fn http_retry_fuzz_desynchronizes_same_source_tasks() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b5-fuzz");
    let body = Arc::new(vec![0x5au8; 5 * 1024 * 1024]);
    let origin = spawn_shared_throttle_origin(Arc::clone(&body)).await;

    const N: usize = 4;
    let mut gids = Vec::new();
    for i in 0..N {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![origin.url(&format!("t{i}.bin"))],
                    options: BTreeMap::from([
                        ("dir".to_string(), dir.display().to_string()),
                        // With the default cap loosened, several workers
                        // run in parallel by default and the same path's
                        // request arrivals would be interleaved by several
                        // workers' initial requests (tiny gaps are not
                        // retry gaps); the first-retry gap assertion
                        // presumes a single-worker request order, so a
                        // single connection keeps the original scenario.
                        ("max-connection-per-server".to_string(), "1".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        ));
    }

    // First request 429 -> backoff retry succeeds -> task ends Done — wait for all to converge.
    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        gids.iter().all(|gid| {
            stopped
                .iter()
                .any(|v| v.gid == *gid && v.status == StatusKind::Complete)
        })
    })
    .await;

    // Per-task first-retry gap (arrival delta from the 1st to the 2nd data request).
    let log = origin.log.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let mut gaps: Vec<Duration> = Vec::new();
    for i in 0..N {
        let path = format!("/t{i}.bin");
        let times: Vec<Instant> = log
            .iter()
            .filter(|(p, _)| *p == path)
            .map(|(_, t)| *t)
            .collect();
        assert!(
            times.len() >= 2,
            "task {path} needs >= 2 data requests (429 -> retry): {times:?}"
        );
        gaps.push(times[1].duration_since(times[0]));
    }

    // Lower bound: jitter only adds — the gap >= the 200ms base (10ms mock timing margin).
    for (i, gap) in gaps.iter().enumerate() {
        assert!(
            gap >= &Duration::from_millis(190),
            "task {i}'s first retry gap {gap:?} < the 200ms base (fuzz must not breach the lower bound)"
        );
        assert!(
            gap < &Duration::from_secs(2),
            "task {i}'s first retry gap {gap:?} exceeds the 200ms+25%+scheduling-headroom magnitude"
        );
    }

    // Sample-variance assertion: the N gaps are distinct (not all equal) —
    // the synchronized retry storm is decoupled. Without jitter the N gaps
    // would be the same base plus same-magnitude scheduling noise, and
    // all-equal would be astronomically unlikely; this assertion is red for
    // a degenerate constant-zero-jitter implementation.
    let distinct = gaps.iter().collect::<std::collections::HashSet<_>>().len();
    assert!(
        distinct >= 2,
        "all N tasks failing at the same source at the same instant share an identical first-retry \
         gap ({gaps:?}) — the retry storm is not decoupled (fuzz absent or degenerate)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ===== Behavior-alignment round (BadRange fast terminal / cap domain //
// cap persistence / cross-file stagger) =====

/// Fixture: a 206 echo-mismatch origin — the probe (`bytes=0-0`) gets a
/// correct 206 echo (the segmentable verdict holds); any data-plane Range
/// request gets a 206 whose `Content-Range` echo is offset by +1024
/// (echo_start != request start — the first judgment arm of
/// [`taiji_http::client::validate_range_echo`]) -> download-time BadRange
/// (the deterministic protocol-contradiction trigger). Data-plane arrival
/// times are recorded one by one (the exactly-once assertion face).
async fn spawn_echo_mismatch_origin(body: Arc<Vec<u8>>) -> FlakyOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let data_requests: Arc<std::sync::Mutex<Vec<std::time::Instant>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let data_requests_t = Arc::clone(&data_requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (body, data_requests) = (Arc::clone(&body), Arc::clone(&data_requests_t));
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let head = loop {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..pos + 4).collect();
                        break String::from_utf8_lossy(&head).into_owned();
                    }
                    let mut chunk = [0u8; 4096];
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let total = body.len() as u64;
                let range = head
                    .to_ascii_lowercase()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("range: bytes="))
                    .and_then(|v| {
                        let (s, e) = v.trim().split_once('-')?;
                        Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                    });
                let Some((s, e)) = range else { return };
                if s == 0 && e == 0 {
                    // Probe: a correct 206 echo (the precondition for the drift
                    // shape — the probe verdict is 206).
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes 0-0/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: 1\r\n\r\n"
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&body[..1]).await.ok();
                    let _ = sock.shutdown().await;
                    return;
                }
                // Data plane: record the arrival time, then answer an
                // offset-echo 206 (the body is irrelevant — the client
                // rejects on the echo mismatch before reading the body).
                data_requests
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(std::time::Instant::now());
                let resp = format!(
                    "HTTP/1.1 206 Partial Content\r\n\
                     Content-Range: bytes {}-{}/{total}\r\n\
                     Accept-Ranges: bytes\r\nContent-Length: 0\r\n\r\n",
                    s + 1024,
                    e + 1024
                );
                sock.write_all(resp.as_bytes()).await.ok();
                let _ = sock.shutdown().await;
            });
        }
    });
    FlakyOrigin {
        addr,
        data_requests,
    }
}

/// e2e: a batch-form small task (512KiB, split=2 -> two extents fetching
/// concurrently); after the probe confirms the source is segmentable, the
/// download-time 206 echo mismatches the request (offset drift) -> the
/// batch failure arm must terminate in one shot (aligned with the
/// range_ignored fast terminal): the task fails explicitly with the code-8
/// family error (the canonical `taiji.http.bad_range`, the RPC numeric 8
/// CANNOT_RESUME slot), data-plane requests number exactly 1 (the second
/// extent hits the owner file's abort inside the 5ms stagger window and
/// exits Terminal without firing), and the final name never appears (the
/// drifted body is never written — the echo check rejects before reading
/// the body). Pre-fix red: BadRange took the normal failure arm, burned the
/// retry cap (>= 2 data requests), and the error code landed in the
/// `taiji.http.failed` merge face.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_bad_range_echo_fails_fast_single_request() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-p84-badrange");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_echo_mismatch_origin(Arc::new(body.clone())).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Error)
    })
    .await;

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let msg = entry.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.contains("taiji.http.bad_range"),
        "the error message must carry the bad_range explicit semantics (the code-8 family): {msg:?}"
    );
    assert_eq!(
        entry
            .error_engine
            .as_ref()
            .map(|e| e.code.as_str())
            .unwrap_or(""),
        "taiji.http.bad_range",
        "the engine failure code must be the canonical bad_range (the RPC numeric face 8 direct), \
         msg={msg:?}"
    );
    assert_eq!(
        origin.data_request_count(),
        1,
        "a 206 echo mismatch in the batch-group shape must not burn the retry cap (exactly 1 data \
         request — the fast-terminal arm)"
    );
    assert!(
        !dir.join("f.bin").exists(),
        "a failed task's final name must not appear (no truncated rename)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// e2e: the addUri `http-max-per-host` value domain matches the CLI face —
/// a huge value (2^33 > u32::MAX) gets an explicit `taiji.option.invalid`
/// rejection (pre-fix the parse accepted it and the effective face silently
/// clamped to u32::MAX) and no row is persisted (parse rejection precedes
/// row creation); the domain upper bound 2^32-1 is accepted as usual (the
/// CLI `value_parser!(u32).range(1..)` has the same domain).
#[tokio::test]
async fn add_uri_host_cap_domain_rejects_above_u32_without_row() {
    let dir = temp_dir("http-p84-capdomain");
    let db_path = dir.join("taiji.sqlite3");
    let (persist, writer) = PersistWriter::spawn(db_path.clone())
        .await
        .unwrap_or_else(|e| panic!("writer: {e}"));
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                ..Default::default()
            },
        },
        Some(persist),
    );

    // Huge value 2^33: explicit rejection (taiji.option.invalid prefix).
    let r = call(
        &handle,
        SessionCommand::AddUri {
            uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
            options: BTreeMap::from([
                ("dir".to_string(), dir.display().to_string()),
                ("http-max-per-host".to_string(), "8589934592".to_string()),
            ]),
            position: None,
        },
    )
    .await;
    match r {
        Err(SessionError::Failed { message }) => assert!(
            message.starts_with("taiji.option.invalid"),
            "a huge cap must be domain-rejected (the CLI's same-domain explicit rejection): {message}"
        ),
        other => panic!("a 2^33 cap value must be rejected, got {other:?}"),
    }
    assert_eq!(
        http_table_count(&db_path, "http_task", None),
        0,
        "a rejected addUri must not persist a row"
    );

    // Domain upper bound 2^32-1: accepted (the row persists + the cap
    // effective immediately via last-set-wins).
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/g.bin".to_string()],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                    ("http-max-per-host".to_string(), u32::MAX.to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    wait_until(async || http_row_of(&db_path, &gid_hex).is_some()).await;
    let (state, _) = http_row_of(&db_path, &gid_hex).unwrap_or_else(|| panic!("row"));
    assert_eq!(
        state, "paused",
        "the domain upper bound accepted (the pause intent stored with the row)"
    );
    // Close-out (row removal).
    assert_eq!(
        call(
            &handle,
            SessionCommand::ForceRemove {
                gid: gid_hex.clone()
            }
        )
        .await,
        Ok(CommandReply::Gid(gid))
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// e2e: lower the cap (`http-max-per-host=2`) -> shut down (the kill shape)
/// -> restart (session default cap 64, no CLI injection) -> resume
/// reactivates -> the origin's peak ground truth (the RangePeak measure) is
/// still the lowered value 2 — the cap intent persists in the row's
/// config_json and is restored at activation through the addUri-style
/// channel (pre-fix red: after restart the task reactivated at the session
/// default 64, the 16-connection intent fully expanded, and the peak
/// reached min(split,cap)=16). Also pins the "no infection" face: task rows
/// without the cap option carry no host_cap payload.
#[tokio::test]
async fn host_cap_intent_persists_and_resumes_lowered_after_restart() {
    const BS: u64 = 256 * 1024;
    const BLOCKS: u64 = 32; // 8MiB (> 2 blocks: the grid path, where the per-host cap actually throttles)
    const KILL_AT_DB: i64 = 1024 * 1024; // kill once the DB bitmap >= 1MiB (after the first snapshot)
    let total = BS * BLOCKS;
    let dir = temp_dir("http-p84-cappersist");
    let db_path = dir.join("taiji.sqlite3");
    let body: Vec<u8> = (0..total).map(|i| (i % 199) as u8).collect();
    let (addr, peak) = spawn_range_counting_origin(Arc::new(body.clone())).await;
    let url = format!("http://{addr}/f.bin");

    // ---- Session 1: 16-connection intent + cap lowered to 2 ->
    // shutdown once the bitmap crosses the threshold ----
    let (persist, writer) = PersistWriter::spawn(db_path.clone())
        .await
        .unwrap_or_else(|e| panic!("writer1: {e}"));
    let (handle, join) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                ..Default::default()
            },
        },
        Some(persist),
    );
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![url],
                options: BTreeMap::from([
                    ("split".to_string(), "16".to_string()),
                    ("max-connection-per-server".to_string(), "16".to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                    ("http-max-per-host".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // Control task (no cap option, paused): its row must carry no
    // host_cap payload (the no-infection face).
    let gid_b = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![format!("http://{addr}/b.bin")],
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_b_hex = gid_b.to_string();
    wait_until(async || {
        let a_ok = http_row_of(&db_path, &gid_hex)
            .map(|(_, cfg)| cfg.contains("\"host_cap\":2"))
            .unwrap_or(false);
        let b_clean = http_row_of(&db_path, &gid_b_hex)
            .map(|(_, cfg)| !cfg.contains("host_cap"))
            .unwrap_or(false);
        a_ok && b_clean
    })
    .await;
    // DB bitmap >= 1MiB -> shutdown (the kill shape: the row stays
    // "downloading"). At cap 2 the origin throughput is ~2x136KiB/s, so the
    // first snapshot plus 1MiB takes seconds — use a lenient loop (the 5s
    // wait_until window is not enough and flakes under load).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if http_row_progress_of(&db_path, &gid_hex)
            .map(|(_, _, done, _)| done >= KILL_AT_DB)
            .unwrap_or(false)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "session 1's bitmap progress did not reach the kill point (the cap=2 slow-transfer face)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The in-session last-set-wins face (existing behavior unchanged):
    // the fresh peak <= the lowered cap 2.
    let fresh_peak = peak.peak();
    assert!(
        fresh_peak <= 2,
        "session 1's cap lowering must take effect immediately (addUri set_cap), got peak {fresh_peak}"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    drop(writer);
    // Drain in-flight Ranges to isolate the two phases' counts.
    let mut quiet = false;
    for _ in 0..250 {
        if peak.quiesced() {
            quiet = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(quiet, "in-flight requests must drain after shutdown");
    peak.reset();

    // ---- Session 2: restart at the default cap 64 -> resume
    // reactivates with the lowered-cap intent restored ----
    let (persist2, writer2) = PersistWriter::spawn(db_path.clone())
        .await
        .unwrap_or_else(|e| panic!("writer2: {e}"));
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                ..Default::default()
            },
        },
        Some(persist2),
    );
    let mut complete = false;
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let list = status_list(
            &call(
                &handle2,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        if list
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Complete)
        {
            complete = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(complete, "the resumed task must complete");
    let resumed_peak = peak.peak();
    assert!(
        resumed_peak <= 2,
        "after restart+resume the origin peak ground truth must still be the lowered cap 2 (the \
         RangePeak measure), got {resumed_peak} — pre-fix it reactivated with the session default \
         64 (a peak up to 16)"
    );
    assert!(
        resumed_peak >= 2,
        "the resumed segment's dual-connection parallel lower bound (slack ample + 16 workers \
         contending for 2 permits), got {resumed_peak}"
    );
    // Final file byte check.
    let entry = status_list(
        &call(
            &handle2,
            SessionCommand::TellStopped {
                offset: 0,
                num: u32::MAX,
                keys: vec![],
            },
        )
        .await,
    )
    .into_iter()
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body, "the file is intact after the resumed transfer");
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join2).await;
    let _ = writer2.await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stagger fixture: an accept-timing origin — records each connection's
/// accept time and classifies after parsing the request header (probe =
/// `bytes=0-0`; data = any other Range). Data-plane response headers are
/// delayed 300ms (>> the ~25ms first-wave stagger window) before the body
/// is slow-written: the warm-pool signal (note_host_warm, a process-level
/// 90s window) lights only when the response header arrives — the delayed
/// header guarantees all K same-moment tasks' entire first waves unfold
/// inside the cold-host window (otherwise the first task's first response
/// lights the warm pool and later tasks skip the ramp, defeating the
/// fixture).
struct AcceptTimingOrigin {
    addr: std::net::SocketAddr,
    /// Sequence of (accept time, is_probe).
    accepts: Arc<std::sync::Mutex<Vec<(Instant, bool)>>>,
}

async fn spawn_accept_timing_origin(body: Arc<Vec<u8>>) -> AcceptTimingOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let accepts: Arc<std::sync::Mutex<Vec<(Instant, bool)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let accepts_t = Arc::clone(&accepts);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let at = Instant::now();
            let (body, accepts) = (Arc::clone(&body), Arc::clone(&accepts_t));
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&head).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let total = body.len() as u64;
                    let range = head
                        .to_ascii_lowercase()
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|v| {
                            let (s, e) = v.trim().split_once('-')?;
                            Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                        });
                    let Some((s, e)) = range else { return };
                    let is_probe = s == 0 && e == 0;
                    accepts
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push((at, is_probe));
                    if is_probe {
                        let resp = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Range: bytes 0-0/{total}\r\n\
                             Accept-Ranges: bytes\r\nContent-Length: 1\r\n\r\n"
                        );
                        sock.write_all(resp.as_bytes()).await.ok();
                        sock.write_all(&body[..1]).await.ok();
                        let _ = sock.shutdown().await;
                        return;
                    }
                    // Data plane: a 300ms header delay (the warm-pool window
                    // guard, see the struct doc), then a 4KiB/30ms slow
                    // body write.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let end = (e as usize).min(total as usize - 1);
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes {s}-{end}/{total}\r\n\
                         Accept-Ranges: bytes\r\n\
                         Last-Modified: {LAST_MODIFIED_MOCK}\r\n\
                         Content-Length: {}\r\n\
                         Connection: keep-alive\r\n\r\n",
                        end - s as usize + 1
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    for chunk in body[s as usize..=end].chunks(4 * 1024) {
                        if sock.write_all(chunk).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                }
            });
        }
    });
    AcceptTimingOrigin { addr, accepts }
}

impl AcceptTimingOrigin {
    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path)
    }

    /// Accept-time sequence of data-plane (non-probe) connections (the
    /// timeline-spread assertion face).
    fn data_accept_times(&self) -> Vec<Instant> {
        self.accepts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, probe)| !probe)
            .map(|(t, _)| *t)
            .collect()
    }
}

/// Staggered cross-file e2e: K (=3) tasks open a batch group at the same
/// moment (512KiB, 2 extents each — all join within the group-formation
/// window) -> the first-wave data connections arrive at distinct times
/// (timeline spread): adjacent ordinals in the group-level global order are
/// 5ms apart (CONNECT_STAGGER_MS); the assertion takes >= 2ms (mock timing
/// margin absorbing scheduling jitter). Pre-fix red: each file's Range
/// order started independently at 0 — K ordinal-0 connections at the same
/// moment (the first wave's 6 connections collapsed into 2 clusters with
/// ~0 intra-cluster gaps).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_group_same_moment_tasks_stagger_first_wave_globally() {
    const TOTAL: u64 = 512 * 1024;
    const K: usize = 3; // same-moment task count (>= 3)
    const RANGES_PER_TASK: usize = 2; // split=2/cap=2 -> 2 extents per task
    let dir = temp_dir("http-p84-stagger");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_accept_timing_origin(Arc::new(body.clone())).await;
    let (handle, join) = SessionActor::spawn();

    let mut gids = Vec::new();
    for i in 0..K {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![origin.url(&format!("t{i}.bin"))],
                    options: BTreeMap::from([
                        ("dir".to_string(), dir.display().to_string()),
                        ("split".to_string(), "2".to_string()),
                        ("max-connection-per-server".to_string(), "2".to_string()),
                    ]),
                    position: None,
                },
            )
            .await,
        ));
    }
    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        gids.iter().all(|gid| {
            stopped
                .iter()
                .any(|v| v.gid == *gid && v.status == StatusKind::Complete)
        })
    })
    .await;

    let mut times = origin.data_accept_times();
    times.sort_unstable();
    assert!(
        times.len() >= K * RANGES_PER_TASK,
        "first-wave data connections >= K x extents = {}, got {}: {times:?}",
        K * RANGES_PER_TASK,
        times.len()
    );
    // The first wave of K x RANGES data connections: arrival times distinct
    // (the >= 2ms timeline-spread assertion: the 5ms stagger step minus
    // scheduling-jitter margin).
    for pair in times[..K * RANGES_PER_TASK].windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(
            gap >= Duration::from_millis(2),
            "first-wave connection times clustered (gap {gap:?} < 2ms) — the group-level global \
             stagger did not take effect: {times:?}"
        );
    }
    // Completion and content integrity (the fixture health face).
    for (i, gid) in gids.iter().enumerate() {
        let entry = stopped
            .iter()
            .find(|v| v.gid == *gid)
            .unwrap_or_else(|| panic!("entry {i}"));
        let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(got, body, "task {i} content matches bit for bit");
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ===== Exact-start 206 echo with end-dimension deviation tolerance
// (over-delivery stream close / under-delivery partial progress) =====

/// The over-delivery fixture's filler overshoot (per data request): far
/// above the loopback socket buffer bound — the "filler cannot punch
/// through" assertion is bounded by this (the client closes the stream
/// after reading what it needs, so the origin's filler writes break quickly
/// at buffer scale, far below this value).
const P86_OVER_EXCESS: u64 = 16 * 1024 * 1024;

/// Fixture: a length-deviation origin (raw TCP wire level — observing the
/// early stream close of the over-delivery shape needs server-side real
/// write counts, which the axum face does not provide). The probe
/// (`bytes=0-0`) gets a normal 206; data-plane 206 echoes have an exact
/// start and a deviating end:
/// - over-delivery (`over = true`): the echo range equals the request
///   exactly, `Content-Length` inflated (needed + [`P86_OVER_EXCESS`]);
///   after writing the in-bounds body it keeps writing filler — a client
///   that closes after reading what it needs stops the filler (the
///   disconnect is observed via the real write count);
/// - under-delivery (`over = false`): the first request per range is echoed
///   shortened to the halfway end (`Content-Range: bytes s-(halfway)/T`,
///   CL matching the real send, a clean finish = EOF before the request
///   end); retries of the same range get the full answer (the
///   retry-completion face).
struct LenDeviationOrigin {
    addr: std::net::SocketAddr,
    /// Arrival-time sequence of data-plane (non 0-0) requests.
    data_requests: Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    /// Total filler bytes actually written (accumulated over successful
    /// writes; stops at disconnect).
    filler_written: Arc<std::sync::atomic::AtomicU64>,
    /// Ranges actually served short (counted on each range's first hit).
    short_served: Arc<std::sync::atomic::AtomicU64>,
}

async fn spawn_len_deviation_origin(body: Arc<Vec<u8>>, over: bool) -> LenDeviationOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let data_requests: Arc<std::sync::Mutex<Vec<std::time::Instant>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let filler_written = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let short_served = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Per-range hit counter for the short shape (first hit short, retry full).
    let range_hits: Arc<std::sync::Mutex<std::collections::HashMap<(u64, u64), u32>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let (data_requests_t, filler_written_t, short_served_t, hits_t) = (
        Arc::clone(&data_requests),
        Arc::clone(&filler_written),
        Arc::clone(&short_served),
        Arc::clone(&range_hits),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (body, data_requests, filler_written, short_served, hits) = (
                Arc::clone(&body),
                Arc::clone(&data_requests_t),
                Arc::clone(&filler_written_t),
                Arc::clone(&short_served_t),
                Arc::clone(&hits_t),
            );
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let head = loop {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..pos + 4).collect();
                        break String::from_utf8_lossy(&head).into_owned();
                    }
                    let mut chunk = [0u8; 4096];
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let total = body.len() as u64;
                let range = head
                    .to_ascii_lowercase()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("range: bytes="))
                    .and_then(|v| {
                        let (s, e) = v.trim().split_once('-')?;
                        Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                    });
                let Some((s, e)) = range else { return };
                if s == 0 && e == 0 {
                    // Probe: normal 206 (the segmentable verdict holds — the
                    // precondition for the deviation shapes).
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes 0-0/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: 1\r\n\r\n"
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&body[..1]).await.ok();
                    let _ = sock.shutdown().await;
                    return;
                }
                // Data plane: record the arrival time.
                data_requests
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(std::time::Instant::now());
                if over {
                    // Over-delivery: exact echo + inflated CL; after the
                    // in-bounds body, keep writing filler (a client that
                    // closes once it has what it needs breaks the write
                    // side at buffer scale).
                    let len = e - s + 1;
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes {s}-{e}/{total}\r\n\
                         Accept-Ranges: bytes\r\n\
                         Content-Length: {}\r\n\r\n",
                        len + P86_OVER_EXCESS
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&body[s as usize..=(e as usize).min(total as usize - 1)])
                        .await
                        .ok();
                    let filler = [b'F'; 16384];
                    let mut written: u64 = 0;
                    while written < P86_OVER_EXCESS {
                        if sock.write_all(&filler).await.is_err() {
                            break; // the client closed the stream (the origin-side disconnect view)
                        }
                        written += filler.len() as u64;
                    }
                    filler_written.fetch_add(written, std::sync::atomic::Ordering::SeqCst);
                } else {
                    // Under-delivery: the first hit is shortened to halfway
                    // (a clean finish = EOF before the request end); the
                    // retry gets the full answer.
                    let hit = {
                        let mut m = hits.lock().unwrap_or_else(|p| p.into_inner());
                        let n = m.entry((s, e)).or_insert(0);
                        *n += 1;
                        *n
                    };
                    let len = e - s + 1;
                    let (echo_end, body_len) = if hit == 1 {
                        short_served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        (s + len / 2 - 1, len / 2)
                    } else {
                        (e, len)
                    };
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes {s}-{echo_end}/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: {body_len}\r\n\r\n"
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&body[s as usize..(s + body_len) as usize])
                        .await
                        .ok();
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    LenDeviationOrigin {
        addr,
        data_requests,
        filler_written,
        short_served,
    }
}

impl LenDeviationOrigin {
    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path)
    }

    fn data_request_count(&self) -> usize {
        self.data_requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

/// Matrix 1 e2e (over-delivery stream close): a batch-form small task
/// (512KiB, split=2); the origin's 206 echo has an exact start but an
/// inflated `Content-Length` (+16MiB filler per extent) -> post-fix: read
/// what is needed and close the stream — the task ends Done, the content is
/// byte-identical, data-plane requests number exactly 2 (the over-delivery
/// is accounted as success, no retries), and the filler cannot punch
/// through from the origin's view (the connection drops once the needed
/// amount arrives; the body is never fully read). Pre-fix red: the read
/// loop rejected with `body overruns extent` -> burned the retry cap
/// (SMALL_PATH_FAILURE_CAP=8) -> task Error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p86_over_delivery_reads_needed_and_closes_early() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-p86-over");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_len_deviation_origin(Arc::new(body.clone()), true).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let stopped: Vec<TorrentStatusView>;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let cur = status_list(
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
        if cur
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Complete)
        {
            stopped = cur;
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the task did not complete within the window (over-delivery tolerance draining)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        got, body,
        "content matches bit for bit after over-delivery draining (filler bytes never hit disk)"
    );
    assert_eq!(
        origin.data_request_count(),
        2,
        "over-delivery credited successfully: exactly 1 data request per extent (no retries)"
    );
    let filler = origin
        .filler_written
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        filler >= 1,
        "the over-delivery shape must be present (body bytes are genuinely written past the in-domain amount)"
    );
    assert!(
        filler < P86_OVER_EXCESS,
        "from the origin's view the connection drops right after the required amount (filler \
         actually written {filler} never reaching {P86_OVER_EXCESS} — the body is not read to the end)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Matrix 2 e2e (under-delivery partial progress + the existing retry
/// completion): the origin's 206 echo start is exact and each range's first
/// fetch is echoed shortened to halfway (a clean EOF before the request
/// end) -> post-fix: bytes already read are credited as partial progress,
/// the short read takes the existing failure arm, and the extent returns to
/// the pool for retry -> the same range's second request gets the full
/// answer -> the task ends Done and the content is byte-identical. Pre-fix
/// red: an end deviation was judged BadRange at validation -> a fatal
/// one-shot terminal (task Error, data plane exactly 1 — the fast-terminal
/// philosophy overran a length dimension that should be tolerated).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p86_short_delivery_completes_via_existing_retry() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-p86-short");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_len_deviation_origin(Arc::new(body.clone()), false).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let stopped: Vec<TorrentStatusView>;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let cur = status_list(
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
        if cur
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Complete)
        {
            stopped = cur;
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the task did not complete within the window (retry backfill)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        got, body,
        "content matches bit for bit after retry backfill"
    );
    assert_eq!(
        origin
            .short_served
            .load(std::sync::atomic::Ordering::SeqCst),
        2,
        "both extents' first fetches must be served short (the shape is present)"
    );
    assert!(
        origin.data_request_count() >= 4,
        "each extent >= 2 data requests (short first fetch + retry backfill), got {}",
        origin.data_request_count()
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Matrix 3 e2e (regression anchor: start mismatch keeps the fast
/// terminal): the origin's 206 echo is offset +1024 wholesale (echo_start
/// != request start) -> the length-dimension relaxation must NOT erode the
/// fast terminal: the task fails explicitly (the canonical
/// `taiji.http.bad_range`, code-8 family), data-plane requests number
/// exactly 1, and the final name never appears.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p86_start_mismatch_keeps_bad_range_fast_fail() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-p86-startmm");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_echo_mismatch_origin(Arc::new(body.clone())).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Error)
    })
    .await;

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let msg = entry.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.contains("taiji.http.bad_range"),
        "the error message must carry the bad_range explicit semantics (the code-8 family): {msg:?}"
    );
    assert_eq!(
        entry
            .error_engine
            .as_ref()
            .map(|e| e.code.as_str())
            .unwrap_or(""),
        "taiji.http.bad_range",
        "the engine failure code must be the canonical bad_range, msg={msg:?}"
    );
    assert_eq!(
        origin.data_request_count(),
        1,
        "a start mismatch must terminate fast (exactly 1 data request — the card does not erode it)"
    );
    assert!(
        !dir.join("f.bin").exists(),
        "a failed task's final name must not appear (no truncated rename)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Matrix 4 e2e (regression anchor: the plain-200 fast terminal stays): the
/// probe gets 206 but the data plane always gets 200 (capability drift) ->
/// nothing erodes: the task fails explicitly (`taiji.http.range_ignored`),
/// data-plane requests number exactly 1, and the final name never appears.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p86_plain_200_keeps_range_ignored_fast_fail() {
    const TOTAL: u64 = 512 * 1024;
    let dir = temp_dir("http-p86-200");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 199) as u8).collect();
    let origin = spawn_drifting_origin(Arc::new(body.clone()), 200).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    let mut stopped: Vec<TorrentStatusView> = Vec::new();
    wait_until(async || {
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
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Error)
    })
    .await;

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let msg = entry.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.contains("taiji.http.range_ignored"),
        "the error message must carry the range_ignored explicit semantics: {msg:?}"
    );
    assert_eq!(
        origin.data_request_count(),
        1,
        "the 200 fast terminal must stay (exactly 1 data request — the card does not erode it)"
    );
    assert!(
        !dir.join("f.bin").exists(),
        "a failed task's final name must not appear (no truncated rename)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}
