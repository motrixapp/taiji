/// EOF-delimited streams through ThrottledSink — the global rate limit
/// governs download duration. Before the fix, a bare FileSink bypassed
/// the rate-limit bucket (the same volume finished instantly).
#[tokio::test]
async fn eof_stream_respects_overall_rate_limit() {
    let dir = temp_dir("http-m7-throttle");
    let body: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 41) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), false, false, false).await;
    // 64KiB/s -> 256KiB takes at least ~4s (zero initial bucket burst).
    let global = GlobalOptions {
        dir: dir.clone(),
        max_overall_download_limit: 64 * 1024,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let started = std::time::Instant::now();
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("eof.bin")],
                options: BTreeMap::new(),
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
        .any(|v| v.gid == gid && v.status == StatusKind::Complete)
    })
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(2000),
        "the EOF stream must be constrained by the rate limit (got {elapsed:?})"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ===== politeness-face convergence e2e (tail region) =====

/// Policy-throttled origin server (shared fixture for both tests):
/// data-plane requests answer 429 + `Retry-After: <v>` to the first hit
/// per policy, then always 206 until completion; probes (`bytes=0-0`)
/// are always 206. Records a timeline of every data-plane request's
/// (path, range, time, throttled) — the assertion face in origin-truth
/// terms.
#[derive(Clone)]
enum ThrottleTarget {
    /// Throttle the first data request overall (the steal-seam shape:
    /// whichever worker's first slice gets the 429, the remaining
    /// workers are potential in-window reclaimers).
    FirstOverall,
    /// Throttle the first data request on a path prefix (the yield
    /// shape: A's first slice eats the 429 backoff, B is the peer task
    /// on the same host).
    FirstOnPath(&'static str),
}

#[derive(Clone)]
struct GatedReqLog {
    path: String,
    start: u64,
    end: u64,
    at: Instant,
    throttled: bool,
}

struct GatedOrigin {
    addr: std::net::SocketAddr,
    reqs: Arc<std::sync::Mutex<Vec<GatedReqLog>>>,
}

async fn spawn_gated_origin(
    body: Arc<Vec<u8>>,
    target: ThrottleTarget,
    retry_after_secs: u64,
) -> GatedOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind origin: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let reqs: Arc<std::sync::Mutex<Vec<GatedReqLog>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let reqs_t = Arc::clone(&reqs);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (body, reqs) = (Arc::clone(&body), Arc::clone(&reqs_t));
            let target = target.clone();
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
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .to_string();
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
                    // Probe: a normal 206 (1-byte body).
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
                // Data plane: decide throttling per policy (record
                // first, then decide — the sequence is the decision
                // input).
                let throttled = {
                    let mut guard = reqs.lock().unwrap_or_else(|p| p.into_inner());
                    let throttled = match &target {
                        ThrottleTarget::FirstOverall => guard.is_empty(),
                        ThrottleTarget::FirstOnPath(prefix) => {
                            guard.iter().all(|r| !r.path.starts_with(prefix))
                                && path.starts_with(prefix)
                        }
                    };
                    guard.push(GatedReqLog {
                        path,
                        start: s,
                        end: e,
                        at: Instant::now(),
                        throttled,
                    });
                    throttled
                };
                if throttled {
                    let resp = format!(
                        "HTTP/1.1 429 Too Many Requests\r\n\
                         Retry-After: {retry_after_secs}\r\n\
                         Content-Length: 0\r\n\r\n"
                    );
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
                sock.write_all(&body[s as usize..=end]).await.ok();
                let _ = sock.shutdown().await;
            });
        }
    });
    GatedOrigin { addr, reqs }
}

impl GatedOrigin {
    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path)
    }

    fn data_reqs(&self) -> Vec<GatedReqLog> {
        self.reqs.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}
/// An active task's completed bytes (the metering face): fall back to
/// the stopped view when the active face reads nothing (terminal
/// completion = the full amount — a sampling window crossing the
/// completion boundary must not misread "no longer in the active
/// table" as 0).
async fn active_completed(handle: &SessionHandle, gid: &Gid) -> u64 {
    if let Some(v) = status_list(&call(handle, SessionCommand::TellActive { keys: vec![] }).await)
        .into_iter()
        .find(|v| v.gid == *gid)
    {
        return v.completed_length;
    }
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
    .find(|v| v.gid == *gid)
    .map(|v| v.completed_length)
    .unwrap_or(0)
}

/// Yield-while-backing-off e2e: two tasks on the same host with
/// per-host cap 1 — A (first in, single worker) takes a 429 +
/// `Retry-After: 2` on its first data request, and B (second in) must
/// get its data plane going within A's backoff window: the gap between
/// B's first data request and A's 429 must be far below the service
/// window (origin-truth terms). If A's worker held the permit through
/// its backoff sleep, B would stay pinned for >= the service window
/// before its first data request. A's own retry interval simultaneously
/// pins that Retry-After: 2 is respected (>= 1.9s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backoff_worker_releases_per_host_permit_for_peer_task() {
    const BLOCK: u64 = 256 * 1024;
    let dir = temp_dir("http-p85-yield");
    let body: Vec<u8> = (0..(4 * BLOCK) as usize).map(|i| (i % 199) as u8).collect();
    let origin =
        spawn_gated_origin(Arc::new(body.clone()), ThrottleTarget::FirstOnPath("/a"), 2).await;
    let (handle, join) = SessionActor::spawn();

    let gid_a = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("a.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    // Cap 1 (session-level last-set-wins): A must back
                    // off and yield for the yield face to exist; A
                    // single worker (split=1/cap=1 -> AIMD starts at 1)
                    // guarantees a unique permit holder.
                    ("http-max-per-host".to_string(), "1".to_string()),
                    ("max-connection-per-server".to_string(), "1".to_string()),
                    ("split".to_string(), "1".to_string()),
                    ("http-block-size".to_string(), BLOCK.to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    // Wait for A's first (429) data request to reach the origin (B's
    // entry anchor).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if origin.data_reqs().iter().any(|r| r.path.starts_with("/a")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "A's first data request never arrived within the window: {:?}",
            origin
                .data_reqs()
                .iter()
                .map(|r| r.path.clone())
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let gid_b = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("b.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("max-connection-per-server".to_string(), "2".to_string()),
                    ("split".to_string(), "2".to_string()),
                    ("http-block-size".to_string(), BLOCK.to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    // Both tasks complete (A includes the 2s backoff + retry; a wide
    // window guards against load jitter).
    let stopped: Vec<TorrentStatusView>;
    let deadline = Instant::now() + Duration::from_secs(40);
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
        let a_done = cur
            .iter()
            .any(|v| v.gid == gid_a && v.status == StatusKind::Complete);
        let b_done = cur
            .iter()
            .any(|v| v.gid == gid_b && v.status == StatusKind::Complete);
        if a_done && b_done {
            stopped = cur;
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the two tasks did not complete within the window"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let reqs = origin.data_reqs();
    let t_429 = reqs
        .iter()
        .find(|r| r.path.starts_with("/a"))
        .map(|r| r.at)
        .unwrap_or_else(|| panic!("A's 429 request must be on the timeline"));
    let t_b1 = reqs
        .iter()
        .find(|r| r.path.starts_with("/b"))
        .map(|r| r.at)
        .unwrap_or_else(|| panic!("B's data request must be on the timeline"));
    // Core assertion: B's first data request unfolds within A's backoff
    // window (service window 2s; when yielding works, B only needs a
    // probe + worker startup, ~100ms scale). Without yielding, B would
    // be pinned >= 2s.
    let b_gap = t_b1.saturating_duration_since(t_429);
    assert!(
        b_gap < Duration::from_millis(1400),
        "B must not be crowded out during A's backoff (the gap between B's first data request and \
         the 429 {b_gap:?} — permit-held yielding did not take effect, B was pinned by A's backoff \
         sleep)"
    );
    // A itself respects the service window (clamp 2s + fuzz 0-25% ->
    // [2.0, 2.5]s).
    let a_reqs: Vec<&GatedReqLog> = reqs.iter().filter(|r| r.path.starts_with("/a")).collect();
    assert_eq!(
        a_reqs.iter().filter(|r| r.throttled).count(),
        1,
        "exactly one 429 (fixture health)"
    );
    let a_retry = a_reqs
        .iter()
        .skip(1)
        .map(|r| r.at)
        .min()
        .unwrap_or_else(|| panic!("A must retry (refetch after the 429)"));
    let a_gap = a_retry.saturating_duration_since(t_429);
    assert!(
        a_gap >= Duration::from_millis(1900),
        "A's retry interval must honor Retry-After: 2 (got {a_gap:?})"
    );
    // Completion and content integrity (the two-task fixture health
    // face).
    for (gid, name) in [(gid_a, "a"), (gid_b, "b")] {
        let entry = stopped
            .iter()
            .find(|v| v.gid == gid)
            .unwrap_or_else(|| panic!("entry {name}"));
        let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(got, body, "task {name} content matches bit for bit");
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// No-steal-retransmit within the Retry-After window e2e: one task,
/// multiple workers; the first data request takes a 429 +
/// `Retry-After: 1` — the abandoned extent's byte range must have
/// **no overlapping re-request within the service window (~1s)**
/// (other workers must not reclaim and re-send while the failed worker
/// is backing off — the steal seam where the server wait applies only
/// to the failed worker); after the window a reclaim succeeds and the
/// task finishes Done. The steal shape (immediate return to the pool):
/// another worker reclaims within the window (the overlapping request
/// gap far below the window). Asserted against the origin's counted
/// per-path+range timeline (the 800ms bound leaves mock slack under
/// the 1s service window).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_after_extent_not_reclaimed_within_service_window() {
    const BLOCK: u64 = 256 * 1024;
    let dir = temp_dir("http-p85-nosteal");
    let body: Vec<u8> = (0..(4 * BLOCK) as usize).map(|i| (i % 211) as u8).collect();
    let origin = spawn_gated_origin(Arc::new(body.clone()), ThrottleTarget::FirstOverall, 1).await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    // 3 workers (AIMD starts at 3): after the 429 there
                    // are still >= 2 healthy workers as potential
                    // in-window reclaimers (the main steal shape).
                    ("max-connection-per-server".to_string(), "3".to_string()),
                    ("split".to_string(), "3".to_string()),
                    ("http-block-size".to_string(), BLOCK.to_string()),
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
            "the task did not complete within the window (reclaim after the service window)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let reqs = origin.data_reqs();
    assert!(
        reqs.iter().filter(|r| r.throttled).count() == 1,
        "exactly one 429 (fixture health)"
    );
    let victim = reqs
        .iter()
        .min_by_key(|r| r.at)
        .unwrap_or_else(|| panic!("the data-request timeline is non-empty"));
    assert!(
        victim.throttled,
        "the first data request must be the 429 victim"
    );
    // Within the service window there must be no overlapping
    // re-request of the victim's byte range (origin-truth terms: the
    // path+range timeline). The overlap check covers the re-slice shape
    // (a guided return to the pool re-slices with the same start but
    // splittable lengths — judged by byte overlap, not by identical
    // range).
    let mut overlapping_late = 0usize;
    for r in reqs.iter().filter(|r| !r.throttled) {
        let overlaps = r.start <= victim.end && r.end >= victim.start;
        if !overlaps {
            continue;
        }
        let gap = r.at.saturating_duration_since(victim.at);
        assert!(
            gap >= Duration::from_millis(800),
            "a re-request of the victim's byte range appeared inside the 429 service window \
             (gap {gap:?} < 800ms) — the RetryAfter abandon's not_before filter did not take \
             effect (the steal seam)"
        );
        overlapping_late += 1;
    }
    assert!(
        overlapping_late >= 1,
        "after the window a reclaim of the victim's byte range must exist (otherwise the task \
         could never be Done)"
    );
    // Completion and content integrity.
    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        got, body,
        "the post-window reclaim closes out, content matches bit for bit"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Dual-bucket rate changes take effect immediately (the global +
/// per-task dual token-bucket face): while downloading, changeOption
/// changes the per-task limit 4MiB/s -> 256KiB/s — both full 1s
/// metering windows after the 0.5s hot-update settling period must hug
/// the new rate (<= 1.5x, no stale-rate window left over); after
/// reversing 256KiB/s -> 4MiB/s the in-window rate recovers (>= 2x the
/// low rate). This test pins existing behavior (the
/// `TokenBucket::set_rate` hot-update chain + changeOption's
/// live_limiter face).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_task_rate_change_takes_effect_at_next_metering_window() {
    const BLOCK: u64 = 256 * 1024;
    const TOTAL: u64 = 6 * 1024 * 1024; // 24 blocks (grid path; must not finish in the
    // high-rate window — the sampling window must land mid-transfer)
    const HIGH: u64 = 4 * 1024 * 1024; // 4MiB/s
    const LOW: u64 = 256 * 1024; // 256KiB/s
    let dir = temp_dir("http-p85-rateshift");
    let body: Vec<u8> = (0..TOTAL as usize).map(|i| (i % 251) as u8).collect();
    let origin = spawn_gated_origin(
        Arc::new(body.clone()),
        ThrottleTarget::FirstOnPath("/never"), // healthy origin (no throttling)
        1,
    )
    .await;
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("max-connection-per-server".to_string(), "4".to_string()),
                    ("split".to_string(), "4".to_string()),
                    ("http-block-size".to_string(), BLOCK.to_string()),
                    ("max-download-limit".to_string(), HIGH.to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    // Startup: advance >= 512KiB at the high rate (an in-flight
    // anchor).
    let deadline = Instant::now() + Duration::from_secs(15);
    while active_completed(&handle, &gid).await < 512 * 1024 {
        assert!(
            Instant::now() < deadline,
            "the high-rate segment did not advance within the window"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Slow down: 4MiB/s -> 256KiB/s. After the 0.5s settling period
    // (truncated tokens in the bucket + changeOption's restart
    // convergence), take two full 1s metering windows.
    let result = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: BTreeMap::from([("max-download-limit".to_string(), LOW.to_string())]),
        },
    )
    .await;
    assert!(matches!(result, Ok(CommandReply::Accepted)), "{result:?}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let len_a = active_completed(&handle, &gid).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let len_b = active_completed(&handle, &gid).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let len_c = active_completed(&handle, &gid).await;
    let w1 = len_b.saturating_sub(len_a);
    let w2 = len_c.saturating_sub(len_b);
    // The new pace takes effect immediately: both full windows hug
    // 256KiB/s (the <= 1.5x tolerance includes scheduling jitter; the
    // token bucket is a hard cap — a stale-rate window would blow
    // straight through this bound).
    assert!(
        w1 <= LOW * 3 / 2,
        "after the slowdown the 1st metering window still hugged the old rate ({w1} B/s > 1.5x{LOW}) \
         — stale-rate residue"
    );
    assert!(
        w2 <= LOW * 3 / 2,
        "after the slowdown the 2nd metering window still hugged the old rate ({w2} B/s > 1.5x{LOW}) \
         — stale-rate residue across multiple windows"
    );

    // Reverse: 256KiB/s -> 4MiB/s. After a 0.2s convergence period take
    // a 1.2s metering window — the in-window rate must recover to
    // >= 2x the low rate (no stale low-rate pinning; the window is
    // shorter than the time to finish the remainder, so the sample must
    // land mid-transfer).
    let result = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: BTreeMap::from([("max-download-limit".to_string(), HIGH.to_string())]),
        },
    )
    .await;
    assert!(matches!(result, Ok(CommandReply::Accepted)), "{result:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let len_d = active_completed(&handle, &gid).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let len_e = active_completed(&handle, &gid).await;
    let w3 = len_e.saturating_sub(len_d);
    assert!(
        w3 >= LOW * 2,
        "after the speedup the in-window rate did not recover ({w3} B/1.2s < 2x{LOW}) — low-rate \
         residue pinned"
    );

    // Completion and content integrity.
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
            "the task did not complete within the window"
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
        "content matches bit for bit across the whole rate change"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}
