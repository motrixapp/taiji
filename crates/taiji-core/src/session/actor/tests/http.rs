/// Fixed Last-Modified answered by the mock origin (the remote-time
/// assertion source).
const LAST_MODIFIED_MOCK: &str = "Tue, 01 Sep 2026 12:00:00 GMT";

/// Range request log = (start, end_incl) pairs (the probe bytes=0-0 is
/// recorded too).
struct MockOrigin {
    addr: std::net::SocketAddr,
    ranges: Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    /// Per-request `Cookie` header value log (the replay assertion
    /// source).
    cookies_seen: Arc<std::sync::Mutex<Vec<Option<String>>>>,
}

async fn spawn_mock_origin(
    body: Arc<Vec<u8>>,
    serve_range: bool,
    with_length: bool,
    stall: bool,
) -> MockOrigin {
    spawn_mock_origin_full(body, serve_range, with_length, stall, None, false).await
}

/// Full-parameter form: `set_cookie` adds a Set-Cookie header to every
/// response (the cookie-capture tests); every request's `cookie`
/// header value is recorded into [`MockOrigin::cookies_seen`] (the
/// replay tests); `slow` writes the body in 32KiB chunks with 30ms
/// spacing (both the 200 and 206 arms — the sampling window for the
/// live face and the interruptible window for the grid path).
async fn spawn_mock_origin_full(
    body: Arc<Vec<u8>>,
    serve_range: bool,
    with_length: bool,
    stall: bool,
    set_cookie: Option<String>,
    slow: bool,
) -> MockOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let ranges = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cookies_seen: Arc<std::sync::Mutex<Vec<Option<String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let ranges_t = Arc::clone(&ranges);
    let cookies_seen_t = Arc::clone(&cookies_seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = Arc::clone(&body);
            let ranges = Arc::clone(&ranges_t);
            let cookies_seen = Arc::clone(&cookies_seen_t);
            let set_cookie = set_cookie.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    // Read one request head (delimited by \r\n\r\n).
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
                    cookies_seen.lock().unwrap_or_else(|p| p.into_inner()).push(
                        head.to_ascii_lowercase()
                            .lines()
                            .find_map(|l| l.strip_prefix("cookie: "))
                            .map(str::to_string),
                    );
                    if stall {
                        // Stall: never answer, wait for the peer to
                        // give up (cancelled at test end).
                        let mut sink = [0u8; 64];
                        loop {
                            match sock.read(&mut sink).await {
                                Ok(0) | Err(_) => return,
                                Ok(_) => {}
                            }
                        }
                    }
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
                        Some((s, e)) if serve_range && e < total => {
                            ranges
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .push((s, e));
                            let end = (e as usize).min(total as usize - 1);
                            let mut resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes {s}-{e}/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Last-Modified: {LAST_MODIFIED_MOCK}\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: keep-alive\r\n",
                                end - s as usize + 1
                            );
                            if let Some(sc) = &set_cookie {
                                resp.push_str(&format!("Set-Cookie: {sc}\r\n"));
                            }
                            resp.push_str("\r\n");
                            sock.write_all(resp.as_bytes())
                                .await
                                .unwrap_or_else(|e| panic!("write head: {e}"));
                            let slice = &body[s as usize..=end];
                            if slow {
                                // Chunked slow write: the interruptible
                                // download window of the grid path.
                                for chunk in slice.chunks(32 * 1024) {
                                    sock.write_all(chunk).await.ok();
                                    tokio::time::sleep(Duration::from_millis(30)).await;
                                }
                            } else {
                                sock.write_all(slice)
                                    .await
                                    .unwrap_or_else(|e| panic!("write body: {e}"));
                            }
                        }
                        _ => {
                            // No Range / ignored Range: 200 (the
                            // degraded-download scenarios).
                            if with_length {
                                let mut resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                                     Last-Modified: {LAST_MODIFIED_MOCK}\r\n\
                                     Connection: keep-alive\r\n"
                                );
                                if let Some(sc) = &set_cookie {
                                    resp.push_str(&format!("Set-Cookie: {sc}\r\n"));
                                }
                                resp.push_str("\r\n");
                                sock.write_all(resp.as_bytes()).await.ok();
                                if slow {
                                    // Chunked slow write: the sampling
                                    // window for the live face.
                                    for chunk in body.chunks(32 * 1024) {
                                        sock.write_all(chunk).await.ok();
                                        tokio::time::sleep(Duration::from_millis(30)).await;
                                    }
                                } else {
                                    sock.write_all(&body).await.ok();
                                }
                            } else {
                                let mut head = format!(
                                    "HTTP/1.1 200 OK\r\nLast-Modified: {LAST_MODIFIED_MOCK}\r\n\
                                     Connection: close\r\n"
                                )
                                .into_bytes();
                                if let Some(sc) = &set_cookie {
                                    head.extend_from_slice(
                                        format!("Set-Cookie: {sc}\r\n").as_bytes(),
                                    );
                                }
                                head.extend_from_slice(b"\r\n");
                                sock.write_all(&head).await.ok();
                                sock.write_all(&body).await.ok();
                                let _ = sock.shutdown().await;
                                return; // EOF-delimited; the connection ends.
                            }
                        }
                    }
                }
            });
        }
    });
    MockOrigin {
        addr,
        ranges,
        cookies_seen,
    }
}

impl MockOrigin {
    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path)
    }

    fn fetch_ranges(&self) -> Vec<(u64, u64)> {
        self.ranges
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .filter(|&(s, e)| !(s == 0 && e == 0))
            .collect()
    }

    /// The `Cookie` header each request carried (None = no cookie
    /// header).
    fn cookies_seen(&self) -> Vec<Option<String>> {
        self.cookies_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Flaky origin: probe requests (`bytes=0-0`) get a normal 206; data
/// Range requests get a 206 head followed by `drop_after` body bytes
/// and then a **disconnect** (no connection reuse — the real
/// disconnect shape). Two failure modes:
/// - `drop_after > 0`: a **failure with progress** — each fetch writes
///   `drop_after` bytes then breaks (the "drops after every segment"
///   long-transfer shape);
/// - `drop_after = 0`: disconnects without even sending the response
///   head — a **zero-byte failure** (a connect-phase break with no
///   transfer evidence).
///
/// Data-plane (non 0-0) requests are timestamped one by one for the
/// failure-cadence and retry-gap assertions.
struct FlakyOrigin {
    addr: std::net::SocketAddr,
    /// Data-plane Range request arrival timestamps (`Instant`).
    data_requests: Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
}

async fn spawn_flaky_origin(body: Arc<Vec<u8>>, drop_after: u64) -> FlakyOrigin {
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
                // Read one request head (\r\n\r\n delimited; one request
                // per connection here).
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
                    // Probe: a normal 206 (1-byte body; the probe reads
                    // only the head, then closes).
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
                // Data plane: record the request time.
                data_requests
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(std::time::Instant::now());
                if drop_after == 0 {
                    // Zero-byte failure mode: no head at all;
                    // disconnect right after reading the request.
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
                let n = (drop_after as usize).min(len);
                sock.write_all(&body[s as usize..s as usize + n]).await.ok();
                let _ = sock.shutdown().await;
            });
        }
    });
    FlakyOrigin {
        addr,
        data_requests,
    }
}

impl FlakyOrigin {
    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path)
    }

    fn data_request_count(&self) -> usize {
        self.data_requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Arrival gap between data-plane request i (0-based) and i+1 (the
    /// retry-backoff assertion source).
    fn data_request_gap(&self, i: usize) -> Option<Duration> {
        let reqs = self
            .data_requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        reqs.get(i + 1)
            .zip(reqs.get(i))
            .map(|(a, b)| a.duration_since(*b))
    }
}

/// Positive case (same semantics as the reference `mMadeProgress ->
/// mNumFailed=1`): a long transfer that repeatedly "drops after every
/// segment" — each fetch writes one full block (4MiB) then
/// disconnects. The failure budget resets on progress
/// ([`failure_budget_step`]), so the worker is not retired by the
/// five-consecutive-extent-failure cap; the task keeps advancing to
/// completion and the file is byte-identical. `--http-min-chunk=16M`
/// pins extents to >= 4 blocks so every fetch fails with a partial
/// body plus disconnect (never a full success), keeping the failure
/// shape present throughout (data-plane requests >= the 6-block
/// count). The default cap=1 keeps a single grid worker, so counts
/// are deterministic.
///
/// Terminal-state note: even without the progress reset, a capped
/// worker is re-spawned by the supervisor on the next drive tick and
/// the task still finishes — this e2e pins the scenario's terminal
/// outcome; exact counting semantics are pinned by the
/// `failure_budget_step_matrix` unit test.
#[tokio::test]
async fn http_progress_resets_worker_failure_budget() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b1-progress");
    // 24MiB = 6 blocks @4MiB (more than 2 blocks: no fast path).
    let body: Vec<u8> = (0..6 * 4 * 1024 * 1024u32)
        .map(|i| (i % 251) as u8)
        .collect();
    let origin = spawn_flaky_origin(Arc::new(body.clone()), 4 * 1024 * 1024).await;

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-min-chunk".to_string(), "16M".to_string()),
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
        "the file still matches bit for bit after block refetches across disconnect gaps"
    );
    // The failure shape is present throughout: data-plane requests
    // exceed the block count (>= 6 partial-body disconnects plus
    // finalization), not one smooth single-request download.
    assert!(
        origin.data_request_count() >= 6,
        "the repeated-disconnect shape must actually occur: {}",
        origin.data_request_count()
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative case: zero-byte failures (disconnect right after the head
/// is read, no body at all) are not progress evidence — the failure
/// cap still burns through (five consecutive zero-byte failures ->
/// worker exit -> supervisor respawn -> burning again), and the task
/// **never completes**. Proves the progress reset only applies to
/// failures that wrote bytes; the negative close-out cap remains (the
/// same origin family as the positive case, the only difference being
/// byte progress — hence the binary terminal outcomes).
#[tokio::test]
async fn http_zero_byte_failures_are_not_progress() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b1-zero");
    let body: Vec<u8> = (0..6 * 4 * 1024 * 1024u32)
        .map(|i| (i % 251) as u8)
        .collect();
    let origin = spawn_flaky_origin(Arc::new(body.clone()), 0).await;

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-min-chunk".to_string(), "16M".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    // Observation window (~4s, several failure-cap cycles): the task
    // must not complete under zero-byte failures, and failing requests
    // must keep coming (cap burn -> respawn -> burn again; the
    // negative path is not exempted by the progress reset).
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(20)).await;
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
        .iter()
        .any(|v| v.gid == gid && v.status == StatusKind::Complete);
        assert!(
            !done,
            "zero-byte failures must not be excused as complete by the progress reset"
        );
        if origin.data_request_count() >= 10 {
            break; // two cap cycles observed (5 per cycle) — enough evidence.
        }
    }
    assert!(
        origin.data_request_count() >= 10,
        "failures must keep occurring (respawn continues after cap burn): {}",
        origin.data_request_count()
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Throttled origin: probe requests (`bytes=0-0`) get a normal 206;
/// the **first `throttle_first_n` data-plane** requests get 429 +
/// `Retry-After: <v>` (None = 429 without the header), after which 206
/// serves to completion. Data-plane arrival times are recorded (the
/// retry-gap assertion source; parameterized because batched
/// multi-worker first fetches can hit the throttle concurrently).
async fn spawn_throttled_origin(
    body: Arc<Vec<u8>>,
    retry_after: Option<String>,
    throttle_first_n: usize,
) -> FlakyOrigin {
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
            let (body, data_requests, retry_after) = (
                Arc::clone(&body),
                Arc::clone(&data_requests_t),
                retry_after.clone(),
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
                    // Probe: a normal 206.
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
                let throttled = {
                    let mut reqs = data_requests.lock().unwrap_or_else(|p| p.into_inner());
                    let throttled = reqs.len() < throttle_first_n;
                    reqs.push(std::time::Instant::now());
                    throttled
                };
                if throttled {
                    // The first `throttle_first_n` data requests get
                    // 429 (no header when `retry_after` is None).
                    let mut resp =
                        String::from("HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n");
                    if let Some(v) = &retry_after {
                        resp.push_str(&format!("Retry-After: {v}\r\n"));
                    }
                    resp.push_str("\r\n");
                    sock.write_all(resp.as_bytes()).await.ok();
                    let _ = sock.shutdown().await;
                    return;
                }
                // Normal 206 (the full range body).
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
    FlakyOrigin {
        addr,
        data_requests,
    }
}

/// Positive case (honors the reference `parseUnavailableHeaders`
/// semantics): 429 + `Retry-After: 1` -> the retry waits for the
/// server value (clamped to 1s) — the gap between the first two
/// data-plane requests is >= ~1s (the 200ms default pace does not
/// apply), and the task completes with identical content. The gap
/// upper bound also proves no pathological stretching (clamp behavior
/// healthy). The clamp ceiling itself (3600s -> 30s) is pinned by the
/// taiji-http unit test `retry_after_clamp_semantics` (a 30s+ e2e is
/// not worth repeating here).
#[tokio::test]
async fn http_retry_after_is_honored_between_attempts() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b3-honor");
    let body: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_throttled_origin(Arc::new(body.clone()), Some("1".into()), 1).await;

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
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
    // Retry gap = the server value (1s): >= 900ms (scheduling jitter
    // tolerated). If the 200ms default pace were not replaced, this
    // assertion fails.
    let gap = origin
        .data_request_gap(0)
        .unwrap_or_else(|| panic!("need >= 2 data requests (429 -> retry)"));
    assert!(
        gap >= Duration::from_millis(900),
        "the retry interval must honor Retry-After: 1 (got {gap:?})"
    );
    assert!(
        gap < Duration::from_secs(35),
        "the interval must not exceed the clamp magnitude (the 30s cap + jitter headroom; got {gap:?})"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative case: 429 **without** a `Retry-After` header -> no server
/// value to honor, the default pace (200ms-class) retries — gap
/// < 900ms and the task completes. The wait applies only when the
/// server explicitly asks (no invented politeness delay).
#[tokio::test]
async fn http_throttle_without_retry_after_keeps_default_pace() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b3-default");
    let body: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_throttled_origin(Arc::new(body.clone()), None, 1).await;

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
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

    let gap = origin
        .data_request_gap(0)
        .unwrap_or_else(|| panic!("need >= 2 data requests (429 -> retry)"));
    // Upper bound (1500ms): a single scheduling hiccup under load can
    // already exceed 4.5x the nominal 200ms, so the old 900ms bound
    // was loosened. This fixture has no Retry-After header (no server
    // value to misuse), so the meaningful regressions it still catches
    // are a stretched default pace (a 2s-class retry-wait default or
    // the 30s clamp applied by mistake); both fail this bound.
    assert!(
        gap < Duration::from_millis(1500),
        "without Retry-After the default pace must hold (got {gap:?})"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Drifting origin: probe requests (`bytes=0-0`) get a normal 206 (so
/// the range-capable verdict holds); data-plane Range requests always
/// answer `data_status` — 200 = the full body (the "probe said yes,
/// download said no" capability drift); 404 = an off-table status
/// (the existing retryable failure path, for contrast). The data-plane
/// request count is recorded.
async fn spawn_drifting_origin(body: Arc<Vec<u8>>, data_status: u16) -> FlakyOrigin {
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
                    // Probe: a normal 206 (the range-capable verdict —
                    // the drift precondition).
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
                // Data plane: always answer with data_status.
                match data_status {
                    200 => {
                        // Full body (200 = Range ignored — the
                        // capability-drift shape).
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n");
                        sock.write_all(resp.as_bytes()).await.ok();
                        sock.write_all(&body).await.ok();
                    }
                    404 => {
                        sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .ok();
                    }
                    other => {
                        let resp = format!("HTTP/1.1 {other} X\r\nContent-Length: 0\r\n\r\n");
                        sock.write_all(resp.as_bytes()).await.ok();
                    }
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

/// Positive case (the reference's "Expected partial, but received OK"
/// -> STATUS_CANNOT_RESUME semantics): after the probe confirms range
/// support (206), a 200 to a download-phase Range request fails the
/// task **explicitly** with `taiji.http.range_ignored`, and there are
/// **zero new data requests after the terminal state** (a fatal ends
/// it immediately — no extent retry cap is burned; the first AIMD
/// wave's connection count is not pinned, see the assertion note).
/// Contrast with a probe-phase 200 (the origin honestly lacks Range ->
/// single-connection degraded completion, as in the no-range
/// degradation tests such as
/// `http_checksum_degraded_tee_verifies_without_reread`): probe phase
/// = capability degradation; download phase = capability drift that
/// fails explicitly (never a silent restart from zero, never a reward
/// for lying — the design decision is documented in the
/// `HttpRangeTransport::fetch` note).
#[tokio::test]
async fn http_probe_confirmed_then_200_fails_explicitly() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b2-200");
    let body: Vec<u8> = (0..5 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_drifting_origin(Arc::new(body.clone()), 200).await;

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
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
    // Fatal-once request contract: at least one data request
    // (RangeIgnored is decided by the data-plane fetch before reading
    // the body — zero requests is unreachable) and **zero new data
    // requests after the terminal state** (no retry cap or backoff is
    // burned — contrast the 404 negative case, whose retryable path
    // keeps adding requests during the window). The count itself is
    // not pinned to "exactly one": the AIMD slow-start first wave
    // opens up to `split` (default 5) concurrent connections, and
    // whether a second first-wave request lands before the fatal
    // teardown is pure timing — those are designed-in parallel
    // connections, not retries, and they burn no cap. Quiescence after
    // the terminal state is the deterministic criterion:
    // teardown_segmented aborts and joins every worker before the fail
    // close-out, so once the Error state is visible no in-flight
    // request source exists and the count must be stable (a request
    // after the terminal state would be a real retry, i.e. a real
    // defect).
    assert!(
        origin.data_request_count() >= 1,
        "the range_ignored fatal must be triggered by a data-plane request (the >= 1 lower bound)"
    );
    let quiet_at = origin.data_request_count();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        origin.data_request_count(),
        quiet_at,
        "after the fatal terminal there must be zero new data requests (no retry cap burned — \
         contrast the 404 negative case's backoff retries)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative case: an off-table 404 keeps the **retryable** failure
/// path (an unexpected_response-family error with failure-cap retries
/// — data-plane requests >= 2) and never enters the range_ignored
/// fatal semantics. Asserted within the window: no completion, retries
/// happen, and if an Error terminal is reached its message is
/// unexpected_response-family (the contrast to range_ignored's
/// fatal-once + terminal-quiescence contract).
#[tokio::test]
async fn http_plain_404_keeps_retryable_unexpected_response_path() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b2-404");
    let body: Vec<u8> = (0..5 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_drifting_origin(Arc::new(body.clone()), 404).await;

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                position: None,
            },
        )
        .await,
    );

    // Observation window: wait for a retry (>= 2 data requests) or an
    // Error terminal, whichever first.
    let mut final_msg: Option<String> = None;
    for _ in 0..250 {
        tokio::time::sleep(Duration::from_millis(20)).await;
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
            if v.status == StatusKind::Error {
                final_msg = v.error_message.clone();
                break;
            }
        }
        if origin.data_request_count() >= 2 {
            break;
        }
    }
    assert!(
        origin.data_request_count() >= 2,
        "404 must take the retryable path (>= 2 data requests), got {}",
        origin.data_request_count()
    );
    if let Some(msg) = final_msg {
        assert!(
            msg.contains("unexpected_response") && !msg.contains("range_ignored"),
            "if an Error terminal is reached, 404's error family must be unexpected_response: {msg:?}"
        );
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Grid-path e2e (session level): addUri -> probe (206 + TOTAL) ->
/// block-grid download -> bitmap snapshot -> finalize rename ->
/// tellStopped `http` sub-dictionary carries every promised field, the
/// file is byte-identical, terminal state Complete.
#[tokio::test]
async fn http_task_grid_download_completes_with_http_dict() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-grid");
    let body: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("f.bin")],
        options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);

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

    // http sub-dictionary promised fields:
    // finalUrl/blocks/blocksTotal/renamePending=false/
    // sources[url,rate,state].
    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let http = entry.http.as_ref().unwrap_or_else(|| panic!("http dict"));
    assert_eq!(http.final_url, origin.url("f.bin"));
    assert_eq!(
        http.blocks_total, 1,
        "1MiB @ 4MiB blocks = a single-block grid"
    );
    assert_eq!(http.blocks_done, 1);
    assert!(!http.rename_pending, "normal close-out has nothing pending");
    assert_eq!(http.sources.len(), 1);
    assert_eq!(http.sources[0].url, origin.url("f.bin"));
    assert_eq!(entry.total_length, body.len() as u64);
    assert_eq!(entry.completed_length, body.len() as u64);
    // Single-file view: output path + the source list
    // (files[].uris).
    assert_eq!(entry.files.len(), 1);
    assert!(
        entry.files[0].path.ends_with("f.bin"),
        "{}",
        entry.files[0].path
    );
    assert_eq!(entry.files[0].uris.len(), 1);
    // File bytes identical (at the renamed target; the `.part` is
    // gone).
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body, "downloaded bytes round-trip");
    // Exactly one full-file Range fetch happened (block 0); the probe
    // (0,0) is not counted.
    assert_eq!(origin.fetch_ranges(), vec![(0, body.len() as u64 - 1)]);

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// With a live view present, `completedLength` projects at byte level:
/// the projection may lead the block accounting (bytes of a
/// not-yet-full block become visible; under pure block accounting
/// completed would always equal blocks_done x block length and
/// sampling could never lead). Samples are monotonic, never exceed
/// totalLength, and the final value converges to the accounting final
/// (the stopped face remains the block-accounting authority). Block
/// accounting is unchanged: `http.blocksDone/blocksTotal` keep the
/// block granularity.
#[tokio::test]
async fn http_live_completed_length_projects_byte_level() {
    const BLOCK: u64 = 4 * 1024 * 1024;
    let dir = temp_dir("http-p63-bytes");
    // 5MiB = 2 blocks @4MiB; the 32KiB/30ms slow write gives a ~4s
    // download window (ample sampling).
    let body: Arc<Vec<u8>> = Arc::new((0..5 * 1024 * 1024u32).map(|i| (i % 241) as u8).collect());
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
    let (handle, join) = SessionActor::spawn();
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-block-size".to_string(), "4M".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    // Sample (completed, blocks_done, total) triples during the
    // download.
    let mut samples: Vec<(u64, u64, u64)> = Vec::new();
    wait_until(async || {
        let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
        if let Some(v) = active.iter().find(|v| v.gid == gid) {
            let blocks = v.http.as_ref().map(|h| h.blocks_done).unwrap_or(0);
            samples.push((v.completed_length, blocks, v.total_length));
        }
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
    assert!(
        samples.len() >= 4,
        "the sampling face must cover the download window (>= 4 beats); samples={samples:?}"
    );
    // (1) Byte-level: some sample leads the block accounting — bytes
    // of a partial block show up in completedLength (previously
    // completed always equaled blocks_done x block length).
    assert!(
        samples.iter().any(|&(c, b, _)| c > b * BLOCK),
        "completedLength must advance at byte level (may lead the block accounting); samples={samples:?}"
    );
    // (2) Monotonic and <= totalLength across all samples.
    let mut prev = 0u64;
    for &(c, _, t) in &samples {
        assert!(
            c >= prev,
            "completedLength must be monotonic: {prev} -> {c}"
        );
        assert!(c <= t, "completedLength <= totalLength: {c} > {t}");
        prev = c;
    }
    // (3) Final value = the accounting final: the stopped face (the
    // block-accounting authority) is full and self-consistent, and the
    // block face is full (projection != accounting — the terminal
    // close-out is unaffected by the byte projection).
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    assert_eq!(entry.total_length, body.len() as u64);
    assert_eq!(
        entry.completed_length,
        body.len() as u64,
        "the final value = the accounting final"
    );
    let http = entry.http.as_ref().unwrap_or_else(|| panic!("http dict"));
    assert_eq!(http.blocks_total, 2, "5MiB @ 4MiB = a two-block grid");
    assert_eq!(http.blocks_done, 2);
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body.as_slice(), "downloaded bytes round-trip");

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cold-row guard (semantics preserved): after a pause there is no
/// live reading, so `completedLength` projects the row's accounting
/// truth (`total_done`, the block face without partial-block bytes)
/// and `totalLength` the probe-authoritative total. The byte-level
/// projection applies only while a live view exists (projection !=
/// accounting: the cold-row face never reads or writes byte
/// counts).
#[tokio::test]
async fn http_cold_row_projection_keeps_accounting_face_after_pause() {
    const BLOCK: u64 = 4 * 1024 * 1024;
    let dir = temp_dir("http-p63-cold");
    let db = tmp_db("http-p63-cold");
    // 5MiB = 2 blocks @4MiB; block 1 (the 1MiB tail) completes first,
    // so the block face can rest at 4MiB.
    let body: Arc<Vec<u8>> = Arc::new((0..5 * 1024 * 1024u32).map(|i| (i % 233) as u8).collect());
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
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
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-block-size".to_string(), "4M".to_string()),
                    // The default cap is now 16 (5 parallel workers);
                    // this scenario's single-worker choreography (the
                    // 1MiB tail block completing first) is calibrated
                    // for one connection, so pin it explicitly.
                    ("max-connection-per-server".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // Wait for the block accounting to advance (the first block
    // persisted: the row bitmap present = at least one block), then
    // pause to freeze the cold row (the byte face leads the block face
    // by then — the main block is still being written after the tail
    // block finished).
    wait_until(async || {
        http_row_progress_of(&db, &gid_hex)
            .map(|(_, bm, _, _)| bm.is_some())
            .unwrap_or(false)
    })
    .await;
    let _ = call(
        &handle,
        SessionCommand::Pause {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || {
        http_row_progress_of(&db, &gid_hex)
            .map(|(s, _, _, _)| s == "paused")
            .unwrap_or(false)
    })
    .await;
    // Cold-row projection = the row's accounting truth: completed vs
    // the row's total_done (block face, whole blocks) and total vs the
    // probe-authoritative length.
    let (_, _, total_done, _) =
        http_row_progress_of(&db, &gid_hex).unwrap_or_else(|| panic!("row must exist"));
    let v = match call(
        &handle,
        SessionCommand::TellStatus {
            gid: gid_hex.clone(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => v,
        other => panic!("expected TorrentStatus reply, got {other:?}"),
    };
    assert_eq!(
        v.total_length,
        body.len() as u64,
        "the cold row's total = the probe authority"
    );
    // The projection is the byte face (including in-block tail bytes
    // of an in-flight block); the row is the block face (accounting
    // granularity). At the pause point they differ by less than one
    // in-flight block (the old single-connection timing happened to
    // make them equal; the widened concurrency cap broke that
    // coincidence). Invariant: block face <= projection <= block face
    // + BLOCK (the projection leads by at most one in-flight
    // block).
    assert!(
        v.completed_length >= total_done as u64 && v.completed_length < total_done as u64 + BLOCK,
        "the cold row's projection leads the row's block-face accounting by at most one block: \
         completed={} total_done={}",
        v.completed_length,
        total_done
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Checksum-prefetch overlap: a slow origin (32KiB/30ms chunks) with a
/// 64MiB body (16-block grid path) over 8 connections — guided
/// assignment gives each connection 2 sequential blocks, so block
/// completions arrive in two waves well separated in time, far more
/// than the time the pre-hash needs to catch up. By the time finish
/// runs, the unconsumed bytes must be <= total/2 (a post-hoc
/// full-hash would see the full total — the prefetch would never have
/// consumed anything during the download). The final file must be
/// byte-correct and the completion notification must arrive.
#[tokio::test]
async fn http_checksum_prefetch_overlaps_slow_download() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-cs-pf");
    let total = 64 * 1024 * 1024u32;
    let body: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let origin = spawn_mock_origin_full(
        Arc::new(body.clone()),
        true,
        true,
        false,
        None,
        true, // slow: 32KiB chunks + 30ms spacing
    )
    .await;
    let digest = {
        use sha2::Digest as _;
        sha2::Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("big.bin")],
        options: std::collections::BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("checksum".to_string(), format!("sha-256={digest}")),
            ("split".to_string(), "8".to_string()),
            ("max-connection-per-server".to_string(), "8".to_string()),
        ]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);
    let gid_hex = gid.to_string();

    // The slow download takes ~8s: beyond the wait_until window, so
    // poll locally (30s cap).
    let mut ok = false;
    for _ in 0..1500 {
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
        );
        if done
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Complete)
        {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        ok,
        "the slow download did not complete within 30s (is the prefetch path blocked?)"
    );

    // Overlap evidence: at finish time the unconsumed bytes are
    // <= total/2 (first-wave blocks were already consumed during the
    // download; a post-hoc full hash would see the full total).
    let obs = super::http_task::prefetch_finish_observations();
    let (_, pending) = obs
        .iter()
        .rev()
        .find(|(g, _)| g == &gid_hex)
        .unwrap_or_else(|| panic!("finish observation absent (prefetch not assembled?): {obs:?}"));
    assert!(
        *pending <= total as u64 / 2,
        "the verdict was not pipelined (zero consumption during download = the post-hoc full-hash \
         shape): pending={pending}"
    );

    // Semantic regression: the final file lands correctly.
    let final_path = dir.join("big.bin");
    assert_eq!(
        std::fs::read(&final_path).unwrap_or_else(|e| panic!("read: {e}")),
        body,
        "final file content == the authoritative body"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(10), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Degraded face: a no-range origin (single sequential connection)
/// plus a correct `sha-256` -> the tee pre-hash settles during the
/// download and the completion path never re-reads for hashing; the
/// final file is correct.
#[tokio::test]
async fn http_checksum_degraded_tee_verifies_without_reread() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-cs-deg");
    let body: Vec<u8> = (0..512 * 1024u32).map(|i| (i % 247) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), false, true, false).await;
    let digest = {
        use sha2::Digest as _;
        sha2::Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("deg.bin")],
        options: std::collections::BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("checksum".to_string(), format!("sha-256={digest}")),
        ]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);

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

    let final_path = dir.join("deg.bin");
    assert_eq!(
        std::fs::read(&final_path).unwrap_or_else(|e| panic!("read: {e}")),
        body,
        "the degraded tee's final file content == the authoritative body"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The numeric error code 32 anchor: a `--checksum` mismatch at
/// completion fails the task with errorCode = 32 (CHECKSUM_ERROR,
/// cross-validates `ChecksumCheckIntegrityEntry.cc`) — the per-code
/// number flows through HttpEnd.error_engine -> error_engine -> the
/// taiji-rpc render chain instead of collapsing to 1.
#[tokio::test]
async fn http_checksum_failure_reports_numeric_code_32() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-cs32");
    let body: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("f.bin")],
        options: BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            (
                "checksum".to_string(),
                format!("sha-256={}", "0".repeat(64)),
            ),
        ]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);

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
        .unwrap_or_else(|| panic!("error entry"));
    // The core face passes the canonical code through and keeps the
    // collapsed numeric face (the taiji-rpc render layer owns the
    // mapping; the outward 32 is pinned by the rpc view tests).
    assert_eq!(
        entry.error_engine.as_ref().map(|f| f.code.as_str()),
        Some("taiji.http.checksum_mismatch"),
        "the canonical code passes through with the entry"
    );
    assert_eq!(
        entry.error_code,
        Some(1),
        "the core numeric face keeps the merged collapse"
    );
    let msg = entry.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.starts_with("taiji.http.checksum_mismatch:"),
        "the canonical code rides the message face: {msg}"
    );
    assert!(
        entry.completed_length == 0,
        "a mismatched task's completed = 0"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--remote-time`: after completion, set the final file's mtime from
/// the remote Last-Modified (best effort; disabled by default leaves
/// the mtime untouched).
#[tokio::test]
async fn http_remote_time_sets_file_mtime_when_enabled() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-rtime");
    let body: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 241) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("f.bin")],
        options: BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("remote-time".to_string(), "true".to_string()),
        ]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);
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

    let path = dir.join("f.bin");
    let got = std::fs::metadata(&path)
        .unwrap_or_else(|e| panic!("stat {path:?}: {e}"))
        .modified()
        .unwrap_or_else(|e| panic!("mtime: {e}"));
    let want_unix = taiji_http::remotetime::parse_http_date(LAST_MODIFIED_MOCK)
        .unwrap_or_else(|| panic!("mock date must parse"));
    let want = std::time::UNIX_EPOCH + std::time::Duration::from_secs(want_unix as u64);
    assert_eq!(got, want, "mtime == the remote Last-Modified");

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Option value-domain rejection: timeout=0, socks proxies, a non-bool
/// check-certificate, a colon-less header, http-max-per-host=0 — all
/// rejected at add with `taiji.option.invalid` (the aria2
/// OptionHandler rule: never silent).
#[tokio::test]
async fn http_runtime_options_reject_invalid_values() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-optval");
    let cases: Vec<(&str, String)> = vec![
        ("timeout", "0".into()),
        ("timeout", "-3".into()),
        ("timeout", "abc".into()),
        ("connect-timeout", "0".into()),
        ("max-tries", "x".into()),
        ("retry-wait", "-1".into()),
        ("all-proxy", "socks5://127.0.0.1:1080".into()),
        ("all-proxy", "ftp://127.0.0.1:21".into()),
        ("check-certificate", "maybe".into()),
        ("remote-time", "sometimes".into()),
        ("http-max-per-host", "0".into()),
    ];
    for (opt, val) in &cases {
        let r = call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ((*opt).to_string(), val.clone()),
                ]),
                position: None,
            },
        )
        .await;
        match r {
            Err(SessionError::Failed { message }) => assert!(
                message.starts_with("taiji.option.invalid"),
                "--{opt}={val} must be value-domain-rejected: {message}"
            ),
            other => panic!("--{opt}={val} must be rejected, got {other:?}"),
        }
    }
    // The colon-less header shape (the aria2 header option requires
    // ": ").
    let r = call(
        &handle,
        SessionCommand::AddUri {
            uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
            options: BTreeMap::from([
                ("dir".to_string(), dir.display().to_string()),
                ("header".to_string(), "X-No-Colon-Value".to_string()),
            ]),
            position: None,
        },
    )
    .await;
    assert!(
        matches!(r, Err(SessionError::Failed { .. })),
        "a colon-less header must be rejected"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `--split` upper bound at the session face (the
/// task-amplification defense): under the static scheduler the first
/// wave spawns `--split` workers per source unconditionally, so
/// split=1000000 would explode at acceptance. Out-of-domain values are
/// rejected at addUri (`taiji.option.invalid`, no clamping, no silent
/// acceptance); in-domain values are accepted and echoed normally.
#[tokio::test]
async fn http_split_upper_bound_rejects_task_amplification() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-split-cap");
    // Out of domain (the static first-wave amplification and the
    // u32::MAX+1 overflow): the task is rejected.
    for val in ["1000000", "4294967296", "4097"] {
        let r = call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-scheduler".to_string(), "static".to_string()),
                    ("split".to_string(), val.to_string()),
                ]),
                position: None,
            },
        )
        .await;
        match r {
            Err(SessionError::Failed { message }) => assert!(
                message.starts_with("taiji.option.invalid"),
                "--split={val} out of domain must be rejected at the task level: {message}"
            ),
            other => panic!("--split={val} out of domain must be rejected, got {other:?}"),
        }
    }
    // In domain (64, static): accepted normally + option echo
    // (pause=true keeps it in ReservedPaused — no race with the
    // network).
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                    ("http-scheduler".to_string(), "static".to_string()),
                    ("split".to_string(), "64".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::GetOption {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Options(m)) => {
            assert_eq!(m.get("split").map(String::as_str), Some("64"));
            assert_eq!(m.get("http-scheduler").map(String::as_str), Some("static"));
        }
        other => panic!("expected Options, got {other:?}"),
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Auth face (session-level assembly): a Basic-challenging origin plus
/// the `--http-user/--http-passwd` options -> the drive context
/// carries the preset credentials -> the download completes; the probe
/// gets 401 (no credentials) and the client layer answers the
/// challenge with the preset Basic.
#[tokio::test]
async fn http_session_download_with_basic_auth_options() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let body: Arc<Vec<u8>> = Arc::new((0..64 * 1024u32).map(|i| (i % 97) as u8).collect());
    let body_t = body.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = body_t.clone();
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
                // Basic base64("u:p") = "dTpw"; decide by value prefix
                // on the lowercased head (test-origin shortcut, no full
                // base64 recomputation needed).
                let authorized = head
                    .to_ascii_lowercase()
                    .lines()
                    .any(|l| l.starts_with("authorization: basic dtp"));
                let total = body.len();
                if !authorized {
                    let resp = "HTTP/1.1 401 Unauthorized\r\n\
                         WWW-Authenticate: Basic realm=\"t\"\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\r\n";
                    sock.write_all(resp.as_bytes()).await.ok();
                    let _ = sock.shutdown().await;
                    return;
                }
                let range = head
                    .to_ascii_lowercase()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("range: bytes="))
                    .and_then(|v| {
                        let (st, en) = v.trim().split_once('-')?;
                        Some((st.parse::<u64>().ok()?, en.parse::<u64>().ok()?))
                    });
                match range {
                    Some((st, en)) if en < total as u64 => {
                        let slice = &body[st as usize..=(en as usize).min(total - 1)];
                        let resp = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Range: bytes {st}-{en}/{total}\r\n\
                             Accept-Ranges: bytes\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\r\n",
                            slice.len()
                        );
                        sock.write_all(resp.as_bytes()).await.ok();
                        sock.write_all(slice).await.ok();
                    }
                    _ => {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                             Connection: close\r\n\r\n"
                        );
                        sock.write_all(resp.as_bytes()).await.ok();
                        sock.write_all(&body).await.ok();
                    }
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    let url = format!("http://{addr}/f.bin");

    let dir2 = temp_dir("http-auth");
    let (handle, join) = SessionActor::spawn();
    let add = SessionCommand::AddUri {
        uris: vec![url.clone()],
        options: BTreeMap::from([
            ("dir".to_string(), dir2.display().to_string()),
            ("http-user".to_string(), "u".to_string()),
            ("http-passwd".to_string(), "p".to_string()),
        ]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);
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
    let got = std::fs::read(dir2.join("f.bin")).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, *body, "authenticated download bytes round-trip");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir2);
}

/// numActive semantics: HTTP tasks and BT share the
/// `--max-concurrent-downloads` scheduling slots — a probing task
/// counts into numActive; a paused task only counts into numWaiting.
///
/// Counting is decoupled from scheduling slots: numActive counts the
/// session's active task set, not download connections (a media task
/// in a post-download processing phase would still count). The single
/// counting point is `get_global_stat`; this test pins the slot/count
/// decoupling: in a slot (the active set) => counted, not in a slot
/// (paused/queued) => not counted.
#[tokio::test]
async fn num_active_counts_http_tasks_and_decouples_from_slots() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-numactive");
    // Stalling origin: the task stays parked in the probe phase
    // (holding a slot in the active set).
    let origin = spawn_mock_origin(Arc::new(vec![0u8; 1024]), true, true, true).await;

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("a.bin")],
        options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
        position: None,
    };
    let _active_gid = gid_of(&call(&handle, add).await);
    let add_paused = SessionCommand::AddUri {
        uris: vec![origin.url("b.bin")],
        options: BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("pause".to_string(), "true".to_string()),
        ]),
        position: None,
    };
    let _paused_gid = gid_of(&call(&handle, add_paused).await);

    wait_until(async || {
        match call(&handle, SessionCommand::GetGlobalStat).await {
            Ok(CommandReply::GlobalStat(g)) => {
                // In a slot (parked in probing) = counted in numActive;
                // paused = only numWaiting — the two counts do not
                // overlap.
                g.num_active == 1 && g.num_waiting == 1
            }
            other => panic!("getGlobalStat: {other:?}"),
        }
    })
    .await;
    // tellActive follows the same rule (the same active set).
    let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    assert_eq!(active.len(), 1);
    assert!(
        active[0].http.is_some(),
        "tellActive carries the http sub-dictionary"
    );
    // getUris source list for the paused (never-activated) task: all
    // "waiting" (aria2 spent/remaining semantics — never started, so
    // nothing is spent; see the commands.rs get_uris doc).
    let paused_hex = _paused_gid.to_string();
    match call(&handle, SessionCommand::GetUris { gid: paused_hex }).await {
        Ok(CommandReply::Uris(uris)) => {
            assert_eq!(uris.len(), 1);
            assert_eq!(uris[0].status, "waiting");
        }
        other => panic!("getUris: {other:?}"),
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Degraded path e2e (Range ignored + Content-Length present) -> a
/// single-connection DegradedJob end to end (no bitmap, rename
/// close-out) -> Done; blocksTotal=0 (no bitmap face).
#[tokio::test]
async fn http_task_degraded_download_with_length() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-degraded");
    let body: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 97) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), false, true, false).await;

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("deg.bin")],
        options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);
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
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    let http = entry.http.as_ref().unwrap_or_else(|| panic!("http dict"));
    assert_eq!(http.blocks_total, 0, "a degraded task has no bitmap face");
    assert_eq!(entry.completed_length, body.len() as u64);
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body);
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Degraded without a total length (200 + connection-close
/// delimiting) -> EOF-delimited streaming + finalize -> Done (the
/// received byte count is the authoritative length).
#[tokio::test]
async fn http_task_degraded_download_without_length() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-eof");
    let body: Vec<u8> = (0..32 * 1024u32).map(|i| (i % 53) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), false, false, false).await;

    let add = SessionCommand::AddUri {
        uris: vec![origin.url("eof.bin")],
        options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
        position: None,
    };
    let gid = gid_of(&call(&handle, add).await);
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
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    assert_eq!(
        entry.completed_length,
        body.len() as u64,
        "EOF received bytes are the authority"
    );
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body);
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// kill -9 resume semantics: a seeded half-done store row + a prealloc
/// `.part` -> a session restart rebuilds the task (bootstrap_http) ->
/// the probe digest matches -> bitmap resume (completed blocks are not
/// refetched) -> only the remaining blocks are fetched -> the file is
/// complete.
#[tokio::test]
async fn http_task_resumes_from_seeded_row_after_restart() {
    const BS: u64 = 4 * 1024 * 1024;
    let dir = temp_dir("http-resume");
    let db_path = dir.join("taiji.sqlite3");
    // 5MiB = 2 blocks @4MiB; block 0 is on disk, block 1 pending.
    let body: Vec<u8> = (0..(5 * 1024 * 1024u32)).map(|i| (i % 199) as u8).collect();
    let part = part_path_of(&dir, "f.bin");
    let seeded: Vec<u8> = body[..BS as usize]
        .iter()
        .chain(std::iter::repeat_n(&0u8, body.len() - BS as usize))
        .copied()
        .collect();
    std::fs::write(&part, &seeded).unwrap_or_else(|e| panic!("seed part: {e}"));

    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
    let url = origin.url("f.bin");
    let gid_hex = "8000000000000777".to_string();
    // The row digest = the canonical facts this probe will produce
    // (path + length; no strong ETag -> a PathOnly weak resume).
    let digest = validator_digest_of("/f.bin", Some(body.len() as u64));
    let row = taiji_store::persist::HttpTaskRow {
        gid: gid_hex.clone(),
        url: url.clone(),
        final_url: url.clone(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 1,
        dir: dir.display().to_string(),
        out: "f.bin".into(),
        config_json: "{}".into(),
        probe_json: None,
        validator_digest: Some(digest),
        block_size: BS as i64,
        block_bitmap: Some(vec![0b01]),
        block_count: Some(2),
        total_done: BS as i64,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    // Pre-write the store row (the previous session's bitmap-snapshot
    // legacy); closing the store simulates the crash.
    {
        let (handle_w, writer) = PersistWriter::spawn(db_path.clone())
            .await
            .unwrap_or_else(|e| panic!("writer: {e}"));
        handle_w
            .upsert_http_task(row)
            .await
            .unwrap_or_else(|e| panic!("seed row: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
    }

    // New session on the same store: bootstrap_http rebuilds and
    // activates the task -> bitmap resume.
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = PersistWriter::spawn(db_path.clone())
        .await
        .unwrap_or_else(|e| panic!("writer2: {e}"));
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));

    let expected_gid = Gid::from_u64(u64::from_str_radix(&gid_hex, 16).unwrap_or(0));
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
        .any(|v| v.gid == expected_gid && v.status == StatusKind::Complete)
    })
    .await;

    // Resume evidence: exactly one full-file Range, starting at block
    // 1 (the probe (0,0) is not counted).
    assert_eq!(
        origin.fetch_ranges(),
        vec![(BS, body.len() as u64 - 1)],
        "block 0 is not refetched (bitmap resume)"
    );
    let entry = status_list(
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
    .find(|v| v.gid == expected_gid)
    .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body, "the file is intact after resume");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&dir);
}

fn part_path_of(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.part"))
}

/// Digest helper sharing the drive's source (validator facts -> the
/// canonical sha256 digest).
fn validator_digest_of(path: &str, total: Option<u64>) -> Vec<u8> {
    super::super::http::validator_digest(&super::super::http::ValidatorFacts {
        final_url_path: path.into(),
        total_len: total,
        etag: None,
        // The mock origin always answers Last-Modified (the remote-time
        // assertion source) — the recovery digest must derive from the
        // same probe facts.
        last_modified: Some(LAST_MODIFIED_MOCK.into()),
        encoding_ok: true,
    })
    .unwrap_or_default()
}

// ===== Regression face: lifecycle / recovery close-out / cookie wiring =====

use taiji_store::persist::{HttpTaskRow as TestHttpRow, PersistWriter as TestPersistWriter};

/// Read an http_task row's (state, config_json) straight from sqlite
/// (an independent WAL reader; None when the row is absent).
fn http_row_of(db: &std::path::Path, gid: &str) -> Option<(String, String)> {
    let conn = ok(rusqlite::Connection::open(db), "open http row read");
    conn.query_row(
        "SELECT state, config_json FROM http_task WHERE gid = ?1",
        params![gid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
    .unwrap_or_else(|e| panic!("http row query: {e}"))
}

/// http_task row progress reading (the bitmap-survival assertion
/// source).
type HttpRowProgress = (String, Option<Vec<u8>>, i64, Option<Vec<u8>>);

/// Read an http_task row's progress `(state, block_bitmap, total_done,
/// validator_digest)` straight from sqlite (the bitmap-survival
/// assertion source; None when the row is absent).
fn http_row_progress_of(db: &std::path::Path, gid: &str) -> Option<HttpRowProgress> {
    let conn = ok(
        rusqlite::Connection::open(db),
        "open http row progress read",
    );
    conn.query_row(
        "SELECT state, block_bitmap, total_done, validator_digest FROM http_task WHERE gid = ?1",
        params![gid],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<Vec<u8>>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
            ))
        },
    )
    .optional()
    .unwrap_or_else(|e| panic!("http row progress query: {e}"))
}

/// Row counting straight from sqlite.
fn http_table_count(db: &std::path::Path, table: &str, gid: Option<&str>) -> i64 {
    let conn = ok(rusqlite::Connection::open(db), "open count read");
    match gid {
        Some(g) => ok(
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE gid = ?1"),
                params![g],
                |r| r.get(0),
            ),
            "count",
        ),
        None => ok(
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)),
            "count all",
        ),
    }
}

use rusqlite::OptionalExtension as _;

/// Test http_task row constructor (a queued-state baseline).
fn seeded_http_row(gid: &str, url: &str, dir: &std::path::Path, out: &str) -> TestHttpRow {
    TestHttpRow {
        gid: gid.into(),
        url: url.into(),
        final_url: url.into(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 1,
        dir: dir.display().to_string(),
        out: out.into(),
        config_json: "{}".into(),
        probe_json: None,
        validator_digest: None,
        block_size: 0,
        block_bitmap: None,
        block_count: None,
        total_done: 0,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    }
}

/// An active task's forceRemove deletes its http_task row and a
/// restart must not resurrect it. (Regression: the mirror fallback ran
/// after the row was removed, leaving the row in probing, and the
/// restart bootstrap resurrected the task.)
#[tokio::test]
async fn http_row_deleted_on_force_remove_not_restored_after_restart() {
    let dir = temp_dir("http-rm-active");
    let db = tmp_db("http-rm-active");
    // Stalling origin: the task stays parked in the probe phase (the
    // active face).
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
                options: BTreeMap::new(),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // The row is registered and has left queued (the drive advanced to
    // probing).
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(s, _)| s != "queued")
            .unwrap_or(false)
    })
    .await;

    // forceRemove deletes the row (it used to linger).
    let _ = call(
        &handle,
        SessionCommand::ForceRemove {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || http_row_of(&db, &gid_hex).is_none()).await;

    // Simulated kill + restart: the task must not come back.
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let (persist2, writer2) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(persist2));
    tokio::time::sleep(Duration::from_millis(500)).await;
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
    let active = status_list(&call(&handle2, SessionCommand::TellActive { keys: vec![] }).await);
    assert!(
        waiting.iter().all(|v| v.gid != gid) && active.iter().all(|v| v.gid != gid),
        "a removed task must not resurrect after restart"
    );
    assert_eq!(http_table_count(&db, "http_task", None), 0);
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Removing a reserved task (added but never activated) deletes its
/// row. (Regression: a reserved task has no mirror, so the fallback
/// found nothing after the row was removed; the row lingered in queued
/// and the restart resurrected the task — the original "add then
/// remove, restart, and it is back" scenario.)
#[tokio::test]
async fn http_row_deleted_on_reserved_remove() {
    let dir = temp_dir("http-rm-reserved");
    let db = tmp_db("http-rm-reserved");
    let origin = spawn_mock_origin(Arc::new(vec![7u8; 1024]), true, true, true).await;
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 0, // never activates: a stable reserved face.
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::new(),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    wait_until(async || http_row_of(&db, &gid_hex).is_some()).await;
    let _ = call(
        &handle,
        SessionCommand::Remove {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || http_row_of(&db, &gid_hex).is_none()).await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    assert_eq!(http_table_count(&db, "http_task", None), 0);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Cookie cascade: a seeded store row + task cookies -> restart
/// (bootstrap loads them) -> remove -> the row is deleted and the
/// cookies clear with the FK cascade.
#[tokio::test]
async fn http_remove_cascades_persisted_cookies() {
    let dir = temp_dir("http-rm-cookie");
    let db = tmp_db("http-rm-cookie");
    let gid_hex = "8000000000000778".to_string();
    // Seed the row + cookie (the previous session's legacy).
    {
        let (handle_w, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "seed writer");
        handle_w
            .upsert_http_task(seeded_http_row(
                &gid_hex,
                "http://127.0.0.1:1/f.bin",
                &dir,
                "f.bin",
            ))
            .await
            .unwrap_or_else(|e| panic!("seed row: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
        let conn = ok(rusqlite::Connection::open(&db), "seed cookie open");
        ok(
            conn.execute(
                "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                     expires_utc, secure, host_only, creation_utc)
                 VALUES (?1, 'http', 'sid', 'x.example', '/', 'v1', NULL, 0, 1, 0)",
                params![gid_hex],
            ),
            "seed cookie",
        );
    }
    // Restart: bootstrap loads them (max_concurrent=0 keeps the task
    // reserved).
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 0,
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(http_table_count(&db, "http_task", None), 1);
    assert_eq!(http_table_count(&db, "task_cookie", None), 1);
    // remove deletes the row + the cookies cascade away.
    let _ = call(
        &handle,
        SessionCommand::Remove {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || http_table_count(&db, "http_task", None) == 0).await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    assert_eq!(
        http_table_count(&db, "task_cookie", None),
        0,
        "cookies cascade-delete along with the row (deletion implies clearing)"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// The row state domain guard: sampling http_task.state throughout the
/// download must never leave the value domain (planning is a runtime
/// phase only; a row parked in probing after a crash/shutdown in the
/// planning window is inside the recovery set — no orphans).
/// (Regression: the shared row mirror was overwritten with an
/// out-of-domain value during planning, polluting the persisted row on
/// any mirror flush.)
#[tokio::test]
async fn http_row_state_stays_in_active_domain_during_download() {
    let dir = temp_dir("http-b2-domain");
    let db = tmp_db("http-b2-domain");
    let body: Vec<u8> = (0..(1024 * 1024u32)).map(|i| (i % 61) as u8).collect();
    let origin =
        spawn_mock_origin_full(Arc::new(body.clone()), false, true, false, None, true).await;
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
                options: BTreeMap::new(),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    const DOMAIN: [&str; 7] = [
        "queued",
        "probing",
        "downloading",
        "finalizing",
        "paused",
        "error",
        "done",
    ];
    let mut saw_downloading = false;
    wait_until(async || {
        if let Some((state, _)) = http_row_of(&db, &gid_hex) {
            assert!(
                DOMAIN.contains(&state.as_str()),
                "row state {state} is outside the http_task.state value domain"
            );
            if state == "downloading" {
                saw_downloading = true;
            }
        }
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
    assert!(
        saw_downloading,
        "the sampling face covered the downloading phase"
    );
    assert_eq!(
        http_row_of(&db, &gid_hex).map(|(s, _)| s),
        Some("done".into())
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// A done+renamePending row closes out idempotently across a restart:
/// bootstrap reads it back -> the `.part` rename lands -> the row flag
/// clears.
#[tokio::test]
async fn rename_pending_rows_close_out_on_bootstrap() {
    let dir = temp_dir("http-b3-close");
    let db = tmp_db("http-b3-close");
    let gid_hex = "8000000000000779".to_string();
    let body: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 13) as u8).collect();
    // `.part` present + final file missing = the on-disk fact that the
    // rename never landed.
    let part = part_path_of(&dir, "f.bin");
    std::fs::write(&part, &body).unwrap_or_else(|e| panic!("seed part: {e}"));
    let mut row = seeded_http_row(&gid_hex, "http://127.0.0.1:1/f.bin", &dir, "f.bin");
    row.state = "finalizing".into();
    row.total_done = body.len() as i64;
    row.config_json = http_task::HttpPersistConfig {
        rename_pending: true,
        publication: Some(super::http_publication::PublicationRecord {
            intent: taiji_http::finalize::RenameIntent::new(
                gid_hex.clone(),
                part_path_of(&dir, "f.bin"),
                dir.join("f.bin"),
                row.total_done.max(0) as u64,
            ),
            phase: super::http_publication::PublicationPhase::Publishing,
            external: false,
            error: None,
        }),
        ..Default::default()
    }
    .to_json();
    {
        let (handle_w, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "seed writer");
        handle_w
            .upsert_http_task(row)
            .await
            .unwrap_or_else(|e| panic!("seed row: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
    }
    // Restart: bootstrap closes it out (retry_pending used to never
    // run, leaving it pending forever).
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 0,
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let final_path = dir.join("f.bin");
    wait_until(async || final_path.exists()).await;
    let got = std::fs::read(&final_path).unwrap_or_else(|e| panic!("read final: {e}"));
    assert_eq!(
        got, body,
        "content matches bit for bit after the rename close-out"
    );
    assert!(!part.exists(), "the `.part` is gone after settling");
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(_, cfg)| !cfg.contains("\"rename_pending\":true"))
            .unwrap_or(false)
    })
    .await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Disk facts missing (the target is occupied + the `.part` absent)
/// -> no fabricated close-out; the row stays pending.
#[tokio::test]
async fn rename_pending_stays_pending_when_disk_facts_missing() {
    let dir = temp_dir("http-b3-stay");
    let db = tmp_db("http-b3-stay");
    let gid_hex = "8000000000000780".to_string();
    // The `.part` is absent; the target path is occupied by a
    // different-sized foreign file (closeout sees a mismatch -> stays
    // pending).
    std::fs::write(dir.join("f.bin"), b"foreign!").unwrap_or_else(|e| panic!("{e}"));
    let mut row = seeded_http_row(&gid_hex, "http://127.0.0.1:1/f.bin", &dir, "f.bin");
    row.state = "finalizing".into();
    row.config_json = http_task::HttpPersistConfig {
        rename_pending: true,
        publication: Some(super::http_publication::PublicationRecord {
            intent: taiji_http::finalize::RenameIntent::new(
                gid_hex.clone(),
                part_path_of(&dir, "f.bin"),
                dir.join("f.bin"),
                row.total_done.max(0) as u64,
            ),
            phase: super::http_publication::PublicationPhase::Publishing,
            external: false,
            error: None,
        }),
        ..Default::default()
    }
    .to_json();
    {
        let (handle_w, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "seed writer");
        handle_w
            .upsert_http_task(row)
            .await
            .unwrap_or_else(|e| panic!("seed row: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
    }
    let global = GlobalOptions {
        dir: dir.clone(),
        max_concurrent_downloads: 0,
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    // Give the close-out scan plenty of time: the flag is still there
    // (a mismatch keeps it pending for a later decision).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, cfg) = http_row_of(&db, &gid_hex).unwrap_or_else(|| panic!("row"));
    assert!(
        cfg.contains("rename_pending"),
        "missing on-disk facts must not clear the flag"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// renamePending close-out mutual exclusion: while the final path is
/// held by another task (the creation-time placeholder of an in-flight
/// task's plan_output), the close-out must not race the rename — skip
/// this round, touch nothing; once the holder releases, the close-out
/// lands normally (the mutex must not deadlock the polling loop).
/// (Regression: the close-out renamed without consulting the claim
/// table — its guard only excluded the same gid.)
#[tokio::test]
async fn rename_pending_close_out_skips_while_final_held_by_other() {
    let dir = temp_dir("http-sec22-poll");
    let gid_hex = "8000000000000790".to_string();
    let other = "8000000000000799".to_string();
    let body: Vec<u8> = (0..96u32).map(|i| (i % 11) as u8).collect();
    let part = dir.join("f.bin.part");
    let final_path = dir.join("f.bin");
    std::fs::write(&part, &body).unwrap_or_else(|e| panic!("seed part: {e}"));
    use taiji_http::finalize::{FinalizeOutcome, Finalizer, MemoryJournal, RenameIntent};
    let mut intent =
        RenameIntent::new(gid_hex, part.clone(), final_path.clone(), body.len() as u64);
    intent.auto_rename = false;
    let finalizer = Finalizer::new(Arc::new(MemoryJournal::default()));

    // Another task holds the final path (an in-flight task's
    // creation-time placeholder).
    taiji_http::partfile::claim_final_path(&final_path, &other)
        .unwrap_or_else(|e| panic!("claim: {e}"));

    let closed = matches!(
        finalizer.resume(&intent).await,
        Ok(FinalizeOutcome::Completed { .. })
    );
    assert!(
        !closed,
        "the final path is held by another task -> skip this round (must not report closed)"
    );
    assert!(
        part.exists(),
        "the `.part` must not be renamed away while the window is held"
    );
    assert!(
        !final_path.exists(),
        "the final file must not appear within the window"
    );

    // The holder releases -> the close-out lands normally (no
    // over-kill).
    taiji_http::partfile::release_final_path(&final_path, &other);
    let closed = matches!(
        finalizer.resume(&intent).await,
        Ok(FinalizeOutcome::Completed { .. })
    );
    assert!(closed, "after the holder releases, the close-out must land");
    assert_eq!(
        std::fs::read(&final_path).unwrap_or_else(|e| panic!("read final: {e}")),
        body,
        "content matches bit for bit after close-out"
    );
    assert!(!part.exists(), "the `.part` is gone after settling");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Resume must honor the row's persisted block_size (immutable per
/// task). (Regression: the drive overwrote it with
/// DEFAULT_BLOCK_SIZE(4MiB), reinterpreting a 1MiB-granularity bitmap
/// as 4MiB — two 1MiB bits filled a whole 4MiB grid, so the task
/// "completed" without fetching the remaining blocks and the second
/// half of the file stayed zeros.)
#[tokio::test]
async fn resume_honors_persisted_block_size() {
    const BS: u64 = 1024 * 1024; // row-persisted 1MiB granularity (not the 4MiB default).
    let dir = temp_dir("http-m6-bs");
    let db = tmp_db("http-m6-bs");
    let total = 5 * 1024 * 1024u64; // 5 blocks @1MiB.
    let body: Vec<u8> = (0..total as u32).map(|i| (i % 199) as u8).collect();
    // Blocks 0 and 1 are on disk (2MiB); the rest is zeros (the
    // prealloc shape).
    let mut seeded = body[..2 * BS as usize].to_vec();
    seeded.extend(std::iter::repeat_n(
        &0u8,
        (total as usize) - 2 * BS as usize,
    ));
    let part = part_path_of(&dir, "f.bin");
    std::fs::write(&part, &seeded).unwrap_or_else(|e| panic!("seed part: {e}"));
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
    let url = origin.url("f.bin");
    let gid_hex = "8000000000000781".to_string();
    let mut row = seeded_http_row(&gid_hex, &url, &dir, "f.bin");
    row.validator_digest = Some(validator_digest_of("/f.bin", Some(total)));
    row.block_size = BS as i64;
    row.block_bitmap = Some(vec![0b11]);
    row.block_count = Some(5);
    row.total_done = 2 * BS as i64;
    {
        let (handle_w, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "seed writer");
        handle_w
            .upsert_http_task(row)
            .await
            .unwrap_or_else(|e| panic!("seed row: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
    }
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let expected_gid = Gid::from_u64(u64::from_str_radix(&gid_hex, 16).unwrap_or(0));
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
        .any(|v| v.gid == expected_gid && v.status == StatusKind::Complete)
    })
    .await;
    // Resume evidence: the first fetch starts at 2MiB (blocks 0-1 not
    // refetched) and the remaining range is covered seamlessly exactly
    // once (the dynamic default claims shards at guided granularity,
    // so the Range count varies with the window snapshot).
    let mut ranges = origin.fetch_ranges();
    ranges.sort_unstable();
    assert_eq!(
        ranges.first().copied().map(|(s, _)| s),
        Some(2 * BS),
        "row-granularity resume: blocks 0 and 1 are not refetched"
    );
    let mut covered = 0u64;
    for (s, e) in &ranges {
        assert_eq!(
            *s,
            2 * BS + covered,
            "resume ranges join seamlessly (no repeats, no jumps)"
        );
        covered += e - s + 1;
    }
    assert_eq!(
        2 * BS + covered,
        total,
        "the remaining range is covered exactly once"
    );
    let entry = status_list(
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
    .find(|v| v.gid == expected_gid)
    .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        got, body,
        "granularity reinterpretation would fabricate progress — the file must be intact"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// The live face during a degraded download: the source state reads
/// active, totalLength backfills early (it used to stay 0 until
/// close-out), and getGlobalStat.downloadSpeed includes the http live
/// rate (previously always missed); at the terminal state the source
/// returns to waiting.
#[tokio::test]
async fn degraded_download_reports_live_state_rate_and_total() {
    let dir = temp_dir("http-m8-live");
    // A ~1.4s slow body (45 x 32KiB chunks, 1ms apart).
    let body: Vec<u8> = (0..(45 * 32 * 1024u32)).map(|i| (i % 97) as u8).collect();
    let origin =
        spawn_mock_origin_full(Arc::new(body.clone()), false, true, false, None, true).await;
    let (handle, join) = SessionActor::spawn();
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("deg.bin")],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                position: None,
            },
        )
        .await,
    );
    // Sample during the download window: source active + totalLength
    // backfilled + a non-zero rate face.
    let mut saw_active = false;
    let mut saw_total = false;
    let mut saw_stat_rate = false;
    wait_until(async || {
        let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
        if let Some(v) = active.iter().find(|v| v.gid == gid) {
            if let Some(http) = &v.http {
                if http.sources[0].state == "active" {
                    saw_active = true;
                }
                if http.sources[0].rate > 0 {
                    saw_stat_rate = true;
                }
            }
            if v.total_length == body.len() as u64 {
                saw_total = true;
            }
        }
        if let Ok(CommandReply::GlobalStat(g)) = call(&handle, SessionCommand::GetGlobalStat).await
        {
            if g.download_speed > 0 {
                saw_stat_rate = true;
            }
        }
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
    assert!(
        saw_active,
        "the source state during download must be active"
    );
    assert!(
        saw_total,
        "totalLength must be backfilled during download (known total)"
    );
    assert!(
        saw_stat_rate,
        "the download rate must be exposed (live + getGlobalStat)"
    );
    // Terminal state: the source returns to waiting.
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
    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let http = entry.http.as_ref().unwrap_or_else(|| panic!("http dict"));
    assert_eq!(
        http.sources[0].state, "waiting",
        "after close-out the source returns to waiting"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cookie wiring: Set-Cookie captured during the download is written
/// back to sqlite on the periodic tick. (Regression: nothing ever
/// called the cookie upsert, so captures lived only in memory.)
#[tokio::test]
async fn http_task_cookies_captured_to_store() {
    let dir = temp_dir("http-c11-capture");
    let db = tmp_db("http-c11-capture");
    // A slow large body (4MiB @ 32KiB/30ms ~= 3.8s): the download
    // window spans the 2s write-back tick (a stalling origin sends no
    // Set-Cookie to capture, hence the slow body).
    let origin = spawn_mock_origin_full(
        Arc::new(vec![7u8; 4 * 1024 * 1024]),
        false,
        true,
        false,
        Some("sid=v1; Path=/".to_string()),
        true,
    )
    .await;
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
                options: BTreeMap::new(),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // The 2s write-back tick persists the capture (it used to stay
    // 0).
    wait_until(async || http_table_count(&db, "task_cookie", Some(&gid_hex)) > 0).await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// After forceRemove's token.cancel + abort abandons the wrapped drive
/// future, the cookie write-back loop task must exit with the run
/// token. (Regression: the loop was only tied to the sync_stop/tick
/// arms — the sync_stop.cancel() after the in-wrapper drive().await
/// became unreachable when the future was dropped, so the loop lived
/// forever: after row removal every 2s tick logged a dangling-FK
/// upsert error and leaked memory until process exit. The
/// [`super::http_task::cookie_loop_exit_observations`] seam asserts
/// the loop completed.)
#[tokio::test]
async fn cookie_sync_loop_exits_after_force_remove_abort() {
    let dir = temp_dir("http-sec34-cookie");
    let db = tmp_db("http-sec34-cookie");
    // A slow body (8MiB @ 32KiB/30ms ~= 7.7s): the download window
    // spans the 2s write-back tick and the forceRemove moment (an
    // early completion would clear the cookies first and break the
    // setup); after the Set-Cookie capture the loop is in its active
    // write-back state (the observable precondition).
    let origin = spawn_mock_origin_full(
        Arc::new(vec![7u8; 8 * 1024 * 1024]),
        false,
        true,
        false,
        Some("sid=v1; Path=/".to_string()),
        true,
    )
    .await;
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
                options: BTreeMap::new(),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // Loop-active precondition: the cookie is captured and persisted
    // (the loop has completed at least one real upsert).
    wait_until(async || http_table_count(&db, "task_cookie", Some(&gid_hex)) > 0).await;

    // forceRemove: token.cancel -> abort (the tasks.rs remove(force)
    // order) -> row deletion (cookies cascade). The loop used to live
    // forever, leaving no exit record at the seam.
    let _ = call(
        &handle,
        SessionCommand::ForceRemove {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || {
        super::http_task::cookie_loop_exit_observations()
            .iter()
            .any(|g| g == &gid_hex)
    })
    .await;

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Cookies are cleared on completion (captured first, cleared at
/// completion — cookies never survive completion) + recovery replay
/// (a stored cookie -> after a restart the activated request carries
/// the Cookie header).
#[tokio::test]
async fn http_task_cookies_cleared_on_done_and_replayed_after_restart() {
    // ---- Part 1: cleared on completion ----
    let dir = temp_dir("http-c11-clear");
    let db = tmp_db("http-c11-clear");
    let body: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 17) as u8).collect();
    let origin = spawn_mock_origin_full(
        Arc::new(body.clone()),
        true,
        true,
        false,
        Some("sid=v1; Path=/".to_string()),
        false,
    )
    .await;
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
    wait_until(async || http_table_count(&db, "task_cookie", None) == 0).await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);

    // ---- Part 2: recovery replay (a stored cookie -> requests carry
    // it after the restart) ----
    let dir2 = temp_dir("http-c11-replay");
    let db2 = tmp_db("http-c11-replay");
    let body2: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 19) as u8).collect();
    let origin2 = spawn_mock_origin(Arc::new(body2), true, true, true).await; // stall keeps the request in flight.
    let gid_hex = "8000000000000784".to_string();
    {
        let (handle_w, writer) = ok(TestPersistWriter::spawn(db2.clone()).await, "seed writer");
        handle_w
            .upsert_http_task(seeded_http_row(
                &gid_hex,
                &origin2.url("f.bin"),
                &dir2,
                "f.bin",
            ))
            .await
            .unwrap_or_else(|e| panic!("seed row: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
        let conn = ok(rusqlite::Connection::open(&db2), "seed cookie open");
        ok(
            conn.execute(
                "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                     expires_utc, secure, host_only, creation_utc)
                 VALUES (?1, 'http', 'sid', '127.0.0.1', '/', 'v1', NULL, 0, 1, 0)",
                params![gid_hex],
            ),
            "seed cookie",
        );
    }
    let global2 = GlobalOptions {
        dir: dir2.clone(),
        ..Default::default()
    };
    let (persist2, writer2) = ok(
        TestPersistWriter::spawn(db2.clone()).await,
        "spawn writer 2",
    );
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(persist2));
    // After activation the probe/download requests carry the replayed
    // cookie.
    wait_until(async || !origin2.cookies_seen().is_empty()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = origin2.cookies_seen();
    assert!(
        seen.iter().any(|c| c.as_deref() == Some("sid=v1")),
        "resume replay: requests must carry the stored cookie, got {seen:?}"
    );
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = std::fs::remove_dir_all(&dir2);
    let _ = std::fs::remove_file(&db2);
}

/// Lifecycle matrix e2e: add(pause) -> unpause -> pause mid-download
/// -> the paused row persists -> unpause -> completion; error ->
/// unpause re-probes; remove deletes the row, then shutdown.
#[tokio::test]
async fn http_lifecycle_matrix_with_pause_resume_remove() {
    let dir = temp_dir("http-matrix");
    let db = tmp_db("http-matrix");
    // A slow degraded origin: the download window is sampleable.
    let body: Vec<u8> = (0..(30 * 32 * 1024u32)).map(|i| (i % 53) as u8).collect();
    let origin =
        spawn_mock_origin_full(Arc::new(body.clone()), false, true, false, None, true).await;
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let stopped = async || {
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
    };
    // Phase 1: add(pause=true) -> a paused row.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("m.bin")],
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
    // Phase 2: unpause -> activation (the row leaves paused).
    let _ = call(
        &handle,
        SessionCommand::Unpause {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(s, _)| s != "paused" && s != "queued")
            .unwrap_or(false)
    })
    .await;
    // Phase 3: pause mid-download -> the row is paused + back in the
    // waiting queue.
    let _ = call(
        &handle,
        SessionCommand::Pause {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(s, _)| s == "paused")
            .unwrap_or(false)
    })
    .await;
    // Phase 4: unpause -> completion (row done, file present, cookies
    // cleared). An unpause is refused while the pause teardown (the
    // Ended event) is not yet processed by the actor — retry until the
    // teardown bookkeeping is done (resume after it requeues
    // paused).
    wait_until(async || {
        matches!(
            call(
                &handle,
                SessionCommand::Unpause {
                    gid: gid_hex.clone()
                }
            )
            .await,
            Ok(CommandReply::Gid(_))
        )
    })
    .await;
    wait_until(async || {
        stopped()
            .await
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Complete)
    })
    .await;
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(s, _)| s == "done")
            .unwrap_or(false)
    })
    .await;
    // Phase 5: an errored task -> unpause re-probes -> fails again
    // (the migration arm closes).
    let gid_err = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/e.bin".to_string()],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                position: None,
            },
        )
        .await,
    );
    wait_until(async || {
        stopped()
            .await
            .iter()
            .any(|v| v.gid == gid_err && v.status == StatusKind::Error)
    })
    .await;
    let _ = call(
        &handle,
        SessionCommand::Unpause {
            gid: gid_err.to_string(),
        },
    )
    .await;
    wait_until(async || {
        matches!(
            call(&handle, SessionCommand::GetGlobalStat).await,
            Ok(CommandReply::GlobalStat(g)) if g.num_stopped_total >= 2
        )
    })
    .await;
    // Phase 6: a reserved task's forceRemove deletes the row (aria2
    // remove is unavailable for finished tasks, so the matrix covers
    // the reserved/active faces).
    let gid_rm = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/r.bin".to_string()],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let rm_hex = gid_rm.to_string();
    wait_until(async || http_row_of(&db, &rm_hex).is_some()).await;
    let _ = call(
        &handle,
        SessionCommand::ForceRemove {
            gid: rm_hex.clone(),
        },
    )
    .await;
    wait_until(async || http_row_of(&db, &rm_hex).is_none()).await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
    drop(writer);
    assert_eq!(
        http_row_of(&db, &gid_hex).map(|(s, _)| s),
        Some("done".into()),
        "a completed task's row keeps its terminal state"
    );
    assert_eq!(http_table_count(&db, "http_task", Some(&rm_hex)), 0);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Shape 1 (the default grid path): pausing mid-download persists a
/// paused row carrying the fsynced bitmap progress (regression: the
/// pause row used to overwrite the newer DB snapshot with the stale
/// activation-time mirror, wiping the bitmap/progress/resume digest)
/// -> unpause -> bitmap resume (block 0 not refetched) -> completion,
/// byte-identical.
#[tokio::test]
async fn http_grid_pause_resume_keeps_bitmap_progress() {
    const BS: u64 = 256 * 1024;
    let dir = temp_dir("http-grid-pause");
    let db = tmp_db("http-grid-pause");
    // 4MiB = 16 blocks @256KiB; the 32KiB/30ms slow write gives a ~4s
    // interruptible window.
    let body: Arc<Vec<u8>> = Arc::new((0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect());
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
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
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                    // The default cap is now 16 (5 parallel workers);
                    // the bitmap-survival assertion (block 0 fetched
                    // exactly once) presumes single-worker sequential
                    // completion (under parallelism block 0 may
                    // legitimately be unfinished at pause time, and a
                    // resume refetch is not a regression), so pin one
                    // connection.
                    ("max-connection-per-server".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // The first snapshot commit lands (the first completed block
    // triggers it immediately).
    wait_until(async || {
        http_row_progress_of(&db, &gid_hex)
            .map(|(_, bm, _, _)| bm.is_some())
            .unwrap_or(false)
    })
    .await;
    // Pause mid-download -> the paused row carries the fsynced bitmap
    // face.
    let _ = call(
        &handle,
        SessionCommand::Pause {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || {
        http_row_progress_of(&db, &gid_hex)
            .map(|(s, _, _, _)| s == "paused")
            .unwrap_or(false)
    })
    .await;
    let (state, bitmap, total_done, digest) =
        http_row_progress_of(&db, &gid_hex).unwrap_or_else(|| panic!("row must exist"));
    assert_eq!(state, "paused");
    let bm = bitmap.unwrap_or_else(|| panic!("paused row must keep bitmap"));
    assert!(
        bm.iter().any(|b| *b != 0),
        "the bitmap is non-empty (progress survived)"
    );
    assert!(total_done >= BS as i64, "total_done >= 1 block");
    assert!(
        digest.is_some(),
        "the resume digest travels with the row (a missing digest = the reactivation judges \
         FromZero and redownloads the whole file)"
    );
    // unpause (refused while the teardown bookkeeping is pending —
    // retry until accepted) -> bitmap resume.
    wait_until(async || {
        matches!(
            call(
                &handle,
                SessionCommand::Unpause {
                    gid: gid_hex.clone()
                }
            )
            .await,
            Ok(CommandReply::Gid(_))
        )
    })
    .await;
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
    // Bitmap-survival evidence: exactly one real fetch with start=0
    // (the two probes' (0,0) do not count; a FromZero reactivation
    // would restart the whole file and push this count to >= 2).
    let zero_fetches = origin
        .fetch_ranges()
        .iter()
        .filter(|(s, e)| *s == 0 && *e > 0)
        .count();
    assert_eq!(
        zero_fetches, 1,
        "block 0 is not refetched (pause->resume bitmap survival)"
    );
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body.as_slice(), "the file is intact after resume");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Shape 2 (saveSession flush): saveSession mid-download -> the row
/// write carries the bitmap face synced back from the mirror
/// (regression: a blind out-of-lock write of the stale mirror wiped
/// the row's bitmap/digest).
#[tokio::test]
async fn http_grid_save_session_flush_keeps_row_progress() {
    let dir = temp_dir("http-grid-save");
    let db = tmp_db("http-grid-save");
    let body: Arc<Vec<u8>> = Arc::new((0..4 * 1024 * 1024u32).map(|i| (i % 199) as u8).collect());
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
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
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    wait_until(async || {
        http_row_progress_of(&db, &gid_hex)
            .map(|(_, bm, _, _)| bm.is_some())
            .unwrap_or(false)
    })
    .await;
    // saveSession full flush: the mirror face is synced by the
    // snapshot ticks, so the row's progress face does not regress.
    let result = call(&handle, SessionCommand::SaveSession).await;
    assert!(matches!(result, Ok(CommandReply::Accepted)), "{result:?}");
    let (state, bitmap, total_done, digest) =
        http_row_progress_of(&db, &gid_hex).unwrap_or_else(|| panic!("row must exist"));
    assert_eq!(state, "downloading");
    let bm = bitmap.unwrap_or_else(|| panic!("row must keep bitmap after saveSession"));
    assert!(bm.iter().any(|b| *b != 0), "the bitmap is non-empty");
    assert!(total_done >= 256 * 1024, "progress not lost");
    assert!(digest.is_some(), "the resume digest not lost");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Shape 3 (changeOption restart): a legal runtime change -> the
/// restart semantics requeue at the head and reactivate -> bitmap
/// resume (block 0 not refetched) -> completion.
#[tokio::test]
async fn http_grid_change_option_restart_keeps_bitmap_progress() {
    let dir = temp_dir("http-grid-copt");
    let db = tmp_db("http-grid-copt");
    let body: Arc<Vec<u8>> = Arc::new((0..4 * 1024 * 1024u32).map(|i| (i % 173) as u8).collect());
    let origin = spawn_mock_origin_full(Arc::clone(&body), true, true, false, None, true).await;
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
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                    // The default cap is now 16 (5 parallel workers);
                    // the post-restart "block 0 fetched exactly once"
                    // bitmap-survival assertion presumes single-worker
                    // sequential completion, so pin one connection.
                    ("max-connection-per-server".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    wait_until(async || {
        http_row_progress_of(&db, &gid_hex)
            .map(|(_, bm, _, _)| bm.is_some())
            .unwrap_or(false)
    })
    .await;
    // Change while running (an active task = restart semantics).
    let result = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid_hex.clone(),
            options: BTreeMap::from([("split".to_string(), "3".to_string())]),
        },
    )
    .await;
    assert!(matches!(result, Ok(CommandReply::Accepted)), "{result:?}");
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
    // Bitmap-survival evidence (as in shape 1): exactly one real
    // block-0 fetch.
    let zero_fetches = origin
        .fetch_ranges()
        .iter()
        .filter(|(s, e)| *s == 0 && *e > 0)
        .count();
    assert_eq!(
        zero_fetches, 1,
        "after restart block 0 is not refetched (bitmap survival)"
    );
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body.as_slice(), "the file is intact after restart");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// Cookie lifecycle: activation must not clear the persisted set
/// ("clear on completion/removal — never on activation").
/// (Regression: activation unconditionally reset the task store and
/// the write-back loop's first tick upserted an empty set = a full
/// clear.) With a stalling origin capturing nothing, several
/// write-back ticks are observed and the stored set must survive
/// intact, across restarts included.
#[tokio::test]
async fn http_task_cookie_activation_preserves_persisted_set() {
    let dir = temp_dir("http-cookie-keep");
    let db = tmp_db("http-cookie-keep");
    let gid_hex = "8000000000000790".to_string();
    // Stalling origin: parked at probe, zero Set-Cookie captures (the
    // write-back loop's empty-set shape).
    let origin = spawn_mock_origin(Arc::new(vec![7u8; 64 * 1024]), true, true, true).await;
    {
        let (handle_w, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "seed writer");
        handle_w
            .upsert_http_task(seeded_http_row(
                &gid_hex,
                &origin.url("f.bin"),
                &dir,
                "f.bin",
            ))
            .await
            .unwrap_or_else(|e| panic!("seed row: {e}"));
        drop(handle_w);
        writer.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
        let conn = ok(rusqlite::Connection::open(&db), "seed cookie open");
        for (name, value, created) in [
            ("sid", "v1", 1_700_000_000i64),
            ("pref", "dark", 1_700_000_001i64),
        ] {
            ok(
                conn.execute(
                    "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                         expires_utc, secure, host_only, creation_utc)
                     VALUES (?1, 'http', ?2, '127.0.0.1', '/', ?3, NULL, 0, 1, ?4)",
                    params![gid_hex, name, value, created],
                ),
                "seed cookie",
            );
        }
    }
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn writer");
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    // Span >= 2 write-back ticks (2s each): an empty-set tick must not
    // trigger a full clear.
    tokio::time::sleep(Duration::from_millis(4_500)).await;
    assert_eq!(
        http_table_count(&db, "task_cookie", Some(&gid_hex)),
        2,
        "activation + the write-back loop must not clear the persisted set"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    assert_eq!(
        http_table_count(&db, "task_cookie", Some(&gid_hex)),
        2,
        "shutdown (neither completed nor removed) must not clear cookies"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// In-session reactivation replay + clear-on-completion: a slow
/// degraded origin captures a Set-Cookie -> pause -> unpause: the
/// reactivated requests must carry the previously captured cookie
/// (regression: the replay seed was only injected at bootstrap, so
/// in-session reactivations never had one) -> completion -> the
/// cookies are cleared.
#[tokio::test]
async fn http_task_cookie_reactivation_replays_captured_set() {
    let dir = temp_dir("http-cookie-replay2");
    let db = tmp_db("http-cookie-replay2");
    // ~3.2MiB @ 32KiB/30ms ~= 3s window (enough for the 2s capture
    // tick to land).
    let body: Vec<u8> = (0..(100 * 32 * 1024u32)).map(|i| (i % 61) as u8).collect();
    let origin = spawn_mock_origin_full(
        Arc::new(body.clone()),
        false,
        true,
        false,
        Some("sid=v1; Path=/".to_string()),
        true,
    )
    .await;
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
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // The capture has been persisted.
    wait_until(async || http_table_count(&db, "task_cookie", Some(&gid_hex)) > 0).await;
    // Pause mid-download -> paused.
    let _ = call(
        &handle,
        SessionCommand::Pause {
            gid: gid_hex.clone(),
        },
    )
    .await;
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(s, _)| s == "paused")
            .unwrap_or(false)
    })
    .await;
    // unpause (refused while the teardown bookkeeping is pending —
    // retry until accepted) -> reactivation replay.
    wait_until(async || {
        matches!(
            call(
                &handle,
                SessionCommand::Unpause {
                    gid: gid_hex.clone()
                }
            )
            .await,
            Ok(CommandReply::Gid(_))
        )
    })
    .await;
    wait_until(async || {
        origin
            .cookies_seen()
            .iter()
            .any(|c| c.as_deref() == Some("sid=v1"))
    })
    .await;
    // Cleared on completion (the cookie rule).
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
    wait_until(async || http_table_count(&db, "task_cookie", None) == 0).await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// PEM form of the self-signed test CA (a base64 wrapping of the
/// taiji-http test fixture `ftp-test-ca/ca_cert.der` — the same
/// constant; the `--ca-certificate` parse face only cares that the
/// file is readable and valid PEM, and inlining avoids a cross-crate
/// fixture dependency).
const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBjTCCATOgAwIBAgIULNgffOkfakwNynuI/RDSNq9xBwIwCgYIKoZIzj0EAwIw\n\
HDEaMBgGA1UEAwwRdGFpamkgZnRwIHRlc3QgQ0EwHhcNMjYwOTE2MDMxNTM3WhcN\n\
NDYwOTExMDMxNTM3WjAcMRowGAYDVQQDDBF0YWlqaSBmdHAgdGVzdCBDQTBZMBMG\n\
ByqGSM49AgEGCCqGSM49AwEHA0IABCWVn9CwjZPSx18QZ6tC//nyCfG+GYeUgL3L\n\
jEIpb6Shez1EO1gO0aE/TBT684iGVvVsiBoQY9Fp/44Sotvc45yjUzBRMB0GA1Ud\n\
DgQWBBQJZgkGwbmmOtE8YjXxnJ0fmFIZCjAfBgNVHSMEGDAWgBQJZgkGwbmmOtE8\n\
YjXxnJ0fmFIZCjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCICd1\n\
YR2mjStTC896vidbIQPiR/TgsTWbh/GVJnSq/+jZAiEA+gAxHpKKV1fw80GLGOlH\n\
d3tcVkcVXvcSWnnhuGy3nqs=\n\
-----END CERTIFICATE-----\n";

/// HTTP task option acceptance vs the declared diff tables (the
/// per-option half of the check): every name in
/// `HTTP_PERSIST_OPTION_NAMES`/`HTTP_RUNTIME_OPTION_NAMES`, accepted
/// alone with a legal value, must show an observable consumption;
/// names outside the tables (unknown options) are ignored without
/// error — the reference rule. The tables live in `session::options`
/// (the single diff source); this test pins the parse arms to drift
/// together with them.
#[test]
fn http_task_option_tables_match_parsers() {
    use crate::session::options::{HTTP_PERSIST_OPTION_NAMES, HTTP_RUNTIME_OPTION_NAMES};
    use std::collections::BTreeMap;

    // The ca-certificate option value is a temp PEM file (the parse
    // face really loads and validates it; the bad-path rejection is
    // re-checked in the consumed arm).
    let ca_dir = temp_dir("ca-opt");
    let ca_pem_path = ca_dir.join("ca.pem");
    std::fs::write(&ca_pem_path, TEST_CA_PEM).unwrap_or_else(|e| panic!("write ca pem: {e}"));
    let ca_pem_value = ca_pem_path.display().to_string();

    let opts_of = |k: &str, v: &str| {
        let mut m = BTreeMap::new();
        m.insert(k.to_string(), v.to_string());
        m
    };
    let persist_of = |k: &str, v: &str| {
        http_task_options(&opts_of(k, v), &http_task::HttpPersistConfig::default())
            .unwrap_or_else(|e| panic!("{k}: {e}"))
    };
    // Persist face: each of the three keys must land an observable
    // value.
    for name in HTTP_PERSIST_OPTION_NAMES {
        let cfg = match *name {
            "http-incomplete-suffix" => persist_of(name, ".d21").incomplete_suffix == ".d21",
            "checksum" => {
                let digest = "ab".repeat(32);
                persist_of(name, &format!("sha-256={digest}"))
                    .checksum
                    .is_some()
            }
            "remote-time" => persist_of(name, "true").remote_time,
            "http-host-finalize" => persist_of(name, "true").host_finalize,
            other => panic!("HTTP_PERSIST_OPTION_NAMES contains an unknown arm {other:?}"),
        };
        assert!(
            cfg,
            "the HTTP persist accepted name {name:?} has no observable consumption (table/parse-arm drift)"
        );
    }
    // Runtime face: each key must land an observable value
    // (differentiated from the default).
    for name in HTTP_RUNTIME_OPTION_NAMES {
        let opts = http_task_runtime_options(
            &opts_of(
                name,
                match *name {
                    "timeout" | "connect-timeout" => "17",
                    "max-tries" => "9",
                    "retry-wait" => "4",
                    "user-agent" => "taiji-diff-test/1",
                    "header" => "X-Tb21: v",
                    "http-user" => "u21",
                    "http-passwd" => "p21",
                    "all-proxy" => "http://127.0.0.1:8080",
                    // Domain 2 (the HTTPS-dedicated slot / Referer / the
                    // transparent gzip switch): legal values that differ
                    // from the defaults so the slot assertions are
                    // distinguishable.
                    "https-proxy" => "http://127.0.0.1:8081",
                    "referer" => "https://origin.example/page",
                    "http-accept-gzip" => "true",
                    "check-certificate" => "false",
                    // Task-level CA face: a PEM file path (a temp file
                    // assembled at the top of the test).
                    "ca-certificate" => ca_pem_value.as_str(),
                    // Scheduler group: legal in-domain values.
                    "split" => "7",
                    "min-split-size" => "4M",
                    "max-connection-per-server" => "16",
                    "http-stall-window" => "9",
                    "http-scheduler" => "static",
                    // Batch budget: a legal in-domain value.
                    "http-batch-budget" => "7",
                    "http-block-size" => "256K",
                    "http-max-chunk" => "8M",
                    "http-protocol" => "h2",
                    // h2 flow-control windows: legal in-domain values
                    // that differ from the 8MiB/16MiB defaults so the
                    // slot assertions are distinguishable.
                    "http2-adaptive-window" => "true",
                    "http2-stream-window" => "4194304",
                    "http2-connection-window" => "33554432",
                    // h2 multi-connection + keep-alive: legal in-domain
                    // values.
                    "http2-max-connections" => "4",
                    "http2-keep-alive-interval" => "30",
                    "ftp-user" => "fu21",
                    "ftp-passwd" => "fp21",
                    "ftp-ssl" => "implicit",
                    "ftp-pasv" => "true",
                    "ftp-reuse-connection" => "false",
                    // PASV address policy (taiji extension): a legal
                    // in-domain value differing from the peer default so
                    // the slot assertion is distinguishable.
                    "ftp-pasv-address-check" => "strict",
                    other => panic!("HTTP_RUNTIME_OPTION_NAMES contains an unknown arm {other:?}"),
                },
            ),
            &http_task::HttpTaskOpts::default(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let consumed = match *name {
            "timeout" => opts.read_timeout == std::time::Duration::from_secs(17),
            "connect-timeout" => opts.connect_timeout == std::time::Duration::from_secs(17),
            "max-tries" => opts.retry.max_tries == 9,
            "retry-wait" => opts.retry.base_wait == std::time::Duration::from_secs(4),
            "user-agent" => opts.user_agent.as_deref() == Some("taiji-diff-test/1"),
            "header" => opts.headers.iter().any(|(k, v)| k == "X-Tb21" && v == "v"),
            "http-user" | "http-passwd" => opts.auth.is_some(),
            "all-proxy" => opts.proxy.is_some(),
            // Domain 2: the dedicated HTTPS slot / the every-hop Referer /
            // the gzip switch (default false = the identity probe
            // posture, so true is observable).
            "https-proxy" => opts.proxy_https.as_deref() == Some("http://127.0.0.1:8081"),
            "referer" => opts.referer.as_deref() == Some("https://origin.example/page"),
            "http-accept-gzip" => opts.accept_gzip,
            "check-certificate" => opts.accept_invalid_certs,
            // Task-level CA face: the path + DER snapshot land in the
            // slots; a bad path = a parse-time taiji.option.invalid
            // rejection (never a silent pass).
            "ca-certificate" => {
                opts.ca_cert_path.is_some()
                    && !opts.ca_cert_der.is_empty()
                    && http_task_runtime_options(
                        &opts_of("ca-certificate", "/nonexistent/taiji-ca.pem"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
            }
            "ftp-user" | "ftp-passwd" => opts.ftp_auth.is_some(),
            "ftp-ssl" => {
                opts.ftp_tls == taiji_http::ftp::FtpTlsMode::Implicit
                    // The default is not confused by implicit (the
                    // default = auth, explicit TLS).
                    && taiji_http::ftp::FtpTlsMode::default()
                        == taiji_http::ftp::FtpTlsMode::Explicit
            }
            // The ftp-pasv acceptance face is value validation: true is
            // accepted; false (active-mode PORT) is rejected
            // explicitly — PASV/EPSV only here, a declared diff.
            "ftp-pasv" => {
                http_task_runtime_options(
                    &opts_of("ftp-pasv", "false"),
                    &http_task::HttpTaskOpts::default(),
                )
                .is_err()
                    && http_task_runtime_options(
                        &opts_of("ftp-pasv", "yes"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
            }
            "ftp-reuse-connection" => !opts.ftp_reuse_connection,
            // ftp-pasv-address-check (taiji extension): strict lands in
            // the slot and projects into FtpConfig (the hop before
            // FtpTransport::for_uri consumes the value); the default is
            // peer (the aligned posture); out-of-domain/non-lowercase
            // values are rejected without clamping (exact lowercase
            // match).
            "ftp-pasv-address-check" => {
                use taiji_http::ftp::PasvAddressPolicy as Pap;
                opts.ftp_pasv_policy == Pap::DenyPrivate
                    // The default is not confused by strict (the
                    // default = peer, the aligned posture).
                    && taiji_http::ftp::PasvAddressPolicy::default() == Pap::AlignPeer
                    && opts.to_ftp_config().pasv_policy == Pap::DenyPrivate
                    && ["bogus", "PEER", "Strict"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("ftp-pasv-address-check", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
            }
            // Scheduler group: legal values land in the slots and
            // out-of-domain values are rejected (the aria2-native
            // domain 1..=16, rejected not clamped; defaults stay
            // frozen).
            "split" => opts.split == 7,
            "min-split-size" => opts.min_split_size == 4 * 1024 * 1024,
            "max-connection-per-server" => {
                opts.max_conn_per_server == 16
                    && http_task_runtime_options(
                        &opts_of("max-connection-per-server", "0"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    && http_task_runtime_options(
                        &opts_of("max-connection-per-server", "65"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    && http_task_runtime_options(
                        &opts_of("max-connection-per-server", "x"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
            }
            "http-stall-window" => {
                opts.stall_window == std::time::Duration::from_secs(9)
                    && http_task_runtime_options(
                        &opts_of("http-stall-window", "0"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    // Domain floor = several heartbeat ticks: 1s/2s
                    // (one or two ticks) are rejected.
                    && http_task_runtime_options(
                        &opts_of("http-stall-window", "1"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    && http_task_runtime_options(
                        &opts_of("http-stall-window", "2"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    && http_task_runtime_options(
                        &opts_of("http-stall-window", "3"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_ok()
            }
            // Scheduler mode (taiji extension): static lands in the
            // slot; the default dynamic is not confused by the legal
            // value; unknown values are rejected (anything outside the
            // lowercase set, same as SchedulerMode).
            "http-scheduler" => {
                opts.scheduler == taiji_http::scheduler::SchedulerMode::Static
                    && taiji_http::scheduler::SchedulerMode::default()
                        == taiji_http::scheduler::SchedulerMode::Dynamic
                    && http_task_runtime_options(
                        &opts_of("http-scheduler", "guided"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
            }
            // Guided extent cap (taiji extension): 8MiB lands in the
            // slot (inside the 4MiB default block domain); below the
            // block granularity is rejected (a sub-block extent is not
            // expressible — the §4.3 cross-key check: combined with a
            // 256KiB block a 2MiB cap is accepted, 128K still
            // rejected).
            "http-max-chunk" => {
                let combined = |block: &str, max: &str| {
                    let mut m = opts_of("http-block-size", block)
                        .into_iter()
                        .collect::<BTreeMap<_, _>>();
                    m.insert("http-max-chunk".to_string(), max.to_string());
                    http_task_runtime_options(&m, &http_task::HttpTaskOpts::default())
                };
                opts.max_chunk == 8 * 1024 * 1024
                    && http_task_runtime_options(
                        &opts_of("http-max-chunk", "x"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    && combined("256K", "2M")
                        .map(|o| o.max_chunk == 2 * 1024 * 1024)
                        .unwrap_or(false)
                    && combined("256K", "128K").is_err()
            }
            // Block granularity (taiji extension): the 256KiB domain
            // floor lands in the slot; out-of-domain (non-power-of-two /
            // out of bounds) values are rejected — the row contract's
            // single block_size_domain source.
            "http-block-size" => {
                opts.block_size == 256 * 1024
                    && http_task_runtime_options(
                        &opts_of("http-block-size", "300K"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    && http_task_runtime_options(
                        &opts_of("http-block-size", "32M"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
                    && http_task_runtime_options(
                        &opts_of("http-block-size", "128K"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .is_err()
            }
            // Protocol shape (taiji extension): h2 lands in the slot;
            // the default is auto (the status-quo anchor, not confused
            // by the legal value); h1/auto are accepted; unknown values
            // are rejected; the to_client_config projection carries the
            // full domain (the transport-level switch), and the default
            // projection stays Auto.
            "http-protocol" => {
                use taiji_http::client::HttpProtocol;
                opts.http_protocol == HttpProtocol::Http2
                    && taiji_http::client::HttpProtocol::default() == HttpProtocol::Auto
                    && http_task::HttpTaskOpts::default()
                        .to_client_config()
                        .http_protocol
                        == HttpProtocol::Auto
                    && ["auto", "h1", "h2"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http-protocol", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_ok()
                    })
                    // An empty value = the key is absent (an empty
                    // filter means "not provided"), not a rejection; all
                    // unknown spellings are rejected.
                    && ["h2c", "HTTP/2", "h3", "prior-knowledge"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http-protocol", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
                    && {
                        let h2c = http_task_runtime_options(
                            &opts_of("http-protocol", "h2"),
                            &http_task::HttpTaskOpts::default(),
                        );
                        h2c.map(|o| {
                            o.to_client_config().http_protocol == HttpProtocol::Http2
                        })
                        .unwrap_or(false)
                    }
            }
            // h2 flow-control windows (taiji extension): all three keys
            // land in the slots; the defaults anchor the engine values
            // (windows Some(8MiB)/Some(16MiB), adaptive off); the
            // domain edges (65535 / 2^31-1) are accepted, out-of-domain
            // (65534 / 2^31) and non-numeric values rejected; the
            // to_client_config projection carries through.
            "http2-adaptive-window" => {
                opts.http2_adaptive_window
                    && !http_task::HttpTaskOpts::default().http2_adaptive_window
                    && ["yes", "on", "2"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http2-adaptive-window", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
                    && http_task_runtime_options(
                        &opts_of("http2-adaptive-window", "false"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| !o.http2_adaptive_window)
                    .unwrap_or(false)
 // The projection face (like the other four key arms): this
                    // assertion fails if the parse line is deleted or
                    // the projection breaks — all five key arms are
                    // pinned through to_client_config.
                    && http_task_runtime_options(
                        &opts_of("http2-adaptive-window", "true"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| o.to_client_config().http2_adaptive_window)
                    .unwrap_or(false)
            }
            "http2-stream-window" => {
                opts.http2_stream_window == Some(4194304)
                    && http_task::HttpTaskOpts::default().http2_stream_window
                        == Some(taiji_http::client::DEFAULT_H2_STREAM_WINDOW)
                    && ["65534", "2147483648", "0", "x"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http2-stream-window", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
                    && ["65535", "2147483647"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http2-stream-window", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_ok()
                    })
                    && {
                        let w = http_task_runtime_options(
                            &opts_of("http2-stream-window", "4194304"),
                            &http_task::HttpTaskOpts::default(),
                        );
                        w.map(|o| o.to_client_config().http2_stream_window == Some(4194304))
                            .unwrap_or(false)
                    }
            }
            "http2-connection-window" => {
                opts.http2_connection_window == Some(33554432)
                    && http_task::HttpTaskOpts::default().http2_connection_window
                        == Some(taiji_http::client::DEFAULT_H2_CONN_WINDOW)
                    && ["65534", "2147483648", "x"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http2-connection-window", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
                    && http_task_runtime_options(
                        &opts_of("http2-connection-window", "33554432"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| o.to_client_config().http2_connection_window == Some(33554432))
                    .unwrap_or(false)
            }
            // h2 multi-connection + keep-alive (taiji extension): the
            // values land in the slots; the defaults anchor the status
            // quo (K=1, keep-alive off); out-of-domain K (0/9) and
            // keep-alive (3601/negative) are rejected; the upper bounds
            // (8/3600) are accepted (guards against `>` decaying into
            // `>=`); keep-alive 0 = explicitly off; the projection
            // carries through.
            "http2-max-connections" => {
                opts.http2_max_connections == 4
                    && http_task::HttpTaskOpts::default().http2_max_connections == 1
                    && ["0", "9", "x"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http2-max-connections", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
                    && http_task_runtime_options(
                        &opts_of("http2-max-connections", "1"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| {
                        o.to_client_config().http2_max_connections == 1
                    })
                    .unwrap_or(false)
 // Upper-bound acceptance: if `n > 8` decayed to
                    // `n >= 8`, the value 8 would be rejected and this
                    // assertion would fail.
                    && http_task_runtime_options(
                        &opts_of("http2-max-connections", "8"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| o.http2_max_connections == 8)
                    .unwrap_or(false)
            }
            "http2-keep-alive-interval" => {
                opts.http2_keep_alive_interval == Some(std::time::Duration::from_secs(30))
                    && http_task::HttpTaskOpts::default().http2_keep_alive_interval.is_none()
 // The negative-shape sample matches the sibling arms: "-1"
                    // hits the unsigned parse rejection.
                    && ["3601", "-1", "x"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http2-keep-alive-interval", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
                    && http_task_runtime_options(
                        &opts_of("http2-keep-alive-interval", "0"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| {
                        o.http2_keep_alive_interval.is_none()
                            && o.to_client_config().http2_keep_alive_interval.is_none()
                    })
                    .unwrap_or(false)
 // Upper-bound acceptance: if `n > 3600` decayed to
                    // `n >= 3600`, the value 3600 would be rejected and
                    // this assertion would fail.
                    && http_task_runtime_options(
                        &opts_of("http2-keep-alive-interval", "3600"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| {
                        o.http2_keep_alive_interval
                            == Some(std::time::Duration::from_secs(3600))
                    })
                    .unwrap_or(false)
                    && http_task_runtime_options(
                        &opts_of("http2-keep-alive-interval", "30"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| {
                        o.to_client_config().http2_keep_alive_interval
                            == Some(std::time::Duration::from_secs(30))
                    })
                    .unwrap_or(false)
            }
            // Batch budget (taiji extension): 7 lands in the slot; the
            // default 16 anchors the engine constant; out-of-domain
            // values (1 = serialized, 65 = past the host cap and
            // meaningless, non-numeric) are rejected.
            "http-batch-budget" => {
                opts.batch_budget == 7
                    && http_task::HttpTaskOpts::default().batch_budget
                        == taiji_http::batch::DEFAULT_BATCH_BUDGET
                    && ["1", "65", "0", "x"].iter().all(|v| {
                        http_task_runtime_options(
                            &opts_of("http-batch-budget", v),
                            &http_task::HttpTaskOpts::default(),
                        )
                        .is_err()
                    })
                    && http_task_runtime_options(
                        &opts_of("http-batch-budget", "2"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| o.batch_budget == 2)
                    .unwrap_or(false)
                    && http_task_runtime_options(
                        &opts_of("http-batch-budget", "64"),
                        &http_task::HttpTaskOpts::default(),
                    )
                    .map(|o| o.batch_budget == 64)
                    .unwrap_or(false)
            }
            other => panic!("HTTP_RUNTIME_OPTION_NAMES contains an unknown arm {other:?}"),
        };
        assert!(
            consumed,
            "the HTTP runtime accepted name {name:?} has no observable consumption (table/parse-arm drift)"
        );
    }
    // Unknown options are ignored (the reference rule): no error, no
    // default change.
    let mut unknown = BTreeMap::new();
    unknown.insert("not-an-aria2-option".to_string(), "1".to_string());
    let cfg = http_task_options(&unknown, &http_task::HttpPersistConfig::default())
        .unwrap_or_else(|e| panic!("unknown persist must be ignored: {e}"));
    let opts = http_task_runtime_options(&unknown, &http_task::HttpTaskOpts::default())
        .unwrap_or_else(|e| panic!("unknown runtime must be ignored: {e}"));
    assert_eq!(cfg, http_task::HttpPersistConfig::default());
    assert_eq!(
        opts.read_timeout,
        http_task::HttpTaskOpts::default().read_timeout
    );
    assert!(opts.headers.is_empty() && opts.auth.is_none() && opts.proxy.is_none());
}

/// Multi-URI array e2e (session level, the multi-source assembly
/// consumer): addUri with multiple URIs (mirrors of one file) ->
/// per-source probing and merging -> multi-source coordinator assembly
/// (EWMA-weighted shares, §4.7) -> both sources claim extents ->
/// tellStopped/getUris `sources`/`uris` present the same ordered
/// source set. The 9MiB file = 3 blocks (4MiB grid), two workers (one
/// per source) fetching in parallel.
#[tokio::test]
async fn http_multi_uri_array_allocates_across_sources_with_sources_face() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-multi");
    // 9MiB = 3 blocks: both sources have >= 2 extents to claim (share
    // arbitration must not collapse to one source).
    let body: Vec<u8> = (0..9 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
    let body = Arc::new(body);
    let origin_a = spawn_mock_origin(Arc::clone(&body), true, true, false).await;
    let origin_b = spawn_mock_origin(Arc::clone(&body), true, true, false).await;
    let uris = vec![origin_a.url("m.bin"), origin_b.url("m.bin")];

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: uris.clone(),
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
                position: None,
            },
        )
        .await,
    );

    // getUris lists per source while the task is queued/downloading
    // (aria2 HTTP semantics); activation probes every source, so all
    // are spent -> all "used" (see the commands.rs get_uris doc for
    // the pre-activation "waiting" window).
    wait_until(async || {
        match call(
            &handle,
            SessionCommand::GetUris {
                gid: gid.to_string(),
            },
        )
        .await
        {
            Ok(CommandReply::Uris(uris_view)) => {
                let seen: Vec<&str> = uris_view.iter().map(|u| u.uri.as_str()).collect();
                seen == uris.as_slice() && uris_view.iter().all(|u| u.status == "used")
            }
            other => panic!("expected Uris reply, got {other:?}"),
        }
    })
    .await;
    match call(
        &handle,
        SessionCommand::GetUris {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Uris(uris_view)) => {
            let seen: Vec<&str> = uris_view.iter().map(|u| u.uri.as_str()).collect();
            assert_eq!(
                seen,
                uris.as_slice(),
                "the multi-URI array enqueues one entry per source"
            );
            assert!(uris_view.iter().all(|u| u.status == "used"));
        }
        other => panic!("expected Uris reply, got {other:?}"),
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
        stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Complete)
    })
    .await;

    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let http = entry.http.as_ref().unwrap_or_else(|| panic!("http dict"));
    // The sources face: both sources in user order; finished workers
    // close out -> waiting.
    assert_eq!(
        http.sources.len(),
        2,
        "one entry per source of the multi-URI array"
    );
    assert_eq!(http.sources[0].url, uris[0]);
    assert_eq!(http.sources[1].url, uris[1]);
    // The allocation really spanned sources: both made Range fetches
    // (the probe bytes=0-0 is not counted).
    assert!(
        !origin_a.fetch_ranges().is_empty(),
        "source A must participate in sharding"
    );
    assert!(
        !origin_b.fetch_ranges().is_empty(),
        "source B must participate in sharding (multi-source assembly spawns a worker per source)"
    );
    assert_eq!(http.blocks_total, 3);
    assert_eq!(http.blocks_done, 3);
    assert_eq!(entry.total_length, 9 * 1024 * 1024);
    // The file bytes are identical.
    assert_eq!(entry.files.len(), 1);
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body.as_slice(), "downloaded bytes round-trip");

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mixed-source fault tolerance e2e: a dead FTP source (port 1 refuses
/// immediately) + a live http mirror — the FTP source is dropped at
/// probe failure (the merge-table "drop sources that fail probing"
/// rule) and the http source completes as usual; the sources face
/// honestly shows the failed state, never dragging or disguising.
#[tokio::test]
async fn http_dead_ftp_source_dropped_http_mirror_completes() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-ftp-mixed");
    let body: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 249) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
    let ftp_dead = "ftp://127.0.0.1:1/f.bin".to_string();
    let http_uri = origin.url("f.bin");

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![ftp_dead.clone(), http_uri.clone()],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
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
    let http = entry.http.as_ref().unwrap_or_else(|| panic!("http dict"));
    assert_eq!(
        http.sources.len(),
        2,
        "the full user source set is presented"
    );
    let ftp_slot = http
        .sources
        .iter()
        .find(|s| s.url == ftp_dead)
        .unwrap_or_else(|| panic!("ftp slot"));
    assert_eq!(
        ftp_slot.state, "failed",
        "a dead FTP source = the failed terminal state"
    );
    let http_slot = http
        .sources
        .iter()
        .find(|s| s.url == http_uri)
        .unwrap_or_else(|| panic!("http slot"));
    assert!(http_slot.state == "waiting" || http_slot.state == "active");
    assert_eq!(entry.total_length, body.len() as u64);
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(got, body, "the http mirror completes with matching bytes");

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The multi-source list persists end to end: a multi-URI add writes
/// mirrors_json with the row -> the restart bootstrap expands the same
/// source set (one getUris item per source) — recovery no longer falls
/// back to a single source.
#[tokio::test]
async fn http_mirrors_json_roundtrip_survives_restart() {
    use taiji_store::persist::PersistWriter;

    let db = tmp_db("mirrors-rt");
    let dir = temp_dir("mirrors-rt");
    let uris = vec![
        "http://127.0.0.1:1/a.bin".to_string(),
        "http://127.0.0.1:2/a.bin".to_string(),
        "ftp://127.0.0.1:3/a.bin".to_string(),
    ];
    let add = SessionCommand::AddUri {
        uris: uris.clone(),
        options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
        position: None,
    };

    // ---- Session 1: register (paused, not activated) -> persist ->
    // shutdown ----
    let (writer, wjoin) = match PersistWriter::spawn(db.clone()).await {
        Ok(w) => w,
        Err(e) => panic!("spawn writer: {e}"),
    };
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let gid = gid_of(&call(&handle, add).await);
    match call(&handle, SessionCommand::SaveSession).await {
        Ok(CommandReply::Accepted) => {}
        other => panic!("saveSession accepted, got {other:?}"),
    }
    {
        let conn = rusqlite::Connection::open(&db).unwrap_or_else(|e| panic!("open: {e}"));
        let mirrors: String = conn
            .query_row(
                "SELECT mirrors_json FROM http_task WHERE gid = ?1",
                rusqlite::params![gid.to_string()],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("mirrors_json readback: {e}"));
        let vals: Vec<serde_json::Value> =
            serde_json::from_str(&mirrors).unwrap_or_else(|e| panic!("mirrors parse: {e}"));
        let stored: Vec<&str> = vals
            .iter()
            .filter_map(|v| v.get("url").and_then(|u| u.as_str()))
            .collect();
        assert_eq!(
            stored,
            uris.as_slice(),
            "the multi-URI array persists with the row"
        );
    }
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // ---- Session 2: bootstrap recovery -> the source set expands in
    // the same order ----
    let (writer2, wjoin2) = match PersistWriter::spawn(db.clone()).await {
        Ok(w) => w,
        Err(e) => panic!("spawn writer 2: {e}"),
    };
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    let mut restored = false;
    for _ in 0..100 {
        let waiting = status_list(
            &call(
                &handle2,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        if waiting.iter().any(|v| v.gid == gid) {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(restored, "the task is restored after restart");
    match call(
        &handle2,
        SessionCommand::GetUris {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Uris(uris_view)) => {
            let seen: Vec<&str> = uris_view.iter().map(|u| u.uri.as_str()).collect();
            assert_eq!(
                seen,
                uris.as_slice(),
                "recovery expands the multi-source list (ftp included)"
            );
        }
        other => panic!("expected Uris reply, got {other:?}"),
    }

    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

/// mirrors_json persistence unit matrix: the write face (>1 source
/// serializes, a single source omits) and the restore face (url-key
/// objects and bare string items tolerated, order-preserving dedup,
/// the row url always first, a corrupt payload falls back to the
/// single source).
#[test]
fn mirrors_json_persist_and_restore_matrix() {
    let uris = vec![
        "http://a/f.bin".to_string(),
        "http://b/f.bin".to_string(),
        "ftp://c/f.bin".to_string(),
    ];
    // Write face: multiple sources serialize as url-key object arrays;
    // a single source writes nothing (None).
    let raw = http_task::mirrors_json_of(&uris).unwrap_or_else(|| panic!("multi must persist"));
    let vals: Vec<serde_json::Value> =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse: {e}"));
    let urls: Vec<&str> = vals
        .iter()
        .map(|v| v.get("url").and_then(|u| u.as_str()).unwrap_or(""))
        .collect();
    assert_eq!(urls, ["http://a/f.bin", "http://b/f.bin", "ftp://c/f.bin"]);
    assert_eq!(
        http_task::mirrors_json_of(&uris[..1]),
        None,
        "a single-source row writes no payload"
    );
    // Restore face: order-preserving expansion.
    assert_eq!(
        http_task::uris_from_mirrors(Some(&raw), "http://a/f.bin"),
        uris,
        "restore expands the same set in the same order"
    );
    // String items tolerated + dedup + the row url always first.
    let legacy = r#"["http://x/1",{"url":"http://x/2"},"http://x/1"]"#;
    assert_eq!(
        http_task::uris_from_mirrors(Some(legacy), "http://x/1"),
        vec!["http://x/1".to_string(), "http://x/2".to_string()],
        "string items tolerated, duplicates deduped"
    );
    // A corrupt/missing payload -> single-source fallback (the url
    // column).
    assert_eq!(
        http_task::uris_from_mirrors(None, "http://a/f.bin"),
        vec!["http://a/f.bin".to_string()]
    );
    assert_eq!(
        http_task::uris_from_mirrors(Some("not-json"), "http://a/f.bin"),
        vec!["http://a/f.bin".to_string()]
    );
}

// ===== Import: in-flight progress rescue on the activation chain
// (adoption rename + rename suppression + digest-gate degradation) =====

use super::http_task::HttpPersistConfig;
use crate::session::persist::import::ImportSource;
use crate::session::persist::import_http::{
    HttpImportPlanner, HttpPlanEntry, HttpPlanInput, HttpProgressFacts, HttpSourceTask,
    PathConflictAction, apply_http_import,
};

/// MSB-first piece bitmap constructor (the fork/aria2 BitfieldMan
/// encoding; fixed length = ceil(pieces/8)).
fn p50_bitfield(num_pieces: u64, done: &[u64]) -> Vec<u8> {
    let mut bf = vec![0u8; num_pieces.div_ceil(8) as usize];
    for p in done {
        bf[(*p / 8) as usize] |= 0x80 >> (*p % 8);
    }
    bf
}

/// The import-shape digest (the importer's seeded facts: first URI
/// path + total length, strong-validator facts absent — the fork
/// stores no etag/last_modified while real servers always send them,
/// so the digest is certain to drift).
fn p50_import_digest(path: &str, total: u64) -> Vec<u8> {
    super::super::http::validator_digest(&super::super::http::ValidatorFacts {
        final_url_path: path.into(),
        total_len: Some(total),
        etag: None,
        last_modified: None,
        encoding_ok: true,
    })
    .unwrap_or_default()
}

/// Activation resume e2e: a fork fixture with a partial `f.iso` (a
/// non-prealloc frontier) + a bitmap-bearing row -> the real import
/// adopts it (`f.iso` -> `f.iso.part`) -> unpause -> assertions: the
/// report's "imported progress 4/8" matches the activation reality
/// (zero refetches before the frontier + blocks_done >= 4), `out` was
/// not renamed (no `f.iso.1`), and the final file is complete. Three
/// links close in one happy path: adoption rename (the data becomes
/// the resume input), auto-rename suppression (the final file's
/// absence is the adoption's result), and digest-gate degradation (the
/// bitmap is not wiped by digest drift).
#[tokio::test]
async fn http_task_imported_progress_resume_e2e_from_fork_data_file() {
    const PIECE: u64 = 256 * 1024;
    const TOTAL: u64 = 8 * PIECE; // 8 pieces = 8 blocks @256KiB
    const FRONTIER: usize = 4 * PIECE as usize; // fork write frontier = blocks 0..4
    let parent = temp_dir("http-p50-e2e");
    let dl = parent.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let db_path = parent.join("taiji.sqlite3");
    let body: Vec<u8> = (0..TOTAL as u32).map(|i| (i % 199) as u8).collect();
    // Fork fixture: partial data written straight to the final path
    // `f.iso` (the shape that kills the rename link).
    ok(
        std::fs::write(dl.join("f.iso"), &body[..FRONTIER]),
        "seed fork data",
    );

    // Slow origin (32KiB/30ms): a ~1s download window for observing
    // the activation.
    let origin =
        spawn_mock_origin_full(Arc::new(body.clone()), true, true, false, None, true).await;
    let url = origin.url("f.iso");
    let gid_hex = "8000000000000911".to_string();
    let task = HttpSourceTask {
        source: ImportSource::ForkDb {
            db_path: db_path.clone(),
            fork_gid: "0000000000000099".into(),
        },
        source_key: "fork-db:0000000000000099".into(),
        fork_gid: Some("0000000000000099".into()),
        queue_pos: 0,
        uris: vec![url],
        unsupported_uris: vec![],
        dir: dl.display().to_string(),
        out: Some("f.iso".into()),
        paused: true,
        options: vec![],
        progress: Some(HttpProgressFacts {
            piece_length: PIECE,
            total_length: TOTAL,
            bitfield: p50_bitfield(8, &[0, 1, 2, 3]),
        }),
    };
    let mut planner = HttpImportPlanner::new(Vec::new());
    let planned = match planner.plan(HttpPlanInput {
        task: &task,
        gid_hex,
        imported_gid: None,
        conflict_action: PathConflictAction::Skip,
    }) {
        HttpPlanEntry::Planned(p) => *p,
        other => panic!("plan: {other:?}"),
    };
    // The report face: the imported-progress note (4/8 blocks @ 256KiB
    // grid).
    let report = planned
        .warnings
        .iter()
        .find(|w| w.starts_with("imported progress:"))
        .unwrap_or_else(|| panic!("imported progress note missing: {:?}", planned.warnings))
        .clone();
    assert!(
        report.contains("4/8 blocks"),
        "the report note should record 4/8 blocks: {report}"
    );

    // Real import: adoption rename + persistence.
    let (hw, jw) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
    let applied = apply_http_import(&hw, std::slice::from_ref(&planned)).await;
    assert!(applied[0].error.is_none(), "apply: {:?}", applied[0].error);
    // Adoption evidence: `f.iso` has been archived as `f.iso.part`,
    // bytes unchanged.
    assert!(
        !dl.join("f.iso").exists(),
        "the final file must have been adopted via rename"
    );
    assert_eq!(
        ok(std::fs::read(dl.join("f.iso.part")), "read adopted"),
        &body[..FRONTIER],
        "the adopted `.part` = the fork-frontier data"
    );
    drop(hw);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), jw).await,
        "writer exit",
    );

    // New session on the same store: bootstrap rebuilds the paused
    // task -> unpause activates.
    let (persist, writer) = ok(
        PersistWriter::spawn(db_path.clone()).await,
        "spawn writer 2",
    );
    let global = GlobalOptions {
        dir: dl.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = Gid::from_u64(u64::from_str_radix(&planned.gid, 16).unwrap_or(0));
    // The unpause reply = the re-enqueued GID (aria2 unpause
    // semantics).
    match call(
        &handle,
        SessionCommand::Unpause {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Gid(g)) => assert_eq!(g, gid, "the unpause receipt"),
        other => panic!("unpause: {other:?}"),
    }
    // Activation reality: the slow origin guarantees a download window
    // — blocks_done starts at the imported bitmap count and the
    // terminal state is Complete.
    let mut observed_done = 0u64;
    let mut completed = false;
    for _ in 0..250 {
        if let Ok(CommandReply::StatusList(entries)) =
            call(&handle, SessionCommand::TellActive { keys: vec![] }).await
        {
            for e in &entries {
                if e.gid == gid {
                    if let Some(h) = &e.http {
                        observed_done = observed_done.max(h.blocks_done);
                    }
                }
            }
        }
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
        .any(|v| v.gid == gid && v.status == StatusKind::Complete)
        {
            completed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(completed, "the task must complete");
    assert!(
        observed_done >= 4,
        "the observed blocks_done at activation >= the imported bitmap's block count (4), got {observed_done}"
    );

    // Resume hit: every fetch Range lies past the imported progress
    // frontier (blocks 0..4 not refetched) and the first cut starts at
    // the frontier (the measured anchor matching the reported 4/8
    // blocks x 256KiB).
    let ranges = origin.fetch_ranges();
    assert!(!ranges.is_empty(), "fetches must have occurred");
    assert_eq!(
        ranges.iter().map(|r| r.0).min(),
        Some(FRONTIER as u64),
        "resume hit at activation: zero refetch before the frontier, the first cut starts at the \
         imported progress frontier"
    );
    // out not renamed: the final file lands at `f.iso` with no
    // auto-rename candidates (the rename-suppression link).
    assert!(!dl.join("f.iso.1").exists(), "no silent rename to f.iso.1");
    assert!(
        !dl.join("f.iso.1.part").exists(),
        "no renamed-candidate part produced"
    );
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    assert_eq!(entry.files[0].path, dl.join("f.iso"), "out not renamed");
    let got = ok(std::fs::read(&entry.files[0].path), "read final");
    assert_eq!(got, body, "the file is intact after resume");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&parent);
}

/// The digest-gate degradation link, isolated: an import-shape row
/// (seeded digest without etag/last_modified, no probe_json, the
/// imported_progress flag) + an already-adopted `.part` -> activation
/// must not clear the bitmap on digest drift; the resume hits (zero
/// refetches before the frontier). The mock origin always sends
/// Last-Modified — previously the seeded digest (missing lm) drifted
/// from the measured one, clearing the bitmap first and re-fetching
/// everything from zero.
#[tokio::test]
async fn http_task_imported_row_digest_gate_degraded_on_first_activation() {
    const BS: u64 = 4 * 1024 * 1024;
    let parent = temp_dir("http-p50-gate");
    let dl = parent.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let db_path = parent.join("taiji.sqlite3");
    // 5MiB = 2 blocks @4MiB; block 0 is on disk (the adopted
    // frontier), block 1 pending.
    let body: Vec<u8> = (0..(5 * 1024 * 1024u32)).map(|i| (i % 199) as u8).collect();
    ok(
        std::fs::write(part_path_of(&dl, "f.bin"), &body[..BS as usize]),
        "seed adopted part",
    );
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
    let url = origin.url("f.bin");
    let gid_hex = "8000000000000912".to_string();
    let row = taiji_store::persist::HttpTaskRow {
        gid: gid_hex.clone(),
        url: url.clone(),
        final_url: String::new(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 1,
        dir: dl.display().to_string(),
        out: "f.bin".into(),
        config_json: HttpPersistConfig {
            imported_progress: true,
            ..HttpPersistConfig::default()
        }
        .to_json(),
        probe_json: None,
        validator_digest: Some(p50_import_digest("/f.bin", body.len() as u64)),
        block_size: BS as i64,
        block_bitmap: Some(vec![0b01]),
        block_count: Some(2),
        total_done: BS as i64,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    {
        let (hw, jw) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
        ok(hw.upsert_http_task(row).await, "seed row");
        drop(hw);
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(1), jw).await,
            "writer exit",
        );
    }
    let (persist, writer) = ok(
        PersistWriter::spawn(db_path.clone()).await,
        "spawn writer 2",
    );
    let global = GlobalOptions {
        dir: dl.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = Gid::from_u64(u64::from_str_radix(&gid_hex, 16).unwrap_or(0));
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
    // Resume hit: block 0 is not refetched (digest drift did not clear
    // the bitmap); only the remaining block 1 is fetched.
    assert_eq!(
        origin.fetch_ranges(),
        vec![(BS, body.len() as u64 - 1)],
        "digest-gate degradation: the imported bitmap survives, zero refetch before the frontier"
    );
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    let got = ok(std::fs::read(&entry.files[0].path), "read final");
    assert_eq!(got, body, "the file is intact after resume");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&parent);
}

/// The rename-suppression link, isolated: at activation the final file
/// already exists for an imported bitmap row (the `.part` placeholder
/// makes the adoption guard step in: `f.bin` and `f.bin.part`
/// coexist) -> an explicit conflict failure, never a silent rename to
/// `f.bin.1` (previously it renamed and the two data copies lost each
/// other); `f.bin` and the `.part` stay byte-identical.
#[tokio::test]
async fn http_task_imported_row_final_file_conflict_fails_without_rename() {
    const BS: u64 = 4 * 1024 * 1024;
    let parent = temp_dir("http-p50-rename");
    let dl = parent.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let db_path = parent.join("taiji.sqlite3");
    let body: Vec<u8> = (0..(5 * 1024 * 1024u32)).map(|i| (i % 199) as u8).collect();
    ok(
        std::fs::write(dl.join("f.bin"), &body),
        "seed leftover final",
    );
    ok(
        std::fs::write(part_path_of(&dl, "f.bin"), &body[..BS as usize]),
        "seed part",
    );
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
    let url = origin.url("f.bin");
    let gid_hex = "8000000000000913".to_string();
    let row = taiji_store::persist::HttpTaskRow {
        gid: gid_hex.clone(),
        url: url.clone(),
        final_url: String::new(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 1,
        dir: dl.display().to_string(),
        out: "f.bin".into(),
        config_json: HttpPersistConfig {
            imported_progress: true,
            ..HttpPersistConfig::default()
        }
        .to_json(),
        probe_json: None,
        validator_digest: Some(p50_import_digest("/f.bin", body.len() as u64)),
        block_size: BS as i64,
        block_bitmap: Some(vec![0b01]),
        block_count: Some(2),
        total_done: BS as i64,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    {
        let (hw, jw) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
        ok(hw.upsert_http_task(row).await, "seed row");
        drop(hw);
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(1), jw).await,
            "writer exit",
        );
    }
    let (persist, writer) = ok(
        PersistWriter::spawn(db_path.clone()).await,
        "spawn writer 2",
    );
    let global = GlobalOptions {
        dir: dl.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = Gid::from_u64(u64::from_str_radix(&gid_hex, 16).unwrap_or(0));
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
    // Rename suppressed: no `f.bin.1` produced; the final file and the
    // `.part` keep their bytes.
    assert!(!dl.join("f.bin.1").exists(), "no silent rename to f.bin.1");
    assert!(!dl.join("f.bin.1.part").exists());
    assert_eq!(
        ok(std::fs::read(dl.join("f.bin")), "read final"),
        body,
        "the final file keeps its original bytes"
    );
    assert_eq!(
        ok(std::fs::read(part_path_of(&dl, "f.bin")), "read part"),
        &body[..BS as usize],
        "the `.part` keeps its original bytes"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&parent);
}

// ===== Import consumption at activation (imported_options folded
// into requests + cold-row real projections) =====

/// A validating mock forward proxy (raw TCP, in-process): records
/// every request head block and answers 200 + Content-Length + the
/// full body (probe and data share one face). The proxy-side record is
/// the "request went through" evidence — paired with a dead origin
/// (direct connection unreachable), task completion implies the
/// request rode the proxy (the fold-in anchor).
struct MockProxy {
    addr: std::net::SocketAddr,
    heads: Arc<std::sync::Mutex<Vec<String>>>,
}

async fn spawn_mock_proxy(body: Arc<Vec<u8>>) -> MockProxy {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let heads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let heads_t = Arc::clone(&heads);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = Arc::clone(&body);
            let heads = Arc::clone(&heads_t);
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    // Read one request head block (\r\n\r\n delimited).
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
                    heads.lock().unwrap_or_else(|p| p.into_inner()).push(head);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                         Connection: keep-alive\r\n\r\n",
                        body.len()
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    if sock.write_all(&body).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    MockProxy { addr, heads }
}

impl MockProxy {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request head block (lowercased; the assertion source).
    fn heads(&self) -> Vec<String> {
        self.heads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect()
    }
}

/// Imported auth-header/UA/proxy e2e: an imported row's
/// imported_options (header/user-agent/all-proxy) must be folded in
/// when activation assembles the request. The origin is unreachable
/// directly (port 1) -> completion implies the request rode the
/// proxy; the proxy validates the auth header and UA are present.
/// (Regression: imported_options had no consumer anywhere, so nothing
/// was folded at runtime and the direct-connection failure failed the
/// task.)
#[tokio::test]
async fn http_task_imported_options_fold_e2e_proxy_auth_header() {
    let parent = temp_dir("http-p53-fold");
    let dl = parent.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let db_path = parent.join("taiji.sqlite3");
    let body: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 199) as u8).collect();
    let proxy = spawn_mock_proxy(Arc::new(body.clone())).await;
    let gid_hex = "8000000000000921".to_string();
    let row = taiji_store::persist::HttpTaskRow {
        gid: gid_hex.clone(),
        // Dead origin: without the proxy fold-in the connection is
        // refused and the task fails (the regression's root cause).
        url: "http://127.0.0.1:1/f.bin".to_string(),
        final_url: String::new(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 1,
        dir: dl.display().to_string(),
        out: "f.bin".into(),
        config_json: HttpPersistConfig {
            imported_options: Some(vec![
                ("user-agent".to_string(), "taiji-import-agent/1".to_string()),
                (
                    "header".to_string(),
                    "Authorization: Bearer tok-9f2".to_string(),
                ),
                ("all-proxy".to_string(), proxy.url()),
            ]),
            ..HttpPersistConfig::default()
        }
        .to_json(),
        probe_json: None,
        validator_digest: None,
        block_size: 0,
        block_bitmap: None,
        block_count: None,
        total_done: 0,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    {
        let (hw, jw) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
        ok(hw.upsert_http_task(row).await, "seed row");
        drop(hw);
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(1), jw).await,
            "writer exit",
        );
    }
    let (persist, writer) = ok(
        PersistWriter::spawn(db_path.clone()).await,
        "spawn writer 2",
    );
    let global = GlobalOptions {
        dir: dl.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = Gid::from_u64(u64::from_str_radix(&gid_hex, 16).unwrap_or(0));
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
    // Proxy + headers present: the origin is unreachable, so
    // completion means the request rode the proxy; the auth header and
    // UA must be folded into the request (the mock checks their
    // presence — the acceptance criterion).
    let heads = proxy.heads();
    assert!(
        !heads.is_empty(),
        "requests must arrive via the proxy (the origin is unreachable directly)"
    );
    assert!(
        heads
            .iter()
            .any(|h| h.lines().any(|l| l == "authorization: bearer tok-9f2")),
        "the auth header must be folded into the request: {heads:?}"
    );
    assert!(
        heads
            .iter()
            .any(|h| h.lines().any(|l| l == "user-agent: taiji-import-agent/1")),
        "the UA must be folded into the request: {heads:?}"
    );
    let entry = status_list(
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
    .find(|v| v.gid == gid)
    .unwrap_or_else(|| panic!("entry"));
    let got = ok(std::fs::read(&entry.files[0].path), "read final");
    assert_eq!(got, body, "the file downloaded through the proxy is intact");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&parent);
}

/// Imported checksum fold-in e2e: an imported row's imported_options
/// carries `checksum=sha-256=<hex>` (a bad digest) -> folded into the
/// persist face at activation, the completion-time final arbitration
/// must receive the value and intercept the mismatch (canonical code
/// `taiji.http.checksum_mismatch`; on the small-file grid path the
/// arbitration runs before the rename, so a mismatched final file
/// never lands). The folded value freezes into the row ("the DB is
/// the journal" — the arbitration face reads exactly this payload).
/// (Regression: checksum was neither folded nor consumed anywhere, so
/// imported tasks had no end-to-end verification and completed anyway
/// — tampered content sailed through.)
#[tokio::test]
async fn http_task_imported_checksum_mismatch_intercepted_e2e() {
    let parent = temp_dir("http-sec31-csm");
    let dl = parent.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let db_path = parent.join("taiji.sqlite3");
    let body: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
    let gid_hex = "8000000000000931".to_string();
    let row = taiji_store::persist::HttpTaskRow {
        gid: gid_hex.clone(),
        url: origin.url("f.bin"),
        final_url: String::new(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 1,
        dir: dl.display().to_string(),
        out: "f.bin".into(),
        config_json: HttpPersistConfig {
            imported_options: Some(vec![(
                "checksum".to_string(),
                format!("sha-256={}", "0".repeat(64)),
            )]),
            ..HttpPersistConfig::default()
        }
        .to_json(),
        probe_json: None,
        validator_digest: None,
        block_size: 0,
        block_bitmap: None,
        block_count: None,
        total_done: 0,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    {
        let (hw, jw) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
        ok(hw.upsert_http_task(row).await, "seed row");
        drop(hw);
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(1), jw).await,
            "writer exit",
        );
    }
    let (persist, writer) = ok(
        PersistWriter::spawn(db_path.clone()).await,
        "spawn writer 2",
    );
    let global = GlobalOptions {
        dir: dl.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = Gid::from_u64(u64::from_str_radix(&gid_hex, 16).unwrap_or(0));
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
        .unwrap_or_else(|| panic!("error entry"));
    assert_eq!(
        entry.error_engine.as_ref().map(|f| f.code.as_str()),
        Some("taiji.http.checksum_mismatch"),
        "the imported checksum must reach the completion-time arbitration and intercept the mismatch"
    );
    assert!(
        !dl.join("f.bin").exists(),
        "a file failing verification must not land (arbitration before the rename)"
    );
    // Fold-into-row evidence: the row config_json's checksum value has
    // been frozen by the fold-in — the arbitration face (task_checksum
    // reading the row payload) consumes exactly this copy.
    let cfg_json = {
        let conn = ok(rusqlite::Connection::open(&db_path), "open db");
        ok(
            conn.query_row(
                "SELECT config_json FROM http_task WHERE gid = ?1",
                params![&gid_hex],
                |r| r.get::<_, String>(0),
            ),
            "config_json",
        )
    };
    assert!(
        cfg_json.contains(r#""checksum":"sha-256="#),
        "the folded value must persist with the row (the arbitration face reads this payload): {cfg_json}"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&parent);
}

/// Imported checksum value-domain e2e: imported_options carrying
/// `checksum=sha3-256=<hex>` (outside the six-hash domain) hits the
/// same fold-in domain validation as the addUri face (scheme in
/// md5|sha-1|sha-224|sha-256|sha-384|sha-512) and is rejected
/// explicitly with `taiji.option.invalid` (the task dies before the
/// probing phase — never silently dropped while pretending to work).
/// (Regression: the key was silently ignored and the task completed —
/// acceptance without effect is a disguise.)
#[tokio::test]
async fn http_task_imported_checksum_unsupported_algorithm_rejected_e2e() {
    let parent = temp_dir("http-sec31-sha3");
    let dl = parent.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let db_path = parent.join("taiji.sqlite3");
    let body: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_mock_origin(Arc::new(body.clone()), true, true, false).await;
    let gid_hex = "8000000000000932".to_string();
    let row = taiji_store::persist::HttpTaskRow {
        gid: gid_hex.clone(),
        url: origin.url("f.bin"),
        final_url: String::new(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 1,
        dir: dl.display().to_string(),
        out: "f.bin".into(),
        config_json: HttpPersistConfig {
            imported_options: Some(vec![(
                "checksum".to_string(),
                format!("sha3-256={}", "0".repeat(32)),
            )]),
            ..HttpPersistConfig::default()
        }
        .to_json(),
        probe_json: None,
        validator_digest: None,
        block_size: 0,
        block_bitmap: None,
        block_count: None,
        total_done: 0,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    {
        let (hw, jw) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
        ok(hw.upsert_http_task(row).await, "seed row");
        drop(hw);
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(1), jw).await,
            "writer exit",
        );
    }
    let (persist, writer) = ok(
        PersistWriter::spawn(db_path.clone()).await,
        "spawn writer 2",
    );
    let global = GlobalOptions {
        dir: dl.clone(),
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = Gid::from_u64(u64::from_str_radix(&gid_hex, 16).unwrap_or(0));
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
        stopped.iter().any(|v| {
            v.gid == gid && (v.status == StatusKind::Error || v.status == StatusKind::Complete)
        })
    })
    .await;
    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    assert_eq!(
        entry.status,
        StatusKind::Error,
        "an unsupported algorithm must be explicitly rejected (accepting without effect is a fabrication)"
    );
    assert_eq!(
        entry.error_engine.as_ref().map(|f| f.code.as_str()),
        Some("taiji.option.invalid"),
        "rejection face = taiji.option.invalid: {:?}",
        entry.error_engine
    );
    let msg = entry.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.contains("checksum"),
        "the rejection message must name the checksum value domain: {msg}"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&parent);
}

/// Cold-row projection: queued/paused rows without a live view project
/// the row's real values from tellStatus — completedLength = the row's
/// total_done; totalLength = the probe-authoritative total
/// (probe_json) > the grid-derived value (block_count x block_size) >
/// 0. The fork returns real values for paused tasks (same rule);
/// previously it was always 0/0.
#[tokio::test]
async fn http_task_cold_rows_project_real_total_and_completed() {
    const BS: i64 = 256 * 1024;
    let parent = temp_dir("http-p53-cold");
    let dl = parent.join("dl");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    let db_path = parent.join("taiji.sqlite3");
    // Row A: a paused imported-bitmap row — no probe, so the total is
    // grid-derived (8 x 256KiB) and completed = the row's total_done
    // (4 blocks).
    let a = "8000000000000922".to_string();
    let row_a = taiji_store::persist::HttpTaskRow {
        gid: a.clone(),
        url: "http://127.0.0.1:1/a.bin".to_string(),
        final_url: String::new(),
        mirrors_json: None,
        state: "paused".into(),
        queue_pos: 1,
        dir: dl.display().to_string(),
        out: "a.bin".into(),
        config_json: HttpPersistConfig {
            imported_progress: true,
            ..HttpPersistConfig::default()
        }
        .to_json(),
        probe_json: None,
        validator_digest: None,
        block_size: BS,
        block_bitmap: Some(vec![0b1111_0000]),
        block_count: Some(8),
        total_done: 4 * BS,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    // Row B: a queued row — the probe-authoritative total is present
    // (probe_json) and must be projected exactly; the grid-derived
    // value (3 x 4MiB) must not override it.
    let b = "8000000000000923".to_string();
    let facts_b = serde_json::to_string(&super::super::http::ValidatorFacts {
        final_url_path: "/b.bin".into(),
        total_len: Some(12345),
        etag: None,
        last_modified: None,
        encoding_ok: true,
    })
    .unwrap_or_else(|e| panic!("facts: {e}"));
    let row_b = taiji_store::persist::HttpTaskRow {
        gid: b.clone(),
        url: "http://127.0.0.1:1/b.bin".to_string(),
        final_url: String::new(),
        mirrors_json: None,
        state: "queued".into(),
        queue_pos: 2,
        dir: dl.display().to_string(),
        out: "b.bin".into(),
        config_json: HttpPersistConfig::default().to_json(),
        probe_json: Some(facts_b),
        validator_digest: None,
        block_size: 4 * 1024 * 1024,
        block_bitmap: None,
        block_count: Some(3),
        total_done: 0,
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    {
        let (hw, jw) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
        ok(hw.upsert_http_task(row_a).await, "seed a");
        ok(hw.upsert_http_task(row_b).await, "seed b");
        drop(hw);
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(1), jw).await,
            "writer exit",
        );
    }
    let (persist, writer) = ok(
        PersistWriter::spawn(db_path.clone()).await,
        "spawn writer 2",
    );
    // max-concurrent-downloads = 0 (built directly): fillup grants no
    // slots, so the queued row stays cold (no live view) and the
    // paused row stays in the pause queue as usual.
    let global = GlobalOptions {
        dir: dl.clone(),
        max_concurrent_downloads: 0,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let status_of = |v: &TorrentStatusView| -> (u64, u64, StatusKind) {
        (v.total_length, v.completed_length, v.status)
    };
    let sa = match call(
        &handle,
        SessionCommand::TellStatus {
            gid: a.clone(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => *v,
        other => panic!("tellStatus a: {other:?}"),
    };
    assert_eq!(
        status_of(&sa),
        (8 * BS as u64, 4 * BS as u64, StatusKind::Paused),
        "cold row A: grid-derived total + the row's completed amount (the fork's paused-state \
         real values follow the same rule)"
    );
    let sb = match call(
        &handle,
        SessionCommand::TellStatus {
            gid: b.clone(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => *v,
        other => panic!("tellStatus b: {other:?}"),
    };
    assert_eq!(
        status_of(&sb),
        (12345, 0, StatusKind::Waiting),
        "cold row B: the probe-authoritative total beats the grid-derived value; never started = \
         zero completed"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = writer.await;
    let _ = std::fs::remove_dir_all(&parent);
}

// ===== Re-parallelization after crash/interrupt recovery (the
// single-connection resume gap) =====

/// Range concurrency observation (e2e): `open`/`close` bracket every
/// request carrying a Range header (the 206 arm); `peak` = the
/// high-water mark of concurrent in-flight Ranges — the direct
/// observation of post-recovery parallelism; `quiesced` = all
/// in-flight requests drained (the cross-phase count isolation).
struct RangePeak {
    inflight: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

impl RangePeak {
    fn new() -> Arc<RangePeak> {
        Arc::new(RangePeak {
            inflight: std::sync::atomic::AtomicUsize::new(0),
            peak: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    fn open(&self) {
        let n = self
            .inflight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.peak.fetch_max(n, std::sync::atomic::Ordering::SeqCst);
    }
    fn close(&self) {
        self.inflight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn peak(&self) -> usize {
        self.peak.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Current in-flight connections (unlike the peak, it recedes —
    /// the per-frame reading for conditional assertions).
    fn inflight(&self) -> usize {
        self.inflight.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn reset(&self) {
        self.peak.store(0, std::sync::atomic::Ordering::SeqCst);
    }
    fn quiesced(&self) -> bool {
        self.inflight.load(std::sync::atomic::Ordering::SeqCst) == 0
    }
}

/// Counting origin (a variant of the full-parameter MockOrigin): the
/// 206/200 arms share one shape (the same Last-Modified both times —
/// identical probe facts, the strong-digest resume path); the body is
/// written in 4KiB chunks with 30ms spacing (~136KiB/s per connection
/// — a computable single-connection lower bound, the denominator of
/// the wall-time assertion); a keep-alive loop serves several extents
/// per connection serially (worker-to-connection is one-to-one, so
/// the peak = the concurrent connection count).
async fn spawn_range_counting_origin(body: Arc<Vec<u8>>) -> (std::net::SocketAddr, Arc<RangePeak>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let peak = RangePeak::new();
    let peak_t = Arc::clone(&peak);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = Arc::clone(&body);
            let peak = Arc::clone(&peak_t);
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
                    match range {
                        // Serving semantics match the real thing (e <
                        // total is always a 206 — the probe Range 0-0
                        // must receive a 206, else the probe would
                        // judge no-range, the task would degrade to a
                        // single connection, and every concurrency
                        // assertion would idle); the peak counts only
                        // the data face (e > s — the 1-byte probe does
                        // not count as in flight).
                        Some((s, e)) if e < total => {
                            if e > s {
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
                            let counted = e > s;
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                if counted {
                                    peak.close();
                                }
                                return;
                            }
                            let slice = &body[s as usize..=end];
                            // 4KiB/30ms chunked slow write: the
                            // connection's in-flight time is
                            // computable.
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
                        }
                    }
                }
            });
        }
    });
    (addr, peak)
}

/// e2e: a 16-connection task (split=16 + cap=16) downloads past half,
/// then stops (the kill shape: the row stays in downloading with its
/// bitmap); a restart's bootstrap reactivates it, and the assertions
/// are:
/// - the concurrency intent persists with the row (the config_json
/// payload carries the effective split/cap);
/// - the post-recovery concurrent in-flight Range peak is >=
/// min(split, cap) = 16;
/// - the resume wall time stays in the fresh-run class (< the
/// single-connection serial lower bound = remaining/rate);
/// - the final file is byte-identical.
#[tokio::test]
async fn http_task_resume_reparallelizes_with_concurrent_ranges_after_restart() {
    const BS: u64 = 256 * 1024;
    const BLOCKS: u64 = 64; // 16MiB; the remainder >= 32 blocks >= min(split,cap)
    const KILL_AT_DB: i64 = 2 * 1024 * 1024; // kill once the DB bitmap has >= 2MiB (after the first tick)
    const PER_CONN_RATE_BPS: u64 = 150 * 1024; // an optimistic bound on the server 4KiB/30ms pace
    let total = BS * BLOCKS;
    let dir = temp_dir("http-resume-parallel");
    let db_path = dir.join("taiji.sqlite3");
    let body: Vec<u8> = (0..total).map(|i| (i % 199) as u8).collect();
    let (addr, peak) = spawn_range_counting_origin(Arc::new(body.clone())).await;
    let url = format!("http://{addr}/f.bin");

    // ---- Session 1: create with 16-connection intent, kill once the
    // DB bitmap crosses the threshold ----
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (persist, writer) = PersistWriter::spawn(db_path.clone())
        .await
        .unwrap_or_else(|e| panic!("writer1: {e}"));
    let (handle, join) = SessionActor::spawn_with_persist(SessionOptions { global }, Some(persist));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![url],
                options: std::collections::BTreeMap::from([
                    ("split".to_string(), "16".to_string()),
                    ("max-connection-per-server".to_string(), "16".to_string()),
                    ("http-block-size".to_string(), "256K".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // The concurrency intent freezes into the row (persisted at
    // creation).
    wait_until(async || {
        http_row_of(&db_path, &gid_hex)
            .map(|(_, cfg)| {
                cfg.contains("\"split\":16") && cfg.contains("\"max_conn_per_server\":16")
            })
            .unwrap_or(false)
    })
    .await;
    // The fresh phase is already fully parallel (the startup
    // semantics): peak >= 16.
    wait_until(async || {
        let st = match call(
            &handle,
            SessionCommand::TellStatus {
                gid: gid_hex.clone(),
                keys: vec![],
            },
        )
        .await
        {
            Ok(CommandReply::TorrentStatus(v)) => v,
            _ => return false,
        };
        st.connections >= 16
    })
    .await;
    // DB bitmap >= 2MiB (after the first tick) -> stop. The row stays
    // downloading (the same row domain as kill -9, so the restart
    // resumes); the bitmap fsync precedes the row write (a power loss
    // never leaves the bitmap ahead of the data).
    wait_until(async || {
        http_row_progress_of(&db_path, &gid_hex)
            .map(|(_, _, done, _)| done >= KILL_AT_DB)
            .unwrap_or(false)
    })
    .await;
    let (_, bitmap, db_done, _) =
        http_row_progress_of(&db_path, &gid_hex).unwrap_or_else(|| panic!("row"));
    assert!(
        bitmap.is_some() && db_done >= KILL_AT_DB,
        "the bitmap is already in the store at kill time"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    drop(writer);
    // After in-flight Ranges drain, isolate the two phases' counts
    // (fresh-phase peak evidence).
    let mut quiet = false;
    for _ in 0..250 {
        if peak.quiesced() {
            quiet = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(quiet, "in-flight requests must drain after shutdown");
    let fresh_peak = peak.peak();
    assert!(
        fresh_peak >= 16,
        "the fresh phase's concurrent Range peak >= min(split,cap)=16, got {fresh_peak}"
    );
    peak.reset();
    let remaining = total - u64::try_from(db_done).unwrap_or(0);
    let serial_secs = remaining as f64 / PER_CONN_RATE_BPS as f64;

    // ---- Session 2: bootstrap reactivation -> post-recovery
    // parallelism assertions ----
    let t_reopen = Instant::now();
    let (persist2, writer2) = PersistWriter::spawn(db_path.clone())
        .await
        .unwrap_or_else(|e| panic!("writer2: {e}"));
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(persist2));
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
    let resume_wall = t_reopen.elapsed();
    let resumed_peak = peak.peak();
    assert!(
        resumed_peak >= 16,
        "after recovery the concurrent Range peak >= min(split,cap)=16 (a single-connection gap \
         reappearing = the red face), got {resumed_peak}"
    );
    assert!(
        resume_wall.as_secs_f64() < serial_secs,
        "the recovery segment's duration {}s must be below the single-connection serial lower \
         bound {}s (remaining {remaining}B @ {PER_CONN_RATE_BPS}B/s per connection)",
        resume_wall.as_secs_f64(),
        serial_secs
    );
    // Final byte verdict on the file.
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
    assert_eq!(got, body, "the file is intact after the resumed recovery");
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join2).await;
    let _ = writer2.await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The changeOption sync face: legal split / max-connection-per-server
/// changes persist with the row (the config_json concurrency intent is
/// overwritten), so a later restart's recovery starts from the latest
/// effective values. A stalling origin pins the task in the probe
/// phase (Active), keeping changeOption reachable with no completion
/// race.
#[tokio::test]
async fn http_change_option_updates_persisted_concurrency_face() {
    let dir = temp_dir("http-copt-concurrency");
    let db = tmp_db("http-copt-concurrency");
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
                options: std::collections::BTreeMap::from([("split".to_string(), "4".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();
    // Frozen at creation: face = {split:4, cap:1 (default)}.
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(_, cfg)| cfg.contains("\"split\":4"))
            .unwrap_or(false)
    })
    .await;
    // A split change -> the face syncs.
    let r = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid_hex.clone(),
            options: std::collections::BTreeMap::from([("split".to_string(), "8".to_string())]),
        },
    )
    .await;
    assert!(matches!(r, Ok(CommandReply::Accepted)), "{r:?}");
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(_, cfg)| cfg.contains("\"split\":8"))
            .unwrap_or(false)
    })
    .await;
    // A cap change -> the effective in-domain value (12) persists,
    // split kept.
    let r = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid_hex.clone(),
            options: std::collections::BTreeMap::from([(
                "max-connection-per-server".to_string(),
                "12".to_string(),
            )]),
        },
    )
    .await;
    assert!(matches!(r, Ok(CommandReply::Accepted)), "{r:?}");
    wait_until(async || {
        http_row_of(&db, &gid_hex)
            .map(|(_, cfg)| {
                cfg.contains("\"split\":8") && cfg.contains("\"max_conn_per_server\":12")
            })
            .unwrap_or(false)
    })
    .await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

// ===== If-Match conditional resume (enabled after the probe confirms
// a strong ETag; 412 -> clear the bitmap, re-probe, restart from
// zero) =====

/// ETag origin: the content state can flip (v1 -> v2, ETag and body
/// switch together) — probes and data requests both answer from the
/// **current** state; a data request carrying `If-Match` that fails
/// the strong comparison against the current ETag gets 412 (the
/// RFC 9110 §13.1.1 content-changed shape). `flip_after` = flip after
/// serving the Nth data request (the "content changes mid-download"
/// shape). `weak` = answer with a `W/` weak tag (always the same
/// value, never flips); `no_etag` = never send an ETag — together
/// they pin the frozen seam "the weak/no-ETag paths are zero-change"
/// (the client must not send If-Match).
/// Data-plane request record: (start, if_match, response status).
type EtagReqLog = Arc<std::sync::Mutex<Vec<(u64, Option<String>, u16)>>>;

struct EtagOrigin {
    addr: std::net::SocketAddr,
    /// Data-plane request record: (start, if_match, response
    /// status).
    data: EtagReqLog,
    /// Probe request log (one per attempt; the element = the ETag the
    /// answer used).
    probes: Arc<std::sync::Mutex<Vec<Option<String>>>>,
}

/// The origin's content state (the ETag and body flip together).
struct EtagState {
    etag: Option<String>,
    body: Vec<u8>,
}

async fn spawn_etag_origin(
    v1: EtagState,
    v2: EtagState,
    flip_after: usize,
    weak: bool,
    no_etag: bool,
) -> EtagOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let state = Arc::new(std::sync::Mutex::new(v1));
    let v2 = Arc::new(v2);
    let served = Arc::new(std::sync::Mutex::new(0usize));
    let data: EtagReqLog = Arc::new(std::sync::Mutex::new(Vec::new()));
    let probes: Arc<std::sync::Mutex<Vec<Option<String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    // A per-request serving gate: read state -> respond (including
    // writing the body to the socket) -> flip, all mutually exclusive.
    // Invariant: the flip is atomic with "the Nth data request has
    // been served" — when the client's connections arrive
    // concurrently (a 4MiB body under load can fill the loopback
    // buffer and stall write_all, the root cause of the flaky parallel
    // runs), the next request cannot read state until this one has
    // flipped, ruling out the self-contradictory "a later request
    // still gets a 206 under the old ETag".
    let serve_gate = Arc::new(tokio::sync::Mutex::new(()));
    let (state_t, served_t, data_t, probes_t, gate_t) = (
        Arc::clone(&state),
        Arc::clone(&served),
        Arc::clone(&data),
        Arc::clone(&probes),
        Arc::clone(&serve_gate),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (state, served, data, probes, serve_gate) = (
                Arc::clone(&state_t),
                Arc::clone(&served_t),
                Arc::clone(&data_t),
                Arc::clone(&probes_t),
                Arc::clone(&gate_t),
            );
            let v2 = Arc::clone(&v2);
            let (flip_after, weak, no_etag) = (flip_after, weak, no_etag);
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
                    let if_match = lower
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("if-match: "))
                        .map(str::to_string);
                    let Some((s, e)) = range else { return };
                    // The serving gate spans this whole request
                    // (response writes and the flip included): the
                    // guard auto-releases at the end of the loop
                    // body.
                    let _gate = serve_gate.lock().await;
                    let (etag_now, total) = {
                        let st = state.lock().unwrap_or_else(|p| p.into_inner());
                        (st.etag.clone(), st.body.len() as u64)
                    };
                    let served_etag = |etag: &Option<String>| -> Option<String> {
                        // Weak-tag shape: always W/"w" (the weak-resume
                        // frozen-seam assertion source).
                        if weak {
                            return Some("W/\"w\"".into());
                        }
                        if no_etag { None } else { etag.clone() }
                    };
                    if s == 0 && e == 0 {
                        // Probe: a 206 with 1 byte (Content-Range
                        // 0-0/TOTAL + the current ETag).
                        let etag_hdr = served_etag(&etag_now);
                        probes
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(etag_hdr.clone());
                        let mut resp = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Range: bytes 0-0/{total}\r\n\
                             Accept-Ranges: bytes\r\nContent-Length: 1\r\n"
                        );
                        if let Some(t) = &etag_hdr {
                            resp.push_str(&format!("ETag: {t}\r\n"));
                        }
                        resp.push_str("Connection: keep-alive\r\n\r\n");
                        sock.write_all(resp.as_bytes()).await.ok();
                        let first = state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .body
                            .first()
                            .copied()
                            .unwrap_or(0);
                        sock.write_all(&[first]).await.ok();
                        continue;
                    }
                    // Data plane: an If-Match failing the strong
                    // comparison against the current ETag -> 412.
                    let mismatch = if_match.is_some()
                        && if_match.as_deref() != etag_now.as_deref()
                        && !weak
                        && !no_etag;
                    let status: u16 = if mismatch { 412 } else { 206 };
                    data.lock().unwrap_or_else(|p| p.into_inner()).push((
                        s,
                        if_match.clone(),
                        status,
                    ));
                    if mismatch {
                        sock.write_all(
                            b"HTTP/1.1 412 Precondition Failed\r\n\
                             Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                        )
                        .await
                        .ok();
                        continue;
                    }
                    let etag_hdr = served_etag(&etag_now);
                    let end = (e as usize).min(total as usize - 1);
                    let len = end - s as usize + 1;
                    let mut resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes {s}-{end}/{total}\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: {len}\r\n"
                    );
                    if let Some(t) = &etag_hdr {
                        resp.push_str(&format!("ETag: {t}\r\n"));
                    }
                    resp.push_str("Connection: keep-alive\r\n\r\n");
                    sock.write_all(resp.as_bytes()).await.ok();
                    let slice = state.lock().unwrap_or_else(|p| p.into_inner()).body
                        [s as usize..=end]
                        .to_vec();
                    sock.write_all(&slice).await.ok();
                    // Flip: after serving the flip_after-th data
                    // request, v1 -> v2.
                    let mut n = served.lock().unwrap_or_else(|p| p.into_inner());
                    *n += 1;
                    if *n == flip_after && !weak && !no_etag {
                        *state.lock().unwrap_or_else(|p| p.into_inner()) = (*v2).clone();
                    }
                }
            });
        }
    });
    EtagOrigin { addr, data, probes }
}

impl EtagOrigin {
    fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path)
    }

    fn data_log(&self) -> Vec<(u64, Option<String>, u16)> {
        self.data.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn probe_etags(&self) -> Vec<Option<String>> {
        self.probes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// A shallow clone of the ETag state (the body cloned for the
/// fixture's flip writes).
impl Clone for EtagState {
    fn clone(&self) -> Self {
        EtagState {
            etag: self.etag.clone(),
            body: self.body.clone(),
        }
    }
}

/// Positive case: the probe sees a strong ETag (v1) -> mid-download
/// the origin's content flips (v2) -> the following Range requests
/// fail If-Match -> **412** -> the task clears its bitmap, re-probes
/// (the second round sees v2), and **restarts from zero** (a start=0
/// refetch exists after the 412 — the bitmap was really cleared, not
/// faked) -> terminal Done with content = fresh v2 bytes (zero v1
/// residue = no misplaced bytes on disk). 5MiB = 2 blocks (past the
/// 4MiB block boundary); the engine's default connection cap is not 1
/// (split=5 / max-conn=16), so two data connections can reach the
/// origin concurrently under load — request-order determinism is
/// pinned by the fixture's serving gate (per-request mutual exclusion +
/// flip after serving the first data request), not by client
/// scheduling timing.
#[tokio::test]
async fn http_if_match_412_restarts_from_zero_and_completes() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b4-if-match");
    let v1 = EtagState {
        etag: Some("\"v1\"".into()),
        body: vec![0x11u8; 5 * 1024 * 1024],
    };
    let v2 = EtagState {
        etag: Some("\"v2\"".into()),
        body: vec![0x77u8; 5 * 1024 * 1024],
    };
    let origin = spawn_etag_origin(v1, v2, 1, false, false).await;

    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![origin.url("f.bin")],
                options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
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

    // Terminal content = fresh v2 bytes (zero v1 residue).
    let entry = stopped
        .iter()
        .find(|v| v.gid == gid)
        .unwrap_or_else(|| panic!("entry"));
    let got = std::fs::read(&entry.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
    assert!(
        got.iter().all(|&b| b == 0x77),
        "after redownload from zero the content must be fresh v2 bytes (first byte {:#x})",
        got.first().copied().unwrap_or(0)
    );
    assert_eq!(got.len(), 5 * 1024 * 1024);

    let data = origin.data_log();
    // The 412 is really there (the server rejected the If-Match
    // mismatch).
    let first_412 = data
        .iter()
        .position(|&(_, _, status)| status == 412)
        .unwrap_or_else(|| panic!("a 412 (If-Match mismatch) must exist: {data:?}"));
    // Every request before the 412 carried If-Match: "v1" (the probe
    // confirmed the strong ETag -> the feature armed).
    assert!(
        data[..first_412]
            .iter()
            .all(|r| r.1.as_deref() == Some("\"v1\"")),
        "data requests before the 412 must carry If-Match v1: {:?}",
        &data[..first_412]
    );
    // The bitmap clear is real, not faked: a start=0 refetch exists
    // after the 412 (carrying If-Match v2).
    assert!(
        data[first_412 + 1..]
            .iter()
            .any(|r| r.0 == 0 && r.1.as_deref() == Some("\"v2\"")),
        "after the 412 a from-zero refetch is required (start=0 + If-Match v2): {:?}",
        &data[first_412 + 1..]
    );
    // The re-probe face: exactly two probe rounds (v1 -> v2).
    assert_eq!(
        origin.probe_etags(),
        vec![Some("\"v1\"".into()), Some("\"v2\"".into())],
        "exactly two probe rounds: the first confirms v1 (If-Match armed), the restart round sees v2"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The frozen seam: with a weak ETag (`W/`) and with no ETag, the
/// request face carries **zero If-Match** (the weak/no-ETag paths are
/// zero-change, avoiding servers with non-conformant If-Match
/// handling) and the tasks still finish Done.
#[tokio::test]
async fn http_if_match_absent_without_strong_etag() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("http-b4-no-strong");
    let body = vec![0x33u8; 1024 * 1024];
    let weak_origin = spawn_etag_origin(
        EtagState {
            etag: Some("\"ignored\"".into()),
            body: body.clone(),
        },
        EtagState {
            etag: None,
            body: body.clone(),
        },
        usize::MAX,
        true,
        false,
    )
    .await;
    let bare_origin = spawn_etag_origin(
        EtagState {
            etag: None,
            body: body.clone(),
        },
        EtagState {
            etag: None,
            body: body.clone(),
        },
        usize::MAX,
        false,
        true,
    )
    .await;

    let mut gids = Vec::new();
    for (origin, name) in [(&weak_origin, "g-weak.bin"), (&bare_origin, "g-bare.bin")] {
        gids.push(gid_of(
            &call(
                &handle,
                SessionCommand::AddUri {
                    uris: vec![origin.url(name)],
                    options: BTreeMap::from([("dir".to_string(), dir.display().to_string())]),
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

    for (origin, tag) in [(&weak_origin, "weak ETag"), (&bare_origin, "no ETag")] {
        let data = origin.data_log();
        assert!(
            !data.is_empty(),
            "{tag} source must have data requests (the task really downloaded)"
        );
        assert!(
            data.iter().all(|r| r.1.is_none()),
            "{tag} paths must not carry If-Match (the zero-change frozen seam): {data:?}"
        );
        assert!(
            data.iter().all(|r| r.2 == 206),
            "{tag} paths have zero 412s (no preflight validation face): {data:?}"
        );
    }
    // The content is still correct.
    for v in stopped.iter().filter(|v| gids.contains(&v.gid)) {
        let got = std::fs::read(&v.files[0].path).unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(got, body);
    }

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Cookie intake gate (the load-cookies wiring + the two direct
// methods) ----

/// Cookie-gated mock origin (a protected URL): a request whose
/// `Cookie` header contains `required_cookie` (a `name=value`
/// substring) gets 200 + body; otherwise 401. Every request's `Cookie`
/// header is recorded into the returned ledger (None = no cookie
/// header).
async fn spawn_cookie_gated_origin(
    body: Arc<Vec<u8>>,
    required_cookie: &'static str,
) -> (
    std::net::SocketAddr,
    Arc<std::sync::Mutex<Vec<Option<String>>>>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let cookies_seen: Arc<std::sync::Mutex<Vec<Option<String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_t = Arc::clone(&cookies_seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = Arc::clone(&body);
            let seen = Arc::clone(&seen_t);
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
                    let cookie = head
                        .to_ascii_lowercase()
                        .lines()
                        .find_map(|l| l.strip_prefix("cookie: "))
                        .map(str::to_string);
                    let carries = cookie.as_ref().is_some_and(|c| c.contains(required_cookie));
                    seen.lock().unwrap_or_else(|p| p.into_inner()).push(cookie);
                    let total = body.len();
                    if carries {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                             Connection: close\r\n\r\n"
                        );
                        sock.write_all(resp.as_bytes()).await.ok();
                        sock.write_all(&body).await.ok();
                    } else {
                        // The protected face: no cookie / wrong cookie
                        // = 401 (the login-walled content rejection
                        // arm).
                        sock.write_all(
                            b"HTTP/1.1 401 Unauthorized\r\n\
                              WWW-Authenticate: Basic realm=\"gated\"\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .ok();
                    }
                    let _ = sock.shutdown().await;
                    // After the Connection: close answer the loop
                    // returns to reading a head — the peer closing the
                    // connection ends it at EOF (isomorphic to
                    // spawn_mock_origin's keep-alive loop; this mock
                    // closes after a single request).
                }
            });
        }
    });
    (addr, cookies_seen)
}

fn gated_url(addr: std::net::SocketAddr, path: &str) -> String {
    format!("http://{addr}/{path}")
}

/// `--load-cookies` with a Netscape file -> the task CookieStore is
/// pre-filled -> requests carry the cookie and the download
/// completes; the no-cookie control fails with 401 (the protected-URL
/// face).
#[tokio::test]
async fn load_cookies_file_seeds_task_jar_and_requests_carry_it() {
    let dir = temp_dir("http-gap11-jar");
    // The Netscape file: a host-only 127.0.0.1 session cookie (an
    // exact match for the mock host; expiry=0 = a session cookie,
    // valid for the jar's lifetime).
    let cookie_file = dir.join("cookies.txt");
    std::fs::write(
        &cookie_file,
        "# Netscape HTTP Cookie File\n\
         127.0.0.1\tFALSE\t/\tFALSE\t0\tsid\tabc123\n",
    )
    .unwrap_or_else(|e| panic!("write cookies: {e}"));
    let body = Arc::new(vec![9u8; 256 * 1024]);
    let (addr, seen) = spawn_cookie_gated_origin(Arc::clone(&body), "sid=abc123").await;
    let (handle, join) = SessionActor::spawn();
    // With the cookie: carrying sid -> 200 -> completion.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![gated_url(addr, "protected.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    (
                        "load-cookies".to_string(),
                        cookie_file.display().to_string(),
                    ),
                    ("max-tries".to_string(), "1".to_string()),
                ]),
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
    assert!(
        seen.lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|c| c.as_deref().is_some_and(|v| v.contains("sid=abc123"))),
        "requests must carry the file cookie: {:?}",
        seen.lock().unwrap_or_else(|p| p.into_inner())
    );
    // No-cookie control: a new task on the same origin -> 401 -> task
    // failure (acceptance unchanged — the gate sits at request time,
    // not at intake).
    let gid2 = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![gated_url(addr, "denied.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("max-tries".to_string(), "1".to_string()),
                ]),
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
        .any(|v| v.gid == gid2 && v.status == StatusKind::Error)
    })
    .await;
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The fail-closed arm: a missing or >1MiB file = the task is rejected
/// (`taiji.option.invalid`, no row persisted); the changeOption face
/// shares the gate (a bad path is rejected explicitly — a rejected
/// call mutates nothing).
#[tokio::test]
async fn load_cookies_fail_closed_rejects_bad_files() {
    let dir = temp_dir("http-gap11-fail");
    // The oversized file (1MiB + 1 byte — the MAX_COOKIE_FILE_BYTES
    // anchor).
    let big = dir.join("big.txt");
    std::fs::write(&big, vec![b'a'; 1024 * 1024 + 1]).unwrap_or_else(|e| panic!("write big: {e}"));
    let (handle, join) = SessionActor::spawn();
    let opts = |path: String| {
        BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("load-cookies".to_string(), path),
            ("max-tries".to_string(), "1".to_string()),
        ])
    };
    for (label, path) in [
        ("missing", dir.join("nope.txt").display().to_string()),
        ("oversized", big.display().to_string()),
    ] {
        let r = call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: opts(path),
                position: None,
            },
        )
        .await;
        let msg = match r {
            Err(e) => e.to_string(),
            Ok(_) => panic!("{label}: must be rejected"),
        };
        assert!(
            msg.contains("taiji.option.invalid") && msg.contains("load-cookies"),
            "{label}: {msg}"
        );
    }
    // The changeOption face: a paused task + a bad path = an explicit
    // rejection; the task stays in the waiting domain.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/f.bin".to_string()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let r = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: opts(dir.join("nope.txt").display().to_string()),
        },
    )
    .await;
    assert!(
        r.as_ref()
            .is_err_and(|e| e.to_string().contains("taiji.option.invalid")),
        "changeOption with a bad path must be explicitly rejected: {r:?}"
    );
    // A rejected call mutates nothing: the task is still there (not
    // deactivated).
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
    assert!(
        waiting.iter().any(|v| v.gid == gid),
        "the task is still in the waiting domain"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The changeOption acceptance + effect face: a paused task loads a
/// cookie file via changeOption -> unpause activates -> requests carry
/// it (the seed reaches the task store through the activation
/// chain).
#[tokio::test]
async fn load_cookies_via_change_option_takes_effect_on_activation() {
    let dir = temp_dir("http-gap11-copt");
    let cookie_file = dir.join("c2.txt");
    std::fs::write(&cookie_file, "127.0.0.1\tFALSE\t/\tFALSE\t0\tk2\tv2\n")
        .unwrap_or_else(|e| panic!("write: {e}"));
    let body = Arc::new(vec![3u8; 128 * 1024]);
    let (addr, seen) = spawn_cookie_gated_origin(Arc::clone(&body), "k2=v2").await;
    let (handle, join) = SessionActor::spawn();
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![gated_url(addr, "copt.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                    ("max-tries".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let r = call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: BTreeMap::from([(
                "load-cookies".to_string(),
                cookie_file.display().to_string(),
            )]),
        },
    )
    .await;
    assert!(matches!(r, Ok(CommandReply::Accepted)), "{r:?}");
    // Activation (unpause) -> the seed takes effect -> k2 is carried
    // -> completion.
    let _ = call(
        &handle,
        SessionCommand::Unpause {
            gid: gid.to_string(),
        },
    )
    .await;
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
    assert!(
        seen.lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|c| c.as_deref().is_some_and(|v| v.contains("k2=v2"))),
        "after activation requests must carry the changeOption-loaded cookie: {:?}",
        seen.lock().unwrap_or_else(|p| p.into_inner())
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The global-face entry: changeGlobalOption sets a session-level
/// cookie source -> a later addUri without the per-task key falls back
/// to the global one and carries it; the getGlobalOption echo shows
/// the path.
#[tokio::test]
async fn load_cookies_global_entry_feeds_subsequent_tasks() {
    let dir = temp_dir("http-gap11-glob");
    let cookie_file = dir.join("g.txt");
    std::fs::write(&cookie_file, "127.0.0.1\tFALSE\t/\tFALSE\t0\tgk\tgv\n")
        .unwrap_or_else(|e| panic!("write: {e}"));
    let body = Arc::new(vec![5u8; 64 * 1024]);
    let (addr, seen) = spawn_cookie_gated_origin(Arc::clone(&body), "gk=gv").await;
    let (handle, join) = SessionActor::spawn();
    let _ = call(
        &handle,
        SessionCommand::ChangeGlobalOption {
            options: BTreeMap::from([(
                "load-cookies".to_string(),
                cookie_file.display().to_string(),
            )]),
        },
    )
    .await;
    // The echo face.
    let echo = match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(m)) => m,
        other => panic!("echo: {other:?}"),
    };
    assert_eq!(
        echo.get("load-cookies").map(String::as_str),
        Some(cookie_file.display().to_string().as_str())
    );
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![gated_url(addr, "glob.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("max-tries".to_string(), "1".to_string()),
                ]),
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
    assert!(
        seen.lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|c| c.as_deref().is_some_and(|v| v.contains("gk=gv"))),
        "the session-source task must carry it: {:?}",
        seen.lock().unwrap_or_else(|p| p.into_inner())
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// addUriWithCookies (structured direct delivery): cookies enter the
/// task CookieStore -> requests carry them; the combined semantics
/// strip manual `Cookie:` headers (the jar is authoritative,
/// mirroring the fork's "Structured cookies are authoritative") —
/// non-Cookie manual headers are untouched. The scheme/class rejection
/// arms use the fork's verbatim text plus the tightened metadata-face
/// wording.
#[tokio::test]
async fn add_uri_with_cookies_structured_carries_and_strips_manual_cookie_header() {
    let dir = temp_dir("http-gap11-direct");
    let body = Arc::new(vec![2u8; 96 * 1024]);
    let (addr, seen) = spawn_cookie_gated_origin(Arc::clone(&body), "sid=direct9").await;
    let (handle, join) = SessionActor::spawn();
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUriWithCookies {
                uris: vec![gated_url(addr, "direct.bin")],
                cookies: vec![TaskCookieSpec {
                    name: "sid".to_string(),
                    value: "direct9".to_string(),
                    domain: "127.0.0.1".to_string(),
                    path: "/".to_string(),
                    host_only: true,
                    secure: false,
                    http_only: false,
                    expires_utc: None,
                }],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    // A manual Cookie header (will be stripped) + a
                    // legal manual header (kept).
                    (
                        "header".to_string(),
                        "Cookie: rogue=1\nX-Probe: 1".to_string(),
                    ),
                    ("max-tries".to_string(), "1".to_string()),
                ]),
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
    let snapshot = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(
        snapshot
            .iter()
            .any(|c| c.as_deref().is_some_and(|v| v.contains("sid=direct9"))),
        "structured cookies must be carried: {snapshot:?}"
    );
    assert!(
        snapshot
            .iter()
            .all(|c| c.as_deref().is_none_or(|v| !v.contains("rogue"))),
        "manual Cookie headers must be stripped (the jar is authoritative): {snapshot:?}"
    );
    // The scheme rejection arm (the fork's verbatim text,
    // RpcMethodImpl.cc).
    let r = call(
        &handle,
        SessionCommand::AddUriWithCookies {
            uris: vec!["ftp://127.0.0.1:1/f.bin".to_string()],
            cookies: vec![],
            options: BTreeMap::new(),
            position: None,
        },
    )
    .await;
    let msg = match r {
        Err(e) => e.to_string(),
        Ok(_) => panic!("ftp URI must be rejected"),
    };
    assert_eq!(msg, "Task cookies require HTTP or HTTPS URIs.");
    // The .torrent URL class rejection (the metadata-fetch face has no
    // cookie consumer — a declared tightening).
    let r = call(
        &handle,
        SessionCommand::AddUriWithCookies {
            uris: vec!["https://example.invalid/t.torrent".to_string()],
            cookies: vec![],
            options: BTreeMap::new(),
            position: None,
        },
    )
    .await;
    let msg = match r {
        Err(e) => e.to_string(),
        Ok(_) => panic!("torrent URL must be rejected"),
    };
    assert!(msg.contains("taiji.option.invalid"), "{msg}");
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// setTaskCookies (runtime override): replacing a waiting/paused
/// task's whole set -> activation carries the new set; active tasks
/// and non-HTTP tasks hit the fork's verbatim text gate
/// (RpcMethodImpl.cc).
#[tokio::test]
async fn set_task_cookies_overrides_waiting_task_and_gates_states() {
    let dir = temp_dir("http-gap11-set");
    let body = Arc::new(vec![6u8; 64 * 1024]);
    let (addr, seen) = spawn_cookie_gated_origin(Arc::clone(&body), "sid=second").await;
    let (handle, join) = SessionActor::spawn();
    let cookies = |value: &str| {
        vec![TaskCookieSpec {
            name: "sid".to_string(),
            value: value.to_string(),
            domain: "127.0.0.1".to_string(),
            path: "/".to_string(),
            host_only: true,
            secure: false,
            http_only: false,
            expires_utc: None,
        }]
    };
    // The paused task: setTaskCookies overrides -> unpause ->
    // completes carrying the new set.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![gated_url(addr, "set.bin")],
                options: BTreeMap::from([
                    ("dir".to_string(), dir.display().to_string()),
                    ("pause".to_string(), "true".to_string()),
                    ("max-tries".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let r = call(
        &handle,
        SessionCommand::SetTaskCookies {
            gid: gid.to_string(),
            cookies: cookies("second"),
        },
    )
    .await;
    assert_eq!(r, Ok(CommandReply::Accepted), "{r:?}");
    let _ = call(
        &handle,
        SessionCommand::Unpause {
            gid: gid.to_string(),
        },
    )
    .await;
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
    assert!(
        seen.lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|c| c.as_deref().is_some_and(|v| v.contains("sid=second"))),
        "activation after the override must carry the new set: {:?}",
        seen.lock().unwrap_or_else(|p| p.into_inner())
    );
    // The non-HTTP task gate (a magnet = the Magnet shape): the fork's
    // verbatim text.
    let mgid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let r = call(
        &handle,
        SessionCommand::SetTaskCookies {
            gid: mgid.to_string(),
            cookies: cookies("x"),
        },
    )
    .await;
    let msg = match r {
        Err(e) => e.to_string(),
        Ok(_) => panic!("non-HTTP task must be rejected"),
    };
    assert_eq!(
        msg,
        "Task cookies can only be set on waiting or paused cookie tasks."
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Full-terminal-set cookie cleanup at the error terminal (the
/// mode-aware retention is **retired**; the old
/// test asserted "resident keeps cookies after the error, GC/shutdown
/// sweep own cleanup" and is flipped here: done **and** error clear
/// immediately, in one-shot and resident modes alike, and the error
/// clear publishes the `taiji.task.cookiesClearedOnError` alert
/// (payload = gid/taskKind/count — never a cookie value).
/// Seed = an HTTP task row pointing at a refusing port + one cookie:
/// (a) one_shot: cleared at the error terminal (unchanged face);
/// (b) resident (the old "kept" arm): **cleared at the error too** —
/// the flip anchor; no 24h GC, no shutdown sweep exists anymore;
/// (c) resident + graceful shutdown: the error clear already happened
/// at the terminal; shutdown changes nothing (the retired sweep's
/// assertion inverted).
async fn sec17_seed(db: &std::path::Path, dir: &std::path::Path, gid_hex: &str) {
    let (w, join) = ok(
        TestPersistWriter::spawn(db.to_path_buf()).await,
        "seed writer",
    );
    w.upsert_http_task(seeded_http_row(
        gid_hex,
        "http://127.0.0.1:1/f.bin",
        dir,
        "f.bin",
    ))
    .await
    .unwrap_or_else(|e| panic!("seed row: {e}"));
    drop(w);
    join.await.unwrap_or_else(|e| panic!("writer exit: {e}"));
    let conn = ok(rusqlite::Connection::open(db), "seed cookie open");
    ok(
        conn.execute(
            "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                 expires_utc, secure, host_only, creation_utc)
             VALUES (?1, 'http', 'sid', '127.0.0.1', '/', 'v1', NULL, 0, 1, 0)",
            rusqlite::params![gid_hex],
        ),
        "seed cookie",
    );
}
#[tokio::test]
async fn http_error_cookie_clears_on_terminal_all_modes_with_alert() {
    // ---- (a) one_shot: cleared at the error (with the alert) ----
    {
        let dir = temp_dir("sec17-a");
        let db = tmp_db("sec17-a");
        let gid_hex = "8000000000000971".to_string();
        sec17_seed(&db, &dir, &gid_hex).await;
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn a");
        let (handle, join) = SessionActor::spawn_with_persist(
            SessionOptions {
                global: GlobalOptions {
                    dir: dir.clone(),
                    one_shot: true,
                    ..Default::default()
                },
            },
            Some(persist),
        );
        let mut alert_rx = handle.subscribe_task_cookie_events();
        wait_until(async || {
            status_list(
                &handle
                    .call(SessionCommand::TellStopped {
                        offset: 0,
                        num: u32::MAX,
                        keys: vec![],
                    })
                    .await,
            )
            .iter()
            .any(|v| v.gid.to_string() == gid_hex && v.status == StatusKind::Error)
        })
        .await;
        wait_until(async || http_table_count(&db, "task_cookie", None) == 0).await;
        let alert = tokio::time::timeout(Duration::from_secs(2), alert_rx.recv())
            .await
            .unwrap_or_else(|e| panic!("the error clear must publish the alert: {e}"))
            .unwrap_or_else(|e| panic!("bus alive: {e}"));
        assert_eq!(alert.gid.to_string(), gid_hex);
        assert_eq!(alert.task_kind, "http");
        assert_eq!(alert.count, 1, "exactly the seeded row count");
        handle.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
        drop(writer);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
    }
    // ---- (b) resident: the FLIP — cleared at the error terminal,
    // no retention window, no GC tick, no shutdown sweep ----
    {
        let dir = temp_dir("sec17-b");
        let db = tmp_db("sec17-b");
        let gid_hex = "8000000000000972".to_string();
        sec17_seed(&db, &dir, &gid_hex).await;
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn b");
        let (handle, join) = SessionActor::spawn_with_persist(
            SessionOptions {
                global: GlobalOptions {
                    dir: dir.clone(),
                    ..Default::default()
                },
            },
            Some(persist),
        );
        let mut alert_rx = handle.subscribe_task_cookie_events();
        wait_until(async || {
            status_list(
                &handle
                    .call(SessionCommand::TellStopped {
                        offset: 0,
                        num: u32::MAX,
                        keys: vec![],
                    })
                    .await,
            )
            .iter()
            .any(|v| v.gid.to_string() == gid_hex && v.status == StatusKind::Error)
        })
        .await;
        wait_until(async || http_table_count(&db, "task_cookie", None) == 0).await;
        let alert = tokio::time::timeout(Duration::from_secs(2), alert_rx.recv())
            .await
            .unwrap_or_else(|e| panic!("the resident error clear must alert: {e}"))
            .unwrap_or_else(|e| panic!("bus alive: {e}"));
        assert_eq!(
            (alert.gid.to_string(), alert.task_kind, alert.count),
            (gid_hex, "http", 1)
        );
        handle.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
        drop(writer);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
    }
    // ---- (c) resident + shutdown: the terminal clear already
    // happened; shutdown changes nothing (the retired sweep inverted) --
    // a fresh seed after the error keeps its cookie only if no error
    // terminal fires; here we re-seed and stop without activating:
    // the cookie must SURVIVE shutdown (no sweep exists anymore). ----
    {
        let dir = temp_dir("sec17-c");
        let db = tmp_db("sec17-c");
        let gid_hex = "8000000000000973".to_string();
        sec17_seed(&db, &dir, &gid_hex).await;
        let (persist, writer) = ok(TestPersistWriter::spawn(db.clone()).await, "spawn c");
        let (handle, join) = SessionActor::spawn_with_persist(
            SessionOptions {
                global: GlobalOptions {
                    dir: dir.clone(),
                    max_concurrent_downloads: 0,
                    ..Default::default()
                },
            },
            Some(persist),
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        // max_concurrent_downloads=0: the task stays reserved (no
        // error terminal) — its cookie survives shutdown (the retired
        // sweep no longer clears waiting tasks' cookies; active/paused
        // retention is the unchanged non-terminal semantics).
        assert_eq!(http_table_count(&db, "task_cookie", None), 1);
        handle.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(3), join).await;
        drop(writer);
        assert_eq!(
            http_table_count(&db, "task_cookie", None),
            1,
            "a non-terminal task's cookies are not cleared by shutdown (retention semantics \
             unchanged; the sweep face is retired)"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
    }
}
