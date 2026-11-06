//! Acceptance e2e: the unified `task_cookie` face across the
//! media family (the structured-cookie design) — driven through the SessionActor's
//! addMedia/setTaskCookies faces against a mock HLS source (the
//! established mock fixture kit, the media_task_e2e semantics), asserting:
//!
//! * addMedia's structured direct pass lands in the unified table at
//! creation (task_kind=media), rides every fetch (the mock records
//! the Cookie header), and the **full terminal set clears** — done
//! leaves zero rows (`add_media_cookie_direct_pass_*`);
//! * the error terminal clears too **and publishes the
//! `taiji.task.cookiesClearedOnError` alert** (payload =
//! gid/taskKind/count; the cookie value never appears in the event —
//! the redact discipline) (`media_error_terminal_clears_*`);
//! * restart replay: a paused-mid-download media task's cookies
//! survive the restart (the activation seed reads the unified table
//! back — on the pre-fix tree the in-memory set died with the
//! session) (`media_cookie_restart_replay_after_pause`);
//! * setTaskCookies accepts waiting/paused **media** tasks (the
//! flipped gate; active tasks and BT tasks still answer the fork's
//! verbatim gate text) (`set_task_cookies_media_gates`);
//! * remove pairs the cookie clear (`media_remove_pairs_*`);
//! * the startup GC sweeps injected crash-window residue (orphans +
//! terminal residue) and re-emits the alert for error-form rows,
//! never touching active rows, idempotently
//! (`startup_gc_sweeps_injected_residue_and_alerts`).
//!
//! Native-only synthesis path (fMP4 fixture); the SSRF lab runs
//! allow-private (the loopback mock).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionOptions, StatusKind,
    TaskCookieEvent, TaskCookieSpec,
};
use taiji_media::testkit::{FixtureSample, avcc_sample, build_init, build_segment};

// ---------------------------------------------------------------------------
// mock source (video+audio fMP4 fixture; every request's Cookie header
// lands in the shared log)
// ---------------------------------------------------------------------------

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

/// One recorded request: (path, the Cookie header value or None).
type CookieLog = Arc<Mutex<Vec<(String, Option<String>)>>>;

fn cookie_of(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn build_media_fixture(
    addr: &SocketAddr,
    video_segments: usize,
) -> (String, String, Vec<Vec<u8>>, Vec<u8>) {
    let video_spec = taiji_media::testkit::video_init_spec();
    let video_init = build_init(&video_spec);
    let mut segments = Vec::new();
    let mut decode_time = 0u64;
    for seq in 0..video_segments as u32 {
        let samples: Vec<FixtureSample> = (0..3)
            .map(|i| FixtureSample {
                duration: 33,
                size: 512,
                sync: i == 0,
                cts: 0,
            })
            .collect();
        let payload: Vec<u8> = samples
            .iter()
            .enumerate()
            .flat_map(|(i, s)| avcc_sample(i == 0, s.size as usize).into_iter())
            .collect();
        segments.push(build_segment(1, seq, decode_time, &samples, &payload));
        decode_time += 99;
    }
    let mut video = String::from("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n");
    video.push_str("#EXT-X-MEDIA-SEQUENCE:10\n");
    video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/vinit.mp4\"\n"));
    for i in 0..video_segments {
        video.push_str(&format!("#EXTINF:0.099,\nhttp://{addr}/vseg{i}.m4s\n"));
    }
    video.push_str("#EXT-X-ENDLIST\n");
    let master = format!(
        "#EXTM3U\n\
         #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,CODECS=\"avc1.64001f\"\n\
         http://{addr}/v.m3u8\n"
    );
    (master, video, segments, video_init)
}

/// The mock source (the media_task_e2e per-index route shape): every
/// request's Cookie header lands in the shared log; `delay_ms` stalls
/// each segment (the pause seam), `fail_seg` 500s one video segment
/// permanently (the error seam).
async fn spawn_cookie_source(
    video_segments: usize,
    delay_ms: u64,
    fail_seg: Option<usize>,
) -> (SocketAddr, CookieLog) {
    let log: CookieLog = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let (master, video, segs, vinit) = build_media_fixture(&addr, video_segments);
    let log_master = Arc::clone(&log2);
    let log_variant = Arc::clone(&log2);
    let log_init = Arc::clone(&log2);
    let routes = Router::new()
        .route(
            "/master.m3u8",
            get(move |headers: axum::http::HeaderMap| {
                let log = Arc::clone(&log_master);
                let body = master.clone();
                async move {
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(("master".into(), cookie_of(&headers)));
                    full_body(body.into_bytes(), "application/vnd.apple.mpegurl")
                }
            }),
        )
        .route(
            "/v.m3u8",
            get(move |headers: axum::http::HeaderMap| {
                let log = Arc::clone(&log_variant);
                let body = video.clone();
                async move {
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(("variant".into(), cookie_of(&headers)));
                    full_body(body.into_bytes(), "application/vnd.apple.mpegurl")
                }
            }),
        )
        .route(
            "/vinit.mp4",
            get(move |headers: axum::http::HeaderMap| {
                let log = Arc::clone(&log_init);
                let body = vinit.clone();
                async move {
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(("vinit".into(), cookie_of(&headers)));
                    full_body(body, "video/mp4")
                }
            }),
        );
    let mut with_seg = routes;
    for (i, seg) in segs.iter().enumerate() {
        let seg = seg.clone();
        let log = Arc::clone(&log2);
        let delay = delay_ms;
        let failing = fail_seg == Some(i);
        with_seg = with_seg.route(
            &format!("/vseg{i}.m4s"),
            get(move |headers: axum::http::HeaderMap| {
                let log = Arc::clone(&log);
                let seg = seg.clone();
                async move {
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push((format!("vseg{i}"), cookie_of(&headers)));
                    if failing {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
                    }
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    full_body(seg, "video/mp4")
                }
            }),
        );
    }
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, with_seg).await {
            panic!("serve: {e}");
        }
    });
    (addr, log)
}

// ---------------------------------------------------------------------------
// harness (the media_task_e2e shape)
// ---------------------------------------------------------------------------

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("media-cookie-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

async fn session_at(
    db: &std::path::Path,
    dir: &std::path::Path,
) -> taiji_core::session::SessionHandle {
    let (persist, _join) =
        taiji_store::persist::writer::PersistWriter::spawn(db.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let options = SessionOptions {
        global: GlobalOptions {
            dir: dir.to_path_buf(),
            one_shot: true,
            media_allow_private_key_url: true,
            ..Default::default()
        },
    };
    let (session, _actor) = SessionActor::spawn_with_persist(options, Some(persist));
    session
}

fn media_options(dir: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([
        ("dir".to_string(), dir.display().to_string()),
        (
            "media-allow-private-key-url".to_string(),
            "true".to_string(),
        ),
    ])
}

fn spec(name: &str, value: &str) -> Vec<TaskCookieSpec> {
    vec![TaskCookieSpec {
        name: name.to_string(),
        value: value.to_string(),
        domain: "127.0.0.1".to_string(),
        path: "/".to_string(),
        host_only: true,
        secure: false,
        http_only: false,
        expires_utc: None,
    }]
}

fn cookie_rows(db: &std::path::Path, gid: &str) -> i64 {
    let conn = rusqlite::Connection::open(db.join("taiji.sqlite3"))
        .unwrap_or_else(|e| panic!("open: {e}"));
    conn.query_row(
        "SELECT COUNT(*) FROM task_cookie WHERE gid = ?1",
        [gid],
        |r| r.get(0),
    )
    .unwrap_or_else(|e| panic!("count: {e}"))
}

fn cookie_rows_all(db: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open(db.join("taiji.sqlite3"))
        .unwrap_or_else(|e| panic!("open: {e}"));
    conn.query_row("SELECT COUNT(*) FROM task_cookie", [], |r| r.get(0))
        .unwrap_or_else(|e| panic!("count: {e}"))
}

async fn wait_terminal(
    session: &taiji_core::session::SessionHandle,
    gid: &str,
) -> (StatusKind, Option<String>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let st = tokio::time::timeout_at(
            deadline,
            session.call(SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: Vec::new(),
            }),
        )
        .await
        .unwrap_or_else(|e| panic!("terminal wait timeout: {e}"));
        if let Ok(CommandReply::TorrentStatus(view)) = st {
            match view.status {
                StatusKind::Complete => return (StatusKind::Complete, None),
                StatusKind::Error => return (StatusKind::Error, view.error_message.clone()),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn kill_session(session: &taiji_core::session::SessionHandle) {
    let _ = tokio::time::timeout(Duration::from_secs(5), session.shutdown()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
}

fn cookie_bearing_hits(log: &CookieLog) -> usize {
    log.lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter(|(_, c)| c.is_some())
        .count()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// addMedia's structured direct pass (acceptance ⑤): the cookie lands in the
/// unified table at creation, rides every fetch (the mock's Cookie
/// header log), and Done — the full terminal set — clears the rows.
#[tokio::test]
async fn add_media_cookie_direct_pass_persists_and_clears_on_done() {
    let (addr, log) = spawn_cookie_source(4, 0, None).await;
    let dir = tempdir("direct");
    let session = session_at(&dir, &dir).await;
    let gid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{addr}/master.m3u8"),
            options: media_options(&dir),
            cookies: spec("sid", "media-direct-v1"),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    };
    // Creation-time landing: the row exists before any activation
    // (the task may still be waiting).
    assert_eq!(
        cookie_rows(&dir, &gid),
        1,
        "addMedia persisted: the row lands in the unified table at creation \
         (task_kind=media)"
    );
    {
        // The persisted kind is the media label.
        let conn = rusqlite::Connection::open(dir.join("taiji.sqlite3"))
            .unwrap_or_else(|e| panic!("open: {e}"));
        let kind: String = conn
            .query_row(
                "SELECT task_kind FROM task_cookie WHERE gid = ?1",
                [&gid],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("kind: {e}"));
        assert_eq!(kind, "media");
    }
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Complete, "{err:?}");
    // Transport consumption: the mock saw the cookie on the manifest
    // fetches (the established delivery face, unchanged).
    assert!(
        cookie_bearing_hits(&log) >= 1,
        "the mock source must see the Cookie header: {:?}",
        log.lock().unwrap_or_else(|p| p.into_inner())
    );
    // Done clears the unified-table rows (acceptance ②, the done half).
    assert_eq!(
        cookie_rows(&dir, &gid),
        0,
        "zero residue in the unified table after Done"
    );
    kill_session(&session).await;
}

/// The error terminal (acceptance ②, the error half + acceptance ⑦
/// redact): cookies clear
/// **with the alert** — the payload carries gid/taskKind/count and
/// never the cookie value.
#[tokio::test]
async fn media_error_terminal_clears_cookies_and_alerts_without_values() {
    let (addr, _log) = spawn_cookie_source(6, 0, Some(3)).await;
    let dir = tempdir("err");
    let session = session_at(&dir, &dir).await;
    let mut alert_rx = session.subscribe_task_cookie_events();
    let gid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{addr}/master.m3u8"),
            options: media_options(&dir),
            cookies: spec("sid", "super-secret-value"),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    };
    assert_eq!(cookie_rows(&dir, &gid), 1);
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Error, "{err:?}");
    assert_eq!(
        cookie_rows(&dir, &gid),
        0,
        "the error terminal clears too (both task families)"
    );
    let alert = tokio::time::timeout(Duration::from_secs(3), alert_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("the error clear must alert: {e}"))
        .unwrap_or_else(|e| panic!("bus alive: {e}"));
    assert_eq!(alert.gid.to_string(), gid);
    assert_eq!(alert.task_kind, "media");
    assert_eq!(alert.count, 1);
    // Acceptance ⑦: the payload face never carries the cookie value.
    let rendered = format!("{alert:?}");
    assert!(
        !rendered.contains("super-secret-value") && !rendered.contains("sid"),
        "the alert payload must not carry the cookie name/value: {rendered}"
    );
    kill_session(&session).await;
}

/// Restart replay (acceptance ⑤, restart replay; the flipped anchor ③
/// — pre-fix the
/// in-memory media cookie set died with the session): a paused
/// mid-download media task restarts with its cookies intact; the
/// resumed activation seeds from the unified table (the mock sees the
/// cookie header again after the restart).
#[tokio::test]
async fn media_cookie_restart_replay_after_pause() {
    let (addr, log) = spawn_cookie_source(10, 120, None).await;
    let dir = tempdir("replay");
    let url = format!("http://{addr}/master.m3u8");
    let gid = {
        let session = session_at(&dir, &dir).await;
        let mut phases = session.subscribe_media_events();
        let gid = match session
            .call(SessionCommand::AddMedia {
                url: url.clone(),
                options: media_options(&dir),
                cookies: spec("sid", "replay-v1"),
                position: None,
            })
            .await
        {
            Ok(CommandReply::Gid(g)) => g.to_string(),
            other => panic!("addMedia: {other:?}"),
        };
        // Wait for the downloading phase (the media_task row has
        // landed), then pause.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let ev = tokio::time::timeout_at(deadline, phases.recv())
                .await
                .unwrap_or_else(|e| panic!("phase timeout: {e}"))
                .unwrap_or_else(|e| panic!("bus alive: {e}"));
            if ev.phase.as_str() == "downloading" {
                break;
            }
        }
        let _ = session
            .call(SessionCommand::Pause { gid: gid.clone() })
            .await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let st = session
                .call(SessionCommand::TellStatus {
                    gid: gid.clone(),
                    keys: Vec::new(),
                })
                .await;
            if let Ok(CommandReply::TorrentStatus(v)) = st {
                if v.status == StatusKind::Paused {
                    break;
                }
            }
            assert!(tokio::time::Instant::now() < deadline, "pause never landed");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            cookie_rows(&dir, &gid),
            1,
            "cookies persist in the paused state (non-terminal rows are kept)"
        );
        kill_session(&session).await;
        gid
    };
    let hits_before = cookie_bearing_hits(&log);
    assert!(hits_before > 0, "session A carried the cookie");
    // Session B: the paused row restores; unpause resumes carrying the
    // persisted cookie (the unified-table read-back).
    let session = session_at(&dir, &dir).await;
    assert_eq!(
        cookie_rows(&dir, &gid),
        1,
        "survives the restart (unified-table read-back — the flipped anchor: \
         the old pure-in-memory face died on restart)"
    );
    let _ = session
        .call(SessionCommand::Unpause { gid: gid.clone() })
        .await;
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Complete, "{err:?}");
    assert!(
        cookie_bearing_hits(&log) > hits_before,
        "post-restart activation must carry the cookie again (replay): \
         before {hits_before}, after {}",
        cookie_bearing_hits(&log)
    );
    assert_eq!(cookie_rows(&dir, &gid), 0, "cleared after Done");
    kill_session(&session).await;
}

/// setTaskCookies on media tasks (acceptance ⑥; the flipped anchor ② —
/// the pre-fix gate refused media tasks with the same text): a
/// waiting/paused media task accepts the whole-set replacement
/// (persisted kind=media; the next activation carries it), an active
/// task refuses, and a BT task still refuses — both with the fork's
/// verbatim gate text.
#[tokio::test]
async fn set_task_cookies_media_gates() {
    let (addr, log) = spawn_cookie_source(10, 120, None).await;
    let dir = tempdir("gates");
    let session = session_at(&dir, &dir).await;
    let gate_text = "Task cookies can only be set on waiting or paused cookie tasks.";

    // ---- waiting (pause=true) media task: accepted + persisted ----
    let wgid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{addr}/master.m3u8"),
            options: std::collections::BTreeMap::from([
                ("dir".to_string(), dir.display().to_string()),
                (
                    "media-allow-private-key-url".to_string(),
                    "true".to_string(),
                ),
                ("pause".to_string(), "true".to_string()),
            ]),
            cookies: Vec::new(),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    };
    let r = session
        .call(SessionCommand::SetTaskCookies {
            gid: wgid.clone(),
            cookies: spec("sid", "via-set-v1"),
        })
        .await;
    assert_eq!(
        r,
        Ok(CommandReply::Accepted),
        "media task accepted (flipped anchor ②): {r:?}"
    );
    assert_eq!(
        cookie_rows(&dir, &wgid),
        1,
        "persist-first lands in the table"
    );
    let _ = session
        .call(SessionCommand::Unpause { gid: wgid.clone() })
        .await;
    let (status, err) = wait_terminal(&session, &wgid).await;
    assert_eq!(status, StatusKind::Complete, "{err:?}");
    assert!(
        log.lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|(_, c)| c.as_deref().is_some_and(|v| v.contains("sid=via-set-v1"))),
        "the post-set activation must carry the new set (the next activation seeds from it)"
    );
    assert_eq!(cookie_rows(&dir, &wgid), 0);

    // ---- active media task: the verbatim gate ----
    let (addr2, _log2) = spawn_cookie_source(10, 120, None).await;
    let agid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{addr2}/master.m3u8"),
            options: media_options(&dir),
            cookies: Vec::new(),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    };
    // Wait until the task is active (a request hit the source).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let list = session
            .call(SessionCommand::TellActive { keys: Vec::new() })
            .await;
        if let Ok(CommandReply::StatusList(items)) = list {
            if items.iter().any(|v| v.gid.to_string() == agid) {
                break;
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "never active");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let r = session
        .call(SessionCommand::SetTaskCookies {
            gid: agid.clone(),
            cookies: spec("sid", "x"),
        })
        .await;
    let msg = match r {
        Err(e) => e.to_string(),
        Ok(_) => panic!("active media task must be rejected"),
    };
    assert_eq!(msg, gate_text, "gate text unchanged");

    // ---- BT task: the verbatim gate ----
    let mgid = match session
        .call(SessionCommand::AddUri {
            uris: vec!["magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into()],
            options: std::collections::BTreeMap::from([("pause".to_string(), "true".to_string())]),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("{other:?}"),
    };
    let r = session
        .call(SessionCommand::SetTaskCookies {
            gid: mgid.clone(),
            cookies: spec("sid", "x"),
        })
        .await;
    let msg = match r {
        Err(e) => e.to_string(),
        Ok(_) => panic!("BT task must stay rejected"),
    };
    assert_eq!(msg, gate_text, "BT family still refused");
    kill_session(&session).await;
}

/// remove pairs the cookie clear (acceptance ②, the remove half,
/// media leg): a
/// mid-download media task with cookies → forceRemove → the row and
/// the cookie rows are both gone.
#[tokio::test]
async fn media_remove_pairs_the_cookie_clear() {
    let (addr, _log) = spawn_cookie_source(10, 120, None).await;
    let dir = tempdir("rm");
    let session = session_at(&dir, &dir).await;
    let gid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{addr}/master.m3u8"),
            options: media_options(&dir),
            cookies: spec("sid", "rm-v1"),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    };
    // Wait for the row to land (downloading), then remove.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let conn = rusqlite::Connection::open(dir.join("taiji.sqlite3"))
            .unwrap_or_else(|e| panic!("open: {e}"));
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM media_task WHERE gid = ?1",
                [&gid],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if n == 1 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "row never landed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(cookie_rows(&dir, &gid), 1);
    let _ = session
        .call(SessionCommand::ForceRemove { gid: gid.clone() })
        .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if cookie_rows(&dir, &gid) == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "cookie rows left after remove (paired deletion failed)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    kill_session(&session).await;
}

/// The reserved (waiting/paused) remove arms pair the media cookie
/// clear too (acceptance ② — review-blocker regression: the reserved arm
/// never touched media rows/cookies, so a waiting media task's
/// creation-time cookie rows — and a paused-after-activation task's
/// media row — survived Remove/forceRemove). Two legs over the same
/// reserved arm: (a) never-activated (pause=true addMedia, no
/// media_task row yet) → Remove → zero cookie rows; (b)
/// paused-mid-download (row present) → forceRemove → row + cookies
/// both gone (the restart-resurrection face dies with the row).
#[tokio::test]
async fn media_reserved_remove_pairs_the_cookie_clear() {
    let (addr, _log) = spawn_cookie_source(10, 120, None).await;
    let dir = tempdir("rm-reserved");
    let session = session_at(&dir, &dir).await;
    let paused_opts = |dir: &std::path::Path| -> std::collections::BTreeMap<String, String> {
        let mut o = media_options(dir);
        o.insert("pause".to_string(), "true".to_string());
        o
    };

    // ---- (a) never-activated waiting task: creation-time cookie rows
    // only (no media_task row) → Remove → zero residue.
    let wgid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{addr}/master.m3u8"),
            options: paused_opts(&dir),
            cookies: spec("sid", "wait-v1"),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    };
    assert_eq!(
        cookie_rows(&dir, &wgid),
        1,
        "creation-time persistence precondition (persists under pause=true too)"
    );
    let _ = session
        .call(SessionCommand::Remove { gid: wgid.clone() })
        .await;
    assert_eq!(
        cookie_rows(&dir, &wgid),
        0,
        "the reserved arm's Remove must leave no cookie residue (review gap a)"
    );

    // ---- (b) paused-mid-download task (media_task row present) →
    // forceRemove → the row AND the cookies are gone.
    let pgid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{addr}/master.m3u8"),
            options: media_options(&dir),
            cookies: spec("sid", "paused-v1"),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    };
    // Wait for the row (downloading), then pause → reserved-paused.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let conn = rusqlite::Connection::open(dir.join("taiji.sqlite3"))
            .unwrap_or_else(|e| panic!("open: {e}"));
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM media_task WHERE gid = ?1",
                [&pgid],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if n == 1 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "row never landed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = session
        .call(SessionCommand::Pause { gid: pgid.clone() })
        .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let st = session
            .call(SessionCommand::TellStatus {
                gid: pgid.clone(),
                keys: Vec::new(),
            })
            .await;
        if let Ok(CommandReply::TorrentStatus(v)) = st {
            if v.status == StatusKind::Paused {
                break;
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "pause never landed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(cookie_rows(&dir, &pgid), 1);
    let _ = session
        .call(SessionCommand::ForceRemove { gid: pgid.clone() })
        .await;
    assert_eq!(
        cookie_rows(&dir, &pgid),
        0,
        "the reserved arm's forceRemove must leave no cookie residue (review gap b)"
    );
    let conn = rusqlite::Connection::open(dir.join("taiji.sqlite3"))
        .unwrap_or_else(|e| panic!("open: {e}"));
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM media_task WHERE gid = ?1",
            [&pgid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(
        n, 0,
        "the reserved arm's forceRemove must also delete the media row \
         (the restart-resurrection face)"
    );
    kill_session(&session).await;
}

/// The startup GC at the session level (acceptance ③): injected crash-window
/// residue — orphans, done-form residue, error-form residue — is
/// swept at bootstrap; the error-form groups re-emit the alert; the
/// active row survives; a second boot sweeps nothing more.
#[tokio::test]
async fn startup_gc_sweeps_injected_residue_and_alerts() {
    let dir = tempdir("gc");
    let db_path = dir.join("taiji.sqlite3");
    {
        let (persist, join) = taiji_store::persist::writer::PersistWriter::spawn(db_path.clone())
            .await
            .unwrap_or_else(|e| panic!("writer: {e}"));
        let http_row = |gid: &str, state: &str| taiji_store::persist::HttpTaskRow {
            gid: gid.to_string(),
            url: "http://127.0.0.1:1/f.bin".into(),
            final_url: String::new(),
            mirrors_json: None,
            state: state.into(),
            queue_pos: 0,
            dir: dir.display().to_string(),
            out: "f.bin".into(),
            config_json: "{}".into(),
            probe_json: None,
            validator_digest: None,
            block_size: 4096,
            block_bitmap: None,
            block_count: None,
            total_done: 0,
            error_code: None,
            error_msg: None,
            created_at: 1,
            updated_at: 1,
        };
        let media_row = |gid: &str, state: &str| taiji_store::persist::MediaTaskRow {
            gid: gid.to_string(),
            kind: "hls".into(),
            manifest_url: "http://127.0.0.1:1/m.m3u8".into(),
            state: state.into(),
            phase_detail_json: None,
            variant_json: None,
            selector_json: None,
            output_name: None,
            bridge_json: None,
            staging_dir: dir.join("s").display().to_string(),
            output_path: dir.join("o").display().to_string(),
            manifest_norm_digest: vec![1],
            total_done: 0,
            config_json: "{}".into(),
            error_code: None,
            error_msg: None,
            created_at: 1,
            updated_at: 1,
        };
        let ck = |gid: &str, kind: &str, name: &str| taiji_store::persist::TaskCookieRow {
            gid: gid.to_string(),
            task_kind: kind.to_string(),
            name: name.into(),
            domain: "127.0.0.1".into(),
            path: "/".into(),
            value: "v".into(),
            expires_utc: None,
            secure: false,
            host_only: true,
            creation_utc: 1,
        };
        let ha = "8000000000000601"; // active http (paused) — kept
        let he = "8000000000000602"; // error http — swept + alert
        let hd = "8000000000000603"; // done http — swept (log)
        let me = "8000000000000604"; // error media — swept + alert
        persist
            .upsert_http_task(http_row(ha, "paused"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        persist
            .upsert_http_task(http_row(he, "error"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        persist
            .upsert_http_task(http_row(hd, "done"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        persist
            .upsert_media_task(media_row(me, "error"))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        persist
            .upsert_task_cookies(ha, "http", vec![ck(ha, "http", "keep")])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        persist
            .upsert_task_cookies(he, "http", vec![ck(he, "http", "e1"), ck(he, "http", "e2")])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        persist
            .upsert_task_cookies(hd, "http", vec![ck(hd, "http", "d1")])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        persist
            .upsert_task_cookies(me, "media", vec![ck(me, "media", "m1")])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        drop(persist);
        let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
        // Raw orphans (no task row at all — the crash window's (a)
        // class): seeded straight into the table.
        let conn = rusqlite::Connection::open(&db_path).unwrap_or_else(|e| panic!("{e}"));
        for gid in ["8000000000000605", "8000000000000606"] {
            conn.execute(
                "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                     expires_utc, secure, host_only, creation_utc)
                 VALUES (?1, 'http', 'o', '127.0.0.1', '/', 'v', NULL, 0, 1, 1)",
                [gid],
            )
            .unwrap_or_else(|e| panic!("{e}"));
        }
    }
    // Boot: the sweep runs at bootstrap; the error-form rows alert.
    let session = session_at(&dir, &dir).await;
    let mut alert_rx = session.subscribe_task_cookie_events();
    // (The sweep runs before subscription completes in a race — but
    // bootstrap precedes the first command round-trip, so drain with a
    // bounded wait; both alerts must be in.)
    let mut alerts: Vec<TaskCookieEvent> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && alerts.len() < 2 {
        if let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(100), alert_rx.recv()).await
        {
            alerts.push(ev);
        }
    }
    alerts.sort_by_key(|a| a.task_kind.to_string());
    assert_eq!(
        alerts.len(),
        2,
        "both error-residue groups (http+media) alert once each"
    );
    assert_eq!((alerts[0].task_kind, alerts[0].count), ("http", 2));
    assert_eq!((alerts[1].task_kind, alerts[1].count), ("media", 1));
    // Active kept; everything else swept.
    assert_eq!(
        cookie_rows_all(&dir),
        1,
        "active row kept; orphan/terminal residue fully swept"
    );
    assert_eq!(cookie_rows(&dir, "8000000000000601"), 1);
    // Give the actor a beat, then kill and reboot: idempotent.
    kill_session(&session).await;
    let session2 = session_at(&dir, &dir).await;
    let mut alert_rx2 = session2.subscribe_task_cookie_events();
    assert_eq!(
        cookie_rows_all(&dir),
        1,
        "second run sweeps nothing more (idempotent)"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), alert_rx2.recv())
            .await
            .is_err()
            || cookie_rows_all(&dir) == 1,
        "second run emits no alert and clears no rows"
    );
    kill_session(&session2).await;
}
