//! Soak deliverable 3② (session half): the negative matrix rows that
//! are **task-level** semantics — §6 track-necessity grading (a
//! required track's failure terminalizes the task as Error; an
//! explicitly attached side track's failure degrades to completion
//! with the warning event) and the §5 DASH rows' session face
//! (the MPD entry drives the M2 DASH line — the
//! per-row judgment-table codes [live_unsupported/drm_unsupported]
//! assert end-to-end here).
//!
//! The driver-level §5 rows (live/EVENT/SAMPLE-AES/SESSION-KEY/
//! iframes/not_media/manifest_too_large caps) live in taiji-media's
//! `negative_matrix`; §7 precheck negatives + both-channels-failed →
//! `media_synth_e2e`; SSRF/key negatives →
//! `media_crypto_e2e`; template/probe anti-forgery →
//! `media_task_e2e` (regression references — the same gate runs
//! them).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionOptions, StatusKind,
};
use taiji_media::testkit::{
    FixtureSample, avcc_sample, build_init, build_segment, video_init_spec,
};

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

async fn spawn_with(build: impl FnOnce(SocketAddr) -> Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let app = build(addr);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

/// Which paths answer 500 (failure injection).
#[derive(Clone, Default)]
struct Fail {
    paths: Arc<std::sync::Mutex<Vec<String>>>,
    seg_hits: Arc<AtomicU64>,
}

impl Fail {
    fn is_failing(&self, path: &str) -> bool {
        self.paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|p| p == path)
    }

    fn fail(&self, path: &str) {
        self.paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.to_string());
    }
}

/// One failing-or-good segment route factory.
fn seg_route(fail: Fail, body: Vec<u8>, path: &'static str) -> axum::routing::MethodRouter {
    get(move || async move {
        fail.seg_hits.fetch_add(1, Ordering::SeqCst);
        if fail.is_failing(path) {
            return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
        }
        full_body(body.clone(), "video/mp4")
    })
}

/// A video-only variant (fMP4, 1 MAP) + a subtitle rendition, with
/// per-path failure injection.
async fn spawn_source() -> (SocketAddr, Fail) {
    let fail = Fail::default();
    let f2 = fail.clone();
    let addr = spawn_with(move |addr| {
        let vspec = video_init_spec();
        let video_init = build_init(&vspec);
        let mut video_segments = Vec::new();
        let mut decode_time = 0u64;
        for seq in 0..6u32 {
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
            video_segments.push(build_segment(1, seq, decode_time, &samples, &payload));
            decode_time += 99;
        }
        let mut video = String::from(
            "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:10\n",
        );
        video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/vinit.mp4\"\n"));
        for i in 0..6usize {
            video.push_str(&format!("#EXTINF:0.099,\nhttp://{addr}/vseg{i}.m4s\n"));
        }
        video.push_str("#EXT-X-ENDLIST\n");
        let subs = "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
                    #EXTINF:2.0,\nhttp://HOST/svtt0.vtt\n\
                    #EXTINF:2.0,\nhttp://HOST/svtt1.vtt\n\
                    #EXT-X-ENDLIST\n"
            .replace("HOST", &addr.to_string());
        let master = format!(
            "#EXTM3U\n\
             #EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"sub\",LANGUAGE=\"en\",NAME=\"EN\",URI=\"http://{addr}/sub.m3u8\"\n\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,SUBTITLES=\"sub\"\n\
             http://{addr}/v.m3u8\n"
        );
        let fail = f2.clone();
        let mut app = Router::new()
            .route(
                "/master.m3u8",
                get(move || async move {
                    full_body(master.clone().into_bytes(), "application/vnd.apple.mpegurl")
                }),
            )
            .route(
                "/v.m3u8",
                get(move || async move {
                    full_body(video.clone().into_bytes(), "application/vnd.apple.mpegurl")
                }),
            )
            .route(
                "/sub.m3u8",
                get(move || async move {
                    full_body(subs.clone().into_bytes(), "application/vnd.apple.mpegurl")
                }),
            )
            .route(
                "/vinit.mp4",
                get(move || async move { full_body(video_init.clone(), "video/mp4") }),
            );
        for (i, seg) in video_segments.iter().enumerate() {
            let path: &'static str = Box::leak(format!("/vseg{i}.m4s").into_boxed_str());
            app = app.route(path, seg_route(fail.clone(), seg.clone(), path));
        }
        for i in 0..2usize {
            let path: &'static str = Box::leak(format!("/svtt{i}.vtt").into_boxed_str());
            let body = format!("WEBVTT\n\n00:00:0{i}.000 --> 00:00:0{i}.900\ncue {i}\n")
                .into_bytes();
            app = app.route(path, seg_route(fail.clone(), body, path));
        }
        app
    })
    .await;
    (addr, fail)
}

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("media-neg-core-{tag}-{}-{n}", std::process::id()));
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
            ..Default::default()
        },
    };
    let (session, _actor) = SessionActor::spawn_with_persist(options, Some(persist));
    session
}

fn media_options(
    dir: &std::path::Path,
    selector: Option<&str>,
) -> std::collections::BTreeMap<String, String> {
    let mut m = std::collections::BTreeMap::from([
        ("dir".to_string(), dir.display().to_string()),
        (
            "media-allow-private-key-url".to_string(),
            "true".to_string(),
        ),
    ]);
    if let Some(sel) = selector {
        m.insert("media-selector".to_string(), sel.to_string());
    }
    m
}

async fn add_media(
    session: &taiji_core::session::SessionHandle,
    url: &str,
    options: std::collections::BTreeMap<String, String>,
) -> String {
    match session
        .call(SessionCommand::AddMedia {
            url: url.to_string(),
            options,
            cookies: Vec::new(),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("{other:?}"),
    }
}

async fn wait_terminal(
    session: &taiji_core::session::SessionHandle,
    gid: &str,
) -> (StatusKind, Option<String>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match session
            .call(SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: Vec::new(),
            })
            .await
        {
            Ok(CommandReply::TorrentStatus(v)) => {
                if matches!(v.status, StatusKind::Complete | StatusKind::Error) {
                    return (v.status, v.error_message.clone());
                }
            }
            other => panic!("{other:?}"),
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never reached a terminal state"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// §6 row: the REQUIRED track (the selected variant) failing → the
/// task terminalizes Error (not a partial Done).
#[tokio::test]
async fn required_track_failure_is_task_error() {
    let (addr, fail) = spawn_source().await;
    // Every video segment 500s (the required track cannot deliver).
    for i in 0..6 {
        fail.fail(&format!("/vseg{i}.m4s"));
    }
    let dir = tempdir("req-fail");
    let session = session_at(&dir, &dir).await;
    let gid = add_media(
        &session,
        &format!("http://{addr}/master.m3u8"),
        media_options(&dir, None),
    )
    .await;
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Error, "error code: {err:?}");
}

/// Degraded-completion row (the media spec's side-track rule, flipped
/// from the known-defect signature tolerance by review): an **explicitly attached side
/// track** (format_id multi-value) failing to download degrades the
/// task to **completion with a warning** — never an Error. Pre-fix,
/// `build_track_inputs` filtered only `TrackState::Failed`, so the
/// degraded sidecar's zero-byte archive reached `rewrite_track`
/// ("has zero archived bytes") and terminalized the task as Error;
/// the row now asserts the spec behavior outright: Complete + the
/// sidecar-degradation warning event (the warning payload is the
/// degraded track-state projection — label + failure text).
#[tokio::test]
async fn attached_side_track_failure_degrades_with_warning() {
    let (addr, fail) = spawn_source().await;
    fail.fail("/svtt0.vtt");
    fail.fail("/svtt1.vtt");
    let dir = tempdir("side-fail");
    let session = session_at(&dir, &dir).await;
    let mut warnings = Vec::new();
    let mut phases = session.subscribe_media_events();
    let gid = add_media(
        &session,
        &format!("http://{addr}/master.m3u8"),
        media_options(&dir, Some("format_id=v0,s0")),
    )
    .await;
    let (status, err) = wait_terminal(&session, &gid).await;
    // Drain the phase/warning stream for the sidecar warning (the
    // download-verdict face emits the degradation warning whatever the
    // synthesis outcome).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), phases.recv()).await {
            Ok(Ok(ev)) if ev.warning.is_some() => warnings.push(ev.warning),
            Ok(Ok(_)) => continue,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            _ => break,
        }
    }
    // The degraded track-state projection: the warning names the
    // sidecar (label s0 / subtitle) with its degradation text.
    assert!(
        warnings.iter().flatten().any(|w| (w.message.contains("s0")
            || w.message.contains("subtitle"))
            && w.message.contains("degraded")),
        "the sidecar degradation warning landed: {warnings:?}"
    );
    // The spec row: degraded completion, never Error.
    assert_eq!(
        status,
        StatusKind::Complete,
        "side-track failure degrades to completion per the media spec: {err:?}"
    );
    // The task reached Done with a real product (the video track
    // synthesized through).
    assert!(
        dir.join("v0.mp4").is_file()
            || std::fs::read_dir(&dir)
                .map(|entries| entries
                    .filter_map(|e| e.ok())
                    .any(|e| e.path().extension().is_some_and(|x| x == "mp4")))
                .unwrap_or(false),
        "the video product landed in {}",
        dir.display()
    );
}

/// §5 DASH rows (the DASH-arm flip, red-then-green): the MPD entry
/// parses and
/// drives the M2 line — the refusal rows assert the per-row
/// judgment-table codes end-to-end through the session. Red form of
/// record (this row pre-flip): the dynamic MPD was refused at the
/// entry classification with `manifest_parse` ("DASH parsing is not
/// wired in the 0.3 HLS line"); green = `live_unsupported` (the
/// v0.3.1 judgment-table row), DRM = `drm_unsupported`.
#[tokio::test]
async fn dash_dynamic_refused_live_unsupported_and_drm_row() {
    // dynamic → live_unsupported (the window checks land in the 0.4 line).
    let addr = spawn_with(move |_a| {
        Router::new().route(
            "/live.mpd",
            get(|| async move {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/dash+xml")],
                    "<?xml version=\"1.0\"?><MPD type=\"dynamic\"/>",
                )
            }),
        )
    })
    .await;
    let dir = tempdir("dashlive");
    let session = session_at(&dir, &dir).await;
    let gid = add_media(
        &session,
        &format!("http://{addr}/live.mpd"),
        media_options(&dir, None),
    )
    .await;
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Error);
    assert!(
        err.as_deref()
            .is_some_and(|c| c.contains("taiji.media.live_unsupported")),
        "the dynamic-MPD row lands the live_unsupported code: {err:?}"
    );

    // ContentProtection (any scheme, any level) → drm_unsupported.
    let addr = spawn_with(move |_a| {
        Router::new().route(
            "/drm.mpd",
            get(|| async move {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/dash+xml")],
                    "<?xml version=\"1.0\"?><MPD type=\"static\"><Period><AdaptationSet>\
                     <ContentProtection schemeIdUri=\"urn:mpeg:dash:mp4protection:2011\"/>\
                     <Representation id=\"r\" bandwidth=\"1\"/></AdaptationSet></Period></MPD>",
                )
            }),
        )
    })
    .await;
    let dir = tempdir("dashdrm");
    let session = session_at(&dir, &dir).await;
    let gid = add_media(
        &session,
        &format!("http://{addr}/drm.mpd"),
        media_options(&dir, None),
    )
    .await;
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Error);
    assert!(
        err.as_deref()
            .is_some_and(|c| c.contains("taiji.media.drm_unsupported")),
        "the ContentProtection row lands the drm_unsupported code: {err:?}"
    );
}

/// Zombie regression (from a crafted-BMFF PoC finding): crafted
/// BMFF bytes — a moof declaring `largesize = 2^64 - 8`, wrapping the
/// box-end arithmetic — flow through a real task as the segment body
/// and reach the synthesis fold. Pre-fix the fold **panicked inside
/// the media driver task** whose JoinHandle was dropped bare:
/// TaskNotice::Ended never fired and the task zombie'd in the running
/// set (this row's red form: `wait_terminal` blew its 60 s deadline).
/// Post-fix both layers hold: the box arithmetic is a staging error
/// (never a panic) and the driver's panic gate maps any residual
/// panic to the task-level Error terminal — the task reaches a
/// terminal state here either way.
#[tokio::test]
async fn crafted_bmff_bytes_error_not_zombie() {
    let crafted = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(b"free");
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(b"mdat");
        buf.extend_from_slice(&(u64::MAX - 7).to_be_bytes());
        buf
    };
    let crafted_seg = crafted.clone();
    let addr = spawn_with(move |addr| {
        let vspec = video_init_spec();
        let video_init = build_init(&vspec);
        let media = format!(
            "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n\
             #EXT-X-MAP:URI=\"http://{addr}/vinit.mp4\"\n\
             #EXTINF:1.0,\nhttp://{addr}/vseg0.m4s\n\
             #EXT-X-ENDLIST\n"
        );
        let master = format!(
            "#EXTM3U\n\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240\n\
             http://{addr}/v.m3u8\n"
        );
        Router::new()
            .route(
                "/master.m3u8",
                get(move || async move {
                    full_body(master.into_bytes(), "application/vnd.apple.mpegurl")
                }),
            )
            .route(
                "/v.m3u8",
                get(move || async move {
                    full_body(media.into_bytes(), "application/vnd.apple.mpegurl")
                }),
            )
            .route(
                "/vinit.mp4",
                get(move || async move { full_body(video_init.clone(), "video/mp4") }),
            )
            .route(
                "/vseg0.m4s",
                get(move || async move { full_body(crafted_seg.clone(), "video/mp4") }),
            )
    })
    .await;
    let dir = tempdir("crafted-bmff");
    let session = session_at(&dir, &dir).await;
    let gid = add_media(
        &session,
        &format!("http://{addr}/master.m3u8"),
        media_options(&dir, None),
    )
    .await;
    // The red form (pre-fix) never returned: the driver task died on
    // the fold panic with its JoinHandle dropped. The gate on this
    // row is terminality itself + the Error state.
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(
        status,
        StatusKind::Error,
        "crafted bytes terminalize Error (not a zombie): {err:?}"
    );
    // The failure must come from the synthesis fold consuming the
    // crafted archive (the staging face), not an earlier phase —
    // pinning that the bytes actually reached the fold.
    assert!(
        err.as_deref().is_some_and(|m| m.contains("bmff")),
        "the fold's refusal text names the bmff face: {err:?}"
    );
}

/// A DASH task that fails **after** its base row write
/// keeps the row's facts. Pre-fix, the error terminal wrote the
/// whole-row fail template — `kind` read back `hls` (hardcoded),
/// output_name/variant_json blanked, manifest_norm_digest zeroed.
/// Post-fix the terminal is a partial-column UPDATE (state + error
/// fields only), so the row still says `dash` with its product name.
#[tokio::test]
async fn dash_task_error_row_keeps_kind_and_facts() {
    let addr = spawn_with(move |addr| {
        let mpd = format!(
            r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT2S" profiles="urn:mpeg:dash:profile:isoff-live:2011">
  <Period duration="PT2S">
    <AdaptationSet id="vid" mimeType="video/mp4" codecs="avc1.64001f">
      <SegmentTemplate timescale="1000" duration="1000" startNumber="1"
        initialization="http://{addr}/init.mp4" media="http://{addr}/seg-$Number$.m4s"/>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
</MPD>"#
        );
        let not_found = || async move { StatusCode::NOT_FOUND.into_response() };
        Router::new()
            .route(
                "/m.mpd",
                get(move || async move { full_body(mpd.into_bytes(), "application/dash+xml") }),
            )
            // init + both segments miss (the task fails in the fetch
            // phase, after the Downloading-phase row write).
            .route("/init.mp4", get(not_found))
            .route("/seg-1.m4s", get(not_found))
            .route("/seg-2.m4s", get(not_found))
    })
    .await;
    let dir = tempdir("dash-fail-row");
    // A private writer handle (cloned before the actor takes one) so
    // the row can be read back after the terminal.
    let (persist, _join) =
        taiji_store::persist::writer::PersistWriter::spawn(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let reader = persist.clone();
    let options = SessionOptions {
        global: GlobalOptions {
            dir: dir.clone(),
            one_shot: true,
            ..Default::default()
        },
    };
    let (session, _actor) = SessionActor::spawn_with_persist(options, Some(persist));
    let gid = add_media(
        &session,
        &format!("http://{addr}/m.mpd"),
        media_options(&dir, None),
    )
    .await;
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Error, "error code: {err:?}");
    // The durable row: kind stays dash (the pre-fix template wrote
    // hls), the error fields landed, and the output_name snapshot
    // survived the terminal.
    let row = reader
        .load_media_task(&gid)
        .await
        .unwrap_or_else(|e| panic!("row read: {e}"))
        .unwrap_or_else(|| panic!("the task row exists"));
    assert_eq!(row.state, "error");
    assert_eq!(row.kind, "dash", "a failed DASH task's row stays dash");
    assert!(row.error_code.is_some(), "the error code landed: {row:?}");
    assert!(
        row.output_name.is_some(),
        "the Downloading-phase output_name snapshot survives the terminal: {row:?}"
    );
}

/// A DASH task that fails **before its first anchor
/// write** — the unknown-template-field refusal lands between the
/// classification (the sniff already decided `dash`) and the
/// Downloading-phase row write — still goes durable through the
/// `row_for_fail` fresh-row fallback, and that fallback must carry
/// the **actual** kind. Pre-fix the fresh-row template hardcoded
/// `kind = "hls"`, so a no-row DASH failure read back as an HLS
/// task (the partial-column UPDATE path cannot help here:
/// there is no row to update).
#[tokio::test]
async fn dash_task_no_row_failure_fallback_row_keeps_kind() {
    let addr = spawn_with(move |_a| {
        let mpd = r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT2S" profiles="urn:mpeg:dash:profile:isoff-live:2011">
  <Period duration="PT2S">
    <AdaptationSet id="vid" mimeType="video/mp4" codecs="avc1.64001f">
      <SegmentTemplate timescale="1000" duration="1000" startNumber="1"
        initialization="init.mp4" media="seg-$Number$.m4s"/>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
</MPD>"#
            .to_string();
        Router::new().route(
            "/m.mpd",
            get(move || async move { full_body(mpd.into_bytes(), "application/dash+xml") }),
        )
    })
    .await;
    let dir = tempdir("dash-norow-fail");
    // A private writer handle (cloned before the actor takes one) so
    // the fallback-inserted row can be read back after the terminal.
    let (persist, _join) =
        taiji_store::persist::writer::PersistWriter::spawn(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let reader = persist.clone();
    let options = SessionOptions {
        global: GlobalOptions {
            dir: dir.clone(),
            one_shot: true,
            ..Default::default()
        },
    };
    let (session, _actor) = SessionActor::spawn_with_persist(options, Some(persist));
    let mut opts = media_options(&dir, None);
    // The unknown template field: the refusal fires at §10's
    // expansion — after classification, before the base row write
    // (zero segment traffic; no init/seg routes even exist).
    opts.insert(
        "media-template".to_string(),
        "{uploader}-{id}.{ext}".to_string(),
    );
    let gid = add_media(&session, &format!("http://{addr}/m.mpd"), opts).await;
    let (status, err) = wait_terminal(&session, &gid).await;
    assert_eq!(status, StatusKind::Error, "error code: {err:?}");
    assert!(
        err.as_deref()
            .is_some_and(|c| c.contains("taiji.option.invalid")),
        "the unknown-field refusal is the failure: {err:?}"
    );
    // The durable row exists ONLY through the fallback insert (no
    // anchor write ever happened) — and its kind must be the task's
    // actual kind, not the hardcoded hls.
    let row = reader
        .load_media_task(&gid)
        .await
        .unwrap_or_else(|e| panic!("row read: {e}"))
        .unwrap_or_else(|| panic!("the fallback inserted a row"));
    assert_eq!(row.state, "error");
    assert_eq!(
        row.kind, "dash",
        "the no-row fallback insert carries the actual kind: {row:?}"
    );
    assert!(row.error_code.is_some(), "the error code landed: {row:?}");
}
