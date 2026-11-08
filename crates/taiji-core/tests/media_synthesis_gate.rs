//! Media synthesis-gate acceptance e2e: the media synthesis gate as
//! a session task face — driven through the SessionActor's addMedia
//! against a mock HLS source (the media_task_e2e fixture shape).
//!
//! Determinism posture (wall-clock ratio assertions are banned —
//! an earlier suite's flake precedent): the native synthesis channel is
//! in-process (the ffmpeg fallback channel's exec-shim spawns
//! `current_exe`, which under a libtest harness is the test binary —
//! the reason no taiji-core e2e exercises that channel), so a
//! synthesis seat is held for milliseconds per small fixture. The
//! suite therefore asserts through two instrument families:
//!
//! * **event-order + meter assertions** (fully deterministic): on the
//!   single six-event channel, the backfilled task's `Start` must
//!   precede the gated task's terminal (`Complete`) — with
//!   max-concurrent-downloads = 1 the backfill could not have happened
//!   unless the download slot was released **at the gate**, before the
//!   holder's terminal; the download meter stays at exactly the
//!   download budget with a *downloading* task throughout (the
//!   synthesis seat never leaks into the meter);
//! * **tight-loop park catch** (an earlier pool's precedent,
//!   check.rs's "tight loop, no sleep" shape): a parked proc_wait
//!   member's tellWaiting projection is sampled at full poll rate
//!   across the millisecond-scale park window (multi-round with fresh
//!   tasks; the caught sample IS the ②/⑥ precondition, and every
//!   post-command face is durable).
//!
//! Registry-count mechanics (budget boundary, flag carrying, halt
//! semantics, the nine-domain union) are pinned table-driven in
//! `session::queue::tests`; the gate pair mechanics in
//! `session::media::tests`; the budget default/clamp in
//! `session::actor::tests` (synthesis.rs). ④'s "pause phase memory: the
//! existing tests stay regression-green" rides the existing
//! `media_task_e2e::pause_phase_memory_processing`
//! (the gate's grant-immediately path preserves the §3.2 memory faces).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_core::session::{
    CommandReply, EventKind, GlobalOptions, MediaEvent, SessionActor, SessionCommand, SessionEvent,
    SessionOptions, StatusKind,
};
use taiji_media::testkit::{
    FixtureSample, audio_init_spec, avcc_sample, build_init, build_segment, sample_bytes,
    video_init_spec,
};

// ---------------------------------------------------------------------------
// mock source (two-track fMP4 HLS: video + audio — native-capable)
// ---------------------------------------------------------------------------

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

/// The mock two-track fixture: video (fMP4, 1 MAP) + audio (fMP4).
/// `video_delay_ms` stalls each video-segment request (the
/// deterministic download-window seam — the media_task_e2e shape).
/// Segment count scales the synthesis window (more segments = a wider
/// processing phase for the tight-loop park catch).
async fn spawn_source(video_segments: usize, video_delay_ms: u64) -> SocketAddr {
    spawn_source_sized(video_segments, video_delay_ms, 512).await
}

/// `video_payload_bytes` scales the per-segment payload (the synthesis
/// window knob: the native channel's rewrite/concat/verify cost scales
/// with the total bytes — a heavy fixture holds the synthesis seat for
/// tens/hundreds of milliseconds, widening the pause-all race window).
async fn spawn_source_sized(
    video_segments: usize,
    video_delay_ms: u64,
    video_payload_bytes: usize,
) -> SocketAddr {
    spawn_with(move |addr| {
        let vspec = video_init_spec();
        let video_init = build_init(&vspec);
        let mut video_bodies = Vec::new();
        let mut decode_time = 0u64;
        let mut video = String::from("#EXTM3U
#EXT-X-VERSION:7
#EXT-X-TARGETDURATION:1
");
        video.push_str("#EXT-X-MEDIA-SEQUENCE:10
");
        video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/vinit.mp4\"
"));
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
            video.push_str(&format!("#EXTINF:0.099,
http://{addr}/vseg{seq}.m4s
"));
        }
        video.push_str("#EXT-X-ENDLIST
");

        let aspec = audio_init_spec();
        let audio_init = build_init(&aspec);
        let mut audio_bodies = Vec::new();
        let mut adt = 0u64;
        let mut audio = String::from("#EXTM3U
#EXT-X-TARGETDURATION:1
");
        audio.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/ainit.mp4\"
"));
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
                .flat_map(|(i, s)| {
                    sample_bytes(40 + seq as u8 + i as u8, s.size as usize).into_iter()
                })
                .collect();
            audio_bodies.push(build_segment(1, seq, adt, &samples, &payload));
            adt += 4096;
            audio.push_str(&format!("#EXTINF:0.0928,
http://{addr}/aseg{seq}.m4s
"));
        }
        audio.push_str("#EXT-X-ENDLIST
");

        let master = format!(
            "#EXTM3U
\
             #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en\",NAME=\"EN\",DEFAULT=YES,URI=\"http://{addr}/audio.m3u8\"
\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,CODECS=\"avc1.64001f,mp4a.40.2\",AUDIO=\"aud\"
\
             http://{addr}/v.m3u8
"
        );

        let routes = Router::new()
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
        let mut with_seg = routes;
        for (i, body) in audio_bodies.iter().enumerate() {
            let body = body.clone();
            with_seg = with_seg.route(
                &format!("/aseg{i}.m4s"),
                get(move || async move { full_body(body.clone(), "video/mp4") }),
            );
        }
        for (i, seg) in video_bodies.iter().enumerate() {
            let seg = seg.clone();
            let delay = video_delay_ms;
            with_seg = with_seg.route(
                &format!("/vseg{i}.m4s"),
                get(move || async move {
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    full_body(seg.clone(), "video/mp4")
                }),
            );
        }
        with_seg
    })
    .await
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("media-synth-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

/// A persist-backed session with the synthesis budget set (the
/// per-session synthesis face lives on the globals until the RPC key
/// is wired; direct construction is the declared internal field
/// path).
async fn session_at(
    db: &Path,
    dir: &Path,
    synth_budget: usize,
    max_dl: usize,
) -> taiji_core::session::SessionHandle {
    let (persist, _join) =
        taiji_store::persist::writer::PersistWriter::spawn(db.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let options = SessionOptions {
        global: GlobalOptions {
            dir: dir.to_path_buf(),
            media_synthesis_concurrency: synth_budget,
            max_concurrent_downloads: max_dl,
            ..Default::default()
        },
    };
    let (session, _actor) = SessionActor::spawn_with_persist(options, Some(persist));
    session
}

fn media_options(dir: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("dir".to_string(), dir.display().to_string()),
        // The mock lives on loopback — the SSRF default-deny needs the
        // explicit allow (the established mock-source precedent).
        (
            "media-allow-private-key-url".to_string(),
            "true".to_string(),
        ),
    ])
}

async fn add_media(session: &taiji_core::session::SessionHandle, url: &str, dir: &Path) -> String {
    match session
        .call(SessionCommand::AddMedia {
            url: url.to_string(),
            options: media_options(dir),
            cookies: Vec::new(),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    }
}

async fn num_active(session: &taiji_core::session::SessionHandle) -> u64 {
    match session.call(SessionCommand::GetGlobalStat).await {
        Ok(CommandReply::GlobalStat(g)) => g.num_active,
        other => panic!("getGlobalStat: {other:?}"),
    }
}

/// Full getGlobalStat view (the four-pool caliber's read face).
async fn global_stat(
    session: &taiji_core::session::SessionHandle,
) -> taiji_core::session::GlobalStatView {
    match session.call(SessionCommand::GetGlobalStat).await {
        Ok(CommandReply::GlobalStat(g)) => g,
        other => panic!("getGlobalStat: {other:?}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RowView {
    gid: String,
    status: StatusKind,
}

async fn views(session: &taiji_core::session::SessionHandle, cmd: SessionCommand) -> Vec<RowView> {
    match session.call(cmd).await {
        Ok(CommandReply::StatusList(v)) => v
            .into_iter()
            .map(|s| RowView {
                gid: s.gid.to_string(),
                status: s.status,
            })
            .collect(),
        other => panic!("tell*: {other:?}"),
    }
}

async fn tell_active(session: &taiji_core::session::SessionHandle) -> Vec<RowView> {
    views(session, SessionCommand::TellActive { keys: vec![] }).await
}

async fn tell_waiting(session: &taiji_core::session::SessionHandle) -> Vec<RowView> {
    views(
        session,
        SessionCommand::TellWaiting {
            offset: 0,
            num: u32::MAX,
            keys: vec![],
        },
    )
    .await
}

async fn tell_stopped(session: &taiji_core::session::SessionHandle) -> Vec<RowView> {
    views(
        session,
        SessionCommand::TellStopped {
            offset: 0,
            num: u32::MAX,
            keys: vec![],
        },
    )
    .await
}

/// The media sub-dictionary's live phase (the processing/verifying
/// observation face for an in-flight synthesis).
async fn media_phase(session: &taiji_core::session::SessionHandle, gid: &str) -> Option<String> {
    match session
        .call(SessionCommand::TellStatus {
            gid: gid.to_string(),
            keys: vec![],
        })
        .await
    {
        Ok(CommandReply::TorrentStatus(v)) => v.media.as_ref().map(|m| m.phase.to_string()),
        other => panic!("tellStatus: {other:?}"),
    }
}

/// Non-panicking bounded poll: `true` = the predicate held within the
/// window, `false` = it never did (the caller decides — the round
/// validity discriminator's face).
async fn wait_for_opt(mut pred: impl AsyncFnMut() -> bool, window: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        if pred().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Poll `pred` to convergence (bounded window, 50ms ticks).
async fn wait_for(mut pred: impl AsyncFnMut() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if pred().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not reached within the poll window: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Drain the six-event bus into a gid→event list (bounded by deadline;
/// broadcast lag is tolerated — the assertions below use order and
/// presence, never completeness).
async fn wait_event(
    rx: &mut tokio::sync::broadcast::Receiver<SessionEvent>,
    pred: impl Fn(&SessionEvent) -> bool,
    what: &str,
) -> SessionEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("event wait timeout: {what}"))
            .unwrap_or_else(|e| panic!("event bus: {e}: {what}"));
        if pred(&ev) {
            return ev;
        }
    }
}

async fn wait_media(
    rx: &mut tokio::sync::broadcast::Receiver<MediaEvent>,
    pred: impl Fn(&MediaEvent) -> bool,
    what: &str,
) -> MediaEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("media wait timeout: {what}"))
            .unwrap_or_else(|e| panic!("media bus: {e}: {what}"));
        if pred(&ev) {
            return ev;
        }
    }
}

async fn media_row_state(db: &Path, gid: &str) -> Option<String> {
    let conn = rusqlite::Connection::open(db.join("taiji.sqlite3"))
        .unwrap_or_else(|e| panic!("open db: {e}"));
    conn.query_row(
        "SELECT state FROM media_task WHERE gid = ?1",
        rusqlite::params![gid],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

/// The tight-loop park catch (the check-pool shape): poll tellWaiting
/// at full rate for a member with the 'waiting' status. With
/// max-concurrent-downloads ≥ the task count, every task activates
/// immediately, so a 'waiting' tellWaiting member can only be a
/// proc_wait park (the reserved FIFO is empty). The park window is the
/// seat holder's remaining synthesis (milliseconds — the native
/// channel is in-process), hence no sleep between samples. Returns the
/// caught gid, or None when every round's window was missed (the
/// caller's documented escape precedent).
async fn catch_parked(
    session: &taiji_core::session::SessionHandle,
    candidates: &[String],
    rounds: usize,
) -> Option<String> {
    for _ in 0..rounds {
        for _ in 0..2000 {
            let waiting = tell_waiting(session).await;
            for v in waiting {
                if v.status == StatusKind::Waiting && candidates.contains(&v.gid) {
                    return Some(v.gid);
                }
            }
            // Every candidate terminalized: this round's race is lost —
            // stop polling, the caller re-seeds a fresh round.
            let stopped = tell_stopped(session).await;
            if candidates.iter().all(|c| {
                stopped.iter().any(|s| {
                    &s.gid == c && matches!(s.status, StatusKind::Complete | StatusKind::Error)
                })
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
        // Round interleave: wait this round's tasks out, then the
        // caller re-seeds.
        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                let stopped = tell_stopped(session).await;
                if candidates
                    .iter()
                    .all(|c| stopped.iter().any(|s| &s.gid == c))
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    let active = tell_active(session).await;
                    let waiting = tell_waiting(session).await;
                    panic!(
                        "round drain timeout: active={active:?} waiting={waiting:?} stopped={stopped:?}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// ① + ⑤ (the synthesis slice) + the active→proc_wait backfill edge:
/// synthesis budget 1, download budget 1 — task A releases its
/// download slot **at the gate** and the same tick's fillup backfills
/// it to task B, which then downloads *while* A holds the synthesis
/// seat. Deterministic faces:
/// * on the single six-event channel, B's `Start` precedes A's
/// terminal — with max-concurrent-downloads = 1, B could not have
/// activated unless A's download slot was released before A's
/// terminal (release-at-gate, not release-at-end);
/// * A's media `processing` phase event is observed (the gate →
/// permit → Processing path ran);
/// * throughout B's download the meter reads exactly 1 (the download
/// budget) with B downloading — the synthesis seat never leaks into
/// the download meter (⑤'s steady-state slice; the sample sits in
/// B's seconds-long download window, far from any transfer edge).
#[tokio::test]
async fn synth_budget_one_releases_download_slot_at_gate() {
    let fast = spawn_source(60, 0).await;
    let slow = spawn_source(20, 300).await;
    let dir = tempdir("slot");
    let session = session_at(&dir, &dir, 1, 1).await;
    let mut six = session.subscribe_events();
    let mut media = session.subscribe_media_events();
    let a = add_media(&session, &format!("http://{fast}/master.m3u8"), &dir).await;
    let b = add_media(&session, &format!("http://{slow}/master.m3u8"), &dir).await;

    // A gates (its Processing phase event fires), B backfills (Start),
    // then both terminalize.
    let a_started = wait_event(&mut six, |e| e.gid.to_string() == a, "A Start").await;
    assert_eq!(a_started.kind, EventKind::Start);
    let a_processing = wait_media(
        &mut media,
        |e| e.gid.to_string() == a && e.phase.as_str() == "processing" && e.warning.is_none(),
        "A processing phase event",
    )
    .await;
    let _ = a_processing;
    let b_started = wait_event(
        &mut six,
        |e| e.gid.to_string() == b && e.kind == EventKind::Start,
        "B Start (backfill)",
    )
    .await;
    let a_done = wait_event(
        &mut six,
        |e| e.gid.to_string() == a && e.kind == EventKind::Complete,
        "A terminal",
    )
    .await;
    let _ = a_done;
    assert!(
        b_started.kind == EventKind::Start,
        "B's backfilled Start precedes A's terminal (the download slot \
         is released at the gate, not at the terminal)"
    );

    // ⑤ steady-state slice: B's download is seconds long; throughout
    // it the meter reads exactly the download budget with B (a
    // downloading task) as the only occupant. Sampled at several
    // points inside the window (all post-transfer — no transient
    // window is inside an assertion).
    wait_for(
        || async { media_phase(&session, &b).await.as_deref() == Some("downloading") },
        "B enters the downloading phase",
    )
    .await;
    for _ in 0..4 {
        let n = num_active(&session).await;
        assert_eq!(
            n, 1,
            "download slots at full load = max-concurrent-downloads (sampled {n})"
        );
        let active = tell_active(&session).await;
        assert!(
            active.iter().any(|v| v.gid == b),
            "the download slot is occupied by downloading-phase task B"
        );
        let phase = media_phase(&session, &b).await;
        assert_eq!(
            phase.as_deref(),
            Some("downloading"),
            "B still in the downloading phase (sampled phase {phase:?})"
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    // Drain: both complete natively; the registries empty out.
    wait_for(
        || async {
            let stopped = tell_stopped(&session).await;
            stopped
                .iter()
                .any(|v| v.gid == a && v.status == StatusKind::Complete)
                && stopped
                    .iter()
                    .any(|v| v.gid == b && v.status == StatusKind::Complete)
        },
        "both tasks reach the Complete terminal",
    )
    .await;
    assert_eq!(
        num_active(&session).await,
        0,
        "download slots back to zero at terminal"
    );
    assert!(
        tell_waiting(&session).await.is_empty(),
        "proc_wait empty at terminal"
    );
    session.shutdown().await;
}

/// ② + ⑥ (the tight-loop catch): synthesis budget 2 (= the default
/// value) with three tasks racing the same fixture — two take the
/// seats, the third parks into proc_wait for the leaders' remaining
/// synthesis. The caught sample IS the acceptance precondition:
/// the parked member is tellWaiting-visible with the **existing**
/// 'waiting' status (zero value-domain extension — no invisible task
/// in any of the three FIFOs). The remove lands while parked (the gate
/// await loses the
/// token race): the member leaves the FIFO, the Removed result lands,
/// and no seat of any pool is occupied at any sample. If every
/// round's millisecond-scale window is missed, the documented escape
/// shape skips the park-dependent faces — the
/// always-true faces (all tasks Complete, registries empty) still
/// hold.
#[tokio::test]
async fn parked_member_remove_is_immediate_and_visible() {
    let src = spawn_source(60, 0).await;
    let dir = tempdir("rm");
    // Budget 2 = the default value, spelled out (synthesis budget 2).
    let session = session_at(&dir, &dir, 2, 5).await;

    let mut caught = None;
    for round in 0..4 {
        let mut trio = Vec::new();
        for _ in 0..3 {
            let g = add_media(&session, &format!("http://{src}/master.m3u8"), &dir).await;
            trio.push(g);
        }
        if let Some(parked) = catch_parked(&session, &trio, 1).await {
            // ②: remove the parked member immediately. The catch sample
            // (inside catch_parked) already carried the ⑥ visibility
            // face — a 'waiting'-status member in the tellWaiting
            // projection — and any follow-up query would race the
            // promotion (the member may have taken a freed seat between
            // the sample and the remove; both states remove cleanly
            // through the same halt semantics).
            assert!(matches!(
                session
                    .call(SessionCommand::Remove {
                        gid: parked.clone(),
                    })
                    .await,
                Ok(CommandReply::Gid(_))
            ));
            wait_for(
                || async {
                    tell_stopped(&session)
                        .await
                        .iter()
                        .any(|v| v.gid == parked && v.status == StatusKind::Removed)
                },
                "parked member remove → Removed terminal lands in results",
            )
            .await;
            assert!(
                !tell_waiting(&session).await.iter().any(|v| v.gid == parked),
                "after remove, the member left proc_wait (tellWaiting)"
            );
            assert_eq!(
                num_active(&session).await,
                0,
                "after remove, no slot is occupied"
            );
            let removed = parked.clone();
            caught = Some(parked);
            // Drain this round's remaining two.
            wait_for(
                || async {
                    let stopped = tell_stopped(&session).await;
                    trio.iter()
                        .all(|t| t == &removed || stopped.iter().any(|s| &s.gid == t))
                },
                "round drain",
            )
            .await;
            break;
        }
        let _ = round;
    }
    let caught = caught.unwrap_or_else(|| {
        // Documented escape (the millisecond park window lost all
        // rounds): the park-dependent faces are skipped; the session's
        // steady faces are asserted by the drain below (the
        // established tight-loop-catch escape shape).
        eprintln!("p126: park window missed in all rounds; skipping park-dependent faces");
        String::new()
    });
    let _ = caught;

    // Steady faces (hold regardless of the catch): the last trio's
    // non-removed members completed, registries empty.
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let stopped = tell_stopped(&session).await;
            let waiting = tell_waiting(&session).await;
            let active = tell_active(&session).await;
            // Removed entries are legitimate here (the caught member's
            // intentional remove in the catch phase).
            if waiting.is_empty()
                && stopped
                    .iter()
                    .all(|v| matches!(v.status, StatusKind::Complete | StatusKind::Removed))
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "terminal state not reached: active={active:?} \
                     waiting={waiting:?} stopped={stopped:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    assert_eq!(num_active(&session).await, 0);
    session.shutdown().await;
}

/// ③ + ④: the gate-await × pause race and the park/unpark round trip.
/// A parks behind the holder; the pause lands (whether mid-hang or a
/// beat later mid-processing — both faces are the synthesis-side
/// teardown): the driver's token cancel races the gate await /
/// synthesis, the teardown carries the §3.2 phase memory
/// (`paused` + phaseDetail 'processing' — the exact event face), the
/// consume requeues to the paused queue **front** (durable), and the
/// seat releases. The unpause re-activates through the plain
/// reserved-paused arm (no activation-phase special case), re-walks
/// Resolving → Downloading (idempotent — the second 'resolving' media
/// event), converges back onto the gate and completes. The proc_wait →
/// processing promotion edge (release-then-backfill with no external
/// event) is the holder's own drain: its terminal's trailing pump_all
/// admits the parked member without any further command.
#[tokio::test]
async fn gate_hang_pause_requeue_unpause_roundtrip() {
    let src = spawn_source(60, 0).await;
    let dir = tempdir("park");
    let session = session_at(&dir, &dir, 1, 5).await;
    let mut media = session.subscribe_media_events();
    let mut six = session.subscribe_events();

    let mut caught = None;
    let mut holder = String::new();
    for _ in 0..4 {
        // Three tasks under budget 1: the first gater takes the seat,
        // the other two park early in the holder's window (the
        // two-task shape parks late and misses the window).
        let mut trio = Vec::new();
        for _ in 0..3 {
            let g = add_media(&session, &format!("http://{src}/master.m3u8"), &dir).await;
            trio.push(g);
        }
        let a = trio[0].clone();
        let b = trio[1].clone();
        if let Some(parked) = catch_parked(&session, &trio, 1).await {
            caught = Some(parked.clone());
            holder = if parked == a { b } else { a };
            // ③: pause the parked member; the teardown's memory face is
            // the exact observable.
            assert!(matches!(
                session
                    .call(SessionCommand::Pause {
                        gid: parked.clone()
                    })
                    .await,
                Ok(CommandReply::Gid(_))
            ));
            let paused_ev = wait_media(
                &mut media,
                |e| {
                    e.gid.to_string() == parked
                        && e.phase.as_str() == "paused"
                        && e.warning.is_none()
                },
                "paused event",
            )
            .await;
            assert_eq!(
                paused_ev.phase_detail.as_deref(),
                Some("processing"),
                "③: pause while parked → Paused{{memory: Processing}} (event phaseDetail)"
            );
            // Requeue to the paused queue FRONT (durable).
            wait_for(
                || async {
                    let waiting = tell_waiting(&session).await;
                    waiting
                        .first()
                        .map(|v| v.gid == parked && v.status == StatusKind::Paused)
                        == Some(true)
                },
                "pause → requeued to the paused queue front",
            )
            .await;
            // The paused member left the synthesis faces (requeue =
            // seatless, the reserved-paused front above); the meter at
            // most counts the still-downloading round members.
            assert!(
                num_active(&session).await <= 2,
                "paused member occupies no slot (sampled value {})",
                num_active(&session).await
            );
            // ④: unpause — the plain reserved-paused arm re-activates;
            // the idempotent re-walk fires a second 'resolving' phase.
            assert!(matches!(
                session
                    .call(SessionCommand::Unpause {
                        gid: parked.clone()
                    })
                    .await,
                Ok(CommandReply::Gid(_))
            ));
            let rewalk = wait_media(
                &mut media,
                |e| {
                    e.gid.to_string() == parked
                        && e.phase.as_str() == "resolving"
                        && e.warning.is_none()
                },
                "unpause → re-walks Resolving",
            )
            .await;
            let _ = rewalk;
            break;
        }
        holder = a;
        let _ = b;
    }
    let Some(parked) = caught else {
        panic!(
            "park window never caught (tight-loop lost all four rounds) — \
             the race-predicate test needs a parked sample"
        );
    };
    let _ = holder;

    // Drain: the unparked member re-walks → gate → completes; the
    // holder completes. (The holder's terminal released its seat and
    // the trailing pump promoted the parked member whenever the park
    // was still held — release-then-backfill, no external event.)
    wait_for(
        || async {
            let stopped = tell_stopped(&session).await;
            stopped
                .iter()
                .any(|v| v.gid == parked && v.status == StatusKind::Complete)
        },
        "④: unpause round trip converges (re-walk → gate → Complete)",
    )
    .await;
    assert_eq!(num_active(&session).await, 0);
    assert!(tell_waiting(&session).await.is_empty());
    session.shutdown().await;
    let _ = &mut six;
}

/// ⑩: proc_wait does not cross a restart. Session 1: a member parks
/// behind the holder; the session shuts down inside the window. The
/// persisted rows carry no proc_wait-specific state — the parked row
/// stays 'downloading' (the hang happens before the Processing row
/// write), the holder's row is a normal 'processing'/'done' value —
/// and no proc_wait position persists. Session 2 (same DB): the rows
/// re-enter by their phase memory, re-walk Resolving → Downloading
/// (idempotent) → **through the gate again** (the second 'processing'
/// phase event proves the re-entry) and terminalize normally.
#[tokio::test]
async fn proc_wait_does_not_cross_restart() {
    let src = spawn_source(60, 0).await;
    let dir = tempdir("restart");
    let db = dir.clone();
    let session = session_at(&db, &dir, 1, 5).await;
    let mut media = session.subscribe_media_events();

    let mut shutdown_pair = None;
    for _ in 0..8 {
        let mut trio = Vec::new();
        for _ in 0..3 {
            let g = add_media(&session, &format!("http://{src}/master.m3u8"), &dir).await;
            trio.push(g);
        }
        let a = trio[0].clone();
        let b = trio[1].clone();
        if let Some(parked) = catch_parked(&session, &trio, 1).await {
            // Shutdown inside the park window: the gate hang's token
            // cancel lands the Cancelled teardown (no row write — the
            // row keeps its download-phase value).
            session.shutdown().await;
            shutdown_pair = Some((a, b, parked));
            break;
        }
        // Round lost: drain and re-seed.
        wait_for(
            || async {
                let stopped = tell_stopped(&session).await;
                trio.iter().all(|t| stopped.iter().any(|s| &s.gid == t))
            },
            "round drain",
        )
        .await;
    }
    // When every round's millisecond window was missed (rare), the
    // generic restart faces below still hold — the session shuts down
    // over completed tasks and the value-domain + re-entry faces are
    // asserted on those rows (the established escape shape; the hang-specific
    // sample faces are skipped, not weakened).
    let caught_shape = shutdown_pair.is_some();
    let (a, b, parked) = match shutdown_pair {
        Some(triple) => triple,
        None => {
            eprintln!("park window missed in all rounds; asserting the generic restart faces");
            session.shutdown().await;
            (String::new(), String::new(), String::new())
        }
    };
    let other = if parked == a { b.clone() } else { a.clone() };

    if caught_shape {
        // The persisted truth: no proc_wait-specific row state, the
        // parked row still at its download phase. The shutdown lands
        // within microseconds of the caught sample: if the member was
        // still gate-hung, its row stays 'downloading' (the Processing
        // write happens only after the permit); if it promoted in the
        // gap, the row is the normal 'processing' phase write. BOTH are
        // pre-existing §3.2 values — neither is a proc_wait-specific row
        // state, and no proc_wait position persisted (the session-2
        // round trip below proves the re-entry by phase).
        let parked_row = media_row_state(&db, &parked)
            .await
            .unwrap_or_else(|| panic!("parked row missing"));
        assert!(
            matches!(parked_row.as_str(), "downloading" | "processing"),
            "parked member row = a pre-existing value (no proc_wait-specific row state; \
             got {parked_row})"
        );
    }
    // Each row is checked against the **value domain** rather than a
    // specific assignment (the third member may itself be parked —
    // budget 1, three tasks, two gate hangs): every accepted state is a
    // pre-existing §3.2 value (the hang face 'downloading', the
    // synthesis face 'processing'/'verifying', the terminal 'done') —
    // no proc_wait-specific row state exists.
    for gid in [&parked, &other] {
        if gid.is_empty() {
            continue;
        }
        let row = media_row_state(&db, gid)
            .await
            .unwrap_or_else(|| panic!("row missing for {gid}"));
        assert!(
            matches!(
                row.as_str(),
                "downloading" | "processing" | "verifying" | "done"
            ),
            "post-shutdown row must be a pre-existing §3.2 value ({gid}: {row})"
        );
    }

    // Session 2: the rows re-enter by phase; each **re-enqueued** row
    // (the active-state set) re-walks Resolving → Downloading → the
    // gate (structurally: every session run enters through the same
    // pipeline head) and terminalizes normally. The holder's row is
    // 'processing' when the shutdown landed inside the hold
    // (re-enqueued), 'done' when the hold already drained (terminal —
    // not re-enqueued). The terminal faces are the race-free
    // observation (the media bus's early phase events race the test's
    // post-spawn subscription and are not asserted here).
    let session2 = session_at(&db, &dir, 1, 5).await;
    let mut reenqueued = Vec::new();
    for gid in [&parked, &other] {
        let row = media_row_state(&db, gid).await;
        if row.as_deref().is_some_and(|s| {
            matches!(
                s,
                "queued"
                    | "resolving"
                    | "downloading"
                    | "processing"
                    | "verifying"
                    | "recording"
                    | "finalizing"
            )
        }) {
            reenqueued.push(gid.clone());
        } else {
            assert_eq!(
                row.as_deref(),
                Some("done"),
                "non-re-enqueued row must be the done terminal state ({gid}: {row:?})"
            );
        }
    }
    if caught_shape {
        assert!(
            reenqueued.contains(&parked),
            "gate-hung row ('downloading') must re-enqueue (phase-memory recovery face)"
        );
    }
    assert!(
        !reenqueued.is_empty(),
        "the restarted session re-enqueues at least one row (phase-memory recovery face)"
    );
    wait_for(
        || async {
            let stopped = tell_stopped(&session2).await;
            reenqueued.iter().all(|t| {
                stopped
                    .iter()
                    .any(|v| v.gid == *t && v.status == StatusKind::Complete)
            })
        },
        "⑩: restarted session terminates normally (re-enqueued tasks Complete)",
    )
    .await;
    let _ = &other;
    assert_eq!(num_active(&session2).await, 0);
    assert!(
        tell_waiting(&session2).await.is_empty(),
        "proc_wait leaves zero persisted state"
    );
    session2.shutdown().await;
    let _ = &mut media;
}

/// ⑥'s default-visibility face at budget 1 with a **single** parked
/// member (the simplest projection sample): the tellWaiting appended
/// segment carries the parked member with the 'waiting' status while
/// both registries otherwise stay clean — the three-FIFO
/// no-invisible-task discipline's synthesis slice. Skipped via the
/// documented escape when every round's park window is missed (the
/// projection itself is exercised by the remove/pause tests above on
/// their caught samples).
#[tokio::test]
async fn parked_member_visible_in_tell_waiting() {
    let src = spawn_source(60, 0).await;
    let dir = tempdir("vis");
    // Budget 2 = the default value, spelled out (⑥: synthesis budget 2).
    let session = session_at(&dir, &dir, 2, 5).await;

    // The visibility face is asserted **atomically on one tellWaiting
    // snapshot** (the park window is the seat holder's remaining
    // synthesis — milliseconds — so any follow-up command would race
    // the promotion; the single response carries the whole projection).
    let mut caught = false;
    'rounds: for _ in 0..6 {
        let mut trio = Vec::new();
        for _ in 0..3 {
            let g = add_media(&session, &format!("http://{src}/master.m3u8"), &dir).await;
            trio.push(g);
        }
        for _ in 0..3000 {
            let waiting = tell_waiting(&session).await;
            let parked_rows: Vec<&RowView> = waiting
                .iter()
                .filter(|v| v.status == StatusKind::Waiting && trio.contains(&v.gid))
                .collect();
            if !parked_rows.is_empty() {
                // ⑥: the parked member(s) carry the existing 'waiting'
                // value — zero value-domain extension; the snapshot's
                // waiting members are all this round's own (no foreign
                // segment, no invisible task).
                for v in &parked_rows {
                    assert_eq!(v.status, StatusKind::Waiting);
                }
                assert!(
                    waiting.iter().all(|v| trio.contains(&v.gid)),
                    "the tellWaiting parked segment holds only this round's members \
                     (no invisible/foreign task)"
                );
                caught = true;
                break 'rounds;
            }
            // Every round member terminalized: this race is lost —
            // re-seed.
            let stopped = tell_stopped(&session).await;
            if trio.iter().all(|t| stopped.iter().any(|s| &s.gid == t)) {
                break;
            }
            tokio::task::yield_now().await;
        }
        wait_for(
            || async {
                let stopped = tell_stopped(&session).await;
                trio.iter().all(|t| stopped.iter().any(|s| &s.gid == t))
            },
            "round drain",
        )
        .await;
    }
    if !caught {
        eprintln!("park window missed in all rounds; the visibility face rode the sibling tests");
    }
    wait_for(
        || async {
            let stopped = tell_stopped(&session).await;
            let waiting = tell_waiting(&session).await;
            waiting.is_empty() && stopped.iter().all(|v| v.status == StatusKind::Complete)
        },
        "terminal drain",
    )
    .await;
    session.shutdown().await;
}

/// pauseAll/forcePauseAll reach the synthesis pool (pinned by a
/// review round, mirroring the check-pool shape one pool over): both synthesis faces
/// are swept. Regression form this pins: since the synthesis pool
/// landed, a media task
/// leaves the active face at its Downloading → Processing gate, so a
/// synthesizing member (processing registry) or a gate-hung driver
/// (proc_wait) was invisible to pause-all's active sweep — the permit
/// still fired and every synthesis ran to Done against the global
/// pause intent (tasks landing Complete in results). The
/// mutation-verified core: after pauseAll, no synthesis-side member
/// reaches Complete across a window far longer than an unperturbed
/// synthesis of this fixture; both members land paused (the paused
/// events carry the §3.2 phase memory — both faces produce
/// detail 'processing': the gate hang sits at the synthesis boundary
/// and the true synthesis remembers the live phase); unpauseAll
/// resumes them to their normal terminals.
/// pauseAll/forcePauseAll reach the synthesis pool (pinned by a
/// review round, mirroring the check-pool shape one pool over): both synthesis faces
/// are swept. Regression form this pins: since the synthesis pool
/// landed, a media task
/// leaves the active face at its Downloading → Processing gate, so a
/// synthesizing member (processing registry) or a gate-hung driver
/// (proc_wait) was invisible to pause-all's active sweep — the permit
/// still fired and every synthesis ran to Done against the global
/// pause intent (tasks landing Complete in results). The
/// mutation-verified core: pauseAll lands the moment the holder's
/// Processing phase event fires (a synthesis-side member is then
/// guaranteed in the registry); if the trigger→command roundtrip
/// outran the synthesis (rare), the round is voided and re-seeded —
/// a round is valid only when the member did **not** terminalize
/// around the command — and a valid round asserts three
/// Complete-free seconds (pre-fix this went red in every valid
/// round: the synthesizing member ran to Done), the §3.2 phase
/// memory riding the paused event (detail 'processing'), both
/// members requeued paused, and unpauseAll resuming them to their
/// normal terminals.
#[tokio::test]
async fn pause_all_reaches_synthesis_pool() {
    // 300 segments x 64 KiB payloads (~20 MB): the native synthesis
    // (rewrite + concat + box verify) scales with the bytes — a
    // synthesis window of tens to hundreds of milliseconds, comfortably
    // outlasting the trigger→command roundtrip.
    let src = spawn_source_sized(300, 0, 65536).await;
    let dir = tempdir("pauseall");
    let session = session_at(&dir, &dir, 1, 5).await;
    let mut media = session.subscribe_media_events();

    let mut valid = false;
    'rounds: for _ in 0..8 {
        // Two tasks, budget 1: the first gater holds the seat (the
        // processing face), the second trails (still downloading or
        // parked behind the holder) — pause-all must own every face
        // they can be on.
        let a = add_media(&session, &format!("http://{src}/master.m3u8"), &dir).await;
        let b = add_media(&session, &format!("http://{src}/master.m3u8"), &dir).await;
        let processing_ev = wait_media(
            &mut media,
            |e| e.gid.to_string() == a && e.phase.as_str() == "processing" && e.warning.is_none(),
            "holder's processing event (synthesis-side member registered)",
        )
        .await;
        let _ = processing_ev;

        assert!(matches!(
            session.call(SessionCommand::PauseAll).await,
            Ok(CommandReply::Accepted)
        ));

        // Round validity: the command must have landed while BOTH
        // members were still live (pre-command completions void the
        // round — either member may finish its whole task first,
        // download-finish order is arbitrary). A terminal entry for
        // either member settling within the window means the round
        // raced → resume any paused leftover (UnpauseAll) and re-seed.
        let raced = wait_for_opt(
            || async {
                let stopped = tell_stopped(&session).await;
                stopped.iter().any(|v| v.gid == a || v.gid == b)
            },
            Duration::from_secs(1),
        )
        .await;
        if raced {
            // Self-healing drain: a pause-flagged straggler may still be
            // mid-teardown when the first UnpauseAll passes (the flag
            // lands its paused requeue a beat later) — re-issue the
            // idempotent unpause on every tick so each straggler is
            // swept as it surfaces in the reserved face.
            wait_for(
                || async {
                    let _ = session.call(SessionCommand::UnpauseAll).await;
                    let stopped = tell_stopped(&session).await;
                    let waiting = tell_waiting(&session).await;
                    waiting.is_empty()
                        && stopped.iter().any(|v| v.gid == a)
                        && stopped.iter().any(|v| v.gid == b)
                },
                "round drain",
            )
            .await;
            continue 'rounds;
        }

        // Mutation face: no synthesis-side member terminalizes while
        // the global pause holds (pre-fix the synthesizing member ran
        // to Done here — red in every valid round).
        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            loop {
                let stopped = tell_stopped(&session).await;
                let completed: Vec<&str> = stopped
                    .iter()
                    .filter(|v| v.gid == a || v.gid == b)
                    .map(|v| if v.gid == a { "a" } else { "b" })
                    .collect();
                assert!(
                    completed.is_empty(),
                    "after pause-all, no synthesis-side task may terminalize (mutation face): \
                     completed={completed:?} \
                     a_phase={:?} b_phase={:?} waiting={:?} active={:?}",
                    media_phase(&session, &a).await,
                    media_phase(&session, &b).await,
                    tell_waiting(&session).await,
                    tell_active(&session).await,
                );
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        // A (gate-passed — the processing face at trigger time) lands
        // paused with the §3.2 phase memory (detail 'processing'); B is
        // on whichever face it had reached (mid-download on the active
        // face, or parked at the gate) — its paused landing itself is
        // the assertion (the synthesis-side memory face is A's
        // assertion plus the gate-hang round-trip test above).
        {
            let g = a.clone();
            let ev = wait_media(
                &mut media,
                move |e| {
                    e.gid.to_string() == g && e.phase.as_str() == "paused" && e.warning.is_none()
                },
                "A's paused event (synthesis-side phase memory)",
            )
            .await;
            assert_eq!(
                ev.phase_detail.as_deref(),
                Some("processing"),
                "pause phase memory lands with pause-all (the true synthesis remembers Processing)"
            );
        }
        wait_for(
            || async {
                let waiting = tell_waiting(&session).await;
                waiting
                    .iter()
                    .filter(|v| (v.gid == a || v.gid == b) && v.status == StatusKind::Paused)
                    .count()
                    == 2
            },
            "both members requeued to the paused queue (requeue front)",
        )
        .await;
        valid = true;

        // Resume face: unpauseAll clears the reserved-paused intent and
        // the members re-walk → gate → their normal terminals (one
        // synthesizes within the budget, the other parks and promotes
        // on the release).
        assert!(matches!(
            session.call(SessionCommand::UnpauseAll).await,
            Ok(CommandReply::Accepted)
        ));
        wait_for(
            || async {
                let stopped = tell_stopped(&session).await;
                stopped
                    .iter()
                    .any(|v| v.gid == a && v.status == StatusKind::Complete)
                    && stopped
                        .iter()
                        .any(|v| v.gid == b && v.status == StatusKind::Complete)
            },
            "both tasks complete after unpauseAll",
        )
        .await;
        assert_eq!(num_active(&session).await, 0);
        assert!(tell_waiting(&session).await.is_empty());
        break 'rounds;
    }
    assert!(
        valid,
        "no valid pause-all landing in any of the eight rounds (trigger race lost every round)"
    );
    session.shutdown().await;
}

/// The observation-face slice (the four-pool observation spec): ⑥'s synthesis
/// cells + ④'s three-list union coverage + ②'s processing-resident
/// cell. Synthesis budget 2 (= the default value, spelled out) with
/// three tasks racing the same fixture — two take the seats, the third
/// parks into proc_wait. At the caught parked sample: numSynthesizing
/// = 2 (in flight only — the proc_wait member is NOT counted),
/// numWaiting = the four-segment merge (== the tellWaiting count), and
/// tellActive ∪ tellWaiting ∪ tellStopped covers every gid exactly
/// once (parked members are never invisible). The processing residents
/// project 'active' in
/// tellActive/tellStatus (the gate hang is an in-task phase — no
/// status-value extension).
///
/// Escape ruling of record (deterministic wait infeasible, documented
/// fallback): the tight-loop catch races a
/// wall-clock window and keeps the documented skip escape. The
/// deterministic-wait alternatives were measured out on this suite's
/// runtime shape: (a) a state precondition `numSynthesizing == 2`
/// never converges — three racing fixtures stagger their gate
/// arrivals by roughly the seat-hold duration (both scale with the
/// fixture bytes; the measured heavy-fixture rounds peaked at one
/// occupied seat), so "both seats held while the third parks" is not
/// a waitable state; (b) per-segment download delays tune only
/// relative arrival times against a ±tens-of-ms machine-variance
/// window; (c) instrumenting the gate acquire needs a product seam —
/// the SynthesisGate is actor-injected at spawn, not test-reachable.
/// Correctness therefore anchors on the deterministic table-driven
/// unit tests, mutation-verified: dropping the proc_wait
/// segment from `QueueMan::waiting_snapshot` (the exact invisibility
/// regression this e2e's escape can silently absorb) reddens
/// `session::queue::tests::waiting_snapshot_final_segment_order_and_statuses`
/// while this e2e passes through its escape — the e2e is the
/// integration linter, the queue unit tests are the gate. The escape
/// below reports its measured miss count for exactly that reading.
#[tokio::test]
async fn four_pool_meters_and_three_list_coverage_under_gate_park() {
    let src = spawn_source_sized(60, 0, 2048).await;
    let dir = tempdir("p127-cov");
    // Budget 2 = the default value, spelled out (synthesis budget 2).
    let session = session_at(&dir, &dir, 2, 5).await;

    let mut caught = false;
    // Every gid this session ever held (the union-coverage domain:
    // earlier rounds' terminals ride tellStopped).
    let mut all_gids: Vec<String> = Vec::new();
    // The escape is measured, not silent — each missed
    // round counts, and the escape line reports the per-run rate. The
    // retry window widened 4 → 8 rounds (the catch loop drains each
    // miss in ~70 ms; the doubled window measurably lifts the catch
    // odds on fast hosts without a runtime cost worth naming).
    let mut missed_rounds = 0usize;
    let total_rounds = 8usize;
    for _round in 0..total_rounds {
        let mut trio = Vec::new();
        for _ in 0..3 {
            let g = add_media(&session, &format!("http://{src}/master.m3u8"), &dir).await;
            trio.push(g);
        }
        all_gids.extend(trio.iter().cloned());
        if let Some(parked) = catch_parked(&session, &trio, 1).await {
            caught = true;
            // The catch sample IS the park-visibility face (④'s
            // no-invisible-parked-task slice): a 'waiting'-status member stood in
            // tellWaiting while both seats were held — structurally
            // numSynthesizing was 2 at that instant (the promotion
            // gate admits only on a free seat; the arithmetic is
            // pinned table-driven in session::media::tests and at the
            // four-pool steady sample in session::actor::tests::
            // four_pool_mixed_load_global_stat_caliber). Multi-RPC
            // assertions would race the ms-scale promotion, so — the
            // established shape — remove the parked member immediately and
            // assert the **durable** faces after.
            assert!(matches!(
                session
                    .call(SessionCommand::Remove {
                        gid: parked.clone(),
                    })
                    .await,
                Ok(CommandReply::Gid(_))
            ));
            wait_for(
                || async {
                    tell_stopped(&session)
                        .await
                        .iter()
                        .any(|v| v.gid == parked && v.status == StatusKind::Removed)
                },
                "parked member remove → Removed terminal lands in results",
            )
            .await;
            assert!(
                !tell_waiting(&session).await.iter().any(|v| v.gid == parked),
                "after remove, the member left proc_wait (tellWaiting)"
            );
            let gs = global_stat(&session).await;
            assert_eq!(
                gs.num_active, 0,
                "synthesis occupies no download slot (not counted in numActive)"
            );
            assert!(
                gs.num_synthesizing <= 2,
                "synthesis seat upper bound (no seat leak; sampled value {})",
                gs.num_synthesizing
            );
            // ④: the three-list union covers every gid this session
            // ever held exactly once (earlier rounds' terminals ride
            // tellStopped). The three reads ride three RPCs — a
            // ms-scale transition (a seat finishing mid-read) races
            // the snapshot, so re-read until a settled snapshot
            // (covered AND disjoint) or a bounded attempt count.
            let mut snap = None;
            for _ in 0..20 {
                let active = tell_active(&session).await;
                let waiting = tell_waiting(&session).await;
                let stopped = tell_stopped(&session).await;
                let mut seen: Vec<String> = active.iter().map(|v| v.gid.clone()).collect();
                seen.extend(waiting.iter().map(|v| v.gid.clone()));
                seen.extend(stopped.iter().map(|v| v.gid.clone()));
                let mut sorted = seen.clone();
                sorted.sort();
                sorted.dedup();
                let mut want = all_gids.clone();
                want.sort();
                if sorted == want && seen.len() == want.len() {
                    snap = Some((waiting, gs.num_waiting));
                    break;
                }
            }
            let Some((waiting, num_waiting)) = snap else {
                panic!(
                    "three-list snapshot did not converge \
                     (coverage/disjointness still failing after 20 re-reads)"
                );
            };
            assert_eq!(
                num_waiting as usize,
                waiting.len(),
                "numWaiting = four-segment merge == the tellWaiting count"
            );
            // Drain this round's tasks out (the round loop then exits
            // via `caught`).
            {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                loop {
                    let stopped = tell_stopped(&session).await;
                    if trio.iter().all(|t| stopped.iter().any(|s| &s.gid == t)) {
                        break;
                    }
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "round drain timeout"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            break;
        }
        // This round's window was missed (the catch loop drained the
        // trio): count the miss and re-seed the next round.
        missed_rounds += 1;
    }
    if !caught {
        // Documented escape (the millisecond park window lost all
        // rounds): the park-dependent faces are skipped (the
        // established precedent); the session's steady faces are
        // asserted by the final drain below. The measured rate rides
        // the line for the escape ruling — a persistently-escaping
        // environment is
        // a coverage signal (the correctness gate is the queue unit
        // test anchor cited in the doc above), never a silent pass.
        eprintln!(
            "park window missed in all rounds (miss rate {missed_rounds}/{total_rounds}); \
             skipping park-dependent faces — correctness anchor: \
             session::queue::tests::waiting_snapshot_final_segment_order_and_statuses"
        );
    }
    // Steady faces (hold regardless of the catch): the last trio
    // completed, registries empty, every meter at zero.
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let stopped = tell_stopped(&session).await;
            if !stopped.is_empty()
                && stopped.iter().all(|v| {
                    matches!(
                        v.status,
                        StatusKind::Complete
                                | StatusKind::Error
                                // The caught parked member's
                                // intentional remove in the catch
                                // phase.
                                | StatusKind::Removed
                    )
                })
                && tell_waiting(&session).await.is_empty()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "terminal state not reached"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let gs = global_stat(&session).await;
    assert_eq!(gs.num_active, 0);
    assert_eq!(gs.num_synthesizing, 0);
    assert_eq!(gs.num_waiting, 0);
    session.shutdown().await;
}
