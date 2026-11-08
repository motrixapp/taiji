//! The watermark watchdog coroutine-leak
//! regression. Pre-fix the 30s staging-quota sampler was a detached
//! `tokio::spawn` whose only terminations were four explicit
//! `abort()` calls inside `run` — every other exit leaked the poller:
//!
//! * the `?` early returns between the spawn and those sites
//!   (manifest-URL parse, `save_track` ledger writes, …);
//! * the outer cancel (the session drives `run` inside a
//!   `tokio::select!`; a stop tears the future down without running
//!   any of its code) — a detached spawn is never aborted by a
//!   future drop.
//!
//! Long sessions accumulated one 30s poller per task. The fix = the
//! RAII `WatchdogGuard` (drop aborts). Both leak paths are pinned
//! here through the `watchdog_observer` probe face: the captured
//! JoinHandle must terminate once the driver exits (early return or
//! drop), while the sampler is provably still alive at its spawn
//! (the control leg).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use futures::future::BoxFuture;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::trackdl::{MediaLedger, MediaTaskRecord, TrackRecord};
use taiji_media::{MediaError, SegmentRecord};

// ---------------------------------------------------------------------------
// mock source: a media-playlist task (the direct-entry form — one
// video track of unknown-length segments, the (b) layer), a slow
// per-segment cadence (the cancel seam), and a plain fast form.
// ---------------------------------------------------------------------------

fn ts_body(seq: u64) -> Vec<u8> {
    format!("SEGDATA{seq}").into_bytes()
}

async fn spawn_source(seg_delay_ms: u64) -> (SocketAddr, Arc<AtomicU64>) {
    let hits = Arc::new(AtomicU64::new(0));
    let hits2 = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let hits = hits2;
    let media = {
        let mut m = String::from("#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:2\n");
        for i in 0..4u64 {
            m.push_str(&format!("#EXTINF:1.0,\nhttp://{addr}/seg{i}.ts\n"));
        }
        m.push_str("#EXT-X-ENDLIST\n");
        m
    };
    let app = Router::new().route(
        "/media.m3u8",
        get(move || async move {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")],
                media,
            )
                .into_response()
        }),
    );
    let mut app = app;
    for i in 0..4u64 {
        let hits = Arc::clone(&hits);
        let body = ts_body(i);
        let delay = seg_delay_ms;
        app = app.route(
            &format!("/seg{i}.ts"),
            get(move || async move {
                hits.fetch_add(1, Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                (StatusCode::OK, [(header::CONTENT_TYPE, "video/mp2t")], body).into_response()
            }),
        );
    }
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    (addr, hits)
}

// ---------------------------------------------------------------------------
// ledger: an in-memory minimal MediaLedger whose save_track fails on
// demand (the `?` early-exit seam of the leak path ①).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ProbeLedger {
    fail_save_track: std::sync::Mutex<bool>,
}

impl MediaLedger for ProbeLedger {
    fn ensure_task<'a>(
        &'a self,
        _row: &'a MediaTaskRecord,
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn save_track<'a>(
        &'a self,
        _gid: &'a str,
        _track: &'a TrackRecord,
        _segments: &'a [SegmentRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        let fail = *self
            .fail_save_track
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Box::pin(std::future::ready(if fail {
            Err(MediaError::Staging("injected save_track failure".into()))
        } else {
            Ok(())
        }))
    }

    fn load_track<'a>(
        &'a self,
        _gid: &'a str,
        _track_idx: usize,
    ) -> BoxFuture<'a, Result<taiji_media::trackdl::LoadedTrack, MediaError>> {
        Box::pin(std::future::ready(Ok(None)))
    }

    fn upsert_media_keys<'a>(
        &'a self,
        _gid: &'a str,
        _keys: &'a [taiji_media::keys::KeyRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn load_media_keys<'a>(
        &'a self,
        _gid: &'a str,
    ) -> BoxFuture<'a, Result<Vec<taiji_media::keys::KeyRecord>, MediaError>> {
        Box::pin(std::future::ready(Ok(Vec::new())))
    }
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("taiji-media-leak-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
    path
}

type Handles = Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>;

fn download(out_dir: &std::path::Path, handles: Handles) -> MediaDownload {
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
    let mut dl = MediaDownload::new(
        "8000000000000123",
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: out_dir.to_path_buf(),
            // The mock lives on the loopback (the documented lab
            // posture; no DNS face is exercised here).
            allow_private_key_url: true,
            ..MediaDownloadConfig::default()
        },
    );
    dl.watchdog_observer = Some(Arc::new(move |handle| {
        handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(handle);
    }));
    dl
}

/// Wait until every captured handle reports finished (the abort is
/// reaped asynchronously; bounded wait).
async fn await_all_finished(handles: &Handles) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let all = handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .all(|h| h.is_finished());
        if all {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// Leak path ① (the `?` early return): a `save_track` ledger failure
/// after the watchdog spawn makes `run` return `Err` before any of
/// the old explicit abort sites — pre-fix the sampler survived the
/// return and looped forever. Post-fix the RAII guard aborts it: the
/// captured handle finishes.
#[tokio::test]
async fn watchdog_dies_on_early_return() {
    let (addr, _hits) = spawn_source(0).await;
    let out = tempdir("early");
    let handles: Handles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ledger = ProbeLedger::default();
    *ledger
        .fail_save_track
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = true;
    let dl = download(&out, Arc::clone(&handles));
    let res = dl.run(&format!("http://{addr}/media.m3u8"), &ledger).await;
    assert!(res.is_err(), "the injected ledger failure surfaces");
    assert!(
        await_all_finished(&handles).await,
        "the watchdog coroutine must terminate when run returns early (the leak fix)"
    );
}

/// Leak path ② (the outer cancel): the driving future is dropped
/// mid-track (the session's select! shape) — pre-fix nothing aborted
/// the detached sampler. Post-fix the guard's drop (part of the
/// dropped future's locals) aborts it.
#[tokio::test]
async fn watchdog_dies_on_outer_cancel() {
    let (addr, hits) = spawn_source(300).await;
    let out = tempdir("cancel");
    let handles: Handles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ledger = ProbeLedger::default();
    let dl = download(&out, Arc::clone(&handles));
    {
        let url = format!("http://{addr}/media.m3u8");
        let run = dl.run(&url, &ledger);
        tokio::pin!(run);
        // Mid-track cancel: the first slow segment is in flight (the
        // driver is inside the track fetch, past the spawn).
        tokio::select! {
            _ = &mut run => panic!("the slow source must not finish before the cancel"),
            _ = tokio::time::sleep(Duration::from_millis(150)) => {}
        }
        // Drop happens here (the pinned future goes out of scope).
    }
    assert!(hits.load(Ordering::SeqCst) >= 1, "a segment was in flight");
    assert!(
        await_all_finished(&handles).await,
        "the watchdog coroutine must terminate when the driver future is dropped (the leak fix)"
    );
}

/// Control leg: exactly one sampler per run, and none survives the
/// normal return (the happy path is leak-free too; the spawn count
/// anchors the two leak legs — their assertions are about this very
/// handle's termination).
#[tokio::test]
async fn watchdog_spawns_then_dies_on_normal_return() {
    let (addr, _hits) = spawn_source(0).await;
    let out = tempdir("happy");
    let handles: Handles = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ledger = ProbeLedger::default();
    let dl = download(&out, Arc::clone(&handles));
    let report = dl
        .run(&format!("http://{addr}/media.m3u8"), &ledger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    assert!(!report.tracks.is_empty());
    {
        let got = handles.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(got.len(), 1, "exactly one sampler per run");
    }
    assert!(
        await_all_finished(&handles).await,
        "no sampler survives the normal return either"
    );
}
