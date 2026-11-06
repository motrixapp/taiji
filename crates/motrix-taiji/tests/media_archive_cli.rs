//! CLI-face e2e: the real `taiji media download` binary
//! against a loopback HLS mock — the archive lifecycle through the
//! CLI flag family:
//!
//! 1. `--media-archive=true` download → exit 0, the archive row lands;
//! 2. the same URL re-run (rotated query) → the checkpoint-1 skip:
//! exit 0 with **zero** payload fetches (the mock counts);
//! 3. `--media-archive-clear=true` (the one-shot pre-clear) + the
//! same URL → exit 0 and the payload face is hit again (a full
//! re-download — the clear-then-redownload premise, through the
//! `taiji.clearMediaArchive` session face).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_media::testkit::{
    FixtureSample, avcc_sample, build_init, build_segment, video_init_spec,
};

fn body(bytes: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], bytes).into_response()
}

fn fixture_segment(seq: u32, decode_time: u64) -> Vec<u8> {
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
        .flat_map(|(i, s)| avcc_sample(i == 0, s.size as usize))
        .collect();
    build_segment(1, seq, decode_time, &samples, &payload)
}

async fn spawn_source(payload_hits: Arc<AtomicU64>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let init = build_init(&video_init_spec());
    let segs: Vec<Vec<u8>> = (0..3u32)
        .map(|i| fixture_segment(i, u64::from(i) * 99))
        .collect();
    let payload_hits2 = Arc::clone(&payload_hits);
    let app = Router::new()
        .route(
            "/v.m3u8",
            get(move || {
                let mut video = String::from(
                    "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:0\n",
                );
                video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/vinit.mp4\"\n"));
                for i in 0..3 {
                    video.push_str(&format!("#EXTINF:0.099,\nhttp://{addr}/vseg{i}.m4s\n"));
                }
                video.push_str("#EXT-X-ENDLIST\n");
                async move { body(video.into_bytes(), "application/vnd.apple.mpegurl") }
            }),
        )
        .route(
            "/master.m3u8",
            get(move || {
                let text = format!(
                    "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240\nhttp://{addr}/v.m3u8\n"
                );
                async move { body(text.into_bytes(), "application/vnd.apple.mpegurl") }
            }),
        )
        .route(
            "/vinit.mp4",
            get(move || {
                let hits = Arc::clone(&payload_hits2);
                let bytes = init.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    body(bytes, "video/mp4")
                }
            }),
        );
    let mut app = app;
    for (i, seg) in segs.into_iter().enumerate() {
        let hits = Arc::clone(&payload_hits);
        app = app.route(
            &format!("/vseg{i}.m4s"),
            get(move || {
                let hits = Arc::clone(&hits);
                let bytes = seg.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    body(bytes, "video/mp4")
                }
            }),
        );
    }
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

fn tempdir(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("media-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

fn run_cli(args: &[&str]) -> (i32, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_taiji"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn taiji: {e}"));
    (
        out.status.code().unwrap_or(-1),
        format!(
            "stderr: {} stdout: {}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        ),
    )
}

/// multi_thread flavor: the blocking `Command::output()` must not
/// starve the in-test axum server (a single-threaded runtime parks
/// the server task while the CLI child waits on it — the 60s
/// transport-timeout failure mode).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_lifecycle_through_the_cli() {
    let payload_hits = Arc::new(AtomicU64::new(0));
    let addr = spawn_source(Arc::clone(&payload_hits)).await;
    let dir = tempdir("e2e");
    let db = dir.join("taiji.sqlite3");
    let url = format!("http://{addr}/master.m3u8");
    let db_arg = format!("--sqlite3-db-path={}", db.display());
    let dir_arg = format!("--dir={}", dir.display());

    // (1) The archiving download.
    let (code, stderr) = run_cli(&[
        "media",
        "download",
        &url,
        &db_arg,
        &dir_arg,
        "--media-allow-private-key-url=true",
        "--media-archive=true",
    ]);
    assert_eq!(code, 0, "first download exits 0: {stderr}");
    let after_first = payload_hits.load(Ordering::SeqCst);
    assert!(after_first >= 4, "a real download happened ({after_first})");
    assert!(dir.join("master.mp4").is_file());

    // (2) The duplicate skip: the same URL with a rotated query —
    // zero payload fetches.
    let (code, stderr) = run_cli(&[
        "media",
        "download",
        &format!("{url}?token=cli-2"),
        &db_arg,
        &dir_arg,
        "--media-allow-private-key-url=true",
        "--media-archive=true",
    ]);
    assert_eq!(code, 0, "the skip exits 0 (Done-shaped): {stderr}");
    assert_eq!(
        payload_hits.load(Ordering::SeqCst),
        after_first,
        "checkpoint 1 spends zero payload traffic"
    );

    // (3) The one-shot pre-clear + the same URL: a full re-download.
    let (code, stderr) = run_cli(&[
        "media",
        "download",
        &url,
        &db_arg,
        &dir_arg,
        "--media-allow-private-key-url=true",
        "--media-archive=true",
        "--media-archive-clear=true",
    ]);
    assert_eq!(code, 0, "clear-then-download exits 0: {stderr}");
    assert!(
        payload_hits.load(Ordering::SeqCst) > after_first,
        "after the clear the same fingerprint re-downloads"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
