//! CLI e2e: `taiji media download <url>` end to end against a
//! mock HLS source — the one-shot drive runs the same SessionActor
//! pipeline as the RPC face (exit 0 on the verified product; exit 1 on
//! task failure; exit 2 on option-domain rejection).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_media::testkit::{
    FixtureSample, audio_init_spec, avcc_sample, build_init, build_segment, sample_bytes,
    video_init_spec,
};

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

async fn spawn_source() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let a = addr;
    let app = Router::new()
        .route(
            "/master.m3u8",
            get(move || async move {
                full_body(
                    format!(
                        "#EXTM3U\n\
                         #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en\",NAME=\"EN\",DEFAULT=YES,URI=\"http://{a}/audio.m3u8\"\n\
                         #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,CODECS=\"avc1.64001f,mp4a.40.2\",AUDIO=\"aud\"\n\
                         http://{a}/v.m3u8\n"
                    )
                    .into_bytes(),
                    "application/vnd.apple.mpegurl",
                )
            }),
        )
        .route(
            "/v.m3u8",
            get(move || async move {
                full_body(
                    format!(
                        "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n\
                         #EXT-X-MEDIA-SEQUENCE:1\n#EXT-X-MAP:URI=\"http://{a}/vinit.mp4\"\n\
                         #EXTINF:0.099,\nhttp://{a}/vseg0.m4s\n#EXTINF:0.099,\nhttp://{a}/vseg1.m4s\n\
                         #EXTINF:0.099,\nhttp://{a}/vseg2.m4s\n#EXT-X-ENDLIST\n"
                    )
                    .into_bytes(),
                    "application/vnd.apple.mpegurl",
                )
            }),
        )
        .route(
            "/audio.m3u8",
            get(move || async move {
                full_body(
                    format!(
                        "#EXTM3U\n#EXT-X-TARGETDURATION:1\n\
                         #EXT-X-MAP:URI=\"http://{a}/ainit.mp4\"\n\
                         #EXTINF:0.0928,\nhttp://{a}/aseg0.m4s\n#EXTINF:0.0928,\nhttp://{a}/aseg1.m4s\n\
                         #EXT-X-ENDLIST\n"
                    )
                    .into_bytes(),
                    "application/vnd.apple.mpegurl",
                )
            }),
        );
    let vinit = build_init(&video_init_spec());
    let ainit = build_init(&audio_init_spec());
    let mut vsegs: Vec<Vec<u8>> = Vec::new();
    let mut dt = 0u64;
    for seq in 0..3u32 {
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
        vsegs.push(build_segment(1, seq, dt, &samples, &payload));
        dt += 99;
    }
    let mut asegs: Vec<Vec<u8>> = Vec::new();
    let mut adt = 0u64;
    for seq in 0..2u32 {
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
            .flat_map(|(i, s)| sample_bytes(40 + seq as u8 + i as u8, s.size as usize).into_iter())
            .collect();
        asegs.push(build_segment(1, seq, adt, &samples, &payload));
        adt += 4096;
    }
    let app = app
        .route(
            "/vinit.mp4",
            get(move || async move { full_body(vinit.clone(), "video/mp4") }),
        )
        .route(
            "/ainit.mp4",
            get(move || async move { full_body(ainit.clone(), "video/mp4") }),
        );
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut app = app;
    for (i, seg) in vsegs.into_iter().enumerate() {
        app = app.route(
            &format!("/vseg{i}.m4s"),
            get(move || async move { full_body(seg.clone(), "video/mp4") }),
        );
    }
    for (i, seg) in asegs.into_iter().enumerate() {
        app = app.route(
            &format!("/aseg{i}.m4s"),
            get(move || async move { full_body(seg.clone(), "video/mp4") }),
        );
    }
    let _ = SEQ.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

fn tempdir(tag: &str) -> PathBuf {
    static SEQ2: AtomicU64 = AtomicU64::new(0);
    let n = SEQ2.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("media-cli-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

/// The happy path: exit 0, the product at the sanitized name, staging
/// cleaned. The SSRF allow flag rides `--media-allow-private-key-url`
/// (the loopback mock, the established SSRF-test precedent).
#[tokio::test(flavor = "multi_thread")]
async fn cli_media_download_completes() {
    let addr = spawn_source().await;
    // Server liveness probe (a direct fetch before spawning the CLI —
    // a dead mock must fail here, not as a CLI timeout).
    {
        let client = taiji_http::client::HttpClient::new(Default::default())
            .unwrap_or_else(|e| panic!("client: {e}"));
        let followed = client
            .get(
                &format!("http://{addr}/master.m3u8"),
                &taiji_http::traits::RequestCtx::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("mock reachable: {e}"));
        let mut body = Vec::new();
        let mut resp = followed.response;
        while let Some(chunk) = resp.chunk().await.unwrap_or_else(|e| panic!("chunk: {e}")) {
            body.extend_from_slice(&chunk);
        }
        assert!(body.starts_with(b"#EXTM3U"), "the master body");
    }
    let dir = tempdir("ok");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_taiji"))
        .args([
            "media",
            "download",
            &format!("http://{addr}/master.m3u8"),
            "--dir",
            dir.display().to_string().as_str(),
            "--sqlite3-db-path",
            dir.join("t.sqlite3").display().to_string().as_str(),
            "--media-allow-private-key-url=true",
        ])
        .env("RUST_LOG", "info")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    let code = out.status.code();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    std::fs::write(dir.join("cli-stderr.log"), &stderr).ok();
    assert_eq!(code, Some(0), "exit 0 on the verified product\n{stderr}");
    assert!(dir.join("master.mp4").exists(), "the product is in place");
    assert!(
        !dir.join(".taiji-b").exists()
            || std::fs::read_dir(dir.join(".taiji-b"))
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
        "staging cleaned at Done"
    );
}

/// Option-domain rejection: an out-of-domain `--media-segment-
/// concurrency` exits 2 with the `taiji.option.invalid` face (the
/// require_equals discipline's strict parse).
#[tokio::test(flavor = "multi_thread")]
async fn cli_media_rejects_out_of_domain_flags() {
    let addr = spawn_source().await;
    let dir = tempdir("bad");
    let out = Command::new(env!("CARGO_BIN_EXE_taiji"))
        .args([
            "media",
            "download",
            &format!("http://{addr}/master.m3u8"),
            "--dir",
            dir.display().to_string().as_str(),
            "--sqlite3-db-path",
            dir.join("t.sqlite3").display().to_string().as_str(),
            "--media-segment-concurrency=999",
        ])
        .output()
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    assert_eq!(out.status.code(), Some(2), "the option-domain exit");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        text.contains("taiji.option.invalid"),
        "the strict parse face: {text}"
    );
}

/// A task-level failure: exit 1 (an unreachable manifest — the CLI
/// surfaces the honest task error; the classification faces are
/// pinned in the taiji-core e2e).
#[tokio::test(flavor = "multi_thread")]
async fn cli_media_task_failure_exits_one() {
    let addr = spawn_source().await;
    let dir = tempdir("nm");
    let out = Command::new(env!("CARGO_BIN_EXE_taiji"))
        .args([
            "media",
            "download",
            &format!("http://{addr}/missing.m3u8"),
            "--dir",
            dir.display().to_string().as_str(),
            "--sqlite3-db-path",
            dir.join("t.sqlite3").display().to_string().as_str(),
            "--media-allow-private-key-url=true",
        ])
        .output()
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    assert_eq!(out.status.code(), Some(1), "task failure exit");
}
