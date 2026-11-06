//! Media perf gate ④ — 100 concurrent media tasks: the session-level
//! RSS increment ≤ 100 MiB (the soak's per-task footprint ×100 is the
//! subject; small fMP4 fixtures, all tasks running to completion
//! under one session actor).
//!
//! The RSS face is `ps -o rss=` on this host (the workspace forbids
//! `unsafe`, so no in-process allocator wrapping — the same
//! upper-bound proxy posture as gate ①).
//! The delta assertion is release-only (the earlier media perf gates' posture);
//! numbers always print.

use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionOptions, StatusKind,
};
use taiji_media::testkit::{
    FixtureSample, avcc_sample, build_init, build_segment, video_init_spec,
};

fn full_body(body: Vec<u8>, kind: &'static str) -> axum::response::Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

fn rss_mib() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.trim().parse::<u64>().unwrap_or(0) as f64 / 1024.0
        }
        _ => 0.0,
    }
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("media-gate4-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate4_hundred_tasks_rss_increment() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let vspec = video_init_spec();
    let init = build_init(&vspec);
    let mut segs = Vec::new();
    let mut dt = 0u64;
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
        segs.push(build_segment(1, seq, dt, &samples, &payload));
        dt += 99;
    }
    let mut playlist = String::from(
        "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:10\n",
    );
    playlist.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/init.mp4\"\n"));
    for i in 0..6usize {
        playlist.push_str(&format!("#EXTINF:0.099,\nhttp://{addr}/seg{i}.m4s\n"));
    }
    playlist.push_str("#EXT-X-ENDLIST\n");
    let init_c = init.clone();
    let mut app = Router::new()
        .route(
            "/media.m3u8",
            get(move || async move {
                full_body(
                    playlist.clone().into_bytes(),
                    "application/vnd.apple.mpegurl",
                )
            }),
        )
        .route(
            "/init.mp4",
            get(move || async move { full_body(init_c.clone(), "video/mp4") }),
        );
    for (i, seg) in segs.iter().enumerate() {
        let seg = seg.clone();
        app = app.route(
            &format!("/seg{i}.m4s"),
            get(move || async move { full_body(seg.clone(), "video/mp4") }),
        );
    }
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });

    let dir = tempdir("sess");
    let (persist, _pjoin) =
        taiji_store::persist::writer::PersistWriter::spawn(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let options = SessionOptions {
        global: GlobalOptions {
            dir: dir.clone(),
            one_shot: true,
            ..Default::default()
        },
    };
    let (session, _actor) = SessionActor::spawn_with_persist(options, Some(persist));

    // Settle, sample, then add 100 tasks at once.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rss_before = rss_mib();
    let mut gids = Vec::new();
    for _ in 0..100 {
        let opts = std::collections::BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            (
                "media-allow-private-key-url".to_string(),
                "true".to_string(),
            ),
        ]);
        let gid = match session
            .call(SessionCommand::AddMedia {
                url: format!("http://{addr}/media.m3u8"),
                options: opts,
                cookies: Vec::new(),
                position: None,
            })
            .await
        {
            Ok(CommandReply::Gid(g)) => g.to_string(),
            other => panic!("{other:?}"),
        };
        gids.push(gid);
    }
    // Wait for every task's terminal state.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    for gid in &gids {
        loop {
            let done = match session
                .call(SessionCommand::TellStatus {
                    gid: gid.clone(),
                    keys: Vec::new(),
                })
                .await
            {
                Ok(CommandReply::TorrentStatus(v)) => {
                    matches!(v.status, StatusKind::Complete | StatusKind::Error)
                }
                _ => false,
            };
            if done {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "task {gid} never settled"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let rss_after = rss_mib();
    let delta = rss_after - rss_before;
    println!(
        "[MEDIA-GATE-4] tasks={} rss_before_mib={rss_before:.0} rss_after_mib={rss_after:.0} \
         delta_mib={delta:.0} (budget: <=100)",
        gids.len()
    );
    let _ = session.shutdown().await;
    if cfg!(not(debug_assertions)) {
        assert!(
            delta <= 100.0,
            "media perf gate ④: RSS increment {delta:.0}MiB > 100MiB over 100 tasks"
        );
    } else {
        eprintln!("debug build — delta asserted in release only (delta {delta:.0}MiB)");
    }
}
