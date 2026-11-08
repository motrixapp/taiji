//! Soak deliverable 3①: the kill×70 crash soak — the media recovery
//! matrix extended to a randomized 70-round soak over the media task
//! family (the kill-soak / multi-seed precedents).
//!
//! Round shape: a deterministic seed (xorshift64, round-indexed)
//! picks the download form — the (a) grid layer (BYTERANGE over one
//! resource) or the (b) seg_bitmap layer (plain segments) — the
//! interrupted phase (downloading / processing / verifying / paused),
//! and the kill timing (which segment hit to die after, or the
//! post-phase race window). Each round kills the session (the
//! root-token cancel = the established crash shape), then asserts the §8
//! recovery invariants:
//!
//! * **bitmap vs archive reconciliation**: the killed track's
//!   archive length equals Σ seg_len over the done prefix (and the
//!   final archive equals Σ over ALL segments) — zero false records
//!   by construction (a bit never outruns delivered bytes);
//! * **truncation to the last complete segment boundary**: the same
//!   equality after restart, before any re-download lands;
//! * **phase re-entry**: the restarted session re-enters by the
//!   persisted phase and the task completes (product in place).
//!
//! Verdict discipline: every round asserts to a terminal
//! outcome — a round that never completes is a failure, never a skip.
//! The per-round log lines (visible under --nocapture) are the soak's
//! required "output trace" evidence.

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

// ---------------------------------------------------------------------------
// deterministic PRNG (std-only; multi-seed posture)
// ---------------------------------------------------------------------------

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

// ---------------------------------------------------------------------------
// the dual-form source: (a) BYTERANGE grid + (b) plain segments
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Hits {
    grid: Arc<AtomicU64>,
    seg: Arc<AtomicU64>,
}

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

struct Fixture {
    grid_playlist: String,
    seg_playlist: String,
    init: Vec<u8>,
    segs: Vec<Vec<u8>>,
    blob: Vec<u8>,
}

fn build_fixture(addr: &SocketAddr, n_segments: usize) -> Fixture {
    // The shared media: one fMP4 track (testkit builder — the fold's
    // accepted per-track form), used by BOTH layers:
    // * (a) the single-file form — the blob = init span + per-segment
    // spans, MAP BYTERANGE + segment BYTERANGEs (explicit offsets;
    // the known-length grid layer);
    // * (b) whole-resource segments, non-zero sequence.
    let vspec = video_init_spec();
    let init = build_init(&vspec);
    let mut segs = Vec::new();
    let mut decode_time = 0u64;
    for seq in 0..n_segments as u32 {
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
        segs.push(build_segment(1, seq, decode_time, &samples, &payload));
        decode_time += 99;
    }
    let mut blob = init.clone();
    let mut spans: Vec<(u64, u64)> = Vec::new(); // (offset, len)
    for seg in &segs {
        spans.push((blob.len() as u64, seg.len() as u64));
        blob.extend_from_slice(seg);
    }
    let mut grid = String::from(
        "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:500\n",
    );
    grid.push_str(&format!(
        "#EXT-X-MAP:URI=\"http://{addr}/blob.bin\",BYTERANGE=\"{}@0\"\n",
        init.len()
    ));
    for (i, (off, len)) in spans.iter().enumerate() {
        grid.push_str(&format!(
            "#EXTINF:0.099,\n#EXT-X-BYTERANGE:{len}@{off}\nhttp://{addr}/blob.bin\n"
        ));
        let _ = i;
    }
    grid.push_str("#EXT-X-ENDLIST\n");

    let mut segp = String::from(
        "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:9000\n",
    );
    segp.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/sinit.mp4\"\n"));
    for i in 0..n_segments {
        segp.push_str(&format!("#EXTINF:0.099,\nhttp://{addr}/seg{i}.m4s\n"));
    }
    segp.push_str("#EXT-X-ENDLIST\n");
    Fixture {
        grid_playlist: grid,
        seg_playlist: segp,
        init,
        segs,
        blob,
    }
}

async fn spawn_source(n_segments: usize) -> (SocketAddr, Hits) {
    let hits = Hits::default();
    let h2 = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let fx = build_fixture(&addr, n_segments);
    let grid_hits = h2.grid.clone();
    let blob = fx.blob.clone();
    let seg_hits = h2.seg.clone();
    let init2 = fx.init.clone();
    let app = Router::new()
        .route(
            "/grid.m3u8",
            get(move || async move {
                full_body(
                    fx.grid_playlist.clone().into_bytes(),
                    "application/vnd.apple.mpegurl",
                )
            }),
        )
        .route(
            "/seg.m3u8",
            get(move || async move {
                full_body(
                    fx.seg_playlist.clone().into_bytes(),
                    "application/vnd.apple.mpegurl",
                )
            }),
        )
        .route(
            "/sinit.mp4",
            get(move || async move { full_body(init2.clone(), "video/mp4") }),
        )
        .route(
            "/blob.bin",
            get(move |req: axum::extract::Request| async move {
                let hits = grid_hits.clone();
                hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                // Honor one Range GET per grid block (the (a)-layer
                // transport's merged fetches).
                let range = req
                    .headers()
                    .get(header::RANGE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if range.is_empty() {
                    return full_body(blob.clone(), "application/octet-stream");
                }
                let spec = range.trim().strip_prefix("bytes=").unwrap_or("");
                let (a, b) = spec
                    .split_once('-')
                    .map(|(a, b)| {
                        (
                            a.parse::<u64>().unwrap_or(0),
                            b.parse::<u64>().unwrap_or(u64::MAX),
                        )
                    })
                    .unwrap_or((0, u64::MAX));
                let end = (b + 1).min(blob.len() as u64);
                let body = blob[a as usize..end as usize].to_vec();
                let mut resp = Response::new(axum::body::Body::from(body));
                *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
                resp.headers_mut().insert(
                    header::CONTENT_RANGE,
                    axum::http::HeaderValue::from_str(&format!("bytes {a}-{}/{end}", end - 1))
                        .unwrap_or_else(|e| panic!("{e}")),
                );
                resp
            }),
        );
    let mut app = app;
    for (i, seg) in fx.segs.iter().enumerate() {
        let seg = seg.clone();
        let hits = seg_hits.clone();
        app = app.route(
            &format!("/seg{i}.m4s"),
            get(move || async move {
                hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                full_body(seg.clone(), "video/mp4")
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
// harness (the media_task_e2e shapes)
// ---------------------------------------------------------------------------

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("media-soak-{tag}-{}-{n}", std::process::id()));
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

fn media_options(dir: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([
        ("dir".to_string(), dir.display().to_string()),
        (
            "media-allow-private-key-url".to_string(),
            "true".to_string(),
        ),
    ])
}

async fn media_row_state(dir: &std::path::Path, gid: &str) -> Option<String> {
    let (persist, _join) =
        taiji_store::persist::writer::PersistWriter::spawn(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let row = persist
        .load_media_task(gid)
        .await
        .unwrap_or_else(|e| panic!("row load: {e}"));
    drop(persist);
    row.map(|r| r.state)
}

/// Wait for the kill threshold or the task's natural completion
/// (whichever first — a fast task degenerates the round into
/// crash-after-done, itself a recovery face: the done row restarts
/// intact and the product stays).
async fn wait_hits_or_done(
    session: &taiji_core::session::SessionHandle,
    gid: &str,
    counter: &AtomicU64,
    target: u64,
) -> bool {
    let base = counter.load(Ordering::SeqCst);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if counter.load(Ordering::SeqCst) >= base + target {
            return true;
        }
        if let Ok(CommandReply::TorrentStatus(v)) = session
            .call(SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: Vec::new(),
            })
            .await
            && matches!(v.status, StatusKind::Complete | StatusKind::Error)
        {
            return false;
        }

        assert!(
            tokio::time::Instant::now() < deadline,
            "neither the hit threshold nor a terminal state arrived"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn kill_session(session: &taiji_core::session::SessionHandle) {
    let _ = tokio::time::timeout(Duration::from_secs(5), session.shutdown()).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
}

async fn wait_terminal(
    session: &taiji_core::session::SessionHandle,
    dir: &std::path::Path,
    gid: &str,
) -> StatusKind {
    // TellStatus carries the live face; a done row that completed
    // around the kill (the crash-after-done degenerate round) may not
    // be visible there — the DB row is the terminal truth this soak
    // reconciles against (the product + ledger checks follow).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut next_db_poll = tokio::time::Instant::now();
    loop {
        // A transient/not-found reply keeps polling under the deadline.
        if let Ok(CommandReply::TorrentStatus(v)) = session
            .call(SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: Vec::new(),
            })
            .await
            && matches!(v.status, StatusKind::Complete | StatusKind::Error)
        {
            return v.status;
        }
        if tokio::time::Instant::now() >= next_db_poll {
            next_db_poll = tokio::time::Instant::now() + Duration::from_millis(200);
            match media_row_state(dir, gid).await.as_deref() {
                Some("done") => return StatusKind::Complete,
                Some("error") => return StatusKind::Error,
                _ => {}
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "round never reached a terminal state (gid {gid})"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The killed state's ledger + archive reconciliation: for every
/// track row, archive file length == Σ seg_len over the DONE prefix
/// of the bitmap (the §8 invariants: reconciliation + truncation to
/// the last complete segment boundary + zero false records — a set
/// bit never outruns delivered bytes).
///
/// A `done` task may already have run the success cleanup (staging
/// removed, product in place) — the ledger rows remain as the
/// delivery proof; the archive check then yields to the product
/// check. A missing archive with an unfinished row is only legal
/// when nothing was delivered yet (done prefix 0).
async fn assert_reconciliation(
    dir: &std::path::Path,
    gid: &str,
    row_done: bool,
) -> (usize, usize, u64) {
    let (persist, _join) =
        taiji_store::persist::writer::PersistWriter::spawn(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let tracks = persist
        .load_media_tracks(gid)
        .await
        .unwrap_or_else(|e| panic!("load tracks: {e}"));
    drop(persist);
    let mut total_done = 0usize;
    let mut total = 0usize;
    let mut archived = 0u64;
    for (track, segments) in &tracks {
        let done = bitmap_prefix(track.seg_bitmap.as_deref().unwrap_or(&[]));
        let sum_done: u64 = segments.iter().take(done).map(|s| s.seg_len as u64).sum();
        let sum_all: u64 = segments.iter().map(|s| s.seg_len as u64).sum();
        let archive_path = dir.join(".taiji-b").join(gid).join(&track.local_name);
        match std::fs::metadata(&archive_path) {
            Ok(m) => {
                let archive_len = m.len();
                assert!(
                    archive_len == sum_done || archive_len == sum_all,
                    "reconciliation: track {} archive {archive_len} != done-prefix \
                     {sum_done} (all {sum_all}) — bitmap/archive disagree \
                     (zero-false-record breach)",
                    track.local_name
                );
                archived += archive_len;
            }
            Err(_) => {
                // No archive on disk: legal only for a finished (and
                // cleaned) task or a nothing-delivered prefix.
                assert!(
                    row_done || sum_done == 0,
                    "track {} archive missing with a {sum_done}-byte done prefix \
                     (unfinished row lost its staging)",
                    track.local_name
                );
            }
        }
        total_done += done;
        total += segments.len();
    }
    (total_done, total, archived)
}

fn bitmap_prefix(bytes: &[u8]) -> usize {
    // The pack form (trackdl::pack_bitmap): LSB-first per byte, the
    // done-prefix is the leading run of set bits.
    let mut n = 0usize;
    for b in bytes {
        for bit in 0..8 {
            if (b >> bit) & 1 == 1 {
                n += 1;
            } else {
                return n;
            }
        }
    }
    n
}

// ---------------------------------------------------------------------------

// the soak
// ---------------------------------------------------------------------------

/// The soak's base seed (round r uses DEFAULT_SEED + r·φ; re-roll the
/// whole soak with MEDIA_KILL_SEED0).
const DEFAULT_SEED: u64 = 0x5EED_0000_00C0_FFEE;

#[tokio::test]
async fn kill_x70_crash_soak() {
    // 70 rounds; seeds round-indexed (deterministic; MEDIA_KILL_SEED0
    // re-rolls the whole soak).
    let seed0: u64 = std::env::var("MEDIA_KILL_SEED0")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SEED);
    let rounds: u64 = std::env::var("MEDIA_KILL_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(70);
    let (addr, hits) = spawn_source(12).await;
    let mut stats: std::collections::BTreeMap<String, usize> = Default::default();
    for r in 0..rounds {
        let mut rng = XorShift(seed0.wrapping_add(r.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1);
        let phase = match rng.below(4) {
            0 => "downloading",
            1 => "processing",
            2 => "verifying",
            _ => "paused",
        };
        // The paused leg always takes the (b) form: the grid layer's
        // ≤8-adjacent-merge collapses the whole short track into 1-2
        // GETs, so a mid-download pause on the grid form is a race
        // against completion, not a controllable kill point (the
        // downloading/processing/verifying legs cover the grid form).
        let form = if phase == "paused" || rng.below(2) == 0 {
            "segbmp"
        } else {
            "grid"
        };
        let path = if form == "grid" {
            "/grid.m3u8"
        } else {
            "/seg.m3u8"
        };
        let kill_after: u64 = if form == "grid" {
            1 + rng.below(2)
        } else {
            1 + rng.below(8)
        }; // deliveries before the kill
        let dir = tempdir(&format!("r{r}"));
        let tag = format!("round {r}: form={form} phase={phase} kill_after={kill_after}");
        let gid = {
            let session = session_at(&dir, &dir).await;
            let mut phases = session.subscribe_media_events();
            let gid = match session
                .call(SessionCommand::AddMedia {
                    url: format!("http://{addr}{path}"),
                    options: media_options(&dir),
                    cookies: Vec::new(),
                    position: None,
                })
                .await
            {
                Ok(CommandReply::Gid(g)) => g.to_string(),
                other => panic!("{tag}: {other:?}"),
            };
            match phase {
                "downloading" => {
                    // Die after `kill_after` deliveries of the chosen
                    // form (randomized kill timing; a task that
                    // completes first degenerates the round).
                    let counter = if form == "grid" {
                        &hits.grid
                    } else {
                        &hits.seg
                    };
                    let _ = wait_hits_or_done(&session, &gid, counter, kill_after).await;
                }
                "paused" => {
                    let counter = if form == "grid" {
                        &hits.grid
                    } else {
                        &hits.seg
                    };
                    let still_live = wait_hits_or_done(&session, &gid, counter, kill_after).await;
                    if still_live {
                        let _ = session
                            .call(SessionCommand::Pause { gid: gid.clone() })
                            .await;
                        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
                        loop {
                            if let Ok(CommandReply::TorrentStatus(v)) = session
                                .call(SessionCommand::TellStatus {
                                    gid: gid.clone(),
                                    keys: Vec::new(),
                                })
                                .await
                                && v.status == StatusKind::Paused
                            {
                                break;
                            }
                            assert!(
                                tokio::time::Instant::now() < deadline,
                                "{tag}: never paused"
                            );
                            tokio::time::sleep(Duration::from_millis(15)).await;
                        }
                    }
                }
                "processing" | "verifying" => {
                    // Race the phase: wait for the phase event, then a
                    // randomized small window before the kill.
                    let window = Duration::from_millis(rng.below(40));
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                    loop {
                        let ev = tokio::time::timeout_at(deadline, phases.recv())
                            .await
                            .unwrap_or_else(|_| panic!("{tag}: phase timeout"))
                            .unwrap_or_else(|_| panic!("{tag}: bus closed"));
                        if ev.warning.is_none() && ev.phase.as_str() == phase {
                            break;
                        }
                    }
                    tokio::time::sleep(window).await;
                }
                _ => unreachable!(),
            }
            kill_session(&session).await;
            drop(session);
            gid
        };
        // Post-kill reconciliation (the §8 invariants on the killed
        // state, before any recovery traffic).
        let killed_row_done = media_row_state(&dir, &gid).await.as_deref() == Some("done");
        let (done, total, archived) = assert_reconciliation(&dir, &gid, killed_row_done).await;
        // Phase re-entry: the fresh session re-enters and completes
        // (a paused row restarts ReservedPaused — no auto-activation;
        // the unpause is the driver of the resumed run, the recovery
        // matrix's posture).
        let session2 = session_at(&dir, &dir).await;
        if phase == "paused" {
            // The unpause must land AFTER the bootstrap restored the
            // row (an unpause racing the requeue is a no-op and the
            // row would sit ReservedPaused forever).
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                if session2
                    .call(SessionCommand::TellStatus {
                        gid: gid.clone(),
                        keys: Vec::new(),
                    })
                    .await
                    .is_ok()
                {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{tag}: the killed row never restored"
                );
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            let _ = session2
                .call(SessionCommand::Unpause { gid: gid.clone() })
                .await;
        }
        let status = wait_terminal(&session2, &dir, &gid).await;
        assert_eq!(
            status,
            StatusKind::Complete,
            "{tag}: re-entry did not complete (killed at {done}/{total}, {archived}B)"
        );
        assert!(
            dir.join("seg.mp4").exists() || dir.join("grid.mp4").exists(),
            "{tag}: the product lands"
        );
        // Final reconciliation: the whole track delivered (the done
        // row's staging may be cleaned — the ledger + product carry
        // the proof).
        let (done2, total2, archived2) = assert_reconciliation(&dir, &gid, true).await;
        assert_eq!(
            done2, total2,
            "{tag}: full delivery after re-entry ({done2}/{total2})"
        );
        println!(
            "{tag} seed={} killed@{done}/{total} ({archived}B) -> recovered {done2}/{total2} ({archived2}B) OK",
            seed0.wrapping_add(r.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1
        );
        *stats.entry(format!("{form}/{phase}")).or_default() += 1;
    }
    println!("kill×{rounds} soak complete: {stats:?}");
}
