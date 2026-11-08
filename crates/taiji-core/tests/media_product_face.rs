//! Product-face acceptance e2e (the template matrix, the archive
//! checkpoints, the info.json export, and the DASH metadata wiring)
//! over the session pipeline (the addMedia face → the mock source →
//! the Done close-out), asserting:
//!
//! * **template matrix** — the default `{id}.{ext}` shape, the
//!   six-field explicit template, the missing-field `NA` convention,
//!   the unknown-field `taiji.option.invalid` refusal with **zero
//!   segment traffic**, the sanitization rewrite (warning + the
//!   sanitized name used + the row read-back consistent), and the HLS
//!   `{title}` = `NA` anchor (no standard HLS title source — never
//!   synthesized);
//! * **DASH value-domain wiring** — `ProgramInformation/
//! Title` fills `{title}` (the DASH linkage) and embeds `©nam`; the
//!   anchored-scheme thumbnail descriptor fetches and embeds `covr`;
//!   `--no-meta` disables the embed face;
//! * **archive** — the Done close-out records the fingerprints;
//!   checkpoint ① (same URL, rotated query) skips with **zero outbound
//!   of any kind**; checkpoint ② (an alias URL serving the identical
//!   manifest) skips with the manifest fetched but **zero segment
//!   traffic**; both rides the `archive_duplicate` warning; the
//!   `taiji.clearMediaArchive` RPC clears and the same fingerprint
//!   re-downloads;
//! * **info.json** — default off; on = the frozen whitelist, the
//!   redacted manifest URL (the signed query never reaches disk), the
//!   forbidden keys structurally absent, `--no-meta` orthogonal;
//! * **SSRF negative** — a private-network thumbnail URI is
//!   refused before any outbound to it (degrade + warning, zero hits).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_core::session::{
    CommandReply, GlobalOptions, MediaEvent, SessionActor, SessionCommand, SessionOptions,
    StatusKind,
};
use taiji_media::testkit::{
    FixtureSample, avcc_sample, build_init, build_segment, video_init_spec,
};

// ---------------------------------------------------------------------------
// mock faces
// ---------------------------------------------------------------------------

fn body(bytes: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], bytes).into_response()
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

/// Per-path request counters, split into the manifest face (master/
/// variant/MPD playlists) and the payload face (init + segments + the
/// thumbnail) — the zero-traffic assertions read the second (and for
/// checkpoint ①, both).
#[derive(Default, Clone)]
struct Hits {
    manifest: Arc<AtomicU64>,
    payload: Arc<AtomicU64>,
    thumb: Arc<AtomicU64>,
}

impl Hits {
    fn manifest(&self) -> u64 {
        self.manifest.load(Ordering::SeqCst)
    }
    fn payload(&self) -> u64 {
        self.payload.load(Ordering::SeqCst)
    }
    fn thumb(&self) -> u64 {
        self.thumb.load(Ordering::SeqCst)
    }
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

/// A tiny valid PNG (1x1) — the covr magic face.
fn tiny_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D, b'I', b'H', b'D', b'R', 0,
        0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1F, 0x15, 0xC4, 0x89, 0, 0, 0, 0x0A, b'I', b'D',
        b'A', b'T', 0x78, 0x9C, 0x63, 0, 1, 0, 0, 5, 0, 1, 0x0D, 0x0A, 0x2D, 0xB4, 0, 0, 0, 0,
        0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
}

/// The HLS mock: a master playlist + one video variant (fMP4, one
/// MAP, 3 segments). `alias` adds a second master path serving the
/// same bytes (the checkpoint-② same-content face).
async fn spawn_hls(hits: Hits, alias: bool) -> SocketAddr {
    spawn_with(move |addr| {
        let vspec = video_init_spec();
        let init = build_init(&vspec);
        let segs: Vec<Vec<u8>> = (0..3u32)
            .map(|i| fixture_segment(i, u64::from(i) * 99))
            .collect();
        let mut video = String::from(
            "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:10\n",
        );
        video.push_str(&format!("#EXT-X-MAP:URI=\"http://{addr}/vinit.mp4\"\n"));
        for i in 0..3 {
            video.push_str(&format!("#EXTINF:0.099,\nhttp://{addr}/vseg{i}.m4s\n"));
        }
        video.push_str("#EXT-X-ENDLIST\n");
        let master = format!(
            "#EXTM3U\n\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,CODECS=\"avc1.64001f\"\n\
             http://{addr}/v.m3u8\n"
        );
        let hits_m = hits.clone();
        let hits_p = hits.clone();
        let master_alias = master.clone();
        let mut app = Router::new()
            .route(
                "/master.m3u8",
                get(move || {
                    let hits = hits_m.clone();
                    let text = master.clone();
                    async move {
                        hits.manifest.fetch_add(1, Ordering::SeqCst);
                        body(text.into_bytes(), "application/vnd.apple.mpegurl")
                    }
                }),
            )
            .route(
                "/v.m3u8",
                get({
                    let hits = hits.clone();
                    move || {
                        let hits = hits.clone();
                        let text = video.clone();
                        async move {
                            hits.manifest.fetch_add(1, Ordering::SeqCst);
                            body(text.into_bytes(), "application/vnd.apple.mpegurl")
                        }
                    }
                }),
            )
            .route(
                "/vinit.mp4",
                get({
                    let hits = hits.clone();
                    move || {
                        let hits = hits.clone();
                        let bytes = init.clone();
                        async move {
                            hits.payload.fetch_add(1, Ordering::SeqCst);
                            body(bytes, "video/mp4")
                        }
                    }
                }),
            );
        if alias {
            let hits_m2 = hits.clone();
            let text2 = master_alias;
            app = app.route(
                "/alias.m3u8",
                get(move || {
                    let hits = hits_m2.clone();
                    let text = text2.clone();
                    async move {
                        hits.manifest.fetch_add(1, Ordering::SeqCst);
                        body(text.into_bytes(), "application/vnd.apple.mpegurl")
                    }
                }),
            );
        }
        for (i, seg) in segs.into_iter().enumerate() {
            let hits_p = hits_p.clone();
            app = app.route(
                &format!("/vseg{i}.m4s"),
                get(move || {
                    let hits = hits_p.clone();
                    let bytes = seg.clone();
                    async move {
                        hits.payload.fetch_add(1, Ordering::SeqCst);
                        body(bytes, "video/mp4")
                    }
                }),
            );
        }
        app
    })
    .await
}

/// The DASH mock: a single-period SegmentTemplate MPD with
/// `ProgramInformation/Title` + the anchored-scheme thumbnail
/// descriptor (the DASH value-domain faces); video init + 3
/// segments; the thumbnail at `/thumb.png` (counted separately).
/// `alias` serves the **identical MPD bytes** at `/alias.mpd` — the
/// archive checkpoint-② cross-URL fixture (the same content, a different
/// fetch location).
async fn spawn_dash(hits: Hits, title: Option<&str>, thumbnail: Option<&str>) -> SocketAddr {
    spawn_dash_opt(hits, title, thumbnail, false).await
}

async fn spawn_dash_opt(
    hits: Hits,
    title: Option<&str>,
    thumbnail: Option<&str>,
    alias: bool,
) -> SocketAddr {
    spawn_with(move |addr| {
        let pi = title
            .map(|t| format!("<ProgramInformation><Title>{t}</Title></ProgramInformation>\n  "));
        let thumb = thumbnail.map(|_| {
            format!(
                "<SupplementalProperty schemeIdUri=\"urn:mpeg:dash:thumbnail:2016\" \
                 value=\"http://{addr}/thumb.png\"/>\n  "
            )
        });
        let mpd_text = format!(
            r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT0.297S" profiles="urn:mpeg:dash:profile:isoff-live:2011">
  {}{}<Period id="p1" duration="PT0.297S">
    <AdaptationSet mimeType="video/mp4" codecs="avc1.64001f">
      <SegmentTemplate timescale="1000" duration="99" startNumber="1"
        initialization="init.mp4" media="seg-$Number$.m4s"/>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
            pi.unwrap_or_default(),
            thumb.unwrap_or_default(),
        );
        let vspec = video_init_spec();
        let init = build_init(&vspec);
        let segs: Vec<Vec<u8>> = (0..3u32)
            .map(|i| fixture_segment(i, u64::from(i) * 99))
            .collect();
        let png = tiny_png();
        let hits_m = hits.clone();
        let hits_p = hits.clone();
        let hits_t = hits.clone();
        let mpd_alias = mpd_text.clone();
        let mut app = Router::new().route(
            "/media.mpd",
            get(move || {
                let hits = hits_m.clone();
                let text = mpd_text.clone();
                async move {
                    hits.manifest.fetch_add(1, Ordering::SeqCst);
                    body(text.into_bytes(), "application/dash+xml")
                }
            }),
        );
        if alias {
            let hits_m2 = hits.clone();
            app = app.route(
                "/alias.mpd",
                get(move || {
                    let hits = hits_m2.clone();
                    let text = mpd_alias.clone();
                    async move {
                        hits.manifest.fetch_add(1, Ordering::SeqCst);
                        body(text.into_bytes(), "application/dash+xml")
                    }
                }),
            );
        }
        if thumbnail.is_some() {
            app = app.route(
                "/thumb.png",
                get(move || {
                    let hits = hits_t.clone();
                    let bytes = png.clone();
                    async move {
                        hits.thumb.fetch_add(1, Ordering::SeqCst);
                        body(bytes, "image/png")
                    }
                }),
            );
        }
        app = app.route(
            "/init.mp4",
            get({
                let hits = hits.clone();
                move || {
                    let hits = hits.clone();
                    let bytes = init.clone();
                    async move {
                        hits.payload.fetch_add(1, Ordering::SeqCst);
                        body(bytes, "video/mp4")
                    }
                }
            }),
        );
        for (i, seg) in segs.into_iter().enumerate() {
            let hits_p = hits_p.clone();
            app = app.route(
                &format!("/seg-{}.m4s", i + 1),
                get(move || {
                    let hits = hits_p.clone();
                    let bytes = seg.clone();
                    async move {
                        hits.payload.fetch_add(1, Ordering::SeqCst);
                        body(bytes, "video/mp4")
                    }
                }),
            );
        }
        app
    })
    .await
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("media-face-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

struct Rig {
    session: taiji_core::session::SessionHandle,
    _actor: tokio::task::JoinHandle<()>,
    persist: taiji_store::persist::PersistHandle,
    _writer: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

async fn rig_at(db_dir: &std::path::Path, out_dir: &std::path::Path, allow_private: bool) -> Rig {
    let db = db_dir.join("taiji.sqlite3");
    let (persist, writer_join) = taiji_store::persist::writer::PersistWriter::spawn(db)
        .await
        .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let options = SessionOptions {
        global: GlobalOptions {
            dir: out_dir.to_path_buf(),
            one_shot: true,
            media_allow_private_key_url: allow_private,
            ..Default::default()
        },
    };
    let (session, actor) = SessionActor::spawn_with_persist(options, Some(persist.clone()));
    Rig {
        session,
        _actor: actor,
        persist,
        _writer: writer_join,
        dir: out_dir.to_path_buf(),
    }
}

fn options(dir: &std::path::Path, extra: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::from([
        ("dir".to_string(), dir.display().to_string()),
        // The mock lives on loopback — the SSRF default-deny needs the
        // explicit allow (the same lab posture as the earlier media gates).
        (
            "media-allow-private-key-url".to_string(),
            "true".to_string(),
        ),
    ]);
    for (k, v) in extra {
        m.insert(k.to_string(), v.to_string());
    }
    m
}

async fn add_media(rig: &Rig, url: &str, opts: BTreeMap<String, String>) -> String {
    match rig
        .session
        .call(SessionCommand::AddMedia {
            url: url.to_string(),
            options: opts,
            cookies: Vec::new(),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g.to_string(),
        other => panic!("addMedia: {other:?}"),
    }
}

/// Drive to the terminal state (tellStatus polling, the e2e face)
/// while opportunistically draining the media bus for the warnings —
/// a terminal Error does not necessarily emit an error *phase* event
/// (media_fail flips the live state without a phase note), so the
/// poll is the authority.
async fn drive_to_terminal(
    rig: &Rig,
    rx: &mut tokio::sync::broadcast::Receiver<MediaEvent>,
    gid: &str,
) -> (StatusKind, Vec<(String, String)>) {
    let mut warnings = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        tokio::select! {
            ev = rx.recv() => {
                if let Ok(ev) = ev
                    && let Some(w) = &ev.warning
                {
                    warnings.push((w.code.clone(), w.message.clone()));
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                let st = tokio::time::timeout_at(
                    deadline,
                    rig.session.call(SessionCommand::TellStatus {
                        gid: gid.to_string(),
                        keys: Vec::new(),
                    }),
                )
                .await
                .unwrap_or_else(|e| panic!("status timeout: {e}"));
                if let Ok(CommandReply::TorrentStatus(view)) = st {
                    match view.status {
                        StatusKind::Complete => return (StatusKind::Complete, warnings),
                        StatusKind::Error => return (StatusKind::Error, warnings),
                        _ => {}
                    }
                }
            }
        }
    }
}

async fn output_name_of(rig: &Rig, gid: &str) -> String {
    rig.persist
        .load_media_task(gid)
        .await
        .unwrap_or_else(|e| panic!("row load: {e}"))
        .and_then(|row| row.output_name)
        .unwrap_or_else(|| panic!("{gid}: row carries no output_name"))
}

// ---------------------------------------------------------------------------
// the template product matrix
// ---------------------------------------------------------------------------

/// The default shape, the explicit six-field template, the NA
/// convention, the unknown-field refusal (zero segment traffic), the
/// sanitization rewrite (warning + sanitized name used + row
/// consistency), and the HLS {title} = NA anchor.
#[tokio::test]
async fn template_product_matrix_hls() {
    let hits = Hits::default();
    let addr = spawn_hls(hits.clone(), false).await;
    let dir = tempdir("tmpl-matrix");
    let rig = rig_at(&dir, &dir, true).await;

    // (1) The default `{id}.{ext}` shape: id = the manifest stem.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/master.m3u8"),
        options(&dir, &[]),
    )
    .await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    assert_eq!(
        output_name_of(&rig, &gid).await,
        "master.mp4",
        "the default shape"
    );
    assert!(rig.dir.join("master.mp4").is_file(), "the product exists");

    // (2) The explicit six-field template over the same fixture
    // (title/playlist_index = NA on HLS — no standard source, the
    // 0.5-bridge fields; res rides the selected node; lang = NA with
    // no audio group).
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/master.m3u8"),
        options(
            &dir,
            &[(
                "media-template",
                "{title}-{id}-{res}-{lang}-{playlist_index}.{ext}",
            )],
        ),
    )
    .await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    assert_eq!(
        output_name_of(&rig, &gid).await,
        "NA-master-320x240-NA-NA.mp4",
        "the six-field explicit shape (NA convention)"
    );

    // (3) An unknown field refuses the task — zero segment traffic
    // (the expansion runs in Resolving, before any staging).
    let segs_before = hits.payload();
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/master.m3u8"),
        options(&dir, &[("media-template", "{uploader}-{id}.{ext}")]),
    )
    .await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Error, "unknown field = refused task");
    assert_eq!(
        hits.payload(),
        segs_before,
        "an unknown-field refusal spends zero segment traffic"
    );

    // (4) The sanitization rewrite: a hostile `out` (traversal + the
    // leading dash) expands, gets sanitized (warning + the sanitized
    // name used), and the row read-back matches the on-disk product.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/master.m3u8"),
        options(&dir, &[("out", "../-evil name")]),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(
        status,
        StatusKind::Complete,
        "a hostile name sanitizes, not fails"
    );
    let name = output_name_of(&rig, &gid).await;
    assert!(
        !name.contains('/') && !name.starts_with('-') && !name.contains(".."),
        "sanitized: {name:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|(code, _)| code == "taiji.media.template_unsafe"),
        "the rewrite raises template_unsafe: {warnings:?}"
    );
    assert!(
        rig.dir.join(&name).is_file(),
        "the sanitized name is the product"
    );

    // (4b) The remaining §11 vectors through the same pipeline face:
    // NUL/control, overlong (the 200-byte clamp), and the Unicode
    // spoofing family — `out` is the raw JSON string face (a manifest
    // cannot carry NUL; XML 1.0 rejects it, so the vector rides the
    // option value here and via the DASH Title's bidi form in the
    // dash_hostile test).
    let hostile = format!("na\u{0}me-{}\u{202E}evil", "x".repeat(400));
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/master.m3u8"),
        options(&dir, &[("out", hostile.as_str())]),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete, "sanitized, not failed");
    assert!(
        warnings
            .iter()
            .any(|(code, _)| code == "taiji.media.template_unsafe"),
        "the hostile out raises template_unsafe"
    );
    let name = output_name_of(&rig, &gid).await;
    assert!(
        !name.chars().any(char::is_control),
        "NUL/controls stripped: {name:?}"
    );
    assert!(
        name.len() <= taiji_media::MAX_OUTPUT_NAME_BYTES,
        "clamped: {name:?}"
    );
    assert!(!name.contains('\u{202E}'), "the bidi override is stripped");
    assert!(rig.dir.join(&name).is_file(), "row == product");

    // (5) The HLS {title} anchor: no standard title source — NA,
    // never synthesized.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/master.m3u8"),
        options(&dir, &[("media-template", "{title}.{ext}")]),
    )
    .await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    assert_eq!(
        output_name_of(&rig, &gid).await,
        "NA.mp4",
        "HLS {{title}} = NA (the anchor)"
    );

    let _ = rig.session.shutdown().await;
}

// ---------------------------------------------------------------------------
// the DASH value-domain wiring
// ---------------------------------------------------------------------------

/// A hostile DASH Title (the remote-string posture, §10 #1): the
/// traversal/dash/Unicode vectors expand, get sanitized (warning +
/// the sanitized name used + the row read-back consistent) — the
/// title linkage's hostile half.
#[tokio::test]
async fn dash_hostile_title_sanitizes() {
    let hits = Hits::default();
    let addr = spawn_dash(hits.clone(), Some("../../-evil\u{202E}name"), None).await;
    let dir = tempdir("dash-evil-title");
    let rig = rig_at(&dir, &dir, true).await;
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/media.mpd"),
        options(&dir, &[("media-template", "{title}.{ext}")]),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete, "sanitized, not failed");
    assert!(
        warnings
            .iter()
            .any(|(code, _)| code == "taiji.media.template_unsafe"),
        "the hostile title raises template_unsafe: {warnings:?}"
    );
    let name = output_name_of(&rig, &gid).await;
    assert!(
        !name.contains('/') && !name.starts_with('-') && !name.contains(".."),
        "sanitized: {name:?}"
    );
    assert!(
        rig.dir.join(&name).is_file(),
        "the sanitized name is the product"
    );
    let _ = rig.session.shutdown().await;
}

/// The MPD Title fills `{title}` (the value-domain linkage) and both
/// metadata faces embed (©nam + covr, the box-probe assertions);
/// `--no-meta` disables the embed face.
#[tokio::test]
async fn dash_title_and_thumbnail_embed() {
    let hits = Hits::default();
    let addr = spawn_dash(hits.clone(), Some("Big Buck Bunny"), Some("png")).await;
    let dir = tempdir("dash-meta");
    let rig = rig_at(&dir, &dir, true).await;

    // The linkage: {title} expands from ProgramInformation/Title
    // (this first add also archives — the duplicate-skip pin below).
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/media.mpd"),
        options(
            &dir,
            &[
                ("media-template", "{title}.{ext}"),
                ("media-archive", "true"),
            ],
        ),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete, "warnings: {warnings:?}");
    assert_eq!(
        output_name_of(&rig, &gid).await,
        "Big Buck Bunny.mp4",
        "the DASH Title fills {{title}}"
    );
    let product = std::fs::read(rig.dir.join("Big Buck Bunny.mp4"))
        .unwrap_or_else(|e| panic!("product: {e}"));
    // The native probe's ©nam/covr assertions ran inside the pipeline
    // (a violation would have failed the task); the byte scan here is
    // the independent confirmation.
    assert!(
        find_subsequence(&product, &[0xA9, b'n', b'a', b'm']).is_some(),
        "©nam rides the product"
    );
    assert!(
        find_subsequence(&product, b"Big Buck Bunny").is_some(),
        "the title payload is verbatim"
    );
    assert!(
        find_subsequence(&product, b"covr").is_some(),
        "covr rides the product"
    );
    assert!(
        find_subsequence(&product, &tiny_png()).is_some(),
        "the fetched thumbnail payload is the covr bytes"
    );
    assert_eq!(hits.thumb(), 1, "the thumbnail was fetched exactly once");

    // The archive pin on the same fixture: a rotated-query re-add hits
    // checkpoint ① and spends NOTHING — not even the thumbnail (the
    // checkpoint precedes the thumbnail fetch by construction).
    let thumb_before = hits.thumb();
    let payload_before = hits.payload();
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/media.mpd?sig=rotated"),
        options(
            &dir,
            &[
                ("media-template", "{title}.{ext}"),
                ("media-archive", "true"),
            ],
        ),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete, "the skip is Done-shaped");
    assert!(
        warnings
            .iter()
            .any(|(code, _)| code == "taiji.media.archive_duplicate"),
        "the duplicate rides the bypass warning: {warnings:?}"
    );
    assert_eq!(hits.thumb(), thumb_before, "skip: no thumbnail fetch");
    assert_eq!(hits.payload(), payload_before, "skip: zero payload traffic");

    // --no-meta: the embed face off — neither item, no thumbnail fetch.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/media.mpd"),
        options(
            &dir,
            &[("no-meta", "true"), ("media-template", "{title}-nm.{ext}")],
        ),
    )
    .await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    let product = std::fs::read(rig.dir.join("Big Buck Bunny-nm.mp4"))
        .unwrap_or_else(|e| panic!("product: {e}"));
    assert!(
        find_subsequence(&product, &[0xA9, b'n', b'a', b'm']).is_none(),
        "--no-meta: no ©nam"
    );
    assert!(
        find_subsequence(&product, b"covr").is_none(),
        "--no-meta: no covr (the fetch never happens)"
    );
    assert_eq!(
        hits.thumb(),
        1,
        "no additional thumbnail fetch under --no-meta"
    );

    let _ = rig.session.shutdown().await;
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The archive checkpoint-② cross-URL face on the DASH side (a
/// review blocker's pin): the **identical MPD bytes** fetched from a second
/// URL hit the manifest compartment — the compartment is deliberately
/// URL-free ([`mpd_content_digest`]; the row's `mpd_digest` binds the
/// entry URL for its recovery purpose and would miss). The manifest
/// IS fetched (the digest is of the fetched form); nothing else is.
#[tokio::test]
async fn dash_alias_same_content_hits_checkpoint_two() {
    let hits = Hits::default();
    let addr = spawn_dash_opt(hits.clone(), Some("Aliased"), None, true).await;
    let dir = tempdir("dash-alias");
    let rig = rig_at(&dir, &dir, true).await;

    // The archiving download from the first URL.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/media.mpd"),
        options(&dir, &[("media-archive", "true")]),
    )
    .await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    let manifest_after_first = hits.manifest();
    let payload_after_first = hits.payload();

    // The identical bytes from the alias URL: checkpoint ② hits — the
    // cross-URL face the URL-bound row digest could not serve.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/alias.mpd"),
        options(&dir, &[("media-archive", "true")]),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete, "Done-shaped skip");
    assert!(
        warnings
            .iter()
            .any(|(code, msg)| code == "taiji.media.archive_duplicate"
                && msg.contains("manifest digest")),
        "checkpoint ② (not ① — the URL differs): {warnings:?}"
    );
    assert!(
        hits.manifest() > manifest_after_first,
        "the alias manifest was fetched (the digest is of the fetched form)"
    );
    assert_eq!(
        hits.payload(),
        payload_after_first,
        "cross-URL hit: zero segment traffic"
    );

    let _ = rig.session.shutdown().await;
}

// ---------------------------------------------------------------------------
// the archive checkpoints + the clear face
// ---------------------------------------------------------------------------

/// The full archive lifecycle through the session: Done records the
/// row → checkpoint ① (rotated query) skips with zero outbound of any
/// kind → checkpoint ② (an alias URL, identical manifest bytes) skips
/// with the manifest fetched but zero segment traffic → both rides
/// the archive_duplicate warning → the clear RPC empties the table
/// and the same fingerprint re-downloads.
#[tokio::test]
async fn media_archive_checkpoints_and_clear() {
    let hits = Hits::default();
    let addr = spawn_hls(hits.clone(), true).await;
    let dir = tempdir("archive");
    let rig = rig_at(&dir, &dir, true).await;
    let url = format!("http://{addr}/master.m3u8");

    // (1) The archiving download: Complete + the row recorded.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(&rig, &url, options(&dir, &[("media-archive", "true")])).await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    let name = output_name_of(&rig, &gid).await;
    let digest = taiji_media::archive_url_digest(&url);
    let row = rig
        .persist
        .load_media_archive_by_url(&digest)
        .await
        .unwrap_or_else(|e| panic!("archive read: {e}"))
        .unwrap_or_else(|| panic!("the Done close-out archived the task"));
    assert_eq!(row.kind, "hls");
    assert_eq!(row.output_name, name);
    assert!(!row.manifest_digest.is_empty());
    let manifest_digest = row.manifest_digest.clone();
    let m_after_first = hits.manifest();
    let p_after_first = hits.payload();

    // (2) Checkpoint ①: the same resource under a rotated query —
    // zero outbound of ANY kind (not even the manifest).
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("{url}?token=rotated-2"),
        options(&dir, &[("media-archive", "true")]),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(
        status,
        StatusKind::Complete,
        "the skip is Done-shaped (not Error)"
    );
    assert!(
        warnings.iter().any(
            |(code, msg)| code == "taiji.media.archive_duplicate" && msg.contains("URL digest")
        ),
        "checkpoint ① rides the bypass warning: {warnings:?}"
    );
    assert_eq!(
        output_name_of(&rig, &gid).await,
        name,
        "the archived name is the skip row's"
    );
    assert_eq!(
        hits.manifest(),
        m_after_first,
        "checkpoint ①: zero manifest fetches"
    );
    assert_eq!(
        hits.payload(),
        p_after_first,
        "checkpoint ①: zero payload fetches"
    );

    // (3) Checkpoint ②: an alias URL serving the identical manifest —
    // the manifest IS fetched (the digest is of the fetched form), the
    // segments never are.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &format!("http://{addr}/alias.m3u8"),
        options(&dir, &[("media-archive", "true")]),
    )
    .await;
    let (status, warnings) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    assert!(
        warnings
            .iter()
            .any(|(code, msg)| code == "taiji.media.archive_duplicate"
                && msg.contains("manifest digest")),
        "checkpoint ② rides the bypass warning: {warnings:?}"
    );
    assert!(
        hits.manifest() > m_after_first,
        "checkpoint ② fetched the manifest"
    );
    assert_eq!(
        hits.payload(),
        p_after_first,
        "checkpoint ②: zero segment traffic"
    );

    // (4) Off by default: no archive flag → no checkpoint, a full
    // second download of the same URL.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(&rig, &url, options(&dir, &[])).await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    assert!(
        hits.payload() > p_after_first,
        "without media-archive the same URL fully re-downloads"
    );

    // (5) The clear RPC: the count face, the table empties, and the
    // same fingerprint re-downloads afterwards.
    let removed = match rig.session.call(SessionCommand::ClearMediaArchive).await {
        Ok(CommandReply::ArchiveCleared { removed }) => removed,
        other => panic!("clearMediaArchive: {other:?}"),
    };
    // Skips never archive (nothing was downloaded from those URLs —
    // the alias's checkpoint-② hit leaves no row): exactly the one
    // row the real download wrote.
    assert_eq!(removed, 1, "only the really-downloaded URL's row");
    let gone = rig
        .persist
        .load_media_archive_by_manifest(&manifest_digest)
        .await
        .unwrap_or_else(|e| panic!("archive read: {e}"));
    assert!(gone.is_none(), "cleared");
    let p_before_re = hits.payload();
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(&rig, &url, options(&dir, &[("media-archive", "true")])).await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    assert!(
        hits.payload() > p_before_re,
        "after the clear the same fingerprint re-downloads"
    );

    let _ = rig.session.shutdown().await;
}

// ---------------------------------------------------------------------------
// the info.json export
// ---------------------------------------------------------------------------

/// Default off; on = the frozen whitelist + the redacted URL + the
/// forbidden keys structurally absent; `--no-meta` orthogonal.
#[tokio::test]
async fn info_json_whitelist_redact_and_default_off() {
    let hits = Hits::default();
    let addr = spawn_dash(hits.clone(), Some("Signed &amp; Titled"), None).await;
    let dir = tempdir("infojson");
    let rig = rig_at(&dir, &dir, true).await;
    // The signed URL: the query must never reach the export.
    let url = format!("http://{addr}/media.mpd?sig=SECRETSIG123&token=zzz");

    // (1) Default off: no sidecar.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(&rig, &url, options(&dir, &[])).await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    let any_sidecar = std::fs::read_dir(&rig.dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|f| f.file_name().to_string_lossy().ends_with(".info.json"))
        })
        .unwrap_or(false);
    assert!(
        !any_sidecar,
        "default off: no info.json anywhere in the output dir"
    );

    // (2) On (and --no-meta alongside — the orthogonality pin): the
    // whitelisted, redacted sidecar at the product's side.
    let mut rx = rig.session.subscribe_media_events();
    let gid = add_media(
        &rig,
        &url,
        options(
            &dir,
            &[
                ("media-info-json", "true"),
                ("no-meta", "true"),
                ("media-template", "{title}.{ext}"),
            ],
        ),
    )
    .await;
    let (status, _) = drive_to_terminal(&rig, &mut rx, &gid).await;
    assert_eq!(status, StatusKind::Complete);
    let sidecar_path = rig.dir.join("Signed & Titled.info.json");
    let text = match std::fs::read_to_string(&sidecar_path) {
        Ok(t) => t,
        Err(e) => {
            let listing = std::fs::read_dir(&rig.dir)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .map(|f| f.file_name().to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let row_name = output_name_of(&rig, &gid).await;
            panic!("info.json: {e}; dir=[{listing}] row output_name={row_name:?}")
        }
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}"));
    let obj = v.as_object().unwrap_or_else(|| panic!("object"));
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut want: Vec<&str> = taiji_media::INFO_JSON_KEYS.to_vec();
    want.sort_unstable();
    assert_eq!(keys, want, "the whitelist is the frozen set");
    for forbidden in ["http_headers", "cookies", "token"] {
        assert!(
            !obj.contains_key(forbidden) && !text.contains(&format!("\"{forbidden}\"")),
            "{forbidden}: structurally absent (key AND serialized form)"
        );
    }
    assert_eq!(
        obj["manifest_url"].as_str(),
        Some(format!("http://{addr}/media.mpd").as_str()),
        "the signed query is redacted away"
    );
    assert!(
        !text.contains("SECRETSIG") && !text.contains("token=zzz"),
        "secret material never reaches the export"
    );
    assert_eq!(obj["kind"].as_str(), Some("dash"));
    assert_eq!(obj["title"].as_str(), Some("Signed & Titled"));
    let want_digest = taiji_media::archive_url_digest(&url);
    assert_eq!(
        obj["url_digest"].as_str(),
        Some(want_digest.as_str()),
        "the archive fingerprint rides the export"
    );
    assert_eq!(obj["ext"].as_str(), Some("mp4"));
    assert!(obj["bytes"].as_u64().unwrap_or(0) > 0, "the product size");

    let _ = rig.session.shutdown().await;
}

// ---------------------------------------------------------------------------
// the SSRF negative
// ---------------------------------------------------------------------------

/// A private-network thumbnail URI is refused by the SSRF line BEFORE
/// any outbound to it: the metadata_degraded warning fires and the
/// thumbnail server observes zero hits (the task itself proceeds to
/// its own SSRF refusal on the loopback segments — the same line,
/// allow=false here by construction).
#[tokio::test]
async fn thumbnail_ssrf_negative_zero_outbound() {
    let hits = Hits::default();
    // allow_private = false for this rig (below): the thumbnail check
    // refuses the loopback descriptor target before the fetch.
    let addr = spawn_dash(hits.clone(), Some("T"), Some("png")).await;
    let dir = tempdir("ssrf-neg");
    let rig = rig_at(&dir, &dir, false).await;

    let mut rx = rig.session.subscribe_media_events();
    let _gid = add_media(
        &rig,
        &format!("http://{addr}/media.mpd"),
        // NOTE: no allow-private here — see rig_at(false).
        BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("media-template".to_string(), "{id}.{ext}".to_string()),
        ]),
    )
    .await;
    // Drive until the metadata_degraded warning (the task eventually
    // errors on the loopback segments — the same SSRF line — but the
    // warning is emitted in Resolving, before any of that).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut saw_degrade = false;
    let mut saw_error = false;
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|e| panic!("phase timeout: {e}"))
            .unwrap_or_else(|e| panic!("bus closed: {e}"));
        if let Some(w) = &ev.warning {
            if w.code == "taiji.media.metadata_degraded" {
                saw_degrade = true;
                break;
            }
        }
        if ev.phase.as_str() == "error" {
            saw_error = true;
            break;
        }
    }
    assert!(
        saw_degrade,
        "the thumbnail refusal degrades with the warning (saw_error={saw_error})"
    );
    assert_eq!(
        hits.thumb(),
        0,
        "the SSRF refusal spends zero outbound to the thumbnail target"
    );
    let _ = rig.session.shutdown().await;
}
