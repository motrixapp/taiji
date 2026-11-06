//! The verdict decision-table rows (driver half): they are
//! driven end-to-end through the real download pipeline against a
//! local origin — each refusal row asserts the explicit error code
//! (`taiji.media.*`), and the caps rows (`not_media` /
//! `manifest_too_large`) assert the classification / limit faces.
//!
//! Regression references (the rows whose e2e already lives in the
//! other suites — the same gate runs them; this file maps, not
//! duplicates):
//! * track-necessity driver rows — `media_e2e` (required
//! fails the set / sidecar degrades with the warning recorded);
//! the **session-level** rows (task Error / degraded-complete +
//! warning event) live in taiji-core's `media_negative`.
//! * three-precheck negatives + both-channels-failed →
//! `media_synth_e2e` (disk precheck, ffmpeg-missing
//! zero-traffic, both-fail Error + staging retained + idempotent
//! re-run).
//! * SSRF/key negatives (key-URI and media-segment-URL faces) →
//! `media_crypto_e2e::ssrf_wire_matrix_and_negative_faces`.
//! * Template disinfection / probe anti-forgery →
//! `media_task_e2e` (probe governance + fabricated-token rows) and
//! the template suite.
//!
//! DASH rows (a red-then-green flip): the MPD entry drives the
//! DASH line — the driver rows assert the per-row judgment-table
//! codes end-to-end (dynamic → `live_unsupported`, ContentProtection
//! → `drm_unsupported`; the nested-sidx row asserts at the
//! materialization face in `mpd_golden`). Red form of record
//! (pre-DASH support): the MPD entry was refused with the manifest_parse
//! "DASH parsing is not wired" face; green = per-row codes.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::MediaError;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};

fn text_body(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")],
        body,
    )
        .into_response()
}

async fn spawn_playlist_origin(playlists: Vec<(&'static str, String)>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let mut app = Router::new();
    for (path, body) in playlists {
        let route = format!("/{path}");
        app = app.route(&route, get(move || async move { text_body(body.clone()) }));
    }
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

fn out_dir(tag: &str) -> PathBuf {
    common::origin::tempdir("taiji-neg", tag)
}

async fn run_manifest(
    addr: &SocketAddr,
    path: &str,
    tag: &str,
) -> Result<taiji_media::mediadl::MediaRunReport, MediaError> {
    let out = out_dir(tag);
    let db = out_dir(&format!("{tag}-db"));
    let (ledger, join) = common::ledger::spawn_ledger(&db.join("taiji.sqlite3")).await;
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let dl = MediaDownload::new(
        &format!("b95{tag}").truncate_pad(),
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: out,
            allow_private_key_url: true,
            ..MediaDownloadConfig::default()
        },
    );
    let res = dl.run(&format!("http://{addr}/{path}"), &ledger).await;
    join.abort();
    res
}

/// Truncate/pad helper for stable 16-hex gids from short tags.
trait GidPad {
    fn truncate_pad(self) -> String;
}
impl GidPad for String {
    fn truncate_pad(self) -> String {
        let mut s: String = self.chars().filter(char::is_ascii_hexdigit).collect();
        s.truncate(16);
        while s.len() < 16 {
            s.push('0');
        }
        s
    }
}

// ---------------------------------------------------------------------------
// verdict decision-table refusal rows (driver e2e)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_live_without_endlist_refused() {
    let addr = spawn_playlist_origin(vec![(
        "live.m3u8",
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\nhttp://x/s0.ts\n".to_string(),
    )])
    .await;
    let err = match run_manifest(&addr, "live.m3u8", "live1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.live_unsupported", "{err}");
}

#[tokio::test]
async fn row_event_playlist_refused() {
    // EVENT: PLAYLIST-TYPE=EVENT and no ENDLIST — the same 0.3
    // transitional refusal (0.4 owns LIVE/EVENT).
    let addr = spawn_playlist_origin(vec![(
        "event.m3u8",
        "#EXTM3U\n#EXT-X-PLAYLIST-TYPE:EVENT\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\n\
         http://x/s0.ts\n"
            .to_string(),
    )])
    .await;
    let err = match run_manifest(&addr, "event.m3u8", "event1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.live_unsupported", "{err}");
}

#[tokio::test]
async fn row_sample_aes_refused() {
    let addr = spawn_playlist_origin(vec![(
        "saes.m3u8",
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
         #EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"http://x/k\"\n\
         #EXTINF:2.0,\nhttp://x/s0.ts\n#EXT-X-ENDLIST\n"
            .to_string(),
    )])
    .await;
    let err = match run_manifest(&addr, "saes.m3u8", "saes1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.sample_aes_unsupported", "{err}");
}

#[tokio::test]
async fn row_session_key_refused() {
    let addr = spawn_playlist_origin(vec![(
        "sk.m3u8",
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
         #EXT-X-SESSION-KEY:METHOD=AES-128,URI=\"http://x/k\"\n\
         #EXTINF:2.0,\nhttp://x/s0.ts\n#EXT-X-ENDLIST\n"
            .to_string(),
    )])
    .await;
    let err = match run_manifest(&addr, "sk.m3u8", "skey1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.session_key_unsupported", "{err}");
}

#[tokio::test]
async fn row_iframes_only_refused() {
    let addr = spawn_playlist_origin(vec![(
        "ifr.m3u8",
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-I-FRAMES-ONLY\n\
         #EXTINF:2.0,\nhttp://x/s0.ts\n#EXT-X-ENDLIST\n"
            .to_string(),
    )])
    .await;
    let err = match run_manifest(&addr, "ifr.m3u8", "ifr1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.iframes_unsupported", "{err}");
}

// ---------------------------------------------------------------------------
// caps rows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_not_media_classification() {
    // The `taiji.media.not_media` row: the entry classifier refuses a
    // non-manifest page (the driver-level parse of an HTML body
    // reports `manifest_parse`; the not_media code is the entry
    // classification face — both asserted).
    let addr =
        spawn_playlist_origin(vec![("page.html", "<html>hello world</html>".to_string())]).await;
    let err = match run_manifest(&addr, "page.html", "notm1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.manifest_parse", "{err}");
    let kind = taiji_media::classify_entry(Some(b"<html>hello</html>".as_slice()), None, None);
    assert!(
        matches!(kind, taiji_media::EntryKind::NotMedia),
        "the classifier refuses the page: {kind:?}"
    );
    let html_err = MediaError::NotMedia("x".to_string());
    assert_eq!(html_err.code(), "taiji.media.not_media");
}

#[tokio::test]
async fn row_manifest_too_large_segment_cap() {
    // 100_001 segments: over the ≤100k cap → manifest_too_large at
    // parse (the driver fetches the body then the parser refuses).
    let mut text = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
    for i in 0..=100_000u64 {
        text.push_str(&format!("#EXTINF:1.0,\nhttp://x/s{i}.ts\n"));
    }
    text.push_str("#EXT-X-ENDLIST\n");
    let addr = spawn_playlist_origin(vec![("big.m3u8", text)]).await;
    let err = match run_manifest(&addr, "big.m3u8", "bigc1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
}

#[tokio::test]
async fn row_manifest_too_large_byte_cap() {
    // A body past the 16MiB byte cap (the parser's
    // MAX_MANIFEST_BYTES face).
    let mut text = String::with_capacity(16 * 1024 * 1024 + 1024);
    text.push_str("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
    while text.len() <= 16 * 1024 * 1024 {
        text.push_str("#EXTINF:1.0,\nhttp://x/pad.ts\n");
    }
    text.push_str("#EXT-X-ENDLIST\n");
    let addr = spawn_playlist_origin(vec![("huge.m3u8", text)]).await;
    let err = match run_manifest(&addr, "huge.m3u8", "bigb1").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
}

// ---------------------------------------------------------------------------
// DASH rows: the DASH line owns the per-row codes
// ---------------------------------------------------------------------------

fn dash_origin(mpd: &'static str) -> SocketAddr {
    futures::executor::block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let app = Router::new().route(
            "/manifest.mpd",
            get(move || async move {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/dash+xml")],
                    mpd,
                )
            }),
        );
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                panic!("serve: {e}");
            }
        });
        addr
    })
}

/// The classification layer routes an MPD entry to the DASH flavor
/// (never parsed as HLS) — the routing pin (the flavor vocabulary
/// stays the parser's face).
#[test]
fn row_dash_entry_classifies_dash() {
    let mpd = br#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static">
  <Period><AdaptationSet>
  <Representation id="1"><BaseURL>a.m4s</BaseURL></Representation></AdaptationSet></Period>
</MPD>"#;
    let kind = taiji_media::classify_entry(Some(mpd), Some("manifest.mpd"), None);
    assert!(
        matches!(
            kind,
            taiji_media::EntryKind::Manifest(taiji_media::ManifestFlavor::Dash)
        ),
        "an MPD entry classifies DASH: {kind:?}"
    );
}

/// dynamic → `live_unsupported` at the driver (red form of record: the
/// pre-DASH manifest_parse "not wired" face; green = the verdict
/// table row's code).
#[tokio::test]
async fn row_dash_dynamic_refused() {
    let addr = dash_origin(
        r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="dynamic">
  <Period><AdaptationSet mimeType="video/mp4">
    <Representation id="v" bandwidth="1" mimeType="video/mp4"><BaseURL>v.m4s</BaseURL></Representation>
  </AdaptationSet></Period>
</MPD>"#,
    );
    let err = match run_manifest(&addr, "manifest.mpd", "dashdy").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.live_unsupported", "{err}");
}

/// ContentProtection — any scheme, any level → `drm_unsupported` at
/// the driver (never supported).
#[tokio::test]
async fn row_dash_drm_refused() {
    let addr = dash_origin(
        r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static">
  <Period><AdaptationSet mimeType="video/mp4">
    <ContentProtection schemeIdUri="urn:uuid:9a04f079-9840-4286-ab92-e65be0885f95"/>
    <Representation id="v" bandwidth="1" mimeType="video/mp4"><BaseURL>v.m4s</BaseURL></Representation>
  </AdaptationSet></Period>
</MPD>"#,
    );
    let err = match run_manifest(&addr, "manifest.mpd", "dashdrm").await {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "taiji.media.drm_unsupported", "{err}");
}
