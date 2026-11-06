//! The DNS-rebinding connection-pin
//! regression. The SSRF judgment (`check_uri`) and the transport's
//! own connection resolution are otherwise **two independent DNS
//! queries** — a rebinding attacker answers the judgment with a
//! public address and the connect query with a private/link-local
//! one (the media spec's download line's only remaining seam: literal,
//! parse-layer and redirect endpoints were already covered).
//!
//! The fix pins the fetch transport: every host the judgment resolves
//! is pinned (via the base client's `pinned_resolve` production face)
//! to the address the judgment saw — one resolution, the connection
//! lands on it, Host/SNI keep the URL's name.
//!
//! The driver-level regression: a **dual-answer resolver** (judgment
//! query → public TEST-NET-1 address; every later query → a private
//! rebinding answer) behind a second-order variant URI. The fetch
//! must ride the pin (the observed pin table names the judged
//! address — pre-fix it stayed empty and the connect query would
//! have been a fresh, attacker-controlled resolution). The
//! taiji-http wire face (`with_pinned_resolve_routes_to_the_pin`,
//! client.rs) proves the pinned transport's connection physically
//! lands on the pinned address; the literal/cache no-regression legs
//! pin the unchanged behavior for hosts that never resolve.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures::future::BoxFuture;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use taiji_media::mediadl::{MediaDownload, MediaDownloadConfig};
use taiji_media::ssrf::{HostVerdictCache, SsrfResolver};
use taiji_media::trackdl::{MediaLedger, MediaTaskRecord, TrackRecord};
use taiji_media::{MediaError, SegmentRecord, TrackSetVerdict};

/// The dual-answer rebinding resolver: the first query (the judgment)
/// answers a public TEST-NET-1 address, every later query flips to a
/// private one (the rebinding). Query count observable.
struct RebindResolver {
    queries: AtomicU64,
}

impl SsrfResolver for RebindResolver {
    fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            let n = self.queries.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Ok(vec![
                    "192.0.2.1".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                ])
            } else {
                Ok(vec![
                    "10.0.0.5".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                ])
            }
        })
    }
}

/// Minimal in-memory ledger (no rows needed for the pin face).
#[derive(Default)]
struct NullLedger;

impl MediaLedger for NullLedger {
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
        Box::pin(std::future::ready(Ok(())))
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

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

/// The master playlist lives on the loopback mock (a first-order URL
/// — never media-SSRF-judged); its variant URI carries the fake
/// hostname (the second-order judgment + pin face).
async fn spawn_master(variant_host: &str) -> SocketAddr {
    let master = format!(
        "#EXTM3U\n\
         #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=320x240,CODECS=\"avc1.64001f\"\n\
         http://{variant_host}/v.m3u8\n"
    )
    .into_bytes();
    let manifest = master.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let app = Router::new().route(
        "/master.m3u8",
        get(move || async move { full_body(manifest.clone(), "application/vnd.apple.mpegurl") }),
    );
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "taiji-media-rebind-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
    path
}

fn download(out_dir: &std::path::Path, allow_private: bool) -> MediaDownload {
    let client = HttpClient::new(ClientConfig {
        // The pinned connect targets TEST-NET-1 (unroutable by
        // design): the fetch fails fast instead of hanging.
        connect_timeout: Duration::from_millis(750),
        read_timeout: Duration::from_millis(750),
        ..ClientConfig::default()
    })
    .unwrap_or_else(|e| panic!("client: {e}"));
    MediaDownload::new(
        "8000000000000124",
        client,
        RequestCtx::default(),
        MediaDownloadConfig {
            output_dir: out_dir.to_path_buf(),
            // Default-deny posture (the judgment must run — the flag
            // would skip resolution entirely and pin nothing).
            allow_private_key_url: allow_private,
            ..MediaDownloadConfig::default()
        },
    )
}

/// The rebinding pin: the judgment's public answer is pinned onto the
/// fetch transport; the track fails through the PIN (connect to the
/// judged TEST-NET-1 address), never through a second DNS answer.
/// Pre-fix the pin table stayed empty — the connect query was a
/// fresh, attacker-controlled resolution.
#[tokio::test]
async fn rebinding_judged_address_is_pinned_onto_the_fetch() {
    let resolver = Arc::new(RebindResolver {
        queries: AtomicU64::new(0),
    });
    let addr = spawn_master("rebind-pinning.example").await;
    let out = tempdir("rebind");
    let mut dl = download(&out, false);
    dl.resolver = Some(Arc::clone(&resolver) as Arc<dyn SsrfResolver>);
    let report = dl
        .run(&format!("http://{addr}/master.m3u8"), &NullLedger)
        .await
        .unwrap_or_else(|e| panic!("run returns the report: {e}"));
    // The variant fetch failed (through the unroutable pin) — the
    // required track's failure is the Failed verdict.
    assert!(
        matches!(report.verdict, TrackSetVerdict::Failed { .. }),
        "the pinned-but-unroutable variant fails the task: {:?}",
        report.verdict
    );
    // The judgment actually resolved (the dual-answer seam ran).
    assert!(
        resolver.queries.load(Ordering::SeqCst) >= 1,
        "the judgment resolved the host"
    );
    // THE pin: the judged public address (with the judged URI's
    // default port), not the rebinding answer, not empty.
    assert_eq!(
        dl.active_pins(),
        vec![(
            "rebind-pinning.example".to_string(),
            SocketAddr::new(
                "192.0.2.1"
                    .parse::<IpAddr>()
                    .unwrap_or(IpAddr::from([0, 0, 0, 0])),
                80
            )
        )],
        "the fetch transport is pinned to the judgment's address"
    );
}

/// No-regression legs: literal-IP sources (no resolution) and the
/// verdict-cache reuse pin nothing and change nothing — the base
/// client serves them (empty pin table), and a cached host's second
/// URI reuses the first verdict without re-resolution.
#[tokio::test]
async fn literal_and_cached_hosts_stay_unpinned() {
    // Literal source under the flag: no NeedsResolve, no pins.
    let addr = spawn_master("127.0.0.1:1").await;
    let out = tempdir("literal");
    let dl = download(&out, true);
    let report = dl
        .run(&format!("http://{addr}/master.m3u8"), &NullLedger)
        .await
        .unwrap_or_else(|e| panic!("run: {e}"));
    assert!(
        matches!(report.verdict, TrackSetVerdict::Failed { .. })
            || matches!(report.verdict, TrackSetVerdict::Complete { .. }),
        "the literal run reaches its verdict: {:?}",
        report.verdict
    );
    assert!(
        dl.active_pins().is_empty(),
        "literal/flag paths resolve nothing and pin nothing"
    );
    // Verdict-cache reuse (the HostVerdictCache face): one host, two
    // URIs — the second consults the cache, no second resolution, and
    // the recorded pin is the first judgment's address.
    let resolver = Arc::new(RebindResolver {
        queries: AtomicU64::new(0),
    });
    let mut cache = HostVerdictCache::new();
    let policy = taiji_media::ssrf::SsrfPolicy::default();
    taiji_media::ssrf::check_uri(
        "http://cache-pinning.example/a.ts",
        &policy,
        resolver.as_ref(),
        &mut cache,
    )
    .await
    .unwrap_or_else(|e| panic!("first judgment: {e}"));
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 1);
    taiji_media::ssrf::check_uri(
        "http://cache-pinning.example/b.ts",
        &policy,
        resolver.as_ref(),
        &mut cache,
    )
    .await
    .unwrap_or_else(|e| panic!("cached judgment: {e}"));
    assert_eq!(
        resolver.queries.load(Ordering::SeqCst),
        1,
        "the cached host is not re-resolved"
    );
    let verdict = cache
        .get("cache-pinning.example")
        .unwrap_or_else(|| panic!("cached"));
    assert!(verdict.allowed);
    assert_eq!(
        verdict.pin.map(|a| a.ip()),
        Some(
            "192.0.2.1"
                .parse::<IpAddr>()
                .unwrap_or(IpAddr::from([0, 0, 0, 0]))
        ),
        "the pin records the judgment's address"
    );
}
