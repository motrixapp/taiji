//! The probe action face's **four-gate matrix** —
//! the tests that were scattered across ~7 sites (the `media.rs`
//! unit faces for the cap/rate/TTL mechanics, `media_task_e2e`'s
//! governance rows, the rpc dispatch write-gate adjudication)
//! collected as one positive/negative matrix per gate, so a silent
//! drift in any single gate turns this file red:
//!
//! * **fail-closed** — `probeMedia`'s `read_only=false` row (the bit
//!   the RPC write gate consumes; the gate's e2e consumption is
//!   `taiji-rpc`'s `media_methods_write_gate_adjudication`: with no
//!   secret the method fails closed like every write face);
//! * **in-flight cap 2** (`PROBE_INFLIGHT_CAP`) — a third probe over
//!   two live ones answers the honest busy face;
//! * **per-origin rate limit** (`PROBE_ORIGIN_INTERVAL` = 1s, the
//!   module-documented implementation anchor) — same-origin
//!   back-to-back is throttled, distinct origins are not;
//! * **opaque token TTL 10min** (`PROBE_TTL` = 600s, the §4 spec
//!   number) — unknown/fabricated tokens present `probe_expired`.
//!
//! The rate/busy rejections deliberately keep the **generic text**
//! form (no `taiji.media.*` code — §14 has no row for them; the
//! canonical-code need stays raised at the coordination face).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use taiji_core::session::{
    CommandReply, GlobalOptions, RPC_METHOD_INFO, SessionActor, SessionCommand, SessionOptions,
    StatusKind,
};

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

async fn spawn_with(build: impl FnOnce(SocketAddr) -> Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let app = build(addr);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

/// One manifest origin with an optional response delay + a request
/// counter (the in-flight/busy and rate rows observe the probe's own
/// fetches).
async fn slow_origin(path: &'static str, delay_ms: u64) -> (SocketAddr, std::sync::Arc<AtomicU64>) {
    let hits = std::sync::Arc::new(AtomicU64::new(0));
    let h = std::sync::Arc::clone(&hits);
    let addr = spawn_with(move |addr| {
        let media = format!(
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\nhttp://{addr}/s0.ts\n\
             #EXT-X-ENDLIST\n"
        );
        Router::new().route(
            path,
            get(move || {
                let hits = std::sync::Arc::clone(&h);
                let media = media.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    full_body(media.into_bytes(), "application/vnd.apple.mpegurl")
                }
            }),
        )
    })
    .await;
    (addr, hits)
}

fn tempdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("media-gates-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}

/// The probe face's SSRF line rides the session-global flag (the mock
/// origins live on loopback — the same lab posture as the earlier media gates).
async fn session_at(dir: &std::path::Path) -> taiji_core::session::SessionHandle {
    let (persist, _join) =
        taiji_store::persist::writer::PersistWriter::spawn(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    let options = SessionOptions {
        global: GlobalOptions {
            dir: dir.to_path_buf(),
            one_shot: true,
            media_allow_private_key_url: true,
            ..Default::default()
        },
    };
    let (session, _actor) = SessionActor::spawn_with_persist(options, Some(persist));
    session
}

async fn probe(
    session: &taiji_core::session::SessionHandle,
    url: String,
) -> Result<CommandReply, taiji_core::session::SessionError> {
    session.call(SessionCommand::ProbeMedia { url }).await
}

/// Gate ① fail-closed: the registered `read_only` bit is false — the
/// RPC write gate consumes exactly this row (probeMedia = the §4
/// action face; no secret → fail-closed like every write face —
/// pinned end-to-end by taiji-rpc's
/// `media_methods_write_gate_adjudication`, which runs in the same
/// gate; asserted here so the matrix is self-contained on the bit
/// the gate reads).
#[test]
fn gate_fail_closed_read_only_bit() {
    let row = RPC_METHOD_INFO
        .iter()
        .find(|d| d.name == "taiji.probeMedia")
        .unwrap_or_else(|| panic!("the probe method is registered"));
    assert!(!row.read_only, "probeMedia is a write/action face");
    // The four-method face is exactly four (no silent growth — the
    // governance anchors live in command.rs's frozen tests).
    const MEDIA_METHODS: [&str; 4] = [
        "taiji.addMedia",
        "taiji.probeMedia",
        "taiji.getMediaFormats",
        "taiji.stopRecording",
    ];
    let media: Vec<&str> = RPC_METHOD_INFO
        .iter()
        .map(|d| d.name)
        .filter(|n| MEDIA_METHODS.contains(n))
        .collect();
    assert_eq!(media, MEDIA_METHODS);
}

/// Gates ②③④ e2e: the busy cap, the per-origin rate limit (both in
/// their generic non-`taiji.media.*` text form), and the token TTL's
/// anti-forgery face.
#[tokio::test]
async fn probe_action_face_gates_e2e() {
    let dir = tempdir("gates");
    let session = session_at(&dir).await;

    // ---- Gate ②: the global in-flight cap 2 (three distinct origins
    // so the per-origin rate windows stay out of the way). Two slow
    // probes hold both slots; the third answers the busy face; after
    // the drain (and its own origin's rate window) it is admitted.
    let (a_addr, _a_hits) = slow_origin("/a.m3u8", 600).await;
    let (b_addr, _b_hits) = slow_origin("/b.m3u8", 600).await;
    let (c_addr, c_hits) = slow_origin("/c.m3u8", 0).await;
    // The two slow probes and the third call run concurrently on
    // this task (shared borrows of the handle; the 150ms head start
    // lets the slow pair reach — and hold — both slots first).
    let (pa, pb, busy) = tokio::join!(
        probe(&session, format!("http://{a_addr}/a.m3u8")),
        probe(&session, format!("http://{b_addr}/b.m3u8")),
        async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            probe(&session, format!("http://{c_addr}/c.m3u8")).await
        }
    );
    let _ = pa.unwrap_or_else(|e| panic!("probe a: {e}"));
    let _ = pb.unwrap_or_else(|e| panic!("probe b: {e}"));
    let busy = busy
        .err()
        .unwrap_or_else(|| panic!("the third concurrent probe is refused"));
    assert!(busy.to_string().contains("probe busy"), "{busy}");
    assert!(
        !busy.to_string().contains("taiji.media."),
        "the busy face keeps the generic text form (§14 has no row): {busy}"
    );
    assert_eq!(
        c_hits.load(Ordering::SeqCst),
        0,
        "the busy probe never reached the fetch"
    );
    // The refused probe retries after its own origin's rate window
    // and is admitted.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    match probe(&session, format!("http://{c_addr}/c.m3u8")).await {
        Ok(CommandReply::MediaProbe { .. }) => {}
        other => panic!("the retried probe is admitted: {other:?}"),
    }
    assert_eq!(c_hits.load(Ordering::SeqCst), 1);

    // ---- Gate ③: the per-origin rate limit (1s) — same origin
    // back-to-back is throttled with the generic rate text; a
    // distinct origin is not.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    match probe(&session, format!("http://{c_addr}/c.m3u8")).await {
        Ok(CommandReply::MediaProbe { .. }) => {}
        other => panic!("the window elapsed: {other:?}"),
    }
    let throttled = probe(&session, format!("http://{c_addr}/c.m3u8"))
        .await
        .err()
        .unwrap_or_else(|| panic!("same-origin back-to-back is throttled"));
    assert!(
        throttled.to_string().contains("probe rate limit"),
        "{throttled}"
    );
    assert!(
        !throttled.to_string().contains("taiji.media."),
        "the rate face keeps the generic text form: {throttled}"
    );
    let (d_addr, _d_hits) = slow_origin("/d.m3u8", 0).await;
    match probe(&session, format!("http://{d_addr}/d.m3u8")).await {
        Ok(CommandReply::MediaProbe { .. }) => {}
        other => panic!("a distinct origin is not throttled: {other:?}"),
    }

    // ---- Gate ④: the opaque-token TTL's anti-forgery face — a
    // fabricated token never substitutes a snapshot (the mechanics
    // of the 10min expiry are pinned by the `media.rs` unit face
    // `probe_token_cache_ttl_and_antiforgery`; the e2e row here is
    // the fabricated-token arm over the real RPC-shaped path).
    let err = session
        .call(SessionCommand::AddMedia {
            url: format!("http://{d_addr}/d.m3u8"),
            options: std::collections::BTreeMap::from([
                ("dir".to_string(), dir.display().to_string()),
                (
                    "media-allow-private-key-url".to_string(),
                    "true".to_string(),
                ),
                (
                    "probe-token".to_string(),
                    "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                ),
            ]),
            cookies: Vec::new(),
            position: None,
        })
        .await
        .err()
        .unwrap_or_else(|| panic!("a fabricated token is rejected"));
    assert!(
        err.to_string().contains("taiji.media.probe_expired"),
        "{err}"
    );
    // A live token consumes cleanly (the positive arm).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let token = match probe(&session, format!("http://{c_addr}/c.m3u8")).await {
        Ok(CommandReply::MediaProbe { token, .. }) => token,
        other => panic!("{other:?}"),
    };
    let gid = match session
        .call(SessionCommand::AddMedia {
            url: format!("http://{c_addr}/c.m3u8"),
            options: std::collections::BTreeMap::from([
                ("dir".to_string(), dir.display().to_string()),
                (
                    "media-allow-private-key-url".to_string(),
                    "true".to_string(),
                ),
                ("probe-token".to_string(), token),
            ]),
            cookies: Vec::new(),
            position: None,
        })
        .await
    {
        Ok(CommandReply::Gid(g)) => g,
        other => panic!("{other:?}"),
    };
    // The task runs to a terminal state over the mock media playlist
    // (a single TS segment — the honest terminal here is Error's
    // synthesis refusal or Complete; either proves the token
    // consumed and the pipeline ran, which is this gate's face).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let st = session
            .call(SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: Vec::new(),
            })
            .await;
        if let Ok(CommandReply::TorrentStatus(v)) = st {
            if matches!(v.status, StatusKind::Complete | StatusKind::Error) {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never reached a terminal state"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
