//! Mock (axum) wire-level cross-validation: manual redirects (relative
//! Location / loops / hop limit), cross-host credential stripping,
//! identity compression negotiation, per-domain cookie jar sending,
//! and the UA/Range transport face.
//!
//! The mock face adds no TLS termination: the https→http downgrade is
//! pure decision logic covered by unit tests (client.rs); this file
//! verifies all http-side wire behavior.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use serde_json::{Value, json};

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::cookies::CookieJar;
use taiji_http::error::HttpError;
use taiji_http::traits::{AuthScheme, RequestCtx};

/// Spawn the mock on a random 127.0.0.1 port and return its address.
async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    addr
}

fn client() -> HttpClient {
    HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"))
}

fn authed_ctx() -> RequestCtx {
    RequestCtx {
        headers: vec![
            ("Authorization".to_string(), "Bearer topsecret".to_string()),
            ("Proxy-Authorization".to_string(), "Basic prx".to_string()),
            ("X-Custom".to_string(), "keepme".to_string()),
        ],
        cookies: vec![("sid".to_string(), "abc".to_string())],
        auth: Some(AuthScheme::Basic {
            user: "u".to_string(),
            passwd: "p".to_string(),
        }),
        ..RequestCtx::default()
    }
}

/// A 3xx redirect response (Location relative/absolute as given by the
/// caller). The Location is built from obs-text bytes — real servers
/// do send non-ASCII (IDN/UTF-8) Locations.
fn redirect(loc: String) -> Response {
    let value = axum::http::HeaderValue::from_bytes(loc.as_bytes())
        .unwrap_or_else(|e| panic!("location value '{loc}': {e}"));
    (StatusCode::FOUND, [(header::LOCATION, value)]).into_response()
}

/// Echo the request headers of interest as JSON.
async fn echo(headers: HeaderMap) -> Json<Value> {
    let h = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    Json(json!({
        "authorization": h("authorization"),
        "proxy-authorization": h("proxy-authorization"),
        "cookie": h("cookie"),
        "user-agent": h("user-agent"),
        "accept-encoding": h("accept-encoding"),
        "range": h("range"),
        "x-custom": h("x-custom"),
    }))
}

/// Read the body and parse it as JSON (the reqwest json feature is
/// off, so text + parse).
async fn body_json(resp: reqwest::Response) -> Value {
    let text = resp.text().await.unwrap_or_else(|e| panic!("body: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("json '{text}': {e}"))
}

/// WHATWG URL resolution of a relative Location chain plus final URL
/// accounting.
///
/// `/start` →302→ `sub/step2` (relative path) →301→ `../final.bin`
/// (dot segments normalized) →200 `payload`.
#[tokio::test]
async fn redirect_chain_relative_resolution_and_final_url() {
    let app = Router::new()
        .route(
            "/start",
            get(|| async { redirect("sub/step2".to_string()) }),
        )
        .route(
            "/sub/step2",
            get(|| async { redirect("../final.bin".to_string()) }),
        )
        .route("/final.bin", get(|| async { "payload" }))
        .route("/echo", get(echo));
    let addr = spawn(app).await;
    let base = format!("http://{addr}");

    let followed = client()
        .get(&format!("{base}/start"), &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));

    assert_eq!(followed.hops, 2);
    assert_eq!(followed.final_url.as_str(), format!("{base}/final.bin"));
    assert_eq!(followed.final_url_path(), "/final.bin"); // path form, query stripped
    let body = followed
        .response
        .text()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"));
    assert_eq!(body, "payload");
}

/// visited-set loop detection: A→B→A must be rejected before the
/// second lap.
#[tokio::test]
async fn redirect_loop_detected() {
    let app = Router::new()
        .route("/loop-a", get(|| async { redirect("/loop-b".to_string()) }))
        .route("/loop-b", get(|| async { redirect("/loop-a".to_string()) }));
    let addr = spawn(app).await;

    let res = client()
        .get(&format!("http://{addr}/loop-a"), &RequestCtx::default())
        .await;
    assert!(matches!(res, Err(HttpError::RedirectLoop)), "{res:?}");
}

/// Hop limit: an infinite chain is rejected at the 21st redirect
/// (default 20 hops).
#[tokio::test]
async fn redirect_hop_limit_enforced() {
    let app = Router::new().route(
        "/hop/{n}",
        get(|Path(n): Path<u32>| async move { redirect(format!("/hop/{}", n + 1)) }),
    );
    let addr = spawn(app).await;

    let res = client()
        .get(&format!("http://{addr}/hop/0"), &RequestCtx::default())
        .await;
    assert!(
        matches!(res, Err(HttpError::RedirectLimit { max: 20 })),
        "{res:?}"
    );
}

/// A cross-host (different port = different authority) redirect strips
/// credential headers; non-credential headers pass through intact.
#[tokio::test]
async fn cross_host_redirect_strips_credentials() {
    let sink_app = Router::new().route("/sink", get(echo));
    let sink_addr = spawn(sink_app).await;

    let sink = sink_addr.to_string();
    let redir_app = Router::new().route(
        "/redir",
        get(move || {
            let loc = format!("http://{sink}/sink");
            async move { redirect(loc) }
        }),
    );
    let redir_addr = spawn(redir_app).await;

    let followed = client()
        .get(&format!("http://{redir_addr}/redir"), &authed_ctx())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    assert_eq!(followed.hops, 1);

    let seen = body_json(followed.response).await;
    assert_eq!(seen["authorization"], Value::Null, "{seen}");
    assert_eq!(seen["proxy-authorization"], Value::Null, "{seen}");
    assert_eq!(seen["cookie"], Value::Null, "{seen}"); // explicit cookie pair stripped too
    assert_eq!(seen["x-custom"], json!("keepme"), "{seen}"); // non-credential header kept
}

/// A same-host redirect keeps all credentials (preset Basic / explicit
/// cookie pair).
#[tokio::test]
async fn same_host_redirect_keeps_credentials() {
    let app = Router::new()
        .route("/redir", get(|| async { redirect("/sink".to_string()) }))
        .route("/sink", get(echo));
    let addr = spawn(app).await;

    let ctx = RequestCtx {
        cookies: vec![("sid".to_string(), "abc".to_string())],
        auth: Some(AuthScheme::Basic {
            user: "u".to_string(),
            passwd: "p".to_string(),
        }),
        ..RequestCtx::default()
    };
    let followed = client()
        .get(&format!("http://{addr}/redir"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));

    let seen = body_json(followed.response).await;
    // Preset Basic header (kept on same host; base64("u:p") = "dTpw").
    assert_eq!(seen["authorization"], json!("Basic dTpw"), "{seen}");
    let cookie = seen["cookie"].as_str().unwrap_or_default();
    assert!(cookie.contains("sid=abc"), "{cookie}");
}

/// Data-plane policy: explicit `Accept-Encoding: identity`, default UA,
/// Range passthrough.
#[tokio::test]
async fn identity_encoding_default_ua_and_range_passthrough() {
    let app = Router::new().route("/sink", get(echo));
    let addr = spawn(app).await;
    let c = client();

    let followed = c
        .get_range(&format!("http://{addr}/sink"), &RequestCtx::default(), 0, 0)
        .await
        .unwrap_or_else(|e| panic!("get_range: {e}"));
    let seen = body_json(followed.response).await;
    assert_eq!(seen["accept-encoding"], json!("identity"), "{seen}");
    assert_eq!(seen["range"], json!("bytes=0-0"), "{seen}");
    let ua = seen["user-agent"].as_str().unwrap_or_default();
    assert!(ua.starts_with("taiji/"), "{ua}");

    // identity_encoding=false → the header is not set (reqwest gzip
    // auto-negotiation).
    let cfg = ClientConfig {
        identity_encoding: false,
        ..ClientConfig::default()
    };
    let negotiated = HttpClient::new(cfg).unwrap_or_else(|e| panic!("{e}"));
    let followed = negotiated
        .get(&format!("http://{addr}/sink"), &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    let seen = body_json(followed.response).await;
    assert_ne!(seen["accept-encoding"], json!("identity"), "{seen}");
}

/// `--load-cookies` jar: sent per domain (the host-only 127.0.0.1
/// entry matches, the other domain is not sent), merged with the
/// explicit cookie pair into a single header.
#[tokio::test]
async fn cookie_jar_domain_scoped_over_wire() {
    let app = Router::new().route("/sink", get(echo));
    let addr = spawn(app).await;

    let jar_text = "127.0.0.1\tFALSE\t/\tFALSE\t0\tjarhost\tyes\n\
                    example.com\tTRUE\t/\tFALSE\t0\tjardomain\tno\n"
        .to_string();
    let jar = CookieJar::parse_netscape(&jar_text);
    let cfg = ClientConfig::default();
    let c = HttpClient::with_jar(cfg, jar).unwrap_or_else(|e| panic!("{e}"));

    let followed = c
        .get(&format!("http://{addr}/sink"), &authed_ctx())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    let seen = body_json(followed.response).await;
    let cookie = seen["cookie"].as_str().unwrap_or_default();
    assert!(cookie.contains("sid=abc"), "{cookie}"); // explicit pair
    assert!(cookie.contains("jarhost=yes"), "{cookie}"); // jar (host match)
    assert!(!cookie.contains("jardomain"), "{cookie}"); // jar (other domain not sent)
}

/// Read-idle timeout wiring: `--timeout` (read_timeout) shorter than
/// the server's response delay → a transport error, after at least the
/// configured timeout (distinct from an immediate connection-refused
/// shape).
#[tokio::test]
async fn read_timeout_wired() {
    let app = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            "late"
        }),
    );
    let addr = spawn(app).await;

    let cfg = ClientConfig {
        read_timeout: std::time::Duration::from_millis(50),
        ..ClientConfig::default()
    };
    let c = HttpClient::new(cfg).unwrap_or_else(|e| panic!("{e}"));
    let t0 = std::time::Instant::now();
    let res = c
        .get(&format!("http://{addr}/slow"), &RequestCtx::default())
        .await;
    assert!(matches!(res, Err(HttpError::Transport(_))), "{res:?}");
    assert!(
        t0.elapsed() >= std::time::Duration::from_millis(45),
        "failed too fast for a read timeout: {:?}",
        t0.elapsed()
    );
}

/// Credential revival attack: A→B (cross-host, stripped) →B' (same-host
/// self-hop) — an adjacent-hop comparison would recompute keep=true and
/// send the Authorization/Basic preset/explicit cookies stripped at the
/// first hop straight to B' (one hop is enough for an attacker to
/// harvest). Credential stripping must be monotonic: once stripped,
/// every later hop (including same-host self-hops and hops back into
/// the first hop's scope) stays stripped.
#[tokio::test]
async fn credential_strip_not_revived_by_same_host_hop() {
    let followed = run_revival_chain(
        "127.0.0.1",
        "http://127.0.0.1:{port}/hop",
        "http://127.0.0.1:{port}/final",
        &[],
        ClientConfig::default(),
    )
    .await;
    assert_eq!(followed.hops, 2);
    let seen = body_json(followed.response).await;
    assert_eq!(seen["authorization"], Value::Null, "{seen}");
    assert_eq!(seen["proxy-authorization"], Value::Null, "{seen}");
    assert_eq!(seen["cookie"], Value::Null, "{seen}");
}

/// Same attack, host-case variant: B' differing from B only by case
/// (a difference normalization erases) must not revive credentials
/// either. DNS pinning (pinned_resolve) keeps the .test names off real
/// resolution; both forms must be equivalent on the same scope key.
#[tokio::test]
async fn revival_blocked_via_host_case_variant() {
    let followed = run_revival_chain(
        "127.0.0.1",
        "http://evil.test:{port}/hop",
        "http://EVIL.TEST:{port}/final",
        &[("evil.test", "127.0.0.1")],
        ClientConfig::default(),
    )
    .await;
    assert_eq!(followed.hops, 2);
    let seen = body_json(followed.response).await;
    assert_eq!(seen["authorization"], Value::Null, "{seen}");
    assert_eq!(seen["cookie"], Value::Null, "{seen}");
}

/// Attack variant: IDN — B in punycode, B' in Unicode form (the same
/// scope after IDNA normalization).
#[tokio::test]
async fn revival_blocked_via_idn_variant() {
    let followed = run_revival_chain(
        "127.0.0.1",
        "http://xn--e1afmkfd.test:{port}/hop",
        "http://пример.test:{port}/final",
        &[("xn--e1afmkfd.test", "127.0.0.1")],
        ClientConfig::default(),
    )
    .await;
    assert_eq!(followed.hops, 2, "final: {}", followed.final_url);
    let seen = body_json(followed.response).await;
    assert_eq!(seen["authorization"], Value::Null, "{seen}");
    assert_eq!(seen["cookie"], Value::Null, "{seen}");
}

/// Attack variant: IPv6 — B' appears in the fully expanded zero form
/// `[0:0:0:0:0:0:0:1]` (normalized to `[::1]` by URL parsing, same
/// scope).
#[tokio::test]
async fn revival_blocked_via_ipv6_zero_form() {
    let followed = run_revival_chain(
        "[::1]",
        "http://[::1]:{port}/hop",
        "http://[0:0:0:0:0:0:0:1]:{port}/final",
        &[],
        ClientConfig::default(),
    )
    .await;
    assert_eq!(followed.hops, 2);
    let seen = body_json(followed.response).await;
    assert_eq!(seen["authorization"], Value::Null, "{seen}");
    assert_eq!(seen["cookie"], Value::Null, "{seen}");
}

fn pinned_addr(ip: &str, port: u16) -> std::net::SocketAddr {
    format!("{ip}:{port}")
        .parse()
        .unwrap_or_else(|e| panic!("pinned addr: {e}"))
}

/// Shared driver for the A→B→B' revival chains: origin /start →
/// (cross-host) → `b_hop_pattern` (evil /hop) → `b_prime_pattern` (a
/// same-scope spelling of B) → evil /final echo. Returns the final
/// Followed for each variant to assert on. `{port}` is the evil server
/// port; `bind` is the evil bind address (`[::1]` for the IPv6
/// variant); `pins` are (name, IP) DNS pin entries — .test/IDN names
/// cannot really resolve (an explicit URL port always wins over the
/// pinned port).
async fn run_revival_chain(
    bind: &str,
    b_hop_pattern: &str,
    b_prime_pattern: &str,
    pins: &[(&str, &str)],
    mut cfg: ClientConfig,
) -> taiji_http::client::Followed {
    // Bind the evil server first: B and B' must share host:port (the
    // same-host self-hop).
    let evil_listener = tokio::net::TcpListener::bind(format!("{bind}:0"))
        .await
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    let evil_addr = evil_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let port = evil_addr.port().to_string();
    let b_prime = b_prime_pattern.replace("{port}", &port);
    let evil_app = Router::new()
        .route(
            "/hop",
            get(move || {
                let loc = b_prime.clone();
                async move { redirect(loc) }
            }),
        )
        .route("/final", get(echo));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(evil_listener, evil_app).await {
            panic!("serve: {e}");
        }
    });

    // origin /start → B (the cross-host hop that triggers stripping).
    let start_loc = b_hop_pattern.replace("{port}", &port);
    let start_app = Router::new().route(
        "/start",
        get(move || {
            let loc = start_loc.clone();
            async move { redirect(loc) }
        }),
    );
    let start_addr = spawn(start_app).await;

    if !pins.is_empty() {
        cfg.pinned_resolve = pins
            .iter()
            .map(|(name, ip)| ((*name).to_string(), pinned_addr(ip, 0)))
            .collect();
    }

    HttpClient::new(cfg)
        .unwrap_or_else(|e| panic!("client: {e}"))
        .get(
            &format!("http://{}:{}/start", start_addr.ip(), start_addr.port()),
            &authed_ctx(),
        )
        .await
        .unwrap_or_else(|e| panic!("get: {e}"))
}

/// Query-variant loop (/qloop → /qloop?i=1 → /qloop?i=2 → …): with
/// the visited key being the full URL, every variant looks "new",
/// bypasses loop detection, burns the 20-hop budget, and misreports
/// RedirectLimit. The key must include a (scheme, host, port, path)
/// dimension so this is judged RedirectLoop.
#[tokio::test]
async fn query_variant_loop_is_redirect_loop_not_limit() {
    let app = Router::new().route(
        "/qloop",
        get(|q: axum::extract::RawQuery| async move {
            let i =
                q.0.as_deref()
                    .and_then(|s| s.strip_prefix("i="))
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
            redirect(format!("/qloop?i={}", i + 1))
        }),
    );
    let addr = spawn(app).await;

    let res = client()
        .get(&format!("http://{addr}/qloop"), &RequestCtx::default())
        .await;
    assert!(matches!(res, Err(HttpError::RedirectLoop)), "{res:?}");
}

/// Non-UTF-8 Location: a 3xx carrying a Location with opaque bytes
/// (obs-text) must not be silently surfaced as a terminal 3xx without
/// a Location — it is lossy-converted and joined/followed as usual
/// (the replacement character is percent-encoded per WHATWG URL).
#[tokio::test]
async fn non_utf8_location_followed_lossy() {
    let app = Router::new()
        .route(
            "/start",
            get(|| async {
                let loc = axum::http::HeaderValue::from_bytes(b"/sink\xff")
                    .unwrap_or_else(|e| panic!("header value: {e}"));
                (StatusCode::FOUND, [(header::LOCATION, loc)], "jump-body").into_response()
            }),
        )
        // Wildcard segment: the lossy replacement character
        // (U+FFFD → %EF%BF%BD) cannot be a static route.
        .route("/sink{*rest}", get(|| async { "payload" }));
    let addr = spawn(app).await;

    let followed = client()
        .get(&format!("http://{addr}/start"), &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    assert_eq!(
        followed.hops, 1,
        "3xx with non-utf8 Location must be followed, not returned as terminal"
    );
    assert_eq!(followed.response.status(), 200);
    assert!(
        followed.final_url.as_str().ends_with("/sink%EF%BF%BD"),
        "final url: {}",
        followed.final_url
    );
}

/// 3xx body drain: a 302 whose body exceeds the transport read buffer
/// (32KiB) but stays under the drain cap must be drained to EOF so the
/// connection returns to the pool and both hops reuse one TCP
/// connection (a hand-written HTTP/1.1 server counts accepts — axum
/// cannot observe the connection count).
#[tokio::test]
async fn redirect_body_drained_enables_connection_reuse() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HOP_BODY: usize = 32 * 1024; // exceeds the read buffer; < MAX_REDIRECT_DRAIN_BYTES
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let conns = Arc::new(AtomicUsize::new(0));
    let counter = conns.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut pending: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 2048];
                loop {
                    let n = match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    pending.extend_from_slice(&chunk[..n]);
                    // Accumulate a full request head (GET has no body),
                    // then answer by path.
                    let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let req = String::from_utf8_lossy(&pending[..end]).to_string();
                    pending.clear();
                    if req.starts_with("GET /start ") {
                        // 3xx + large body: the connection cannot be
                        // reused without draining.
                        let head = format!(
                            "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: {HOP_BODY}\r\n\r\n"
                        );
                        if sock.write_all(head.as_bytes()).await.is_err() {
                            return;
                        }
                        let filler = vec![b'x'; HOP_BODY];
                        if sock.write_all(&filler).await.is_err() {
                            return;
                        }
                    } else if sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    let followed = client()
        .get(&format!("http://{addr}/start"), &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    assert_eq!(followed.hops, 1);
    let body = followed
        .response
        .text()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"));
    assert_eq!(body, "final");

    assert_eq!(
        conns.load(Ordering::Relaxed),
        1,
        "both hops must ride one keep-alive connection after the 3xx body is drained"
    );
}

// ---- redirect-target IP hygiene (aligned with the initial-URL policy):
// ---- e2e regression anchors ----

/// Regression anchor (allow side): a loopback-initial mock 302 to
/// another loopback port is allowed. A localhost initial URL counts as
/// a restricted origin (trusted LAN/tunnel topology), so redirect IP
/// hygiene follows the initial-URL policy and allows every hop.
#[tokio::test]
async fn loopback_initial_redirect_to_other_loopback_port_allowed() {
    let final_app = Router::new().route("/final", get(|| async { "lan-ok" }));
    let final_addr = spawn(final_app).await;

    let loc = format!("http://{final_addr}/final");
    let start_app = Router::new().route(
        "/start",
        get(move || {
            let loc = loc.clone();
            async move { redirect(loc) }
        }),
    );
    let start_addr = spawn(start_app).await;

    let followed = client()
        .get(
            &format!("http://{start_addr}/start"),
            &RequestCtx::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("loopback->loopback cross-port hops must pass: {e:?}"));
    assert_eq!(followed.hops, 1);
    let body = followed
        .response
        .text()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"));
    assert_eq!(body, "lan-ok");
}

/// Regression anchor (restricted-initial fully allowed): a
/// loopback-initial mock 302 to the cloud metadata literal
/// `http://169.254.169.254/latest/meta-data/` is allowed — the request
/// really goes out and failure must be a transport error, not
/// `RedirectToRestrictedIp` (a localhost/LAN initial jumping to
/// intranet/metadata endpoints is trusted-topology semantics; this
/// defense does not tighten it). A short connect_timeout makes the
/// unreachable link-local target fail fast.
#[tokio::test]
async fn loopback_initial_redirect_to_linklocal_literal_allowed() {
    // Environment guard: cloud CI runners (Azure/GCP) host a LIVE
    // metadata service on 169.254.169.254 — the "unreachable target"
    // premise of this test does not hold there and the followed 404
    // would be misread as a failure. Probe cheaply and skip loudly.
    if tokio::net::TcpStream::connect("169.254.169.254:80")
        .await
        .is_ok()
    {
        eprintln!(
            "SKIP(redirect.linklocal): a live metadata service answers at \
             169.254.169.254 on this host (cloud runner) — the \
             unreachable-target premise does not hold"
        );
        return;
    }
    let loc = "http://169.254.169.254/latest/meta-data/".to_string();
    let app = Router::new().route(
        "/start",
        get(move || {
            let loc = loc.clone();
            async move { redirect(loc) }
        }),
    );
    let addr = spawn(app).await;

    let cfg = ClientConfig {
        connect_timeout: std::time::Duration::from_secs(1),
        read_timeout: std::time::Duration::from_secs(1),
        ..ClientConfig::default()
    };
    let c = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let res = c
        .get(&format!("http://{addr}/start"), &RequestCtx::default())
        .await;
    match res {
        // Allowed: the request goes out; the unreachable link-local
        // endpoint yields a transport error.
        Err(HttpError::Transport(_)) => {}
        Err(e @ HttpError::RedirectToRestrictedIp { .. }) => {
            panic!(
                "a loopback initial must not reject restricted targets \
             (the aligned-initial policy): {e:?}"
            )
        }
        other => panic!("expected a transport error (the target is unreachable), got {other:?}"),
    }
}
