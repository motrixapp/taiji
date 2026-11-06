//! Mock lab v2: Basic/Digest challenge-response authentication, proxy
//! absolute-form + userinfo authentication, slow-tail read idle (the
//! `--timeout` destination), and no-retry on 429 — wire-level
//! cross-validation of the behavior matrix.
//!
//! Carriers: an axum mock plus a raw TCP mock (the proxy absolute-form
//! and mid-transfer stall shapes need wire-level control that axum's
//! router cannot express).

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use taiji_http::auth::{self, Challenge};
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::error::HttpError;
use taiji_http::probe::{ProbeVerdict, probe_uri};
use taiji_http::traits::{AuthScheme, RequestCtx};

/// Test-only Result unwrap (lints forbid unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Spawn the mock on a random 127.0.0.1 port and return its base URL.
async fn spawn(app: Router) -> String {
    let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "local_addr");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    format!("http://{addr}")
}

/// Probe-success shape (decision row 1): 206 + `bytes 0-0/123456`.
fn row1_response() -> Response {
    (
        StatusCode::PARTIAL_CONTENT,
        [
            (header::CONTENT_RANGE, "bytes 0-0/123456"),
            (header::ACCEPT_RANGES, "bytes"),
            (header::CONTENT_LENGTH, "1"),
        ],
        "x",
    )
        .into_response()
}

fn client() -> HttpClient {
    HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"))
}

/// Request context with preset Basic credentials (built as one struct
/// literal, per clippy field_reassign_with_default).
fn basic_ctx(user: &str, passwd: &str) -> RequestCtx {
    RequestCtx {
        auth: Some(AuthScheme::Basic {
            user: user.into(),
            passwd: passwd.into(),
        }),
        ..RequestCtx::default()
    }
}

/// Expected preset Basic header (std-only base64 implementation).
fn basic_header(user: &str, passwd: &str) -> String {
    format!("Basic {}", b64(format!("{user}:{passwd}").as_bytes()))
}

/// Standard base64 (self-contained — no new dependency).
fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ---------- Basic preemptive ----------

/// Basic preemptive (`--http-user/--http-passwd` → `AuthScheme::Basic`):
/// valid credentials get 206 directly; no credentials → 401 surfaces as
/// an out-of-table error (probe semantics unchanged).
#[tokio::test]
async fn basic_preemptive_succeeds_and_absence_stays_unexpected() {
    let app = Router::new().route(
        "/f.bin",
        get(|headers: HeaderMap| async move {
            match headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            {
                Some(a) if a == basic_header("u", "p") => row1_response(),
                _ => (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"t\"")],
                    "nope",
                )
                    .into_response(),
            }
        }),
    );
    let base = spawn(app).await;

    let ctx = basic_ctx("u", "p");
    let verdict = probe_uri(&client(), &format!("{base}/f.bin"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("basic auth must pass: {e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));

    // No credentials → 401 surfaces unchanged (UnexpectedResponse
    // semantics are untouched by the auth face).
    let res = probe_uri(&client(), &format!("{base}/f.bin"), &RequestCtx::default()).await;
    assert_eq!(res, Err(HttpError::UnexpectedResponse { status: 401 }));
}

/// Wrong Basic credentials: the preset is rejected →
/// `taiji.auth.failed` (resending the same credentials cannot succeed,
/// so the client short-circuits without extra round trips).
#[tokio::test]
async fn basic_rejected_credentials_are_auth_failed() {
    let app = Router::new().route(
        "/f.bin",
        get(|headers: HeaderMap| async move {
            match headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            {
                Some(a) if a == basic_header("u", "p") => row1_response(),
                _ => (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"t\"")],
                    "nope",
                )
                    .into_response(),
            }
        }),
    );
    let base = spawn(app).await;
    let ctx = basic_ctx("u", "wrong");
    let res = probe_uri(&client(), &format!("{base}/f.bin"), &ctx).await;
    match res {
        Err(HttpError::AuthFailed(m)) => assert!(m.contains("basic"), "{m}"),
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

// ---------- Digest challenge-response ----------

/// Digest-protected app: the 401 carries `WWW-Authenticate`; an
/// Authorization answer is accepted by independently recomputing the
/// response value (RFC 7616 §3.4 formula) → the row 1 shape.
fn digest_app(user: &'static str, passwd: &'static str, algorithm: &'static str) -> Router {
    const REALM: &str = "t";
    const NONCE: &str = "deadbeefcafe";
    Router::new().route(
        "/f.bin",
        get(move |headers: HeaderMap| async move {
            if let Some(authz) = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                && let (Some(got), Some(uri), Some(nc), Some(cnonce)) = (
                    digest_param(authz, "response"),
                    digest_param(authz, "uri"),
                    digest_param(authz, "nc"),
                    digest_param(authz, "cnonce"),
                )
            {
                let want = expected_digest_response(
                    user, passwd, REALM, NONCE, &uri, &nc, &cnonce, algorithm,
                );
                if got == want {
                    return row1_response();
                }
            }
            let challenge = format!(
                "Digest realm=\"{REALM}\", nonce=\"{NONCE}\", qop=\"auth\", \
                 algorithm={algorithm}, opaque=\"opq\""
            );
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, challenge)],
                "auth required",
            )
                .into_response()
        }),
    )
}

/// Expected response value (independent recomputation; the same
/// formula as the client side — RFC 7616 §3.4; `algorithm` = MD5 |
/// SHA-256).
#[allow(clippy::too_many_arguments)]
fn expected_digest_response(
    user: &str,
    passwd: &str,
    realm: &str,
    nonce: &str,
    uri: &str,
    nc: &str,
    cnonce: &str,
    algorithm: &str,
) -> String {
    let h = |b: &[u8]| -> String {
        match algorithm {
            "SHA-256" => {
                use sha2::Digest as _;
                let mut d = sha2::Sha256::new();
                sha2::Digest::update(&mut d, b);
                sha2::Digest::finalize(d)
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect()
            }
            _ => auth::md5_hex(b),
        }
    };
    let ha1 = h(format!("{user}:{realm}:{passwd}").as_bytes());
    let ha2 = h(format!("GET:{uri}").as_bytes());
    h(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes())
}

/// Minimal auth-param extraction (quoted/token forms).
fn digest_param(header: &str, key: &str) -> Option<String> {
    let rest = header.strip_prefix("Digest ")?;
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        if k.trim().eq_ignore_ascii_case(key) {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Digest (MD5, qop=auth): 401 challenge → Authorization answer → 206.
#[tokio::test]
async fn digest_challenge_md5_answered() {
    digest_round_trip("MD5").await;
}

/// Digest (SHA-256, the RFC 7616 recommended algorithm).
#[tokio::test]
async fn digest_challenge_sha256_answered() {
    digest_round_trip("SHA-256").await;
}

async fn digest_round_trip(algorithm: &'static str) {
    let base = spawn(digest_app("u", "p", algorithm)).await;
    let ctx = basic_ctx("u", "p");
    let verdict = probe_uri(&client(), &format!("{base}/f.bin"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("digest {algorithm} must pass: {e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));
}

/// Wrong Digest credentials: the answer still gets 401 →
/// `taiji.auth.failed` (each URL is answered exactly once, no loop).
#[tokio::test]
async fn digest_wrong_password_is_auth_failed() {
    let base = spawn(digest_app("u", "wrong-passwd", "MD5")).await;
    let ctx = basic_ctx("u", "p");
    let res = probe_uri(&client(), &format!("{base}/f.bin"), &ctx).await;
    assert!(
        matches!(res, Err(HttpError::AuthFailed(_))),
        "expected AuthFailed, got {res:?}"
    );
}

/// Unsupported algorithm (the -sess form): explicit AuthFailed, no
/// silent downgrade.
#[tokio::test]
async fn digest_sess_algorithm_rejected_explicitly() {
    let base = spawn(digest_app("u", "p", "MD5-sess")).await;
    let ctx = RequestCtx {
        auth: Some(AuthScheme::Digest {
            user: "u".into(),
            passwd: "p".into(),
        }),
        ..RequestCtx::default()
    };
    let res = probe_uri(&client(), &format!("{base}/f.bin"), &ctx).await;
    match res {
        Err(HttpError::AuthFailed(m)) => {
            assert!(m.to_ascii_lowercase().contains("md5-sess"), "{m}")
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

// ---------- Digest stale renegotiation (RFC 7616 §3.6) ----------

/// Stale-challenge reply builder (`stale=true` = reissue for an
/// expired nonce only).
fn stale_challenge(nonce: &str, realm: &str, stale: bool) -> Response {
    let extra = if stale { ", stale=true" } else { "" };
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            format!(
                "Digest realm=\"{realm}\", nonce=\"{nonce}\", \
                 qop=\"auth\", algorithm=MD5{extra}"
            ),
        )],
        "nonce stale",
    )
        .into_response()
}

/// Digest stale app: no Authorization → first challenge N1; an N1
/// answer → 401 with `stale=true` reissuing N2 (credentials are not
/// rechecked — stale means credentials were already verified and only
/// the nonce expired, RFC 7616 §3.6); an N2 answer is verified by the
/// formula → row 1.
fn digest_stale_app(user: &'static str, passwd: &'static str) -> Router {
    const REALM: &str = "t";
    const NONCE1: &str = "pc12-stale-n1";
    const NONCE2: &str = "pc12-stale-n2";
    Router::new().route(
        "/f.bin",
        get(move |headers: HeaderMap| async move {
            if let Some(authz) = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            {
                if digest_param(authz, "nonce").as_deref() == Some(NONCE1) {
                    return stale_challenge(NONCE2, REALM, true);
                }
                if digest_param(authz, "nonce").as_deref() == Some(NONCE2)
                    && let (Some(got), Some(uri), Some(nc), Some(cnonce)) = (
                        digest_param(authz, "response"),
                        digest_param(authz, "uri"),
                        digest_param(authz, "nc"),
                        digest_param(authz, "cnonce"),
                    )
                    && got
                        == expected_digest_response(
                            user, passwd, REALM, NONCE2, &uri, &nc, &cnonce, "MD5",
                        )
                {
                    return row1_response();
                }
            }
            stale_challenge(NONCE1, REALM, false)
        }),
    )
}

/// `stale=true` renegotiation: an expired nonce with valid credentials
/// → the same credentials answer a fresh nonce once → success (the RFC
/// 7616 §3.6 SHOULD retry). nonce_nc is keyed per nonce: N2's nc
/// starts from 1.
#[tokio::test]
async fn digest_stale_true_renegotiates_once_and_succeeds() {
    let base = spawn(digest_stale_app("u", "p")).await;
    let ctx = basic_ctx("u", "p");
    let verdict = probe_uri(&client(), &format!("{base}/f.bin"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("stale renegotiation must pass: {e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));
}

/// Loop anchor: a malicious server endlessly reissuing `stale=true`
/// nonces — a URL is re-answered for stale at most once; a second
/// stale still yields [`HttpError::AuthFailed`] (request count bounded:
/// first hit + answer + one stale re-answer = 3).
#[tokio::test]
async fn digest_endless_stale_stays_auth_failed_with_bounded_requests() {
    let hits = Arc::new(AtomicUsize::new(0));
    let nonce_seq = Arc::new(AtomicUsize::new(0));
    let (hits_c, seq_c) = (Arc::clone(&hits), Arc::clone(&nonce_seq));
    let app = Router::new().route(
        "/f.bin",
        get(move |_headers: HeaderMap| async move {
            hits_c.fetch_add(1, Ordering::Relaxed);
            let nonce = format!("pc12-endless-{}", seq_c.fetch_add(1, Ordering::Relaxed));
            stale_challenge(&nonce, "t", true)
        }),
    );
    let base = spawn(app).await;
    let ctx = basic_ctx("u", "p");
    let res = probe_uri(&client(), &format!("{base}/f.bin"), &ctx).await;
    assert!(
        matches!(res, Err(HttpError::AuthFailed(_))),
        "endless stale must stay AuthFailed, got {res:?}"
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "the stale re-answer happens exactly once (stops after 3 requests, no infinite loop)"
    );
}

// ---------- Multiple challenges in one header (RFC 9110 §11.6.1 list) ----------

/// Two challenges in one header: `Basic realm="a", Digest realm="b",
/// nonce=…` (Digest second). With multi-challenge-aware parsing the
/// Digest challenge receives the answer per preference order (the
/// comma separates challenges and parameters alike; the bare `Digest`
/// token after `realm="a"` is a scheme, not a parameter name). The
/// server only accepts a Digest answer.
#[tokio::test]
async fn single_header_multiple_challenges_digest_answered() {
    const REALM: &str = "b";
    const NONCE: &str = "pc12-multi";
    let app = Router::new().route(
        "/f.bin",
        get(move |headers: HeaderMap| async move {
            if let Some(authz) = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                && authz.starts_with("Digest ")
                && let (Some(got), Some(uri), Some(nc), Some(cnonce)) = (
                    digest_param(authz, "response"),
                    digest_param(authz, "uri"),
                    digest_param(authz, "nc"),
                    digest_param(authz, "cnonce"),
                )
                && got
                    == expected_digest_response("u", "p", REALM, NONCE, &uri, &nc, &cnonce, "MD5")
            {
                return row1_response();
            }
            // Two challenges in one WWW-Authenticate header value (not
            // two header lines).
            (
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    format!(
                        "Basic realm=\"a\", Digest realm=\"{REALM}\", \
                         nonce=\"{NONCE}\", qop=\"auth\", algorithm=MD5"
                    ),
                )],
                "pick a scheme",
            )
                .into_response()
        }),
    );
    let base = spawn(app).await;
    let ctx = basic_ctx("u", "p");
    let verdict = probe_uri(&client(), &format!("{base}/f.bin"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("digest in second position must be answered: {e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));
}

/// Challenge-parsing regression (Basic/Digest/unknown scheme — a
/// wire-side supplement to the auth module unit tests; the
/// multi-challenge list form is covered by the
/// `www_authenticate_multi_challenge_single_header` unit test).
#[test]
fn www_authenticate_parse_covers_basic_and_digest() {
    assert_eq!(
        auth::parse_www_authenticate("Basic realm=\"x\""),
        vec![Challenge::Basic]
    );
    assert!(matches!(
        auth::parse_www_authenticate(
            "Digest realm=\"t\", nonce=\"n\", qop=\"auth\", algorithm=MD5"
        )
        .as_slice(),
        [Challenge::Digest(_)]
    ));
    assert_eq!(auth::parse_www_authenticate("NTLM"), Vec::new());
}

// ---------- Proxy (absolute-form + userinfo auth) ----------

/// `--all-proxy`: the request goes to the proxy in absolute-form (the
/// HTTP proxy wire shape); URL userinfo rides in Proxy-Authorization;
/// the proxy replying with the row 1 shape is success.
#[tokio::test]
async fn all_proxy_speaks_absolute_form_with_userinfo() {
    let listener = ok(TcpListener::bind("127.0.0.1:0"), "bind proxy");
    let addr = ok(listener.local_addr(), "proxy addr");
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen_t = seen.clone();
    std::thread::spawn(move || {
        let (mut sock, _) = ok(listener.accept(), "accept");
        let mut buf = [0u8; 4096];
        let n = ok(sock.read(&mut buf), "read request");
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        if let Ok(mut s) = seen_t.lock() {
            s.push(req.clone());
        }
        let head = "HTTP/1.1 206 Partial Content\r\n\
             Content-Range: bytes 0-0/123456\r\n\
             Accept-Ranges: bytes\r\n\
             Content-Length: 1\r\n\
             Connection: close\r\n\r\n";
        ok(sock.write_all(head.as_bytes()), "write head");
        ok(sock.write_all(b"x"), "write body");
    });

    let cfg = ClientConfig {
        proxy: Some(format!("http://proxyuser:proxypass@{addr}")),
        ..ClientConfig::default()
    };
    let cl = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let verdict = probe_uri(&cl, "http://origin.test/f.bin", &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("proxy request must pass: {e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));

    let req = ok(seen.lock(), "seen").join("\n----\n");
    assert!(
        req.contains("GET http://origin.test/f.bin HTTP/1.1"),
        "absolute-form request line required: {req}"
    );
    assert!(
        req.to_ascii_lowercase()
            .contains("proxy-authorization: basic "),
        "userinfo must surface as Proxy-Authorization: {req}"
    );
}

// ---------- Slow-tail read idle (the `--timeout` destination) ----------

/// The server sends response headers plus a partial body, then stalls:
/// zero bytes within the `--timeout` (read_timeout) window → a
/// read-idle error (the `taiji.http.transport` face).
#[tokio::test]
async fn slow_tail_read_idle_times_out() {
    let listener = ok(TcpListener::bind("127.0.0.1:0"), "bind slow");
    let addr = ok(listener.local_addr(), "slow addr");
    std::thread::spawn(move || {
        let (mut sock, _) = ok(listener.accept(), "accept");
        // Read the full request head first (a single read may only
        // capture part of it).
        let mut buf = vec![0u8; 4096];
        let mut filled = 0;
        loop {
            let n = ok(sock.read(&mut buf[filled..]), "read request");
            filled += n;
            if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") || n == 0 {
                break;
            }
        }
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n";
        ok(sock.write_all(head.as_bytes()), "write head");
        ok(sock.write_all(&[1u8, 2, 3]), "write partial body");
        // Stall: never close, never write again (the peer judges the
        // read-idle window).
        loop {
            match sock.read(&mut [0u8; 64]) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    });

    let cfg = ClientConfig {
        read_timeout: Duration::from_millis(400),
        ..ClientConfig::default()
    };
    let cl = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let followed = cl
        .get(&format!("http://{addr}/f.bin"), &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("headers must arrive: {e}"));
    let mut resp = followed.response;
    // Reading the body: 3 bytes arrive, then read idle → timeout error.
    let mut got = 0usize;
    let res = loop {
        match resp.chunk().await {
            Ok(Some(c)) => got += c.len(),
            Ok(None) => break Ok(got),
            Err(e) => break Err(e),
        }
    };
    match res {
        Err(e) => {
            assert!(e.is_timeout(), "expected read-idle timeout, got: {e}");
        }
        Ok(n) => panic!("stalled body must not finish (got {n} bytes)"),
    }
}

// ---------- 429 ----------

/// 429 is an out-of-table status (no dedicated arm in aria2's status
/// switch → EX_BAD_STATUS fallback): fails in one shot, no retry (4xx
/// is not Transport-class).
#[tokio::test]
async fn status_429_fails_immediately_without_retry() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = Router::new().route(
        "/f.bin",
        get(move || async move {
            counter.fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "1")],
                "slow down",
            )
                .into_response()
        }),
    );
    let base = spawn(app).await;

    let mut cfg = ClientConfig::default();
    cfg.retry.max_tries = 5; // 4xx is not Transport-class → retry does not engage
    let cl = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let res = probe_uri(&cl, &format!("{base}/f.bin"), &RequestCtx::default()).await;
    assert_eq!(
        res,
        Err(HttpError::UnexpectedResponse { status: 429 }),
        "429 = an out-of-table status propagates verbatim"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1, "4xx must not retry");
}
