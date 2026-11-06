//! Task-cookie face wire-level cross-validation: Set-Cookie capture
//! into task storage, per-domain/path/Secure re-sending, two-task
//! isolation, re-sending across a redirect chain, and the layering
//! with cross-host credential stripping.
//!
//! Layering invariant (wire level): a cross-host redirect strips
//! explicit credential headers and the explicit cookie pair, but
//! task-store cookies are still re-sent to same-domain targets under
//! the domain-match constraint.

use std::net::SocketAddr;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use serde_json::{Value, json};

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::cookies::CookieStore;
use taiji_http::traits::RequestCtx;

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

/// A 3xx redirect response.
fn redirect(loc: String) -> Response {
    let value = axum::http::HeaderValue::from_bytes(loc.as_bytes())
        .unwrap_or_else(|e| panic!("location value '{loc}': {e}"));
    (StatusCode::FOUND, [(header::LOCATION, value)]).into_response()
}

/// Echo the Cookie header.
async fn echo_cookie(headers: HeaderMap) -> Json<Value> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Json(json!({ "cookie": cookie }))
}

/// Read the body and parse it as JSON (the reqwest json feature is
/// off, so text + parse).
async fn json_body(resp: reqwest::Response) -> Value {
    let text = resp.text().await.unwrap_or_else(|e| panic!("body: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("json '{text}': {e}"))
}

/// Task context: a RequestCtx carrying an independent task store, plus
/// the store handle.
fn task_ctx() -> (RequestCtx, CookieStore) {
    let store = CookieStore::new();
    let ctx = RequestCtx {
        task_cookies: Some(store.clone()),
        ..RequestCtx::default()
    };
    (ctx, store)
}

/// Capture and re-send across a redirect chain: /start issues
/// `Set-Cookie: sid=abc; Path=/` then 302 → /final — the hop response's
/// Set-Cookie is captured and re-sent on the next hop's request.
#[tokio::test]
async fn set_cookie_captured_and_resent_on_redirect_chain() {
    let app = Router::new()
        .route(
            "/start",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [
                        (header::SET_COOKIE, "sid=abc; Path=/"),
                        (header::LOCATION, "/final"),
                    ],
                )
                    .into_response()
            }),
        )
        .route("/final", get(echo_cookie));
    let addr = spawn(app).await;

    let (ctx, store) = task_ctx();
    let followed = HttpClient::new(ClientConfig::default())
        .unwrap_or_else(|e| panic!("client: {e}"))
        .get(&format!("http://{addr}/start"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    assert_eq!(followed.hops, 1);

    let seen = json_body(followed.response).await;
    let cookie = seen["cookie"].as_str().unwrap_or_default();
    assert!(cookie.contains("sid=abc"), "{seen}");

    // Captured into the store (for re-sending on later segment/retry
    // requests).
    assert_eq!(store.len(), 1);
    assert_eq!(store.snapshot()[0].name, "sid");
    assert_eq!(store.snapshot()[0].value, "abc");
}

/// Store re-send across requests: after capture, later same-task
/// requests carry the cookie; requests without a store do not.
#[tokio::test]
async fn stored_cookie_resent_on_later_requests_only() {
    let app = Router::new()
        .route(
            "/set",
            get(|| async {
                (
                    StatusCode::OK,
                    [(header::SET_COOKIE, "t=xyz; Path=/")],
                    "ok",
                )
                    .into_response()
            }),
        )
        .route("/echo", get(echo_cookie));
    let addr = spawn(app).await;
    let base = format!("http://{addr}");

    let (ctx, store) = task_ctx();
    let bare = RequestCtx::default();
    {
        let c = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
        c.get(&format!("{base}/set"), &ctx)
            .await
            .unwrap_or_else(|e| panic!("set: {e}"));

        // A later same-task request re-sends it.
        let followed = c
            .get(&format!("{base}/echo"), &ctx)
            .await
            .unwrap_or_else(|e| panic!("echo: {e}"));
        let seen = json_body(followed.response).await;
        assert!(
            seen["cookie"]
                .as_str()
                .unwrap_or_default()
                .contains("t=xyz"),
            "{seen}"
        );

        // A request without a task store: carries nothing (isolation
        // stays inside the task context).
        let followed = c
            .get(&format!("{base}/echo"), &bare)
            .await
            .unwrap_or_else(|e| panic!("echo: {e}"));
        let seen = json_body(followed.response).await;
        assert_eq!(seen["cookie"], Value::Null, "{seen}");
    }
    assert_eq!(store.len(), 1);
}

/// Two tasks do not cross: two independent task stores each capture
/// their own cookies, invisible to each other (per-task isolation).
#[tokio::test]
async fn two_task_stores_do_not_cross_contaminate() {
    let app = Router::new()
        .route(
            "/set",
            get(|| async {
                (
                    StatusCode::OK,
                    [(header::SET_COOKIE, "only-task-a=1; Path=/")],
                    "ok",
                )
                    .into_response()
            }),
        )
        .route("/echo", get(echo_cookie));
    let addr = spawn(app).await;
    let base = format!("http://{addr}");

    let (ctx_a, store_a) = task_ctx();
    let (ctx_b, store_b) = task_ctx();
    let c = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));

    c.get(&format!("{base}/set"), &ctx_a)
        .await
        .unwrap_or_else(|e| panic!("set: {e}"));
    assert_eq!(store_a.len(), 1);
    assert!(store_b.is_empty(), "task B must not see task A's cookie");

    // Task B's request carries none of task A's cookies.
    let followed = c
        .get(&format!("{base}/echo"), &ctx_b)
        .await
        .unwrap_or_else(|e| panic!("echo: {e}"));
    let seen = json_body(followed.response).await;
    assert_eq!(seen["cookie"], Value::Null, "{seen}");

    // Task A's later requests re-send as usual.
    let followed = c
        .get(&format!("{base}/echo"), &ctx_a)
        .await
        .unwrap_or_else(|e| panic!("echo: {e}"));
    let seen = json_body(followed.response).await;
    assert!(
        seen["cookie"]
            .as_str()
            .unwrap_or_default()
            .contains("only-task-a=1"),
        "{seen}"
    );
}

/// Secure cookie: captured into the store over http, but never
/// re-sent on http requests (the http mirror of the https→http
/// downgrade rule).
#[tokio::test]
async fn secure_cookie_captured_but_never_resent_over_http() {
    let app = Router::new()
        .route(
            "/set",
            get(|| async {
                (
                    StatusCode::OK,
                    [(header::SET_COOKIE, "s=secret; Secure; Path=/")],
                    "ok",
                )
                    .into_response()
            }),
        )
        .route("/echo", get(echo_cookie));
    let addr = spawn(app).await;
    let base = format!("http://{addr}");

    let (ctx, store) = task_ctx();
    let c = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
    c.get(&format!("{base}/set"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("set: {e}"));
    assert_eq!(store.len(), 1);
    assert!(store.snapshot()[0].secure);

    let followed = c
        .get(&format!("{base}/echo"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("echo: {e}"));
    let seen = json_body(followed.response).await;
    assert_eq!(
        seen["cookie"],
        Value::Null,
        "secure cookie must not ride http: {seen}"
    );
}

/// Cross-host redirect layering: the explicit cookie pair and
/// credential headers are stripped on the cross-host hop, while
/// task-store cookies stay under the domain-match constraint — a
/// cross-domain target receives none of the origin's stored cookies.
#[tokio::test]
async fn stored_cookie_not_sent_cross_host_while_explicit_pair_is_stripped() {
    // The other host uses a pinned name (cookie domains do not isolate
    // ports — the same 127.0.0.1 on a different port is the same domain
    // under RFC 6265, so a genuinely different name is required to
    // build a cross-host shape).
    let other_app = Router::new().route("/final", get(echo_cookie));
    let other_addr = spawn(other_app).await;
    let other_loc = format!("http://other.test:{}/final", other_addr.port());

    let origin_app = Router::new()
        .route(
            "/start",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [
                        (header::SET_COOKIE, "sid=abc; Path=/"),
                        (header::LOCATION, "/hop"),
                    ],
                )
                    .into_response()
            }),
        )
        .route(
            "/hop",
            get(move || {
                let loc = other_loc.clone();
                async move { redirect(loc) }
            }),
        );
    let origin_addr = spawn(origin_app).await;

    // Pinned address port 0 = the URL's explicit port picks the
    // connect target (reqwest semantics).
    let cfg = ClientConfig {
        pinned_resolve: vec![(
            "other.test".to_string(),
            "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|e| panic!("pinned addr: {e}")),
        )],
        ..ClientConfig::default()
    };

    let (mut ctx, store) = task_ctx();
    ctx.cookies = vec![("explicit".to_string(), "pair".to_string())];
    ctx.headers = vec![("Authorization".to_string(), "Bearer t".to_string())];

    let followed = HttpClient::new(cfg)
        .unwrap_or_else(|e| panic!("client: {e}"))
        .get(&format!("http://{origin_addr}/start"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    assert_eq!(followed.hops, 2);

    let seen = json_body(followed.response).await;
    let cookie = seen["cookie"].as_str().unwrap_or_default();
    assert!(
        !cookie.contains("explicit=pair"),
        "explicit pair must be stripped: {seen}"
    );
    assert!(
        !cookie.contains("sid=abc"),
        "stored cookie must not cross hosts: {seen}"
    );

    // Capture is unaffected by the cross-host hop: the origin's store
    // still holds it.
    assert_eq!(store.len(), 1);
}

/// Path scoping: a stored cookie with `Path=/deep` is re-sent only to
/// requests under /deep.
#[tokio::test]
async fn path_scoped_cookie_resent_only_under_path() {
    let app = Router::new()
        .route(
            "/deep/set",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [
                        (header::SET_COOKIE, "p=1; Path=/deep"),
                        (header::LOCATION, "/deep/final"),
                    ],
                )
                    .into_response()
            }),
        )
        .route("/deep/final", get(echo_cookie))
        .route("/other", get(echo_cookie));
    let addr = spawn(app).await;
    let base = format!("http://{addr}");

    let (ctx, _) = task_ctx();
    let c = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
    let followed = c
        .get(&format!("{base}/deep/set"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("set: {e}"));
    let seen = json_body(followed.response).await;
    let cookie = seen["cookie"].as_str().unwrap_or_default();
    assert!(
        cookie.contains("p=1"),
        "redirect hop within path scope: {seen}"
    );

    let followed = c
        .get(&format!("{base}/other"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("other: {e}"));
    let seen = json_body(followed.response).await;
    assert!(
        !seen["cookie"].as_str().unwrap_or_default().contains("p=1"),
        "{seen}"
    );
}

/// Same-key absorb-merge: a later same-name cookie replaces the
/// earlier value; the re-send is not duplicated.
#[tokio::test]
async fn absorb_merge_replaces_value_on_wire() {
    let app = Router::new()
        .route(
            "/v1",
            get(|| async {
                (StatusCode::OK, [(header::SET_COOKIE, "k=old; Path=/")], "1").into_response()
            }),
        )
        .route(
            "/v2",
            get(|| async {
                (StatusCode::OK, [(header::SET_COOKIE, "k=new; Path=/")], "2").into_response()
            }),
        )
        .route("/echo", get(echo_cookie));
    let addr = spawn(app).await;
    let base = format!("http://{addr}");

    let (ctx, store) = task_ctx();
    let c = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
    for path in ["/v1", "/v2"] {
        c.get(&format!("{base}{path}"), &ctx)
            .await
            .unwrap_or_else(|e| panic!("{path}: {e}"));
    }
    assert_eq!(store.len(), 1, "same (name, domain, path) merges in place");

    let followed = c
        .get(&format!("{base}/echo"), &ctx)
        .await
        .unwrap_or_else(|e| panic!("echo: {e}"));
    let seen = json_body(followed.response).await;
    assert_eq!(seen["cookie"], json!("k=new"), "{seen}");
}
