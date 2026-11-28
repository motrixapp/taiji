//! Wire-level cross-validation of the start-URL fast path
//! (`HttpRangeTransport::request_uri`): the data-plane extent fetch
//! dials the probe-converged final URL directly instead of re-walking
//! the redirect chain, so the chain's cross-endpoint credential
//! stripping never runs on its own. A cross-origin start must carry no
//! credentials — the entry site's credential headers and explicit
//! cookie pairs stay home, non-credential headers pass — exactly what a
//! cross-host 302 would have produced. Before the fix the start hop
//! stripped only the preset auth and leaked the rest to the final host.
//!
//! The mock face adds no TLS termination (same posture as
//! redirect_mock.rs); a different 127.0.0.1 port is a different origin.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::error::HttpError;
use taiji_http::traits::{AuthScheme, Extent, NoopSink, RequestCtx, SegmentTransport};
use taiji_http::transport::HttpRangeTransport;

/// Every request the mock saw, reduced to the credential-relevant
/// header set.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<Value>>>);

impl Seen {
    fn push(&self, headers: &HeaderMap) {
        let h = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        self.0
            .lock()
            .unwrap_or_else(|e| panic!("seen lock: {e}"))
            .push(json!({
                "authorization": h("authorization"),
                "proxy-authorization": h("proxy-authorization"),
                "cookie": h("cookie"),
                "x-custom": h("x-custom"),
                "range": h("range"),
            }));
    }

    fn requests(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap_or_else(|e| panic!("seen lock: {e}"))
            .clone()
    }
}

/// A 206 answering `bytes=0-7` in full (the extent every case fetches).
async fn range_sink(State(seen): State<Seen>, headers: HeaderMap) -> Response {
    seen.push(&headers);
    (
        StatusCode::PARTIAL_CONTENT,
        [
            (header::CONTENT_RANGE, "bytes 0-7/8"),
            (header::CONTENT_LENGTH, "8"),
        ],
        vec![b'x'; 8],
    )
        .into_response()
}

/// Spawn the mock on a random 127.0.0.1 port and return its address
/// plus what it saw.
async fn spawn() -> (SocketAddr, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/f.bin", get(range_sink))
        .with_state(seen.clone());
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
    (addr, seen)
}

/// The entry site's full credential set: preset Basic, credential
/// headers, an explicit cookie pair, and one non-credential header.
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

/// One extent fetch through the start-URL transport: `entry` is the
/// source-entry URI, `request_uri` the probe-converged start.
async fn fetch_extent(entry: String, request_uri: Option<String>) -> Result<(), HttpError> {
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    let transport = HttpRangeTransport::new(
        client,
        entry,
        request_uri,
        0,
        taiji_io::metrics::registry_default(),
    );
    let extent = Extent { start: 0, len: 8 };
    transport
        .fetch(&extent, &authed_ctx(), &NoopSink::default())
        .await
}

/// A cross-origin start (different port) carries no credentials: the
/// final host sees neither the entry site's credential headers nor its
/// explicit cookie pair, while the non-credential header passes. The
/// entry host is never contacted (the fast path skips the chain).
#[tokio::test]
async fn cross_origin_start_carries_no_credentials() {
    let (final_addr, final_seen) = spawn().await;
    let (entry_addr, entry_seen) = spawn().await;

    fetch_extent(
        format!("http://{entry_addr}/f.bin"),
        Some(format!("http://{final_addr}/f.bin")),
    )
    .await
    .unwrap_or_else(|e| panic!("fetch: {e}"));

    assert!(
        entry_seen.requests().is_empty(),
        "the start-URL fast path must not walk the entry chain"
    );
    let requests = final_seen.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let seen = &requests[0];
    assert_eq!(seen["authorization"], Value::Null, "{seen}");
    assert_eq!(seen["proxy-authorization"], Value::Null, "{seen}");
    assert_eq!(
        seen["cookie"],
        Value::Null,
        "the entry site's explicit cookie pair must not reach the final host"
    );
    assert_eq!(seen["x-custom"], json!("keepme"), "{seen}");
    assert_eq!(seen["range"], json!("bytes=0-7"), "{seen}");
}

/// A same-origin start keeps the full credential scope (401
/// challenge-response unchanged): preset Basic and the explicit cookie
/// pair travel as on a plain first hop.
#[tokio::test]
async fn same_origin_start_keeps_credentials() {
    let (addr, seen) = spawn().await;

    fetch_extent(
        format!("http://{addr}/entry.bin"),
        Some(format!("http://{addr}/f.bin")),
    )
    .await
    .unwrap_or_else(|e| panic!("fetch: {e}"));

    let requests = seen.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let seen = &requests[0];
    let authorization = seen["authorization"].as_str().unwrap_or_default();
    assert!(authorization.contains("Bearer topsecret"), "{seen}");
    let cookie = seen["cookie"].as_str().unwrap_or_default();
    assert!(cookie.contains("sid=abc"), "{seen}");
    assert_eq!(seen["x-custom"], json!("keepme"), "{seen}");
}
