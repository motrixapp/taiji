//! Data-plane Range echo validation (wire-level mock): a 206
//! response's `Content-Range` start must echo the request start on
//! every response — a mismatch rejects with `taiji.http.bad_range`
//! (anchor: aria2 `HttpResponse.cc` validateResponse +
//! `HttpRequest.cc` isRangeSatisfied → EX_INVALID_RANGE_HEADER /
//! CANNOT_RESUME). Without this check a mid-file wrong range silently
//! corrupts the output within the body bounds.
//!
//! Length dimension relaxed: when the start matches, the end echo is
//! no longer required to be exact — a body length (Content-Length or
//! the chunked total) differing from the requested remainder is a
//! length deviation: over-delivery is handled by the data-plane read
//! loop reading only what it needs and closing the stream (extra body
//! discarded); under-delivery banks the bytes read as partial progress
//! into the existing retry (anchor: HttpPartDownloader.kt). The
//! fast-fail BadRange semantics for a mismatching, missing, or
//! malformed start are unchanged.

use std::net::SocketAddr;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use taiji_http::client::{ClientConfig, Followed, HttpClient};
use taiji_http::error::HttpError;
use taiji_http::traits::RequestCtx;

/// Spawn the mock on a random 127.0.0.1 port (same scaffolding as
/// probe_mock).
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

/// A 206 shape: a fixed echoed Content-Range plus a body matching the
/// echoed range length.
fn echo_response(content_range: &'static str, body_len: usize) -> Response {
    (
        StatusCode::PARTIAL_CONTENT,
        [
            (header::CONTENT_RANGE, content_range),
            (header::CONTENT_LENGTH, body_len.to_string().leak() as &str),
        ],
        vec![b'x'; body_len],
    )
        .into_response()
}

async fn get_range(addr: SocketAddr, path: &str) -> Result<Followed, HttpError> {
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    client
        .get_range(
            &format!("http://{addr}{path}"),
            &RequestCtx::default(),
            0,
            9,
        )
        .await
}

/// A wrong start echo (`bytes 5-9/100` against a `bytes=0-9` request):
/// the core shape that would silently corrupt the file with a wrong
/// range → `taiji.http.bad_range`.
#[tokio::test]
async fn echo_start_mismatch_is_bad_range() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async { echo_response("bytes 5-9/100", 5) }),
    );
    let addr = spawn(app).await;
    let err = get_range(addr, "/f.bin")
        .await
        .err()
        .unwrap_or_else(|| panic!("wrong-start echo must be rejected"));
    assert_eq!(err, HttpError::BadRange);
}

/// End deviation with a matching start (the relaxed dimension):
/// `bytes 0-4/100` against a `bytes=0-9` request (the server grants
/// less than requested — under-delivery) and `bytes 0-14/100` (over-
/// delivery). A matching start is the data-correctness evidence, so
/// validation passes; the length deviation is settled by the
/// data-plane read loop (under-delivery: a short read banks partial
/// progress for retry; over-delivery: read what is needed and close —
/// anchor: HttpPartDownloader.kt).
#[tokio::test]
async fn echo_end_deviation_with_matching_start_is_tolerated() {
    for content_range in ["bytes 0-4/100", "bytes 0-14/100", "bytes 0-4/*"] {
        let range: &'static str = Box::leak(content_range.to_string().into_boxed_str());
        let body_len = content_range
            .trim_start_matches("bytes 0-")
            .split('/')
            .next()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|e| e + 1)
            .unwrap_or(5);
        let app = Router::new().route(
            "/f.bin",
            get(move || async move { echo_response(range, body_len) }),
        );
        let addr = spawn(app).await;
        let followed = get_range(addr, "/f.bin")
            .await
            .unwrap_or_else(|e| panic!("start-matching echo `{content_range}` must pass: {e}"));
        assert_eq!(followed.response.status(), StatusCode::PARTIAL_CONTENT);
    }
}

/// A missing echo (206 without Content-Range): range correctness
/// cannot be proven → rejected (aria2 getRange() with the header
/// missing → unsatisfied → CANNOT_RESUME, same verdict).
#[tokio::test]
async fn echo_missing_is_bad_range() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async {
            (
                StatusCode::PARTIAL_CONTENT,
                [(header::CONTENT_LENGTH, "10")],
                vec![b'x'; 10],
            )
                .into_response()
        }),
    );
    let addr = spawn(app).await;
    let err = get_range(addr, "/f.bin")
        .await
        .err()
        .unwrap_or_else(|| panic!("missing echo must be rejected"));
    assert_eq!(err, HttpError::BadRange);
}

/// A total echo <= end (`bytes 0-9/9`, a pathological shape; `bytes
/// 0-0/0` is the same family) → `taiji.http.bad_range`.
#[tokio::test]
async fn echo_total_not_beyond_end_is_bad_range() {
    let app = Router::new().route("/f.bin", get(|| async { echo_response("bytes 0-9/9", 10) }));
    let addr = spawn(app).await;
    let err = get_range(addr, "/f.bin")
        .await
        .err()
        .unwrap_or_else(|| panic!("total <= end echo must be rejected"));
    assert_eq!(err, HttpError::BadRange);
}

/// A non-bytes echo unit (`items 0-9/100`): unparseable → rejected.
#[tokio::test]
async fn echo_wrong_unit_is_bad_range() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async { echo_response("items 0-9/100", 10) }),
    );
    let addr = spawn(app).await;
    let err = get_range(addr, "/f.bin")
        .await
        .err()
        .unwrap_or_else(|| panic!("non-bytes unit must be rejected"));
    assert_eq!(err, HttpError::BadRange);
}

/// Healthy shapes pass: an exact echo (including `*` with no total —
/// total-length authority lives in the probe/merge layers; the
/// transport does not judge length beyond its remit).
#[tokio::test]
async fn exact_echo_passes() {
    for content_range in ["bytes 0-9/100", "bytes 0-9/*"] {
        let range: &'static str = Box::leak(content_range.to_string().into_boxed_str());
        let app = Router::new().route(
            "/f.bin",
            get(move || async move { echo_response(range, 10) }),
        );
        let addr = spawn(app).await;
        let followed = get_range(addr, "/f.bin")
            .await
            .unwrap_or_else(|e| panic!("exact echo `{content_range}` must pass: {e}"));
        assert_eq!(followed.response.status(), StatusCode::PARTIAL_CONTENT);
    }
}
