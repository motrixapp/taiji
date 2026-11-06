//! Per-host connection cap wire tests: the cap counter shared across
//! tasks — with multiple tasks fetching concurrently from the same
//! host, the server-observed in-flight request count never exceeds
//! the cap, and the count returns to zero once all requests finish.
//!
//! The "across tasks" carrier: one independent tokio task per request,
//! each with its own `HttpClient`/`RequestCtx` (no sharing between
//! tasks; the only shared face is the `Arc<HostCap>` registry —
//! isomorphic to the production SessionActor single-instance
//! distribution).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::perhost::HostCap;
use taiji_http::probe::{ProbeVerdict, probe_uri};
use taiji_http::traits::RequestCtx;

/// Test-only Result unwrap (lints forbid unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Probe-success shape (decision row 1).
fn row1_response() -> Response {
    use axum::http::header;
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

/// Cap-count wire test: cap = 2, 12 concurrent cross-task requests
/// (the server holds each request 60ms to create in-flight overlap) —
/// the server-observed peak is <= 2, every request succeeds, and
/// active ends at zero.
#[tokio::test]
async fn per_host_cap_counts_across_tasks_on_the_wire() {
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let (inflight_t, max_t, total_t) = (inflight.clone(), max_seen.clone(), total.clone());
    let app = Router::new().route(
        "/f.bin",
        get(move || {
            let inflight = inflight_t.clone();
            let max_seen = max_t.clone();
            let total = total_t.clone();
            async move {
                let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(cur, Ordering::SeqCst);
                total.fetch_add(1, Ordering::SeqCst);
                // The hold window creates in-flight overlap (what the
                // cap constrains).
                tokio::time::sleep(Duration::from_millis(60)).await;
                inflight.fetch_sub(1, Ordering::SeqCst);
                row1_response()
            }
        }),
    );
    let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "addr");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    let base = format!("http://{addr}");
    let url = format!("{base}/f.bin");

    // Session-level single-instance registry (the production shape):
    // cap = 2.
    let cap = Arc::new(HostCap::new(2));
    assert_eq!(cap.cap(), 2);
    let host = HostCap::host_key(&url).unwrap_or_else(|| panic!("host key"));

    let mut joins = Vec::new();
    for _ in 0..12 {
        let cap = cap.clone();
        let url = url.clone();
        let host = host.clone();
        joins.push(tokio::spawn(async move {
            // Each task has its own client/ctx (no task sharing — the
            // cap is the only shared face).
            let client =
                HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
            let _permit = cap.acquire(&host).await;
            let verdict = probe_uri(&client, &url, &RequestCtx::default())
                .await
                .unwrap_or_else(|e| panic!("request must pass: {e}"));
            assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));
        }));
    }
    for j in joins {
        ok(j.await, "task join");
    }

    assert_eq!(
        total.load(Ordering::SeqCst),
        12,
        "all requests are served by the server (cap waits do not swallow requests)"
    );
    assert_eq!(
        inflight.load(Ordering::SeqCst),
        0,
        "all permits released back to zero"
    );
    assert_eq!(
        cap.active(&host),
        0,
        "the registry's final count returns to zero"
    );
    let peak = max_seen.load(Ordering::SeqCst);
    assert!(
        peak >= 2,
        "concurrency within the cap must actually happen \
         (peak = {peak}; the cap = 2 count is not decorative)"
    );
    assert!(
        peak <= 2,
        "the server-observed in-flight peak must not exceed the cap (peak = {peak})"
    );
}

/// Runtime cap adjustment on the wire: after a decrease, new
/// acquisitions respect the new cap (existing permits are not revoked
/// — convergence happens as they release).
#[tokio::test]
async fn cap_adjustment_tightens_acquisition() {
    let cap = Arc::new(HostCap::new(4));
    let host = "http://adjust.test:80";
    let mut permits = Vec::new();
    for _ in 0..4 {
        permits.push(cap.acquire(host).await);
    }
    assert_eq!(cap.active(host), 4);
    // Lower to 2: the existing 4 permits stay; new acquisition is refused.
    cap.set_cap(2);
    assert!(
        cap.try_acquire(host).is_none(),
        "new acquisitions are bound by the new cap"
    );
    drop(permits);
    assert_eq!(cap.active(host), 0);
    // After release, exactly 2 can be acquired under the new cap.
    let a = cap.try_acquire(host).unwrap_or_else(|| panic!("a"));
    let b = cap.try_acquire(host).unwrap_or_else(|| panic!("b"));
    assert!(cap.try_acquire(host).is_none());
    let _ = (a, b);
}
