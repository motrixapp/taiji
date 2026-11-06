//! Mock lab (axum): wire-level cross-validation of all 7 rows of the
//! probing decision table, the probe request wire shape (GET +
//! `Range: bytes=0-0` + `Accept-Encoding: identity`), and out-of-table
//! response shapes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bytes::Bytes;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::error::HttpError;
use taiji_http::probe::{
    MergeInput, MergedPlan, ProbeVerdict, ProbedSource, merge_probes, probe_uri,
};
use taiji_http::traits::{RequestCtx, TransportKind};

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

async fn probe(addr: SocketAddr, path: &str) -> Result<ProbeVerdict, HttpError> {
    probe_uri(
        &client(),
        &format!("http://{addr}{path}"),
        &RequestCtx::default(),
    )
    .await
}

/// Row 1 shape: 206 + `bytes 0-0/TOTAL` + Accept-Ranges/ETag/
/// Last-Modified + a 1-byte probe body.
fn row1_response() -> Response {
    (
        StatusCode::PARTIAL_CONTENT,
        [
            (header::CONTENT_RANGE, "bytes 0-0/123456"),
            (header::ACCEPT_RANGES, "bytes"),
            (header::ETAG, "\"etag-row1\""),
            (header::LAST_MODIFIED, "Tue, 01 Sep 2026 00:00:00 GMT"),
            (header::CONTENT_LENGTH, "1"),
        ],
        "x",
    )
        .into_response()
}

/// Captures the most recent request headers (wire-shape assertion; the
/// Mutex is never held across await).
type Captured = Arc<Mutex<Option<HeaderMap>>>;

/// Records the request headers, then replies with the row 1 shape.
async fn capture_and_row1(captured: Captured, headers: HeaderMap) -> Response {
    if let Ok(mut slot) = captured.lock() {
        *slot = Some(headers);
    }
    row1_response()
}

/// Read the captured request headers (panics on poisoning or absence).
fn captured_headers(captured: &Captured) -> HeaderMap {
    captured
        .lock()
        .unwrap_or_else(|e| panic!("capture poisoned: {e}"))
        .clone()
        .unwrap_or_else(|| panic!("no request captured"))
}

fn header_of(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

// ---------- The 7 decision-table rows (one mock shape each) ----------

/// Row 1: 206 + `Content-Range: bytes 0-0/TOTAL` → segmentable, with
/// TOTAL as the authoritative length; Accept-Ranges/ETag/Last-Modified
/// and the final URL are recorded.
#[tokio::test]
async fn row1_206_with_total_is_segmentable() {
    let app = Router::new().route("/f.bin", get(|| async { row1_response() }));
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match verdict {
        ProbeVerdict::RangeWithLength(r) => {
            assert_eq!(r.total_len, Some(123456));
            assert_eq!(r.etag, Some("\"etag-row1\"".to_string()));
            assert_eq!(
                r.last_modified,
                Some("Tue, 01 Sep 2026 00:00:00 GMT".to_string())
            );
            assert!(r.accept_ranges);
            assert_eq!(r.encoding, None);
            assert_eq!(r.final_url, format!("http://{addr}/f.bin"));
            // ResumeValidator derivation (its fields mirror the probe record).
            let v = r.resume_validator();
            assert_eq!(v.final_url_path, "/f.bin");
            assert_eq!(v.total_len, Some(123456));
            assert_eq!(v.etag, Some("\"etag-row1\"".to_string()));
            assert!(v.encoding_ok);
        }
        other => panic!("expected row 1 verdict, got {other:?}"),
    }
}

/// Row 2: 206 + `Content-Range: bytes 0-0/*` → Range-capable but no
/// total length → single-connection degradation, no bitmap (weak).
#[tokio::test]
async fn row2_206_without_total_degrades_weak() {
    let app = Router::new().route("/f.bin", get(|| async { row2_response() }));
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match verdict {
        ProbeVerdict::RangeNoLength(r) => {
            assert_eq!(r.total_len, None);
            assert!(r.accept_ranges); // a 206 is itself Range support
        }
        other => panic!("expected row 2 verdict, got {other:?}"),
    }
}

/// Row 2 shape builder (206 + `bytes 0-0/*`, no total length).
fn row2_response() -> Response {
    (
        StatusCode::PARTIAL_CONTENT,
        [
            (header::CONTENT_RANGE, "bytes 0-0/*"),
            (header::CONTENT_LENGTH, "1"),
        ],
        "x",
    )
        .into_response()
}

/// Row 3: 200 + Content-Length → Range ignored → single-connection
/// degradation. Also pins the probe request wire shape: GET +
/// `Range: bytes=0-0` + `Accept-Encoding: identity` (the mock ignores
/// Range and returns the full 200).
#[tokio::test]
async fn row3_200_with_length_range_ignored() {
    let captured: Captured = Arc::new(Mutex::new(None));
    let recorder = captured.clone();
    // A 123456-byte full body: axum derives a matching Content-Length
    // from Bytes.
    let app = Router::new().route(
        "/f.bin",
        get(move |headers: HeaderMap| async move {
            if let Ok(mut slot) = recorder.lock() {
                *slot = Some(headers);
            }
            (StatusCode::OK, Bytes::from(vec![0u8; 123456])).into_response()
        }),
    );
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match verdict {
        ProbeVerdict::NoRangeWithLength(r) => {
            assert_eq!(r.total_len, Some(123456));
            assert!(!r.accept_ranges);
        }
        other => panic!("expected row 3 verdict, got {other:?}"),
    }

    let seen = captured_headers(&captured);
    assert_eq!(header_of(&seen, "range"), "bytes=0-0");
    assert_eq!(header_of(&seen, "accept-encoding"), "identity");
}

/// Row 4: 200 + chunked/no length → single-connection degradation, no
/// bitmap (weak).
#[tokio::test]
async fn row4_200_chunked_no_length_weak() {
    // A streaming body (length unknown) → hyper sends
    // Transfer-Encoding: chunked.
    let stream = futures::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(Bytes::from(
        "chunk",
    ))]);
    let app = Router::new().route(
        "/f.bin",
        get(move || async move { Body::from_stream(stream).into_response() }),
    );
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match verdict {
        ProbeVerdict::NoRangeNoLength(r) => {
            assert_eq!(r.total_len, None);
        }
        other => panic!("expected row 4 verdict, got {other:?}"),
    }
}

/// Row 5: 416 + `Content-Range: bytes */0` → empty file: create a
/// 0-byte output, done.
#[tokio::test]
async fn row5_416_star_zero_empty_file_done() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async {
            (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, "bytes */0")],
            )
                .into_response()
        }),
    );
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match verdict {
        ProbeVerdict::EmptyFile(r) => {
            assert_eq!(r.total_len, Some(0));
            assert_eq!(r.resume_validator().total_len, Some(0));
        }
        other => panic!("expected row 5 verdict, got {other:?}"),
    }
}

/// Row 6: 416 + `Content-Range: bytes */N` (N>0) → the length changed →
/// `taiji.http.bad_range`.
#[tokio::test]
async fn row6_416_star_n_is_bad_range() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async {
            (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, "bytes */777")],
            )
                .into_response()
        }),
    );
    let addr = spawn(app).await;

    let res = probe(addr, "/f.bin").await;
    assert_eq!(res, Err(HttpError::BadRange));
}

/// Row 7: Content-Encoding != identity → Range semantics unknown →
/// single-connection degradation with self-decompression; no bitmap.
///
/// Mechanism check: the probe face uses `get_range_raw` (a transport
/// instance with auto-decompression off) and the response headers must
/// keep the original `Content-Encoding` — the data-plane instance (the
/// reqwest gzip feature is on by default) strips that header while
/// decompressing, which would blind the verdict.
#[tokio::test]
async fn row7_content_encoding_not_identity_degrades() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async {
            (
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_RANGE, "bytes 0-0/123456"),
                    (header::CONTENT_ENCODING, "gzip"),
                    (header::CONTENT_LENGTH, "1"),
                ],
                "x",
            )
                .into_response()
        }),
    );
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match verdict {
        ProbeVerdict::Encoded(r) => {
            assert_eq!(r.encoding, Some("gzip".to_string()));
            // Range semantics unknown: the 206+TOTAL is not recorded
            // (an encoded entity length cannot be authoritative); no
            // bitmap.
            assert_eq!(r.total_len, None);
            assert!(!r.resume_validator().encoding_ok);
            assert!(!r.accept_ranges);
        }
        other => panic!("expected row 7 verdict, got {other:?}"),
    }

    // Mechanism check: on the same shape the data-plane instance
    // (get_range) already auto-decompresses and the Content-Encoding
    // header is stripped — the probe face must bypass that.
    let followed = client()
        .get_range(
            &format!("http://{addr}/f.bin"),
            &RequestCtx::default(),
            0,
            0,
        )
        .await
        .unwrap_or_else(|e| panic!("get_range: {e}"));
    assert!(
        followed
            .response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_none(),
        "data-plane reqwest must have auto-decompressed (header stripped)"
    );
}

// ---------- Forced encoding by a non-conforming server (row 7 wins
// ---------- over the status shape) ----------

/// Non-conforming server: a Range probe force-answered with gzip
/// (206 + TOTAL + `Content-Encoding: gzip`). The probe face must read
/// the unstripped original headers → row 7 Encoded → the merge table
/// decides "not segmentable" (SingleConnection + self_decompress) —
/// never a Range-segmented plan (otherwise Content-Range TOTAL is the
/// compressed length while the data plane has already decompressed the
/// body, silently corrupting the file).
#[tokio::test]
async fn force_gzip_response_never_enters_segmented_plan() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async {
            (
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_RANGE, "bytes 0-0/123456"),
                    (header::CONTENT_ENCODING, "gzip"),
                    (header::CONTENT_LENGTH, "1"),
                ],
                "x",
            )
                .into_response()
        }),
    );
    let addr = spawn(app).await;
    let uri = format!("http://{addr}/f.bin");

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match &verdict {
        ProbeVerdict::Encoded(r) => {
            assert_eq!(r.encoding, Some("gzip".to_string()));
            assert!(!verdict.is_segmentable(), "encoded source must not segment");
        }
        other => panic!("expected row 7 verdict, got {other:?}"),
    }

    let merged = merge_probes(MergeInput {
        sources: vec![ProbedSource {
            uri,
            kind: TransportKind::Http,
            outcome: Ok(verdict),
        }],
        checksum: None,
    })
    .unwrap_or_else(|e| panic!("merge: {e}"));
    match merged {
        MergedPlan::SingleConnection {
            self_decompress, ..
        } => assert!(self_decompress, "row 7 degrade carries self-decompress"),
        other => panic!("expected single connection, got {other:?}"),
    }
}

// ---------- Wire shape and redirect convergence ----------

/// Probe request wire shape (row 1 shape + header capture):
/// `Range: bytes=0-0` + `Accept-Encoding: identity` always present.
#[tokio::test]
async fn probe_wire_carries_range_and_identity() {
    let captured: Captured = Arc::new(Mutex::new(None));
    let recorder = captured.clone();
    let app = Router::new().route(
        "/f.bin",
        get(move |headers: HeaderMap| capture_and_row1(recorder, headers)),
    );
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));

    let seen = captured_headers(&captured);
    assert_eq!(header_of(&seen, "range"), "bytes=0-0");
    assert_eq!(header_of(&seen, "accept-encoding"), "identity");
    assert_eq!(seen.get_all("range").iter().count(), 1); // single header, no stacking
}

/// A probe converging through a redirect chain: final URL accounting,
/// verdict taken from the terminal response.
#[tokio::test]
async fn probe_follows_redirect_and_records_final_url() {
    let app = Router::new()
        .route(
            "/start",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "/f.bin".to_string())],
                )
                    .into_response()
            }),
        )
        .route("/f.bin", get(|| async { row1_response() }));
    let addr = spawn(app).await;

    let verdict = probe(addr, "/start")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match verdict {
        ProbeVerdict::RangeWithLength(r) => {
            assert_eq!(r.final_url, format!("http://{addr}/f.bin"));
            assert_eq!(r.resume_validator().final_url_path, "/f.bin");
        }
        other => panic!("expected row 1 verdict, got {other:?}"),
    }
}

// ---------- Out-of-table shapes ----------

/// Out-of-table statuses (404/401) → `taiji.http.unexpected_response`.
#[tokio::test]
async fn out_of_table_statuses_are_unexpected_response() {
    let app = Router::new()
        .route(
            "/gone",
            get(|| async { (StatusCode::NOT_FOUND, "nope").into_response() }),
        )
        .route(
            "/locked",
            get(|| async { (StatusCode::UNAUTHORIZED, "auth").into_response() }),
        )
        .route(
            "/missing-cr",
            get(|| async { StatusCode::PARTIAL_CONTENT.into_response() }),
        );
    let addr = spawn(app).await;

    assert_eq!(
        probe(addr, "/gone").await,
        Err(HttpError::UnexpectedResponse { status: 404 })
    );
    assert_eq!(
        probe(addr, "/locked").await,
        Err(HttpError::UnexpectedResponse { status: 401 })
    );
    // 206 without Content-Range: an unverifiable echo is rejected.
    // aria2 validateResponse validates each 206 (missing header →
    // CANNOT_RESUME), the same family as bad_range.
    assert_eq!(probe(addr, "/missing-cr").await, Err(HttpError::BadRange));
}

/// A 206 echo not matching the probe's `bytes=0-0` → `bad_range`
/// (anchor: aria2 HttpResponse.cc isRangeSatisfied → CANNOT_RESUME).
#[tokio::test]
async fn mismatched_range_echo_is_bad_range() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async {
            (
                StatusCode::PARTIAL_CONTENT,
                [(header::CONTENT_RANGE, "bytes 5-5/100")],
                "x",
            )
                .into_response()
        }),
    );
    let addr = spawn(app).await;

    assert_eq!(probe(addr, "/f.bin").await, Err(HttpError::BadRange));
}

/// 416 + `bytes */*` (total length unknown) → out-of-table, never
/// misjudged as an empty file.
#[tokio::test]
async fn star_star_content_range_on_416_is_out_of_table() {
    let app = Router::new().route(
        "/f.bin",
        get(|| async {
            (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, "bytes */*")],
            )
                .into_response()
        }),
    );
    let addr = spawn(app).await;

    assert_eq!(
        probe(addr, "/f.bin").await,
        Err(HttpError::UnexpectedResponse { status: 416 })
    );
}

/// The probe never issues HEAD: the mock counts HEAD requests and
/// answers 405, so any HEAD on the probe path shows up immediately.
#[tokio::test]
async fn head_is_never_issued_by_probe() {
    let head_hits = Arc::new(AtomicUsize::new(0));
    let counter = head_hits.clone();
    let app = Router::new().route(
        "/f.bin",
        get(|| async { row1_response() }).head(move || async move {
            counter.fetch_add(1, Ordering::Relaxed);
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        }),
    );
    let addr = spawn(app).await;

    let verdict = probe(addr, "/f.bin")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));
    assert_eq!(
        head_hits.load(Ordering::Relaxed),
        0,
        "probe must not issue HEAD"
    );
}

/// Transport failure: connection refused → `taiji.http.transport` (one
/// input shape of the merge table's remove-all path; the wire check
/// confirms a probe error is never disguised as a verdict).
#[tokio::test]
async fn connection_refused_is_transport_error() {
    // Port 1 (unreachable).
    let res = probe_uri(
        &client(),
        "http://127.0.0.1:1/f.bin",
        &RequestCtx::default(),
    )
    .await;
    assert!(matches!(res, Err(HttpError::Transport(_))), "{res:?}");
}

/// Probe retries: transient drops (connection accepted, then closed
/// immediately) retry as Transport-class, matching aria2 URI-level
/// max-tries — the first 2 attempts drop and the 3rd returns the row 1
/// shape; the probe must succeed with at least 3 observed connections.
#[tokio::test]
async fn probe_retries_transient_transport_failures() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                // Dropping immediately = closed connection (transient
                // shape, no HTTP reply).
                continue;
            }
            let mut sock = sock;
            let resp = "HTTP/1.1 206 Partial Content\r\n\
                        content-range: bytes 0-0/123456\r\n\
                        accept-ranges: bytes\r\n\
                        content-length: 1\r\n\
                        connection: close\r\n\r\nx";
            use tokio::io::AsyncWriteExt;
            if sock.write_all(resp.as_bytes()).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });

    let cfg = ClientConfig {
        retry: taiji_http::retry::RetryPolicy {
            max_tries: 3,
            ..taiji_http::retry::RetryPolicy::default()
        },
        ..ClientConfig::default()
    };
    let cl = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let verdict = probe_uri(&cl, &format!("http://{addr}/f.bin"), &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe must recover after transient drops: {e}"));
    assert!(matches!(verdict, ProbeVerdict::RangeWithLength(_)));
    assert!(
        accepts.load(Ordering::SeqCst) >= 3,
        "must retry after the transient drops (observed connections < 3): {}",
        accepts.load(Ordering::SeqCst)
    );
}

/// Retry exhaustion: every connection drops immediately; after exactly
/// max_tries attempts a Transport error surfaces.
#[tokio::test]
async fn probe_retry_exhaustion_reports_transport_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        loop {
            let Ok((_sock, _)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            // Dropping closes the socket: always a transient drop.
        }
    });

    let cfg = ClientConfig {
        retry: taiji_http::retry::RetryPolicy {
            max_tries: 2,
            ..taiji_http::retry::RetryPolicy::default()
        },
        ..ClientConfig::default()
    };
    let cl = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let res = probe_uri(&cl, &format!("http://{addr}/f.bin"), &RequestCtx::default()).await;
    assert!(matches!(res, Err(HttpError::Transport(_))), "{res:?}");
    assert!(
        accepts.load(Ordering::SeqCst) >= 2,
        "must use up max_tries before exhaustion: {}",
        accepts.load(Ordering::SeqCst)
    );
}

/// 4xx is not retried (`UnexpectedResponse` is not Transport-class — a
/// deterministic failure): exactly one request.
#[tokio::test]
async fn probe_does_not_retry_4xx() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let app = Router::new().route(
        "/f.bin",
        get(move || async move {
            counter.fetch_add(1, Ordering::Relaxed);
            (StatusCode::NOT_FOUND, "gone").into_response()
        }),
    );
    let addr = spawn(app).await;
    let cfg = ClientConfig {
        retry: taiji_http::retry::RetryPolicy {
            max_tries: 5,
            ..taiji_http::retry::RetryPolicy::default()
        },
        ..ClientConfig::default()
    };
    let cl = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let res = probe_uri(&cl, &format!("http://{addr}/f.bin"), &RequestCtx::default()).await;
    assert_eq!(
        res,
        Err(HttpError::UnexpectedResponse { status: 404 }),
        "4xx stops after one request"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1, "4xx must not retry");
}
