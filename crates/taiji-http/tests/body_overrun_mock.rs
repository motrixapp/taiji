//! Wire-level mock regression: the `HttpBodyTransport` read-loop
//! circuit breaker against over-delivery plus the absolute cap for
//! unknown-length streams.
//!
//! Drift shape: during probing the same URL answers 200 +
//! `Content-Length: 1000` (identity, decision row 3
//! [`ProbeVerdict::NoRangeWithLength`]); during download the same GET
//! switches to `Content-Encoding: gzip` + chunked — the data-plane
//! transport instance auto-decompresses (decompressing despite the
//! identity negotiation) and 8192 decompressed bytes (190:1 ratio)
//! enter the read loop. Without the check, every decompressed byte
//! lands on disk past the declared length.
//!
//! Fixed semantics: over-delivery (N declared, more delivered) →
//! `taiji.http.transport` with a `body overruns extent ..` payload
//! (matching the existing over-delivery error shape), the task fails,
//! and bytes written stay <= the declared length. Unknown-length EOF
//! streams (the unbounded extent sentinel) break on the
//! [`MAX_UNBOUNDED_STREAM_BYTES`] absolute cap (cap-function unit
//! tests live in the transport.rs test area; a 1TiB-scale e2e is not
//! feasible — this file pins the contrast behavior of an in-cap EOF
//! stream passing untouched).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bytes::Bytes;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::error::HttpError;
use taiji_http::probe::{ProbeVerdict, probe_uri};
use taiji_http::traits::{Extent, NoopSink, RequestCtx, SegmentTransport};
use taiji_http::transport::HttpBodyTransport;

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

/// Declared length during probing (identity, 200 + Content-Length).
const DECLARED: usize = 1000;

/// Decompressed byte count during download (> DECLARED — proof of drift).
const DECOMPRESSED: usize = 8192;

/// Compile-time pin on the drift premise: the decompressed size must
/// exceed the declared length.
const _: () = assert!(
    DECOMPRESSED > DECLARED,
    "the drift shape requires the decompressed size to exceed the declared length"
);

/// A gzip entity of 8192 zero bytes (43B, 190:1 ratio — the minimal
/// reproduction of the amplification shape; 1TiB-scale e2e is not
/// feasible, so the cap semantics are pinned here).
const GZ_ZERO_8K: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0xda, 0xfe, 0xcd, 0x6a, 0x02, 0xff, 0xed, 0xc1, 0x01, 0x0d, 0x00, 0x00,
    0x00, 0xc2, 0xa0, 0xf7, 0x4f, 0x6d, 0x0e, 0x37, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x77, 0x03, 0x94, 0x99, 0xf4, 0xd8, 0x00, 0x20, 0x00, 0x00,
];

/// The drifting origin: a probe request (carrying `Range: bytes=0-0`)
/// gets 200 + CL=DECLARED (identity full body — axum derives the
/// matching Content-Length from Bytes); a download request (no Range
/// header) gets `Content-Encoding: gzip` + chunked on the same URL (a
/// streaming body with no length).
async fn drifting_origin(headers: HeaderMap) -> Response {
    if headers.contains_key(header::RANGE) {
        (StatusCode::OK, Bytes::from(vec![0u8; DECLARED])).into_response()
    } else {
        let stream = futures::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(
            Bytes::from_static(GZ_ZERO_8K),
        )]);
        let mut resp = Response::new(Body::from_stream(stream));
        resp.headers_mut().insert(
            header::CONTENT_ENCODING,
            axum::http::HeaderValue::from_static("gzip"),
        );
        resp
    }
}

/// The drift regression: the probe records NoRangeWithLength (1000B
/// declared) → the download of the same URL decompresses an 8192B gzip
/// stream → the task must fail with the over-delivery error and write
/// no more than the declared length. Without the overrun check, fetch
/// would return Ok having written 8192B > 1000B.
#[tokio::test]
async fn drift_gzip_over_delivery_fails_with_overrun_and_bounded_disk() {
    let app = Router::new().route("/f.bin", get(drifting_origin));
    let addr = spawn(app).await;
    let uri = format!("http://{addr}/f.bin");
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));

    // Probe phase: the honest shape (200 + CL=1000, identity) → row 3.
    let verdict = probe_uri(&client, &uri, &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    let total_len = match verdict {
        ProbeVerdict::NoRangeWithLength(r) => r
            .total_len
            .unwrap_or_else(|| panic!("row 3 must record CL")),
        other => panic!("expected row 3 verdict, got {other:?}"),
    };
    assert_eq!(total_len, DECLARED as u64);

    // Self-check first: the gzip trailing ISIZE (little-endian u32) is
    // the decompressed length — the over-delivery premise (decompressed
    // > declared) must hold or the test proves nothing.
    let gz_isize = u32::from_le_bytes([
        GZ_ZERO_8K[39],
        GZ_ZERO_8K[40],
        GZ_ZERO_8K[41],
        GZ_ZERO_8K[42],
    ]) as usize;
    assert_eq!(
        gz_isize, DECOMPRESSED,
        "the gzip entity must decompress to {DECOMPRESSED}B"
    );
    // Download phase: the same URL has drifted to a gzip stream (the
    // data plane auto-decompresses 8192B > 1000B).
    let transport = HttpBodyTransport::new(
        client,
        uri,
        Arc::new(taiji_io::metrics::MetricsRegistry::new()),
    );
    let sink = NoopSink::default();
    let extent = Extent {
        start: 0,
        len: total_len,
    };
    let res = transport
        .fetch(&extent, &RequestCtx::default(), &sink)
        .await;

    // Over-delivery → task failure with the existing
    // `body overruns extent` error shape.
    let err = res.err().unwrap_or_else(|| {
        panic!(
            "over-delivery must fail with an error \
             (everything currently landing on disk = the defect face)"
        )
    });
    match &err {
        HttpError::Transport(msg) => {
            assert!(msg.contains("body overruns extent"), "error shape: {msg}")
        }
        other => panic!("expected Transport (body overruns extent), got {other}"),
    }
    // Bytes written stay <= declared (out-of-extent decompressed bytes
    // must not land on disk).
    assert!(
        sink.written_bytes() <= total_len,
        "{}B written must not exceed the declared length {total_len}B",
        sink.written_bytes(),
    );
}

/// The unbounded-EOF contrast (stays green, guarding against false
/// trips): row 4 (200 + chunked, no length) → no total length → the
/// EOF-delimited sentinel extent (`u64::MAX-1`) → a small in-cap
/// stream writes fully and succeeds — the absolute cap only trips
/// over-cap shapes and leaves normal unknown-length streams alone.
#[tokio::test]
async fn unbounded_eof_stream_within_cap_passes() {
    let body: &'static [u8] = b"unbounded eof stream body";
    let app = Router::new().route(
        "/f.bin",
        get(move || async move {
            // `body` is a 'static literal (Copy), so the closure stays
            // Fn and rebuilds the stream per request.
            let stream = futures::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(
                Bytes::from_static(body),
            )]);
            Body::from_stream(stream).into_response()
        }),
    );
    let addr = spawn(app).await;
    let uri = format!("http://{addr}/f.bin");
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));

    let verdict = probe_uri(&client, &uri, &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert!(
        matches!(verdict, ProbeVerdict::NoRangeNoLength(_)),
        "expected row 4 verdict, got {verdict:?}"
    );

    let transport = HttpBodyTransport::new(
        client,
        uri,
        Arc::new(taiji_io::metrics::MetricsRegistry::new()),
    );
    let sink = NoopSink::default();
    // EOF-delimited sentinel (the taiji-core download_eof_stream shape).
    let extent = Extent {
        start: 0,
        len: u64::MAX - 1,
    };
    transport
        .fetch(&extent, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("an unknown-length stream within the cap must succeed: {e}"));
    assert_eq!(sink.written_bytes(), body.len() as u64);
}
