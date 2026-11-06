//! The shared local origin over a generated fixture tree (the fixture
//! test binaries): serves `<root>` under `/fx/<relpath>` with Range support
//! for the (a)-layer's BYTERANGE fetches, plus per-resource hit/range
//! logging for the wire-side assertions. Test-support only.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// Origin-side observation: hits + Range headers per range-aware
/// resource (`.mp4`/`.bin`), keyed by nothing (single-blob fixtures).
#[derive(Clone, Default)]
pub struct OriginState {
    pub blob_hits: Arc<AtomicU64>,
    pub blob_ranges: Arc<std::sync::Mutex<Vec<String>>>,
}

impl OriginState {
    /// The Range headers seen so far (in order).
    pub fn ranges(&self) -> Vec<String> {
        self.blob_ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn hits(&self) -> u64 {
        self.blob_hits.load(Ordering::SeqCst)
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or_default() {
        "m3u8" => "application/vnd.apple.mpegurl",
        "mp4" | "m4s" => "video/mp4",
        "ts" => "video/mp2t",
        "mkv" => "video/x-matroska",
        "bin" => "application/octet-stream",
        "vtt" => "text/vtt",
        _ => "application/octet-stream",
    }
}

fn full_body(body: Vec<u8>, kind: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response()
}

/// Serve one file from the tree (Range-honoring).
async fn tree_file(State((root, st)): State<(PathBuf, OriginState)>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let rel = path.trim_start_matches("/fx/").to_string();
    // Path-traversal refusal: only relative components below the root
    // resolve.
    if rel.split('/').any(|c| c == ".." || c.is_empty()) || rel.is_empty() {
        return (StatusCode::NOT_FOUND, "bad path").into_response();
    }
    let full = root.join(&rel);
    let Ok(bytes) = std::fs::read(&full) else {
        return (StatusCode::NOT_FOUND, "missing").into_response();
    };
    if rel.ends_with(".mp4") || rel.ends_with(".bin") {
        // The range-aware resources: count and echo proper 206s.
        let range = req
            .headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        st.blob_hits.fetch_add(1, Ordering::SeqCst);
        st.blob_ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(range.clone());
        if range.is_empty() {
            return full_body(bytes, content_type(&rel));
        }
        let (start, end_incl) = parse_range(&range, bytes.len() as u64);
        let body = bytes[start as usize..=(end_incl as usize)].to_vec();
        let mut resp = Response::new(axum::body::Body::from(body));
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        let headers = resp.headers_mut();
        let cr = HeaderValue::from_str(&format!("bytes {start}-{end_incl}/{}", bytes.len()))
            .unwrap_or_else(|e| panic!("content-range: {e}"));
        headers.insert(header::CONTENT_RANGE, cr);
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from(end_incl - start + 1),
        );
        return resp;
    }
    full_body(bytes, content_type(&rel))
}

fn parse_range(range: &str, total: u64) -> (u64, u64) {
    let spec = range.trim().strip_prefix("bytes=").unwrap_or("");
    match spec.split_once('-') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() => (
            a.parse().unwrap_or(0),
            b.parse::<u64>().unwrap_or(total - 1).min(total - 1),
        ),
        Some((a, _)) if !a.is_empty() => (a.parse().unwrap_or(0), total - 1),
        _ => (0, total - 1),
    }
}

/// The origin: /fx/<relpath> over the generated tree.
pub async fn spawn_tree_origin(root: &Path) -> (SocketAddr, OriginState) {
    let st = OriginState::default();
    let st2 = st.clone();
    let root = root.to_path_buf();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let app = Router::new()
        .route("/fx/{*rest}", get(tree_file))
        .with_state((root, st2));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            panic!("serve: {e}");
        }
    });
    (addr, st)
}

/// A fresh scratch dir (caller-tagged; removed first).
pub fn tempdir(prefix: &str, tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{prefix}-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    path
}
