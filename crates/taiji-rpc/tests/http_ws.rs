//! Transport-layer integration tests: HTTP/WS semantics on real
//! sockets (auth positive/negative/delay, size limit, batch, multicall,
//! CORS, WS upgrade smoke, shutdown full-chain exit).
//!
//! The HTTP client is a raw HTTP/1.1 client over a native tokio
//! TcpStream (self-contained test surface, zero new dependencies); the
//! WS client is a minimal handshake + frame codec (RFC 6455 subset,
//! test-only).

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use taiji_core::session::SessionActor;
use taiji_rpc::{RpcConfig, serve};

const JSON_CT: &str = "application/json-rpc";

fn cfg(
    port: u16,
    secret: Option<&str>,
    allow_origin_all: bool,
    max_request_size: usize,
) -> RpcConfig {
    RpcConfig {
        port,
        secret: secret.map(str::to_string),
        allow_origin_all,
        max_request_size,
        ..Default::default()
    }
}

async fn spawn(secret: Option<&str>) -> (taiji_rpc::ServerHandle, CancellationToken) {
    spawn_with(cfg(0, secret, false, 10 * 1024 * 1024)).await
}

async fn spawn_with(config: RpcConfig) -> (taiji_rpc::ServerHandle, CancellationToken) {
    let (session, _join) = SessionActor::spawn();
    let token = CancellationToken::new();
    let handle = serve(config, std::sync::Arc::new(session), token.clone())
        .await
        .unwrap_or_else(|e| panic!("serve failed: {e}"));
    (handle, token)
}

/// Raw HTTP/1.1 request: returns (status, headers, body, elapsed).
async fn raw_http(
    addr: std::net::SocketAddr,
    method: &str,
    body: Option<&str>,
) -> (u16, Vec<(String, String)>, String, Duration) {
    raw_http_with(addr, method, "", body).await
}

/// Raw HTTP/1.1 request with **extra request headers** (each line must
/// end with `\r\n`).
async fn raw_http_with(
    addr: std::net::SocketAddr,
    method: &str,
    extra_headers: &str,
    body: Option<&str>,
) -> (u16, Vec<(String, String)>, String, Duration) {
    let t0 = Instant::now();
    let mut s = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => panic!("connect {addr}: {e}"),
    };
    let (payload, extra) = match body {
        Some(b) => (
            b,
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ),
        ),
        None => ("", String::new()),
    };
    let req = format!(
        "{method} /jsonrpc HTTP/1.1\r\nHost: {addr}\r\n{extra}{extra_headers}Connection: close\r\n\r\n{payload}"
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = Vec::new();
    // Connection: close: reading to the peer close yields the complete
    // response.
    match tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await {
        Ok(Ok(_)) => {}
        other => panic!("read_to_end: {other:?}"),
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, payload) = match text.split_once("\r\n\r\n") {
        Some((h, p)) => (h, p.to_string()),
        None => panic!("malformed http response: {text:?}"),
    };
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status in {status_line:?}"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        .collect();
    (status, headers, payload, t0.elapsed())
}

async fn post_json(
    addr: std::net::SocketAddr,
    body: &str,
) -> (u16, Vec<(String, String)>, String, Duration) {
    raw_http(addr, "POST", Some(body)).await
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------- HTTP semantics

#[tokio::test]
async fn post_get_version_ok_is_fast_and_json_rpc_content_type() {
    let (srv, _token) = spawn(None).await;
    let (status, headers, body, elapsed) =
        post_json(srv.local_addr, r#"{"id":1,"method":"getVersion"}"#).await;
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "content-type"), Some(JSON_CT));
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("body not json: {e}: {body}"));
    assert_eq!(v["id"], 1);
    assert_eq!(v["jsonrpc"], "2.0");
    assert!(
        v["result"]["version"]
            .as_str()
            .unwrap_or("")
            .starts_with("taiji/"),
        "frozen prefix violated: {body}"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "authorized path must be fast: {elapsed:?}"
    );
}

#[tokio::test]
async fn unauthorized_is_http_400_after_one_second_delay() {
    // Criterion 2 (negative + delay): DelayedCommand 1s -> HTTP 400 +
    // "Unauthorized".
    let (srv, _token) = spawn(Some("sekrit")).await;
    let (status, _h, body, elapsed) =
        post_json(srv.local_addr, r#"{"id":2,"method":"getVersion"}"#).await;
    assert_eq!(status, 400);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    assert_eq!(v["error"]["code"], 1);
    assert_eq!(v["error"]["message"], "Unauthorized");
    assert!(
        elapsed >= Duration::from_millis(950),
        "unauthorized response must be delayed ~1s, got {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "delay must not be unbounded: {elapsed:?}"
    );

    // Positive: with the token, admitted immediately.
    let (status, _h, body, elapsed) = post_json(
        srv.local_addr,
        r#"{"id":3,"method":"getVersion","params":["token:sekrit"]}"#,
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("taiji/"));
    assert!(
        elapsed < Duration::from_millis(500),
        "token path must be fast: {elapsed:?}"
    );
}

#[tokio::test]
async fn oversize_body_is_rejected_explicitly() {
    // Criterion: size limit — over-limit explicit error (413 +
    // taiji.request.too_large).
    let (srv, _token) = spawn_with(cfg(0, None, false, 64)).await;
    let big = format!(
        r#"{{"id":1,"method":"getVersion","pad":"{}"}}"#,
        "x".repeat(200)
    );
    let (status, _h, body, _e) = post_json(srv.local_addr, &big).await;
    assert_eq!(status, 413);
    assert!(body.contains("taiji.request.too_large"), "got {body}");
}

#[tokio::test]
async fn parse_error_maps_to_500_minus_32700() {
    // Cross-checked against HttpServerBodyCommand.cc default branch:
    // -32700 -> HTTP 500.
    let (srv, _token) = spawn(None).await;
    let (status, _h, body, _e) = post_json(srv.local_addr, "not json at all").await;
    assert_eq!(status, 500);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    assert_eq!(v["error"]["code"], -32700);
    assert_eq!(v["error"]["message"], "Parse error.");
}

#[tokio::test]
async fn batch_call_returns_array_with_200() {
    let (srv, _token) = spawn(None).await;
    let (status, _h, body, _e) = post_json(
        srv.local_addr,
        r#"[{"id":1,"method":"getVersion"},{"id":2,"method":"no.such"}]"#,
    )
    .await;
    assert_eq!(status, 200, "batch always 200 (sendJsonRpcBatchResponse)");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let arr = v
        .as_array()
        .unwrap_or_else(|| panic!("batch must be array: {body}"));
    assert_eq!(arr.len(), 2);
    assert!(arr[0]["result"]["version"].is_string());
    assert_eq!(arr[1]["error"]["message"], "No such method: no.such");
}

#[tokio::test]
async fn multicall_over_http_wraps_and_inlines() {
    let (srv, _token) = spawn(None).await;
    let (status, _h, body, _e) = post_json(
        srv.local_addr,
        r#"{"id":9,"method":"system.multicall","params":[[
            {"methodName":"getVersion"},
            {"methodName":"addUri"},
            {"methodName":"system.multicall"}
        ]]}"#,
    )
    .await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let slots = v["result"]
        .as_array()
        .unwrap_or_else(|| panic!("slots: {body}"));
    assert_eq!(slots.len(), 3);
    assert!(slots[0].is_array(), "success wrapped in list");
    // Write gate: with no secret set, write subcalls are rejected at
    // the dispatch layer (an inline error slot, not fatal).
    assert_eq!(
        slots[1]["message"],
        "unauthenticated write requires --rpc-secret"
    );
    assert_eq!(slots[2]["message"], "Recursive system.multicall forbidden.");
}

#[tokio::test]
async fn batch_over_item_cap_is_rejected_over_http() {
    // Batch item cap over real HTTP — 1001 items rejected as one whole
    // batch (taiji.request.too_many_items), before per-item processing.
    let (srv, _token) = spawn(None).await;
    let mut items = Vec::new();
    for i in 0..1001 {
        items.push(format!(r#"{{"id":{i},"method":"getVersion"}}"#));
    }
    let big = format!("[{}]", items.join(","));
    let (status, _h, body, _e) = post_json(srv.local_addr, &big).await;
    assert_eq!(status, 400);
    assert!(
        body.contains("taiji.request.too_many_items"),
        "cap error: {body}"
    );
}

// ---------------------------------------------------------------- CORS

#[tokio::test]
async fn cors_allow_origin_all_adds_headers_and_preflight() {
    let (srv, _token) = spawn_with(cfg(0, None, true, 10 * 1024 * 1024)).await;
    let (_s, headers, _b, _e) =
        post_json(srv.local_addr, r#"{"id":1,"method":"getVersion"}"#).await;
    assert_eq!(header(&headers, "access-control-allow-origin"), Some("*"));

    // Preflight: reference HttpServerBodyCommand.cc.
    let mut s = TcpStream::connect(srv.local_addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let req = format!(
        "OPTIONS /jsonrpc HTTP/1.1\r\nHost: {0}\r\nOrigin: http://example.local\r\n\
         Access-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\n\
         Connection: close\r\n\r\n",
        srv.local_addr
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    // hyper writes header names lowercase on the wire; the assertion
    // lowercases uniformly (semantics are case-insensitive).
    let text = String::from_utf8_lossy(&buf).to_lowercase();
    assert!(text.starts_with("http/1.1 200"), "preflight 200: {text}");
    assert!(
        text.contains("access-control-allow-methods: post, get, options"),
        "{text}"
    );
    assert!(text.contains("access-control-max-age: 1728000"), "{text}");
    assert!(
        text.contains("access-control-allow-headers: content-type"),
        "{text}"
    );
}

#[tokio::test]
async fn cors_absent_without_allow_origin_all() {
    let (srv, _token) = spawn_with(cfg(0, None, false, 10 * 1024 * 1024)).await;
    let (_s, headers, _b, _e) =
        post_json(srv.local_addr, r#"{"id":1,"method":"getVersion"}"#).await;
    assert_eq!(header(&headers, "access-control-allow-origin"), None);
}

// ---------------------------------------------------------------- WS

/// Minimal WS client handshake (RFC 6455 subset, test-only).
async fn ws_connect(addr: std::net::SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("ws connect: {e}"));
    let req = format!(
        "GET /jsonrpc HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("ws write: {e}"));
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        other => panic!("ws handshake read: {other:?}"),
    };
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "ws upgrade failed: {head}"
    );
    s
}

async fn ws_send_text(s: &mut TcpStream, text: &str) {
    // Client frames must be masked (RFC 6455 §5.3); a fixed mask
    // suffices for tests.
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    let payload = text.as_bytes();
    let mut frame = vec![0x81u8]; // FIN + text
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
    s.write_all(&frame)
        .await
        .unwrap_or_else(|e| panic!("ws frame write: {e}"));
}

async fn ws_read_text(s: &mut TcpStream) -> String {
    let mut hdr = [0u8; 2];
    match tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut hdr)).await {
        Ok(Ok(_)) => {}
        other => panic!("ws frame header: {other:?}"),
    }
    let opcode = hdr[0] & 0x0F;
    let masked = hdr[1] & 0x80 != 0;
    let mut len = (hdr[1] & 0x7F) as usize;
    if len == 126 {
        let mut b = [0u8; 2];
        s.read_exact(&mut b)
            .await
            .unwrap_or_else(|e| panic!("ws len: {e}"));
        len = u16::from_be_bytes(b) as usize;
    } else if len == 127 {
        let mut b = [0u8; 8];
        s.read_exact(&mut b)
            .await
            .unwrap_or_else(|e| panic!("ws len: {e}"));
        len = u64::from_be_bytes(b) as usize;
    }
    let mut mask_key = [0u8; 4];
    if masked {
        s.read_exact(&mut mask_key)
            .await
            .unwrap_or_else(|e| panic!("ws mask: {e}"));
    }
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload)
        .await
        .unwrap_or_else(|e| panic!("ws payload: {e}"));
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask_key[i % 4];
        }
    }
    assert_eq!(opcode, 1, "expecting text frame, opcode {opcode}");
    String::from_utf8(payload).unwrap_or_else(|e| panic!("ws text utf8: {e}"))
}

#[tokio::test]
async fn ws_upgrade_smoke_request_response() {
    // Criterion: WS upgrade smoke — handshake + request/response round
    // trip.
    let (srv, _token) = spawn(None).await;
    let mut s = ws_connect(srv.local_addr).await;
    ws_send_text(&mut s, r#"{"id":5,"method":"getVersion"}"#).await;
    let reply = ws_read_text(&mut s).await;
    let v: serde_json::Value =
        serde_json::from_str(&reply).unwrap_or_else(|e| panic!("ws reply not json: {e}: {reply}"));
    assert_eq!(v["id"], 5);
    assert!(
        v["result"]["version"]
            .as_str()
            .unwrap_or("")
            .starts_with("taiji/")
    );

    // Bad frame -> -32700 (cross-checked against WebSocketSession.cc
    // dropping bytes -> parse failure).
    ws_send_text(&mut s, "garbage").await;
    let reply = ws_read_text(&mut s).await;
    assert!(reply.contains("-32700"), "parse error over ws: {reply}");
}

// ---------------------------------------------------------------- shutdown

#[tokio::test]
async fn shutdown_via_rpc_exits_server_within_budget() {
    // Criterion: shutdown via RPC triggers a full-chain exit (HTTP
    // response -> token cancel -> server exit). Since the write gate
    // landed, shutdown is a write — driven with a token.
    let (srv, token) = spawn(Some("sekrit")).await;
    let (status, _h, body, _e) = post_json(
        srv.local_addr,
        r#"{"id":1,"method":"shutdown","params":["token:sekrit"]}"#,
    )
    .await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    assert_eq!(v["result"], "OK");
    let joined = tokio::time::timeout(Duration::from_secs(2), srv.join()).await;
    assert!(joined.is_ok(), "server must exit after rpc shutdown");
    assert!(token.is_cancelled());
}

#[tokio::test]
async fn shutdown_without_secret_is_refused_and_server_stays_up() {
    // End-to-end: with no secret set, shutdown is refused and the
    // server stays up.
    let (srv, token) = spawn(None).await;
    let (status, _h, body, _e) = post_json(srv.local_addr, r#"{"id":1,"method":"shutdown"}"#).await;
    assert_eq!(status, 400);
    assert!(
        body.contains("unauthenticated write requires --rpc-secret"),
        "write gate: {body}"
    );
    assert!(
        !token.is_cancelled(),
        "refused write must not stop the server"
    );
    let (status, _h, body, _e) =
        post_json(srv.local_addr, r#"{"id":2,"method":"getVersion"}"#).await;
    assert_eq!(status, 200, "read-only still served: {body}");
}

/// Bind-face matrix, five states (two decoupled axes: the bind face
/// only looks at `--rpc-listen-all`; credential state does not
/// participate — cross-checked against aria2 `HttpListenCommand.cc`
/// adding `AI_PASSIVE` only under listen_all, the fork verbatim
/// isomorphic; the no-credentials WARN text is kept but does not change
/// the bind face, DownloadEngineFactory.cc).
/// Five states: (1) no credentials (2) secret only (3) Basic only
/// (4) listen_all+secret (5) listen_all+Basic x expected bind face.
/// The sixth arm (listen_all without credentials, refused at startup)
/// is [`listen_all_without_credentials_is_refused_at_startup`].
#[tokio::test]
async fn bind_face_matrix_listen_all_axis_decoupled_from_credentials() {
    // (1) no credentials -> loopback.
    let (srv, _t) = spawn(None).await;
    assert!(
        srv.local_addr.ip().is_loopback(),
        "no-credentials must bind loopback"
    );
    // (2) secret only -> still loopback (credentials only decide the
    // auth gate; they no longer implicitly widen the bind face).
    let (srv2, _t2) = spawn(Some("x")).await;
    assert!(
        srv2.local_addr.ip().is_loopback(),
        "secret alone must stay loopback: {}",
        srv2.local_addr
    );
    // (3) --rpc-user/--rpc-passwd only (no secret) -> still loopback.
    let mut c = cfg(0, None, false, 10 * 1024 * 1024);
    c.rpc_user = Some("u".into());
    c.rpc_passwd = Some("p".into());
    let (srv3, _t3) = spawn_with(c).await;
    assert!(
        srv3.local_addr.ip().is_loopback(),
        "basic alone must stay loopback: {}",
        srv3.local_addr
    );
    // (4) listen_all + secret -> 0.0.0.0 (the only deciding item on the
    // bind axis).
    let mut c4 = cfg(
        0,
        Some("listen-all-matrix-secret-16"),
        false,
        10 * 1024 * 1024,
    );
    c4.listen_all = true;
    let (srv4, _t4) = spawn_with(c4).await;
    assert!(
        srv4.local_addr.ip().is_unspecified(),
        "listen_all must bind all interfaces: {}",
        srv4.local_addr
    );
    // (5) listen_all + Basic credentials -> 0.0.0.0.
    let mut c5 = cfg(0, None, false, 10 * 1024 * 1024);
    c5.listen_all = true;
    c5.rpc_user = Some("u".into());
    c5.rpc_passwd = Some("p".into());
    let (srv5, _t5) = spawn_with(c5).await;
    assert!(
        srv5.local_addr.ip().is_unspecified(),
        "listen_all with basic credentials must bind all interfaces: {}",
        srv5.local_addr
    );
}

/// Composition guard (fail-closed controlled difference):
/// `--rpc-listen-all` with no credentials at all -> error exit at
/// startup, the message names the fix (set credentials or drop
/// listen-all to restore loopback). aria2 with the same combination
/// only WARNs and listens anyway (DownloadEngineFactory.cc) — taiji
/// narrows this under the same philosophy as the unauthenticated write
/// gate (declared controlled difference).
#[tokio::test]
async fn listen_all_without_credentials_is_refused_at_startup() {
    let (session, _join) = SessionActor::spawn();
    let mut c = cfg(0, None, false, 10 * 1024 * 1024);
    c.listen_all = true;
    let Err(err) = serve(c, std::sync::Arc::new(session), CancellationToken::new()).await else {
        panic!("listen_all without credentials must refuse to start");
    };
    let msg = err.to_string();
    assert!(msg.contains("--rpc-listen-all"), "names the switch: {msg}");
    assert!(msg.contains("--rpc-secret"), "names the fix path: {msg}");
    assert!(
        msg.contains("loopback"),
        "names the loopback fallback: {msg}"
    );
}

// ---------------------------------------------------------------- Basic auth

/// Test-local standard base64 (the decode surface is covered by the
/// base64.rs/auth.rs tests).
fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn basic_header(user: &str, pass: &str) -> String {
    format!(
        "Authorization: Basic {}\r\n",
        b64(format!("{user}:{pass}").as_bytes())
    )
}

async fn spawn_basic(
    secret: Option<&str>,
    user: Option<&str>,
    passwd: Option<&str>,
) -> (taiji_rpc::ServerHandle, CancellationToken) {
    let mut c = cfg(0, secret, false, 10 * 1024 * 1024);
    c.rpc_user = user.map(str::to_string);
    c.rpc_passwd = passwd.map(str::to_string);
    spawn_with(c).await
}

#[tokio::test]
async fn basic_auth_positive_negative_and_401_shape() {
    // Criteria (positive/negative/no header): missing header / wrong
    // credentials -> 401 + challenge + disableKeepAlive
    // (HttpServerCommand.cc); correct credentials pass (HttpServer.cc).
    let (srv, _t) = spawn_basic(None, Some("u"), Some("p")).await;
    let body = r#"{"id":1,"method":"getVersion"}"#;

    // Correct credentials -> 200 + version, and no delay. **First**:
    // the negative block below accumulates consecutive auth failures
    // (the test source is always 127.0.0.1) — the backoff gate arms a
    // window for same-source attempts past the threshold (default 5),
    // so the fast-path assertion must take its baseline before the
    // failure sequence.
    let (_s, _h, ok_body, elapsed) =
        raw_http_with(srv.local_addr, "POST", &basic_header("u", "p"), Some(body)).await;
    assert!(ok_body.contains("taiji/"), "{ok_body}");
    assert!(
        elapsed < Duration::from_millis(500),
        "authorized path must be fast: {elapsed:?}"
    );

    // No Authorization header -> 401 + WWW-Authenticate (realm
    // cross-checked against HttpServerCommand.cc) + Connection: close
    // (disableKeepAlive).
    let (status, headers, _b, _e) = raw_http_with(srv.local_addr, "POST", "", Some(body)).await;
    assert_eq!(status, 401);
    assert_eq!(
        header(&headers, "www-authenticate"),
        Some("Basic realm=\"aria2\""),
        "challenge header"
    );
    assert_eq!(header(&headers, "connection"), Some("close"));

    // Wrong password / wrong user / lowercase scheme (streq is
    // case-sensitive, util.h) -> 401.
    for extra in [
        basic_header("u", "wrong"),
        basic_header("who", "p"),
        format!("Authorization: basic {}\r\n", b64(b"u:p")),
        "Authorization: Bearer whatever\r\n".to_string(),
        "Authorization: Basic !!!not-base64\r\n".to_string(),
    ] {
        let (status, _h, _b, _e) = raw_http_with(srv.local_addr, "POST", &extra, Some(body)).await;
        assert_eq!(status, 401, "extra={extra:?}");
    }
    // Note: by now the same source has accumulated >= 5 failures —
    // further auth attempts would fall inside the backoff window (the
    // response is still 401, just with ~window-length extra delay; the
    // window-semantics test anchored in src/server.rs
    // `auth_backoff_window_delays_valid_credentials_then_success_resets`).
    // This test sends no further auth requests; scope closed here.

    // user-only (no passwd) -> the password is not checked
    // (HttpServer.cc `!password_ ||`).
    let (srv2, _t2) = spawn_basic(None, Some("u"), None).await;
    for extra in [
        format!("Authorization: Basic {}\r\n", b64(b"u")),
        basic_header("u", "any-password"),
    ] {
        let (status, _h, _b, _e) = raw_http_with(srv2.local_addr, "POST", &extra, Some(body)).await;
        assert_eq!(
            status, 200,
            "password unchecked when unset: extra={extra:?}"
        );
    }
}

#[tokio::test]
async fn basic_auth_unauthorized_is_delayed_one_second() {
    // Criterion (delay): the Basic unauthorized response is delayed
    // ~1s (design: reuses the DelayedCommand mechanism; 1s
    // unauthorized delay).
    let (srv, _t) = spawn_basic(None, Some("u"), Some("p")).await;
    let (_s, _h, _b, elapsed) = raw_http_with(
        srv.local_addr,
        "POST",
        "",
        Some(r#"{"id":1,"method":"getVersion"}"#),
    )
    .await;
    assert!(
        elapsed >= Duration::from_millis(950),
        "basic 401 must be delayed ~1s, got {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "delay must not be unbounded: {elapsed:?}"
    );
}

#[tokio::test]
async fn options_preflight_is_exempt_from_basic() {
    // OPTIONS exemption (HttpServerCommand.cc `!= "OPTIONS"`).
    let (srv, _t) = spawn_basic(None, Some("u"), Some("p")).await;
    let mut s = TcpStream::connect(srv.local_addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let req = format!(
        "OPTIONS /jsonrpc HTTP/1.1\r\nHost: {0}\r\nOrigin: http://example.local\r\n\
         Access-Control-Request-Method: POST\r\nConnection: close\r\n\r\n",
        srv.local_addr
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    assert!(text.starts_with("HTTP/1.1 200"), "preflight 200: {text}");
}

#[tokio::test]
async fn ws_upgrade_is_gated_by_basic() {
    // Upgrade requests are gated the same (authenticate precedes the WS
    // handshake branch, HttpServerCommand.cc).
    let (srv, _t) = spawn_basic(None, Some("u"), Some("p")).await;
    let mut s = TcpStream::connect(srv.local_addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let req = format!(
        "GET /jsonrpc HTTP/1.1\r\nHost: {0}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        srv.local_addr
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    assert!(
        text.starts_with("HTTP/1.1 401"),
        "upgrade without basic must be denied: {text}"
    );
    assert!(text.to_lowercase().contains("www-authenticate"), "{text}");
}

#[tokio::test]
async fn secret_and_basic_layers_are_independent() {
    // Criterion (secret priority semantics): --rpc-secret (token path)
    // and --rpc-user/--rpc-passwd (Basic path) are two independent
    // layers — in the reference, token consumes only PREF_RPC_SECRET
    // (DownloadEngine.cc) and Basic only PREF_RPC_USER/PASSWD
    // (HttpServerCommand.cc); with both set, the HTTP-layer Basic gates
    // first, then the RPC-layer token.
    let (srv, _t) = spawn_basic(Some("s"), Some("u"), Some("p")).await;

    // (1) correct token, no Basic -> HTTP-layer 401 (before the RPC
    // layer).
    let (status, headers, _b, _e) = raw_http_with(
        srv.local_addr,
        "POST",
        "",
        Some(r#"{"id":1,"method":"getVersion","params":["token:s"]}"#),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(
        header(&headers, "www-authenticate"),
        Some("Basic realm=\"aria2\"")
    );

    // (2) correct Basic, no token -> HTTP layer passes, RPC layer
    // "Unauthorized" (code 1 -> HTTP 400, cross-checked in error.rs
    // http_status) + deferred flag.
    let (status, _h, body, elapsed) = raw_http_with(
        srv.local_addr,
        "POST",
        &basic_header("u", "p"),
        Some(r#"{"id":1,"method":"getVersion"}"#),
    )
    .await;
    assert_eq!(status, 400);
    assert!(body.contains("Unauthorized"), "rpc layer: {body}");
    assert!(
        elapsed >= Duration::from_millis(950),
        "rpc-level unauthorized also delayed: {elapsed:?}"
    );

    // (3) both layers pass -> 200 + version.
    let (status, _h, body, _e) = raw_http_with(
        srv.local_addr,
        "POST",
        &basic_header("u", "p"),
        Some(r#"{"id":1,"method":"getVersion","params":["token:s"]}"#),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("taiji/"), "{body}");
}

#[tokio::test]
async fn no_basic_config_keeps_token_only_regression() {
    // Criterion (token: path regression unchanged): with --rpc-user not
    // configured the Basic layer always passes, and the token semantics
    // are exactly as before (missing token -> 1s delay then 400).
    let (srv, _t) = spawn(Some("sekrit")).await;
    let (status, headers, body, elapsed) =
        post_json(srv.local_addr, r#"{"id":1,"method":"getVersion"}"#).await;
    assert_eq!(status, 400);
    assert_eq!(
        header(&headers, "www-authenticate"),
        None,
        "no basic challenge"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    assert_eq!(v["error"]["message"], "Unauthorized");
    assert!(elapsed >= Duration::from_millis(950), "{elapsed:?}");
    let (status, _h, _b, _e) = post_json(
        srv.local_addr,
        r#"{"id":2,"method":"getVersion","params":["token:sekrit"]}"#,
    )
    .await;
    assert_eq!(status, 200);
}
