//! RPC completeness-surface transport integration tests (real
//! sockets): the `sftp://` deferred error code e2e + HTTP-face smoke
//! for getUris/getServers/saveSession.
//!
//! The HTTP client is a raw HTTP/1.1 client over a native tokio
//! TcpStream (self-contained test surface, zero new dependencies;
//! harness isomorphic to http_ws.rs).

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use taiji_core::session::SessionActor;
use taiji_rpc::{RpcConfig, serve};

async fn spawn_with_secret(secret: &str) -> (taiji_rpc::ServerHandle, CancellationToken) {
    let (session, _join) = SessionActor::spawn();
    let config = RpcConfig {
        port: 0,
        secret: Some(secret.to_string()),
        allow_origin_all: false,
        max_request_size: 10 * 1024 * 1024,
        ..Default::default()
    };
    let token = CancellationToken::new();
    let handle = serve(config, std::sync::Arc::new(session), token.clone())
        .await
        .unwrap_or_else(|e| panic!("serve failed: {e}"));
    (handle, token)
}

/// JSON-RPC single call (token as the first parameter; write gate /
/// auth face per the server-injected secret).
async fn rpc(addr: std::net::SocketAddr, secret: &str, method: &str, params: Value) -> Value {
    let mut arr = vec![json!(format!("token:{secret}"))];
    if let Value::Array(rest) = params {
        arr.extend(rest);
    }
    let body = json!({"jsonrpc": "2.0", "id": "t", "method": method, "params": arr});
    let payload = body.to_string();
    let mut s = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    let req = format!(
        "POST /jsonrpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = Vec::new();
    match tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await {
        Ok(Ok(_)) => {}
        other => panic!("read_to_end: {other:?}"),
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let payload = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(payload).unwrap_or_else(|e| panic!("json parse {e}: {text:?}"))
}

/// `sftp://` scheme deferred error code e2e — addUri reaches the
/// session over a real HTTP socket and is rejected wholesale at task
/// creation, the error message carrying the `taiji.sftp.deferred` code
/// (declared difference: SFTP deferred).
#[tokio::test]
async fn sftp_scheme_add_uri_is_deferred_with_explicit_code() {
    let (handle, token) = spawn_with_secret("s").await;
    let addr = handle.local_addr;
    // Pure sftp source.
    let r = rpc(
        addr,
        "s",
        "taiji.addUri",
        json!([["sftp://host.example/f.bin"]]),
    )
    .await;
    let msg = r["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.starts_with("taiji.sftp.deferred:"),
        "the sftp deferred error code: {r}"
    );
    assert_eq!(
        r["error"]["code"],
        json!(1),
        "a task-creation-phase refusal = the code-1 face"
    );
    // Mixed sources (http + sftp): partial acceptance is unreachable
    // under mirror semantics — reject wholesale.
    let r = rpc(
        addr,
        "s",
        "addUri",
        json!([["http://host.example/f.bin", "sftp://host.example/f.bin"]]),
    )
    .await;
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("taiji.sftp.deferred:"),
        "mixed sources are likewise rejected: {r}"
    );
    // The canonical alias face (`taiji.getUris`) works on the same
    // chain: an unknown GID errors explicitly (str2Gid prefix
    // resolution; the error face matches the aria2 text).
    let r = rpc(addr, "s", "taiji.getUris", json!(["0000000000000000"])).await;
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("is not found"),
        "an unknown GID errors explicitly: {r}"
    );
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}
