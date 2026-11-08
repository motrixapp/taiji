//! `metalink` feature two-state build gate: the off state requires the
//! metalink code to stay out of the compiled tree entirely.
//!
//! Assertion mechanism: this test binary is itself a taiji-rpc link
//! product —
//! - On state (default): the `metalink` consumption seam is genuinely
//!   exercised by the test -> taiji-metalink's code and symbol paths
//!   necessarily embed in the binary (the crate identity appears as
//!   symbol names / panic paths);
//! - Off state: `taiji-metalink` is not in the dependency graph
//!   (optional dep + feature gate), so the identity cannot appear in
//!   the product — appearing at all means the gate has failed (the
//!   dependency seam was bypassed).
//!
//! The fingerprint strings are assembled at runtime (this file's source
//! contains no contiguous fingerprint, avoiding self-fulfilling
//! evidence). Running this test in both states closes the loop.
//!
//! Method registration face, two-state assertions (one face at a
//! time): the on state's listMethods contains `taiji.addMetalink`; in
//! the off state the method does not exist — canonical and alias calls
//! all get "No such method" (registration is gated through
//! `taiji-core/metalink`; the canonical_method central point keeps its
//! shape).

/// Assemble the crate-identity fingerprints at runtime (underscore
/// symbol form / hyphen path form).
fn fingerprints() -> [String; 2] {
    [
        format!("taiji{}metalink", '_'),
        format!("taiji{}metalink", '-'),
    ]
}

/// Fingerprint detection within the own binary's bytes (symbol names /
/// panic path strings both carry the crate identity; ASCII substrings
/// survive UTF-8 lossy conversion — replacement happens only on invalid
/// sequences, which cannot swallow valid ASCII substrings).
fn binary_mentions_metalink() -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => panic!("current_exe unavailable: {e}"),
    };
    let bytes = match std::fs::read(&exe) {
        Ok(b) => b,
        Err(e) => panic!("read own binary {}: {e}", exe.display()),
    };
    let text = String::from_utf8_lossy(&bytes);
    fingerprints().iter().any(|fp| text.contains(fp.as_str()))
}

#[test]
fn metalink_symbols_match_feature_state() {
    let present = binary_mentions_metalink();

    #[cfg(feature = "metalink")]
    {
        // On state: the consumption seam is genuinely exercised (below);
        // the symbols must be in the product.
        let doc = taiji_rpc::metalink::parse(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="gate.iso"><size>1</size></file></metalink>"#,
        )
        .unwrap_or_else(|e| panic!("open-state parse must work: {e}"));
        assert_eq!(doc.files.len(), 1);
        assert!(
            present,
            "feature metalink is ON: binary must link its symbols"
        );
    }

    #[cfg(not(feature = "metalink"))]
    {
        // Off state: the module does not exist and the dependency is not
        // in the graph — the fingerprint appearing means the whole-tree
        // gate has failed.
        assert!(
            !present,
            "feature metalink is OFF: binary must not contain its symbols"
        );
    }
}

// ---- method registration face, two-state e2e (real sockets; harness like metalink_rpc.rs) ----

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

/// Registered-state e2e (on-state half): listMethods presents
/// `taiji.addMetalink` and the method is callable (after the write gate
/// passes, it lands on the seam's parameter face — a missing param =
/// the standard text, not "No such method").
#[cfg(feature = "metalink")]
#[tokio::test]
async fn add_metalink_is_registered_on_the_open_face() {
    let (handle, token) = spawn_with_secret("g").await;
    let addr = handle.local_addr;
    let methods = rpc(addr, "g", "system.listMethods", json!([])).await;
    let names: Vec<&str> = methods["result"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        names.contains(&"taiji.addMetalink"),
        "open face must list addMetalink: {names:?}"
    );
    let missing = rpc(
        addr,
        "g",
        "taiji.addMetalink",
        json!(["token:g", "!not-b64!"]),
    )
    .await;
    assert_eq!(
        missing["error"]["message"],
        json!("metalink data is not valid base64."),
        "registered method reaches the seam execution face: {missing}"
    );
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

/// Off-state e2e: feature off = addMetalink not registered — canonical
/// and bare-name calls both get "No such method" (same shape as aria2's
/// NoSuchMethodRpcMethod face when ENABLE_METALINK is off).
#[cfg(not(feature = "metalink"))]
#[tokio::test]
async fn add_metalink_is_method_not_found_when_feature_off() {
    let (handle, token) = spawn_with_secret("g").await;
    let addr = handle.local_addr;
    let methods = rpc(addr, "g", "system.listMethods", json!([])).await;
    let names: Vec<&str> = methods["result"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        !names.iter().any(|n| n.contains("addMetalink")),
        "closed face must not list addMetalink: {names:?}"
    );
    for name in ["taiji.addMetalink", "addMetalink"] {
        let r = rpc(addr, "g", name, json!(["token:g", "AAAA"])).await;
        assert_eq!(r["error"]["code"], json!(1), "{name}");
        assert_eq!(
            r["error"]["message"],
            json!(format!("No such method: {name}")),
            "{name}: closed feature = method not found: {r}"
        );
    }
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}
