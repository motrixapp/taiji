//! Egress bind (`--interface` -> `ClientConfig.local_address` ->
//! reqwest `local_address`): the wire-level criterion — the configured
//! local address must reach the socket layer of every transport
//! connection, observable in two complementary arms:
//!
//! - **positive** (environments where 127.0.0.2 is bindable — Linux
//!   routes the whole 127/8 via lo0, macOS after a lo0 alias): the mock
//!   records the accepted connection's **peer address** == the
//!   configured bind (not the OS default 127.0.0.1 pick);
//! - **negative** (stock macOS: only 127.0.0.1 is assigned, binding
//!   127.0.0.2 fails EADDRNOTAVAIL): the request against a LIVE mock
//!   fails on the bind — the local address was applied (an ignored
//!   config would have connected and returned 200).
//!
//! The unbound control always runs (the mock serves it a 200), pinning
//! the environment shape the arms are judged against.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::traits::RequestCtx;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// The off-.1 loopback address used as the observable bind (127/8 keeps
/// the test hermetic; no external interface is touched).
const BINDABLE_PROBE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));

/// Whether this environment allows binding the probe address (Linux:
/// the whole 127/8 is local; stock macOS: no — the negative arm takes
/// over there).
fn probe_bindable() -> bool {
    std::net::TcpListener::bind((BINDABLE_PROBE, 0)).is_ok()
}

/// One-shot raw HTTP/1.1 mock: binds 127.0.0.1:0, serves exactly one
/// connection a minimal 200, and reports the accepted connection's peer
/// address (the server-side view of the client's source) via the join
/// handle.
async fn spawn_mock() -> (SocketAddr, tokio::task::JoinHandle<SocketAddr>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let task = tokio::spawn(async move {
        let (mut sock, peer) = listener
            .accept()
            .await
            .unwrap_or_else(|e| panic!("accept: {e}"));
        // Drain the request head (bounded; the body-less GET ends at
        // the blank line).
        let mut buf = [0u8; 4096];
        let mut got = 0usize;
        loop {
            let n = sock
                .read(&mut buf[..])
                .await
                .unwrap_or_else(|e| panic!("read: {e}"));
            got += n;
            if buf[..got].windows(4).any(|w| w == b"\r\n\r\n") || got == buf.len() {
                break;
            }
        }
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        peer
    });
    (addr, task)
}

/// One GET through a client built with the given config; asserts a 200
/// terminal response and returns the mock-observed peer address.
async fn get_and_observe_peer(client: &HttpClient) -> SocketAddr {
    let (addr, task) = spawn_mock().await;
    let followed = client
        .get(&format!("http://{addr}/file"), &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("request failed: {e}"));
    assert_eq!(
        followed.response.status().as_u16(),
        200,
        "the request completes against the mock"
    );
    task.await.unwrap_or_else(|e| panic!("mock join: {e}"))
}

/// Bound vs unbound source addresses, observed server-side. with_metrics
/// builds the clients outside the process-level shared pool (test
/// isolation, the same discipline as the other mock labs — two configs
/// differing only in the bind must never share a transport).
#[tokio::test]
async fn client_binds_configured_local_address() {
    // Bound client (local_address = 127.0.0.2).
    let cfg = ClientConfig {
        local_address: Some(BINDABLE_PROBE),
        ..ClientConfig::default()
    };
    let client = HttpClient::with_metrics(cfg, Arc::new(Default::default()))
        .unwrap_or_else(|e| panic!("client: {e}"));

    if probe_bindable() {
        // Positive arm: the accepted peer carries the configured bind.
        let peer = get_and_observe_peer(&client).await;
        assert_eq!(
            peer.ip(),
            BINDABLE_PROBE,
            "the accepted peer address IS the configured local bind"
        );
    } else {
        // Negative arm (stock macOS): the bind is unassignable, so the
        // request must FAIL against a live mock — the failure surface
        // is the proof the local address reached the socket layer (an
        // ignored config would have connected and served the 200).
        let (addr, task) = spawn_mock().await;
        let err = client
            .get(&format!("http://{addr}/file"), &RequestCtx::default())
            .await
            .err()
            .unwrap_or_else(|| panic!("the unassignable bind must fail the request"));
        let text = err.to_string();
        assert!(
            text.contains("bind local") || text.contains("assign requested address"),
            "the failure must be the local bind, got: {text}"
        );
        // The mock connection never arrives; end the task's accept by
        // dropping the listener implicitly (task ends at runtime drop —
        // abort to avoid a dangling accept).
        task.abort();
    }

    // Unbound control (the status quo): the OS source pick for a
    // 127.0.0.1 destination is 127.0.0.1 — the observation above is the
    // bind at work, not an artifact of the loopback topology.
    let client = HttpClient::with_metrics(ClientConfig::default(), Arc::new(Default::default()))
        .unwrap_or_else(|e| panic!("client: {e}"));
    let peer = get_and_observe_peer(&client).await;
    assert_eq!(
        peer.ip(),
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "unbound control: the OS default loopback source"
    );
}
