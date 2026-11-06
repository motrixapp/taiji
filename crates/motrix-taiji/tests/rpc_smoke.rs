//! CLI wiring smoke: `--rpc-listen-port` starts the server -> a native
//! HTTP client calls getVersion -> RPC `shutdown` exits the process
//! gracefully within the shutdown budget.
//!
//! The real binary runs (CARGO_BIN_EXE_taiji); the HTTP client is a
//! native tokio TcpStream speaking bare HTTP/1.1 (zero new
//! dependencies, same shape as the rpc crate integration tests).
//! Security hardening: writes require credentials — without a secret
//! the write gate must refuse and the process must stay up; with a
//! secret, token-driven shutdown must exit cleanly.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind :0: {e}"));
    l.local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"))
        .port()
}

fn spawn_cli(port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_taiji"))
        .arg("--rpc-listen-port")
        .arg(port.to_string())
        .arg("--rpc-secret")
        .arg("smoke-sekrit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn taiji: {e}"))
}

fn spawn_cli_without_secret(port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_taiji"))
        .arg("--rpc-listen-port")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn taiji: {e}"))
}

fn wait_port_open(port: u16, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Bare HTTP/1.1 POST (blocking IO suffices); returns (status, body).
fn rpc_post(port: u16, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|e| panic!("connect: {e}"));
    let req = format!(
        "POST /jsonrpc HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes())
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = String::new();
    s.read_to_end_string(&mut buf);
    let (head, payload) = buf
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("malformed response: {buf:?}"));
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status: {head:?}"));
    (status, payload.to_string())
}

/// Local helper: read_to_end into a String (std Read chaining).
trait ReadToEndString {
    fn read_to_end_string(&mut self, out: &mut String);
}

impl ReadToEndString for TcpStream {
    fn read_to_end_string(&mut self, out: &mut String) {
        use std::io::Read;
        let mut bytes = Vec::new();
        self.read_to_end(&mut bytes)
            .unwrap_or_else(|e| panic!("read: {e}"));
        out.push_str(&String::from_utf8_lossy(&bytes));
    }
}

#[test]
fn unauthenticated_write_is_refused_and_daemon_stays_up() {
    // Security regression: without --rpc-secret a write (shutdown)
    // gets 400 + the frozen message; the service must not exit and
    // the read-only face keeps working.
    let port = free_port();
    let mut child = spawn_cli_without_secret(port);
    assert!(
        wait_port_open(port, Duration::from_secs(10)),
        "cli must open rpc listener on --rpc-listen-port"
    );

    let (status, body) = rpc_post(port, r#"{"id":4,"method":"shutdown"}"#);
    assert_eq!(status, 400, "unauthenticated write: {body}");
    assert!(
        body.contains("unauthenticated write requires --rpc-secret"),
        "write gate message: {body}"
    );
    assert!(
        !matches!(child.try_wait(), Ok(Some(_))),
        "refused write must not stop the daemon"
    );
    // A read-only method is unaffected by the write gate: the service is unharmed.
    let (status, body) = rpc_post(port, r#"{"id":5,"method":"getVersion"}"#);
    assert_eq!(status, 200, "read-only after refused write: {body}");
    assert!(body.contains("taiji/"), "getVersion: {body}");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn cli_rpc_listen_port_smoke_and_rpc_shutdown_exits_cleanly() {
    let port = free_port();
    let mut child = spawn_cli(port);
    assert!(
        wait_port_open(port, Duration::from_secs(10)),
        "cli must open rpc listener on --rpc-listen-port"
    );

    // getVersion via the native client with a token (once a secret is
    // set, the token layer applies to all methods).
    let (status, body) = rpc_post(
        port,
        r#"{"id":1,"method":"getVersion","params":["token:smoke-sekrit"]}"#,
    );
    assert_eq!(status, 200);
    assert!(
        body.contains("taiji/") && body.contains("enabledFeatures"),
        "getVersion shape: {body}"
    );

    // system.listNotifications event-name sanity over the real
    // process (canonical names: taiji.onXxx).
    let (status, body) = rpc_post(
        port,
        r#"{"id":2,"method":"system.listNotifications","params":["token:smoke-sekrit"]}"#,
    );
    assert_eq!(status, 200);
    assert!(
        body.contains("taiji.onBtDownloadComplete"),
        "six events: {body}"
    );

    // shutdown over RPC exits the whole pipeline — the process exits 0 (token-authenticated write).
    let (status, body) = rpc_post(
        port,
        r#"{"id":3,"method":"shutdown","params":["token:smoke-sekrit"]}"#,
    );
    assert_eq!(status, 200);
    assert!(body.contains(r#""result":"OK""#), "shutdown OK: {body}");

    let deadline = Instant::now() + Duration::from_secs(5);
    let exit = loop {
        match child.try_wait().unwrap_or_else(|e| panic!("try_wait: {e}")) {
            Some(e) => break e,
            None if Instant::now() > deadline => panic!("cli did not exit after rpc shutdown"),
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    assert_eq!(
        exit.code(),
        Some(0),
        "graceful shutdown must exit 0 within budget"
    );
}
