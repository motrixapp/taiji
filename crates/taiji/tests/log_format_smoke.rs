//! CLI log-format smoke: the real binary (CARGO_BIN_EXE_taiji) starts
//! an idle daemon (piped stdout = the non-TTY state):
//! - `--log-format json`: stdout is line-delimited valid JSON with the
//!   full field set (timestamp/level/target/fields.message — the
//!   tracing-subscriber json default);
//! - default text + non-TTY: zero ANSI in the output (no `\x1b` at
//!   all — collectors reading redirected logs need no stripping).
//!
//! Closeout mirrors rpc_smoke: token shutdown -> graceful exit 0, no
//! daemon left behind. No new test dependencies (serde_json is already
//! a runtime dependency of the RPC face).

use std::io::{Read, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind :0: {e}"));
    l.local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"))
        .port()
}

/// Start an idle daemon: stdout piped (non-TTY -> text mode must be
/// ANSI-free); RUST_LOG=info is set explicitly (shields against shell
/// environment drift and guarantees assertable log lines).
fn spawn_daemon(port: u16, log_format: Option<&str>) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_taiji"));
    cmd.arg("--rpc-listen-port")
        .arg(port.to_string())
        .arg("--rpc-secret")
        .arg("smoke-sekrit")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(fmt) = log_format {
        cmd.arg("--log-format").arg(fmt);
    }
    cmd.spawn().unwrap_or_else(|e| panic!("spawn taiji: {e}"))
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

/// Bare HTTP/1.1 POST (blocking IO suffices; rpc_smoke isomorphic): returns (status, body).
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
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("read: {e}"));
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, payload) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("malformed response: {text:?}"));
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status: {head:?}"));
    (status, payload.to_string())
}

/// Token shutdown -> graceful exit 0 within the shutdown budget;
/// returns the full stdout collected after closeout.
fn shutdown_and_collect_stdout(mut child: Child, port: u16) -> String {
    let (status, body) = rpc_post(
        port,
        r#"{"id":1,"method":"shutdown","params":["token:smoke-sekrit"]}"#,
    );
    assert_eq!(status, 200, "shutdown: {body}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait().unwrap_or_else(|e| panic!("try_wait: {e}")) {
            Some(e) => {
                assert_eq!(e.code(), Some(0), "graceful shutdown must exit 0");
                break;
            }
            None if Instant::now() > deadline => panic!("cli did not exit after rpc shutdown"),
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("stdout must be piped"))
        .read_to_string(&mut stdout)
        .unwrap_or_else(|e| panic!("read stdout: {e}"));
    stdout
}

/// `--log-format json`: stdout is line-delimited valid JSON with the
/// full field set (timestamp/level/target/fields.message).
#[test]
fn log_format_json_emits_line_delimited_valid_json() {
    let port = free_port();
    let child = spawn_daemon(port, Some("json"));
    assert!(
        wait_port_open(port, Duration::from_secs(10)),
        "cli must open rpc listener on --rpc-listen-port"
    );
    let stdout = shutdown_and_collect_stdout(child, port);

    assert!(!stdout.trim().is_empty(), "json mode must emit log lines");
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line must be valid JSON ({e}): {line:?}"));
        for key in ["timestamp", "level", "target"] {
            assert!(v.get(key).is_some(), "json line missing `{key}`: {line:?}");
        }
        assert!(
            v.get("fields").is_some_and(|f| f.get("message").is_some()),
            "json line missing fields.message: {line:?}"
        );
    }
}

/// Default text + non-TTY (piped capture = the redirected state):
/// stdout is ANSI-free (zero `\x1b`) — collectors, journaling, and
/// benchmark rigs need no escape stripping.
#[test]
fn text_format_non_tty_output_has_zero_ansi() {
    let port = free_port();
    let child = spawn_daemon(port, None); // default text
    assert!(
        wait_port_open(port, Duration::from_secs(10)),
        "cli must open rpc listener on --rpc-listen-port"
    );
    let stdout = shutdown_and_collect_stdout(child, port);

    assert!(!stdout.trim().is_empty(), "text mode must emit log lines");
    assert!(
        !stdout.contains('\x1b'),
        "text + non-tty output must be ansi-clean, got: {stdout:?}"
    );
}
