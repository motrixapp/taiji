//! End-to-end walk-through of the session-metrics JSONL capture (the
//! `BH_METRICS_TRACE` face; the injection seam stands in for the knob
//! because env is process-immutable under edition 2024): one real
//! session — addTorrent over an already-complete payload (initial
//! verification -> seeding) plus a loopback mini-leecher pulling the
//! full payload — with the capture open from session start; the
//! capture file must hold one valid JSON line per 1s tick with a
//! live, growing session behind it.
//!
//! The unset/no-injection arm runs the same session shape with no
//! trace injected: the session's scratch tree must stay free of any
//! capture file (the zero-added-I/O contract at the actor level; the
//! knob's own parse table lives in taiji-io).

use std::time::Duration;

use serde_json::Value as Json;
use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use taiji_core::gid::Gid;
use taiji_core::metainfo::Metainfo;
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionError, SessionHandle,
    SessionOptions, TorrentStatusView,
};
use taiji_store::persist::{PersistHandle, PersistWriter};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: usize = 16384;
const PIECE_COUNT: usize = 4;

fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn test_content() -> Vec<u8> {
    (0..PIECE_COUNT * PIECE_LEN)
        .map(|i| (i % 251 + 1) as u8)
        .collect()
}

/// Real single-file v1 metainfo (measured piece hashes).
fn build_v1_torrent(content: &[u8], name: &str, announce: &str) -> Vec<u8> {
    let mut pieces = Vec::new();
    for c in content.chunks(PIECE_LEN) {
        pieces.extend(Sha1::digest(c).as_slice());
    }
    let info = Value::Dict(vec![
        (b"length".to_vec(), Value::Int(content.len() as i64)),
        (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
        (b"piece length".to_vec(), Value::Int(PIECE_LEN as i64)),
        (b"pieces".to_vec(), Value::Bytes(pieces)),
    ]);
    let top = Value::Dict(vec![
        (
            b"announce".to_vec(),
            Value::Bytes(announce.as_bytes().to_vec()),
        ),
        (b"info".to_vec(), info),
    ]);
    ok(bencode::encode(&top), "encode torrent")
}

fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-metrics-trace-e2e-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    ok(std::fs::create_dir_all(&d), "mkdir");
    d
}

async fn spawn_session(
    db: &std::path::Path,
    listen_port: u16,
    trace: Option<std::path::PathBuf>,
) -> (
    std::sync::Arc<SessionHandle>,
    tokio::task::JoinHandle<()>,
    PersistHandle,
) {
    let (writer, _wjoin) = ok(PersistWriter::spawn(db.to_path_buf()).await, "spawn writer");
    let global = GlobalOptions {
        enable_dht: false,
        listen_port,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with_persist_and_metrics_trace(
        SessionOptions { global },
        Some(writer.clone()),
        trace,
    );
    (std::sync::Arc::new(handle), join, writer)
}

fn gid_of(r: Result<CommandReply, SessionError>) -> Gid {
    match r {
        Ok(CommandReply::Gid(g)) => g,
        other => panic!("expected Gid reply, got {other:?}"),
    }
}

async fn call(handle: &SessionHandle, cmd: SessionCommand) -> Result<CommandReply, SessionError> {
    handle.call(cmd).await
}

async fn tell_status(handle: &SessionHandle, gid: Gid) -> TorrentStatusView {
    match call(
        handle,
        SessionCommand::TellStatus {
            gid: gid.to_string(),
            keys: Vec::new(),
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => *v,
        other => panic!("tellStatus failed: {other:?}"),
    }
}

/// Reserve a loopback TCP port (the engine's fixed listen_port).
async fn reserve_tcp_port() -> u16 {
    let l = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let port = ok(l.local_addr(), "addr").port();
    drop(l);
    port
}

/// Mini-leecher (the seed_recheck_loopback shape): handshake ->
/// interested -> unchoke -> pull every block; returns bytes received.
async fn pull_all_blocks(port: u16, info_hash: [u8; 20], content_len: usize) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the leecher did not connect within 30s"
        );
        let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let mut hs = Vec::with_capacity(68);
        hs.push(19u8);
        hs.extend(b"BitTorrent protocol");
        hs.extend(&[0, 0, 0, 0, 0, 0x10, 0, 0x04]);
        hs.extend(&info_hash);
        hs.extend(b"LEECHERLEECHERLEECH1");
        if s.write_all(&hs).await.is_err() {
            continue;
        }
        let mut resp = [0u8; 68];
        if s.read_exact(&mut resp).await.is_err() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        if s.write_all(&[0, 0, 0, 1, 2]).await.is_err() {
            continue;
        }
        let mut unchoked = false;
        let mut pulled = 0usize;
        let mut next_piece = 0usize;
        let mut next_begin = 0u32;
        loop {
            if pulled >= content_len {
                // Hold the connection open across >= 2 engine 1s
                // ticks: the connection gauges (conn_tcp_in /
                // peers_by_class_local) are tick-sampled SET faces —
                // a sub-second loopback pull would fall between
                // ticks and never appear in the capture.
                tokio::time::sleep(Duration::from_secs(2)).await;
                return pulled;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "leecher pull timed out (pulled {pulled}/{content_len})"
            );
            if !unchoked {
                let mut len_buf = [0u8; 4];
                if s.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len == 0 {
                    continue;
                }
                let mut body = vec![0u8; len];
                if s.read_exact(&mut body).await.is_err() {
                    break;
                }
                if body[0] == 1 {
                    unchoked = true;
                }
                continue;
            }
            let index = next_piece as u32;
            let length = PIECE_LEN.min(content_len - pulled) as u32;
            let mut frame = Vec::with_capacity(17);
            frame.extend(13u32.to_be_bytes());
            frame.push(6u8);
            frame.extend(index.to_be_bytes());
            frame.extend(next_begin.to_be_bytes());
            frame.extend(length.to_be_bytes());
            if s.write_all(&frame).await.is_err() {
                break;
            }
            let mut len_buf = [0u8; 4];
            if tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut len_buf))
                .await
                .unwrap_or(Err(std::io::ErrorKind::Other.into()))
                .is_err()
            {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                continue;
            }
            let mut body = vec![0u8; len];
            if s.read_exact(&mut body).await.is_err() {
                break;
            }
            if body[0] == 7 {
                pulled += body[9..].len();
                next_begin += body[9..].len() as u32;
                if next_begin as usize >= PIECE_LEN {
                    next_begin = 0;
                    next_piece += 1;
                }
            }
        }
    }
}

/// Poll until the predicate holds (100ms steps, `secs` budget).
async fn wait_for<F, Fut>(secs: u64, what: &str, mut pred: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if pred().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Parse the capture file into JSON values (one per line).
fn read_capture(path: &std::path::Path) -> Vec<Json> {
    let text = ok(std::fs::read_to_string(path), "read capture");
    text.lines()
        .enumerate()
        .map(|(i, l)| {
            ok(
                serde_json::from_str::<Json>(l),
                &format!("capture line {i} is not JSON"),
            )
        })
        .collect()
}

/// The capture walk-through: with the trace open for the session's
/// whole life, a real seeding exchange must land as per-tick JSONL
/// snapshot lines with observable session state inside them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_download_lands_in_metrics_trace() {
    let content = test_content();
    let dir = scratch_dir("on");
    let payload = dir.join("payload");
    ok(std::fs::create_dir_all(&payload), "mkdir payload");
    ok(
        std::fs::write(payload.join("blob.bin"), &content),
        "write payload",
    );
    let db = dir.join("session.sqlite3");
    let trace_path = dir.join("metrics.jsonl");
    let port = reserve_tcp_port().await;

    let (handle, join, _writer) = spawn_session(&db, port, Some(trace_path.clone())).await;

    // addTorrent over the already-complete payload: initial
    // verification -> complete -> seeding.
    let torrent = build_v1_torrent(&content, "blob.bin", "http://127.0.0.1:1/announce");
    let meta = ok(Metainfo::parse(&torrent), "parse metainfo");
    let info_hash: [u8; 20] = match meta.meta.identity.v1 {
        Some(h) => h,
        None => panic!("v1 identity missing"),
    };
    let gid = gid_of(
        call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: torrent.clone(),
                options: std::collections::BTreeMap::from([
                    ("dir".to_string(), payload.display().to_string()),
                    // Seed forever (ratio 0 = no ShareRatio condition).
                    ("seed-ratio".to_string(), "0".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    wait_for(60, "completed == totalLength", || {
        let handle = handle.clone();
        async move {
            let v = tell_status(&handle, gid).await;
            v.total_length > 0 && v.completed_length == v.total_length
        }
    })
    .await;
    let pulled = pull_all_blocks(port, info_hash, content.len()).await;
    assert_eq!(pulled, content.len(), "the leecher must drain the payload");

    // Let at least three 1s ticks fire with the session live, then
    // shut down (the actor teardown closes the capture).
    tokio::time::sleep(Duration::from_secs(3)).await;
    handle.shutdown().await;
    ok(join.await, "actor join");

    // The capture: >= 3 lines (one per 1s tick), each a JSON object
    // with the diagnostic core of the snapshot; the run really was a
    // seeded session, so the payload counters must be visible.
    let lines = read_capture(&trace_path);
    assert!(
        lines.len() >= 3,
        "expected >= 3 capture lines (1s tick), got {}",
        lines.len()
    );
    let mut prev_uptime = 0u64;
    for (i, v) in lines.iter().enumerate() {
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("line {i}: not an object"));
        assert!(obj.contains_key("ts_ms"), "line {i}: missing ts_ms");
        let uptime = obj
            .get("uptime_seconds")
            .and_then(Json::as_u64)
            .unwrap_or(0);
        assert!(
            uptime >= prev_uptime,
            "line {i}: uptime went backwards ({uptime} < {prev_uptime})"
        );
        prev_uptime = uptime;
    }
    let last = lines.last().cloned().unwrap_or_else(|| panic!("no lines"));
    let last = last
        .as_object()
        .unwrap_or_else(|| panic!("last capture line is not an object"));
    // Live-connection evidence: the leecher's connection must be
    // visible in the per-tick gauge captures (conn_tcp_in /
    // peers_by_class_local — a loopback peer classes local), and the
    // leave event in the terminal counters. These are the faces the
    // engine 1s tick actually feeds; the aggregate up/down byte
    // counters (`bytes_*_total`) currently have no production feed
    // (only the tcp/utp transport split is bridged) and are therefore
    // NOT asserted — the capture records what the snapshot holds.
    let max_conn = lines
        .iter()
        .filter_map(|v| v.get("conn_tcp_in").and_then(Json::as_u64))
        .max()
        .unwrap_or(0);
    assert!(
        max_conn >= 1,
        "the leecher connection never appeared in the capture (conn_tcp_in max = {max_conn})"
    );
    let max_local = lines
        .iter()
        .filter_map(|v| v.get("peers_by_class_local").and_then(Json::as_u64))
        .max()
        .unwrap_or(0);
    assert!(
        max_local >= 1,
        "the loopback leecher never appeared in peers_by_class_local (max = {max_local})"
    );
    let leaves: u64 = last
        .get("peer_leaves_peer_closed_total")
        .and_then(Json::as_u64)
        .unwrap_or(0);
    assert!(
        leaves >= 1,
        "the leecher's departure never landed in peer_leaves_peer_closed_total"
    );
    for key in [
        "bytes_down_tcp_total",
        "bytes_down_utp_total",
        "peers_by_class_tcp",
        "dht_nodes_v4",
        "dht_queries_get_peers_total",
    ] {
        assert!(
            last.contains_key(key),
            "capture line missing diagnostic key {key}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The unset arm: no injection (and the env knob unset in the test
/// process) = no capture file appears anywhere in the session's
/// scratch tree while the session runs past a tick boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_trace_injected_means_no_capture_file() {
    let dir = scratch_dir("off");
    let db = dir.join("session.sqlite3");
    let port = reserve_tcp_port().await;
    let (handle, join, _writer) = spawn_session(&db, port, None).await;
    // Run past a 1s tick boundary: had the capture been assembled, a
    // line (and its file) would exist by now.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    handle.shutdown().await;
    ok(join.await, "actor join");
    let jsonl: Vec<_> = ok(std::fs::read_dir(&dir), "read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("jsonl"))
        })
        .collect();
    assert!(
        jsonl.is_empty(),
        "capture file created without the knob/injection: {jsonl:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
