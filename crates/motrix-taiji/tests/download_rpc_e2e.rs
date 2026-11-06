//! e2e: download mode + `--enable-rpc` — the same-process RPC server
//! observes the full task lifecycle (tellActive -> completed bytes ->
//! `onBtDownloadComplete` -> RPC shutdown graceful exit); the bare path
//! is a zero-change snapshot control; RPC options without the flag fail
//! at startup. Rig design: docs/design/cli.md.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

const PIECE_LEN: u64 = 16384;
const PIECES: u64 = 6;
const TOTAL: u64 = PIECE_LEN * PIECES;

/// Deterministic content (the same byte source on the seeder/leecher
/// sides; the pseudo-random shape avoids all-zero piece hashes).
fn test_content() -> Vec<u8> {
    (0..TOTAL).map(|i| ((i * 7 + 13) % 251) as u8).collect()
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-dlrpc-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("create_dir {d:?}: {e}"));
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("bind :0: {e}"))
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"))
        .port()
}

/// v1-only single-file metainfo (announce points at the in-process
/// fake tracker). Returns (torrent bytes, 20B infohash for the tracker
/// registry probe).
fn build_v1_torrent(content: &[u8], announce: &str) -> (Vec<u8>, [u8; 20]) {
    let pieces: Vec<u8> = content
        .chunks(PIECE_LEN as usize)
        .flat_map(|c| Sha1::digest(c).to_vec())
        .collect();
    let pair = |k: &[u8], v: Value| (k.to_vec(), v);
    let info = Value::Dict(vec![
        pair(b"length", Value::Int(content.len() as i64)),
        pair(b"name", Value::Bytes(b"blob.bin".to_vec())),
        pair(b"piece length", Value::Int(PIECE_LEN as i64)),
        pair(b"pieces", Value::Bytes(pieces)),
    ]);
    // infohash = sha1(the raw info-section bencode bytes) (BEP3).
    let info_bytes = bencode::encode(&info).unwrap_or_else(|e| panic!("bencode info: {e}"));
    let mut ih = [0u8; 20];
    ih.copy_from_slice(&Sha1::digest(&info_bytes));
    let top = Value::Dict(vec![
        pair(b"announce", Value::Bytes(announce.as_bytes().to_vec())),
        pair(b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("bencode encode: {e}"));
    (raw, ih)
}

fn percent_decode(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&raw[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

fn query_param<'a>(query: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    query.split(|b| *b == b'&').find_map(|s| {
        s.strip_prefix(key)
            .and_then(|r| r.first().filter(|c| **c == b'=').map(|_| &r[1..]))
    })
}

/// Fake tracker handle: port + registry probe (seeder announce readiness).
struct TrackerHandle {
    port: u16,
    registry: Arc<Mutex<HashMap<[u8; 20], Vec<u16>>>>,
}

impl TrackerHandle {
    fn peers(&self, ih: &[u8; 20]) -> Vec<u16> {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(ih)
            .cloned()
            .unwrap_or_default()
    }
}

/// Fake tracker: /announce registers (info_hash -> ports) and replies
/// with the full compact peer list (BEP3; interval=1 speeds up
/// discovery); /scrape replies with a minimal BEP48 face (silences
/// scrape retries). One spawn per connection; the process lifetime is
/// bounded by the test process (detach is enough).
async fn spawn_fake_tracker() -> TrackerHandle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("tracker bind: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .port();
    let registry: Arc<Mutex<HashMap<[u8; 20], Vec<u16>>>> = Arc::new(Mutex::new(HashMap::new()));
    let reg_task = Arc::clone(&registry);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let registry = Arc::clone(&reg_task);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let n = match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    head.extend_from_slice(&chunk[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if head.len() > 8 * 1024 {
                        return;
                    }
                }
                // Request line: GET /announce?...query... HTTP/1.x
                let line_end = head.windows(2).position(|w| w == b"\r\n").unwrap_or(0);
                let line = String::from_utf8_lossy(&head[..line_end]).into_owned();
                let (path, query) = line.split_once('?').unwrap_or((line.as_str(), ""));
                let query = query.split(' ').next().unwrap_or("").as_bytes().to_vec();
                let Some(ih_raw) = query_param(&query, b"info_hash") else {
                    return;
                };
                let ih = percent_decode(ih_raw);
                let Ok(ih) = <[u8; 20]>::try_from(ih) else {
                    return;
                };
                let body = if path.ends_with("/scrape") {
                    // Minimal BEP48 face: d5:filesd20:<ih>d8:completei1eee.
                    let mut b = Vec::new();
                    b.extend_from_slice(b"d5:filesd20:");
                    b.extend_from_slice(&ih);
                    b.extend_from_slice(b"d8:completei1eee");
                    b
                } else {
                    let aport = query_param(&query, b"port")
                        .and_then(|v| String::from_utf8_lossy(v).parse::<u16>().ok());
                    let peers = {
                        let mut book = registry.lock().unwrap_or_else(|e| e.into_inner());
                        let entry = book.entry(ih).or_default();
                        // Repeated same-port announces are idempotent (event=started/empty).
                        if let Some(p) = aport
                            && !entry.contains(&p)
                        {
                            entry.push(p);
                        }
                        entry.clone()
                    };
                    // Compact peers (BEP23): 4B IPv4 + 2B port; all-loopback rig.
                    let mut compact = Vec::new();
                    for p in peers.iter().take(50) {
                        compact.extend_from_slice(&[127, 0, 0, 1]);
                        compact.extend_from_slice(&p.to_be_bytes());
                    }
                    let mut b = Vec::new();
                    b.extend_from_slice(b"d8:intervali1e5:peers");
                    b.extend_from_slice(compact.len().to_string().as_bytes());
                    b.push(b':');
                    b.extend_from_slice(&compact);
                    b.push(b'e');
                    b
                };
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            });
        }
    });
    TrackerHandle { port, registry }
}

/// taiji subprocess (stderr written to a file for failure diagnosis;
/// cwd = temp dir so a default taiji.sqlite3 cannot pollute the repo).
/// Drop = kill (test-side teardown of the seeding resident process).
struct Proc {
    child: Child,
    stderr_path: PathBuf,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn tail(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

fn spawn_taiji(cwd: &std::path::Path, args: &[&str], tag: &str) -> Proc {
    let stderr_path = cwd.join(format!("stderr-{tag}.log"));
    let err = std::fs::File::create(&stderr_path).unwrap_or_else(|e| panic!("stderr file: {e}"));
    let child = Command::new(env!("CARGO_BIN_EXE_taiji"))
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn taiji: {e}"));
    Proc { child, stderr_path }
}

/// rqbit seeder (verifies the full payload, then seeds; see the file
/// header note for why the seeder is not taiji). `--disable-http-api`
/// is mandatory: concurrent rqbit processes collide on port 3030.
fn spawn_rqbit_seeder(
    payload_dir: &std::path::Path,
    torrent: &std::path::Path,
    log_dir: &std::path::Path,
) -> Proc {
    let stderr_path = log_dir.join("stderr-rqbit-seeder.log");
    let err = std::fs::File::create(&stderr_path).unwrap_or_else(|e| panic!("rqbit log: {e}"));
    let child = Command::new("rqbit")
        .arg("download")
        .arg(torrent)
        .arg("-o")
        .arg(payload_dir)
        .arg("--disable-http-api")
        .arg("--overwrite")
        .stdout(Stdio::from(
            err.try_clone().unwrap_or_else(|e| panic!("{e}")),
        ))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "spawn rqbit: {e} (a harness dependency; its absence means the harness is missing)"
            )
        });
    Proc { child, stderr_path }
}

async fn wait_port_open(port: u16, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("port {port} never opened within {budget:?}");
}

/// Bare HTTP/1.1 POST /jsonrpc; returns (status, body).
async fn rpc_post(addr: SocketAddr, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("rpc connect: {e}"));
    let req = format!(
        "POST /jsonrpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("rpc write: {e}"));
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("rpc read timeout"))
        .unwrap_or_else(|e| panic!("rpc read: {e}"));
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

/// Poll tellActive until the predicate hits; returns the matching task's gid.
async fn poll_active(
    addr: SocketAddr,
    secret: &str,
    want: impl Fn(&serde_json::Value) -> bool,
) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let (status, body) = rpc_post(
            addr,
            &format!(r#"{{"id":1,"method":"tellActive","params":["token:{secret}"]}}"#),
        )
        .await;
        assert_eq!(status, 200, "tellActive: {body}");
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("tellActive json: {e}: {body}"));
        if let Some(list) = v.get("result").and_then(|r| r.as_array()) {
            for task in list {
                if want(task) {
                    return task
                        .get("gid")
                        .and_then(|g| g.as_str())
                        .unwrap_or_default()
                        .to_string();
                }
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "tellActive predicate never met: {body}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Minimal WS client handshake (RFC 6455 subset, test-only; no Origin
/// header — non-browser clients pass the same-origin gate; secret
/// only, no rpc-user -> the Basic gate is trivially true).
async fn ws_connect(addr: SocketAddr) -> TcpStream {
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
    let mut head = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut b = [0u8; 512];
        let n = tokio::time::timeout_at(deadline, s.read(&mut b))
            .await
            .unwrap_or_else(|_| panic!("ws handshake timeout"))
            .unwrap_or_else(|e| panic!("ws handshake read: {e}"));
        if n == 0 {
            panic!(
                "ws handshake closed early: {}",
                String::from_utf8_lossy(&head)
            );
        }
        head.extend_from_slice(&b[..n]);
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
        "ws upgrade failed: {}",
        String::from_utf8_lossy(&head)
    );
    s
}

/// Read one frame (server->client frames are unmasked; text frames
/// return the payload, other frames an empty string, close None).
async fn ws_read_frame(s: &mut TcpStream, deadline: tokio::time::Instant) -> Option<String> {
    let mut hdr = [0u8; 2];
    tokio::time::timeout_at(deadline, s.read_exact(&mut hdr))
        .await
        .ok()?
        .ok()?;
    let opcode = hdr[0] & 0x0F;
    let mut len = (hdr[1] & 0x7F) as usize;
    if len == 126 {
        let mut b = [0u8; 2];
        tokio::time::timeout_at(deadline, s.read_exact(&mut b))
            .await
            .ok()?
            .ok()?;
        len = u16::from_be_bytes(b) as usize;
    } else if len == 127 {
        let mut b = [0u8; 8];
        tokio::time::timeout_at(deadline, s.read_exact(&mut b))
            .await
            .ok()?
            .ok()?;
        len = u64::from_be_bytes(b) as usize;
    }
    if hdr[1] & 0x80 != 0 {
        let mut mask = [0u8; 4];
        tokio::time::timeout_at(deadline, s.read_exact(&mut mask))
            .await
            .ok()?
            .ok()?;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        tokio::time::timeout_at(deadline, s.read_exact(&mut payload))
            .await
            .ok()?
            .ok()?;
    }
    match opcode {
        1 => Some(String::from_utf8_lossy(&payload).into_owned()),
        8 => None, // close
        _ => Some(String::new()),
    }
}

/// Wait for a WS frame containing `needle` (the completion-event assertion).
async fn ws_wait_event(s: &mut TcpStream, needle: &str, budget: Duration) -> String {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        match ws_read_frame(s, deadline).await {
            Some(text) if text.contains(needle) => return text,
            Some(_) => continue,
            None => panic!("ws closed before event {needle} arrived"),
        }
    }
}

/// Swarm test mutex (rqbit's default BT port is a global singleton —
/// concurrent swarms would collide; tests hold the lock serially). A
/// tokio async lock (the guard is held across await points — workspace
/// lints forbid a std MutexGuard over await); poisoning is swallowed
/// (an earlier test's panic must not redden the whole file).
static SWARM_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Temp path -> &str (workspace lints ban unwrap/expect; the panic carries the path).
fn pstr(p: &std::path::Path) -> &str {
    p.to_str()
        .unwrap_or_else(|| panic!("non-utf8 temp path: {}", p.display()))
}

/// Shared swarm rig: fake tracker + rqbit seeder (seeds after
/// verifying the full payload). Returns (temp dir, seeder process
/// handle, leecher download dir, infohash); the torrent is
/// bench.torrent (v1 single-file blob.bin, deterministic content).
/// Readiness = the infohash appears in the tracker registry (rqbit's
/// announce arrived). Locking: the caller holds SWARM_GATE for the
/// whole test body; this function takes no lock.
async fn spawn_swarm(tag: &str) -> (PathBuf, Proc, PathBuf, [u8; 20]) {
    let tracker = spawn_fake_tracker().await;
    let tmp = temp_dir(tag);
    let payload = tmp.join("payload");
    let dl_dir = tmp.join("dl");
    std::fs::create_dir_all(&payload).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(&dl_dir).unwrap_or_else(|e| panic!("{e}"));
    let content = test_content();
    std::fs::write(payload.join("blob.bin"), &content).unwrap_or_else(|e| panic!("{e}"));
    let (torrent_bytes, ih) = build_v1_torrent(
        &content,
        &format!("http://127.0.0.1:{}/announce", tracker.port),
    );
    let torrent_path = tmp.join("bench.torrent");
    std::fs::write(&torrent_path, &torrent_bytes).unwrap_or_else(|e| panic!("{e}"));
    let seeder = spawn_rqbit_seeder(&payload, &torrent_path, &tmp);
    // Readiness: rqbit's announce reached the tracker registry (it
    // announces only after verification, so presence means it can
    // serve); settle for another 1.5 s.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if !tracker.peers(&ih).is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "rqbit seeder never announced; stderr: {}",
            seeder.tail()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    (tmp, seeder, dl_dir, ih)
}

const SWARM_SECRET: &str = "dlrpc-sekrit";

/// Full lifecycle, leecher (download + RPC): the task is visible in
/// tellActive -> the `taiji.onBtDownloadComplete` event arrives (WS)
/// -> completed bytes match total -> on-disk bytes compare equal ->
/// RPC shutdown exits gracefully (exit 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_with_rpc_full_lifecycle_e2e() {
    let _gate = SWARM_GATE.lock().await;
    let (tmp, _seeder, dl_dir, ih) = spawn_swarm("lifecycle").await;
    let torrent_path = tmp.join("bench.torrent");

    // WS subscription first (the event window covers the whole download).
    let dl_rpc = free_port();
    let dl_db = tmp.join("leecher.sqlite3");
    let mut leecher = spawn_taiji(
        &tmp,
        &[
            pstr(&torrent_path),
            "-d",
            pstr(&dl_dir),
            "--listen-port",
            &free_port().to_string(),
            "--enable-rpc",
            "--rpc-listen-port",
            &dl_rpc.to_string(),
            "--rpc-secret",
            SWARM_SECRET,
            "--sqlite3-db-path",
            pstr(&dl_db),
        ],
        "leecher",
    );
    wait_port_open(dl_rpc, Duration::from_secs(15)).await;
    let dl_addr: SocketAddr = format!("127.0.0.1:{dl_rpc}")
        .parse()
        .unwrap_or_else(|e| panic!("{e}"));
    let mut ws = ws_connect(dl_addr).await;

    // The task is visible in tellActive (RPC observation covers the whole download).
    let gid = poll_active(dl_addr, SWARM_SECRET, |t| {
        t.get("status").and_then(|s| s.as_str()) == Some("active")
            && t.get("totalLength").and_then(|v| v.as_str()) == Some(&TOTAL.to_string())
    })
    .await;
    assert_eq!(
        gid.len(),
        16,
        "gid = hex16 (the GroupId::toHex semantics, u64)"
    );

    // The completion event arrives (canonical name taiji.onBtDownloadComplete).
    let frame = ws_wait_event(&mut ws, "onBtDownloadComplete", Duration::from_secs(90)).await;
    assert!(
        frame.contains(&gid),
        "complete event must carry gid: {frame}"
    );

    // Completed bytes (completedLength == totalLength) + on-disk byte equality.
    let (_, body) = rpc_post(
        dl_addr,
        &format!(r#"{{"id":2,"method":"tellStatus","params":["token:{SWARM_SECRET}","{gid}"]}}"#),
    )
    .await;
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(
        v["result"]["completedLength"].as_str(),
        Some(TOTAL.to_string().as_str()),
        "completed bytes: {body}"
    );
    let hex_ih: String = ih.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        v["result"]["infoHash"].as_str(),
        Some(hex_ih.as_str()),
        "the task identity = the injected torrent's infohash: {body}"
    );
    let got = std::fs::read(dl_dir.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got.len() as u64, TOTAL, "file size");
    assert_eq!(
        got,
        test_content(),
        "the downloaded content must be byte-for-byte identical to the source"
    );

    // RPC shutdown -> the process exits 0 (graceful shutdown through the session pipeline).
    let (status, body) = rpc_post(
        dl_addr,
        &format!(r#"{{"id":3,"method":"shutdown","params":["token:{SWARM_SECRET}"]}}"#),
    )
    .await;
    assert_eq!(status, 200, "shutdown: {body}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match leecher.child.try_wait().unwrap_or_else(|e| panic!("{e}")) {
            Some(e) => {
                assert_eq!(
                    e.code(),
                    Some(0),
                    "graceful exit required; stderr: {}",
                    leecher.tail()
                );
                break;
            }
            None => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "leecher did not exit after rpc shutdown; stderr: {}",
                    leecher.tail()
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Bare-run snapshot control: the default (no --enable-rpc) path is
/// unchanged — no RPC options involved, the download completes with
/// byte-identical files. A bare run has no RPC shutdown surface (it
/// keeps seeding; the process is killed by Proc::drop).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_download_without_rpc_snapshot() {
    let _gate = SWARM_GATE.lock().await;
    let (tmp, _seeder, dl_dir, _ih) = spawn_swarm("bare").await;
    let torrent_path = tmp.join("bench.torrent");
    let leecher = spawn_taiji(
        &tmp,
        &[
            pstr(&torrent_path),
            "-d",
            pstr(&dl_dir),
            "--listen-port",
            &free_port().to_string(),
        ],
        "bare",
    );
    // Snapshot: the file completes byte-for-byte (no RPC face to
    // observe — completion itself proves the download path works).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        match std::fs::read(dl_dir.join("blob.bin")) {
            Ok(got) if !got.is_empty() && got == test_content() => break,
            _ => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "bare download never completed; stderr: {}",
                    leecher.tail()
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Conflict arm at process level: download mode + RPC group options
/// without `--enable-rpc` -> rejected at startup (exit 2, the clap
/// usage-error code; the message points at --enable-rpc. Validation
/// precedes reading the torrent file — a missing file must still
/// report the conflict first).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_options_without_enable_rpc_are_rejected() {
    let tmp = temp_dir("conflict");
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_taiji"))
        .arg("missing.torrent")
        .arg("--rpc-listen-port")
        .arg(port.to_string())
        .current_dir(&tmp)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn taiji: {e}"));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let exit = loop {
        match child.try_wait().unwrap_or_else(|e| panic!("{e}")) {
            Some(e) => break e,
            None => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "conflict arm must exit fast"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    assert_eq!(
        exit.code(),
        Some(2),
        "the clap usage error shares the same exit code"
    );
    let mut stderr = String::new();
    if let Some(mut p) = child.stderr.take() {
        use std::io::Read as _;
        let _ = p.read_to_string(&mut stderr);
    }
    assert!(
        stderr.contains("--enable-rpc"),
        "conflict message must point to --enable-rpc: {stderr}"
    );
    assert!(
        stderr.contains("--rpc-listen-port"),
        "conflict message must name the offending option: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
