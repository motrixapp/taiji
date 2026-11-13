//! Acceptance: end-to-end hook-subset execution model (SPEC §7.4).
//!
//! Vehicle: fake hooks (shell scripts that log argv argument by argument)
//! against a real SessionActor:
//!
//! - Six trigger-point argv assertions (table-driven start/pause/stop +
//!   error + bt-complete/complete): argv = [gidHex16, numFiles,
//!   firstFilename] — the reference `util.cc executeHook` argv passing,
//!   with no placeholder substitution;
//! - bt-complete and complete dual-fire semantics (a BT task fires both
//!   events, as in aria2's DefaultPieceStorage.cc + RequestGroupMan.cc);
//! - hook failure isolation: a missing command or nonzero exit does not
//!   affect task state (util.cc semantics);
//! - zero overhead with no hook options: the existing hookless path is
//!   unchanged (the runner is not attached; see the hook.rs unit test
//!   `fire_without_command_is_noop`).
//!
//! Coverage (trigger point -> test):
//!
//! | Trigger point | Reference site | Test |
//! |---------------|------------------------|------------------------------------|
//! | start | RequestGroupMan.cc | trigger_points_table_driven |
//! | pause | RequestGroupMan.cc | trigger_points_table_driven |
//! | stop | RequestGroupMan.cc | trigger_points_table_driven |
//! | complete | RequestGroupMan.cc | bt_complete_and_complete_dual_fire |
//! | error | RequestGroupMan.cc | error_hook_fires_on_failed_task |
//! | bt-complete | DefaultPieceStorage.cc | bt_complete_and_complete_dual_fire |

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use taiji_core::gid::Gid;
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionError, SessionOptions,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-session-hook-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// Build a single-file v1 .torrent (same shape as rate_limit_session).
fn build_v1_torrent(content: &[u8], announce: &str) -> (Vec<u8>, [u8; 20]) {
    let mut pieces = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        pieces.extend_from_slice(&Sha1::digest(c));
    }
    let info = Value::Dict(vec![
        (b"length".to_vec(), Value::Int(content.len() as i64)),
        (b"name".to_vec(), Value::Bytes(b"blob.bin".to_vec())),
        (b"piece length".to_vec(), Value::Int(PIECE_LEN as i64)),
        (b"pieces".to_vec(), Value::Bytes(pieces)),
    ]);
    let info_bytes = bencode::encode(&info).unwrap_or_else(|e| panic!("{e}"));
    let mut hasher = Sha1::new();
    hasher.update(&info_bytes);
    let infohash: [u8; 20] = hasher.finalize().into();
    let top = Value::Dict(vec![
        (
            b"announce".to_vec(),
            Value::Bytes(announce.as_bytes().to_vec()),
        ),
        (b"info".to_vec(), info),
    ]);
    (
        bencode::encode(&top).unwrap_or_else(|e| panic!("{e}")),
        infohash,
    )
}

/// Fake tracker: answers with compact peers = the seeder address (same
/// shape as engine_loop).
async fn fake_tracker(seeder_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock
                .read(&mut chunk)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            if n == 0 {
                break;
            }
            req.extend_from_slice(&chunk[..n]);
        }
        let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
            panic!("test expects IPv4 seeder addr");
        };
        let ip = v4.octets();
        let port = seeder_addr.port().to_be_bytes();
        let mut peers = Vec::new();
        peers.extend_from_slice(&ip);
        peers.extend_from_slice(&port);
        let mut raw = Vec::new();
        raw.extend_from_slice(b"d8:intervali60e5:peers");
        raw.extend_from_slice(peers.len().to_string().as_bytes());
        raw.push(b':');
        raw.extend_from_slice(&peers);
        raw.push(b'e');
        let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
        sock.write_all(head.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        sock.write_all(&raw).await.unwrap_or_else(|e| panic!("{e}"));
    });
    addr
}

/// Mini-seeder: interested -> unchoke, request -> piece (same shape as
/// engine_loop).
async fn spawn_mini_seeder(
    listener: tokio::net::TcpListener,
    content: Vec<u8>,
    info_hash: [u8; 20],
) {
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(&hs[28..48], &info_hash, "engine handshake info_hash");
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10; // extended
        resp[27] = 0x04; // fast
        resp[28..48].copy_from_slice(&info_hash);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // After the handshake the mini-seeder sends a full bitfield per
        // BEP 3 (2 pieces = 0b1100_0000). It used to send no ad and rely
        // on the dispatcher's blind-select fallback; that fallback went
        // away with ad-aware dispatch.
        sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        loop {
            let mut len_buf = [0u8; 4];
            if sock.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                continue;
            }
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            match body[0] {
                2 => {
                    sock.write_all(&[0, 0, 0, 1, 1])
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                6 => {
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * PIECE_LEN as usize + begin as usize;
                    let block = content[offset..offset + length as usize].to_vec();
                    let mut frame = Vec::new();
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(&block);
                    sock.write_all(&frame)
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                _ => {}
            }
        }
    });
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!("bh-p41-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// Fake hook: logs argv argument by argument as a
/// `PREFIX|argv1|argv2|argv3` line (observable vehicle for the reference
/// argv-passing semantics).
fn write_hook_script(tag: &str, prefix: &str, log: &Path, body: Option<&str>) -> String {
    let dir = temp_dir(tag);
    let script = dir.join("hook.sh");
    let log_s = log.display().to_string();
    let text = match body {
        // Failure-injection form: exit 3 (nonzero exit, util.cc
        // isolation counterpart).
        Some(extra) => format!("#!/bin/sh\n{extra}\n"),
        None => {
            format!("#!/bin/sh\nprintf '{prefix}|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" >> '{log_s}'\n")
        }
    };
    std::fs::write(&script, text).unwrap_or_else(|e| panic!("{e}"));
    let mut perm = std::fs::metadata(&script)
        .unwrap_or_else(|e| panic!("{e}"))
        .permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&script, perm).unwrap_or_else(|e| panic!("{e}"));
    script.display().to_string()
}

/// Poll the log until a line containing `needle` appears (panic on
/// timeout).
async fn wait_for_line(log: &Path, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = std::fs::read_to_string(log) {
            for line in text.lines() {
                if line.contains(needle) {
                    return line.to_string();
                }
            }
        }
        if Instant::now() > deadline {
            panic!(
                "hook line with `{needle}` not found in {} within {timeout:?}",
                log.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn gid_of(reply: Result<CommandReply, SessionError>) -> Gid {
    match reply.unwrap_or_else(|e| panic!("{e}")) {
        CommandReply::Gid(g) => g,
        other => panic!("expected Gid, got {other:?}"),
    }
}

/// Table-driven trigger-point subset: start / pause / stop (each row =
/// flow + hook injection point + expected argv). start fires on
/// activation (RequestGroupMan.cc); pause fires when the task returns to
/// the queue head during teardown; stop fires at the remove terminal
/// state, where the REMOVED branch keeps the stop hook slot. argv is
/// asserted argument by argument: gidHex16, numFiles, firstFilename.
#[tokio::test]
async fn trigger_points_table_driven() {
    enum Flow {
        /// The pause hook goes through per-task options.
        PausePerTask,
        /// The stop hook goes through **global** options (covers both the
        /// global and the per-task injection).
        StopGlobal,
    }
    let cases: [(&str, Flow); 2] = [
        ("start+pause", Flow::PausePerTask),
        ("start+stop", Flow::StopGlobal),
    ];

    for (i, (name, flow)) in cases.iter().enumerate() {
        let tag = format!("t{i}-{name}");
        let tmp = temp_dir(&tag);
        let log = tmp.join("hook.log");
        let script = write_hook_script(&format!("{tag}-s"), "ARGV", &log, None);

        let mut global = GlobalOptions::default();
        let mut task_opts: BTreeMap<String, String> = BTreeMap::from([
            ("dir".to_string(), tmp.display().to_string()),
            // The start hook is always per-task (vehicle for the
            // fires-on-activation assertion).
            ("on-download-start".to_string(), script.clone()),
        ]);
        match flow {
            Flow::PausePerTask => {
                task_opts.insert("on-download-pause".to_string(), script.clone());
            }
            Flow::StopGlobal => {
                global.hooks.on_download_stop = Some(script.clone());
            }
        }
        let (handle, join) = SessionActor::spawn_with(SessionOptions { global });

        let content = test_content();
        let (torrent, _ih) = build_v1_torrent(&content, "http://127.0.0.1:9/announce");
        let gid = gid_of(
            handle
                .call(SessionCommand::AddTorrent {
                    torrent,
                    options: task_opts,
                    position: None,
                })
                .await,
        );
        let expected = format!("ARGV|{gid}|1|{}", tmp.join("blob.bin").display());

        // start: fires on activation, before any download progress (the
        // fake tracker does not interfere).
        let start_line =
            wait_for_line(&log, &format!("ARGV|{gid}|1|"), Duration::from_secs(15)).await;
        assert_eq!(start_line, expected, "case {name}: start argv");

        match flow {
            Flow::PausePerTask => {
                handle
                    .call(SessionCommand::Pause {
                        gid: gid.to_string(),
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            Flow::StopGlobal => {
                handle
                    .call(SessionCommand::Remove {
                        gid: gid.to_string(),
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
        }
        // Second line = the pause/stop trigger (same argv shape; one
        // line per fire).
        let deadline = Instant::now() + Duration::from_secs(15);
        let all = loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.lines().count() >= 2 {
                break text;
            }
            if Instant::now() > deadline {
                panic!("case {name}: expected 2 hook lines, got {text:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let rows: Vec<&str> = all.lines().collect();
        assert_eq!(rows[1], expected, "case {name}: second trigger argv");

        // Cleanup (in the pause flow the task is still queued; shutdown
        // sweeps it).
        handle.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

/// Error trigger point: a magnet with all discovery sources disabled
/// explicitly fails and fires on-download-error with the in-memory
/// projection payload (numFiles = 0, firstFilename = "" — the util.cc
/// inMemoryDownload branch).
#[tokio::test]
async fn error_hook_fires_on_failed_task() {
    let tmp = temp_dir("err");
    let log = tmp.join("hook.log");
    let script = write_hook_script("err-s", "ARGV", &log, None);
    let (handle, join) = SessionActor::spawn();

    let gid = gid_of(
        handle
            .call(SessionCommand::AddUri {
                uris: vec!["magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into()],
                options: BTreeMap::from([
                    ("on-download-error".to_string(), script),
                    ("bt-disable-dht".to_string(), "true".to_string()),
                    ("dir".to_string(), tmp.display().to_string()),
                ]),
                position: None,
            })
            .await,
    );
    // In-memory projection: argv[2] = 0, argv[3] empty (argv semantics).
    let line = wait_for_line(&log, &format!("ARGV|{gid}|0|"), Duration::from_secs(15)).await;
    assert_eq!(line, format!("ARGV|{gid}|0|"));

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Dual-fire semantics: a BT task finishing its download fires
/// on-bt-download-complete (DefaultPieceStorage.cc, before seeding
/// starts); when seed-time elapses, SeedStopped leads to teardown
/// FINISHED and on-download-complete (RequestGroupMan.cc). Both events
/// fire, and bt-complete precedes complete.
#[tokio::test]
async fn bt_complete_and_complete_dual_fire() {
    let content = test_content();
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let tracker_addr = fake_tracker(seeder_addr).await;
    let (torrent, infohash) =
        build_v1_torrent(&content, &format!("http://{tracker_addr}/announce"));
    spawn_mini_seeder(seeder_listener, content.clone(), infohash).await;

    let tmp = temp_dir("dual");
    let log = tmp.join("hook.log");
    let bt_script = write_hook_script("dual-bt", "BT", &log, None);
    let c_script = write_hook_script("dual-c", "DONE", &log, None);

    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions::default(),
    });
    let gid = gid_of(
        handle
            .call(SessionCommand::AddTorrent {
                torrent,
                options: BTreeMap::from([
                    ("dir".to_string(), tmp.display().to_string()),
                    // seed-time = 1.2s ("0.02" in minute units, the
                    // aria2 convention): after download the task seeds
                    // until the condition is met, then finishes
                    // (SeedStopped -> Complete terminal state).
                    ("seed-time".to_string(), "0.02".to_string()),
                    ("on-bt-download-complete".to_string(), bt_script),
                    ("on-download-complete".to_string(), c_script),
                ]),
                position: None,
            })
            .await,
    );

    // The on-disk content is the proof of the bt-complete moment (verify
    // before write means all pieces on disk = download complete).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match std::fs::read(tmp.join("blob.bin")) {
            Ok(bytes) if bytes == content => break,
            _ => {
                if Instant::now() > deadline {
                    panic!("download did not complete in time");
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let bt_line = wait_for_line(&log, &format!("BT|{gid}|1|"), Duration::from_secs(15)).await;
    assert_eq!(
        bt_line,
        format!("BT|{gid}|1|{}", tmp.join("blob.bin").display()),
        "bt-complete argv"
    );
    let c_line = wait_for_line(&log, &format!("DONE|{gid}|1|"), Duration::from_secs(20)).await;
    assert_eq!(
        c_line,
        format!("DONE|{gid}|1|{}", tmp.join("blob.bin").display()),
        "complete argv"
    );
    // Event order: bt-complete (download finished) precedes complete
    // (seeding teardown FINISHED).
    let all = std::fs::read_to_string(&log).unwrap_or_else(|e| panic!("{e}"));
    let bt_pos = all.find(&bt_line).unwrap_or_else(|| panic!("bt line"));
    let c_pos = all.find(&c_line).unwrap_or_else(|| panic!("c line"));
    assert!(
        bt_pos < c_pos,
        "bt-complete must fire before complete (aria2 event order)"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Failure isolation: neither a missing command nor a nonzero exit may
/// affect task state — the task stays Active (the fake tracker surface
/// never finishes it) and the engine keeps running.
#[tokio::test]
async fn hook_failure_does_not_affect_task_state() {
    // Missing command (spawn failure; reference perror/_exit semantics,
    // log only).
    isolation_case("/nonexistent/bh-hook-xyz-does-not-exist").await;
    // Nonzero exit (exit 3).
    let tmp = temp_dir("iso-script");
    let log = tmp.join("hook.log");
    let script = write_hook_script("iso-body", "", &log, Some("exit 3"));
    isolation_case(&script).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

async fn isolation_case(hook_command: &str) {
    let tmp = temp_dir("iso");
    let (handle, join) = SessionActor::spawn();
    let content = test_content();
    let (torrent, _ih) = build_v1_torrent(&content, "http://127.0.0.1:9/announce");
    let gid = gid_of(
        handle
            .call(SessionCommand::AddTorrent {
                torrent,
                options: BTreeMap::from([
                    ("dir".to_string(), tmp.display().to_string()),
                    ("on-download-start".to_string(), hook_command.to_string()),
                ]),
                position: None,
            })
            .await,
    );
    // After the hook failure the task is still running (Active; the
    // tellActive surface is unaffected by hook failures).
    tokio::time::sleep(Duration::from_millis(800)).await;
    let reply = handle
        .call(SessionCommand::TellActive { keys: vec![] })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match reply {
        CommandReply::StatusList(views) => {
            assert!(
                views
                    .iter()
                    .any(|v| v.gid == gid && v.status == taiji_core::session::StatusKind::Active),
                "task must stay active despite hook failure, got {views:?}"
            );
        }
        other => panic!("expected StatusList, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    let _ = std::fs::remove_dir_all(&tmp);
}
