//! Loopback integration test (**loopback**: every peer is a local TCP
//! socket — no external dependencies; runs without rqbit present): the
//! addTorrent fix surface for an externally complete payload, end to
//! end.
//!
//! Scenario (loopback form of the real-swarm acceptance):
//! 1. generate a payload directory (2 pieces x 16KiB of real content) +
//!    a real v1 metainfo (measured SHA-1 piece hashes);
//! 2. the taiji daemon (SessionActor + sqlite) runs `addTorrent`
//!    pointing at the **already-complete payload directory** — before
//!    the fix: status stayed active, completedLength stayed 0, the
//!    bitfield stayed zero (initial verification never ran); after the
//!    fix: an initial full verification -> `completedLength ==
//! totalLength` -> seeding per `seed_after_complete`;
//! 3. a mini-leecher (same shape as seed_ops `pull_all_blocks`:
//!    handshake -> interested -> unchoke -> real request/piece pulls)
//!    drains the full payload from the taiji seeding surface ->
//!    tellStatus `uploadLength > 0` (the upload counter growing with a
//!    peer is direct evidence of seeding).
//!
//! The forceRecheck surface is covered by the companion case in this
//! file, `force_recheck_clears_corrupt_piece_and_restores_after_repair`
//! — corrupt piece -> initial verification clears it (hole in the
//! bitmap) -> repair the disk + forceRecheck (active task: stop ->
//! verify -> back to the queue and reactivate) -> bitmap full again ->
//! completed == total.

use std::collections::BTreeMap;
use std::time::Duration;

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
const PIECE_COUNT: usize = 2;

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

/// Real single-file v1 metainfo (measured piece hashes; dict keys in
/// byte order — strict decode).
fn build_v1_torrent(content: &[u8], name: &str, announce: &str) -> Vec<u8> {
    let mut pieces = Vec::new();
    for c in content.chunks(PIECE_LEN) {
        pieces.extend_from_slice(Sha1::digest(c).as_slice());
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

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-perf01-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    ok(std::fs::create_dir_all(&d), "mkdir");
    d
}

fn temp_db(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "taiji-perf01-{tag}-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&p);
    p
}

async fn spawn_session(
    db: &std::path::Path,
    listen_port: u16,
) -> (
    std::sync::Arc<SessionHandle>,
    tokio::task::JoinHandle<()>,
    PersistHandle,
) {
    let (writer, _wjoin) = ok(PersistWriter::spawn(db.to_path_buf()).await, "spawn writer");
    let global = GlobalOptions {
        // Test surface: DHT off (no external discovery), fixed
        // listen_port (the leecher dials in; 0 = OS random — the recheck
        // scenario has no inbound peers).
        enable_dht: false,
        listen_port,
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
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

/// Polls until the predicate holds (100ms steps, `secs` budget; the
/// shared assertion seam). A `true` predicate ends the wait.
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

/// Reserve a loopback TCP port (same as seed_ops; pins the engine's
/// listen_port).
async fn reserve_tcp_port() -> u16 {
    let l = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let port = ok(l.local_addr(), "addr").port();
    drop(l);
    port
}

/// Mini-leecher (same shape as seed_ops `pull_all_blocks`): pulls for
/// real from the engine's seeding surface until `content_len` bytes
/// arrive; returns the bytes actually received.
async fn pull_all_blocks(port: u16, info_hash: [u8; 20], content_len: usize) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the leecher did not pull the full amount within 30s"
        );
        let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let mut hs = Vec::with_capacity(68);
        hs.push(19u8);
        hs.extend_from_slice(b"BitTorrent protocol");
        hs.extend_from_slice(&[0, 0, 0, 0, 0, 0x10, 0, 0x04]);
        hs.extend_from_slice(&info_hash);
        hs.extend_from_slice(b"LEECHERLEECHERLEECH1");
        if s.write_all(&hs).await.is_err() {
            continue;
        }
        let mut resp = [0u8; 68];
        if s.read_exact(&mut resp).await.is_err() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        // interested (BEP 3 precondition for requests).
        if s.write_all(&[0, 0, 0, 1, 2]).await.is_err() {
            continue;
        }
        let mut unchoked = false;
        let mut pulled = 0usize;
        let mut next_piece = 0usize;
        let mut next_begin = 0u32;
        let retry_sleep = Duration::from_millis(250);
        loop {
            if pulled >= content_len {
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
            frame.extend_from_slice(&13u32.to_be_bytes());
            frame.push(6u8);
            frame.extend_from_slice(&index.to_be_bytes());
            frame.extend_from_slice(&next_begin.to_be_bytes());
            frame.extend_from_slice(&length.to_be_bytes());
            if s.write_all(&frame).await.is_err() {
                break;
            }
            let mut len_buf = [0u8; 4];
            if tokio::time::timeout(retry_sleep * 40, s.read_exact(&mut len_buf))
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
            match body[0] {
                7 if body.len() >= 13 => {
                    let got_index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    if u64::from(got_index) == u64::from(index) {
                        let block = body[9..].to_vec();
                        if block.len() == length as usize {
                            pulled += block.len();
                            next_begin += length;
                            if next_begin as usize >= PIECE_LEN || pulled >= content_len {
                                next_piece += 1;
                                next_begin = 0;
                            }
                        }
                    }
                }
                _ => tokio::time::sleep(retry_sleep).await,
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Loopback case a: externally complete payload -> addTorrent -> initial
/// full verification (60s budget; a local 32KiB verify takes
/// milliseconds — the budget tolerates slow CI machines) ->
/// `completedLength == totalLength` -> seeding (the mini-leecher really
/// drains the full payload + `uploadLength > 0`).
#[tokio::test]
async fn complete_external_payload_verifies_then_seeds_loopback() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let content = test_content();
    let name = "perf01-loopback.bin";
    let torrent = build_v1_torrent(&content, name, "http://127.0.0.1:1/announce");
    let meta = ok(Metainfo::parse(&torrent), "parse");
    let info_hash = match meta.meta.identity.v1 {
        Some(h) => h,
        None => panic!("v1 identity missing"),
    };

    let payload_dir = temp_dir("loopback-payload");
    ok(
        std::fs::write(payload_dir.join(name), &content),
        "write payload",
    );

    let port = reserve_tcp_port().await;
    let db = temp_db("loopback");
    let (handle, join, _writer) = spawn_session(&db, port).await;

    let t0 = std::time::Instant::now();
    let gid = gid_of(
        call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: torrent.clone(),
                options: BTreeMap::from([
                    ("dir".to_string(), payload_dir.display().to_string()),
                    // Seed forever (ratio 0 = no ShareRatio condition
                    // attached).
                    ("seed-ratio".to_string(), "0".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );

    // Fixed-surface acceptance: completed == total.
    wait_for(60, "completed == totalLength", || {
        let handle = handle.clone();
        async move {
            let v = tell_status(&handle, gid).await;
            v.total_length > 0 && v.completed_length == v.total_length
        }
    })
    .await;
    let verified_secs = t0.elapsed().as_secs_f64();

    // Seeding-surface acceptance: seeder flag + the leecher really
    // drains the full payload + upload counter > 0.
    wait_for(30, "seeder flag", || {
        let handle = handle.clone();
        async move { tell_status(&handle, gid).await.seeder == Some(true) }
    })
    .await;

    let pulled = pull_all_blocks(port, info_hash, content.len()).await;
    assert_eq!(
        pulled,
        content.len(),
        "the leecher must receive the full amount from the seeding face"
    );

    wait_for(30, "uploadLength > 0", || {
        let handle = handle.clone();
        async move { tell_status(&handle, gid).await.upload_length > 0 }
    })
    .await;
    let uploaded = tell_status(&handle, gid).await.upload_length;
    println!(
        "recheck loopback: verified+seeding in {verified_secs:.2}s, \
         uploaded {uploaded} bytes to loopback leecher"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&payload_dir);
    let _ = std::fs::remove_file(&db);
}

/// Loopback case b: corrupt piece -> initial verification clears it
/// (hole in the bitmap; the task still activates and waits to
/// redownload) -> repair the disk + `forceRecheck` (active domain:
/// stop -> verify -> back to the queue and reactivate) -> the bitmap is
/// full again -> completed == total.
#[tokio::test]
async fn force_recheck_clears_corrupt_piece_and_restores_after_repair() {
    let content = test_content();
    let name = "perf01-recheck.bin";
    let torrent = build_v1_torrent(&content, name, "http://127.0.0.1:1/announce");

    // Corrupt piece 1 after writing the payload (length unchanged — the
    // payload_complete gate still hits).
    let payload_dir = temp_dir("recheck-payload");
    let mut corrupted = content.clone();
    corrupted[PIECE_LEN + 5] ^= 0xff;
    ok(
        std::fs::write(payload_dir.join(name), &corrupted),
        "write corrupted",
    );

    let db = temp_db("recheck");
    let (handle, join, writer) = spawn_session(&db, 0).await;
    let gid = gid_of(
        call(
            &handle,
            SessionCommand::AddTorrent {
                torrent,
                options: BTreeMap::from([
                    ("dir".to_string(), payload_dir.display().to_string()),
                    ("seed-ratio".to_string(), "0".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let gid_hex = gid.to_string();

    // Initial verification done: the measured bitmap keeps a hole
    // (piece 0 kept, corrupt piece 1 cleared) — direct evidence of the
    // corrupt-piece clear.
    wait_for(30, "initial recheck leaves hole in bitfield", || {
        let writer = writer.clone();
        let gid_hex = gid_hex.clone();
        async move {
            matches!(
                writer.load_torrent_progress(&gid_hex).await,
                Ok(Some(row)) if row.v1_bitfield == Some(vec![0b1000_0000])
            )
        }
    })
    .await;
    // The engine activates with the holey bitmap (numActive = 1,
    // awaiting redownload).
    wait_for(30, "task active with hole (awaiting redownload)", || {
        let handle = handle.clone();
        async move {
            matches!(
                call(&handle, SessionCommand::GetGlobalStat).await,
                Ok(CommandReply::GlobalStat(g)) if g.num_active == 1
            )
        }
    })
    .await;

    // Repair the disk + forceRecheck (active domain: stop -> verify ->
    // back to the queue and reactivate).
    ok(
        std::fs::write(payload_dir.join(name), &content),
        "repair payload",
    );
    match call(
        &handle,
        SessionCommand::ForceRecheck {
            gid: gid_hex.clone(),
        },
    )
    .await
    {
        Ok(CommandReply::Gid(g)) => assert_eq!(g, gid, "the forceRecheck reply gid"),
        other => panic!("forceRecheck must return gid, got {other:?}"),
    }

    // Bitmap restored + reactivation + completed == total.
    wait_for(30, "bitfield restored after repair", || {
        let writer = writer.clone();
        let gid_hex = gid_hex.clone();
        async move {
            matches!(
                writer.load_torrent_progress(&gid_hex).await,
                Ok(Some(row)) if row.v1_bitfield == Some(vec![0b1100_0000])
            )
        }
    })
    .await;
    wait_for(30, "completed == total after forceRecheck", || {
        let handle = handle.clone();
        async move {
            let v = tell_status(&handle, gid).await;
            v.total_length > 0 && v.completed_length == v.total_length
        }
    })
    .await;

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&payload_dir);
    let _ = std::fs::remove_file(&db);
}
