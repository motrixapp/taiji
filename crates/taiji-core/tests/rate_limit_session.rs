//! Acceptance: SessionActor -> EngineConfig::limiter -> Throttled
//! streams, the full chain end to end. Chain = fake tracker + mini-seeder +
//! a real SessionActor command surface:
//!
//! 1. `--max-overall-download-limit` (session global option) throttling
//! engages — the download completes and the rate stays <= limit x
//! tolerance;
//! 2. per-task `max-download-limit` (addTorrent options, a K-suffix
//! literal) throttling engages — proves K/M parsing (matching aria2
//! getRealSize, Util.cc) plus the per-task bucket in the chain.
//!
//! Rate observation = time to file completion (the honest observable
//! without a query seam: the completion duration must be >= payload /
//! limit).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use taiji_core::session::{
    CommandReply, GlobalOptions, SessionActor, SessionCommand, SessionOptions,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-session-rate-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// Builds a single-file v1 .torrent (announce +
/// info{name,length,piece length,pieces}); returns (bytes, infohash).
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
        // Embeds the dict value directly (Metainfo parsing requires info
        // to be a dict; encoding is deterministic => byte-identical to
        // the separately encoded info_bytes, keeping the infohash check
        // valid).
        (b"info".to_vec(), info),
    ]);
    (
        bencode::encode(&top).unwrap_or_else(|e| panic!("{e}")),
        infohash,
    )
}

/// Fake tracker: answers compact peers = the seeder address (engine_loop
/// shape).
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

/// Mini-seeder: interested -> unchoke, request -> piece (engine_loop
/// shape).
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

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!("bh-p37s-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// Time for a single file to download to completion (full session chain;
/// polls the dest file).
async fn download_and_measure(
    tag: &str,
    global_limit_bps: u64,
    task_options: BTreeMap<String, String>,
    limit_bps: u64,
) -> (Duration, Vec<u8>, std::path::PathBuf) {
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
    // The seeder handshake assertion uses the real infohash.
    spawn_mini_seeder(seeder_listener, content.clone(), infohash).await;

    let tmp = temp_dir(tag);
    let options = SessionOptions {
        global: GlobalOptions {
            max_overall_download_limit: global_limit_bps,
            ..GlobalOptions::default()
        },
    };
    let (handle, join) = SessionActor::spawn_with(options);

    let mut opts: BTreeMap<String, String> =
        BTreeMap::from([("dir".to_string(), tmp.display().to_string())]);
    opts.extend(task_options);
    let reply = handle
        .call(SessionCommand::AddTorrent {
            torrent,
            options: opts,
            position: None,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let gid = match reply {
        CommandReply::Gid(g) => g,
        other => panic!("addTorrent failed: {other:?}"),
    };

    // Poll for content equality (allocation creates the full-length
    // sparse file up front — length is not a completion signal; content
    // comparison is the completion observable without a query seam).
    let started = Instant::now();
    let deadline = started + Duration::from_secs(30);
    let got = loop {
        if Instant::now() > deadline {
            panic!("download did not complete in time (starved under limit?)");
        }
        if let Ok(bytes) = std::fs::read(tmp.join("blob.bin"))
            && bytes == content
        {
            break bytes;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let elapsed = started.elapsed();

    // Cleanup: forceRemove (aborts the seeding engine) + shutdown.
    // (The gid parameter goes through expandUnique prefix-resolution
    // semantics -> the command surface receives the raw string.)
    let _ = handle
        .call(SessionCommand::ForceRemove {
            gid: gid.to_string(),
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    // Rate assertion: completion duration >= payload/limit x 0.7
    // (protocol frames also charge the bucket, only increasing;
    // scheduling/announce/dialing offsets only inflate elapsed — the
    // lower bound is safe).
    let theoretical = content.len() as f64 / limit_bps as f64;
    assert!(
        elapsed.as_secs_f64() >= theoretical * 0.7,
        "rate exceeded limit: {elapsed:?} < theoretical {theoretical}s"
    );
    (elapsed, got, tmp)
}

/// The session-global `--max-overall-download-limit` (8KiB/s) engages end
/// to end.
#[tokio::test]
async fn session_global_overall_download_limit_throttles_e2e() {
    let content = test_content();
    let (elapsed, got, tmp) =
        download_and_measure("global", 8 * 1024, BTreeMap::new(), 8 * 1024).await;
    assert_eq!(got, content, "downloaded content must match the source");
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = elapsed; // the assertion already happened in the helper (a semantic anchor only)
}

/// The per-task `max-download-limit` = "16K" (K-suffix literal) engages
/// end to end.
#[tokio::test]
async fn session_per_task_download_limit_k_suffix_throttles_e2e() {
    let content = test_content();
    let opts = BTreeMap::from([("max-download-limit".to_string(), "16K".to_string())]);
    let (_elapsed, got, tmp) = download_and_measure("task", 0, opts, 16 * 1024).await;
    assert_eq!(got, content, "downloaded content must match the source");
    let _ = std::fs::remove_dir_all(&tmp);
}
