//! Acceptance: duplex reciprocation integration — the engine exchanges
//! data with two complementary peers at the same time while downloading.
//!
//! Topology: S holds only piece 0 (seeder); L holds only piece 1
//! (leecher, expressing interested to the engine). The engine needs both
//! pieces => it must fetch piece 0 from S and piece 1 from L; L needs
//! piece 0 => it must wait for the engine's leecher choking round to
//! unchoke it before fetching piece 0 from the engine (PartialFaceSource
//! only serves verified pieces). An end-to-end proof of bidirectional
//! data flow + tit-for-tat unchoke wiring:
//!
//! - engine -> L: piece 0 bytes (the upload serving surface + the choke
//! round's unchoke landing);
//! - L -> engine: piece 1 bytes (the download surface via ad-aware
//! dispatch);
//! - completion criterion = EngineEnd::Completed + both directions'
//! bytes match their sources.
//!
//! Note: the peers are driven by the test over the raw wire protocol
//! (the same protocol obligation surface); inter-process reciprocity
//! between two engines on a real swarm is covered by a real-swarm
//! regression script.

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: usize = 16384;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-duplex-recip-";
    P.iter().cycle().take(2 * PIECE_LEN).copied().collect()
}

/// Read one wire frame; EOF/timeout = None.
async fn read_msg<S>(sock: &mut S) -> Option<(u8, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(Duration::from_millis(500), sock.read_exact(&mut len_buf)).await {
        Err(_) | Ok(Err(_)) => return None,
        Ok(Ok(_)) => {}
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Some((0, Vec::new())); // keepalive
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_millis(500), sock.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;
    Some((body[0], body[1..].to_vec()))
}

fn piece_frame(index: u32, begin: u32, block: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(13 + block.len());
    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
    frame.push(7u8);
    frame.extend_from_slice(&index.to_be_bytes());
    frame.extend_from_slice(&begin.to_be_bytes());
    frame.extend_from_slice(block);
    frame
}

/// Fake tracker: one announce answered with the [seeder, leecher] address
/// pair.
async fn fake_tracker(
    seeder: std::net::SocketAddr,
    leecher: std::net::SocketAddr,
) -> std::net::SocketAddr {
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
        let mut peers = Vec::new();
        for a in [seeder, leecher] {
            let std::net::IpAddr::V4(v4) = a.ip() else {
                panic!("expects IPv4");
            };
            peers.extend_from_slice(&v4.octets());
            peers.extend_from_slice(&a.port().to_be_bytes());
        }
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

#[tokio::test]
async fn duplex_reciprocation_bidirectional_data_flow() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .try_init();
    let content = test_content();
    let tmp = std::env::temp_dir().join(format!(
        "taiji-duplex-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout =
        Layout::plan_v1_padded(&entries, PIECE_LEN as u32).unwrap_or_else(|e| panic!("{e}"));
    let mut roots = Vec::new();
    for c in content.chunks(PIECE_LEN) {
        roots.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let piece_count = roots.len();

    // ---- Peer S (seeder: holds only piece 0; advertises 0b1000_0000,
    // serves piece-0 requests) ----
    let s_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let s_addr = s_listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let s_content = content.clone();
    tokio::spawn(async move {
        let (mut sock, _) = s_listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[27] = 0x04; // fast ext (reject surface)
        resp[28..48].copy_from_slice(&hs[28..48]); // echo the info_hash
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // bitfield: only piece 0.
        sock.write_all(&[0, 0, 0, 2, 5, 0b1000_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Reciprocity economics: unchoke (the dispatcher sends zero
        // requests to peers that choke us — aria2 fillPiece direct
        // translation; supply peers must let requests through).
        sock.write_all(&[0, 0, 0, 1, 1])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        loop {
            let Some((id, body)) = read_msg(&mut sock).await else {
                continue;
            };
            if id == 6 && body.len() == 12 {
                let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let begin = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                let length = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
                if index == 0 {
                    let off = begin as usize;
                    let block = &s_content[off..off + length as usize];
                    sock.write_all(&piece_frame(0, begin, block))
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
            }
        }
    });

    // ---- Peer L (leecher: holds only piece 1; expresses interested to
    // the engine; fetches piece 0 after the engine unchokes it — the
    // engine-side proof of bidirectional reciprocation) ----
    let l_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let l_addr = l_listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let l_content = content.clone();
    let l_task = tokio::spawn(async move {
        let (mut sock, _) = l_listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[27] = 0x04; // fast ext
        resp[28..48].copy_from_slice(&hs[28..48]); // echo the info_hash
        resp[48..68].copy_from_slice(b"LEECHERLEECHERLEECH0");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // bitfield: only piece 1.
        sock.write_all(&[0, 0, 0, 2, 5, 0b0100_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Express interested to the engine (input to the choking round).
        sock.write_all(&[0, 0, 0, 1, 2])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Reciprocity economics: unchoke the engine (the engine's request
        // side sends zero requests while choked; L remains one of the
        // engine's piece suppliers).
        sock.write_all(&[0, 0, 0, 1, 1])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Reciprocation-window design: L deliberately delays serving
        // piece 1 (> the 10s choke-round interval), so while waiting for
        // piece 1 the engine must cross a choke round -> it unchokes the
        // interested L -> L can then fetch piece 0 (if L delivered
        // immediately the engine would finish in seconds, before the
        // round ever runs).
        let l_start = tokio::time::Instant::now();
        let serve_delay = Duration::from_secs(11);
        let mut pending_serves: Vec<(u32, u32, u32)> = Vec::new();
        let mut served_all_pending = false;

        let mut got_unchoke = false;
        let mut piece0: Vec<u8> = vec![0u8; PIECE_LEN];
        let mut piece0_done = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        while tokio::time::Instant::now() < deadline {
            let past_delay = tokio::time::Instant::now().duration_since(l_start) >= serve_delay;
            // Delay window over: catch up on the queued piece-1 requests
            // (once).
            if past_delay && !served_all_pending {
                for (index, begin, length) in &pending_serves {
                    let off = PIECE_LEN + *begin as usize;
                    let block = &l_content[off..off + *length as usize];
                    sock.write_all(&piece_frame(*index, *begin, block))
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                pending_serves.clear();
                served_all_pending = true;
            }
            // Periodically re-request piece 0 (rejected until the
            // engine's verification settles).
            if got_unchoke && !piece0_done {
                let mut req = Vec::new();
                req.extend_from_slice(&13u32.to_be_bytes());
                req.push(6u8);
                req.extend_from_slice(&0u32.to_be_bytes());
                req.extend_from_slice(&0u32.to_be_bytes());
                req.extend_from_slice(&(PIECE_LEN as u32).to_be_bytes());
                sock.write_all(&req).await.unwrap_or_else(|e| panic!("{e}"));
            }
            let Some((id, body)) = read_msg(&mut sock).await else {
                if piece0_done && got_unchoke && served_all_pending {
                    break;
                }
                // Read timeout != EOF: keep polling (exit conditions at
                // the loop bottom and in the branch above).
                continue;
            };
            match id {
                // The engine's leecher choking round unchoke (the wiring
                // evidence).
                1 => got_unchoke = true,
                6 => {
                    // The engine's piece-1 request: queued during the
                    // delay window, served directly afterwards.
                    if body.len() == 12 {
                        let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        let begin = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                        let length = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
                        if index == 1 {
                            let req = (index, begin, length);
                            if past_delay {
                                let off = PIECE_LEN + begin as usize;
                                let block = &l_content[off..off + length as usize];
                                sock.write_all(&piece_frame(index, begin, block))
                                    .await
                                    .unwrap_or_else(|e| panic!("{e}"));
                            } else {
                                if !pending_serves.contains(&req) {
                                    pending_serves.push(req);
                                }
                            }
                        }
                    }
                }
                7 if body.len() >= 8 => {
                    // piece: piece 0 (the engine's upload serving surface)
                    // or an unrelated piece-1 frame.
                    let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let begin = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                    if index == 0 {
                        let block = &body[8..];
                        piece0[begin as usize..begin as usize + block.len()].copy_from_slice(block);
                        if begin as usize + block.len() >= PIECE_LEN {
                            piece0_done = true;
                        }
                    }
                }
                _ => {}
            }
            if piece0_done && got_unchoke && served_all_pending {
                break;
            }
        }
        assert!(
            got_unchoke,
            "the engine must unchoke an interested peer in the choke round"
        );
        assert!(
            piece0_done,
            "the engine must serve the upload request for the verified piece 0"
        );
        assert_eq!(
            piece0,
            l_content[..PIECE_LEN],
            "the piece 0 the engine uploaded must match the source"
        );
    });

    let tracker_addr = fake_tracker(s_addr, l_addr).await;

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: format!("http://{tracker_addr}/announce"),
        listen_port: 0,
        piece_len: PIECE_LEN as u32,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![FaceConfig {
            kind: FaceKind::V1,
            info_hash: [7u8; 20],
            reserved: Reserved::aria2_default(),
            addressing: Addressing::Flat,
            piece_goffs: (0..piece_count as u64)
                .map(|k| k * PIECE_LEN as u64)
                .collect(),
            piece_bytes: (0..piece_count as u64)
                .map(|k| (content.len() as u64 - k * PIECE_LEN as u64).min(PIECE_LEN as u64))
                .collect(),
            expected: roots,
            plan_file_lengths: vec![content.len() as u64],
            progress_file_lens: vec![content.len() as u64],
            cross: Vec::new(),
            hash_files: None,
        }],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, content, "downloaded content must match the source");
    l_task.await.unwrap_or_else(|e| panic!("{e}"));
    let _ = std::fs::remove_dir_all(&tmp);
}
