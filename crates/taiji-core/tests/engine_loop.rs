//! Acceptance: the engine loop — fake tracker + mini-seeder full-chain
//! download.
//!
//! Chain: announce (a local fake tracker answers with the seeder address)
//! -> connect -> handshake -> interested/unchoke -> request/piece ->
//! VerifiedWriter verification to disk -> EngineEnd::Completed. The
//! minimal automated proof of the "CLI can download to completion" goal
//! (the real-seeder loop runs separately against rqbit).

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-engine-loop-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// v1-only single-face config (engine_loop shape; the face = stream
/// piece space).
fn v1_face_config(
    info_hash: [u8; 20],
    expected: Vec<ExpectedPieceHash>,
    content_len: u64,
) -> FaceConfig {
    FaceConfig {
        kind: FaceKind::V1,
        info_hash,
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..expected.len() as u64)
            .map(|k| k * u64::from(PIECE_LEN))
            .collect(),
        piece_bytes: (0..expected.len() as u64)
            .map(|k| (content_len - k * u64::from(PIECE_LEN)).min(u64::from(PIECE_LEN)))
            .collect(),
        expected,
        plan_file_lengths: vec![content_len],
        progress_file_lens: vec![content_len],
        cross: Vec::new(),
        hash_files: None,
    }
}

/// Fake tracker: answers compact peers = the seeder address.
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
        let text = String::from_utf8_lossy(&req).into_owned();
        assert!(
            text.contains("info_hash="),
            "the announce must carry info_hash: {text}"
        );
        assert!(text.contains("compact=1"));
        assert!(text.contains("event=started"));
        let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
            panic!("test expects IPv4 seeder addr");
        };
        let ip = v4.octets();
        let port = seeder_addr.port().to_be_bytes();
        let mut peers = Vec::new();
        peers.extend_from_slice(&ip);
        peers.extend_from_slice(&port);
        // Hand-assembled bencode (peers is a binary byte string, no
        // string formatting).
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
async fn engine_downloads_from_local_seeder() {
    // Minimal loop: the engine downloads 2 pieces end to end and finishes
    // verified.
    let content = test_content();
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.extend_from_slice(&Sha1::digest(c));
    }
    let tmp = std::env::temp_dir().join(format!(
        "taiji-engine-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    // Expected roots/layout/pool (same parameters as the engine).
    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
    let mut roots = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        roots.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }

    // Start the seeder + tracker first (the announce is filled in once
    // the ports are known).
    // The mini-seeder needs read+write on one stream -> a hand-written
    // TCP loop (no Framed split).
    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_content = content.clone();
    tokio::spawn(async move {
        let (mut sock, _) = seeder_listener
            .accept()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(&hs[28..48], &[7u8; 20], "the engine handshake's info_hash");
        // Answer the handshake (fast + ext bits).
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10; // extended
        resp[27] = 0x04; // fast
        resp[28..48].copy_from_slice(&[7u8; 20]);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // After the handshake the fake seeder sends a full bitfield per
        // BEP 3 (MSB = piece 0, 2 pieces = 0b1100_0000). It used to send
        // no ad and rely on the dispatcher's blind-select fallback
        // (`unwrap_or(current)`); that fallback went away with ad-aware
        // dispatch (upstream anchor: libtorrent request_blocks.cpp —
        // picking only draws candidates from the peer bitfield). Real
        // clients holding data always advertise (the BEP 3 post-handshake
        // bitmap).
        sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Frame loop: read the length prefix + id + payload; interested
        // -> unchoke; request -> piece (served while choked: a test-only
        // mini-seeder).
        loop {
            let mut len_buf = [0u8; 4];
            if sock.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                continue; // keepalive
            }
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            match body[0] {
                2 => {
                    // interested -> unchoke (this mini-seeder unchokes
                    // immediately).
                    sock.write_all(&[0, 0, 0, 1, 1])
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                6 => {
                    // request(index, begin, length) -> piece.
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * PIECE_LEN as usize + begin as usize;
                    let block = seeder_content[offset..offset + length as usize].to_vec();
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
    let tracker_addr = fake_tracker(seeder_addr).await;

    // The engine.
    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: format!("http://{tracker_addr}/announce"),
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config([7u8; 20], roots, content.len() as u64)],
        // New fields at defaults: optional encryption + DHT off + public
        // (keeps this module's wired test surface behavior-unchanged).
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        // No peer exchange on this legacy test surface (wire behavior
        // unchanged).
        peer_exchange: false,
        // No ut_metadata serve surface (the mini-seeder test face does
        // not need it; the magnet full-chain test mounts one via
        // engine_config defaults).
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,   // no NAT on the test face (EngineConfig::nat default unchanged)
        stats: None, // no metrics fed on the test face (EngineConfig::stats default unchanged)
        webseeds: Vec::new(),
    };
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    // On-disk content check.
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, content, "downloaded content must match the source");
    let _ = std::fs::remove_dir_all(&tmp);
}
