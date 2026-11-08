//! Acceptance: BEP 16 super-seeding duplex end to end + BEP 21
//! upload_only advertisement.
//!
//! Topology (all in-process, loopback ports; port discipline per the
//! scheduler contract):
//! - A = DownloadEngine (4-piece torrent, `seed.super_seeding = true`,
//!   resident seeding on completion): first downloads all pieces from C
//!   -> enters the seeding state (BEP 21 upload_only broadcast + BEP 16
//!   super-seed bookkeeping mounted, engine.rs `enter_seeding_state`);
//! - C = mini-seeder: serves all pieces (the download-phase supply
//!   source);
//! - B = super-seed consumer (dials into A's listen port once A seeds;
//!   the port is captured from the fake tracker's announce).
//!
//! End-to-end assertions (BEP 16 text semantics + libtorrent anchors):
//! 1. after registering, B receives **no bitfield** (bt_peer_connection.cpp
//!    "pretend to not have any piece and don't send a bitfield"); instead
//!    bootstrap HAVEs (at most two pieces);
//! 2. the ext handshake B receives carries `upload_only: 1` (BEP 21; the
//!    seeding-state-transition broadcast = engine.rs registration
//!    SetUploadOnly);
//! 3. B requests the assigned piece -> A serves it (piece frame);
//!    requesting a **non-assigned** piece -> reject (the
//!    peer_connection.cpp serving gate);
//! 4. B reports completion (HAVE of the assigned piece) -> A sends a new
//!    HAVE (a different piece) — "only send a new piece after the peer
//!    completes, and only pieces not yet propagated" (torrent.cpp
//!    completion rotation, peer_connection.cpp).

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, FaceConfig, FaceKind};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: usize = 16384;
const PIECES: usize = 4;
const INFO_HASH: [u8; 20] = [7u8; 20];

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-superseed-71-";
    P.iter().cycle().take(PIECES * PIECE_LEN).copied().collect()
}

/// Read one wire frame; timeout = None (same for EOF).
async fn read_msg<S>(sock: &mut S) -> Option<(u8, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(Duration::from_millis(1500), sock.read_exact(&mut len_buf)).await {
        Err(_) | Ok(Err(_)) => return None,
        Ok(Ok(_)) => {}
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Some((0, Vec::new())); // keepalive
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_millis(1500), sock.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;
    Some((body[0], body[1..].to_vec()))
}

/// Mini-seeder: serves all piece requests; signals once after delivering
/// every piece's bytes (the deterministic anchor for judging A complete).
async fn spawn_seeder(
    content: Vec<u8>,
    served_all: tokio::sync::mpsc::Sender<()>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[27] = 0x04; // fast ext
        resp[28..48].copy_from_slice(&hs[28..48]);
        resp[48..68].copy_from_slice(b"CANONSEEDERSEEDER000");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // bitfield: all 4 pieces (MSB order, trailing bits zero — the
        // input to the engine's ad-aware dispatch candidate set; the
        // zero-request policy requires the peer to advertise first).
        sock.write_all(&[0, 0, 0, 2, 5, 0b1111_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Reciprocity economics: unchoke (the dispatcher sends zero
        // requests to peers that choke us — aria2 fillPiece direct
        // translation; supply peers must let requests through).
        sock.write_all(&[0, 0, 0, 1, 1])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut served = 0usize;
        loop {
            let Some((id, body)) = read_msg(&mut sock).await else {
                continue;
            };
            if id == 6 && body.len() == 12 {
                let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let begin = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                let length = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
                if (index as usize) < PIECES {
                    let off = index as usize * PIECE_LEN + begin as usize;
                    let block = &content[off..off + length as usize];
                    let mut frame = Vec::with_capacity(13 + block.len());
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(block);
                    sock.write_all(&frame)
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                    served += length as usize;
                    if served >= PIECES * PIECE_LEN {
                        let _ = served_all.send(()).await;
                    }
                }
            }
        }
    });
    addr
}

/// Fake tracker: captures A's announce `port=` for the test (B's dial-in
/// anchor) and answers with C's address.
async fn fake_tracker(
    seeder: std::net::SocketAddr,
    a_port: Arc<std::sync::Mutex<Option<u16>>>,
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
        let text = String::from_utf8_lossy(&req);
        if let Some(pos) = text.find("port=") {
            let tail = &text[pos + 5..];
            let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(p) = digits.parse::<u16>() {
                *a_port.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
            }
        }
        let mut peers = Vec::new();
        let std::net::IpAddr::V4(v4) = seeder.ip() else {
            panic!("expects IPv4");
        };
        peers.extend_from_slice(&v4.octets());
        peers.extend_from_slice(&seeder.port().to_be_bytes());
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
async fn superseed_duplex_and_upload_only_advertisement() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .try_init();
    let content = test_content();
    let tmp = std::env::temp_dir().join(format!(
        "taiji-superseed-{}-{}",
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
    let roots: Vec<ExpectedPieceHash> = content
        .chunks(PIECE_LEN)
        .map(|c| ExpectedPieceHash::V1(Sha1::digest(c).into()))
        .collect();

    let (served_tx, mut served_rx) = tokio::sync::mpsc::channel::<()>(1);
    let seeder_addr = spawn_seeder(content.clone(), served_tx).await;
    let a_port: Arc<std::sync::Mutex<Option<u16>>> = Arc::new(std::sync::Mutex::new(None));
    let tracker_addr = fake_tracker(seeder_addr, Arc::clone(&a_port)).await;

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
        // Resident seeding on completion (the super-seeding surface needs
        // the engine alive).
        seed_after_complete: true,
        seed: taiji_core::seed::SeedPolicy {
            // BEP 16 master switch (default off — this test enables it).
            super_seeding: true,
            ..taiji_core::seed::SeedPolicy::default()
        },
        writer_factory: None,
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![FaceConfig {
            kind: FaceKind::V1,
            info_hash: INFO_HASH,
            reserved: Reserved::aria2_default(),
            addressing: Addressing::Flat,
            piece_goffs: (0..PIECES as u64).map(|k| k * PIECE_LEN as u64).collect(),
            piece_bytes: vec![PIECE_LEN as u64; PIECES],
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
    let _engine = DownloadEngine::spawn(cfg, &root);

    // Wait for C to deliver all pieces (A's download done) + a grace
    // period for entering the seeding state (verification/mounting is
    // async).
    tokio::time::timeout(Duration::from_secs(30), served_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("seeder never finished serving: {e}"));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let port = a_port
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .expect("tracker must have captured A's listen port");

    // ---- B dials into A (seeding-state registration -> super-seed
    // bootstrap) ----
    let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port);
    let mut sock =
        tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
            .await
            .unwrap_or_else(|e| panic!("dial A: {e}"))
            .unwrap_or_else(|e| panic!("connect: {e}"));

    // Handshake (fast + ext capability bits).
    let mut hs = [0u8; 68];
    hs[0] = 19;
    hs[1..20].copy_from_slice(b"BitTorrent protocol");
    hs[25] = 0x10; // ext (reserved[5]&0x10 — only then will A send an ext handshake)
    hs[27] = 0x04; // fast ext
    hs[28..48].copy_from_slice(&INFO_HASH);
    hs[48..68].copy_from_slice(b"XSUPERSEEDCONSUMER00");
    sock.write_all(&hs).await.unwrap_or_else(|e| panic!("{e}"));
    let mut resp = [0u8; 68];
    sock.read_exact(&mut resp)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        &resp[28..48],
        &INFO_HASH,
        "A must accept the same-info_hash handshake"
    );

    // Collect registration-window frames: assert no bitfield/have-all,
    // an ext handshake with upload_only=1, and bootstrap HAVEs.
    let mut assigned: Vec<u32> = Vec::new();
    let mut saw_bitfield = false;
    let mut saw_have_all = false;
    let mut upload_only_advertised = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && assigned.is_empty() {
        let Some((id, body)) = read_msg(&mut sock).await else {
            continue;
        };
        match id {
            5 => saw_bitfield = true,
            14 => saw_have_all = true,
            4 => {
                if body.len() == 4 {
                    assigned.push(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                }
            }
            20 => {
                // ext handshake: body[0] = ext_id (0 = handshake).
                let dict = taiji_bt::peer_wire::ExtHandshake::decode(&body[1..])
                    .unwrap_or_else(|e| panic!("ext handshake decode: {e:?}"));
                if dict.upload_only {
                    upload_only_advertised = true;
                }
            }
            _ => {}
        }
    }
    assert!(
        !assigned.is_empty(),
        "super-seed bootstrap must send HAVEs (bt_peer_connection.cpp)"
    );
    assert!(
        !saw_bitfield && !saw_have_all,
        "the super-seed seeding state must not send a full bitmap (the BEP16 \
         data-hiding pose)"
    );
    assert!(
        upload_only_advertised,
        "the seeding-state ext handshake must carry upload_only=1 (BEP21)"
    );

    // Express interested and wait for unchoke (choke round cadence
    // <=10s).
    sock.write_all(&[0, 0, 0, 1, 2])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut unchoked = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !unchoked && tokio::time::Instant::now() < deadline {
        let Some((id, _)) = read_msg(&mut sock).await else {
            continue;
        };
        if id == 1 {
            unchoked = true;
        }
    }
    assert!(
        unchoked,
        "the seeding choke round must unchoke an interested peer"
    );

    let current = assigned[assigned.len() - 1];
    // Assigned-piece request -> served.
    let mut req = Vec::new();
    req.extend_from_slice(&13u32.to_be_bytes());
    req.push(6u8);
    req.extend_from_slice(&current.to_be_bytes());
    req.extend_from_slice(&0u32.to_be_bytes());
    req.extend_from_slice(&(PIECE_LEN as u32).to_be_bytes());
    sock.write_all(&req).await.unwrap_or_else(|e| panic!("{e}"));
    let mut served_piece = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !served_piece && tokio::time::Instant::now() < deadline {
        let Some((id, body)) = read_msg(&mut sock).await else {
            continue;
        };
        if id == 7 && body.len() >= 8 {
            let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            assert_eq!(
                index, current,
                "the serving face must deliver the assigned piece"
            );
            served_piece = true;
        }
    }
    assert!(
        served_piece,
        "the assigned piece must be served (the BEP16 supply face)"
    );

    // Non-assigned-piece request -> reject (the serving gate).
    let other = match (0..PIECES as u32).find(|&i| !assigned.contains(&i)) {
        Some(i) => i,
        None => panic!("a 4-piece pool must still hold an unassigned piece"),
    };
    let mut req = Vec::new();
    req.extend_from_slice(&13u32.to_be_bytes());
    req.push(6u8);
    req.extend_from_slice(&other.to_be_bytes());
    req.extend_from_slice(&0u32.to_be_bytes());
    req.extend_from_slice(&(PIECE_LEN as u32).to_be_bytes());
    sock.write_all(&req).await.unwrap_or_else(|e| panic!("{e}"));
    let mut rejected = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !rejected && tokio::time::Instant::now() < deadline {
        let Some((id, _)) = read_msg(&mut sock).await else {
            continue;
        };
        if id == 16 {
            rejected = true; // reject request
        }
    }
    assert!(
        rejected,
        "a non-assigned-piece request must be rejected (the peer_connection.cpp serving gate)"
    );

    // Completion report (HAVE the assigned piece) -> new-piece HAVE (a
    // different piece).
    let mut have = Vec::new();
    have.extend_from_slice(&5u32.to_be_bytes());
    have.push(4u8);
    have.extend_from_slice(&current.to_be_bytes());
    sock.write_all(&have)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut next_piece: Option<u32> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while next_piece.is_none() && tokio::time::Instant::now() < deadline {
        let Some((id, body)) = read_msg(&mut sock).await else {
            continue;
        };
        if id == 4 && body.len() == 4 {
            let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            if index != current {
                next_piece = Some(index);
            }
        }
    }
    assert_ne!(
        next_piece, None,
        "a completion report must be answered with a new-piece HAVE (BEP16 completion rotation)"
    );
    root.cancel();
    let _ = std::fs::remove_dir_all(&tmp);
}
