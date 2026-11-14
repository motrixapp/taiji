//! Integration tests: seed-stop semantics end to end — seed-time stop
//! (SeedStopped vs Detached return paths), bt-stop-timeout forced stop,
//! seeding counter persistence (upload_at_startup base read-back +
//! per-session accumulation landed on disk).
//!
//! Cross-validation sources (aria2, read-only):
//! - SeedCheckCommand.cc (latch + halt), BtSetup.cc (assembly);
//! - BtStopDownloadCommand.cc (1 s tick / speed reset / timeout forced
//!   stop);
//! - RequestGroup.cc (enableSeedOnly);
//! - DefaultBtProgressInfoFile.cc (uploadLength -> uploadLengthAtStartup,
//!   read back as torrent_progress.upload_at_startup).

use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{
    DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind, TrackerWireConfig,
};
use taiji_core::seed::SeedPolicy;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use taiji_store::persist::PersistWriter;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: u32 = 16384;
const GID: &str = "8000000000000042";

fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn tmp_path(tag: &str, ext: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "taiji-seed-ops-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    dir.join(ext)
}

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-seed-ops-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

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

/// Fake tracker: accept loop; announce replies with the seeder address
/// (with `peers_empty=true` an empty peers list — the peerless swarm of
/// the stop-timeout scenario).
async fn mock_tracker(seeder_addr: std::net::SocketAddr, peers_empty: bool) -> String {
    let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "local addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                match sock.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&chunk[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let mut peers = Vec::new();
            if !peers_empty {
                let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
                    panic!("test expects IPv4 seeder addr");
                };
                peers.extend_from_slice(&v4.octets());
                peers.extend_from_slice(&seeder_addr.port().to_be_bytes());
            }
            let mut raw = Vec::new();
            raw.extend_from_slice(b"d8:intervali60e5:peers");
            raw.extend_from_slice(peers.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&raw).await;
        }
    });
    format!("http://{addr}/announce")
}

/// Mini seeder (engine_loop shape): handshake -> interested -> unchoke ->
/// request -> piece loop, until the connection closes.
async fn spawn_mini_seeder(content: Vec<u8>) -> std::net::SocketAddr {
    let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "local addr");
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut hs = [0u8; 68];
        if sock.read_exact(&mut hs).await.is_err() {
            return;
        }
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10;
        resp[27] = 0x04;
        resp[28..48].copy_from_slice(&[7u8; 20]);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        let _ = sock.write_all(&resp).await;
        // The mini seeder sends the full bitfield after its handshake
        // (BEP 3; 2 pieces = 0b1100_0000). It previously advertised
        // nothing and relied on the dispatcher's blind-pick fallback —
        // that fallback was removed with advertisement-aware dispatch
        // (cross-check libtorrent request_blocks.cpp).
        let _ = sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000]).await;
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
            if sock.read_exact(&mut body).await.is_err() {
                break;
            }
            match body[0] {
                2 => {
                    // interested -> unchoke.
                    let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
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
                    let _ = sock.write_all(&frame).await;
                }
                _ => {}
            }
        }
    });
    addr
}

/// Assembles a v1 single-face engine config (seed_after_complete = true +
/// policy injection).
async fn seed_engine_cfg(
    announce: String,
    dest: std::path::PathBuf,
    policy: SeedPolicy,
) -> EngineConfig {
    let content = test_content();
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = ok(Layout::plan_v1_padded(&entries, PIECE_LEN), "layout");
    EngineConfig {
        initial_selection: None,
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce,
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout,
        dest,
        seed_after_complete: true,
        seed: policy,
        writer_factory: None,
        // Default throughput tier (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![v1_face_config([7u8; 20], expected, content.len() as u64)],
        // Defaults for newer fields: optional crypto + DHT off + public
        // (this module's existing test-face wiring stays unchanged).
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        // Pre-existing test faces keep peer exchange off (zero change to
        // existing wire behavior).
        peer_exchange: false,
        // No ut_metadata serve face (the mini-seeder test face does not
        // need it; the magnet full-chain tests mount it via engine_config
        // defaults).
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,   // no NAT face in tests (EngineConfig::nat default)
        stats: None, // no metrics fed in tests (EngineConfig::stats default)
        webseeds: Vec::new(),
    }
}

/// Reserves a loopback TCP port (same as dht_wire; a fixed engine
/// listen_port face for the leecher to dial the seeding port).
async fn reserve_tcp_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let port = l.local_addr().unwrap_or_else(|e| panic!("{e}")).port();
    drop(l);
    port
}

/// Mini leecher: pulls for real from the engine's seeding face —
/// handshake -> interested -> wait unchoke -> request/piece loop until
/// `content.len()` payload bytes are collected. On reject (completion
/// race: the engine's face-complete flag / seeding data source attaches
/// later than the on-disk poll) it backs off and retries the same
/// coordinates.
/// Returns the piece payload bytes actually received (the real driver of
/// the ShareRatioSeedCriteria numerator).
async fn pull_all_blocks(
    port: u16,
    info_hash: [u8; 20],
    piece_count: usize,
    piece_len: u32,
    content_len: usize,
) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    // Retry loop: the whole chain restarts (the engine may close the
    // connection via the pre-completion reject face).
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the leecher did not pull the full amount within 30s \
             (the ratio numerator cannot reach the bar)"
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
        s.write_all(&hs)
            .await
            .unwrap_or_else(|e| panic!("leecher handshake send: {e}"));
        let mut resp = [0u8; 68];
        if s.read_exact(&mut resp).await.is_err() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        // interested (BEP 3 precondition for request).
        s.write_all(&[0, 0, 0, 1, 2])
            .await
            .unwrap_or_else(|e| panic!("interested: {e}"));

        let mut unchoked = false;
        let mut pulled = 0usize;
        let mut next_piece = 0usize;
        let mut next_begin = 0u32;
        let retry_sleep = Duration::from_millis(250);
        loop {
            if pulled >= content_len {
                return pulled;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("leecher pull timed out (pulled {pulled}/{content_len})");
            }
            // Not yet unchoked: only read frames, waiting for unchoke
            // (bitfield/PORT/keep-alive all skipped).
            if !unchoked {
                let mut len_buf = [0u8; 4];
                if s.read_exact(&mut len_buf).await.is_err() {
                    break; // connection lost -> retry the whole chain.
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
            // Unchoked: send the request for the current coordinates
            // first, then read frames until piece/reject.
            let index = next_piece as u32;
            let length = piece_len.min(u32::try_from(content_len - pulled).unwrap_or(piece_len));
            let mut req = Vec::with_capacity(13);
            req.extend_from_slice(&index.to_be_bytes());
            req.extend_from_slice(&next_begin.to_be_bytes());
            req.extend_from_slice(&length.to_be_bytes());
            let mut frame = Vec::with_capacity(17);
            // Frame length = id(1) + request payload(12).
            frame.extend_from_slice(&13u32.to_be_bytes());
            frame.push(6u8);
            frame.extend_from_slice(&req);
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
                7 if body.len() >= 9 => {
                    let got_index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    if u64::from(got_index) == index as u64 && body.len() >= 13 {
                        let block = body[9..].to_vec();
                        if block.len() == length as usize {
                            pulled += block.len();
                            next_begin += length;
                            if next_begin >= piece_len || pulled >= content_len {
                                next_piece += 1;
                                next_begin = 0;
                            }
                            if next_piece >= piece_count && pulled < content_len {
                                panic!(
                                    "piece coordinates exhausted before the full amount \
                                     arrived ({pulled}/{content_len})"
                                );
                            }
                        }
                    }
                }
                // reject (fast ext, id 16) / other: completion race -> back
                // off and resend.
                _ => tokio::time::sleep(retry_sleep).await,
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Seeds until seed-time is met: the engine ends by itself (no external
/// shutdown) — SeedStopped / Detached distinguished by the
/// bt-detach-seed-only flag (return-path semantics).
async fn seeds_until_seed_time(detach: bool) -> EngineEnd {
    let seeder_addr = spawn_mini_seeder(test_content()).await;
    let announce = mock_tracker(seeder_addr, false).await;
    let dest_parent = tmp_path(&format!("seed-{detach}"), "d");
    let policy = SeedPolicy {
        seed_ratio: 0.0, // ratio condition off (not mounted, per BtSetup.cc).
        seed_time: Duration::from_secs(2),
        stop_timeout: Duration::ZERO,
        detach_seed_only: detach,
        // Default for the newer field — super-seeding is irrelevant to
        // this test face, always off.
        super_seeding: false,
    };
    let cfg = seed_engine_cfg(announce, dest_parent.clone(), policy).await;
    let root = CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out (detach={detach})"));
    root.cancel();
    let end = ok(end, "join");
    // The data must really land on disk (the seeding data source is the
    // disk).
    let got = ok(std::fs::read(dest_parent.join("blob.bin")), "read back");
    assert_eq!(
        got,
        test_content(),
        "the seeding task's data must be complete"
    );
    let _ = std::fs::remove_dir_all(&dest_parent);
    end
}

/// Criterion (4): seed-time met -> seeding stops, returning SeedStopped
/// (SeedCheckCommand.cc halt semantics; its latch = the timer starts at
/// download completion).
#[tokio::test]
async fn engine_seeds_until_seed_time_then_returns_seed_stopped() {
    let end = seeds_until_seed_time(false).await;
    assert!(matches!(end, EngineEnd::SeedStopped), "got {end:?}");
}

/// Criterion: bt-detach-seed-only=true -> the same stop path returns
/// Detached (RequestGroup.cc seed-only decision + the engine's
/// return-path distinction).
#[tokio::test]
async fn engine_returns_detached_when_seed_only_flag_set() {
    let end = seeds_until_seed_time(true).await;
    assert!(matches!(end, EngineEnd::Detached), "got {end:?}");
}

/// Regression (engine face): the **ratio path end to end** — a real
/// leecher pulls the full amount from the engine's seeding face
/// (session_up bridges per-peer counters into the session total via the
/// 1 s tick); the instant uploaded >= ratio x completed holds, the engine
/// must SeedStopped by itself (the wiring criterion for the
/// ShareRatioSeedCriteria.cc numerator/denominator + the
/// SeedCheckCommand.cc halt direct translation; unit tests only cover the
/// formula, engine-level seed-time stopping is tested separately — the
/// ratio stop previously had no end-to-end guard).
#[tokio::test]
async fn engine_stops_on_seed_ratio_with_real_upload_pull() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let seeder_addr = spawn_mini_seeder(test_content()).await;
    let announce = mock_tracker(seeder_addr, false).await;
    let dest_parent = tmp_path("ratio-stop", "d");
    let policy = SeedPolicy {
        seed_ratio: 1.0, // default semantics (SPEC section 11): stop once uploaded >= completed.
        seed_time: Duration::ZERO,
        stop_timeout: Duration::ZERO,
        detach_seed_only: false,
        // Default for the newer field — always off.
        super_seeding: false,
    };
    let mut cfg = seed_engine_cfg(announce, dest_parent.clone(), policy).await;
    let engine_port = reserve_tcp_port().await;
    cfg.listen_port = engine_port;
    let content = test_content();
    let piece_count = cfg.faces[0].piece_goffs.len();
    let root = CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);

    // The leecher attaches only after the download completes (on-disk
    // content fully equal): the seeding data source attaches only once all
    // faces are complete (inbound requests during download are answered
    // with reject).
    let mut done = false;
    for _ in 0..300 {
        if std::fs::read(dest_parent.join("blob.bin"))
            .map(|got| got == content)
            .unwrap_or(false)
        {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "the engine did not complete the download within 30s");

    // The leecher pulls the full amount -> numerator = completed (ratio
    // 1.0 exactly meets the bar, the equality side).
    let leecher = tokio::spawn(pull_all_blocks(
        engine_port,
        [7u8; 20],
        piece_count,
        PIECE_LEN,
        content.len(),
    ));

    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the engine did not stop by itself after meeting the ratio \
                 (regression of the SeedCheck wiring gap)"
            )
        });
    root.cancel();
    let end = ok(end, "join");
    assert!(matches!(end, EngineEnd::SeedStopped), "got {end:?}");
    let pulled = ok(leecher.await, "leecher join");
    assert_eq!(
        pulled,
        content.len(),
        "the leecher must pull the full amount (the numerator's semantics)"
    );
    let got = ok(std::fs::read(dest_parent.join("blob.bin")), "read back");
    assert_eq!(got, content, "the seeded data must match the source");
    let _ = std::fs::remove_dir_all(&dest_parent);
}

/// Criterion: bt-stop-timeout — the swarm has no peers and the download
/// speed stays 0; past the timeout the engine force-stops
/// (BtStopDownloadCommand.cc forceHalt semantics; the 1 s tick + speed > 0
/// checkpoint-reset combination is exercised here with a constant-zero
/// speed).
#[tokio::test]
async fn engine_stops_stalled_download_on_bt_stop_timeout() {
    let announce = mock_tracker(std::net::SocketAddr::from(([127, 0, 0, 1], 1)), true).await;
    let dest_parent = tmp_path("stop-timeout", "d");
    let policy = SeedPolicy {
        seed_ratio: 0.0,
        seed_time: Duration::ZERO,
        stop_timeout: Duration::from_secs(3),
        detach_seed_only: false,
        // Default for the newer field — always off.
        super_seeding: false,
    };
    let cfg = seed_engine_cfg(announce, dest_parent.clone(), policy).await;
    let root = CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = ok(end, "join");
    match end {
        EngineEnd::Failed(msg) => {
            assert!(
                msg.contains("bt-stop-timeout"),
                "the stop-timeout stop must be identifiable: {msg}"
            );
        }
        other => panic!("expected Failed(bt-stop-timeout), got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dest_parent);
}

/// Criterion: seeding-counter persistence roundtrip — at startup the
/// engine reads back the previous session's `uploaded_total` as the
/// `upload_at_startup` base (DefaultBtProgressInfoFile.cc direct
/// translation); at shutdown the engine lands the base + session delta
/// (downloaded_total growth = piece bytes actually received; seed_time_s >=
/// the seed-time threshold; non-empty v1 bitfield).
#[tokio::test]
async fn engine_persists_progress_counters_and_restores_base() {
    // sqlite: migrations + the FK fixture parent row + the previous
    // session's base row (uploaded_total=1000, downloaded_total=500,
    // active=90, seed=30).
    let db = tmp_path("db", "sqlite3");
    let (persist, _writer) = ok(PersistWriter::spawn(db.clone()).await, "persist spawn");
    {
        let conn = ok(Connection::open(&db), "fixture conn");
        ok(
            conn.execute(
                "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind, created_at, updated_at)
                 VALUES (?1, 'fixture', 'downloading', 0, '/tmp/fixture', '{}', 'v1', 0, 0)",
                [GID],
            ),
            "fixture torrent",
        );
    }
    let base_row = taiji_store::persist::TorrentProgressRow {
        gid: GID.into(),
        piece_length: i64::from(PIECE_LEN),
        v1_bitfield: None,
        v2_file_bits: None,
        upload_at_startup: 0,
        downloaded_total: 500,
        uploaded_total: 1000,
        active_time_s: 90,
        seed_time_s: 30,
    };
    assert_eq!(
        ok(
            persist.upsert_torrent_progress(base_row).await,
            "base write"
        ),
        taiji_store::persist::PersistOutcome::Written
    );

    let seeder_addr = spawn_mini_seeder(test_content()).await;
    let announce = mock_tracker(seeder_addr, false).await;
    let dest_parent = tmp_path("persist", "d");
    let policy = SeedPolicy {
        seed_ratio: 0.0,
        seed_time: Duration::from_secs(2),
        stop_timeout: Duration::ZERO,
        detach_seed_only: false,
        // Default for the newer field — always off.
        super_seeding: false,
    };
    let cfg = seed_engine_cfg(announce, dest_parent.clone(), policy).await;
    let wire = TrackerWireConfig {
        tiers: vec![(0, cfg.announce.clone())],
        persist: Some((GID.to_string(), persist.clone())),
        guard: None,
    };
    let root = CancellationToken::new();
    let engine = DownloadEngine::spawn_with(cfg, wire, &root);
    let end = tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = ok(end, "join");
    assert!(matches!(end, EngineEnd::SeedStopped), "got {end:?}");

    // Read back the final row (the shutdown flush is guaranteed: written
    // before the engine ends).
    let row = ok(persist.load_torrent_progress(GID).await, "final load")
        .unwrap_or_else(|| panic!("progress row must exist after engine end"));
    assert_eq!(
        row.upload_at_startup, 1000,
        "the session base = the previous session's uploaded_total"
    );
    assert_eq!(
        row.uploaded_total, 1000,
        "this test engine uploaded nothing (zero delta)"
    );
    assert_eq!(
        row.downloaded_total,
        500 + 2 * i64::from(PIECE_LEN),
        "base + the piece bytes actually received in the session"
    );
    assert!(row.active_time_s > 90, "active time accumulated");
    assert!(
        row.seed_time_s >= 30 + 2,
        "seed time accumulated must be >= base + the seed-time threshold (2s), got {}",
        row.seed_time_s
    );
    assert!(
        row.v1_bitfield.is_some_and(|b| !b.is_empty()),
        "the v1 bitfield should persist with the counter row"
    );
    drop(persist);
    drop(_writer);
    let _ = std::fs::remove_dir_all(&dest_parent);
    let _ = std::fs::remove_file(&db);
}

/// The engine's in-flight announce upload reading face
/// (FaceView::session_uploaded) is refreshed by the snapshot tick — this
/// is only a compile-level guard: the TrackerWireConfig persistence
/// injection and the spawn_with frozen face stay unchanged (behavior
/// assertions live in tracker_wire.rs).
#[test]
fn seed_policy_defaults_are_frozen() {
    let p = SeedPolicy::default();
    assert_eq!(p.seed_ratio, 1.0);
    assert_eq!(p.seed_time, Duration::ZERO);
    assert_eq!(p.stop_timeout, Duration::ZERO);
    assert!(!p.detach_seed_only);
    let _ = Arc::new(());
}
