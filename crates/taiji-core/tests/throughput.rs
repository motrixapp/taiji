//! Throughput load vehicle: loopback saturation (multiple seeders + one
//! leecher) measuring the download stack's **stack ceiling** end to end
//! (wire -> dispatch -> pipeline buffers -> verify/write pool).
//!
//! # Measurement discipline
//!
//! The numbers produced here are the **loopback stack ceiling** (steady
//! throughput with effectively unlimited local supply), not real swarm
//! speed (real swarms are bounded by peer supply / RTT / loss). Do not
//! mix the two.
//!
//! # Interpretation regimes (explains the two seeder-count readings)
//!
//! - **Narrow supply (4 seeders)**: aggregate in-flight demand ≈ the
//!   write-cache capacity, zero eviction — the reading is the download
//!   stack's end-to-end ceiling.
//! - **Wide supply (32+ seeders)**: aggregate in-flight demand (peers x
//!   adaptive request window) far exceeds the 16MiB write cache ->
//!   eviction churn; even with the cache enlarged until eviction is
//!   zero, the reading stays pinned — the bottleneck is **demand-side
//!   dispatch pacing** (engine dispatch / request window), not the
//!   storage segment. Do not quote this regime's numbers as a
//!   storage/verify ceiling.
//!
//! # Reproduction (release required — debug-mode hashing is an order of
//! magnitude slower and numbers are meaningless)
//!
//! ```sh
//! # Stack ceiling (default 1GiB / 32 seeders / 256KiB pieces)
//! cargo test -p taiji-core --release --test throughput \
//! -- --ignored --nocapture loopback_saturation
//! # Stack-ceiling regime (4 seeders: aggregate demand ≈ cache, zero
//! eviction)
//! BH_P84_SEEDERS=4 cargo test -p taiji-core --release \
//! --test throughput -- --ignored --nocapture loopback_saturation
//! # Pooling comparison: worker-count sweep
//! BH_VERIFY_WORKERS=1 cargo test -p taiji-core --release \
//! --test throughput -- --ignored --nocapture loopback_saturation
//! BH_VERIFY_WORKERS=2 cargo test ...
//! # Single-machine hard ceilings (hash/disk, for attribution)
//! cargo test -p taiji-core --release --test throughput \
//! -- --ignored --nocapture stack_ceilings
//! ```
//!
//! Environment variables: `BH_P84_BYTES` (total bytes, default 1GiB),
//! `BH_P84_SEEDERS` (seeder count, default 32), `BH_P84_PIECE` (piece
//! length, default 256KiB), `BH_VERIFY_WORKERS` (verify worker count,
//! default min(cores, 4)), `BH_WR_CACHE_BYTES` (write-cache bytes,
//! default 16MiB).

use std::sync::Arc;
use std::time::{Duration, Instant};

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_core::session::metrics::SessionMetrics;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn env_or(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(s) => s.trim().parse().ok().filter(|&n| n > 0).unwrap_or(default),
        Err(_) => default,
    }
}

fn make_content(len: u64) -> Arc<Vec<u8>> {
    let mut v = Vec::with_capacity(len as usize);
    let mut state = 0x9E3779B97F4A7C15u64;
    while v.len() < len as usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        v.extend_from_slice(&state.to_be_bytes());
    }
    v.truncate(len as usize);
    Arc::new(v)
}

/// Steady seeder: handshake + full bitfield + unchoke + request ->
/// piece; connections persist until the peer disconnects (no churn —
/// constant supply; measures the stack, not connection management).
async fn spawn_seeder(listener: tokio::net::TcpListener, piece_len: u32, content: Arc<Vec<u8>>) {
    let pieces = content.len().div_ceil(piece_len as usize);
    let bitfield_len = pieces.div_ceil(8);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let content = Arc::clone(&content);
            tokio::spawn(async move {
                let mut hs = [0u8; 68];
                if sock.read_exact(&mut hs).await.is_err() {
                    return;
                }
                let mut resp = [0u8; 68];
                resp[0] = 19;
                resp[1..20].copy_from_slice(b"BitTorrent protocol");
                resp[27] = 0x04; // fast
                resp[28..48].copy_from_slice(&[7u8; 20]);
                resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
                if sock.write_all(&resp).await.is_err() {
                    return;
                }
                let mut bf = vec![0u8; 4 + 1 + bitfield_len];
                bf[0..4].copy_from_slice(&((1 + bitfield_len) as u32).to_be_bytes());
                bf[4] = 5;
                for b in bf.iter_mut().skip(5) {
                    *b = 0xFF;
                }
                if sock.write_all(&bf).await.is_err() {
                    return;
                }
                let _ = sock.write_all(&[0, 0, 0, 1, 1]).await; // unchoke
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
                    if body[0] != 6 {
                        continue; // only answer requests (saturated supply, no other protocol surface)
                    }
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * piece_len as usize + begin as usize;
                    let end = (offset + length as usize).min(content.len());
                    if offset >= end || offset >= content.len() {
                        break;
                    }
                    let block = content[offset..end].to_vec();
                    let mut frame = Vec::with_capacity(9 + block.len());
                    frame.extend_from_slice(&((9 + block.len()) as u32).to_be_bytes());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(&block);
                    if sock.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// Fake tracker: answers compact peers = all seeder addresses.
async fn fake_tracker(seeder_addrs: Vec<std::net::SocketAddr>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let mut peers = Vec::new();
        for a in &seeder_addrs {
            let std::net::IpAddr::V4(v4) = a.ip() else {
                panic!("IPv4 expected");
            };
            peers.extend_from_slice(&v4.octets());
            peers.extend_from_slice(&a.port().to_be_bytes());
        }
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let peers = peers.clone();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut chunk = [0u8; 512];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&chunk[..n]),
                    }
                }
                let mut raw = Vec::new();
                raw.extend_from_slice(b"d8:intervali120e5:peers");
                raw.extend_from_slice(peers.len().to_string().as_bytes());
                raw.push(b':');
                raw.extend_from_slice(&peers);
                raw.push(b'e');
                let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&raw).await;
            });
        }
    });
    addr
}

/// The main loopback saturation load body.
#[ignore = "load test: run manually in release mode (commands in the file header); not run by the gate"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn loopback_saturation_stack_ceiling() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let total_bytes = env_or("BH_P84_BYTES", 1024 * 1024 * 1024);
    let seeders = env_or("BH_P84_SEEDERS", 32) as usize;
    let piece_len = env_or("BH_P84_PIECE", 256 * 1024) as u32;
    eprintln!(
        "loopback saturation: total={}MiB seeders={seeders} piece={piece_len} \
         workers=BH_VERIFY_WORKERS({})",
        total_bytes / 1024 / 1024,
        std::env::var("BH_VERIFY_WORKERS").unwrap_or_else(|_| "auto".into()),
    );

    let content = make_content(total_bytes);
    let mut expected = Vec::new();
    for c in content.chunks(piece_len as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }
    let tmp = std::env::temp_dir().join(format!(
        "taiji-p84-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("mkdir: {e}"));
    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = Layout::plan_v1_padded(&entries, piece_len).unwrap_or_else(|e| panic!("{e}"));

    let mut addrs = Vec::with_capacity(seeders);
    for _ in 0..seeders {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        addrs.push(addr);
        spawn_seeder(listener, piece_len, Arc::clone(&content)).await;
    }
    let tracker_addr = fake_tracker(addrs).await;

    let metrics = Arc::new(SessionMetrics::new());
    let root = tokio_util::sync::CancellationToken::new();
    let face = FaceConfig {
        kind: FaceKind::V1,
        info_hash: [7u8; 20],
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..expected.len() as u64)
            .map(|k| k * u64::from(piece_len))
            .collect(),
        piece_bytes: (0..expected.len() as u64)
            .map(|k| (content.len() as u64 - k * u64::from(piece_len)).min(u64::from(piece_len)))
            .collect(),
        expected,
        plan_file_lengths: vec![content.len() as u64],
        progress_file_lens: vec![content.len() as u64],
        cross: Vec::new(),
        hash_files: None,
    };
    let cfg = EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: format!("http://{tracker_addr}/announce"),
        listen_port: 0,
        piece_len,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![face],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: Some(Arc::clone(&metrics)),
        webseeds: Vec::new(),
    };
    let engine = DownloadEngine::spawn(cfg, &root);

    // Sampler: records verified bytes at 250ms granularity (16KiB block
    // count x 16384, scaled against the total at the end).
    let (sample_tx, sample_rx) = std::sync::mpsc::channel::<(Duration, u64)>();
    let sampler_metrics = Arc::clone(&metrics);
    let sampler = tokio::spawn(async move {
        let start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let blocks = sampler_metrics.snapshot().blocks_verified_total;
            if sample_tx.send((start.elapsed(), blocks)).is_err() {
                break;
            }
        }
    });

    let t0 = Instant::now();
    let end = tokio::time::timeout(Duration::from_secs(1800), engine).await;
    let elapsed = t0.elapsed();
    root.cancel();
    sampler.abort();
    let end = match end {
        Ok(join) => join.unwrap_or_else(|e| panic!("join: {e}")),
        Err(_) => panic!("engine timed out (supply or stack stalled)"),
    };
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // Verify the on-disk content (performance numbers must rest on
    // correctness).
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got.len(), content.len(), "on-disk length matches");
    assert_eq!(
        &got[..],
        &content[..],
        "downloaded content must match the source"
    );
    let _ = std::fs::remove_dir_all(&tmp);

    // Report: calibration (blocks x 16384 -> actual bytes) + the
    // steady-state window.
    let samples: Vec<(Duration, u64)> = sample_rx.into_iter().collect();
    let final_blocks = samples.last().map(|(_, b)| *b).unwrap_or(0);
    let raw_final = final_blocks * 16384;
    let scale = if raw_final > 0 {
        content.len() as f64 / raw_final as f64
    } else {
        1.0
    };
    let mut win: Vec<f64> = Vec::new();
    let mut prev: Option<(Duration, u64)> = None;
    for s in &samples {
        if let Some((pt, pb)) = prev {
            let dt = (s.0 - pt).as_secs_f64();
            if dt > 0.0 {
                let mibs = (s.1 - pb) as f64 * 16384.0 * scale / dt / 1024.0 / 1024.0;
                win.push(mibs);
            }
        }
        prev = Some(*s);
    }
    // Steady state = median after trimming 20% off both ends (drops the
    // warm-up and tail segments).
    win.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let trim = win.len() / 5;
    let steady: &[f64] = if win.len() >= 5 {
        &win[trim..win.len() - trim]
    } else {
        &win[..]
    };
    let median = if steady.is_empty() {
        0.0
    } else {
        steady[steady.len() / 2]
    };
    let peak = win.iter().cloned().fold(0.0, f64::max);
    let overall = content.len() as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
    eprintln!();
    eprintln!("================ loopback stack ceiling ================");
    eprintln!("total             : {} MiB", content.len() / 1024 / 1024);
    eprintln!("total elapsed     : {elapsed:.2?}");
    eprintln!("overall mean      : {overall:.1} MiB/s");
    eprintln!("steady median(80%): {median:.1} MiB/s");
    eprintln!("peak window       : {peak:.1} MiB/s");
    eprintln!("target            : >= 100.0 MiB/s (6400 x 16KiB blocks/s)");
    eprintln!("========================================================");
    // Observation vehicle: per-block three-stage histogram summary
    // (p50/p90/p99/mean/count) — the source for decomposing the
    // download stack (buffer/verify/write shares).
    if let Some(summary) = metrics.block_stage_log_summary() {
        eprintln!("block_stage: {summary}");
    }
    // Observation vehicle: write calls issued per block (the acceptance
    // "write syscall count per block" reading — with a single-file
    // layout the call count equals the syscall count).
    let total_blocks = final_blocks.max(1);
    eprintln!(
        "store_write_calls: {} total, {:.3}/block",
        metrics.store_write_calls(),
        metrics.store_write_calls() as f64 / total_blocks as f64
    );
}

/// Single-machine hard ceilings (attribution baseline): SHA-1 hashing
/// throughput (1 and 4 threads) + sequential disk write throughput
/// (page-cache writeback, the same write path as the engine). Also a
/// manual release-mode run.
#[ignore = "load test: run manually in release mode (commands in the file header); not run by the gate"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn stack_ceilings_hash_and_disk() {
    const MIB: usize = 1024 * 1024;
    let buf = Arc::new(make_content(64 * MIB as u64));

    // Hash ceiling: SHA-1 accumulated over 256KiB chunks.
    let hash_once = |buf: &[u8]| {
        let mut h = Sha1::new();
        for chunk in buf.chunks(256 * 1024) {
            h.update(chunk);
        }
        h.finalize()
    };
    hash_once(&buf); // warm-up
    let t = Instant::now();
    hash_once(&buf);
    let one = buf.len() as f64 / t.elapsed().as_secs_f64() / MIB as f64;
    let b4 = Arc::clone(&buf);
    let t = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..4 {
            let b = Arc::clone(&b4);
            s.spawn(move || hash_once(&b));
        }
    });
    // 4 threads each hash the full 64MiB -> aggregate throughput =
    // 4 x total / wall clock.
    let four = (4 * buf.len()) as f64 / t.elapsed().as_secs_f64() / MIB as f64;

    // Disk ceiling: FileDiskWriter sequential positional writes (4MiB
    // blocks), /tmp (APFS).
    let tmp = std::env::temp_dir().join(format!("taiji-p84-disk-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));
    let path = tmp.join("disk.bin");
    let write_once = |path: &std::path::Path| {
        let mut w: Box<dyn taiji_store::disk::DiskWriter> =
            Box::new(taiji_store::disk::FileDiskWriter::new());
        w.create(path).unwrap_or_else(|e| panic!("{e}"));
        for i in 0..(128 * MIB / (4 * MIB)) {
            w.write_at((i * 4 * MIB) as u64, &buf[0..4 * MIB])
                .unwrap_or_else(|e| panic!("{e}"));
        }
    };
    write_once(&path); // warm-up
    let t = Instant::now();
    write_once(&path);
    let disk = 128.0 * MIB as f64 / t.elapsed().as_secs_f64() / MIB as f64;
    let _ = std::fs::remove_dir_all(&tmp);

    eprintln!();
    eprintln!("================ single-machine hard ceilings ==================");
    eprintln!("SHA-1 single thread    : {one:.0} MiB/s");
    eprintln!("SHA-1 x4 threads       : {four:.0} MiB/s");
    eprintln!("sequential write(/tmp) : {disk:.0} MiB/s (page-cache semantics)");
    eprintln!("========================================================");
}
