//! Null-store e2e smoke (feature-gated: `cargo test -p taiji-core
//! --features null-store`): the download-completion path running
//! against the no-IO disk baseline — a loopback seeder serves a real
//! payload, the engine verifies and "writes" every piece into
//! `NullDiskWriter` (writes discarded), and the engine must still
//! reach `EngineEnd::Completed` with the destination tree left empty.
//!
//! The wall-time number this smoke prints is the network + pipeline
//! cost with the disk decoupled (the libtorrent
//! `disabled_disk_io_constructor` benchmarking shape): whatever it
//! measures contains no payload read/write/alloc syscalls. The gate is
//! non-default — the null-store face stays out of release builds (see
//! the taiji-store `null-store` feature docs).
//!
//! Rig notes: the seeder shape is the proven store_pipeline rig
//! generalized to N pieces, plus a 50ms settling pause between the
//! handshake response and the bitfield — see the comment at the pause
//! for the observed startup-race context.

#![cfg(feature = "null-store")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{
    DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind, WriterFactory,
};
use taiji_store::disk::DiskWriter;
use taiji_store::error::StoreError;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use taiji_store::null_store::NullDiskWriter;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// 4 MiB of real content (256 pieces x 16KiB) — big enough that the
/// wall time is a meaningful throughput reading, small enough to stay
/// a smoke.
const PIECE_LEN: u32 = 16384;
const PIECE_COUNT: usize = 256;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-store-pipeline-";
    P.iter()
        .cycle()
        .take(PIECE_COUNT * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// Factory handing the engine face a NullDiskWriter (the injection
/// seam behind the same DiskWriter abstraction as the file backend).
struct NullStoreFactory;

impl WriterFactory for NullStoreFactory {
    fn build(&self, _layout: &Layout, _dest: &Path) -> Result<Box<dyn DiskWriter>, StoreError> {
        Ok(Box::new(NullDiskWriter::default()))
    }
}

/// Fake tracker (the store_pipeline shape): compact peers = the
/// seeder's address.
async fn fake_tracker(seeder_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seeder_addr = seeder_addr;
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut chunk = [0u8; 512];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    req.extend_from_slice(&chunk[..n]);
                }
                let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
                    return;
                };
                let mut peers = Vec::new();
                peers.extend_from_slice(&v4.octets());
                peers.extend_from_slice(&seeder_addr.port().to_be_bytes());
                let mut raw = Vec::new();
                raw.extend_from_slice(b"d8:intervali60e5:peers");
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

/// Loopback seeder over the full payload: handshake -> full bitfield
/// -> unchoke -> serve every requested block (the store_pipeline
/// mini-seeder generalized to N pieces). `requests` counts wire
/// requests (the liveness signal).
async fn mini_seeder(content: Vec<u8>, requests: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let content = content.clone();
            let requests = Arc::clone(&requests);
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
                // Settling pause before the bitfield: with the bitfield
                // landing in the same beat as the handshake response,
                // rig variants were observed where the engine's early
                // dispatch never fires (interested + extended handshake
                // sent, zero wire requests ever issued; deterministic
                // per test-binary layout, gone when the bitfield is
                // delayed a beat — a startup race in the engine's
                // ad/unchoke bookkeeping vs dispatch, recorded for
                // separate investigation). The pause is rig-side only.
                tokio::time::sleep(Duration::from_millis(50)).await;
                // Full bitfield (BEP 3): every piece present.
                let mut bitfield = vec![0u8; PIECE_COUNT.div_ceil(8)];
                for i in 0..PIECE_COUNT {
                    bitfield[i / 8] |= 0x80 >> (i % 8);
                }
                let mut frame = Vec::with_capacity(5 + bitfield.len());
                frame.extend(((1 + bitfield.len()) as u32).to_be_bytes());
                frame.push(5u8);
                frame.extend_from_slice(&bitfield);
                if sock.write_all(&frame).await.is_err() {
                    return;
                }
                loop {
                    let mut len_buf = [0u8; 4];
                    if sock.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len == 0 {
                        continue;
                    }
                    let mut body = vec![0u8; len];
                    if sock.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    match body[0] {
                        2 => {
                            // unchoke
                            let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                        }
                        6 => {
                            requests.fetch_add(1, Ordering::SeqCst);
                            let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                            let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                            let length =
                                u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                            let offset = index as usize * PIECE_LEN as usize + begin as usize;
                            let Some(block) = content.get(offset..offset + length as usize) else {
                                return;
                            };
                            let mut frame = Vec::with_capacity(13 + block.len());
                            frame.extend((9 + block.len() as u32).to_be_bytes());
                            frame.push(7u8);
                            frame.extend_from_slice(&index.to_be_bytes());
                            frame.extend_from_slice(&begin.to_be_bytes());
                            frame.extend_from_slice(block);
                            if sock.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    addr
}

/// Download-completion path against the null store: the engine pulls
/// the whole payload over loopback TCP, verifies every piece, and
/// completes with zero files created at the destination — the printed
/// wall time is the network + pipeline cost with the disk decoupled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn download_completes_against_null_store() {
    let content = test_content();
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }

    let tmp = std::env::temp_dir().join(format!(
        "taiji-null-store-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    let entries = vec![PlanEntry {
        path: PathBuf::from("blob.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));

    let seeder_requests = Arc::new(AtomicUsize::new(0));
    let seeder_addr = mini_seeder(content.clone(), Arc::clone(&seeder_requests)).await;
    let tracker_addr = fake_tracker(seeder_addr).await;

    let root = tokio_util::sync::CancellationToken::new();
    let face = FaceConfig {
        kind: FaceKind::V1,
        info_hash: [7u8; 20],
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..expected.len() as u64)
            .map(|k| k * u64::from(PIECE_LEN))
            .collect(),
        piece_bytes: (0..expected.len() as u64)
            .map(|k| (content.len() as u64 - k * u64::from(PIECE_LEN)).min(u64::from(PIECE_LEN)))
            .collect(),
        expected,
        plan_file_lengths: vec![content.len() as u64],
        progress_file_lens: vec![content.len() as u64],
        cross: Vec::new(),
        hash_files: None,
    };
    let cfg = EngineConfig {
        clock: Default::default(),
        rng: Default::default(),
        initial_selection: None,
        preset_progress: None,
        tracker_options: taiji_bt::tracker::TrackerOptions::default(),
        egress: None,
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: format!("http://{tracker_addr}/announce"),
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: Some(Arc::new(NullStoreFactory)),
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
        stats: None,
        webseeds: Vec::new(),
    };

    let t0 = std::time::Instant::now();
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(120), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    let elapsed = t0.elapsed();
    root.cancel();
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // Disk decoupled: nothing was created at the destination (writes
    // discarded, allocation virtual).
    let created: Vec<_> = std::fs::read_dir(&tmp)
        .unwrap_or_else(|e| panic!("{e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert!(
        created.is_empty(),
        "null store must not create files, found {created:?}"
    );

    let mib = content.len() as f64 / (1024.0 * 1024.0);
    println!(
        "null-store e2e: {:.1} MiB completed in {:.3}s = {:.2} MiB/s, {} wire requests \
         (network + pipeline only; disk decoupled)",
        mib,
        elapsed.as_secs_f64(),
        mib / elapsed.as_secs_f64(),
        seeder_requests.load(Ordering::SeqCst)
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
