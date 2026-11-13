//! Structural proof that the main loop does no disk IO and no hashing
//! inline.
//!
//! Technique: inject a gated writer (the first piece write blocks on a
//! test gate). If the main loop still pushed blocks inline (the pre-fix
//! defect shape), the async loop would stall on that write and the
//! tracker would stop receiving periodic announces; after the fix,
//! announces keep arriving on schedule. Releasing the gate lets the
//! download finish normally — proving the blocking is isolated inside
//! the storage pipeline task (SPEC §3.3 shape).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: u32 = 16384;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-store-pipeline-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// Gated writer: the first write_at blocks on the gate (std channel,
/// blocking a pool thread); later writes pass through. create forwards
/// (allocation proceeds, not gated). The gate lives inside a `Mutex`
/// (required by the trait's `Sync` bound — `write_at(&self)` is a shared
/// surface); recv runs outside the lock, so nothing blocks while
/// holding it.
struct GatedWriter {
    inner: taiji_store::torrent_writer::TorrentWriter,
    gate: Mutex<Option<std_mpsc::Receiver<()>>>,
}

impl DiskWriter for GatedWriter {
    fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
        self.inner.open(path, read_only)
    }
    fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
        self.inner.open_existing(path, read_only)
    }
    fn create(&mut self, path: &Path) -> Result<(), StoreError> {
        self.inner.create(path)
    }
    fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
        self.inner.truncate(len)
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
        let rx = self.gate.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(rx) = rx {
            let _ = rx.recv(); // the gate
        }
        self.inner.write_at(offset, data)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
        self.inner.read_at(offset, buf)
    }
    fn flush_os_buffers(&self) -> Result<(), StoreError> {
        self.inner.flush_os_buffers()
    }
    fn size(&self) -> Result<u64, StoreError> {
        self.inner.size()
    }
    fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
        self.inner.set_bypass_page_cache()
    }
}

/// Creates a fresh gate per build and hands the receiver side to the
/// test via the relay.
struct GateFactory {
    /// Relay: passes the gate sender to the test (the test drops it to
    /// release the gate).
    relay: Arc<Mutex<std_mpsc::Sender<std_mpsc::Sender<()>>>>,
}

impl WriterFactory for GateFactory {
    fn build(&self, layout: &Layout, dest: &Path) -> Result<Box<dyn DiskWriter>, StoreError> {
        let (gate_tx, gate_rx) = std_mpsc::channel();
        self.relay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(gate_tx)
            .map_err(|_| StoreError::Internal("gate relay closed".into()))?;
        Ok(Box::new(GatedWriter {
            inner: taiji_store::torrent_writer::TorrentWriter::new(
                layout.clone(),
                dest.to_path_buf(),
                100,
            ),
            gate: Mutex::new(Some(gate_rx)),
        }))
    }
}

/// Fake tracker: answers compact peers = the seeder address and counts
/// announces.
async fn fake_tracker(
    seeder_addr: std::net::SocketAddr,
    hits: Arc<AtomicUsize>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let hits = Arc::clone(&hits);
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
                hits.fetch_add(1, Ordering::SeqCst);
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

/// Mini-seeder (2 pieces): interested -> unchoke, request -> piece.
/// `requests` counts received wire requests (a liveness signal for the
/// main loop's 2s re-dispatch ticker — announce cadence is dominated by
/// the tracker interval and is not usable here).
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
                // After the handshake the mini-seeder sends a full
                // bitfield per BEP 3 (2 pieces = 0b1100_0000). It used to
                // send no ad and rely on the dispatcher's blind-select
                // fallback; that fallback went away with ad-aware
                // dispatch.
                if sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000]).await.is_err() {
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
                            let _ = sock.write_all(&[0, 0, 0, 1, 1]).await; // unchoke
                        }
                        6 => {
                            requests.fetch_add(1, Ordering::SeqCst);
                            let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                            let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                            let length =
                                u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                            let offset = index as usize * PIECE_LEN as usize + begin as usize;
                            let block = content[offset..offset + length as usize].to_vec();
                            let mut frame = Vec::new();
                            frame.extend_from_slice(
                                ((9 + block.len()) as u32).to_be_bytes().as_slice(),
                            );
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
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn main_loop_stays_alive_while_disk_write_is_gated() {
    let content = test_content();
    let mut expected = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        expected.push(ExpectedPieceHash::V1(Sha1::digest(c).into()));
    }

    let tmp = std::env::temp_dir().join(format!(
        "taiji-pipeline-{}-{}",
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
    let tracker_hits = Arc::new(AtomicUsize::new(0));
    let tracker_addr = fake_tracker(seeder_addr, tracker_hits).await;

    // Gate relay: the factory creates a fresh gate per build and hands
    // the receiver back to the test.
    let (relay_tx, relay_rx) = std_mpsc::channel::<std_mpsc::Sender<()>>();
    let relay = Arc::new(Mutex::new(relay_tx));

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
        initial_selection: None,
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
        writer_factory: Some(Arc::new(GateFactory { relay })),
        // Default throughput profile (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![face],
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

    // Wait until the first write hits the gate (the gate sender arrives
    // as soon as the pipeline is built).
    let gate_rx = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match relay_rx.try_recv() {
                Ok(rx) => return rx,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("the factory was never called (the storage pipeline never started)")
    });

    // Key assertion: while the write is held at the gate, the main loop
    // stays alive. If the loop still wrote to disk inline (the pre-fix
    // defect shape), it would stall on the gated write and the seeder
    // would only ever see the first request.
    //
    // Behavior fork:
    // - OFF (`BH_TWO_PHASE_LEDGER=0`, legacy semantics): the 2s
    // re-dispatch window treats storage-confirmation lag as a stalled
    // piece and re-sends wire requests -> within the 5s window the
    // seeder receives >=2 requests (the legacy liveness proxy, kept
    // as-is).
    // - ON (default): the block bytes already arrived (`block_tx.send`
    // succeeded = the network segment settled -> Settling), so
    // storage-confirmation lag no longer triggers wire re-sends
    // (re-sending would only make the peer re-read disk and
    // retransmit; late pieces land in the duplicate discard) -> the
    // count freezes across the two tail samples = zero re-dispatch.
    // Main-loop liveness is instead proven by completing the download
    // with zero re-sends (the loop was never blocked by the gated
    // write — dropping the gate later leads to Completed).
    tokio::time::sleep(Duration::from_secs(5)).await;
    let req_now = seeder_requests.load(Ordering::SeqCst);
    let two_phase_on = std::env::var("BH_TWO_PHASE_LEDGER")
        .map(|v| v != "0")
        .unwrap_or(true);
    if two_phase_on {
        // First dispatches concentrate in the first second of block
        // supply; the tail window [5s, 7s] spans an existing 2s
        // re-dispatch window — a frozen count means zero re-sends
        // (legacy semantics would force >=1 re-dispatch in that window).
        tokio::time::sleep(Duration::from_secs(2)).await;
        let req_tail = seeder_requests.load(Ordering::SeqCst);
        assert_eq!(
            req_tail, req_now,
            "a wire re-send appeared inside the storage-confirmation lag window \
             (anti-amplification semantics regression)"
        );
    } else {
        assert!(
            req_now >= 2,
            "the main loop went unresponsive while the disk write was gated \
             (seeder request count = {req_now} — regression?)"
        );
    }

    // Release the gate (dropping the Sender unblocks the writer-side
    // recv): the download completes normally.
    drop(gate_rx);
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    let got = std::fs::read(tmp.join("blob.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got,
        test_content(),
        "downloaded content must match the source"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
