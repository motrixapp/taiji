//! Disk-protection tiers end to end (the store pipeline's consumption
//! surface):
//! 1. flush beat — with `flush_interval` mounted, periodic fsyncs happen
//!    through the shared handle; the throughput default tier (None) has
//!    no periodic fsync (behavior-unchanged, tested explicitly);
//! 2. allocation mode — the hdd-sequential tier preallocates the full
//!    length with real allocation as soon as a new task starts
//!    (st_blocks non-sparse); the default tier keeps sparse trunc
//!    (existing behavior).
//!
//! Network-free shape: the announce points at a dead port (tracker
//! retries stay silent); the storage pipeline finishes building +
//! allocation at engine startup and stays resident — the flush beat /
//! allocation surfaces do not depend on peer traffic (SPEC §3.3: the
//! storage pipeline task is independent of the network surface).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, FaceConfig, FaceKind, WriterFactory};
use taiji_store::disk::DiskWriter;
use taiji_store::disk_policy::{AllocationMode, DiskPolicy, DiskTier};
use taiji_store::error::StoreError;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};

const PIECE_LEN: u32 = 16384;
const CONTENT_LEN: usize = 2 * PIECE_LEN as usize;

fn v1_expected() -> Vec<ExpectedPieceHash> {
    const P: &[u8] = b"taiji-p88-disk-policy-";
    let content: Vec<u8> = P.iter().cycle().take(CONTENT_LEN).copied().collect();
    content
        .chunks(PIECE_LEN as usize)
        .map(|c| ExpectedPieceHash::V1(Sha1::digest(c).into()))
        .collect()
}

fn temp_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "taiji-p88-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
    dir
}

fn face_config() -> FaceConfig {
    let expected = v1_expected();
    let n = expected.len() as u64;
    FaceConfig {
        kind: FaceKind::V1,
        info_hash: [9u8; 20],
        reserved: Reserved::aria2_default(),
        addressing: Addressing::Flat,
        piece_goffs: (0..n).map(|k| k * u64::from(PIECE_LEN)).collect(),
        piece_bytes: (0..n)
            .map(|k| (CONTENT_LEN as u64 - k * u64::from(PIECE_LEN)).min(u64::from(PIECE_LEN)))
            .collect(),
        expected,
        plan_file_lengths: vec![CONTENT_LEN as u64],
        progress_file_lens: vec![CONTENT_LEN as u64],
        cross: Vec::new(),
        hash_files: None,
    }
}

/// fsync-counting writer (the flush-beat observation surface): the fsync
/// count is shared; reads/writes forward to the inner TorrentWriter.
struct CountingWriter {
    inner: taiji_store::torrent_writer::TorrentWriter,
    fsyncs: Arc<AtomicUsize>,
}

impl DiskWriter for CountingWriter {
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
        self.inner.write_at(offset, data)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
        self.inner.read_at(offset, buf)
    }
    fn flush_os_buffers(&self) -> Result<(), StoreError> {
        self.fsyncs.fetch_add(1, Ordering::SeqCst);
        self.inner.flush_os_buffers()
    }
    fn size(&self) -> Result<u64, StoreError> {
        self.inner.size()
    }
    fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
        self.inner.set_bypass_page_cache()
    }
}

/// Counting factory: everything it builds shares one counter (build runs
/// exactly once during pipeline construction).
struct CountingFactory {
    fsyncs: Arc<AtomicUsize>,
}

impl WriterFactory for CountingFactory {
    fn build(&self, layout: &Layout, dest: &Path) -> Result<Box<dyn DiskWriter>, StoreError> {
        Ok(Box::new(CountingWriter {
            inner: taiji_store::torrent_writer::TorrentWriter::new(
                layout.clone(),
                dest.to_path_buf(),
                100,
            ),
            fsyncs: Arc::clone(&self.fsyncs),
        }))
    }
}

fn engine_cfg(
    dest: &Path,
    policy: DiskPolicy,
    factory: Option<Arc<dyn WriterFactory>>,
) -> EngineConfig {
    EngineConfig {
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        // Dead port: no tracker traffic (the engine is stopped via token
        // cancel).
        announce: "http://127.0.0.1:1/announce".into(),
        listen_port: 0,
        piece_len: PIECE_LEN,
        layout: Layout::plan_v1_padded(
            &[PlanEntry {
                path: PathBuf::from("blob.bin"),
                length: CONTENT_LEN as u64,
                padding: false,
            }],
            PIECE_LEN,
        )
        .unwrap_or_else(|e| panic!("{e}")),
        dest: dest.to_path_buf(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: factory,
        disk_policy: policy,
        faces: vec![face_config()],
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
    }
}

/// st_blocks (512B units) — the non-sparseness assertion surface (file
/// block count).
fn allocated_blocks(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let m = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => panic!("stat {path:?}: {e}"),
    };
    m.blocks()
}

/// Flush beat engaged: with `flush_interval = Some(50ms)` mounted, the
/// storage pipeline fsyncs periodically (through the shared write
/// handle); the beat's existence is judged by polling until >= 2 fsyncs
/// (a 50ms beat gives ~8 per 400ms in theory).
///
/// Hardening: the original version judged once after a fixed 400ms
/// window — under full-repo parallel load, engine spawn -> storage
/// pipeline construction (layout/open/DHT wiring) can be starved past
/// the window, observing 0 fsyncs before the flush loop has run even
/// once. Now a conditional poll (25ms steps; passes immediately once
/// met, so the normal path is not slowed), with a 5s deadline = a window
/// of 100 theoretical beats (ample starvation margin for construction).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_beat_fsyncs_periodically() {
    let tmp = temp_root("beat");
    let fsyncs = Arc::new(AtomicUsize::new(0));
    let policy = DiskPolicy {
        flush_interval: Some(Duration::from_millis(50)),
        ..DiskTier::Throughput.policy()
    };
    let cfg = engine_cfg(
        &tmp,
        policy,
        Some(Arc::new(CountingFactory {
            fsyncs: Arc::clone(&fsyncs),
        })),
    );
    let root = tokio_util::sync::CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);
    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(5);
    let mut hits;
    loop {
        hits = fsyncs.load(Ordering::SeqCst);
        if hits >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the flush cadence must fsync periodically ({hits} hits within the \
             5s observation window — the cadence never started or the storage \
             pipeline build was starved; flush_interval=50ms implies ~100 beats)"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), engine).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Default-tier zero change, pipeline side: the default tier has
/// `flush_interval = None` -> no periodic fsync during the run window
/// (the count stays 0 before cancel). Final data-flush barrier: engine
/// teardown (cancel -> final_flush -> pipeline drain + fsync) produces
/// exactly one final fsync (single face, single pipeline) — the
/// zero-periodic run window and the exactly-one final barrier are
/// asserted separately (the final barrier is a durability property, not
/// a periodic beat).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_tier_has_no_flush_beat() {
    let tmp = temp_root("nobeat");
    let fsyncs = Arc::new(AtomicUsize::new(0));
    let cfg = engine_cfg(
        &tmp,
        DiskPolicy::default(),
        Some(Arc::new(CountingFactory {
            fsyncs: Arc::clone(&fsyncs),
        })),
    );
    let root = tokio_util::sync::CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        fsyncs.load(Ordering::SeqCst),
        0,
        "the default tier must not introduce periodic fsync (zero behavior \
         change in the running window)"
    );
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), engine).await;
    assert_eq!(
        fsyncs.load(Ordering::SeqCst),
        1,
        "the terminal data flush barrier is exactly one fsync (single face, \
         single pipeline; it happens before the engine's JoinHandle returns — \
         final_flush waits on the barrier value before landing the terminal \
         progress row)"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// hdd-sequential tier: a new task preallocates the full length with
/// real allocation at startup — the moment the file appears, st_blocks
/// already cover the full length (peer traffic is zero at that point and
/// no bytes have been written, so the on-disk usage can only come from
/// preallocation).
///
/// Hardening: the wait window for the file to appear went 3s -> 15s —
/// under full-repo parallel load, engine construction (the storage
/// pipeline queues behind DHT/tracker wiring and other spawn work) can
/// be starved past 3s, producing a false `seen = false`. The loop breaks
/// as soon as the file exists, so the normal path is not slowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hdd_tier_preallocates_on_startup() {
    let tmp = temp_root("prealloc");
    let cfg = engine_cfg(&tmp, DiskTier::HddSequential.policy(), None);
    let root = tokio_util::sync::CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);
    let blob = tmp.join("blob.bin");
    let mut seen = false;
    for _ in 0..600 {
        if blob.exists() {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), engine).await;
    assert!(
        seen,
        "the storage pipeline build must complete file allocation (not seen \
         within the 15s window — the build was starved)"
    );
    let blocks = allocated_blocks(&blob);
    assert!(
        blocks * 512 + 4096 >= CONTENT_LEN as u64,
        "the hdd tier's prealloc must really allocate the full length: \
         blocks={blocks} len={CONTENT_LEN}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Default-tier zero change, allocation side: the default tier truncs
/// sparsely — after startup the file has its full length but far fewer
/// on-disk blocks (existing behavior).
///
/// Hardening: same wait-window widening as
/// hdd_tier_preallocates_on_startup (3s -> 15s) against the
/// load-starved-construction false negative.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_tier_allocates_sparse_trunc() {
    let tmp = temp_root("sparse");
    let cfg = engine_cfg(&tmp, DiskPolicy::default(), None);
    let root = tokio_util::sync::CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root);
    let blob = tmp.join("blob.bin");
    let mut seen = false;
    for _ in 0..600 {
        if blob.exists() {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), engine).await;
    assert!(
        seen,
        "the storage pipeline build must complete file allocation (not seen \
         within the 15s window — the build was starved)"
    );
    let blocks = allocated_blocks(&blob);
    assert!(
        blocks * 512 < CONTENT_LEN as u64 / 4,
        "the default tier's trunc must stay sparse: blocks={blocks}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Compile-time existence of all AllocationMode states (all three tier
/// table states reachable; the trunc/falloc/prealloc value domain is
/// frozen).
#[test]
fn allocation_mode_value_domain() {
    assert_eq!(DiskPolicy::default().allocation, AllocationMode::Trunc);
    assert_eq!(
        DiskTier::SsdProtect.policy().allocation,
        AllocationMode::Falloc
    );
    assert_eq!(
        DiskTier::HddSequential.policy().allocation,
        AllocationMode::Prealloc
    );
}
