//! Criterion micro-benchmark: the full-recheck read+hash path used by
//! crash recovery (`session::recheck`'s `verify_face` — per piece one
//! `TorrentReader::read_at_volatile` positioned read plus the primary
//! format hash: v1 = whole-piece SHA-1, v2 = per-16KiB-block SHA-256
//! folded to the piece root).
//!
//! Why dedicated: crash-recovery recheck is a heavy path (a full
//! re-verification of a restored torrent), yet no bench covered it —
//! page-cache-hygiene and future recheck optimizations need a
//! reproducible numeric baseline. This bench is that baseline: the
//! same reader construction and per-piece loop shape as the
//! production `verify_face` (read-once volatile reads included, so
//! DONTNEED-style cache eviction shows up in the numbers), synthetic
//! torrent with pre-generated deterministic data on an OS temp-dir
//! backing (on Linux point `TMPDIR` at a tmpfs to take the disk out
//! of the measurement; on macOS the temp dir is already memory-backed
//! for small files via the unified cache — the read is the page-cache
//! hit face either way, which is exactly the recheck hot path for a
//! recently-written torrent).
//!
//! Parameters: piece count x piece length (the two geometry axes that
//! dominate recheck wall time — syscall count per byte vs hash work
//! per syscall). Reported in two groups: `recheck_bytes` (MiB/s over
//! the whole torrent) and `recheck_pieces` (pieces/s).
//!
//! Run: `cargo bench -p taiji-store --bench bench_recheck` (release).

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sha1::{Digest as _, Sha1};
use taiji_store::layout::{Layout, PlanEntry};
use taiji_store::merkle::{self, BLOCK_SIZE};
use taiji_store::torrent_writer::TorrentReader;

/// Deterministic data (XorShift64 with a fixed seed; same generator
/// family as bench_block_hash — no runtime randomness, no IO).
fn deterministic(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let v = x.to_le_bytes();
        let n = (len - out.len()).min(8);
        out.extend_from_slice(&v[..n]);
    }
    out
}

/// One synthetic torrent on disk: pre-generated data written once at
/// setup (untimed) + the expected per-piece hashes the timed loop
/// verifies against (v1 SHA-1 digests and v2 piece roots).
struct Fixture {
    root: PathBuf,
    layout: Layout,
    piece_len: u32,
    piece_count: usize,
    expected_v1: Vec<[u8; 20]>,
    expected_v2: Vec<[u8; 32]>,
}

impl Fixture {
    fn build(tag: &str, piece_count: usize, piece_len: u32) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "taiji-bench-recheck-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let total = piece_count as u64 * u64::from(piece_len);
        let data = deterministic(total as usize, 0xBEEC_5EED_2026_0001);
        std::fs::write(root.join("blob.bin"), &data).unwrap_or_else(|e| panic!("write: {e}"));

        let entries = vec![PlanEntry {
            path: PathBuf::from("blob.bin"),
            length: total,
            padding: false,
        }];
        let layout =
            Layout::plan_v2_compact(&entries, piece_len).unwrap_or_else(|e| panic!("layout: {e}"));

        let bpp = (piece_len / BLOCK_SIZE) as usize;
        let mut expected_v1 = Vec::with_capacity(piece_count);
        let mut expected_v2 = Vec::with_capacity(piece_count);
        for piece in data.chunks(piece_len as usize) {
            expected_v1.push(Sha1::digest(piece).into());
            let blocks: Vec<[u8; 32]> = piece
                .chunks(BLOCK_SIZE as usize)
                .map(merkle::block_hash)
                .collect();
            // Multi-piece arm (the dominant recheck shape: every piece
            // except a single-piece file's only piece takes it).
            expected_v2.push(merkle::piece_root_from_block_hashes(&blocks, bpp));
        }
        Fixture {
            root,
            layout,
            piece_len,
            piece_count,
            expected_v1,
            expected_v2,
        }
    }

    /// The timed body: exactly the production `verify_face` loop shape
    /// (per piece: one read-once volatile positioned read + the
    /// primary-format hash verdict). Returns verified pieces so
    /// criterion sees the aggregate (and setup asserts it is all of
    /// them — the timed path is the verify-PASS face, the crash-
    /// recovery hot case for intact data).
    fn recheck_pass(&self, v2: bool) -> usize {
        let reader = TorrentReader::new(self.layout.clone(), self.root.clone());
        let bpp = (self.piece_len / BLOCK_SIZE) as usize;
        let mut buf = vec![0u8; self.piece_len as usize];
        let mut verified = 0usize;
        for k in 0..self.piece_count {
            let goff = k as u64 * u64::from(self.piece_len);
            let ok = match reader.read_at_volatile(goff, &mut buf) {
                Ok(n) if n == self.piece_len as usize => {
                    if v2 {
                        let blocks: Vec<[u8; 32]> = buf
                            .chunks(BLOCK_SIZE as usize)
                            .map(merkle::block_hash)
                            .collect();
                        merkle::piece_root_from_block_hashes(&blocks, bpp) == self.expected_v2[k]
                    } else {
                        Sha1::digest(&buf).as_slice() == self.expected_v1[k].as_slice()
                    }
                }
                _ => false,
            };
            verified += usize::from(ok);
        }
        verified
    }

    fn total_bytes(&self) -> u64 {
        self.piece_count as u64 * u64::from(self.piece_len)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Parameter sets: both geometry axes vary (piece count x piece
/// length). Set A = few large pieces (hash-dominated); set B = many
/// smaller pieces (syscall/rpc-dominated — 4x the per-piece overhead
/// per byte).
const PARAMS: [(&str, usize, u32); 2] = [
    ("16x1mib", 16, 1024 * 1024),
    ("128x256kib", 128, 256 * 1024),
];

fn bench_recheck(c: &mut Criterion) {
    for (tag, pieces, piece_len) in PARAMS {
        let fx = Fixture::build(tag, pieces, piece_len);
        // Untimed correctness gate: the timed loop must measure the
        // verify-PASS path.
        assert_eq!(
            fx.recheck_pass(false),
            pieces,
            "v1 recheck pass mismatch ({tag})"
        );
        assert_eq!(
            fx.recheck_pass(true),
            pieces,
            "v2 recheck pass mismatch ({tag})"
        );

        let mut bytes = c.benchmark_group("recheck_bytes");
        bytes.throughput(Throughput::Bytes(fx.total_bytes()));
        bytes.bench_function(format!("v1/{tag}"), |b| {
            b.iter(|| black_box(fx.recheck_pass(false)))
        });
        bytes.bench_function(format!("v2/{tag}"), |b| {
            b.iter(|| black_box(fx.recheck_pass(true)))
        });
        bytes.finish();

        let mut pcs = c.benchmark_group("recheck_pieces");
        pcs.throughput(Throughput::Elements(pieces as u64));
        pcs.bench_function(format!("v1/{tag}"), |b| {
            b.iter(|| black_box(fx.recheck_pass(false)))
        });
        pcs.bench_function(format!("v2/{tag}"), |b| {
            b.iter(|| black_box(fx.recheck_pass(true)))
        });
        pcs.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(8));
    targets = bench_recheck
}
criterion_main!(benches);
