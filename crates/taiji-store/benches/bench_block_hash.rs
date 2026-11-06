//! Criterion micro-benchmark: the pure-function hash segment of block/piece
//! verification (SPEC §14.4 performance surface).
//!
//! Scope: the pure-function segment outside spawn_blocking — v1 whole-piece
//! SHA-1 (the verifier's pre-persist gate) and v2 block-granularity SHA-256 +
//! Merkle node merging (the BEP-52 verification pipeline;
//! `merkle::{block_hash,node_hash,root_from_block_hashes}`). Inputs are
//! deterministically constructed (fixed XorShift seed), no IO/clock. Real
//! end-to-end throughput (including disk and scheduling) is carried by the
//! macro benchmark.
//!
//! Run: `cargo bench -p taiji-store --bench bench_block_hash` (release).

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sha1::{Digest as _, Sha1};

use taiji_store::merkle::{BLOCK_SIZE, block_hash, node_hash, root_from_block_hashes};

/// Deterministic data (XorShift64 with a fixed seed; no runtime randomness).
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

/// v1 scope: SHA-1 whole piece (the pure-function segment, isomorphic to
/// the verifier; the hash core inside aria2's `MultiDiskAdaptor`
/// verification pipeline).
fn sha1_piece(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

fn bench_block_hash(c: &mut Criterion) {
    let block = deterministic(BLOCK_SIZE as usize, 0xB10C_5EED_2026_0001);
    // 1 MiB piece (one of the customary piece lengths) = 64 blocks.
    let piece_1mib = deterministic(1024 * 1024, 0xB10C_5EED_2026_0002);

    let mut group = c.benchmark_group("block_hash");
    group.throughput(Throughput::Bytes(BLOCK_SIZE as u64));
    group.bench_function("sha1/v1_piece_16kib", |b| {
        b.iter(|| sha1_piece(black_box(&block)))
    });
    group.bench_function("sha2/v2_block_16kib", |b| {
        b.iter(|| block_hash(black_box(&block)))
    });

    group.throughput(Throughput::Bytes(piece_1mib.len() as u64));
    group.bench_function("sha1/v1_piece_1mib", |b| {
        b.iter(|| sha1_piece(black_box(&piece_1mib)))
    });
    // Full v2 verification pipeline: a 1 MiB piece = 64 blocks of SHA-256 +
    // 63 node merges.
    group.bench_function("sha2/v2_pipeline_piece_1mib", |b| {
        b.iter(|| {
            let blocks: Vec<[u8; 32]> = piece_1mib
                .chunks(BLOCK_SIZE as usize)
                .map(block_hash)
                .collect();
            root_from_block_hashes(black_box(&blocks))
        })
    });
    group.throughput(Throughput::Bytes(32));
    group.bench_function("merkle/node_hash_pair", |b| {
        let l = [1u8; 32];
        let r = [2u8; 32];
        b.iter(|| node_hash(black_box(&l), black_box(&r)))
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_block_hash
}
criterion_main!(benches);
