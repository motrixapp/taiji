//! criterion micro-benchmark: ProgressModel bitmap synthesis (the SPEC
//! §14.4 performance-gate dev face).
//!
//! Scope: the pure-function segment of the v2 synthesis view — bitmap
//! set (`set_piece_done_global`, hot-called on the engine completion
//! path), `synthesized_bitfield` (the RPC bitfield convention),
//! `completed_length` (the tellStatus aggregation convention). The
//! model shape = a hybrid-convention multi-file layout (512 files x
//! 16KiB pieces, deterministic lengths). No IO / clock / random inputs
//! (lengths derived from a fixed-seed table).
//!
//! Run: `cargo bench -p taiji-core --bench bench_progress` (release).

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

use taiji_core::progress::ProgressModel;

/// Deterministic length table: 512 files, length =
/// 16KiB x (1 + (i*7919) % 33) (the prime 7919 spreads the piece-count
/// distribution; ~9k pieces total).
fn file_lens(n_files: usize) -> Vec<u64> {
    const PIECE: u64 = 16 * 1024;
    (0..n_files)
        .map(|i| PIECE * (1 + (i as u64 * 7919) % 33))
        .collect()
}

fn bench_progress(c: &mut Criterion) {
    let lens = file_lens(512);

    let mut group = c.benchmark_group("progress");

    group.bench_function("from_lengths/512_files", |b| {
        b.iter(|| ProgressModel::from_lengths(black_box(&lens), 16 * 1024))
    });

    group.bench_function("set_piece_done_global/full_sweep", |b| {
        b.iter_batched(
            || ProgressModel::from_lengths(&lens, 16 * 1024),
            |mut pm| {
                let mut newly_done = 0u64;
                for g in 0..pm.global_piece_count() {
                    if pm.set_piece_done_global(g) {
                        newly_done += 1;
                    }
                }
                black_box(newly_done)
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("synthesized_bitfield/512_files_partial", |b| {
        let mut pm = ProgressModel::from_lengths(&lens, 16 * 1024);
        // Half-full pattern (fixed-stride set, deterministic).
        for g in 0..pm.global_piece_count() {
            if g % 2 == 0 {
                pm.set_piece_done_global(g);
            }
        }
        b.iter(|| pm.synthesized_bitfield())
    });

    group.bench_function("completed_length/512_files_partial", |b| {
        let mut pm = ProgressModel::from_lengths(&lens, 16 * 1024);
        for g in 0..pm.global_piece_count() {
            if g % 2 == 0 {
                pm.set_piece_done_global(g);
            }
        }
        b.iter(|| pm.completed_length())
    });

    group.bench_function("piece_done_global/probe_1024", |b| {
        let mut pm = ProgressModel::from_lengths(&lens, 16 * 1024);
        for g in 0..pm.global_piece_count() {
            if g % 2 == 0 {
                pm.set_piece_done_global(g);
            }
        }
        b.iter(|| {
            let mut hits = 0u32;
            for g in 0..1024u64 {
                if pm.piece_done_global(g) {
                    hits += 1;
                }
            }
            hits
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_progress
}
criterion_main!(benches);
