//! criterion micro-benchmark: picker data structures (large-torrent face, >=
//! 100k synthetic pieces).
//!
//! The `legacy` module below is a line-for-line mirror of the
//! pre-refactor `piece_stat.rs` (naming prefixed only), kept purely as the
//! performance reference — it participates in no production path. The new
//! implementation uses bit-compacted counts + a lazily rebuilt bucket view +
//! O(1) seed handling. Three scenarios:
//!
//! 1. `have_storm_round`: 1000 HAVEs + one 50-peer pick round (throughput
//!    = Elements(1000); criterion reports the per-HAVE amortized cost);
//! 2. `seed_cycle`: 50 HaveAll->leave cycles (the seed O(1) face,
//!    `piece_picker.cpp`);
//! 3. `select_round_steady`: steady-state pick rounds with no events
//!    (bucket reads vs full-order scans).
//!
//! Inputs are deterministically constructed (fixed-seed xorshift), no
//! IO/clock. Memory accounting (order 4B + counts 2B + bucket slot 4B =
//! 10B/piece vs the legacy 12B/piece) is asserted in
//! `piece_stat::tests::memory_footprint_accounting`.
//!
//! Run: `cargo bench -p taiji-bt --bench bench_picker` (release).

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use taiji_bt::piece_stat::PieceStatMan;

/// Total piece count (large-torrent face, >= 100k pieces).
const PIECES: u64 = 100_000;
/// HAVEs per round (throughput numerator).
const HAVES_PER_ROUND: u64 = 1000;
/// Peers per pick round.
const PEERS: u64 = 50;

/// Deterministic bitmap (density = one set bit every `density` pieces).
fn bitmap(density: u64) -> Vec<bool> {
    (0..PIECES).map(|i| i % density == 0).collect()
}

/// Deterministic xorshift HAVE sequence.
fn have_seq() -> Vec<u64> {
    let mut x: u64 = 0x0B7D_1D0C_0FFE_EE08;
    (0..HAVES_PER_ROUND)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % PIECES
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Legacy mirror (a verbatim copy of the pre-refactor piece_stat.rs; the
// A/B reference).
// ---------------------------------------------------------------------------
mod legacy {
    /// Legacy PieceStatMan: Vec<u64> shuffle order + Vec<u32> counts, full
    /// maintenance per event.
    #[derive(Debug, Clone)]
    pub struct LegacyStatMan {
        order: Vec<u64>,
        counts: Vec<u32>,
    }

    impl LegacyStatMan {
        pub fn new(piece_num: u64, shuffle: &mut dyn FnMut(usize) -> usize) -> Self {
            let mut order: Vec<u64> = (0..piece_num).collect();
            for i in (1..order.len()).rev() {
                let j = shuffle(i + 1);
                order.swap(i, j);
            }
            LegacyStatMan {
                order,
                counts: vec![0u32; piece_num as usize],
            }
        }

        pub fn order(&self) -> &[u64] {
            &self.order
        }

        pub fn count(&self, index: u64) -> u32 {
            self.counts.get(index as usize).copied().unwrap_or_default()
        }

        /// Legacy HaveAll path: +1 per piece over an all-ones bitmap (the
        /// full update_bitfield form).
        pub fn add_all(&mut self) {
            for c in &mut self.counts {
                *c = c.saturating_add(1);
            }
        }

        /// Legacy seed-leave path: -1 per piece over an all-ones bitmap.
        pub fn sub_all(&mut self) {
            for c in &mut self.counts {
                *c = c.saturating_sub(1);
            }
        }

        pub fn add_piece(&mut self, index: u64) {
            if let Some(c) = self.counts.get_mut(index as usize) {
                *c = c.saturating_add(1);
            }
        }

        /// One-shot count fill (steady-state setup, not timed).
        pub fn fill(&mut self, v: u32) {
            self.counts.fill(v);
        }
    }

    /// Legacy one-pass two-record pick (verbatim mirror; the done mask is
    /// folded into the avail closure: full shuffle-order scan + two
    /// strictly-less-than-min updates).
    pub fn two_phase_scan(
        stats: &LegacyStatMan,
        avail: impl Fn(u64) -> bool,
        claimed: impl Fn(u64) -> bool,
    ) -> Option<u64> {
        let mut spread: Option<(u64, u32)> = None;
        let mut plain: Option<(u64, u32)> = None;
        for &idx in stats.order() {
            if !avail(idx) {
                continue;
            }
            let c = stats.count(idx);
            if plain.is_none_or(|(_, bc)| c < bc) {
                plain = Some((idx, c));
            }
            if !claimed(idx) && spread.is_none_or(|(_, bc)| c < bc) {
                spread = Some((idx, c));
            }
        }
        spread.or(plain).map(|(i, _)| i)
    }
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

/// HAVE storm + pick round (per-HAVE amortized maintenance cost).
fn bench_have_storm(c: &mut Criterion) {
    let mut group = c.benchmark_group("picker_have_storm_100k");
    group.throughput(Throughput::Elements(HAVES_PER_ROUND));
    let haves = have_seq();
    let avail = bitmap(2);
    let claimed = bitmap(8);

    group.bench_function("legacy_scan", |b| {
        b.iter(|| {
            let mut sm = legacy::LegacyStatMan::new(PIECES, &mut |n| n / 2);
            let mut acc = 0u64;
            for chunk in haves.chunks(HAVES_PER_ROUND as usize) {
                for &i in chunk {
                    sm.add_piece(i);
                }
                // 50-peer pick round (legacy: full scan per peer).
                for _ in 0..PEERS {
                    let pick =
                        legacy::two_phase_scan(&sm, |i| avail[i as usize], |i| claimed[i as usize]);
                    acc = acc.wrapping_add(pick.unwrap_or(0));
                }
            }
            black_box(acc)
        })
    });

    group.bench_function("bt_buckets", |b| {
        b.iter(|| {
            let mut sm = PieceStatMan::new(PIECES, &mut |n| n / 2);
            let mut acc = 0u64;
            for chunk in haves.chunks(HAVES_PER_ROUND as usize) {
                for &i in chunk {
                    sm.add_piece(i);
                }
                // 50-peer pick round (new: one lazy rebuild per round +
                // bucket reads per peer).
                for _ in 0..PEERS {
                    let (spread, plain) =
                        sm.select_two_phase(|i| avail[i as usize], |i| claimed[i as usize], None);
                    acc = acc.wrapping_add(spread.or(plain).unwrap_or(0));
                }
            }
            black_box(acc)
        })
    });
    group.finish();
}

/// Seed join/leave cycles (the seed O(1) face).
fn bench_seed_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("picker_seed_cycle_100k");
    group.throughput(Throughput::Elements(PEERS));
    group.bench_function("legacy_per_piece", |b| {
        b.iter(|| {
            let mut sm = legacy::LegacyStatMan::new(PIECES, &mut |n| n / 2);
            for _ in 0..PEERS {
                sm.add_all();
                sm.sub_all();
            }
            black_box(sm.count(0))
        })
    });
    group.bench_function("bt_o1", |b| {
        b.iter(|| {
            let mut sm = PieceStatMan::new(PIECES, &mut |n| n / 2);
            for _ in 0..PEERS {
                sm.add_seed();
                sm.remove_seed();
            }
            black_box(sm.count(0))
        })
    });
    group.finish();
}

/// Steady-state pick rounds (no events; bucket reads vs full-order
/// scans).
fn bench_select_steady(c: &mut Criterion) {
    let mut group = c.benchmark_group("picker_select_steady_100k");
    group.throughput(Throughput::Elements(PEERS));
    let avail = bitmap(2);
    let claimed = bitmap(8);

    group.bench_function("legacy_scan", |b| {
        let mut sm = legacy::LegacyStatMan::new(PIECES, &mut |n| n / 2);
        sm.fill(1); // setup: base count 1 (not timed)
        b.iter(|| {
            let mut acc = 0u64;
            for _ in 0..PEERS {
                let pick =
                    legacy::two_phase_scan(&sm, |i| avail[i as usize], |i| claimed[i as usize]);
                acc = acc.wrapping_add(pick.unwrap_or(0));
            }
            black_box(acc)
        })
    });

    group.bench_function("bt_buckets", |b| {
        let mut sm = PieceStatMan::new(PIECES, &mut |n| n / 2);
        sm.add_seed(); // setup: effective count 1 via the seed counter (not timed)
        b.iter(|| {
            let mut acc = 0u64;
            for _ in 0..PEERS {
                let (spread, plain) =
                    sm.select_two_phase(|i| avail[i as usize], |i| claimed[i as usize], None);
                acc = acc.wrapping_add(spread.or(plain).unwrap_or(0));
            }
            black_box(acc)
        })
    });
    group.finish();
}

criterion_group!(
    bench_picker,
    bench_have_storm,
    bench_seed_cycle,
    bench_select_steady
);
criterion_main!(bench_picker);
