//! AIMD connection execution ring (scale directives → real worker
//! spawn/exit) — the ExtentCoordinator's AIMD decision face
//! ([`crate::aimd`]) produces per-source connection counts; this
//! module cashes them in as spawn/shrink actions on the worker pool.
//!
//! # Responsibility boundary (decision face / execution ring)
//!
//! - **Decision face** ([`crate::aimd::AimdBook`], exclusive to the
//! coordinator actor): slow-start doubling / gain threshold /
//! congestion multiplicative decrease — it only produces numbers,
//! never touches connections;
//! - **Execution ring** (this module, held by the HttpTask driver
//! loop): consumes
//! [`crate::coordinator::CoordinatorHandle::aimd_snapshot`]
//! snapshots; grow = emit spawn directives (the driver side spawns
//! new workers accordingly); shrink = lower the desired count —
//! in-place workers claim a "surplus slot" via CAS at extent
//! boundaries through [`WorkerPool::should_stop`] and exit
//! gracefully (never interrupting an in-flight extent; graceful
//! shutdown of excess connections along the AIMD decrease path).
//!
//! # Shrink protocol (surplus-slot claiming, anti-overshoot /
//! anti-dangling tickets)
//!
//! The desired count `want(source)` is the downward target maintained
//! by the execution ring's single write entry (`apply`, supervisor
//! only); the registered count `alive` is booked by spawn
//! acknowledgment ([`WorkerPool::note_spawn`]) and decremented on
//! worker exit. The worker boundary verdict is a CAS: only when
//! `alive > want` may a worker claim an exit and decrement `alive` —
//! the number of exits is bounded by the surplus at verdict time
//! (CAS mutual exclusion), converging exactly to `want`, and no
//! claim-then-honor tickets exist (if `want` rises before exit, the
//! surplus vanishes and remaining workers stay — zero dangling).
//! Non-shrink exits (failure cap / close-out cancellation) go through
//! [`WorkerPool::note_exit`] on the same ledger.
//!
//! # want semantics
//!
//! `want(source)` = the AIMD snapshot value; snapshot-absent sources
//! (the AimBook is lazily built — no account before the first
//! observation) = the slow-start start (the spec baseline
//! `min(2, cap)`; the user's explicit concurrency intent raises it
//! via [`WorkerPool::with_start`], same source and value as the
//! decision face — a decoupled start would make the first snapshot
//! emit spurious scale directives); removed sources (projected by the
//! driver side from RuntimeStats source-health snapshots) = 0 (all
//! exit — after failover the source has no participation face).
//!
//! # Synchronization face
//!
//! All-atomic counters, lock-free; `apply` is called only by the
//! driver loop (supervisor) single-threaded, and the worker side
//! touches only the two boundary verdicts `should_stop`/`note_exit`
//! — the race face = single writer, many readers; no locks held
//! across await.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::sync::atomic::{AtomicU64, Ordering};

/// Per-source worker slots: registered count and desired count
/// (`want` = the downward target / `alive` = the registered ledger).
struct SourceSlots {
    alive: AtomicU64,
    want: AtomicU64,
}

impl SourceSlots {
    fn new(want: u64) -> Self {
        SourceSlots {
            alive: AtomicU64::new(0),
            want: AtomicU64::new(want),
        }
    }
}

/// AIMD connection execution ring: per-source worker scale ledger (one
/// per task; the driver loop holds it Arc-shared with all workers).
pub struct WorkerPool {
    /// Slow-start start `min(2, cap)` (the desired count for
    /// snapshot-absent sources).
    initial: u64,
    /// Growth cap = `--max-connection-per-server` (defensive clamp —
    /// snapshot values and cap share a source; this only defends
    /// against snapshot drift).
    cap: u64,
    sources: Box<[SourceSlots]>,
}

impl WorkerPool {
    /// Builds from source count and growth cap (cap defensively
    /// clamped >= 1; initial desired = `min(2, cap)`, registered 0 —
    /// the first `apply` emits the slow-start spawn directives).
    pub fn new(source_count: usize, cap: u32) -> Self {
        let cap = u64::from(cap.max(1));
        let initial = 2.min(cap);
        WorkerPool {
            initial,
            cap,
            sources: (0..source_count.max(1))
                .map(|_| SourceSlots::new(initial))
                .collect(),
        }
    }

    /// Builds from source count, growth cap, and an explicit
    /// slow-start start (the start shares source and value with the
    /// AIMD decision face's [`crate::aimd::AimdConfig::with_start`] —
    /// the desired count in the snapshot-absent domain must equal the
    /// decision face's starting value, or the first snapshot emits
    /// spurious scale directives). Defensive clamping of the start:
    /// lower bound = the decision face's own spec probe floor
    /// `min(2, cap)`, upper bound clamped to the cap.
    pub fn with_start(source_count: usize, cap: u32, start: u32) -> Self {
        let cap = u64::from(cap.max(1));
        let initial = u64::from(start).max(2.min(cap)).min(cap).max(1);
        WorkerPool {
            initial,
            cap,
            sources: (0..source_count.max(1))
                .map(|_| SourceSlots::new(initial))
                .collect(),
        }
    }

    /// Fixed-ring construction (the static comparison baseline):
    /// per-source desired = `per_source` (clamped >= 1); snapshots do
    /// not participate — the supervisor never calls `apply`, so the
    /// desired count is constant with zero scaling (`should_stop` is
    /// always false: the registered count matches the fixed desired).
    pub fn fixed(source_count: usize, per_source: u32) -> Self {
        WorkerPool {
            initial: u64::from(per_source.max(1)),
            cap: u64::MAX,
            sources: (0..source_count.max(1))
                .map(|_| SourceSlots::new(u64::from(per_source.max(1))))
                .collect(),
        }
    }

    /// Consumes the AIMD snapshot and the removed-source set, cashing
    /// in scaling (the supervisor-only single-write entry):
    ///
    /// - snapshot values (clamped `[1, cap]`) overwrite that source's
    /// desired count; snapshot-absent sources keep their desired
    /// count (first round = the slow-start start);
    /// - removed sources' desired = 0 (snapshot values never override
    /// a removal decision — removal wins);
    /// - grow: returns the `(source, delta)` spawn-directive sequence
    /// (the shortfall of registered < desired; the caller must
    /// acknowledge with [`WorkerPool::note_spawn`] after acting);
    /// - shrink: the desired count is already lowered; convergence is
    /// left to the worker-boundary surplus claiming in
    /// [`WorkerPool::should_stop`] (no tickets at this entry).
    ///
    /// Returns the `(source, count)` sequence needing fresh spawns
    /// (only sources with delta > 0).
    pub fn apply(&self, snapshot: &[(u32, u32)], removed: &[u32]) -> Vec<(u32, u64)> {
        let mut directives = Vec::new();
        for (idx, slots) in self.sources.iter().enumerate() {
            let source = idx as u32;
            let want = if removed.contains(&source) {
                0
            } else {
                snapshot
                    .iter()
                    .find(|(s, _)| *s == source)
                    .map_or(self.initial, |&(_, n)| (u64::from(n)).clamp(1, self.cap))
            };
            slots.want.store(want, Ordering::Relaxed);
            let alive = slots.alive.load(Ordering::Relaxed);
            if want > alive {
                directives.push((source, want - alive));
            }
        }
        directives
    }

    /// Spawn-directive acknowledgment (called after the driver side
    /// really spawns; the registered count aligns with the directive
    /// quantity).
    pub fn note_spawn(&self, source: u32, n: u64) {
        if let Some(slots) = self.sources.get(source as usize) {
            slots.alive.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Worker-exit decrement (the unified entry for non-shrink exits —
    /// failure cap / close-out cancellation; exits claimed through
    /// shrink already self-decremented in [`WorkerPool::should_stop`]
    /// and must not double-decrement).
    ///
    /// Zero-floor defense: a race exists between spawn acknowledgment
    /// ([`WorkerPool::note_spawn`]) and worker exit (this entry) —
    /// when an exit becomes visible before the acknowledgment, a
    /// naive `fetch_sub` would underflow the registered count from 0
    /// into an astronomic u64 (desire comparisons distorted
    /// wholesale). The zero-floor CAS stops decrementing at the floor
    /// (a late positive acknowledgment then self-heals the count); no
    /// wraparound.
    pub fn note_exit(&self, source: u32) {
        if let Some(slots) = self.sources.get(source as usize) {
            loop {
                let cur = slots.alive.load(Ordering::Acquire);
                if cur == 0 {
                    break;
                }
                if slots
                    .alive
                    .compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }

    /// Extent-boundary shrink verdict: when the registered count
    /// exceeds the desired (surplus exists), claim one exit slot via
    /// CAS — a successful claim = this worker should exit gracefully
    /// (the registered count already self-decremented; the caller
    /// must **not** call [`WorkerPool::note_exit`]); failure = the
    /// slot was claimed by another or no surplus remains, keep
    /// working.
    pub fn should_stop(&self, source: u32) -> bool {
        let Some(slots) = self.sources.get(source as usize) else {
            return false;
        };
        loop {
            let alive = slots.alive.load(Ordering::Acquire);
            let want = slots.want.load(Ordering::Acquire);
            if alive <= want {
                return false;
            }
            if slots
                .alive
                .compare_exchange(alive, alive - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// The source's current desired worker count (observation face;
    /// out-of-range `source` = 0).
    pub fn want(&self, source: u32) -> u64 {
        self.sources
            .get(source as usize)
            .map(|s| s.want.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// The source's registered worker count (observation face).
    pub fn alive(&self, source: u32) -> u64 {
        self.sources
            .get(source as usize)
            .map(|s| s.alive.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defensive hardening: no wraparound in the race where note_exit
    /// becomes visible before the note_spawn acknowledgment (the
    /// zero-floor CAS — a naive fetch_sub from 0 yields an astronomic
    /// u64, distorting desire comparisons wholesale); a late positive
    /// acknowledgment self-heals the count.
    #[test]
    fn note_exit_before_spawn_rebalance_does_not_underflow() {
        let pool = WorkerPool::fixed(1, 1);
        pool.note_exit(0); // exit with nothing registered (0): floor holds.
        assert_eq!(
            pool.alive(0),
            0,
            "0 floor: no wrap-around into an astronomic u64"
        );
        pool.note_spawn(0, 1); // late acknowledgment: count self-heals.
        assert_eq!(pool.alive(0), 1);
        pool.note_exit(0);
        assert_eq!(pool.alive(0), 0, "normal fall-back as usual");
    }

    /// Slow-start first round: `apply(empty snapshot, no removals)`
    /// emits per-source `min(2, cap)` spawn directives (cap 1 → 1 per
    /// source, the aria2 default single-connection shape).
    #[test]
    fn first_apply_emits_slow_start_directives() {
        for (cap, want) in [(1u32, 1u64), (2, 2), (16, 2)] {
            let pool = WorkerPool::new(1, cap);
            let d = pool.apply(&[], &[]);
            assert_eq!(d, vec![(0, want)], "cap={cap}");
            assert_eq!(pool.want(0), want);
        }
    }

    /// Explicit-start first round: `with_start` emits the elevated
    /// spawn directives (cap 16 + start 16 → 16, aligned with the
    /// aria2 reference); out-of-domain starts clamp to the decision
    /// face's own domain `[min(2, cap), cap]`; same source and value
    /// as the decision face (the ledger-alignment face for zero
    /// spurious directives on the first snapshot).
    #[test]
    fn with_start_emits_elevated_directives() {
        for (cap, start, want) in [(16u32, 16u32, 16u64), (16, 5, 5), (1, 16, 1), (8, 0, 2)] {
            let pool = WorkerPool::with_start(1, cap, start);
            let d = pool.apply(&[], &[]);
            assert_eq!(d, vec![(0, want)], "cap={cap} start={start}");
            assert_eq!(pool.want(0), want);
        }
        // Elevated start + first snapshot equal: after acknowledgment,
        // apply is idempotent with zero directives (the convergence
        // face of ledger alignment).
        let pool = WorkerPool::with_start(1, 16, 16);
        let d = pool.apply(&[], &[]);
        pool.note_spawn(0, d[0].1);
        assert!(
            pool.apply(&[(0, 16)], &[]).is_empty(),
            "snapshot = start value: zero directives"
        );
    }

    /// Grow ring: snapshot values cash in as delta directives (the
    /// execution face of the 2→4→8→16 slow-start trajectory); after
    /// acknowledgment the registered count aligns, and repeated apply
    /// emits nothing more (idempotent convergence).
    #[test]
    fn grow_directives_track_snapshot_and_converge() {
        let pool = WorkerPool::new(1, 16);
        let mut n = 0u64;
        for step in [2u32, 4, 8, 16] {
            let d = pool.apply(&[(0, step)], &[]);
            assert_eq!(d, vec![(0, (step as u64) - n)], "step={step}");
            pool.note_spawn(0, (step as u64) - n);
            n = u64::from(step);
            assert_eq!(pool.alive(0), n);
        }
        assert!(
            pool.apply(&[(0, 16)], &[]).is_empty(),
            "zero directives at the cap"
        );
    }

    /// Shrink ring: after the desired count is lowered, surplus
    /// claiming converges exactly — 8 registered, desired 5 → exactly
    /// 3 workers claim exit (CAS mutual exclusion, no overshoot), the
    /// registered count drops straight to 5; claimed exits do not go
    /// through note_exit again (a double decrement = a negative
    /// ledger).
    #[test]
    fn shrink_converges_exactly_to_want_without_overshoot() {
        let pool = WorkerPool::new(1, 16);
        let d = pool.apply(&[(0, 8)], &[]);
        assert_eq!(d, vec![(0, 8)]);
        pool.note_spawn(0, 8);

        let _ = pool.apply(&[(0, 5)], &[]);
        let stopped = (0..8).filter(|_| pool.should_stop(0)).count();
        assert_eq!(stopped, 3, "exactly 3 surplus workers claim exit");
        assert_eq!(
            pool.alive(0),
            5,
            "claiming exit decrements the registered count"
        );
        assert!(
            !pool.should_stop(0),
            "after convergence desired = registered, no surplus"
        );

        // Lowering again to the same value: no further exits
        // (idempotent convergence face).
        let _ = pool.apply(&[(0, 5)], &[]);
        assert!((0..5).all(|_| !pool.should_stop(0)));
    }

    /// Successive shrinks: each round bounds by the current surplus
    /// (8→5→2 leaves exactly 2 registered after two rounds); raising
    /// the desired (grow during an undigested shrink) emits delta
    /// directives from the registered ledger.
    #[test]
    fn successive_shrinks_and_regrow_follow_the_ledger() {
        let pool = WorkerPool::new(1, 16);
        let d = pool.apply(&[(0, 8)], &[]);
        assert_eq!(d, vec![(0, 8)]);
        pool.note_spawn(0, 8);

        // 8→5→2: each round converges by its current surplus.
        let _ = pool.apply(&[(0, 5)], &[]);
        assert_eq!((0..8).filter(|_| pool.should_stop(0)).count(), 3);
        let _ = pool.apply(&[(0, 2)], &[]);
        assert_eq!((0..5).filter(|_| pool.should_stop(0)).count(), 3);
        assert_eq!(pool.alive(0), 2);

        // Raise 2→4: +2 directives from the registered ledger (an
        // undigested shrink does not dangle — remaining workers are
        // already past the surplus line).
        let d = pool.apply(&[(0, 4)], &[]);
        assert_eq!(d, vec![(0, 2)]);
        pool.note_spawn(0, 2);
        assert_eq!(pool.alive(0), 4);
        assert!((0..4).all(|_| !pool.should_stop(0)));
    }

    /// Removed source: desired forced to 0 (snapshot values do not
    /// override), all registered workers exit via surplus claiming;
    /// multi-source isolation (other sources keep scaling normally).
    #[test]
    fn removed_source_desires_zero_and_others_keep_aiming() {
        let pool = WorkerPool::new(2, 16);
        let d = pool.apply(&[], &[]);
        assert_eq!(d, vec![(0, 2), (1, 2)]);
        pool.note_spawn(0, 2);
        pool.note_spawn(1, 2);

        // Source 1 removed + source 0 snapshot 4: source 1 exits
        // fully (2 claims), source 0 grows by 2.
        let mut d = pool.apply(&[(0, 4)], &[1]);
        d.sort();
        assert_eq!(
            d,
            vec![(0, 2)],
            "the removed source emits zero directives, the other source keeps growing"
        );
        assert_eq!((0..2).filter(|_| pool.should_stop(1)).count(), 2);
        assert_eq!(
            pool.alive(1),
            0,
            "the removed source's registered count clears to zero"
        );
        assert_eq!(pool.want(1), 0);
        assert_eq!(pool.want(0), 4);
    }

    /// Snapshot value defensive clamping: over-cap clamped to the
    /// cap, zero raised to 1 (the AIMD decision face already clamps;
    /// this is the execution ring's independent line of defense).
    #[test]
    fn snapshot_values_are_clamped_to_cap_and_floor() {
        let pool = WorkerPool::new(1, 8);
        let d = pool.apply(&[(0, 99)], &[]);
        assert_eq!(d, vec![(0, 8)], "over-cap clamped to the cap");
        pool.note_spawn(0, 8);
        // Desired 0 raised to 1 (a non-removed in-cap source keeps at
        // least 1 worker).
        let _ = pool.apply(&[(0, 0)], &[]);
        assert_eq!(pool.want(0), 1);
        assert_eq!((0..8).filter(|_| pool.should_stop(0)).count(), 7);
    }
}
