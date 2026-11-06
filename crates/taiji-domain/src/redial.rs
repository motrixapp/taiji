//! Peer redial pool.
//!
//! Motivation: within the announce interval (1800s) window, known
//! connectable peers that dropped are never retried by anyone, leaving a
//! discovery gap. This module keeps the set of "handshake-verified, not
//! currently connected" outbound peers inside the engine main loop and
//! redials them at a low, ticked cadence to close that gap.
//!
//! The policy mirrors libtorrent's reconnect machinery: min_reconnect_time
//! = 60s base, the `(failcount + 1) x min_reconnect_time` reconnect gate,
//! `max_failcount` = 3 eviction, linear backoff, plus one intentional
//! fast-dial divergence for departed peers that had delivered data.
//! Upstream anchor mapping: docs/design/domain-policies.md.
//!
//! Hard invariants:
//! - Admission has exactly one entry point, [`RedialPool::note_departure`],
//! called by the engine only when a peer that completed the BT handshake
//! and was registered departs; raw DHT/PEX/tracker addresses never enter
//! the pool. Outbound connections only: an inbound peer's remote port is
//! an ephemeral source port and cannot be redialed (same boundary as PEX
//! fresh bookkeeping, `UTPexExtensionMessage.cc`).
//! - Bounded: capacity capped at [`REDIAL_POOL_CAP`] with eviction (see
//! [`RedialPool::note_departure`]); main-loop tick driven (not a busy
//! loop); at most [`REDIAL_SWEEP_BATCH`] dials per sweep. All time is an
//! injected `Instant`; unit tests never sleep.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Redial cadence base (libtorrent `src/settings_pack.cpp`
/// `SET(min_reconnect_time, 60)` default; the `src/peer_list.cpp`
/// reconnect gate gives a first retry of (0+1) x 60s — same value).
pub const REDIAL_BASE: Duration = Duration::from_secs(60);

/// Fast reconnect base: the first redial wait for a departed peer that
/// **delivered data** (`had_data`). Intentional divergence from libtorrent
/// (which has no fast tier): it only covers the first redial after a
/// data-delivering peer departs, closing the short restart-window gap that
/// the 60s gate always misses. On a miss the entry falls back to the 60s
/// regime ([`miss_wait`]) and **no failure is counted** — a silent
/// departure is weaker evidence than a failed dial (libtorrent
/// `src/peer_list.cpp` inc_failcount only accumulates on connection
/// failures); the `(f+1) x 60` failure gradient and the max_failcount=3
/// eviction are preserved unchanged. `BH_FAST_RECONNECT=0` reverts the
/// whole face to the regular backoff.
pub const FAST_RECONNECT_BASE: Duration = Duration::from_secs(5);

/// Backoff cap = the announce interval's magnitude: past it the tracker
/// re-supplies new candidates and longer redial waits add nothing (local
/// scheduling policy; announce semantics unchanged).
pub const REDIAL_BACKOFF_CAP: Duration = Duration::from_secs(1800);

/// Consecutive redial failure cap (reached -> evicted; failing peers do
/// not squat forever): matches libtorrent `src/settings_pack.cpp`
/// `SET(max_failcount, 3)` plus `src/peer_list.cpp` (failcount >=
/// max_failcount loses connect-candidate status).
pub const REDIAL_MAX_FAILURES: u32 = 3;

/// Pool capacity cap (bounded): 1/8 of the same-order DhtDialDedup cap of
/// 4096 — the redial pool only admits outbound peers that completed a
/// handshake, so it is naturally far smaller than the discovery dedup
/// table.
pub const REDIAL_POOL_CAP: usize = 512;

/// Maximum redials initiated per sweep (2s tick driven; a burst limit that
/// avoids a same-instant redial storm after mass disconnects; 12 x 0.5Hz =
/// at most 6 dials/s). The in-flight cap is this constant itself —
/// dequeue optimistically advances, results converge on report, and the
/// same address is never in flight twice (see [`RedialPool::due`]).
pub const REDIAL_SWEEP_BATCH: usize = 12;

/// Redial failure backoff (linear): `(failures+1) x REDIAL_BASE`, capped
/// at [`REDIAL_BACKOFF_CAP`] — adopts the libtorrent reconnect gate shape
/// `(failcount+1) x min_reconnect_time` (`src/peer_list.cpp`).
/// `failures` = consecutive failures so far: 0 (first try after
/// departure) -> 60s, 1 -> 120s, 2 -> 180s (>= 3 evicts before this
/// matters, but the pure function stays defined for failures >= 3) ...
/// capped at [`REDIAL_BACKOFF_CAP`].
pub fn redial_backoff(failures: u32) -> Duration {
    REDIAL_BACKOFF_CAP.min(
        REDIAL_BASE
            .checked_mul(failures.saturating_add(1))
            .unwrap_or(REDIAL_BACKOFF_CAP),
    )
}

/// Fast reconnect switch read: `BH_FAST_RECONNECT=0` -> off (reverting to
/// the regular backoff: 60s base, the (f+1) x 60 gradient, eviction at 3
/// failures); any other value (including unset) -> on. Evaluated once at
/// [`RedialPool`] construction (a process-level switch, not
/// hot-reloadable); deterministic tests pin it via
/// [`RedialPool::with_fast_reconnect`] — same pattern as taiji-bt
/// request_book.rs `with_window_mode`. Parsing and read timing are
/// registered in `taiji_io::knobs` (read at construction, no caching).
pub fn fast_reconnect_enabled() -> bool {
    taiji_io::knobs::fast_reconnect_enabled()
}

/// Wait after one redial failure (single decision source): an unarmed
/// fast-dial miss (`was_armed`) -> [`REDIAL_BASE`] (the 60s regime — a
/// silent departure is not a connection failure and does not count toward
/// failcount; see [`FAST_RECONNECT_BASE`] / [`RedialPool::note_result`]);
/// otherwise -> [`redial_backoff`] (the (f+1) x 60 gradient).
/// `failures` semantics = the caller's consecutive-failure count:
/// [`RedialPool::note_result`] passes the post-increment value on the
/// non-armed path; [`RedialPool::due`] optimistically passes
/// pre-increment + 1 — both paths share this function so that results
/// arriving normally converge on the same value.
pub fn miss_wait(was_armed: bool, failures: u32) -> Duration {
    if was_armed {
        REDIAL_BASE
    } else {
        redial_backoff(failures)
    }
}

/// Whether the departed connection delivered payload data (up/down
/// counters > 0) — the fast-dial arming condition and the eviction-order
/// protection key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDelivered {
    /// Payload bytes flowed: the departure arms the fast dial (switch
    /// permitting) and the entry is evicted last.
    Yes,
    /// Zero payload bytes: regular 60s regime, evicted first.
    No,
}

/// Dial outcome booked by the pool. The engine's richer tri-state
/// (connected / failed / banned-collapsed-into-remove) collapses before
/// this face: a ban removal never reaches [`RedialPool::note_result`]
/// (it goes through [`RedialPool::remove_ip`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedialOutcome {
    /// The connection was rebuilt: the entry is removed (the next
    /// departure starts fresh).
    Connected,
    /// The dial failed: an armed miss waits [`REDIAL_BASE`] and counts no
    /// failure; otherwise the (f+1) x 60 gradient, eviction at
    /// [`REDIAL_MAX_FAILURES`].
    Failed,
}

/// A redial pool entry: one outbound peer that completed a handshake and
/// is not currently connected.
#[derive(Debug, Clone)]
struct RedialEntry {
    /// Owning face (face index at departure; verified to still exist at
    /// dial time).
    face: usize,
    /// Last moment the peer was known good (this pool uses the departure
    /// moment: the connection had a successful handshake/data exchange,
    /// so departure is its conservative upper bound; used only for
    /// eviction order).
    last_ok: Instant,
    /// Whether data was exchanged during the connection (up/down counters >
    /// 0) — the eviction-order protection key.
    had_data: bool,
    /// Consecutive redial failures (cleared when the entry is removed on a
    /// successful reconnect; same effect as libtorrent zeroing failcount
    /// after a successful connection, `src/peer_list.cpp`
    /// `set_failcount`).
    failures: u32,
    /// Fast-dial armed bit: delivered data at admission and switch on =
    /// true — the first redial lands at [`FAST_RECONNECT_BASE`]; a miss
    /// disarms (later failures follow [`miss_wait`]'s 60s / (f+1) x 60
    /// regime). Removed with the entry on a successful reconnect.
    fast_armed: bool,
    /// Next redial not before.
    next_at: Instant,
}

/// Peer redial pool (main-loop exclusive, no shared lock — events converge
/// through the reg/leave/outcome paths and are processed in order). Key =
/// outbound dial address.
#[derive(Debug)]
pub struct RedialPool {
    entries: HashMap<SocketAddr, RedialEntry>,
    cap: usize,
    /// Fast reconnect switch: evaluated once from `BH_FAST_RECONNECT` at
    /// construction.
    fast: bool,
}

impl RedialPool {
    pub fn new(cap: usize) -> RedialPool {
        RedialPool {
            entries: HashMap::new(),
            cap: cap.max(1),
            fast: fast_reconnect_enabled(),
        }
    }

    /// Pins the fast reconnect switch (deterministic test face; production
    /// goes through [`RedialPool::new`]'s environment read, same pattern
    /// as taiji-bt `with_window_mode`).
    #[cfg(test)]
    pub fn with_fast_reconnect(mut self, fast: bool) -> RedialPool {
        self.fast = fast;
        self
    }

    // len_without_is_empty: len is an observation surface (a telemetry log
    // counter field); the pool has no "empty as a whole" branch semantics
    // (emptiness is carried by due()/admit() queue semantics), so no
    // unused is_empty API is added just to silence the lint.
    #[expect(
        clippy::len_without_is_empty,
        reason = "len is a telemetry counter; no caller branches on emptiness"
    )]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// (Re)registers a peer: the connection is rebuilt, the entry removed
    /// (the next departure re-admits, with the failure count reset — same
    /// effect as libtorrent zeroing failcount after a successful
    /// connection).
    pub fn note_connected(&mut self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }

    /// Peer departed -> admission (the engine calls this only from the
    /// departure path of peers that completed the handshake and were
    /// registered; outbound connections only — an inbound peer's remote
    /// port is an ephemeral source port and cannot be redialed).
    ///
    /// First-dial cadence: delivered data (`had_data`) and switch on =
    /// [`FAST_RECONNECT_BASE`] (5s fast dial for silent-departure
    /// recovery, entry armed); otherwise [`REDIAL_BASE`] (60s, libtorrent
    /// (0+1) x min_reconnect_time).
    ///
    /// Over-cap eviction (bounded): first evict the oldest `last_ok` among
    /// peers with no data exchanged, then the overall oldest `last_ok`
    /// (same direction as libtorrent `src/peer_list.cpp` weeding
    /// candidates: failing/stale first; fixed here as a
    /// had_data/last_ok two-level order).
    pub fn note_departure(
        &mut self,
        face: usize,
        addr: SocketAddr,
        had_data: DataDelivered,
        now: Instant,
    ) {
        let had_data = had_data == DataDelivered::Yes;
        self.entries.remove(&addr);
        if self.entries.len() >= self.cap {
            // Least protected = no data first, then oldest last_ok (min
            // takes the smallest key order).
            let victim = self
                .entries
                .iter()
                .min_by(|a, b| (a.1.had_data, a.1.last_ok).cmp(&(b.1.had_data, b.1.last_ok)))
                .map(|(k, _)| *k);
            if let Some(victim) = victim {
                self.entries.remove(&victim);
            }
        }
        let fast = had_data && self.fast;
        self.entries.insert(
            addr,
            RedialEntry {
                face,
                last_ok: now,
                had_data,
                failures: 0,
                fast_armed: fast,
                next_at: now
                    + if fast {
                        FAST_RECONNECT_BASE
                    } else {
                        REDIAL_BASE
                    },
            },
        );
    }

    /// Redial result report (the pool-books fact; see [`RedialOutcome`]
    /// for what reaches this face):
    /// - `Connected`: connection rebuilt (registration arrives later);
    /// entry removed;
    /// - `Failed`: an unarmed fast-dial miss -> retry at [`REDIAL_BASE`]
    /// 60s and **no failcount** (a silent departure is not a connection
    /// failure: libtorrent only accumulates failcount on connection
    /// failures, `src/peer_list.cpp` inc_failcount — a missed
    /// restart-window probe is weaker evidence than a failed dial; at
    /// most one extra probe per departure cycle, bounded); other
    /// consecutive failures increment, and at [`REDIAL_MAX_FAILURES`]
    /// the entry is evicted (failing peers do not squat forever, same as
    /// libtorrent `peer_list.cpp`); otherwise the next redial follows
    /// [`miss_wait`] (the (f+1) x 60 gradient).
    pub fn note_result(&mut self, addr: &SocketAddr, outcome: RedialOutcome, now: Instant) {
        let Some(entry) = self.entries.get_mut(addr) else {
            return;
        };
        if outcome == RedialOutcome::Connected {
            self.entries.remove(addr);
            return;
        }
        let was_armed = entry.fast_armed;
        entry.fast_armed = false;
        if was_armed {
            // Armed miss: no failure counted; retry at the 60s regime (see
            // above).
            entry.next_at = now + miss_wait(true, entry.failures);
            return;
        }
        entry.failures += 1;
        if entry.failures >= REDIAL_MAX_FAILURES {
            self.entries.remove(addr);
            return;
        }
        entry.next_at = now + miss_wait(false, entry.failures);
    }

    /// Removes all entries for an IP (ban enforcement path; banned peers
    /// are never redialed).
    pub fn remove_ip(&mut self, ip: IpAddr) {
        self.entries.retain(|addr, _| addr.ip() != ip);
    }

    /// Dequeues due entries (main-loop 2s tick driven, not a busy loop):
    /// at most [`REDIAL_SWEEP_BATCH`]. Dequeue optimistically advances
    /// `next_at = now + miss_wait(armed, failures+1)` — if a dial result
    /// report is lost (engine teardown etc.), the entry self-heals and
    /// retries on the existing backoff rhythm, neither dropped nor
    /// busy-looped; when results arrive normally `note_result` converges
    /// on the same value ([`miss_wait`] is the single source).
    pub fn due(&mut self, now: Instant) -> Vec<(usize, SocketAddr)> {
        let mut due_addrs: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(_, e)| e.next_at <= now)
            .map(|(addr, _)| *addr)
            .take(REDIAL_SWEEP_BATCH)
            .collect();
        due_addrs.sort();
        due_addrs
            .into_iter()
            .filter_map(|addr| {
                let entry = self.entries.get_mut(&addr)?;
                entry.next_at = now + miss_wait(entry.fast_armed, entry.failures + 1);
                Some((entry.face, addr))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(oct: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from(oct), port)
    }

    fn addr6(segs: [u16; 8], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from(segs), port)
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Backoff table (linear): (failures+1) x 60s capped at 1800s
    /// (including the u32 overflow face); failures=0 = first try after
    /// departure at 60s.
    #[test]
    fn backoff_table() {
        let cases: [(u32, u64); 8] = [
            (0, 60),
            (1, 120),
            (2, 180),
            (3, 240),
            (28, 1740),
            (29, 1800),       // 30x60 = 1800 = cap
            (30, 1800),       // 31x60 -> cap
            (u32::MAX, 1800), // overflow face (checked_mul -> CAP)
        ];
        for (failures, want_s) in cases {
            let got = redial_backoff(failures);
            assert_eq!(got, secs(want_s), "failures={failures}");
        }
        assert_eq!(redial_backoff(u32::MAX), REDIAL_BACKOFF_CAP);
        // miss_wait decision face: armed miss = the 60s regime (no failure
        // counted); non-armed = redial_backoff as-is.
        assert_eq!(miss_wait(true, 0), secs(60));
        assert_eq!(
            miss_wait(true, 2),
            secs(60),
            "armed miss is independent of failcount"
        );
        assert_eq!(miss_wait(false, 1), secs(120));
        assert_eq!(miss_wait(false, 2), secs(180));
    }

    /// First-dial cadence table (departure branch x fallback switch):
    /// delivered data AND fast -> due at 5s (fast dial); no data OR fast
    /// off -> 60s (reference (0+1) x min_reconnect_time / the regular
    /// backoff, unchanged).
    #[test]
    fn redial_cadence_table() {
        let t0 = Instant::now();
        let cases: [(bool, bool, u64, u64); 4] = [
            // (fast, had_data, not-due-yet boundary s, due boundary s)
            (true, true, 4, 5), // silent-departure fast dial (FAST_RECONNECT_BASE)
            (true, false, 59, 60), // departure without data: not armed -> 60s
            (false, true, 59, 60), // fast=0 fallback: 60s, the regular regime
            (false, false, 59, 60),
        ];
        for (fast, had_data, early, on_time) in cases {
            let delivered = if had_data {
                DataDelivered::Yes
            } else {
                DataDelivered::No
            };
            let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(fast);
            let a = addr([203, 0, 113, 1], 6881);
            pool.note_departure(0, a, delivered, t0);
            assert!(
                pool.due(t0 + secs(early)).is_empty(),
                "fast={fast} had_data={had_data}: not due at {early}s"
            );
            assert_eq!(
                pool.due(t0 + secs(on_time)),
                vec![(0, a)],
                "fast={fast} had_data={had_data}: due at {on_time}s"
            );
        }
    }

    /// A successful reconnect removes the entry; the next departure starts
    /// fresh (failure count cleared, no inherited backoff). The fast=0 row
    /// is the regular 60s regime exactly; the fast=1 row re-arms the 5s
    /// fast dial on a renewed departure.
    #[test]
    fn reconnect_resets_cadence_and_failures() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(false);
        let a = addr([203, 0, 113, 3], 4000);
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(60)); // 1 failure -> backoff 120s
        assert!(pool.due(t0 + secs(119)).is_empty());
        // Peer reconnects via the tracker path (note_connected) ->
        // removed.
        pool.note_connected(&a);
        assert_eq!(pool.len(), 0);
        // Departs again -> starts at 60s (not a continuing 120s backoff).
        pool.note_departure(0, a, DataDelivered::Yes, t0 + secs(200));
        assert!(pool.due(t0 + secs(200) + secs(60)).len() == 1);
        // fast=1 isomorphic: after a reconnect clears state, a renewed
        // departure re-arms 5s (no gradient continuation).
        let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(true);
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        assert_eq!(pool.due(t0 + secs(5)), vec![(0, a)]);
        // Redial succeeded -> connection rebuilt.
        pool.note_result(&a, RedialOutcome::Connected, t0 + secs(5));
        assert_eq!(pool.len(), 0);
        pool.note_departure(0, a, DataDelivered::Yes, t0 + secs(200));
        assert_eq!(
            pool.due(t0 + secs(205)),
            vec![(0, a)],
            "renewed departure re-arms 5s, no inherited backoff"
        );
    }

    /// Failure backoff boundary (linear, fast=0 fallback row): failure 1
    /// -> retry after 120s; failure 2 -> 180s; failure 3 -> evicted
    /// (failing peers do not squat forever; libtorrent max_failcount=3).
    /// The fast=1 failure gradient is in
    /// [`Self::miss_ladder_decision_table`].
    #[test]
    fn failure_backoff_then_eviction() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(false);
        let a = addr([203, 0, 113, 4], 51413);
        pool.note_departure(1, a, DataDelivered::Yes, t0);
        // After dequeue (optimistic advance), failure 1 reported:
        // next = +backoff(1) = 120s.
        assert_eq!(pool.due(t0 + secs(60)), vec![(1, a)]);
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(62));
        assert!(pool.due(t0 + secs(62) + secs(119)).is_empty());
        assert_eq!(pool.due(t0 + secs(62) + secs(120)).len(), 1);
        // Failure 2: next = +backoff(2) = 180s.
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(250));
        assert!(pool.due(t0 + secs(250) + secs(179)).is_empty());
        assert_eq!(pool.due(t0 + secs(250) + secs(180)).len(), 1);
        // Failure 3: reaches REDIAL_MAX_FAILURES -> evicted, never dialed
        // again.
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(500));
        assert_eq!(pool.len(), 0);
        assert!(pool.due(t0 + secs(100_000)).is_empty());
        // Reporting failure for an evicted entry: idempotent, no effect.
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(600));
        assert_eq!(pool.len(), 0);
    }

    /// Reconnect path decision table (silent departure vs failure branches
    /// x backoff escalation). The failure gradient is locked across the
    /// four (fast, had_data) rows — `waits[i]` = the wait to the next
    /// redial after the i-th failure report (note_result and due's
    /// optimistic advance share the single source [`miss_wait`];
    /// same-value convergence asserted inline):
    /// - fast=1 had_data=1 (silent departure): 5s fast dial armed; a miss
    /// waits 60s (no failure counted); then (f+1) x 60 (120/180) —
    /// evicted at 3 counted failures (at most one extra probe per
    /// departure cycle, bounded);
    /// - fast=1 had_data=0 / fast=0 rows: the regular 60/120/180 gradient
    /// unchanged (the fallback rows, same source as
    /// `failure_backoff_then_eviction`);
    /// - the silent-ledger branch is orthogonal to this pool and redial
    /// dials are exempt from its gate — structurally locked by
    /// `silent.rs::pool_independent_of_silent_cooldown`, not repeated
    /// here.
    #[test]
    fn miss_ladder_decision_table() {
        let t0 = Instant::now();
        let cases: [(bool, bool, [u64; 4], bool); 4] = [
            // (fast, had_data, waits, armed_miss_not_counted)
            (true, true, [5, 60, 120, 180], true),
            (true, false, [60, 120, 180, 0], false), // 3rd failure evicts -> 4th row is a placeholder
            (false, true, [60, 120, 180, 0], false),
            (false, false, [60, 120, 180, 0], false),
        ];
        for (fast, had_data, waits, armed_free) in cases {
            let delivered = if had_data {
                DataDelivered::Yes
            } else {
                DataDelivered::No
            };
            let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(fast);
            let a = addr([203, 0, 113, 4], 51413);
            pool.note_departure(1, a, delivered, t0);
            let mut now = t0;
            let strikes = if armed_free { 4 } else { 3 };
            for (round, &wait) in waits.iter().take(strikes).enumerate() {
                now += secs(wait);
                // Due dequeue (optimistic advance armed->60s /
                // non-armed->(f+2)x60) and failure report (armed->60s no
                // count / non-armed->(f+1)x60) converge on the same value.
                assert_eq!(
                    pool.due(now),
                    vec![(1, a)],
                    "fast={fast} had_data={had_data} round={round}"
                );
                pool.note_result(&a, RedialOutcome::Failed, now);
            }
            assert_eq!(
                pool.len(),
                0,
                "fast={fast} had_data={had_data}: final failure evicts"
            );
            assert!(pool.due(t0 + secs(100_000)).is_empty());
        }
        // Boundary of "armed miss not counted": after two departure cycles
        // (each with one armed miss) two counted-failure slots remain
        // (eviction happens on the 3rd counted failure).
        let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(true);
        let a = addr([203, 0, 113, 5], 51413);
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(5)); // armed miss (not counted)
        assert_eq!(
            pool.len(),
            1,
            "armed miss neither evicts nor counts a failure"
        );
        pool.note_result(&a, RedialOutcome::Connected, t0 + secs(65)); // reconnect -> clean slate
        pool.note_departure(0, a, DataDelivered::Yes, t0 + secs(100));
        // Armed miss (again not counted).
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(105));
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(165)); // counted failure #1 -> 120s
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(285)); // counted failure #2 -> 180s
        // Counted failure #3 -> evicted.
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(465));
        assert_eq!(
            pool.len(),
            0,
            "3 counted failures evict (armed misses do not use the quota)"
        );
    }

    /// An armed entry's dequeue optimistic advance = 60s (non-armed =
    /// (f+2) x 60): the lost-result self-heal face re-probes at the armed
    /// regime (a single miss under churn does not drop the entry into the
    /// 2x tier).
    #[test]
    fn armed_optimistic_advance_is_base() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(true);
        let a = addr([203, 0, 113, 6], 51413);
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        assert_eq!(pool.due(t0 + secs(5)), vec![(0, a)]);
        // Dequeue optimistically advances (armed -> +60s): with a lost
        // result it self-heals and re-probes after 60s.
        assert!(pool.due(t0 + secs(6)).is_empty());
        assert_eq!(
            pool.due(t0 + secs(65)),
            vec![(0, a)],
            "armed optimistic advance 60s self-heal"
        );
    }

    /// A successful redial report removes the entry (connection rebuilt;
    /// the registration arm note_connected is an idempotent backstop).
    #[test]
    fn success_result_removes_entry() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP);
        let a = addr([203, 0, 113, 5], 6881);
        pool.note_departure(0, a, DataDelivered::No, t0);
        pool.note_result(&a, RedialOutcome::Connected, t0 + secs(60));
        assert_eq!(pool.len(), 0);
    }

    /// Pool cap eviction: when full, evict among no-data-exchanged peers
    /// first (oldest last_ok at the same level); when all have data, evict
    /// the oldest last_ok; the newly admitted entry itself is never the
    /// victim.
    #[test]
    fn cap_eviction_prefers_no_data_then_oldest() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(2);
        let a = addr([203, 0, 113, 6], 1); // has data, oldest
        let b = addr([203, 0, 113, 7], 2); // no data, t0+30
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        pool.note_departure(0, b, DataDelivered::No, t0 + secs(30));
        // Admit c at capacity (no data, t0+40): b is older among no-data
        // -> b evicted, a (has data) protected.
        let c = addr([203, 0, 113, 8], 3);
        pool.note_departure(1, c, DataDelivered::No, t0 + secs(40));
        assert!(pool.entries.contains_key(&a));
        assert!(pool.entries.contains_key(&c));
        assert!(!pool.entries.contains_key(&b));
        // Admit d (has data, t0+50): c is still the no-data one (despite
        // being newer) -> c evicted.
        let d = addr([203, 0, 113, 9], 4);
        pool.note_departure(0, d, DataDelivered::Yes, t0 + secs(50));
        assert!(pool.entries.contains_key(&a));
        assert!(pool.entries.contains_key(&d));
        assert!(!pool.entries.contains_key(&c));
        // Admit e (has data, t0+60): all have data -> oldest last_ok a
        // evicted.
        let e = addr([203, 0, 113, 11], 5);
        pool.note_departure(0, e, DataDelivered::Yes, t0 + secs(60));
        assert!(pool.entries.contains_key(&d));
        assert!(pool.entries.contains_key(&e));
        assert!(!pool.entries.contains_key(&a));
    }

    /// A repeated departure for the same address overwrites the old entry
    /// (no over-cap from overwriting).
    #[test]
    fn re_departure_overwrites_same_addr() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(2);
        let a = addr([203, 0, 113, 10], 6881);
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        pool.note_departure(0, a, DataDelivered::Yes, t0 + secs(5));
        assert_eq!(pool.len(), 1);
    }

    /// Ban removal: clears by IP (same for IPv6); entries for other IPs
    /// unaffected.
    #[test]
    fn remove_ip_clears_banned_peer_only() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP);
        let a = addr([203, 0, 113, 11], 1);
        let b = addr([203, 0, 113, 12], 2);
        let v6 = addr6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 3);
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        pool.note_departure(0, b, DataDelivered::Yes, t0);
        pool.note_departure(0, v6, DataDelivered::Yes, t0);
        pool.remove_ip(a.ip());
        assert!(!pool.entries.contains_key(&a));
        assert!(pool.entries.contains_key(&b));
        assert!(pool.entries.contains_key(&v6));
    }

    /// Dequeue burst limit + optimistic advance (lost-result self-heal: no
    /// duplicate dequeue, re-dial on backoff). An armed entry's optimistic
    /// advance = the 60s regime ([`miss_wait`]).
    #[test]
    fn due_batch_limit_and_optimistic_advance() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(true);
        for i in 0..(REDIAL_SWEEP_BATCH as u8 + 3) {
            let oct = [203, 0, 113, 20 + i];
            pool.note_departure(0, addr(oct, 6881), DataDelivered::Yes, t0);
        }
        let first = pool.due(t0 + secs(60));
        assert_eq!(first.len(), REDIAL_SWEEP_BATCH);
        // An immediate re-sweep: dequeued entries have advanced and do not
        // reappear (no busy loop, no duplicate dials); the remaining 3 are
        // still due and held for the next sweep by the batch limit —
        // limiting drops nothing.
        assert_eq!(pool.due(t0 + secs(60)).len(), 3);
        assert!(pool.due(t0 + secs(60)).is_empty());
        // Lost result reports: dequeued entries self-heal and re-dequeue
        // at their optimistic advance point (armed -> +miss_wait = 60s).
        let t1 = t0 + secs(60);
        let healed = pool.due(t1 + secs(120));
        assert_eq!(healed.len(), REDIAL_SWEEP_BATCH);
        // Remaining entries (including second-round advanced ones) drain
        // wave by wave: progress within the batch limit until empty.
        let mut waves = 0;
        while pool.len() > 0 {
            let now = t1 + secs(120) + secs(180) * (waves as u32 + 1);
            for (_, a) in pool.due(now) {
                pool.note_result(&a, RedialOutcome::Connected, now);
            }
            waves += 1;
            assert!(waves < 20, "pool did not drain");
        }
    }

    /// Structural statement of had_data and stale-DHT isolation: the only
    /// admission path is note_departure; unverified addresses have no path
    /// into the pool (due never yields unknown addresses).
    #[test]
    fn unknown_addrs_never_surface() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP);
        pool.note_departure(0, addr([203, 0, 113, 30], 6881), DataDelivered::Yes, t0);
        let unknown = addr([198, 51, 100, 1], 6881); // a bare address never admitted via note_departure
        pool.note_result(&unknown, RedialOutcome::Failed, t0 + secs(61));
        pool.note_connected(&unknown);
        assert_eq!(pool.len(), 1);
        let due = pool.due(t0 + secs(61));
        assert_eq!(due, vec![(0, addr([203, 0, 113, 30], 6881))]);
    }
}
