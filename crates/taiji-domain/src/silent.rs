//! Silent-abandon failure ledger for endpoints (closes the redial long
//! tail toward dead discovery-face peers).
//!
//! Problem governed: when a dial plan exhausts, the failure stream shows
//! endpoints that discovery sources keep re-supplying (tracker re-supply
//! has no dedup window; DHT/PEX re-supply likewise) with zero memory of
//! the endpoint being dead. This module keeps a per-endpoint consecutive-
//! silent-abandon count that drives escalating backoff and a cooldown,
//! cutting wasted outbound traffic.
//!
//! Classification (reusing the existing dial-failure classification
//! face): at plan exhaustion, `dial_attempts` containing `handshake` =
//! TCP connect succeeded but the BT handshake did not complete / the uTP
//! stream went silent within the handshake budget (the downstream
//! presentation of the give-up semantics of
//! [`taiji_io::utp::UtpError::Timeout`]). `connect-refused` /
//! `connect-timeout` / `connect-error` = the endpoint is definitely
//! unreachable, not a silent signal (transient network jitter records no
//! cooldown). The verdict = the engine transport face's plan-silent
//! judgment (any `handshake` arm in the plan means silent — a plan that
//! could observe uTP silence necessarily failed on all arms: any arm
//! completing the handshake is a successful dial, and the silent count
//! resets immediately).
//!
//! Upstream anchor mapping: docs/design/domain-policies.md (libtorrent
//! endpoint-granularity failcount semantics; the escalating exponential
//! backoff is an intentional, interoperability-neutral divergence — the
//! 120s base = 2 x min_reconnect_time keeps silent endpoints more
//! aggressive than previously-successful peers).
//!
//! Relations to existing faces (reused side by side, minimal surface —
//! main-loop exclusive, no shared lock, same discipline as
//! [`crate::redial::RedialPool`]/DialDedup):
//! - Redial pool: semantics untouched (60s base / escalation /
//! 3-failure eviction / previously-successful peers only). Redial
//! dials are **exempt** from this ledger's gate (that face manages its
//! own failure policy; tightening it is out of bounds), but redial
//! dials' outcomes still enter the ledger (silent evidence is
//! source-agnostic). The redial sweep batch limit (at most
//! REDIAL_SWEEP_BATCH = 12 per sweep) bounds the exempt outbound rate,
//! orthogonal to this ledger.
//! - dht_dial_dedup: the spatial dedup window (no repeated dial to the
//! same address within 10min, source-agnostic) is untouched; this
//! ledger layers **outcome memory** on top (dialed and silent ->
//! escalating backoff/cooldown); the two are orthogonal. Tracker
//! sources have no dedup window — this ledger is the only face that
//! converges that gap by outcome.
//! - Hole punching (punch dial): gate-exempt — a rendezvous connect
//! instruction is **external new evidence** of reachability asserted by
//! the introducer (same spirit as libtorrent lowering failcount on a
//! tracker re-report), and punched peers are often NAT peers that are
//! silent on direct dial but alive via hole punching — a cooldown gate
//! blocking hole punches would defeat that face. Punch dials are
//! bounded by the dedup window and the 4/60s PeerTask rate limit, no
//! amplification risk; their outcomes still enter the ledger.
//!
//! Face isolation: the silent count only arises from "all plan arms
//! failed" (above), so demotion never blocks a dial that would have
//! succeeded — a plan that can succeed produces a success report, which
//! resets the count immediately. uTP silence does not separately punish
//! the TCP face: a TCP-healthy peer never accumulates silent counts (the
//! plan succeeds on its TCP arm).
//!
//! Bounded discipline: capacity capped at [`SILENT_BOOK_CAP`], evicting
//! the oldest `last_seen` (stalest evidence first); main-loop
//! tick/event driven, all time is an injected `Instant`, unit tests never
//! sleep.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Escalating backoff base (the redial wait after a silent endpoint's 1st
/// consecutive silence): 120s = 2 x libtorrent min_reconnect_time
/// (`src/settings_pack.cpp`) — distinguishes silent endpoints from
/// previously-successful peers (REDIAL_BASE = 60s base); weaker evidence,
/// more aggressive backoff.
pub const SILENT_BACKOFF_BASE: Duration = Duration::from_secs(120);

/// Escalating backoff cap (10min): if the curve reaches the top before
/// the cooldown threshold, waits stop growing.
pub const SILENT_BACKOFF_CAP: Duration = Duration::from_secs(600);

/// Cooldown threshold (consecutive silent count): matches libtorrent
/// max_failcount = 3 (`src/settings_pack.cpp`; `src/peer_list.cpp` — at
/// the threshold the peer loses connect-candidate status). Reached -> the
/// endpoint enters the cooldown table.
pub const SILENT_MAX_FAILS: u32 = 3;

/// Cooldown duration (after the threshold the endpoint leaves
/// discovery-face dialing; expiry auto-recovers and resets the count):
/// 1800s = announce interval magnitude (same reason as the cap — past it
/// the tracker re-supplies new candidates).
pub const SILENT_COOLDOWN: Duration = Duration::from_secs(1800);

/// Ledger capacity cap (bounded): 1/4 of the DhtDialDedup cap of 4096 —
/// silent counts only accumulate for endpoints that were dialed and went
/// silent, so scale is bounded by the discovery dial rate.
pub const SILENT_BOOK_CAP: usize = 1024;

/// Escalating backoff curve: `min(BASE x 2^(fails-1), CAP)` (exponential +
/// cap; an intentional divergence — libtorrent is linear
/// `(failcount+1) x min_reconnect_time`, `src/peer_list.cpp`, this module
/// specifies exponential). `fails` = consecutive silent count so far
/// (>= 1): 1 -> 120s, 2 -> 240s, 3 -> 480s, 4 -> 600s capped.
pub fn silent_backoff(fails: u32) -> Duration {
    let step = fails.saturating_sub(1).min(31);
    SILENT_BACKOFF_CAP.min(
        SILENT_BACKOFF_BASE
            .checked_mul(1u32 << step)
            .unwrap_or(SILENT_BACKOFF_CAP),
    )
}

/// Discovery-face dial admission decision (the [`SilentBook::admit`]
/// return). Both demotion states = skip the dial for discovery sources
/// (tracker/DHT/PEX); they differ only in log attribution (backoff window
/// vs cooldown window). Redial pool / hole-punch sources do not pass
/// through this decision (exempt; the module docs' relations section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SilentVerdict {
    /// Allowed (no record / backoff window passed / cooldown expired —
    /// recovery removes the entry and resets the count).
    Allowed,
    /// Inside the escalating backoff window (fails < threshold): the next
    /// attempt is no earlier than the entry's `defer_until`.
    Backoff,
    /// Inside the cooldown window (fails >= threshold): always skipped
    /// until expiry.
    Cooldown,
}

/// A ledger entry: one endpoint's consecutive-silent-failure memory.
#[derive(Debug)]
struct SilentEntry {
    /// Consecutive silent abandons (cleared when the entry is removed on
    /// a success report; same on cooldown expiry recovery). Upper bound =
    /// [`SILENT_MAX_FAILS`], after which cooldown starts; never grows
    /// unbounded.
    fails: u32,
    /// Escalating backoff window: discovery-face dials skip before this
    /// instant (`now + silent_backoff(fails)`).
    defer_until: Instant,
    /// Cooldown window (None = not cooling): discovery-face dials skip
    /// before this instant; expiry recovers and resets.
    cooldown_until: Option<Instant>,
    /// Instant of the most recent silent evidence (bounded eviction order
    /// key: stalest evidence evicted first).
    last_seen: Instant,
}

/// Endpoint silent-abandon failure ledger (main-loop exclusive, no shared
/// lock — events converge through the dial outcome report channel and are
/// processed in order; the gate decision is read/written synchronously at
/// dial assembly).
#[derive(Debug, Default)]
pub struct SilentBook {
    entries: HashMap<SocketAddr, SilentEntry>,
    cap: usize,
}

impl SilentBook {
    pub fn new(cap: usize) -> SilentBook {
        SilentBook {
            entries: HashMap::new(),
            cap: cap.max(1),
        }
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

    /// Discovery-face dial admission decision: cooldown-expired entries
    /// are lazily removed here (= automatic recovery at expiry with the
    /// count reset — never a permanent block); an expired backoff window
    /// does not reset the count (continuity preserved, the next silence
    /// escalates directly).
    pub fn admit(&mut self, addr: &SocketAddr, now: Instant) -> SilentVerdict {
        let Some(entry) = self.entries.get(addr) else {
            return SilentVerdict::Allowed;
        };
        if let Some(until) = entry.cooldown_until {
            if until <= now {
                // Cooldown expired -> recover (removal = count reset; the
                // peer may have come back to life).
                self.entries.remove(addr);
                return SilentVerdict::Allowed;
            }
            return SilentVerdict::Cooldown;
        }
        if entry.defer_until > now {
            return SilentVerdict::Backoff;
        }
        SilentVerdict::Allowed
    }

    /// Consecutive silent count readout (a candidate-sort-key failcount
    /// surface, read-only with no side effects; no entry = 0). Same
    /// meaning as libtorrent's failcount (peer_list.cpp sorts lower first
    /// — this readout feeds that key).
    pub fn fails(&self, addr: &SocketAddr) -> u32 {
        self.entries.get(addr).map_or(0, |e| e.fails)
    }

    /// Silent-abandon accounting: consecutive count +1 (same direction as
    /// libtorrent inc_failcount, `src/peer_list.cpp` — the count is
    /// bounded, never unbounded), the backoff window advances along the
    /// curve, and at [`SILENT_MAX_FAILS`] the cooldown window starts.
    /// Non-silent failures do not enter here (definitely unreachable is
    /// not silent; see the module docs' classification section) — count
    /// continuity preserved.
    pub fn note_silent(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(e) = self.entries.get(&addr) {
            if e.cooldown_until.is_some_and(|until| until > now) {
                // While cooling, no new dial should arise (the gate blocks
                // it) — defensive: extend the cooldown window and do not
                // increment (no path exists while evidence and cooldown
                // windows do not overlap).
                return;
            }
        }
        let entry = self.entries.entry(addr).or_insert(SilentEntry {
            fails: 0,
            defer_until: now,
            cooldown_until: None,
            last_seen: now,
        });
        entry.fails = entry.fails.saturating_add(1);
        entry.last_seen = now;
        entry.defer_until = now + silent_backoff(entry.fails);
        if entry.fails >= SILENT_MAX_FAILS {
            entry.cooldown_until = Some(now + SILENT_COOLDOWN);
        }
        // Over-cap eviction (bounded): stalest evidence out first (min
        // last_seen).
        if self.entries.len() > self.cap {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| *k);
            if let Some(victim) = victim {
                self.entries.remove(&victim);
            }
        }
    }

    /// Handshake succeeded (new evidence) -> entry removed, count reset
    /// (the peer-revival face; same direction as libtorrent zeroing
    /// failcount after a successful connection, `src/peer_list.cpp`).
    pub fn note_connected(&mut self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redial::{DataDelivered, REDIAL_POOL_CAP, RedialOutcome, RedialPool};
    use std::net::IpAddr;

    fn addr(oct: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from(oct), port)
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Backoff curve table (the backoff sequence unit test): 120s base,
    /// exponential doubling, 600s cap (including the u32 shift saturation
    /// face).
    #[test]
    fn backoff_table() {
        let cases: [(u32, u64); 7] = [
            (1, 120),
            (2, 240),
            (3, 480),
            (4, 600), // 960 -> cap 600
            (5, 600),
            (31, 600),
            (u32::MAX, 600), // shift saturation path neither overflows nor panics
        ];
        for (fails, want_s) in cases {
            assert_eq!(silent_backoff(fails), secs(want_s), "fails={fails}");
        }
        assert_eq!(silent_backoff(u32::MAX), SILENT_BACKOFF_CAP);
    }

    /// Threshold boundary + cooldown expiry recovery (table-driven):
    /// 1, 2 silences = allowed outside the backoff window (no cooldown);
    /// the 3rd = cooldown; expiry auto-recovers and **resets the count**
    /// (the next round of silence re-escalates from 120s, not a cooldown
    /// continuation).
    #[test]
    fn threshold_boundary_and_cooldown_recovery() {
        let t0 = Instant::now();
        let mut book = SilentBook::new(SILENT_BOOK_CAP);
        let a = addr([203, 0, 113, 1], 6881);

        // Silence #1: backoff window 120s.
        book.note_silent(a, t0);
        assert_eq!(book.admit(&a, t0 + secs(60)), SilentVerdict::Backoff);
        assert_eq!(book.admit(&a, t0 + secs(120)), SilentVerdict::Allowed);
        // Silence #2 (silent again after the window expired; continuity
        // preserved): backoff window 240s.
        book.note_silent(a, t0 + secs(120));
        assert_eq!(book.admit(&a, t0 + secs(240)), SilentVerdict::Backoff);
        assert_eq!(book.admit(&a, t0 + secs(360)), SilentVerdict::Allowed);
        // Silence #3: reaches SILENT_MAX_FAILS = 3 -> cooldown 1800s (the
        // backoff window is subsumed by cooldown).
        book.note_silent(a, t0 + secs(360));
        assert_eq!(book.admit(&a, t0 + secs(361)), SilentVerdict::Cooldown);
        assert_eq!(book.admit(&a, t0 + secs(480)), SilentVerdict::Cooldown);
        assert_eq!(book.admit(&a, t0 + secs(2159)), SilentVerdict::Cooldown);
        // Expiry: automatic recovery + count reset — the next silence
        // starts over from 120s.
        assert_eq!(book.admit(&a, t0 + secs(2160)), SilentVerdict::Allowed);
        book.note_silent(a, t0 + secs(2160));
        assert_eq!(book.admit(&a, t0 + secs(2220)), SilentVerdict::Backoff);
        assert_eq!(book.admit(&a, t0 + secs(2280)), SilentVerdict::Allowed);
    }

    /// Revival success resets the count: 2 silences (mid-escalation) -> a
    /// handshake success report -> count cleared; the next silence starts
    /// from level 1 and does not enter cooldown.
    #[test]
    fn success_resets_count() {
        let t0 = Instant::now();
        let mut book = SilentBook::new(SILENT_BOOK_CAP);
        let a = addr([203, 0, 113, 2], 51413);
        book.note_silent(a, t0);
        book.note_silent(a, t0 + secs(120));
        // Success report (peer revived): entry removed.
        book.note_connected(&a);
        assert_eq!(book.admit(&a, t0 + secs(121)), SilentVerdict::Allowed);
        // Silence again = level 1 (120s), not level-3 cooldown.
        book.note_silent(a, t0 + secs(130));
        assert_eq!(book.admit(&a, t0 + secs(140)), SilentVerdict::Backoff);
        assert_eq!(book.admit(&a, t0 + secs(250)), SilentVerdict::Allowed);
        assert_eq!(book.admit(&a, t0 + secs(3000)), SilentVerdict::Allowed);
    }

    /// Unknown addresses are always allowed (no record, no side effects);
    /// reports for evicted/unbooked addresses are idempotent without
    /// panic (defensive).
    #[test]
    fn unknown_addr_allowed_and_note_idempotent() {
        let t0 = Instant::now();
        let mut book = SilentBook::new(SILENT_BOOK_CAP);
        let a = addr([198, 51, 100, 1], 6881);
        assert_eq!(book.admit(&a, t0), SilentVerdict::Allowed);
        assert_eq!(book.len(), 0);
        // A success report for a never-booked address: nothing to clear,
        // no side effects.
        book.note_connected(&a);
        assert_eq!(book.len(), 0);
    }

    /// Bounded eviction: when full, new evidence evicts the oldest
    /// last_seen; the new entry itself is never evicted; capacity stays
    /// within the cap.
    #[test]
    fn cap_evicts_oldest_evidence() {
        let t0 = Instant::now();
        let mut book = SilentBook::new(2);
        let a = addr([203, 0, 113, 3], 1);
        let b = addr([203, 0, 113, 4], 2);
        let c = addr([203, 0, 113, 5], 3);
        book.note_silent(a, t0);
        book.note_silent(b, t0 + secs(30));
        assert_eq!(book.len(), 2);
        // Admit c at capacity: a (oldest at t0) evicted.
        book.note_silent(c, t0 + secs(60));
        assert_eq!(book.len(), 2);
        assert_eq!(book.admit(&a, t0 + secs(61)), SilentVerdict::Allowed);
        assert_eq!(book.admit(&b, t0 + secs(61)), SilentVerdict::Backoff);
        assert_eq!(book.admit(&c, t0 + secs(61)), SilentVerdict::Backoff);
        // After b's memory is refreshed (newer last_seen), admit d: evict
        // c instead? No — c (t0+60) is still older than b (t0+90) -> c
        // evicted, b protected.
        book.note_silent(b, t0 + secs(90));
        let d = addr([203, 0, 113, 6], 4);
        book.note_silent(d, t0 + secs(120));
        assert_eq!(book.len(), 2);
        assert_eq!(book.admit(&c, t0 + secs(121)), SilentVerdict::Allowed);
        assert_eq!(book.admit(&b, t0 + secs(121)), SilentVerdict::Backoff);
        assert_eq!(book.admit(&d, t0 + secs(121)), SilentVerdict::Backoff);
    }

    /// Degenerate capacity-1 form (the cap.max(1) floor): always
    /// admissible, length always 1.
    #[test]
    fn cap_floor_one() {
        let t0 = Instant::now();
        let mut book = SilentBook::new(0);
        book.note_silent(addr([203, 0, 113, 7], 1), t0);
        book.note_silent(addr([203, 0, 113, 8], 2), t0 + secs(1));
        assert_eq!(book.len(), 1);
    }

    /// The redial pool and this ledger do not interfere (structural
    /// assertion): while the same endpoint cools in the silent ledger,
    /// the redial pool's due dequeue/backoff/eviction rhythm is untouched
    /// (no cross-references between the two books — the rule: semantics
    /// for previously-successful peers are never tightened); conversely
    /// the ledger's count escalates independently. (fast pinned to 0 —
    /// the regular backoff regime; this test asserts the two books are
    /// orthogonal, the fast gradient belongs to redial.rs's decision
    /// table, locked by `miss_ladder_decision_table`.)
    #[test]
    fn pool_independent_of_silent_cooldown() {
        let t0 = Instant::now();
        let mut pool = RedialPool::new(REDIAL_POOL_CAP).with_fast_reconnect(false);
        let mut book = SilentBook::new(SILENT_BOOK_CAP);
        let a = addr([203, 0, 113, 9], 6881);
        pool.note_departure(0, a, DataDelivered::Yes, t0);
        book.note_silent(a, t0);
        book.note_silent(a, t0 + secs(120));
        book.note_silent(a, t0 + secs(360)); // -> cooldown
        assert_eq!(book.admit(&a, t0 + secs(400)), SilentVerdict::Cooldown);
        // The redial pool still dequeues the same endpoint at its 60s due
        // time (semantics untouched).
        assert_eq!(
            pool.due(t0 + secs(60)),
            vec![(0, a)],
            "cooldown must not touch the pool cadence"
        );
        // The pool's own 3-failure eviction proceeds normally (independent
        // of the ledger count).
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(62));
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(125));
        pool.note_result(&a, RedialOutcome::Failed, t0 + secs(250));
        assert_eq!(pool.len(), 0, "eviction unchanged");
        // The ledger cooldown is unaffected by the pool eviction.
        assert_eq!(book.admit(&a, t0 + secs(300)), SilentVerdict::Cooldown);
        // Reverse: a previously-successful peer's redial succeeds -> pool
        // entry removed + ledger count cleared (each book receives the
        // same success report; neither acts for the other).
        pool.note_departure(0, a, DataDelivered::Yes, t0 + secs(1000));
        book.note_silent(a, t0 + secs(1000));
        pool.note_result(&a, RedialOutcome::Connected, t0 + secs(1060));
        book.note_connected(&a);
        assert_eq!(pool.len(), 0);
        assert_eq!(book.admit(&a, t0 + secs(1061)), SilentVerdict::Allowed);
    }

    /// Replay of the measured head-endpoint scenario (simulation): a
    /// persistently silent endpoint with the discovery face re-supplying
    /// the address every 30s (the fast re-supply upper-bound model of the
    /// tracker source's no-dedup-window gap). Over an equal horizon
    /// (2h56m = 10,560s) actual dials drop >= 10x versus the recorded
    /// baseline.
    #[test]
    fn closure5_head_replay_suppression_ge_10x() {
        let t0 = Instant::now();
        let mut book = SilentBook::new(SILENT_BOOK_CAP);
        let a = addr([70, 36, 54, 195], 51413); // the recorded top-1 endpoint shape
        let tick = secs(30);
        let horizon = secs(2 * 3600 + 56 * 60);
        const BASELINE_DIALS: u64 = 428; // recorded baseline
        let mut dials: u64 = 0;
        let mut now = t0;
        while now < t0 + horizon {
            if book.admit(&a, now) == SilentVerdict::Allowed {
                dials += 1;
                // All dial plan arms fail (silent) -> the outcome is
                // reported into the ledger.
                book.note_silent(a, now);
            }
            now += tick;
        }
        // Equal-horizon dial count under escalating backoff + cooldown:
        // 3 dials per 2160s cycle (two backoff steps +120s, +240s ->
        // cooldown 1800s -> recover and restart); 2h56m is exactly 5 full
        // cycles = 15 dials (versus the 428 baseline).
        assert!(
            dials * 10 <= BASELINE_DIALS,
            "replayed dials={dials} must be ≥10× below baseline {BASELINE_DIALS}"
        );
        assert_eq!(dials, 15, "curve must match the documented cadence");
    }
}
