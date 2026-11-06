//! Per-source error-reply rate limiting (token bucket).
//!
//! Why limit: an error reply is itself a bandwidth-amplification vector —
//! a peer trades one small malformed query for one error reply, and
//! unbounded error replying would be an amplifier. The per-source token
//! bucket pins error traffic to a constant bound: an empty bucket means
//! *silent, zero replies* toward that source (BEP5 has no "overloaded"
//! code; libtorrent likewise treats silence as the anti-amplification
//! baseline for malformed input — the missing-y reply in `node.cpp` is
//! commented out with a magnification note).
//!
//! # Constants (local values; no BEP/reference precedent)
//!
//! Neither libtorrent nor aria2 rate-limits error replies (libtorrent's
//! closest protection is the process-level socket quota `has_quota()`,
//! `node.cpp` — process-wide, not per-source). Local values and rationale:
//!
//! - [`ERROR_REPLY_RATE_PER_MIN`] = 10: the design bound ("<=10/min"). In
//! a healthy run error replies are ~0 (only bad peers / bad-token races
//! trigger them); 10/min is ~0.17 replies/s at <= ~60B per reply, i.e.
//! ~8B/s per source — a ~60B malformed query can never draw more reply
//! bytes than it sent (amplification < 1:1).
//! - [`ERROR_REPLY_BURST`] = 10 (bucket capacity = one full minute of
//! budget, spendable instantly): headroom for legitimate races — within
//! the two-generation token window (10min rotation, aria2
//! `DHTConstants.h`), an announce carrying the old token is a normal
//! race and the peer recovers by refetching get_peers; a 10-reply burst
//! covers that, then silence.
//! - [`ERROR_LIMITER_MAX_SOURCES`] = 4096: hard cap on per-source state
//! (~200KB, bounded), evicting the least-recently-active entry (same
//! rationale as `wire::MAX_PEER_RECORD_KEYS`). An evicted source
//! re-enters with a fresh budget — but the absolute per-source 10/min
//! bound does not depend on table completeness: an attacker forging
//! many sources still gets a per-source bound (unbounded state growth
//! is what this cap prevents).
//!
//! # Implementation notes
//!
//! Tokens are accounted in integer micro-units (1 token = 10^6 units);
//! refill grants whole [`REFILL_PERIOD`]s truncated down, and the
//! accounting anchor advances only on a successful take (rejected probes
//! do not touch state: sub-period slack accumulates, repeated probing
//! never forfeits earned tokens; an empty-bucket source is also the top
//! eviction candidate) — deterministic, testable boundaries (floating-
//! point accumulation jitters by ±1 at exact boundaries), and downward
//! truncation is the conservative direction for amplification defense.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Per-source sustained error-reply rate cap (replies/minute). Rationale
/// in the module docs.
pub(super) const ERROR_REPLY_RATE_PER_MIN: u64 = 10;

/// Per-source bucket capacity (replies; starts full, spendable
/// instantly). Rationale in the module docs.
pub(super) const ERROR_REPLY_BURST: u64 = 10;

/// Hard cap on per-source state table entries (prevents unbounded memory
/// growth from many sources).
pub(super) const ERROR_LIMITER_MAX_SOURCES: usize = 4096;

/// Accounting unit for one token (1 token = 10^6 micro-units; integer
/// math).
const TOKEN_MICRO: u64 = 1_000_000;

/// Period to refill one token = 60s / per-minute rate (10 -> 6s).
const REFILL_PERIOD: Duration = Duration::from_secs(60 / ERROR_REPLY_RATE_PER_MIN);

/// Per-source bucket: remaining tokens (micro-units) + last accounting
/// instant.
struct Bucket {
    tokens_micro: u64,
    updated: Instant,
}

/// Per-source error-reply limiter (owned by the DhtEngine actor;
/// lock-free).
pub(super) struct ErrorReplyLimiter {
    buckets: HashMap<IpAddr, Bucket>,
}

impl ErrorReplyLimiter {
    pub(super) fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// Admit one error reply (true = send; false = bucket empty, silently
    /// dropped).
    ///
    /// Keyed by source IP (same IP on different ports shares one budget —
    /// amplification defense is per host).
    pub(super) fn admit(&mut self, source: IpAddr, now: Instant) -> bool {
        if !self.buckets.contains_key(&source) {
            if self.buckets.len() >= ERROR_LIMITER_MAX_SOURCES {
                // Capacity reached: evict the least-recently-active entry
                // (hardening; see the module docs).
                let oldest = self
                    .buckets
                    .iter()
                    .min_by_key(|(_, b)| b.updated)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.buckets.remove(&k);
                }
            }
            self.buckets.insert(
                source,
                Bucket {
                    tokens_micro: ERROR_REPLY_BURST * TOKEN_MICRO,
                    updated: now,
                },
            );
        }
        let Some(bucket) = self.buckets.get_mut(&source) else {
            // Just inserted above; unreachable; defensively treat as rejected.
            return false;
        };
        // Whole-period refill truncated down (the conservative direction,
        // see the module docs); the anchor advances only on a successful
        // take — rejected probes do not touch state, sub-period slack
        // accumulates, repeated probing never forfeits earned tokens.
        let periods = elapsed_periods(bucket.updated, now);
        let cap = ERROR_REPLY_BURST * TOKEN_MICRO;
        bucket.tokens_micro = (bucket.tokens_micro as u128)
            .saturating_add(periods.saturating_mul(u128::from(TOKEN_MICRO)))
            .min(u128::from(cap)) as u64;
        if bucket.tokens_micro >= TOKEN_MICRO {
            bucket.tokens_micro -= TOKEN_MICRO;
            bucket.updated = now;
            true
        } else {
            false
        }
    }
}

/// Whole refill periods between `start` and `now` (0 on a non-monotonic
/// clock).
fn elapsed_periods(start: Instant, now: Instant) -> u128 {
    // Duration::as_micros is always u128; the period is nonzero (60/10);
    // the zero branch is defensive.
    let period = REFILL_PERIOD.as_micros();
    if period == 0 {
        return 0;
    }
    now.saturating_duration_since(start).as_micros() / period
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(octet: u8) -> IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, octet))
    }

    /// Threshold boundary: a full bucket admits exactly BURST replies, the
    /// next must be silent (the anti-amplification assertion — zero
    /// replies over budget); per-source budgets are independent.
    #[test]
    fn burst_boundary_then_silence_per_source() {
        let t0 = Instant::now();
        let mut lim = ErrorReplyLimiter::new();
        for i in 0..ERROR_REPLY_BURST {
            assert!(
                lim.admit(src(1), t0),
                "item {} within the full bucket must be admitted",
                i + 1
            );
        }
        assert!(
            !lim.admit(src(1), t0),
            "exhausted bucket must stay silent (anti-amplification)"
        );
        assert!(
            !lim.admit(src(1), t0 + Duration::from_secs(1)),
            "less than one refill period must not recover"
        );
        // Per-source independence: another source's full bucket is
        // unaffected by the first source's exhaustion.
        assert!(lim.admit(src(2), t0));
    }

    /// Refill (window reset) boundaries: one token per 6s period; after a
    /// full 60s window an untouched bucket recovers its whole budget
    /// (table-driven).
    #[test]
    fn refill_window_reset_boundaries() {
        let t0 = Instant::now();
        let mut lim = ErrorReplyLimiter::new();
        for _ in 0..ERROR_REPLY_BURST {
            assert!(lim.admit(src(1), t0));
        }
        // 5s < one refill period (6s) -> still silent.
        assert!(!lim.admit(src(1), t0 + Duration::from_secs(5)));
        // Exactly 6s -> exactly 1 token back, then silent again.
        assert!(lim.admit(src(1), t0 + Duration::from_secs(6)));
        assert!(!lim.admit(src(1), t0 + Duration::from_secs(6)));
        // Exactly 60s (54s since the last take = 9 periods): 9 tokens back
        // (whole-period conservative accounting), silent after the 9th.
        let mut refilled = 0u64;
        for _ in 0..ERROR_REPLY_BURST {
            if lim.admit(src(1), t0 + Duration::from_secs(60)) {
                refilled += 1;
            } else {
                break;
            }
        }
        assert_eq!(refilled, 9, "54s / 6s = 9 tokens (rounded down)");
        // A never-touched source: a full 60s window -> all 10 back (window
        // reset).
        let mut lim2 = ErrorReplyLimiter::new();
        for _ in 0..ERROR_REPLY_BURST {
            assert!(lim2.admit(src(3), t0));
        }
        for _ in 0..ERROR_REPLY_BURST {
            assert!(
                lim2.admit(src(3), t0 + Duration::from_secs(60)),
                "an untouched full window recovers the whole budget"
            );
        }
        assert!(!lim2.admit(src(3), t0 + Duration::from_secs(60)));
    }

    /// Capacity eviction: a full table lets a new source evict the
    /// least-recently-active entry; the evicted source re-enters with
    /// fresh budget (module docs: amplification defense does not depend on
    /// table completeness).
    #[test]
    fn capacity_eviction_evicts_least_recently_updated() {
        let t0 = Instant::now();
        let mut lim = ErrorReplyLimiter::new();
        // 4096 distinct sources inserted at strictly increasing instants
        // fill the table to capacity; the earliest insertion has the
        // oldest updated (millisecond order, no ties — deterministic
        // eviction).
        for i in 0..ERROR_LIMITER_MAX_SOURCES {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                u32::from_be_bytes([198, 51, 100, 0]) + i as u32,
            ));
            lim.admit(ip, t0 + Duration::from_millis(i as u64));
        }
        let first = std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be_bytes([
            198, 51, 100, 0,
        ])));
        let fresh = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1));
        lim.admit(fresh, t0 + Duration::from_secs(2));
        assert!(
            !lim.buckets.contains_key(&first),
            "least-recently-active entry should be evicted"
        );
        assert!(
            lim.buckets.contains_key(&fresh),
            "new source should enter the table"
        );
        assert_eq!(
            lim.buckets.len(),
            ERROR_LIMITER_MAX_SOURCES,
            "table capacity stays constant (bounded)"
        );
    }
}
