//! Per-source rate limiting for inbound queries: token bucket + violation
//! suppression + bootstrap/PORT entry exemption.
//!
//! Why limit: the DHT UDP inbound face previously had no per-source
//! constraint beyond best-effort drops on demux queue overflow (dht channel
//! capacity 1024, `taiji-io/src/udp_demux.rs`) — a single source could
//! flood queries unboundedly (every ping/find_node/get_peers/announce_peer
//! triggers routing-table updates, closest-K computation, token generation
//! and reply encoding), the cheapest amplification surface. This module
//! puts a per-source (IP-keyed) token bucket plus violating-source
//! suppression in front of query handling:
//!
//! - Empty bucket => *silent drop* (BEP5 has no "overloaded" code; an
//!   error/201-style reply would itself become the amplifier — same
//!   trade-off as elsewhere: zero replies once over budget);
//! - After one full burst of *consecutive* over-budget drops
//!   (violations >= burst; rationale in the
//!   [`super::config::DHT_PER_SOURCE_QUERY_BURST`] docs) the source is
//!   suppressed for `suppress_secs` (default 60s): packets are silently
//!   dropped during the window; this is *not a permanent ban* (peers can
//!   come back), and expiry recovers automatically (refill back-fills by
//!   elapsed time, violations reset to zero — no management plane needed);
//! - Only the *query* face is limited: responses/error replies are not
//!   governed by this limiter (prevents a reflection loop); error *replies*
//!   are clamped independently per source by `error_limit` (two limiters,
//!   two faces);
//! - Bootstrap entry points and sources introduced by PORT messages are
//!   exempt ([`QueryRateLimiter::exempt`]): BEP42's "Requests ... should
//!   always be serviced" must hold — v6/new-node bootstrap must not be
//!   starved by the limiter (exemptions carry a TTL and a hard cap; not a
//!   permanent allowlist, see the [`EXEMPT_TTL`] docs).
//!
//! # Constants (engineering hardening)
//!
//! Rate/burst/suppression duration are config-injected (defaults and
//! rationale in the three config constants' docs); the following are pure
//! hardening constants:
//!
//! - [`QUERY_LIMITER_MAX_SOURCES`] = 4096: hard cap on the per-source
//!   state table (same rationale as
//!   `error_limit::ERROR_LIMITER_MAX_SOURCES` / `wire::MAX_PEER_RECORD_KEYS`),
//!   evicting the least-recently-active entry (last_seen). An evicted source
//!   re-enters with fresh budget — but the absolute per-source rate bound
//!   does not depend on table completeness: an attacker forging many
//!   sources still gets a per-source bound (unbounded state growth is what
//!   this cap prevents).
//! - [`EXEMPT_MAX_ENTRIES`] = 4096: exemption table hard cap (same
//!   rationale), evicting the oldest registration.
//! - [`EXEMPT_TTL`] = 10min: an exemption is a temporary bootstrap pass,
//!   not a permanent allowlist — prevents forged PORT messages from
//!   laundering arbitrary sources into a permanent bypass. 10min covers the
//!   worst bootstrap round (entry ping retries 10 x transaction timeout 10s
//!   = 100s, `DHTEntryPointNameResolveCommand.cc` passes 10) with ~6x
//!   margin and matches the in-tree token rotation window (10min,
//!   `DHTConstants.h`); sources still in the bootstrap face (re-bootstrap /
//!   PORT re-registration) renew automatically.
//!
//! # Implementation notes
//!
//! Tokens are accounted in integer micro-units (1 token = 1 query =
//! 10^6 units; identity: 1 token/s = 1 micro-token/us, so gain =
//! elapsed us x pps — pure integer math, no division). Refill truncates
//! downward (the conservative direction); the anchor advances only at a
//! successful take — rejected probes do not touch state, so sub-second
//! slack accumulates and repeated probing never forfeits earned tokens
//! (same as `error_limit`). Integer arithmetic has deterministic,
//! testable boundaries (floating-point accumulation jitters at exact
//! boundaries).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Accounting unit for one token (1 token = 1 query = 10^6 micro-units;
/// integer math).
const TOKEN_MICRO: u64 = 1_000_000;

/// Hard cap on per-source state table entries (prevents unbounded memory
/// growth from many sources).
pub(super) const QUERY_LIMITER_MAX_SOURCES: usize = 4096;

/// Hard cap on exemption table entries (same rationale).
pub(super) const EXEMPT_MAX_ENTRIES: usize = 4096;

/// Exemption entry lifetime (a temporary pass, not a permanent allowlist;
/// rationale in the module docs).
pub(super) const EXEMPT_TTL: Duration = Duration::from_secs(10 * 60);

/// Per-source state: token bucket + violation count + suppression window.
struct SourceState {
    /// Available tokens (micro-units; capacity = burst, full on cold start).
    tokens_micro: u64,
    /// Refill accounting anchor (advances only on a successful take).
    anchor: Instant,
    /// Last packet instant (including dropped queries); the eviction-order
    /// key, so a continuously sending suppressed source is not evicted for
    /// lack of successful takes.
    last_seen: Instant,
    /// Consecutive over-budget drop count (any successful take resets it —
    /// the "consecutive overrun" semantics).
    violations: u32,
    /// Suppression deadline (None = not suppressed; auto-recovers on expiry).
    suppressed_until: Option<Instant>,
}

/// Per-source inbound query rate limiter (owned by the DhtEngine actor;
/// lock-free).
pub(super) struct QueryRateLimiter {
    /// Sustained rate (queries/second).
    rate_pps: u32,
    /// Bucket capacity (queries; also the violation-escalation criterion).
    burst: u32,
    /// Suppression duration.
    suppress: Duration,
    /// Per-source state table (suppression inline; bounded, oldest
    /// last_seen evicted).
    sources: HashMap<IpAddr, SourceState>,
    /// Entry exemption table (bootstrap entries / PORT introductions;
    /// bounded, oldest registration evicted, valid within TTL).
    exempt: HashMap<IpAddr, Instant>,
    /// Total over-budget dropped queries (observable; asserted in tests).
    dropped: u64,
}

impl QueryRateLimiter {
    /// New limiter (parameters injected from [`super::config::DhtEngineConfig`]).
    pub(super) fn new(rate_pps: u32, burst: u32, suppress: Duration) -> Self {
        QueryRateLimiter {
            rate_pps,
            burst,
            suppress,
            sources: HashMap::new(),
            exempt: HashMap::new(),
            dropped: 0,
        }
    }

    /// Register an entry exemption (bootstrap entry / PORT source): inbound
    /// queries from this IP bypass the limiter within the TTL;
    /// re-registering renews.
    pub(super) fn exempt(&mut self, ip: IpAddr, now: Instant) {
        if !self.exempt.contains_key(&ip) && self.exempt.len() >= EXEMPT_MAX_ENTRIES {
            // Capacity reached: evict the oldest registration (hardening;
            // see module docs).
            let oldest = self
                .exempt
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.exempt.remove(&k);
            }
        }
        self.exempt.insert(ip, now);
    }

    /// Admit one inbound query (true = process; false = silently drop).
    ///
    /// Decision order: exemption -> suppression window -> token bucket.
    /// Keyed by source IP (same IP on different ports shares one budget —
    /// protection is per host, matching `error_limit`).
    pub(super) fn admit_query(&mut self, source: IpAddr, now: Instant) -> bool {
        // Bootstrap path first: exemption precedes the suppression check
        // (BEP42 "should always be serviced"); after TTL expiry the source
        // returns to normal limiting.
        if self.is_exempt(source, now) {
            return true;
        }
        if !self.sources.contains_key(&source) {
            if self.sources.len() >= QUERY_LIMITER_MAX_SOURCES {
                let oldest = self
                    .sources
                    .iter()
                    .min_by_key(|(_, s)| s.last_seen)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.sources.remove(&k);
                }
            }
            self.sources.insert(
                source,
                SourceState {
                    tokens_micro: u64::from(self.burst) * TOKEN_MICRO,
                    anchor: now,
                    last_seen: now,
                    violations: 0,
                    suppressed_until: None,
                },
            );
        }
        let Some(st) = self.sources.get_mut(&source) else {
            // Just inserted above; unreachable; defensively treat as rejected.
            self.dropped += 1;
            return false;
        };
        if let Some(until) = st.suppressed_until {
            if now < until {
                // Suppressed: silent drop (last_seen is still recorded, so a
                // continuously sending suppressed source is not evicted from
                // the table for lack of takes).
                st.last_seen = now;
                self.dropped += 1;
                return false;
            }
            // Expired: automatic recovery (not a permanent ban).
            st.suppressed_until = None;
            st.violations = 0;
        }
        // Refill: elapsed x rate truncated down (integer micro-token math:
        // 1 token/s = 1 micro-token/us, so gain = elapsed us x pps, no
        // division; the anchor advances only on a successful take).
        let elapsed_us = now.saturating_duration_since(st.anchor).as_micros();
        let cap = u128::from(self.burst) * u128::from(TOKEN_MICRO);
        let gain = elapsed_us * u128::from(self.rate_pps);
        st.tokens_micro = (u128::from(st.tokens_micro).saturating_add(gain).min(cap)) as u64;
        if st.tokens_micro >= TOKEN_MICRO {
            st.tokens_micro -= TOKEN_MICRO;
            st.anchor = now;
            st.violations = 0;
            st.last_seen = now;
            true
        } else {
            st.violations += 1;
            st.last_seen = now;
            self.dropped += 1;
            if st.violations >= self.burst {
                // A full burst of consecutive over-budget drops => suppress
                // (rationale in the config constant docs).
                st.suppressed_until = Some(now + self.suppress);
                st.violations = 0;
            }
            false
        }
    }

    /// Exemption check (valid within TTL; expired entries are lazily
    /// invalidated, their slots reclaimed by capacity eviction).
    fn is_exempt(&self, ip: IpAddr, now: Instant) -> bool {
        self.exempt
            .get(&ip)
            .is_some_and(|registered| now.saturating_duration_since(*registered) < EXEMPT_TTL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::engine::config::{
        DHT_PER_SOURCE_QUERY_BURST, DHT_PER_SOURCE_QUERY_RATE, DHT_SOURCE_SUPPRESS_SECS,
    };

    fn src(octet: u8) -> IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, octet))
    }

    fn limiter(rate: u32, burst: u32, suppress_secs: u64) -> QueryRateLimiter {
        QueryRateLimiter::new(rate, burst, Duration::from_secs(suppress_secs))
    }

    /// Whether the source is currently suppressed (reads internal state;
    /// avoids adding a method outside test builds).
    fn suppressed_at(lim: &QueryRateLimiter, ip: IpAddr, now: Instant) -> bool {
        lim.sources
            .get(&ip)
            .and_then(|st| st.suppressed_until)
            .is_some_and(|until| now < until)
    }

    /// Defaults match the config constants (25/50/60; see their docs).
    #[test]
    fn default_config_carries_local_ruling_values() {
        let cfg = crate::dht::engine::config::DhtEngineConfig::default();
        assert_eq!(cfg.per_source_query_rate, DHT_PER_SOURCE_QUERY_RATE);
        assert_eq!(cfg.per_source_query_rate, 25);
        assert_eq!(cfg.per_source_query_burst, DHT_PER_SOURCE_QUERY_BURST);
        assert_eq!(cfg.per_source_query_burst, 50);
        assert_eq!(cfg.suppress_secs, DHT_SOURCE_SUPPRESS_SECS);
        assert_eq!(cfg.suppress_secs, 60);
    }

    /// Bucket boundary: a full bucket admits exactly `burst` queries, the
    /// next one is silent; refill recovers exactly per elapsed microseconds
    /// (1s at rate=2 -> 2 queries).
    #[test]
    fn burst_boundary_then_refill_at_rate() {
        let t0 = Instant::now();
        // burst=4: the longest drop streak here is 2 (< burst=4), so
        // suppression is not triggered (escalation has a dedicated test).
        let mut lim = limiter(2, 4, 3600);
        for _ in 0..4 {
            assert!(lim.admit_query(src(1), t0));
        }
        assert!(
            !lim.admit_query(src(1), t0),
            "exhausted bucket must stay silent"
        );
        assert_eq!(lim.dropped, 1);
        // 0.5s < one-query period (rate=2 -> 500ms/query): no full token yet.
        assert!(!lim.admit_query(src(1), t0 + Duration::from_millis(499)));
        // Exactly 500ms -> refill of exactly 1 query; silent again right after.
        assert!(lim.admit_query(src(1), t0 + Duration::from_millis(500)));
        assert!(!lim.admit_query(src(1), t0 + Duration::from_millis(500)));
        // Capacity clamp: after 1h idle, refill does not exceed burst — 3
        // left after the first take, refilled to the cap of 4, four takes
        // then the fifth is silent.
        assert!(lim.admit_query(src(2), t0));
        for _ in 0..4 {
            assert!(lim.admit_query(src(2), t0 + Duration::from_secs(3600)));
        }
        assert!(!lim.admit_query(src(2), t0 + Duration::from_secs(3600)));
    }

    /// "Consecutive" semantics: a successful take resets the violation
    /// count — non-consecutive overruns do not escalate to suppression.
    #[test]
    fn admitted_query_resets_violation_streak() {
        let t0 = Instant::now();
        // rate=2/burst=3: 3 takes from full + 2 drops (violations=2 < 3, no
        // escalation); after a refilled take (count reset), 2 more drops
        // still do not suppress.
        let mut lim = limiter(2, 3, 3600);
        for _ in 0..3 {
            assert!(lim.admit_query(src(1), t0));
        }
        assert!(!lim.admit_query(src(1), t0));
        assert!(!lim.admit_query(src(1), t0));
        assert!(
            !suppressed_at(&lim, src(1), t0),
            "consecutive drops below burst do not suppress"
        );
        assert!(lim.admit_query(src(1), t0 + Duration::from_millis(600)));
        assert!(!lim.admit_query(src(1), t0 + Duration::from_millis(600)));
        assert!(!lim.admit_query(src(1), t0 + Duration::from_millis(600)));
        assert!(!suppressed_at(
            &lim,
            src(1),
            t0 + Duration::from_millis(600)
        ));
        // Third consecutive drop (= burst) => suppression.
        assert!(!lim.admit_query(src(1), t0 + Duration::from_millis(600)));
        assert!(suppressed_at(&lim, src(1), t0 + Duration::from_millis(600)));
    }

    /// Suppression window: refilled tokens are still silently dropped
    /// during it (the per-source bound collapses to 0); recovery happens
    /// exactly after the suppress duration, and the source is re-examined
    /// with a full bucket (not a permanent ban).
    #[test]
    fn suppression_window_expires_and_recovers() {
        let t0 = Instant::now();
        // rate=1/burst=1: first query admitted, the next drop suppresses
        // (violations 1 >= 1).
        let mut lim = limiter(1, 1, 60);
        assert!(lim.admit_query(src(1), t0));
        assert!(!lim.admit_query(src(1), t0));
        assert!(suppressed_at(&lim, src(1), t0));
        // Silent even past a refill period (1s) while suppressed.
        assert!(!lim.admit_query(src(1), t0 + Duration::from_secs(1)));
        assert!(suppressed_at(&lim, src(1), t0 + Duration::from_secs(1)));
        // Exactly 60s: automatic recovery (state flips + query admitted —
        // full bucket).
        assert!(
            !suppressed_at(&lim, src(1), t0 + Duration::from_secs(60)),
            "suppression must recover automatically on expiry"
        );
        assert!(
            lim.admit_query(src(1), t0 + Duration::from_secs(60)),
            "queries must be admitted after recovery (exemption-path assertion counterpart)"
        );
        // A full cycle can re-enter after recovery (suppression is not
        // one-shot).
        assert!(!lim.admit_query(src(1), t0 + Duration::from_secs(60)));
        assert!(suppressed_at(&lim, src(1), t0 + Duration::from_secs(60)));
    }

    /// Exemption path: bypasses the bucket within TTL (over-burst still
    /// admitted); reverts to normal limiting after TTL; re-registration
    /// renews.
    #[test]
    fn exempt_bypasses_limit_until_ttl() {
        let t0 = Instant::now();
        let mut lim = limiter(1, 1, 3600);
        lim.exempt(src(1), t0);
        // 100 over-burst queries all admitted (without exemption the 2nd
        // would be silent).
        for _ in 0..100 {
            assert!(
                lim.admit_query(src(1), t0),
                "exempt source must bypass the limiter"
            );
        }
        assert_eq!(lim.dropped, 0);
        // Non-exempt sources are unaffected, limited normally (1 query +
        // silence).
        assert!(lim.admit_query(src(2), t0));
        assert!(!lim.admit_query(src(2), t0));
        // TTL expired: exemption invalid, back to normal limiting (bucket
        // never used -> full: 1 query).
        let after_ttl = t0 + EXEMPT_TTL + Duration::from_secs(1);
        assert!(
            !lim.is_exempt(src(1), after_ttl),
            "exemption past its TTL must be invalid"
        );
        assert!(lim.admit_query(src(1), after_ttl));
        assert!(!lim.admit_query(src(1), after_ttl));
        // Re-registration renews: exempt again.
        lim.exempt(src(1), after_ttl);
        assert!(lim.is_exempt(src(1), after_ttl + Duration::from_secs(5)));
    }

    /// Bounded eviction: when a table is full, a new entry evicts the
    /// oldest (last_seen / registration time) entry; capacity stays at the
    /// hard cap.
    #[test]
    fn bounded_tables_evict_oldest() {
        let t0 = Instant::now();
        let mut lim = limiter(25, 50, 60);
        // 4096 distinct sources inserted at strictly increasing instants
        // (millisecond order, no ties — deterministic eviction); one packet
        // each (all within burst=50), so last_seen = insertion instant and
        // "oldest last_seen" = earliest insertion.
        for i in 0..QUERY_LIMITER_MAX_SOURCES {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                u32::from_be_bytes([198, 51, 100, 0]) + i as u32,
            ));
            lim.admit_query(ip, t0 + Duration::from_millis(i as u64));
        }
        let first = std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be_bytes([
            198, 51, 100, 0,
        ])));
        let fresh = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1));
        lim.admit_query(fresh, t0 + Duration::from_secs(2));
        assert!(
            !lim.sources.contains_key(&first),
            "least-recently-active entry should be evicted"
        );
        assert!(
            lim.sources.contains_key(&fresh),
            "new source should enter the table"
        );
        assert_eq!(
            lim.sources.len(),
            QUERY_LIMITER_MAX_SOURCES,
            "table capacity stays constant"
        );
        // Exemption table, same rules.
        for i in 0..EXEMPT_MAX_ENTRIES {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                u32::from_be_bytes([198, 52, 100, 0]) + i as u32,
            ));
            lim.exempt(ip, t0 + Duration::from_millis(i as u64));
        }
        let first_exempt = std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be_bytes([
            198, 52, 100, 0,
        ])));
        lim.exempt(fresh, t0 + Duration::from_secs(2));
        assert!(!lim.exempt.contains_key(&first_exempt));
        assert_eq!(lim.exempt.len(), EXEMPT_MAX_ENTRIES);
    }

    /// Per-source independence: exhausting/suppressing source A does not
    /// touch source B's budget.
    #[test]
    fn sources_are_independent() {
        let t0 = Instant::now();
        let mut lim = limiter(1, 1, 3600);
        assert!(lim.admit_query(src(1), t0));
        assert!(!lim.admit_query(src(1), t0));
        assert!(
            lim.admit_query(src(2), t0),
            "source B's budget is independent"
        );
        assert!(lim.admit_query(src(3), t0));
    }
}
