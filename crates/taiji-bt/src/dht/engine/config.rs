//! Engine configuration and the maintenance timer table (split out of
//! engine.rs; pure move).
//!
//! Owns: the interval constants, the `DhtEngineConfig` injection surface,
//! `MaintKind`/`MAINT_KINDS` and `MaintenanceTimers` (one next-due instant
//! per kind).
//! Does not own: the maintenance dispatch on timer expiry (see
//! `maintenance`).

use std::time::{Duration, Instant};

use crate::dht::task::BOOTSTRAP_PING_RETRY;
use crate::dht::token::DHT_TOKEN_UPDATE_INTERVAL;
use crate::dht::transaction::DHT_MESSAGE_TIMEOUT;

/// Bucket refresh check period. aria2 `src/DHTConstants.h`.
pub const DHT_BUCKET_REFRESH_CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Peer announce check period. aria2 `src/DHTConstants.h`.
pub const DHT_PEER_ANNOUNCE_CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Peer announce resend interval. aria2 `src/DHTConstants.h`.
pub const DHT_PEER_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// Peer announce/record sanitization age. aria2 `src/DHTConstants.h`.
pub const DHT_PEER_ANNOUNCE_PURGE_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Autosave period. aria2 `src/DHTSetup.cc` (`30_min`).
pub const DHT_AUTOSAVE_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Default sustained rate of the per-source inbound KRPC query token
/// bucket (queries/second).
///
/// Local value: BEP5 has no rate-limiting semantics; neither libtorrent
/// nor aria2 rate-limits per-source inbound queries (libtorrent's closest
/// protection is the process-level socket quota `has_quota()`,
/// `node.cpp` — process-wide, not per-source). Default 25 pps, from a
/// traffic model:
///
/// - A legitimate single source is one Kademlia client querying this
/// node: its lookup keeps ALPHA=3 in flight
/// ([`crate::dht::task::ALPHA`], aria2 `DHTAbstractNodeLookupTask.h`)
/// advancing once per RTT (tens of ms on the public internet), and this
/// node only appears at the fringe of its candidate set — a sustained
/// single source is single-digit pps, so 25 pps leaves several times
/// margin and normal queries never feel the limit;
/// - A malicious single source is pinned at 25 pps (once the burst is
/// spent), far below what one source can occupy of the demux dht
/// channel (capacity 1024, `taiji-io/src/udp_demux.rs`) — the
/// per-source bound forces flooding to come from many distinct sources,
/// and distinct sources are in turn bounded by the same-scale
/// suppression table (`query_limit::QUERY_LIMITER_MAX_SOURCES`).
pub const DHT_PER_SOURCE_QUERY_RATE: u32 = 25;

/// Default capacity of the per-source inbound query token bucket
/// (queries; starts full, spendable instantly).
///
/// Local value: 50 = the burst of one full lookup round against a single
/// target (K candidates fed ALPHA in flight, aria2
/// `DHTAbstractNodeLookupTask` sends a handful of queries per round
/// against one target) — a legitimate client's whole round never trips a
/// drop. Also the escalation criterion: a full burst of consecutive
/// over-budget drops (`violations >= burst`) escalates to suppression —
/// a legitimate burst drains at most one bucket and then naturally backs
/// off; a source still hammering a full burst beyond budget is not normal
/// behavior (no separate criterion constant; the config surface stays at
/// three parameters).
pub const DHT_PER_SOURCE_QUERY_BURST: u32 = 50;

/// Default violating-source suppression duration (seconds; silent drop,
/// not a permanent ban).
///
/// Default 60s: deliberately not a permanent ban — peers come back (NAT
/// remap / client restart), and expiry recovers automatically without a
/// management plane. 60s >> burst/rate = 2s (the bucket's natural refill
/// time): during suppression the source's inbound bytes are zero, and on
/// expiry it is re-examined with a full bucket.
pub const DHT_SOURCE_SUPPRESS_SECS: u64 = 60;

/// Automatic maintenance kinds (timer-table driven).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaintKind {
    /// Bucket refresh check (dispatches [`super::super::task::RefreshTask`]).
    BucketRefreshCheck,
    /// Peer announce check (sanitization + resend).
    PeerAnnounceCheck,
    /// Token secret rotation.
    TokenRotate,
    /// Autosave (`DhtEvent::Persist`).
    AutoSave,
}

/// All maintenance kinds (for table-driven iteration).
pub const MAINT_KINDS: [MaintKind; 4] = [
    MaintKind::BucketRefreshCheck,
    MaintKind::PeerAnnounceCheck,
    MaintKind::TokenRotate,
    MaintKind::AutoSave,
];

/// Engine configuration (all intervals injectable — tests drive the same
/// table at millisecond scale).
#[derive(Debug, Clone)]
pub struct DhtEngineConfig {
    /// Transaction timeout (`--dht-message-timeout` semantics; default
    /// `DHT_MESSAGE_TIMEOUT` 10s, `DHTConstants.h`).
    pub message_timeout: Duration,
    /// Bootstrap entry ping retry count (`DHTEntryPointNameResolveCommand.cc`
    /// passes 10; PORT-triggered pings use 0, see [`super::super::task`]).
    pub bootstrap_ping_retry: u32,
    pub refresh_check_interval: Duration,
    pub peer_announce_check_interval: Duration,
    pub token_rotate_interval: Duration,
    pub autosave_interval: Duration,
    pub peer_announce_interval: Duration,
    pub peer_announce_purge_interval: Duration,
    /// Per-source inbound KRPC query token bucket sustained rate
    /// (queries/second; default [`DHT_PER_SOURCE_QUERY_RATE`] 25,
    /// rationale in that constant's docs).
    pub per_source_query_rate: u32,
    /// Per-source inbound query bucket capacity (queries; default
    /// [`DHT_PER_SOURCE_QUERY_BURST`] 50, also the escalation criterion —
    /// a full burst of consecutive over-budget drops suppresses,
    /// rationale in that constant's docs).
    pub per_source_query_burst: u32,
    /// Violating-source suppression duration (seconds; silent drop,
    /// automatic recovery on expiry, default
    /// [`DHT_SOURCE_SUPPRESS_SECS`] 60, rationale in that constant's
    /// docs).
    pub suppress_secs: u64,
}

impl Default for DhtEngineConfig {
    fn default() -> Self {
        DhtEngineConfig {
            message_timeout: DHT_MESSAGE_TIMEOUT,
            bootstrap_ping_retry: BOOTSTRAP_PING_RETRY,
            refresh_check_interval: DHT_BUCKET_REFRESH_CHECK_INTERVAL,
            peer_announce_check_interval: DHT_PEER_ANNOUNCE_CHECK_INTERVAL,
            token_rotate_interval: DHT_TOKEN_UPDATE_INTERVAL,
            autosave_interval: DHT_AUTOSAVE_INTERVAL,
            peer_announce_interval: DHT_PEER_ANNOUNCE_INTERVAL,
            peer_announce_purge_interval: DHT_PEER_ANNOUNCE_PURGE_INTERVAL,
            per_source_query_rate: DHT_PER_SOURCE_QUERY_RATE,
            per_source_query_burst: DHT_PER_SOURCE_QUERY_BURST,
            suppress_secs: DHT_SOURCE_SUPPRESS_SECS,
        }
    }
}

impl DhtEngineConfig {
    /// Maintenance kind -> period (timer table).
    pub(super) fn interval_of(&self, kind: MaintKind) -> Duration {
        match kind {
            MaintKind::BucketRefreshCheck => self.refresh_check_interval,
            MaintKind::PeerAnnounceCheck => self.peer_announce_check_interval,
            MaintKind::TokenRotate => self.token_rotate_interval,
            MaintKind::AutoSave => self.autosave_interval,
        }
    }
}

/// Table-driven maintenance timers: one next-due instant per kind; due
/// when `due <= now` (the same boundary as aria2 TimeBasedCommand's
/// ">= interval since last").
#[derive(Debug)]
pub(super) struct MaintenanceTimers {
    pub(super) due: [Option<Instant>; MAINT_KINDS.len()],
}

impl MaintenanceTimers {
    fn index(kind: MaintKind) -> usize {
        MAINT_KINDS.iter().position(|k| *k == kind).unwrap_or(0)
    }

    pub(super) fn schedule_after(&mut self, kind: MaintKind, interval: Duration, now: Instant) {
        self.due[Self::index(kind)] = Some(now + interval);
    }

    /// Schedule every kind uniformly (called at construction).
    pub(super) fn schedule_all(&mut self, cfg: &DhtEngineConfig, now: Instant) {
        for kind in MAINT_KINDS {
            self.schedule_after(kind, cfg.interval_of(kind), now);
        }
    }

    pub(super) fn next_wake(&self) -> Option<Instant> {
        self.due.iter().filter_map(|d| *d).min()
    }

    /// Harvest due kinds (`due <= now`); the caller reschedules
    /// afterwards.
    pub(super) fn fire_due(&mut self, now: Instant) -> Vec<MaintKind> {
        let mut fired = Vec::new();
        for kind in MAINT_KINDS {
            let slot = &mut self.due[Self::index(kind)];
            if slot.is_some_and(|d| d <= now) {
                *slot = None;
                fired.push(kind);
            }
        }
        fired
    }
}
