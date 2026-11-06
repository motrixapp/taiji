//! DhtEngine actor state and assembly (split out of engine.rs; pure move).
//!
//! Owns: actor-exclusive state (single task, lock-free), internal
//! bookkeeping records (transaction routing / bootstrap rounds / announce
//! registry / peer records) and the `new` assembly (restore import +
//! forced refresh dispatch).
//! Does not own: the state transition logic (see the tasks/command/
//! bootstrap/node_id/wire/maintenance/run responsibility modules).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

// rand 0.10: StdRng construction uses make_rng (SeedableRng::from_os_rng
// was removed).
use rand::rngs::StdRng;
use tokio::sync::mpsc;

use crate::dht::token::TokenTracker;
use crate::dht::transaction::TransactionTable;

use super::*;

/// Transaction -> task routing entry (registered at send time).
pub(super) struct RouteTarget {
    pub(super) task_id: TaskId,
    /// Entry node at send time (replies replace the entry by address and
    /// complete the task by node; the table ID is the wire r.id).
    pub(super) node: DhtNode,
}

/// Bootstrap round (select semantics: the first successful entry settles
/// the round and cancels the remaining pings; only a total failure waits
/// for all to settle and then degrades).
pub(super) struct BootstrapRound {
    pub(super) remaining: usize,
    pub(super) successes: usize,
    pub(super) reply: Option<oneshot::Sender<usize>>,
    /// First success has settled (later outcomes of the round's other
    /// pings are not accounted).
    pub(super) settled: bool,
}

/// Our announce registry entry (see the engine/mod divergence list,
/// docs/design/dht.md).
pub(super) struct AnnounceEntry {
    pub(super) port: u16,
    pub(super) face: DhtSwarmKind,
    /// Last Announce command instant (removed after 30min without a resend
    /// command).
    pub(super) last_requested: Instant,
    /// Last announce-capable lookup completion instant.
    pub(super) last_announced: Option<Instant>,
    /// A lookup is already in flight (prevents duplicate dispatches per
    /// target; mirrors the single-flight task semantics of
    /// DHTGetPeersCommand).
    pub(super) inflight: bool,
}

/// Peer records announced by others (one info-hash key; the source of
/// get_peers reply values; DHTPeerAnnounceStorage/DHTPeerAnnounceEntry
/// semantics: dedupe by addr + notifyUpdate + 30min sanitization).
///
/// # Boundedness and dedup
///
/// The container is always bounded: when a key reaches
/// [`MAX_PEER_RECORDS_PER_KEY`] records, [`PeerRecordSet::admit`] evicts
/// the oldest (smallest updated) record before inserting the new address.
/// The cap mirrors libtorrent's per-torrent storage capacity
/// `dht_max_peers` (default 500, src/settings_pack.cpp; at capacity
/// libtorrent drops the announce, src/kademlia/dht_storage.cpp). The
/// eviction policy is an intentional divergence from the reference: the
/// reference drops the *new* announce, this implementation evicts the
/// *oldest* record — letting an attacker fill a key would starve honest
/// announces for a long time, evicting the oldest leaves room for fresh
/// peers.
///
/// Dedup/touch are O(1) hash operations (key = (ip, port)), replacing an
/// earlier O(N) linear `find` scan; at-capacity eviction is an O(n) scan
/// (n <= 500, bounded) paid at most once per *new* record insertion — the
/// repeated-announce fast path never scans.
///
/// Key order is meaningless (HashMap iteration order): the reply value
/// subset is therefore nondeterministic, in the same spirit as
/// libtorrent's random reply sampling (dht_storage.cpp); boundedness
/// assertions depend only on counts/bytes, not on membership.
#[derive(Debug, Default)]
pub(super) struct PeerRecordSet {
    /// (ip, port) -> last update instant. Hash key = O(1) dedup + O(1)
    /// touch; the value drives 30min sanitization and "evict oldest".
    records: HashMap<SocketAddr, Instant>,
}

impl PeerRecordSet {
    /// Dedup-insert or touch (addr dedup + notifyUpdate semantics); when
    /// the key is full and the address is new, evicts the oldest record
    /// (policy trade-off in the type docs).
    pub(super) fn admit(&mut self, addr: SocketAddr, now: Instant) {
        if self.records.len() >= MAX_PEER_RECORDS_PER_KEY && !self.records.contains_key(&addr) {
            // Evict the oldest (hardening; n <= cap, bounded scan).
            let oldest = self
                .records
                .iter()
                .min_by_key(|(_, updated)| **updated)
                .map(|(addr, _)| *addr);
            if let Some(oldest) = oldest {
                self.records.remove(&oldest);
            }
        }
        self.records.insert(addr, now);
    }

    pub(super) fn len(&self) -> usize {
        self.records.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&SocketAddr, &Instant)> {
        self.records.iter()
    }

    /// Age sanitization (30min, `DHTConstants.h`; called from maintenance).
    pub(super) fn retain_fresher_than(&mut self, age: Duration, now: Instant) {
        self.records
            .retain(|_, updated| now.duration_since(*updated) < age);
    }

    /// Newest update instant within the key (the key-level "evict oldest
    /// key" credential; same semantics as max over the record updates).
    pub(super) fn newest(&self) -> Option<Instant> {
        self.records.values().copied().max()
    }
}

/// The DhtEngine actor (a single task owning all state).
pub struct DhtEngine {
    pub(super) family: super::persist::DhtFamily,
    pub(super) cfg: DhtEngineConfig,
    pub(super) local_id: NodeId,
    pub(super) dht_port: u16,
    pub(super) table: RoutingTable,
    pub(super) token: TokenTracker,
    pub(super) rng: StdRng,
    pub(super) txns: TransactionTable,
    pub(super) route: HashMap<TransactionKey, RouteTarget>,
    pub(super) next_task_id: TaskId,
    pub(super) immediate: TaskQueue,
    pub(super) periodic: TaskQueue,
    pub(super) bootstrap_rounds: Vec<BootstrapRound>,
    pub(super) our_announces: HashMap<NodeId, AnnounceEntry>,
    pub(super) peer_records: HashMap<NodeId, PeerRecordSet>,
    /// Total peer records across all keys (the incremental ledger behind
    /// the global cap [`super::wire::MAX_PEER_RECORDS_TOTAL`] — kept in
    /// sync at admit / key eviction / maintenance sanitization, with a
    /// periodic full recount in maintenance as backstop).
    pub(super) peer_records_total: usize,
    /// Cumulative get_peers reply values truncations (observability;
    /// exposed via `DhtSnapshot::values_truncated_total`).
    pub(super) values_truncated_total: u64,
    pub(super) timers: MaintenanceTimers,
    /// BEP42 external address (from SetExternalIp; None = not yet probed,
    /// random/restored id).
    pub(super) external_ip: Option<IpAddr>,
    pub(super) cmd_rx: mpsc::Receiver<DhtCommand>,
    pub(super) event_tx: mpsc::Sender<DhtEvent>,
    pub(super) event_closed_logged: bool,
    pub(super) transport: DhtTransport,
    pub(super) announce_lookups_started: u64,
    /// Per-source error-reply limiter (token bucket; constants and
    /// rationale in the `error_limit` module docs).
    pub(super) error_limiter: ErrorReplyLimiter,
    /// Per-source inbound query limiter and suppression (token bucket +
    /// suppression table + entry exemption; see the `query_limit` module
    /// docs).
    pub(super) query_limiter: QueryRateLimiter,
    /// Outbound per-kind query counters (observability; fed where
    /// `send_query` successfully enqueues outbound — encode failures /
    /// closed outbound channel do not count; exposed via
    /// `DhtSnapshot::queries_*_total`). Kind domain = the four BEP5
    /// message kinds [`crate::dht::message::MessageKind`] (ping/find_node/
    /// get_peers/announce_peer KRPC method names).
    pub(super) queries_ping_total: u64,
    pub(super) queries_find_node_total: u64,
    pub(super) queries_get_peers_total: u64,
    pub(super) queries_announce_peer_total: u64,
    /// Inbound datagram counters (observability; counting-only —
    /// no control-flow branch reads them; exposed via the same-named
    /// `DhtSnapshot` fields): every inbound packet, its y="q" subset, and
    /// the y="r"/e early-drop face (no pending transaction match).
    pub(super) inbound_packets_total: u64,
    pub(super) inbound_queries_total: u64,
    pub(super) inbound_unmatched_drops_total: u64,
}

impl DhtEngine {
    /// Assemble (`spawn` is the external entry; `new` is exposed for tests
    /// and embedded drivers).
    pub(super) fn new(
        family: persist::DhtFamily,
        dht_port: u16,
        cfg: DhtEngineConfig,
        transport: DhtTransport,
        restore: Option<DhtRestoreState>,
        event_tx: mpsc::Sender<DhtEvent>,
        cmd_rx: mpsc::Receiver<DhtCommand>,
    ) -> Self {
        let start = Instant::now();
        let mut rng = rand::make_rng::<StdRng>();
        let (local_id, table, restored_nodes) = match restore {
            Some(r) => {
                // Deserialization succeeded -> keep the persisted node ID
                // (DHTSetup.cc).
                let mut t = RoutingTable::new(r.node_id, start);
                for (id, addr) in &r.nodes {
                    // addNode (not good): imported nodes enter the table as
                    // never-contacted, DHTSetup.cc.
                    t.add_node(&DhtNode::new(*id, *addr), start);
                }
                (r.node_id, t, r.nodes.len())
            }
            None => {
                let id = NodeId::random(&mut rng);
                (id, RoutingTable::new(id, start), 0)
            }
        };
        let mut timers = MaintenanceTimers {
            due: [None; MAINT_KINDS.len()],
        };
        timers.schedule_all(&cfg, start);
        let query_limiter = QueryRateLimiter::new(
            cfg.per_source_query_rate,
            cfg.per_source_query_burst,
            Duration::from_secs(cfg.suppress_secs),
        );
        let mut engine = DhtEngine {
            family,
            cfg,
            local_id,
            dht_port,
            table,
            token: TokenTracker::new(&mut rng),
            rng,
            txns: TransactionTable::new(),
            route: HashMap::new(),
            next_task_id: 0,
            immediate: TaskQueue::new(),
            periodic: TaskQueue::new(),
            bootstrap_rounds: Vec::new(),
            our_announces: HashMap::new(),
            peer_records: HashMap::new(),
            peer_records_total: 0,
            values_truncated_total: 0,
            timers,
            external_ip: None,
            cmd_rx,
            event_tx,
            event_closed_logged: false,
            transport,
            announce_lookups_started: 0,
            error_limiter: ErrorReplyLimiter::new(),
            query_limiter,
            queries_ping_total: 0,
            queries_find_node_total: 0,
            queries_get_peers_total: 0,
            queries_announce_peer_total: 0,
            inbound_packets_total: 0,
            inbound_queries_total: 0,
            inbound_unmatched_drops_total: 0,
        };
        if restored_nodes > 0 {
            // Restored nodes non-empty -> force a refresh into the periodic
            // queue (DHTSetup.cc, setForceRefresh(true)).
            engine.enqueue(QueueKind::Periodic, Task::Refresh(RefreshTask::forced()));
        }
        engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, octet)), port)
    }

    /// Hash dedup + touch + at-capacity evict-oldest (table-driven):
    /// (1) everything is kept before capacity; (2) a duplicate (ip,port)
    /// admit only touches — no growth, no eviction (the O(1) fast path);
    /// (3) at capacity a new address evicts exactly the oldest-updated
    /// record; (4) a touched oldest record survives on its refreshed
    /// instant ("oldest" is by updated, not insertion order).
    #[test]
    fn admit_dedup_touch_and_evict_oldest_table() {
        let t0 = Instant::now();
        let cap = MAX_PEER_RECORDS_PER_KEY;
        let mut set = PeerRecordSet::default();
        // (1) Fill to capacity at strictly increasing instants (millisecond
        // order, no ties — deterministic eviction).
        for i in 0..cap as u32 {
            set.admit(
                v4((i % 254 + 1) as u8, 1000 + i as u16 % 50000),
                t0 + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(set.len(), cap, "all retained before capacity");
        // (2) Duplicate address touch: capacity unchanged (hash dedup).
        let oldest_addr = v4(1, 1000);
        set.admit(oldest_addr, t0 + Duration::from_secs(3600));
        assert_eq!(set.len(), cap, "duplicate (ip,port) must not add a record");
        // (3) Insert a new address at capacity: evicts the current oldest
        // updated (record 1 was touched to newest in (2)). i=1 -> octet 2,
        // port 1001.
        let second_addr = v4(2, 1001);
        let fresh = v4(200, 65500);
        set.admit(fresh, t0 + Duration::from_secs(7200));
        assert_eq!(
            set.len(),
            cap,
            "after eviction at capacity the size stays at the cap"
        );
        assert!(
            !set.iter().any(|(a, _)| *a == second_addr),
            "oldest record evicted"
        );
        assert!(set.iter().any(|(a, _)| *a == fresh), "new record stored");
        // (4) Touch protects: the just-touched oldest is still present
        // ("evict oldest" is by updated).
        assert!(
            set.iter().any(|(a, _)| *a == oldest_addr),
            "touched record survives eviction via its updated instant"
        );
    }

    /// Age sanitization: expired records removed, fresh kept, all-expired
    /// -> empty set (maintenance semantics).
    #[test]
    fn retain_fresher_than_purges_stale_only() {
        let t0 = Instant::now();
        let mut set = PeerRecordSet::default();
        set.admit(v4(1, 1000), t0);
        set.admit(v4(2, 1001), t0 + Duration::from_secs(600));
        let purge = Duration::from_secs(30 * 60);
        // t0+2000s: first record age 2000s >= 1800s expired; second age
        // 1400s < 1800s fresh.
        set.retain_fresher_than(purge, t0 + Duration::from_secs(2000));
        assert_eq!(set.len(), 1, "expired record sanitized, fresh record kept");
        assert!(set.iter().any(|(a, _)| *a == v4(2, 1001)));
        set.retain_fresher_than(purge, t0 + purge + Duration::from_secs(600));
        assert!(
            set.is_empty(),
            "all expired -> empty set (key-level retain input)"
        );
    }

    /// Key-level eviction credential: newest = the max updated within the
    /// key (None when empty).
    #[test]
    fn newest_reflects_latest_update() {
        let t0 = Instant::now();
        let mut set = PeerRecordSet::default();
        assert_eq!(set.newest(), None);
        set.admit(v4(1, 1000), t0);
        set.admit(v4(2, 1001), t0 + Duration::from_secs(5));
        assert_eq!(set.newest(), Some(t0 + Duration::from_secs(5)));
        // Touch advances newest.
        set.admit(v4(1, 1000), t0 + Duration::from_secs(9));
        assert_eq!(set.newest(), Some(t0 + Duration::from_secs(9)));
    }
}
