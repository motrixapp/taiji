//! Bootstrap rounds and PORT message wiring: after the entry pings settle
//! the success count is reported, and success dispatches node_lookup(self) +
//! bucket refresh (`DHTEntryPointNameResolveCommand.cc`); the PORT
//! receive side mirrors `BtPortMessage.cc`.
//!
//! Owns: round accounting and the bootstrap/PORT task dispatch.
//! Does not own: ping/lookup task send/receive driving (tasks).

use std::net::{IpAddr, SocketAddr};

use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use super::*;

/// SPEC §6.7 hardcoded router fallbacks (v4; aria2 has no such behavior —
/// a deliberate SPEC enhancement, see docs/design/dht.md; DNS resolution
/// belongs to core's bootstrap task, this is constants only).
///
/// DNS A-record check at inclusion: all three resolve
/// (`router.bittorrent.com`, `dht.transmissionbt.com`,
/// `router.utorrent.com`); `router.bitcomet.com` has no A record (not
/// included).
///
/// `dht.libtorrent.org:25401` evaluated and rejected: it resolves and is
/// libtorrent's official default bootstrap, but adding it as a fourth
/// entry degraded cold-start bootstrap; not included.
pub const DEFAULT_BOOTSTRAP_NODES: &[(&str, u16)] = &[
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881),
];

impl DhtEngine {
    /// Advance a bootstrap round.
    ///
    /// Select semantics: *the first successful entry settles the round* —
    /// reply immediately + dispatch node_lookup(self) + bucket refresh,
    /// and cancel the round's remaining entry pings (no retry budget is
    /// wasted on unreachable routers; the ">=1 entry success -> lookup+
    /// refresh" trigger of `DHTEntryPointNameResolveCommand.cc` is kept
    /// as-is). Reference comparison: libtorrent `node::bootstrap` joins
    /// all entries into one concurrent walk (`src/kademlia/node.cpp` adds
    /// each entry with observer::flag_initial) and does not wait per
    /// entry; aria2's entry round joins on all-settled — an unreachable
    /// entry's retry budget (retry x transaction timeout) blocks settling,
    /// which this implementation tightens to select. Total failure still
    /// degrades (semantics unchanged). The timeout budget logic
    /// (transaction sweep + wake deadline = min(maintenance, transaction
    /// deadline)) is unchanged.
    ///
    /// The success path also re-dispatches registry announce entries never
    /// announced (the assembly race, see the success branch comment
    /// below) — a zero-send first registered lookup does not occupy the
    /// 15min quiet window (tasks::complete_task); this guarantees the
    /// discovery start point no longer slips past bootstrap settling.
    pub(super) fn advance_bootstrap(&mut self, round_idx: usize, success: bool) {
        let Some(round) = self.bootstrap_rounds.get_mut(round_idx) else {
            return;
        };
        if round.settled {
            // First success already settled: later outcomes of the round's
            // other pings are not accounted.
            return;
        }
        round.remaining = round.remaining.saturating_sub(1);
        if success {
            round.successes += 1;
            round.settled = true;
            let successes = round.successes;
            if let Some(reply) = round.reply.take() {
                let _ = reply.send(successes);
            }
            info!(target: LOG_TARGET, successes, "bootstrap done; dispatching node lookup + refresh");
            self.enqueue(
                QueueKind::Periodic,
                Task::Lookup(LookupTask::new(
                    self.local_id,
                    LookupKind::Nodes,
                    DhtSwarmKind::V1,
                )),
            );
            self.enqueue(QueueKind::Periodic, Task::Refresh(RefreshTask::scheduled()));
            // On bootstrap settling, re-dispatch registry entries never
            // announced: announce registration lands before bootstrap
            // settles (core assembly order — registration is issued right
            // after engine spawn, bootstrap must first resolve/ping), the
            // first lookup runs on an empty table, sends nothing, and does
            // not enter the 15min quiet window (zero sends are not
            // stamped); without this re-dispatch the discovery start point
            // would slip to the first PeerAnnounceCheck (<=5min).
            // Comparison: aria2's per-torrent DHTGetPeersCommand runs
            // periodically from download setup onward and does not wait
            // for bootstrap settling (the "15min / 5min at low peers"
            // cadence, docs/design/dht.md divergence 4).
            let pending: Vec<(NodeId, u16, DhtSwarmKind)> = self
                .our_announces
                .iter()
                .filter(|(_, entry)| !entry.inflight && entry.last_announced.is_none())
                .map(|(target, entry)| (*target, entry.port, entry.face))
                .collect();
            for (target, port, face) in pending {
                debug!(target: LOG_TARGET, "redispatching announce lookup after bootstrap");
                let _ = self.start_peer_lookup(
                    DhtTarget {
                        info_hash: target.0,
                        face,
                    },
                    Some(port),
                    QueueKind::Periodic,
                );
            }
            self.cancel_round_pings(round_idx);
            return;
        }
        if round.remaining > 0 {
            return;
        }
        // All settled and all failed: degrade (unchanged semantics).
        let successes = round.successes;
        if let Some(reply) = round.reply.take() {
            let _ = reply.send(successes);
        }
        warn!(target: LOG_TARGET, "bootstrap failed for all entry points; DHT degraded until reachable");
    }

    /// Cancel the round's remaining entry pings (after first-success
    /// settling; cancelled pings do not retry, their in-flight transactions
    /// converge via the normal timeout sweep — the task is gone, late
    /// replies/timeouts drop at the routing step).
    fn cancel_round_pings(&mut self, round_idx: usize) {
        let cancelled = self.periodic.cancel_bootstrap_pings(round_idx);
        if cancelled > 0 {
            debug!(target: LOG_TARGET, cancelled, "cancelled remaining bootstrap entry pings");
        }
    }

    /// Bootstrap (`DHTEntryPointNameResolveCommand.cc`): one ping task per
    /// entry (retrying cfg.bootstrap_ping_retry) into periodic, run
    /// concurrently; the first success settles (select), all-fail reports
    /// 0 after everything settles. Entry node IDs are unknown -> random
    /// placeholders (same note as BtPortMessage.cc: the ping reply enters
    /// the table with the wire ID).
    pub(super) fn start_bootstrap(
        &mut self,
        entry_points: Vec<SocketAddr>,
        reply: oneshot::Sender<usize>,
    ) {
        let round_idx = self.bootstrap_rounds.len();
        let mut remaining = 0usize;
        for ep in entry_points {
            // Exempt the entry source from inbound query limiting so the
            // bootstrap path is not starved (BEP42 "should always be
            // serviced"); the exemption carries a TTL, and a re-bootstrap
            // of a source still in bootstrap renews it.
            self.query_limiter.exempt(ep.ip(), Instant::now());
            let node = DhtNode::new(NodeId::random(&mut self.rng), ep);
            let mut ping = PingTask::new(node, self.cfg.bootstrap_ping_retry);
            ping.round = Some(round_idx);
            self.enqueue(QueueKind::Periodic, Task::Ping(ping));
            remaining += 1;
        }
        self.bootstrap_rounds.push(BootstrapRound {
            remaining,
            successes: 0,
            reply: Some(reply),
            settled: false,
        });
        if remaining == 0 {
            // No entries = settle immediately (0 successes, no
            // lookup/refresh).
            self.advance_bootstrap(round_idx, false);
        }
    }

    /// PORT message receive side (`BtPortMessage.cc`): port=0 ignored;
    /// ping immediately (createPingTask default retry 0); with only one
    /// bucket, add node_lookup(self).
    pub(super) fn handle_port_node(&mut self, ip: IpAddr, dht_port: u16) {
        if dht_port == 0 {
            debug!(target: LOG_TARGET, "ignored port 0 from PORT message");
            return;
        }
        // Exempt the PORT-introduced source from inbound query limiting so
        // the handshake-followup bootstrap exchange (our ping -> their
        // probe back) is not starved; the exemption carries a TTL (see
        // query_limit EXEMPT_TTL — a temporary pass, preventing forged
        // PORT messages from minting a permanent bypass).
        self.query_limiter.exempt(ip, Instant::now());
        let addr = SocketAddr::new(ip, dht_port);
        let node = DhtNode::new(NodeId::random(&mut self.rng), addr);
        self.enqueue(QueueKind::Immediate, Task::Ping(PingTask::new(node, 0)));
        if self.table.num_buckets() == 1 {
            info!(target: LOG_TARGET, "dispatch node_lookup since too few buckets");
            self.enqueue(
                QueueKind::Immediate,
                Task::Lookup(LookupTask::new(
                    self.local_id,
                    LookupKind::Nodes,
                    DhtSwarmKind::V1,
                )),
            );
        }
    }
}
