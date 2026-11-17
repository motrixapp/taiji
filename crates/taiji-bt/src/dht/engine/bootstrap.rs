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
/// 2026-11 re-vetting (superseding the original three-entry table whose
/// first entry was `router.bittorrent.com`):
/// - `router.bittorrent.com:6881` / `router.utorrent.com:6881`: dead
///   worldwide — the historical address 67.215.246.10 now hosts an
///   unrelated web server (no DHT listener; TCP/UDP 6881 silent from
///   six global vantage points), and transmission#8664 confirms only
///   `dht.transmissionbt.com` / `dht.libtorrent.org` still work. Both
///   dropped.
/// - `dht.transmissionbt.com:6881` first: verified live (find_node
///   answered from both A records, ~180-250ms), and its DNS resolves
///   cleanly everywhere observed.
/// - `dht.libtorrent.org:25401` second (mutual backup, mirroring the
///   v6 table's pairing): verified live (find_node answered from the
///   real address 185.157.221.247). The earlier fourth-entry cold-start
///   regression is superseded by the settle-on-first-success entry
///   round: the backup costs one concurrent ping that is cancelled as
///   soon as the primary settles. Note its DNS is intermittently
///   injected on some direct paths (rotating false A records) — a
///   miss costs nothing, so it stays as second, not first.
pub const DEFAULT_BOOTSTRAP_NODES: &[(&str, u16)] = &[
    ("dht.transmissionbt.com", 6881),
    ("dht.libtorrent.org", 25401),
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
            self.dispatch_unannounced_pending();
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

    /// Re-dispatch registry entries never announced (not in flight, no
    /// completed announce round). Two call sites keep the discovery start
    /// point tight:
    ///
    /// - bootstrap settling — registration lands before bootstrap settles
    ///   (core assembly order — registration is issued right after engine
    ///   spawn, bootstrap must first resolve/ping), so the first lookup
    ///   runs on an empty table, sends nothing, and does not enter the
    ///   quiet window (zero sends are not stamped);
    /// - the post-bootstrap node lookup's completion — settling only
    ///   guarantees one live entry point; the table itself is warmed by
    ///   the self lookup dispatched at settlement. A lookup started
    ///   between the two events seeds from a one-node table, and a thin
    ///   exhausted walk can stamp the full quiet window on a target whose
    ///   peers are one deeper hop away. Running when the self lookup has
    ///   converged gives the redispatch a populated candidate set.
    ///
    /// Idempotent (the filter is state-based, not event-based).
    /// Comparison: aria2's per-torrent DHTGetPeersCommand runs
    /// periodically from download setup onward and does not wait for
    /// bootstrap settling (the "15min / 5min at low peers" cadence,
    /// docs/design/dht.md divergence 4).
    pub(super) fn dispatch_unannounced_pending(&mut self) {
        let pending: Vec<(NodeId, u16, DhtSwarmKind)> = self
            .our_announces
            .iter()
            .filter(|(_, entry)| !entry.inflight && entry.last_announced.is_none())
            .map(|(target, entry)| (*target, entry.port, entry.face))
            .collect();
        for (target, port, face) in pending {
            debug!(target: LOG_TARGET, "redispatching announce lookup");
            let _ = self.start_peer_lookup(
                DhtTarget {
                    info_hash: target.0,
                    face,
                },
                Some(port),
                QueueKind::Periodic,
            );
        }
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
        let reusable = self
            .bootstrap_rounds
            .iter()
            .enumerate()
            .find(|(index, round)| {
                round.reply.is_none()
                    && !self.periodic.references_bootstrap_round(*index)
                    && !self.immediate.references_bootstrap_round(*index)
            })
            .map(|(index, _)| index);
        let round_idx = reusable.unwrap_or(self.bootstrap_rounds.len());
        if round_idx >= 64 {
            let _ = reply.send(0);
            return;
        }
        let mut remaining = 0usize;
        for ep in entry_points.into_iter().take(32) {
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
        let round = BootstrapRound {
            remaining,
            successes: 0,
            reply: Some(reply),
            settled: false,
        };
        if reusable.is_some() {
            self.bootstrap_rounds[round_idx] = round;
        } else {
            self.bootstrap_rounds.push(round);
        }
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
