//! Command handling and the announce registry: `DhtCommand` dispatch (the
//! contract consumption face), announce port validation and registration,
//! peer lookup dispatch, runtime snapshot.
//!
//! Owns: the command entry ([`DhtEngine::handle_command`]) and announce
//! registry bookkeeping (the resend registry, docs/design/dht.md
//! divergence 4).
//! Does not own: lookup network progression (tasks/wire), bootstrap
//! rounds (bootstrap), BEP42 re-derivation (node_id).

use std::time::Instant;

use super::*;

impl DhtEngine {
    pub(super) async fn handle_command(&mut self, cmd: DhtCommand, now: Instant) -> bool {
        match cmd {
            DhtCommand::Announce {
                target,
                port,
                reply,
            } => {
                let outcome = self.register_announce(target, port, now);
                let _ = reply.send(outcome);
            }
            DhtCommand::GetPeers { target, reply } => {
                let outcome = self.start_peer_lookup(target, None, QueueKind::Periodic);
                let _ = reply.send(outcome);
            }
            DhtCommand::Bootstrap {
                entry_points,
                reply,
            } => {
                self.start_bootstrap(entry_points, reply);
            }
            DhtCommand::AddPortNode { ip, dht_port } => {
                self.handle_port_node(ip, dht_port);
            }
            DhtCommand::SetExternalIp { ip } => {
                self.update_external_ip(ip);
            }
            DhtCommand::Snapshot { reply } => {
                let _ = reply.send(self.snapshot());
            }
            DhtCommand::Shutdown { reply } => {
                // Halt save (DHTAutoSaveCommand.cc preProcess -> save).
                self.emit_persist(now).await;
                let _ = reply.send(());
                return false;
            }
        }
        true
    }

    /// Port validated in the same domain as the KRPC encoder
    /// (0 < p < 65535).
    fn validate_announce_port(port: u16) -> Result<(), DhtEngineError> {
        if (1..u16::MAX).contains(&port) {
            Ok(())
        } else {
            Err(DhtEngineError::InvalidPort(port))
        }
    }

    fn register_announce(
        &mut self,
        target: DhtTarget,
        port: u16,
        now: Instant,
    ) -> Result<(), DhtEngineError> {
        Self::validate_announce_port(port)?;
        self.our_announces.insert(
            target.target_id(),
            AnnounceEntry {
                port,
                face: target.face(),
                last_requested: now,
                last_announced: None,
                inflight: false,
            },
        );
        self.start_peer_lookup(target, Some(port), QueueKind::Periodic)
    }

    /// Dispatch a peer lookup (announce or not is decided by
    /// `announce_port`; user commands and maintenance resends both go to
    /// periodic, mirroring DHTGetPeersCommand.cc addPeriodicTask2).
    pub(super) fn start_peer_lookup(
        &mut self,
        target: DhtTarget,
        announce_port: Option<u16>,
        queue: QueueKind,
    ) -> Result<(), DhtEngineError> {
        if announce_port.is_some() {
            self.announce_lookups_started += 1;
            if let Some(entry) = self.our_announces.get_mut(&target.target_id()) {
                entry.inflight = true;
            }
        }
        self.enqueue(
            queue,
            Task::Lookup(LookupTask::new(
                target.target_id(),
                LookupKind::Peers { announce_port },
                target.face(),
            )),
        );
        Ok(())
    }

    fn snapshot(&self) -> DhtSnapshot {
        DhtSnapshot {
            family: self.family,
            node_id: self.local_id.0,
            dht_port: self.dht_port,
            num_nodes: self.table.num_nodes(),
            num_buckets: self.table.num_buckets(),
            transactions: self.txns.len(),
            immediate_executing: self.immediate.len_executing(),
            immediate_waiting: self.immediate.len_waiting(),
            periodic_executing: self.periodic.len_executing(),
            periodic_waiting: self.periodic.len_waiting(),
            announce_entries: self.our_announces.len(),
            peer_record_keys: self.peer_records.len(),
            peer_records_total: self.peer_records.values().map(|set| set.len()).sum(),
            values_truncated_total: self.values_truncated_total,
            announce_lookups_started: self.announce_lookups_started,
            queries_ping_total: self.queries_ping_total,
            queries_find_node_total: self.queries_find_node_total,
            queries_get_peers_total: self.queries_get_peers_total,
            queries_announce_peer_total: self.queries_announce_peer_total,
            inbound_packets_total: self.inbound_packets_total,
            inbound_queries_total: self.inbound_queries_total,
            inbound_unmatched_drops_total: self.inbound_unmatched_drops_total,
        }
    }
}
