//! Maintenance ticks and events/persistence: the table-driven maintenance
//! actions (bucket refresh check, token secret rotation, peer announce
//! sanitization/resend, autosave) and the `DhtEvent` emission face
//! (PeersFound / Persist, persisted by the PersistWriter).
//!
//! Owns: the dispatch of actions on timer expiry and event-channel
//! discipline.
//! Does not own: the timer table itself (config::MaintenanceTimers) and
//! the main loop (run).

use std::time::Instant;

use tracing::{debug, warn};

use super::*;

impl DhtEngine {
    pub(super) async fn run_maintenance(&mut self, kind: MaintKind, now: Instant) {
        match kind {
            MaintKind::BucketRefreshCheck => {
                // DHTBucketRefreshCommand.cc.
                self.enqueue(QueueKind::Periodic, Task::Refresh(RefreshTask::scheduled()));
            }
            MaintKind::TokenRotate => {
                // DHTTokenUpdateCommand -> updateTokenSecret (10min).
                self.token.update_secret(&mut self.rng);
                debug!(target: LOG_TARGET, "token secret rotated");
            }
            MaintKind::PeerAnnounceCheck => self.maintain_peer_announce(now),
            MaintKind::AutoSave => self.emit_persist(now).await,
        }
        self.timers
            .schedule_after(kind, self.cfg.interval_of(kind), now);
    }

    /// Peer announce maintenance (5min check; `DHTPeerAnnounceStorage.cc` +
    /// `DHTConstants.h`): 30min sanitization + >=15min resend.
    fn maintain_peer_announce(&mut self, now: Instant) {
        let purge = self.cfg.peer_announce_purge_interval;
        for records in self.peer_records.values_mut() {
            records.retain_fresher_than(purge, now);
        }
        self.peer_records.retain(|_, records| !records.is_empty());
        // Full recount of the total ledger (the periodic backstop for the
        // incremental counter — realigns after sanitization / empty-key
        // removal).
        self.peer_records_total = self.peer_records.values().map(|s| s.len()).sum();
        self.our_announces
            .retain(|_, entry| now.duration_since(entry.last_requested) < purge);
        let due: Vec<(NodeId, u16, DhtSwarmKind)> = self
            .our_announces
            .iter()
            .filter(|(_, entry)| {
                !entry.inflight
                    && entry
                        .last_announced
                        .is_none_or(|t| now.duration_since(t) >= self.cfg.peer_announce_interval)
            })
            .map(|(target, entry)| (*target, entry.port, entry.face))
            .collect();
        for (target, port, face) in due {
            debug!(target: LOG_TARGET, "re-announcing info_hash (15min cycle)");
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

    // ===== Events / persistence =====

    pub(super) async fn emit_event(&mut self, ev: DhtEvent) {
        if self.event_tx.send(ev).await.is_err() && !self.event_closed_logged {
            warn!(target: LOG_TARGET, "dht event channel closed; further events dropped");
            self.event_closed_logged = true;
        }
    }

    /// Serialize the good nodes of every bucket (only bad removed,
    /// questionable kept — `DHTAutoSaveCommand.cc` + `DHTBucket.cc`) and
    /// emit `DhtEvent::Persist` (persisted by the PersistWriter).
    pub(super) async fn emit_persist(&mut self, now: Instant) {
        let nodes: Vec<TableNode> = self
            .table
            .buckets()
            .iter()
            .flat_map(|b| b.nodes())
            .filter(|n| !n.is_bad())
            .map(|n| TableNode {
                id: *n.id(),
                addr: n.addr(),
                last_seen_ago_secs: n
                    .last_contact()
                    .map_or(u64::MAX, |t| now.saturating_duration_since(t).as_secs()),
            })
            .collect();
        let routing_table = persist::encode_table(&nodes);
        self.emit_event(DhtEvent::Persist {
            family: self.family,
            node_id: self.local_id.0,
            routing_table,
        })
        .await;
    }
}
