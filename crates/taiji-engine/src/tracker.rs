//! Tracker shadow mirror and persistence: `TrackerMirror` (a shadow
//! instance of the same frozen state machine as the actor),
//! `TrackerPersistShared`/flusher, event attribution
//! (`handle_tracker_bookkeeping`), SetTrackers acceptance
//! (`apply_set_trackers`).
//!
//! Owns: event -> row attribution -> dirty rows queued for serial DB
//! writes.
//! Does not own: announce orchestration itself (bt::tracker::actor).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use taiji_bt::tracker::actor::{TrackerActorEvent, TrackerCommand};
use taiji_bt::tracker::{AnnounceList, TierEvent};
use taiji_store::persist::{PersistHandle, PersistOutcome, TrackerRow};

use crate::metrics::SessionMetrics;

use crate::faces::FaceState;
/// Wait budget for the stopped sequence at shutdown (a local policy
/// value: actor TICK 1s + one announce round trip; on timeout, degrade
/// and exit rather than blocking process shutdown).
pub(super) const STOPPED_ANNOUNCE_BUDGET: Duration = Duration::from_secs(15);
/// Next-announce offset after an all-tier failure reset (aria2 restarts
/// the clock at minInterval on reset; with no local interval reading,
/// the row persists at this default — `BtAnnounce.h
/// DEFAULT_ANNOUNCE_INTERVAL = 2_min`).
pub(super) const DEFAULT_ANNOUNCE_INTERVAL: u64 = 120;
/// Actor event -> tracker row attribution: the engine holds a **shadow
/// instance of the same frozen state machine** as the actor
/// (`bt::tracker::AnnounceList`), driven by the identical transition
/// sequence — failure events carry the url, success events are
/// `IntervalUpdated`, and Stop/completed are flipped by the engine's own
/// actions/snapshot (read through the same SwarmSnapshot, visible at the
/// same instant) — the two instances stay in lockstep; attribution = the
/// shadow's `get_announce()` (for a success event, that announce's
/// URL/tier).
///
/// Known boundary (honesty note): a completed-flag flip and the arrival
/// of an in-flight default announce can reorder within <= 1 tick, so a
/// success may be attributed with completed semantics (the row-level
/// impact self-heals on the next announce; tracker rows are cache-grade
/// data, not correctness data).
pub(super) struct TrackerMirror {
    /// Shadow announce list (tier order = the actor's tier_groups order;
    /// URLs deduped).
    pub(super) list: AnnounceList,
    /// (tier number, url) — the row primary-key locator (url dedup ->
    /// unique hit).
    pub(super) tiers: Vec<(usize, String)>,
    /// Row-owning GID (16 hex; reused when `set_trackers` rebuilds
    /// rows).
    pub(super) gid: String,
    /// The engine has sent Stop to this face's actor (the actor will
    /// drive the stopped sequence).
    pub(super) halt: bool,
    /// The snapshot has flipped all_download_finished (the actor will
    /// drive the completed sequence).
    pub(super) completed: bool,
    /// Last successful row key (the scrape attribution target: a scrape
    /// right after a success, same host).
    pub(super) last_success: Option<(usize, String)>,
    /// Row-state cache (the engine-side mirror; event-driven full row
    /// snapshots, enqueued for persistence after each change).
    pub(super) rows: HashMap<(usize, String), TrackerRow>,
}

impl TrackerMirror {
    pub(super) fn new(tiers: &[(usize, String)], gid: &str) -> Self {
        let list = AnnounceList::from_tiers(tiers.iter().map(|(_, u)| vec![u.clone()]).collect());
        let rows = tiers
            .iter()
            .map(|(t, u)| {
                (
                    (*t, u.clone()),
                    TrackerRow {
                        gid: gid.to_string(),
                        tier: *t as i64,
                        url: u.clone(),
                        enabled: true,
                        last_interval: None,
                        last_min_interval: None,
                        next_announce_at: None,
                        last_error: None,
                        last_ok_at: None,
                        seeds: None,
                        leechers: None,
                    },
                )
            })
            .collect();
        TrackerMirror {
            list,
            tiers: tiers.to_vec(),
            gid: gid.to_string(),
            halt: false,
            completed: false,
            last_success: None,
            rows,
        }
    }

    /// SetTrackers (the bt-tracker global-import hot-push face; the same
    /// shape as `TrackerCommand::SetTrackers`): rebuild the shadow table +
    /// row set. Existing URL rows are kept (announce history is not
    /// lost), new URL rows are registered (enabled=1, present before the
    /// first announce), and rows of removed URLs vanish with the table;
    /// the success-attribution pointer is cleared when it names a
    /// removed URL. The halt/completed flags are preserved (shutdown /
    /// completion semantics do not change with a table rebuild).
    pub(super) fn set_trackers(&mut self, tiers: &[(usize, String)]) {
        self.list = AnnounceList::from_tiers(tiers.iter().map(|(_, u)| vec![u.clone()]).collect());
        self.tiers = tiers.to_vec();
        let keep: std::collections::HashSet<(usize, String)> = self.tiers.iter().cloned().collect();
        self.rows.retain(|k, _| keep.contains(k));
        for (t, u) in &self.tiers {
            self.rows
                .entry((*t, u.clone()))
                .or_insert_with(|| TrackerRow {
                    gid: self.gid.clone(),
                    tier: *t as i64,
                    url: u.clone(),
                    enabled: true,
                    last_interval: None,
                    last_min_interval: None,
                    next_announce_at: None,
                    last_error: None,
                    last_ok_at: None,
                    seeds: None,
                    leechers: None,
                });
        }
        if self
            .last_success
            .as_ref()
            .is_some_and(|(_, url)| !self.tiers.iter().any(|(_, u)| u == url))
        {
            self.last_success = None;
        }
    }

    pub(super) fn key_by_url(&self, url: &str) -> Option<(usize, String)> {
        self.tiers.iter().find(|(_, u)| u == url).cloned()
    }

    /// The adjust the actor runs before each announce (the
    /// `DefaultBtAnnounce.cc` port: stopped > completed > default; under
    /// default, all pieces complete with the event still STARTED ->
    /// STARTED_AFTER_COMPLETION). The engine applies the same adjust
    /// before attributing.
    pub(super) fn sync_adjust(&mut self) {
        if self.halt && self.list.count_stopped_allowed_tier() > 0 {
            if !self.list.current_tier_accepts_stopped_event() {
                self.list.move_to_stopped_allowed_tier();
            }
            self.list.set_event(TierEvent::Stopped);
        } else if self.completed && self.list.count_completed_allowed_tier() > 0 {
            if !self.list.current_tier_accepts_completed_event() {
                self.list.move_to_completed_allowed_tier();
            }
            self.list.set_event(TierEvent::Completed);
        } else if self.completed && self.list.get_event() == TierEvent::Started {
            self.list.set_event(TierEvent::StartedAfterCompletion);
        }
    }

    /// Attribute a success event: return the row key of that announce
    /// and advance the shadow state (announceSuccess = event advance +
    /// pointer back to 0, `AnnounceList.cc`).
    pub(super) fn attribute_success(&mut self) -> Option<(usize, String)> {
        self.sync_adjust();
        let url = self.list.get_announce()?.to_string();
        let key = self.key_by_url(&url);
        self.list.announce_success();
        key
    }

    /// Attribute a failure event (the url comes directly from the
    /// event): the shadow advances per announceFailure; all tiers failed
    /// -> resetTier (in sync with the actor's resetAnnounce,
    /// `AnnounceList.cc`).
    pub(super) fn attribute_failure(&mut self, url: &str) -> Option<(usize, String)> {
        self.sync_adjust();
        let key = self.key_by_url(url);
        self.list.announce_failure();
        if self.list.all_tiers_failed() {
            self.list.reset_tier();
        }
        key
    }

    /// Mutate a cached row and return the snapshot (key not in the cache
    /// = no-persist mode, None).
    pub(super) fn modify(
        &mut self,
        key: &(usize, String),
        change: impl FnOnce(&mut TrackerRow),
    ) -> Option<TrackerRow> {
        let row = self.rows.get_mut(key)?;
        change(row);
        Some(row.clone())
    }
}

/// Tracker-row persistence share: the main-loop event side only
/// enqueues row snapshots (no lock across await); an independent
/// flusher task writes the DB serially (zero disk IO in the main loop).
#[derive(Clone)]
pub(super) struct TrackerPersistShared {
    pub(super) gid: String,
    pub(super) handle: PersistHandle,
    /// Dirty-row snapshots (each push = a full row state; duplicate rows
    /// are deduped into skip-writes by the store).
    pub(super) dirty: Arc<Mutex<Vec<TrackerRow>>>,
    pub(super) notify: Arc<tokio::sync::Notify>,
}

impl TrackerPersistShared {
    pub(super) fn enqueue(&self, row: TrackerRow) {
        {
            let mut d = crate::lock(&self.dirty);
            d.push(row);
        }
        self.notify.notify_one();
    }
}
/// Tracker-row attribution + persistence enqueue (shared by the main
/// loop and the shutdown wait; a sync function — actual writes happen
/// in the flusher / the final flush). Event semantics: see the module
/// docs. The success/failure attribution points double as the
/// `taiji_tracker_announces_total` feed.
pub(super) fn handle_tracker_bookkeeping(
    face: &mut FaceState,
    ev: TrackerActorEvent,
    persist: Option<&TrackerPersistShared>,
    session_metrics: Option<&SessionMetrics>,
) {
    match ev {
        TrackerActorEvent::Peers { .. } => {} // dialing is handled by the caller
        TrackerActorEvent::IntervalUpdated {
            interval,
            min_interval,
        } => {
            if let Some(m) = session_metrics {
                m.note_tracker_result(true);
            }
            // Success attribution = the shadow's get_announce() (that
            // announce's URL/tier; the shadow pointer then returns to 0).
            // A UDP interval=0 success has no event (frozen protocol
            // face) -> attribution is missed; it only affects that row's
            // last_interval timing.
            let Some(key) = face.mirror.attribute_success() else {
                return;
            };
            face.mirror.last_success = Some(key.clone());
            let now = epoch_secs();
            let snapshot = face.mirror.modify(&key, |row| {
                row.last_interval = Some(interval as i64);
                row.last_min_interval = Some(min_interval as i64);
                row.next_announce_at = Some(now.saturating_add(interval as i64));
                row.last_ok_at = Some(now);
                row.last_error = None;
            });
            if let (Some(row), Some(p)) = (snapshot, persist) {
                p.enqueue(row);
            }
        }
        TrackerActorEvent::AnnounceFailed { url, reason } => {
            if let Some(m) = session_metrics {
                m.note_tracker_result(false);
            }
            // The failure event carries the url: attribute that row, and
            // the shadow advances per announceFailure (force
            // nextEventIfAfterStarted at the tier end; resetTier when
            // all tiers fail).
            let key = face.mirror.attribute_failure(&url);
            let all_failed = face.mirror.list.all_tiers_failed();
            let now = epoch_secs();
            let snapshot = key.and_then(|k| {
                face.mirror.modify(&k, |row| {
                    row.last_error = Some(reason.clone());
                    if all_failed {
                        // All-fail reset timing (the BtAnnounce.h default interval).
                        row.next_announce_at = Some(now + DEFAULT_ANNOUNCE_INTERVAL as i64);
                    }
                })
            });
            if let (Some(row), Some(p)) = (snapshot, persist) {
                p.enqueue(row);
            }
        }
        TrackerActorEvent::ScrapeResult {
            seeds, leechers, ..
        } => {
            // A scrape right after a success, same host -> attribute the
            // last successful row.
            let Some(key) = face.mirror.last_success.clone() else {
                return;
            };
            let snapshot = face.mirror.modify(&key, |row| {
                row.seeds = Some(seeds.min(i64::MAX as u64) as i64);
                row.leechers = Some(leechers.min(i64::MAX as u64) as i64);
            });
            if let (Some(row), Some(p)) = (snapshot, persist) {
                p.enqueue(row);
            }
        }
        TrackerActorEvent::Halted => {
            info!(target: "taiji::core::engine", "tracker actor halted (stopped sequence done)");
        }
    }
}

pub(super) fn epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
/// Tracker-row persistence flusher: merges dirty rows + serial DB
/// writes; at engine teardown a final flush runs and then aborts
/// (unpersisted rows = engine termination; the session side closes
/// out).
pub(super) fn spawn_tracker_flusher(p: TrackerPersistShared) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            p.notify.notified().await;
            loop {
                let rows: Vec<TrackerRow> = {
                    let mut d = crate::lock(&p.dirty);
                    std::mem::take(&mut *d)
                };
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    match p.handle.upsert_tracker(row).await {
                        Ok(PersistOutcome::Written) => {
                            debug!(target: "taiji::core::engine",
                                gid = %p.gid, "tracker row written")
                        }
                        Ok(PersistOutcome::SkippedUnchanged) => {}
                        Err(e) => {
                            warn!(target: "taiji::core::engine", gid = %p.gid, %e,
                                "tracker row persist failed")
                        }
                    }
                }
            }
        }
    })
}
/// SetTrackers acceptance: forward `TrackerCommand::SetTrackers` to
/// every face's actor (command face, awaiting each ack) + rebuild the
/// shadow row set + enqueue the new rows for persistence (rows of
/// removed URLs are no longer enqueued — stale old rows in the store
/// are handled by the next full-flush semantics; row-level staleness is
/// harmless: announce orchestration follows the actor's in-memory
/// table).
pub(super) async fn apply_set_trackers(
    faces: &mut [FaceState],
    actor_cmds: &[Option<mpsc::Sender<TrackerCommand>>],
    tiers: Vec<(usize, String)>,
    persist: Option<&TrackerPersistShared>,
) {
    let mut flat = tiers;
    flat.sort_by_key(|(tier, _)| *tier);
    for cmd in actor_cmds.iter().flatten() {
        let (tx, rx) = oneshot::channel();
        if cmd
            .send(TrackerCommand::SetTrackers {
                tiers: flat.clone(),
                reply: tx,
            })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
    }
    for face in faces.iter_mut() {
        face.mirror.set_trackers(&flat);
        if let Some(p) = persist {
            for row in face.mirror.rows.values() {
                p.enqueue(row.clone());
            }
        }
    }
}
