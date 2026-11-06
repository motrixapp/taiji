//! Queue / result bookkeeping state machine (pure data, no IO, no
//! spawn — table-driven tests construct it directly).
//!
//! Semantics are a direct translation of the (read-only) reference
//! RequestGroupMan.cc:
//! - reserved FIFO + fillup up to max-concurrent-downloads:
//! `fillRequestGroupFromReserver` — pop ready entries from the queue
//! front and activate up to `maxConcurrentDownloads - numActive`;
//! paused / dependency-pending entries are skipped and re-inserted at
//! the front, order preserved (the `pending` insert);
//! - addUri position: `insertReservedGroup` — pos clamped to the table
//! length;
//! - pause finalization requeues to the front:
//! `ProcessStoppedRequestGroup` pauseRequested ->
//! `reservedGroups_.push_front`;
//! - restart (the changeOption restart path, RpcMethodImpl.cc)
//! finalizes to the front and clears pause (setRestartRequested ->
//! setPauseRequested(false));
//! - DownloadResult table: `addDownloadResult` — numStoppedTotal_ only
//! grows, table trimmed to `--max-download-result` (default 1000);
//! `purgeDownloadResult` clears the table but not the count.
//!
//! Upstream anchor mapping: docs/design/core.md

use std::collections::{BTreeMap, VecDeque};

use crate::gid::Gid;

use super::command::OffsetMode;
use super::view::{DownloadResultEntry, StatusKind};

/// Waiting-queue length cap: aria2 has no such cap; this guards against
/// an RPC queue flood (entries themselves are lightweight — the cap
/// protects the multiplicative face of per-entry Metainfo residency on
/// the jobs side).
pub(crate) const MAX_RESERVED_QUEUE_ENTRIES: usize = 1024;
/// Queued-task metadata byte budget: an upper bound on the sum of
/// `resident_estimate_bytes` of the Metainfo riding with all waiting
/// entries (a .torrent ingested via addTorrent can reach 30 MiB per
/// task — the 1024 x 30 MiB flood face is capped at 256 MiB).
pub(crate) const MAX_QUEUED_METAINFO_BYTES: usize = 256 * 1024 * 1024;

/// `--max-download-result` default (the same-named aria2
/// OptionHandlerFactory option defaults to 1000; the oldest entries are
/// trimmed beyond that, RequestGroupMan.cc).
const MAX_DOWNLOAD_RESULT: usize = 1000;

/// Waiting-queue entry (the session-side projection of an aria2
/// reserved RequestGroup).
#[derive(Debug, Clone)]
pub(crate) struct ReservedEntry {
    pub gid: Gid,
    /// User pause (the waiting-state pauseRequestGroup reserved branch,
    /// RpcMethodImpl.cc: `reserved && !isPauseRequested` -> set).
    pub paused: bool,
}

/// Active-task record (the request-flag projection of an aria2 active
/// RequestGroup).
#[derive(Debug, Clone, Default)]
pub(crate) struct ActiveRecord {
    /// Pause request sent (finalization -> requeue to front paused,
    /// RequestGroupMan.cc).
    pub pause_requested: bool,
    /// Remove request sent (finalization -> DownloadResult; halt
    /// clears pause — RequestGroup.cc setHaltRequested internally does
    /// setPauseRequested(false)).
    pub remove_requested: bool,
    /// changeOption restart request (finalization -> requeue to front
    /// and clear pause).
    pub restart_requested: bool,
}

impl ActiveRecord {
    /// The paused value after requeueing to the front (pause -> true;
    /// restart -> false; remove does not requeue).
    fn requeue_paused(&self) -> Option<bool> {
        if self.restart_requested {
            Some(false)
        } else if self.pause_requested && !self.remove_requested {
            Some(true)
        } else {
            None
        }
    }
}

/// Seeding-residence record (the seed pool's
/// running registry entry). The design table's `BTreeMap<Gid, ()>`
/// sketch grows the two request flags — the same finalization-intent
/// face [`ActiveRecord`] has for the active domain — plus the
/// slot-release marker the forceRecheck Seeding arm needs (the graceful
/// stop is in flight; the registry entry stays so find()/pause/remove
/// keep working, but the slot no longer counts against the seed
/// budget). Still a pure-data addition: no IO, no spawn, table-driven
/// tests construct it directly.
#[derive(Debug, Clone, Default)]
pub(crate) struct SeedingRecord {
    /// Pause request sent (finalization -> requeue to front paused; the
    /// engine stop is the token cancel, the same pause face as the
    /// active domain).
    pub pause_requested: bool,
    /// Remove request sent (finalization -> Removed result; halt clears
    /// pause — the same override order as [`ActiveRecord`]).
    pub remove_requested: bool,
    /// Seed slot released while the entry stays registered (the
    /// forceRecheck stop window). `seeding_len` does not count it.
    pub slot_released: bool,
}

impl SeedingRecord {
    /// The paused value after leaving the registry (pause -> true;
    /// remove does not requeue — no restart face on the seed side).
    fn requeue_paused(&self) -> Option<bool> {
        if self.pause_requested && !self.remove_requested {
            Some(true)
        } else {
            None
        }
    }
}

/// Check-pool parked entry (the check pool's
/// waiting-FIFO member). The design table's `VecDeque<Gid>` sketch grows
/// the paused-intent flag — the same post-recheck requeue face the
/// checking registry entry carried (forceRecheck's reserved arm
/// preserves the waiting entry's pause state through the check). Pure
/// data; table-driven tests construct it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckPendingEntry {
    pub gid: Gid,
    /// User pause intent (the post-recheck requeue honors it — the same
    /// face as the checking registry's paused value).
    pub paused: bool,
}

/// Synthesis-pool record (the
/// synthesis pool's running registry entry — an in-flight media
/// synthesis holding its `media-synthesis-concurrency` slot). The
/// design table's `BTreeMap<Gid, ()>` sketch grows the two request
/// flags — the same finalization-intent face [`SeedingRecord`] grew for
/// the seed pool): a user pause/remove arriving while the
/// synthesis runs sets the flag and cancels the driver token; the
/// teardown's `Ended` consume reads the flags for the
/// requeue-vs-result dispatch (remove overrides pause — halt
/// semantics). Pure data; table-driven tests construct it directly.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessingRecord {
    /// Pause request sent (the driver teardown lands
    /// `MediaEnd::Paused{memory: Processing}` — the §3.2 phase memory;
    /// the consume requeues to the front paused).
    pub pause_requested: bool,
    /// Remove request sent (halt semantics: clears pause — the same
    /// override order as [`ActiveRecord`]/[`SeedingRecord`]; the consume
    /// records Removed + deletes the row).
    pub remove_requested: bool,
}

impl ProcessingRecord {
    /// The paused value after leaving the synthesis faces (pause -> true;
    /// remove does not requeue — no restart face on the synthesis side,
    /// the [`SeedingRecord`] shape).
    fn requeue_paused(&self) -> Option<bool> {
        if self.pause_requested && !self.remove_requested {
            Some(true)
        } else {
            None
        }
    }
}

/// Synthesis-pool parked entry (the synthesis
/// pool's waiting-FIFO member). The design table's `VecDeque<Gid>`
/// sketch grows the two request flags (the [`CheckPendingEntry`]
/// growth precedent): a gate-hung media task still has a **live
/// driver** awaiting its permit — unlike a seed_wait member — so a
/// pause/remove must both mark the intent (the promotion never grants
/// a flagged head) and cancel the token; the teardown's `Ended`
/// consume dispatches from the flags. The flags also carry over from
/// the active record at the SynthesisGate transfer (`begin_synthesis_park`),
/// so a pause/remove racing the gate arrival keeps its halt semantics.
/// Pure data; table-driven tests construct it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SynthesisPark {
    pub gid: Gid,
    /// Pause request sent (the gate await loses the token race -> the
    /// driver teardown lands `Paused{memory: Processing}`; the consume
    /// requeues to the front paused).
    pub pause_requested: bool,
    /// Remove request sent (halt semantics: clears pause).
    pub remove_requested: bool,
}

impl SynthesisPark {
    /// The paused value after leaving the FIFO (the [`ProcessingRecord`]
    /// shape — one dispatch rule across both synthesis faces).
    fn requeue_paused(&self) -> Option<bool> {
        if self.pause_requested && !self.remove_requested {
            Some(true)
        } else {
            None
        }
    }
}

/// One member of the unified waiting snapshot ([`QueueMan::
/// waiting_snapshot`]): the gid plus its projected status — the
/// queue-side half of the tellWaiting status matrix (the actor maps
/// these 1:1 onto base views; the four-pool observation face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WaitingMember {
    pub gid: Gid,
    pub status: StatusKind,
}

/// The waiting-domain segments (the unified waiting projection): the reserved
/// queue plus the three phase FIFOs. A **phase segment is a resource
/// domain** — changePosition's move is segment-local, a position never
/// crosses a segment boundary (clamped into the owning segment's own
/// head/tail), and only the reserved segment persists
/// (queue_pos; the three phase FIFOs are runtime ordering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitingSegment {
    /// The aria2 waiting queue (queue_pos persisted).
    Reserved,
    /// The check pool's parked FIFO.
    CheckPending,
    /// The seed pool's parked FIFO.
    SeedWait,
    /// The synthesis pool's parked FIFO.
    ProcWait,
}

/// The waiting-domain move outcome ([`QueueMan::move_waiting`]): the
/// segment owning the moved gid plus its (from, to) indexes **inside
/// that segment** (the reply space of changePosition = the request's
/// space).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WaitingMove {
    pub segment: WaitingSegment,
    pub from: usize,
    pub to: usize,
}

/// A waiting-FIFO member that can be reordered by the changePosition
/// segment-local move (the [`QueueMan::move_reserved`] IndexedList
/// translation generalized over the three entry shapes — the payload
/// (paused flag / request flags) rides the move untouched).
trait FifoMember {
    fn member_gid(&self) -> Gid;
}

impl FifoMember for ReservedEntry {
    fn member_gid(&self) -> Gid {
        self.gid
    }
}

impl FifoMember for CheckPendingEntry {
    fn member_gid(&self) -> Gid {
        self.gid
    }
}

impl FifoMember for SynthesisPark {
    fn member_gid(&self) -> Gid {
        self.gid
    }
}

impl FifoMember for Gid {
    fn member_gid(&self) -> Gid {
        *self
    }
}

/// The IndexedList::move translation applied to one FIFO (the
/// [`QueueMan::move_reserved`] reference semantics, shared by all four
/// waiting segments): three-mode raw value clamped into the segment's
/// own [0, len-1], reorder = remove(xp) + insert(dest), payloads ride
/// untouched. Returns (from, dest).
fn move_fifo<T: FifoMember>(
    fifo: &mut VecDeque<T>,
    gid: Gid,
    pos: i64,
    how: OffsetMode,
) -> Option<(usize, usize)> {
    let xp = fifo.iter().position(|e| e.member_gid() == gid)?;
    // Found implies size >= 1 (xp in [0, size-1]); size-1 cannot
    // underflow.
    let size = fifo.len() as i64;
    // Signed sums saturate (under remote extreme pos values the
    // reference's ssize_t overflow is UB; clamping here keeps the
    // semantics — extremes necessarily fall outside and clamp back
    // to 0/size-1).
    let raw = match how {
        OffsetMode::Cur => (xp as i64).saturating_add(pos),
        OffsetMode::End => (size - 1).saturating_add(pos),
        OffsetMode::Set => pos,
    };
    let dest = raw.min(size - 1).max(0);
    let entry = fifo.remove(xp)?;
    fifo.insert(dest as usize, entry);
    Some((xp, dest as usize))
}

/// Queue + DownloadResult bookkeeping (exclusive to SessionActor,
/// lock-free).
#[derive(Debug, Default)]
pub(crate) struct QueueMan {
    reserved: VecDeque<ReservedEntry>,
    active: BTreeMap<Gid, ActiveRecord>,
    /// On-disk recheck-in-flight bookkeeping: gid -> paused intent.
    /// Tasks under verification **occupy no concurrency slot and cannot
    /// be activated by fillup** (engine assembly reads the bitmap from
    /// the progress row — activating before verification writes back =
    /// empty bitmap = re-download from zero); completion leaves the
    /// registry via `remove_checking` and re-enters the waiting queue
    /// per the paused intent. The row-state truth (torrent.state =
    /// 'checking') is persisted by the actor; this bookkeeping is only
    /// the in-memory queuing face. **In-flight only** since the
    /// check pool landed:
    /// entries are admitted here by pump_check's budget gate (the
    /// parked face lives in `check_pending` below); `checking_progress`
    /// (actor side) registers at that same promotion, keeping the
    /// "checking_progress entry ⟺ recheck in flight" invariant.
    checking: BTreeMap<Gid, bool>,
    /// Check-pool waiting FIFO (the check pool's parked set): rechecks
    /// parked pending budget (the four former direct-spawn admissions —
    /// addTorrent complete payload / forceRecheck reserved arm /
    /// begin_deferred_recheck / consume_seeding_recheck — plus
    /// bootstrap 'checking' rows). Promotion within
    /// max-concurrent-checks pops from the front (FIFO like
    /// `reserved`/`seed_wait`); parked members occupy **no running slot
    /// of any pool** and project into tellWaiting with the 'checking'
    /// status (the existing row-state value).
    check_pending: VecDeque<CheckPendingEntry>,
    /// Seeding-residence registry (the seed
    /// pool's running set): a BT task whose download completed stays
    /// resident seeding here — **occupying no download slot** (the
    /// active→seeding transfer at SeedingStarted releases the download
    /// slot immediately; `running` keeps the engine handle/token, only
    /// the queue accounting moves).
    seeding: BTreeMap<Gid, SeedingRecord>,
    /// Seed-pool waiting FIFO (the seed budget's parked set: budget-full
    /// completions and restart routing enter here; promotion within the
    /// budget pops from the front — FIFO like `reserved`).
    seed_wait: VecDeque<Gid>,
    /// Synthesis-residence registry (the
    /// synthesis pool's running set): a media task past its gate permit
    /// runs its Processing/Verifying phases here — **occupying no
    /// download slot** (the active→proc_wait transfer at the gate
    /// arrival released it; the permit admission parked→processing
    /// occupies the synthesis slot). Pure queue accounting: `running`
    /// keeps the driver live handle/token untouched.
    processing: BTreeMap<Gid, ProcessingRecord>,
    /// Synthesis-pool waiting FIFO (the `media-synthesis-concurrency`
    /// budget's parked set): media tasks that reached the Downloading →
    /// Processing gate while the budget was full park here — **a live
    /// driver still hangs on the gate permit** (the await races the
    /// task token; a cancellation lands the normal teardown paths).
    /// Promotion within the budget pops from the front (FIFO like
    /// `reserved`); members occupy no running slot of any pool and
    /// project into tellWaiting with the 'waiting' status (the existing
    /// row-state value — the gate hang is an in-task phase, §5).
    proc_wait: VecDeque<SynthesisPark>,
    results: VecDeque<DownloadResultEntry>,
    max_results: usize,
    num_stopped_total: u64,
}

impl QueueMan {
    pub(crate) fn new() -> Self {
        QueueMan {
            reserved: VecDeque::new(),
            active: BTreeMap::new(),
            checking: BTreeMap::new(),
            check_pending: VecDeque::new(),
            seeding: BTreeMap::new(),
            seed_wait: VecDeque::new(),
            processing: BTreeMap::new(),
            proc_wait: VecDeque::new(),
            results: VecDeque::new(),
            max_results: MAX_DOWNLOAD_RESULT,
            num_stopped_total: 0,
        }
    }

    // ---- waiting queue ----

    /// Enqueue (position = None appends; Some(pos) inserts clamped —
    /// the insertReservedGroup RequestGroupMan.cc translation). A
    /// read-only view of the waiting queue (the queue-pressure meter).
    pub(crate) fn reserved_entries(&self) -> &VecDeque<ReservedEntry> {
        &self.reserved
    }

    pub(crate) fn insert_reserved(&mut self, entry: ReservedEntry, pos: Option<usize>) {
        match pos {
            None => self.reserved.push_back(entry),
            Some(pos) => {
                let pos = pos.min(self.reserved.len());
                self.reserved.insert(pos, entry);
            }
        }
    }

    /// Remove a waiting entry (the remove path for waiting tasks; no
    /// DownloadResult — same as aria2 removeReservedGroup,
    /// RequestGroupMan.cc).
    pub(crate) fn remove_reserved(&mut self, gid: Gid) -> bool {
        let before = self.reserved.len();
        self.reserved.retain(|e| e.gid != gid);
        self.reserved.len() != before
    }

    /// Waiting-queue reorder, a direct translation of the aria2
    /// `IndexedList::move` (IndexedList.h — exposed to changePosition
    /// via RequestGroupMan::changeReservedGroupPosition). The three
    /// target modes unify to a raw value clamped to [0, size-1] (the
    /// reference's positive/negative branch structure is equivalent to
    /// unified clamping in this domain):
    /// - [`OffsetMode::Set`]: raw = pos;
    /// - [`OffsetMode::Cur`]: raw = xp + pos;
    /// - [`OffsetMode::End`]: raw = size-1 + pos.
    ///
    /// Unknown gid = `None` (reference -1 -> the caller emits
    /// "GID#%s not found in the waiting queue."). The reorder =
    /// remove(xp) + insert(dest) (the equivalent primitive of the
    /// std::rotate two branches); **paused entries can be moved too**
    /// (the reference reservedGroups_ contains pauseRequested reserved
    /// entries; the fillup order-preserving re-insert is unaffected).
    /// Returns the destination index after the move.
    pub(crate) fn move_reserved(&mut self, gid: Gid, pos: i64, how: OffsetMode) -> Option<usize> {
        move_fifo(&mut self.reserved, gid, pos, how).map(|(_, dest)| dest)
    }

    /// changePosition's waiting-domain dispatch (the unified waiting
    /// projection):
    /// the four waiting segments are each a move domain — the move is
    /// interpreted **inside the owning segment** ([`WaitingSegment`]):
    /// the raw destination clamps into the owning segment's own
    /// [0, len-1] and never crosses a segment boundary (a phase segment
    /// is a resource domain; membership does not change). Only the
    /// reserved segment reorders the persisted face (the caller runs
    /// the queue_pos renumber on a from != to move); the three phase
    /// FIFOs are runtime ordering — zero persistence, zero schema.
    /// None = the gid holds no waiting membership (active / seeding /
    /// checking-in-flight / processing / result / unknown — the caller
    /// emits the reference
    /// `"GID#%s not found in the waiting queue."` text; note the parked
    /// check_pending member shares the `Checking` location pair with
    /// the in-flight recheck, so the dispatch keys on **segment
    /// membership**, never on `find()`).
    pub(crate) fn move_waiting(
        &mut self,
        gid: Gid,
        pos: i64,
        how: OffsetMode,
    ) -> Option<WaitingMove> {
        if let Some(from) = self.reserved.iter().position(|e| e.gid == gid) {
            let to = self.move_reserved(gid, pos, how)?;
            return Some(WaitingMove {
                segment: WaitingSegment::Reserved,
                from,
                to,
            });
        }
        if let Some((from, to)) = move_fifo(&mut self.check_pending, gid, pos, how) {
            return Some(WaitingMove {
                segment: WaitingSegment::CheckPending,
                from,
                to,
            });
        }
        if let Some((from, to)) = move_fifo(&mut self.seed_wait, gid, pos, how) {
            return Some(WaitingMove {
                segment: WaitingSegment::SeedWait,
                from,
                to,
            });
        }
        let (from, to) = move_fifo(&mut self.proc_wait, gid, pos, how)?;
        Some(WaitingMove {
            segment: WaitingSegment::ProcWait,
            from,
            to,
        })
    }

    pub(crate) fn reserved_entry(&self, gid: Gid) -> Option<&ReservedEntry> {
        self.reserved.iter().find(|e| e.gid == gid)
    }

    pub(crate) fn reserved_entry_mut(&mut self, gid: Gid) -> Option<&mut ReservedEntry> {
        self.reserved.iter_mut().find(|e| e.gid == gid)
    }

    /// fillup (the fillRequestGroupFromReserver translation): returns
    /// the GIDs to activate this round (FIFO order) and builds their
    /// ActiveRecords. Paused entries are skipped and re-inserted at the
    /// front, order preserved.
    pub(crate) fn fillup(&mut self, max_concurrent: usize) -> Vec<Gid> {
        let mut to_spawn = Vec::new();
        if max_concurrent <= self.active.len() {
            return to_spawn;
        }
        let mut budget = max_concurrent - self.active.len();
        let mut pending: Vec<ReservedEntry> = Vec::new();
        while budget > 0 {
            let Some(entry) = self.reserved.pop_front() else {
                break;
            };
            if entry.paused {
                // keepRunning (RPC session) && pauseRequested ->
                // pending.
                pending.push(entry);
                continue;
            }
            self.active.insert(entry.gid, ActiveRecord::default());
            to_spawn.push(entry.gid);
            budget -= 1;
        }
        // Re-insert pending at the front, order preserved
        // (insert(begin, ...)).
        for entry in pending.into_iter().rev() {
            self.reserved.push_front(entry);
        }
        to_spawn
    }

    // ---- active face ----

    pub(crate) fn active_len(&self) -> usize {
        self.active.len()
    }

    pub(crate) fn active_record_mut(&mut self, gid: Gid) -> Option<&mut ActiveRecord> {
        self.active.get_mut(&gid)
    }

    /// Remove request pending (the halt-semantics source for
    /// finalization-state decisions: a user remove overrides natural
    /// completion — the aria2 ProcessStoppedRequestGroup DownloadResult
    /// REMOVED face).
    pub(crate) fn is_removing(&self, gid: Gid) -> bool {
        self.active.get(&gid).is_some_and(|r| r.remove_requested)
    }

    /// Request-flag snapshot before retire (the dispatch basis for
    /// finalization persistence: remove -> delete the row, pause ->
    /// paused row, restart -> queued row, no flags natural terminal /
    /// shutdown -> done/error/queued row).
    pub(crate) fn active_flags(&self, gid: Gid) -> Option<(bool, bool, bool)> {
        self.active.get(&gid).map(|rec| {
            (
                rec.pause_requested,
                rec.remove_requested,
                rec.restart_requested,
            )
        })
    }

    pub(crate) fn contains_active(&self, gid: Gid) -> bool {
        self.active.contains_key(&gid)
    }

    /// Remove request: clears pause (halt semantics, the
    /// RequestGroup.cc translation).
    pub(crate) fn request_remove(&mut self, gid: Gid) -> bool {
        match self.active.get_mut(&gid) {
            Some(rec) => {
                rec.remove_requested = true;
                rec.pause_requested = false;
                true
            }
            None => false,
        }
    }

    /// Pause request (active face; failure = already in the pause /
    /// remove flow — the decision source for "GID#%s cannot be paused
    /// now", RpcMethodImpl.cc).
    pub(crate) fn request_pause(&mut self, gid: Gid) -> bool {
        match self.active.get_mut(&gid) {
            Some(rec) if !rec.pause_requested && !rec.remove_requested => {
                rec.pause_requested = true;
                true
            }
            _ => false,
        }
    }

    // ---- finalization ----

    /// Detach from the active face and dispatch per the record:
    /// pause/restart -> requeue to front (Some(paused)); otherwise ->
    /// DownloadResult (numStoppedTotal++, table trimmed). Returns the
    /// same as `ActiveRecord::requeue_paused`; the Result path returns
    /// None.
    pub(crate) fn retire_active(&mut self, gid: Gid, result: DownloadResultEntry) -> Option<bool> {
        let rec = self.active.remove(&gid)?;
        match rec.requeue_paused() {
            Some(paused) => {
                self.reserved.push_front(ReservedEntry { gid, paused });
                Some(paused)
            }
            None => {
                self.record_result(result);
                None
            }
        }
    }

    /// Detach from the active face with neither requeue nor result
    /// (shared by the cleanup after a waiting-item remove and
    /// forceRemove's abort finalization — the aria2 forceRemove
    /// fast-release path).
    pub(crate) fn drop_active(&mut self, gid: Gid) -> bool {
        self.active.remove(&gid).is_some()
    }

    // ---- DownloadResult table ----

    pub(crate) fn remove_result(&mut self, gid: Gid) -> bool {
        let before = self.results.len();
        self.results.retain(|r| r.gid != gid);
        self.results.len() != before
    }

    pub(crate) fn purge_results(&mut self) {
        self.results.clear();
    }

    pub(crate) fn results(&self) -> impl Iterator<Item = &DownloadResultEntry> {
        self.results.iter()
    }

    pub(crate) fn num_stopped_total(&self) -> u64 {
        self.num_stopped_total
    }

    // ---- view snapshots ----

    /// Waiting-queue FIFO order snapshot (the reserved **segment** of
    /// the unified waiting order — see [`Self::waiting_snapshot`]).
    pub(crate) fn reserved_snapshot(&self) -> Vec<ReservedEntry> {
        self.reserved.iter().cloned().collect()
    }

    /// The unified waiting snapshot — **the single point** of the
    /// tellWaiting segment order and the segment status projection
    /// (the final segment order): `reserved ++ check_pending ++
    /// seed_wait ++ proc_wait`, each segment internally FIFO. Every
    /// projection consumer of the waiting domain (tellWaiting rows,
    /// getGlobalStat numWaiting) reads through here, so the order and
    /// the status matrix cannot drift apart across call sites;
    /// changePosition's segment dispatch ([`Self::move_waiting`]) keys
    /// on the same four segment domains. The interim
    /// append order (seed_wait before check_pending) is superseded:
    /// reverting to it turns
    /// `waiting_snapshot_final_segment_order_and_statuses` red.
    ///
    /// Status projection (the same matrix): a reserved member is
    /// `waiting`/`paused` by its own flag; check_pending = `checking`
    /// (the existing row-state value); seed_wait = `seeding` (the
    /// extended value, aligned with the row state); proc_wait =
    /// `waiting` (the gate hang is an in-task phase — no extension).
    pub(crate) fn waiting_snapshot(&self) -> Vec<WaitingMember> {
        let mut out = Vec::with_capacity(
            self.reserved.len()
                + self.check_pending.len()
                + self.seed_wait.len()
                + self.proc_wait.len(),
        );
        for e in &self.reserved {
            out.push(WaitingMember {
                gid: e.gid,
                status: if e.paused {
                    StatusKind::Paused
                } else {
                    StatusKind::Waiting
                },
            });
        }
        for e in &self.check_pending {
            out.push(WaitingMember {
                gid: e.gid,
                status: StatusKind::Checking,
            });
        }
        for gid in &self.seed_wait {
            out.push(WaitingMember {
                gid: *gid,
                status: StatusKind::Seeding,
            });
        }
        for p in &self.proc_wait {
            out.push(WaitingMember {
                gid: p.gid,
                status: StatusKind::Waiting,
            });
        }
        out
    }

    /// Active GID snapshot (tellActive; BTreeMap order = GID order, not
    /// activation order — aria2 requestGroups_ is an activation-order
    /// linked list; the view face only needs set semantics; activation
    /// order can be added here if ever needed).
    pub(crate) fn active_gids(&self) -> Vec<Gid> {
        self.active.keys().copied().collect()
    }

    /// The periodic summary's member caliber (pinned —
    /// **deliberate, not to be extended to the four pools**): the
    /// download pool's active set only. Seeding/checking/synthesis
    /// observation rides the tell* projections and the getGlobalStat
    /// extension keys, never the periodic summary lines. Pinned by
    /// `summary_caliber_download_pool_only_under_mixed_load` (the
    /// `emit_summary` iteration source reads through here).
    pub(crate) fn summary_gids(&self) -> Vec<Gid> {
        self.active_gids()
    }

    // ---- recheck-in-flight face ----

    /// Enter the recheck registry (the shared gate for the addTorrent
    /// full-payload initial verification / forceRecheck): the task is
    /// skipped by fillup during verification and projected as checking
    /// (active semantics) by tellActive/tellStatus. `paused` = the user
    /// pause intent (whether the post-verification requeue stays
    /// paused).
    pub(crate) fn insert_checking(&mut self, gid: Gid, paused: bool) {
        self.checking.insert(gid, paused);
    }

    /// Leave the recheck registry and fetch back the pause intent (the
    /// completion requeue face).
    pub(crate) fn remove_checking(&mut self, gid: Gid) -> Option<bool> {
        self.checking.remove(&gid)
    }

    /// Pause-intent rewrite (the admission face for pause during
    /// verification; false = not registered).
    pub(crate) fn set_checking_paused(&mut self, gid: Gid, paused: bool) -> bool {
        match self.checking.get_mut(&gid) {
            Some(slot) => {
                *slot = paused;
                true
            }
            None => false,
        }
    }

    /// Recheck-in-flight GID snapshot (the checking projection domain
    /// of tellActive).
    pub(crate) fn checking_gids(&self) -> Vec<Gid> {
        self.checking.keys().copied().collect()
    }

    /// Check-pool budget accounting (the admission gate's denominator):
    /// in-flight rechecks only — parked members hold no slot (the
    /// pool rule: running = `checking`, waiting = `check_pending`).
    pub(crate) fn checking_len(&self) -> usize {
        self.checking.len()
    }

    // ---- check pool waiting FIFO ----

    /// Park into the check_pending FIFO (the shared admission face of
    /// the four former direct-spawn points + bootstrap re-admission).
    /// A duplicate park is absorbed (a gid is parked at most once — the
    /// unique-membership invariant).
    pub(crate) fn insert_check_pending(&mut self, gid: Gid, paused: bool) {
        if !self.check_pending.iter().any(|e| e.gid == gid) {
            self.check_pending
                .push_back(CheckPendingEntry { gid, paused });
        }
    }

    /// Leave the check_pending FIFO (the remove path for a parked
    /// member). Returns false when the gid was not parked.
    pub(crate) fn remove_check_pending(&mut self, gid: Gid) -> bool {
        let before = self.check_pending.len();
        self.check_pending.retain(|e| e.gid != gid);
        self.check_pending.len() != before
    }

    /// Pause-intent rewrite on a parked member (the pause/unpause face;
    /// false = not parked). The in-flight twin is
    /// [`Self::set_checking_paused`]; the command arms go through
    /// [`Self::set_check_paused`], which hits whichever face holds the
    /// gid.
    pub(crate) fn set_check_pending_paused(&mut self, gid: Gid, paused: bool) -> bool {
        match self.check_pending.iter_mut().find(|e| e.gid == gid) {
            Some(entry) => {
                entry.paused = paused;
                true
            }
            None => false,
        }
    }

    /// Pause-intent rewrite across both check faces (in-flight registry
    /// first, then the parked FIFO): the single entry point for the
    /// pause/unpause command arms — a gid lives in exactly one of them
    /// (the unique-membership rule), so at most one write lands.
    /// false = gid in neither face.
    pub(crate) fn set_check_paused(&mut self, gid: Gid, paused: bool) -> bool {
        if self.set_checking_paused(gid, paused) {
            return true;
        }
        self.set_check_pending_paused(gid, paused)
    }

    /// Check-pending FIFO snapshot (the tellWaiting appended segment).
    pub(crate) fn check_pending_gids(&self) -> Vec<Gid> {
        self.check_pending.iter().map(|e| e.gid).collect()
    }

    /// Check-pool admission (pump_check's promotion half): pop the
    /// check_pending front when the budget allows. The caller moves the
    /// returned entry into the checking registry (insert_checking) and
    /// spawns the recheck. Returns None when the FIFO is empty or the
    /// budget is full. Never evicts in-flight rechecks (a narrowed budget never preempts:
    /// an over-subscribed registry is tolerated under a narrowed budget,
    /// the narrowing converges via natural completions — a new budget
    /// only constrains subsequent admissions).
    pub(crate) fn admit_next_check(&mut self, budget: usize) -> Option<CheckPendingEntry> {
        if self.checking_len() >= budget {
            return None;
        }
        self.check_pending.pop_front()
    }

    // ---- seed pool (seeding residence + seed_wait) ----

    /// active → seeding transfer (the SeedingStarted consume): the
    /// download slot is released the moment the record moves; the
    /// engine handle/token/state cache stay in `running` untouched
    /// (pure queue accounting). The request flags carry from the
    /// [`ActiveRecord`] into the [`SeedingRecord`] (the
    /// `begin_synthesis_park` alignment): a pause/remove
    /// racing the transfer keeps its halt semantics at the Ended
    /// consume — pre-fix the default record silently dropped the
    /// flag and the consume dispatched a natural terminal. Returns
    /// false when the gid is not on the active face — the idempotency
    /// guard against a duplicate SeedingStarted (repeat arrival must
    /// not repeat the transfer) and against the Ended-first race (the
    /// task already finalized).
    pub(crate) fn begin_seeding(&mut self, gid: Gid) -> bool {
        let Some(rec) = self.active.remove(&gid) else {
            return false;
        };
        self.seeding.insert(
            gid,
            SeedingRecord {
                pause_requested: rec.pause_requested,
                remove_requested: rec.remove_requested,
                slot_released: false,
            },
        );
        true
    }

    /// Direct seeding registration (seed_wait promotion / restart
    /// routing): enters the registry without passing through active —
    /// the seed-side activation path (engine assembly with the complete
    /// bitmap happens inside the seed slot, never a download slot).
    /// Idempotent (a re-insert overwrites the record).
    pub(crate) fn insert_seeding(&mut self, gid: Gid) {
        self.seed_wait.retain(|&g| g != gid);
        self.seeding.insert(gid, SeedingRecord::default());
    }

    /// Leave the seeding registry (Ended consume / remove / checking
    /// transition).
    pub(crate) fn remove_seeding(&mut self, gid: Gid) -> bool {
        self.seeding.remove(&gid).is_some()
    }

    pub(crate) fn contains_seeding(&self, gid: Gid) -> bool {
        self.seeding.contains_key(&gid)
    }

    /// Seeding GID snapshot (BTreeMap order = GID order, the same
    /// set-semantics note as `active_gids`).
    pub(crate) fn seeding_gids(&self) -> Vec<Gid> {
        self.seeding.keys().copied().collect()
    }

    /// Occupied seed-slot count (budget accounting; entries whose slot
    /// was released for an in-flight forceRecheck stop do not count).
    pub(crate) fn seeding_len(&self) -> usize {
        self.seeding.values().filter(|r| !r.slot_released).count()
    }

    /// Request-flag snapshot before the seeding retire (the seed-domain
    /// twin of `active_flags`): (pause, remove).
    pub(crate) fn seeding_flags(&self, gid: Gid) -> Option<(bool, bool)> {
        self.seeding
            .get(&gid)
            .map(|r| (r.pause_requested, r.remove_requested))
    }

    /// Pause request (the seeding-residence face of `request_pause`:
    /// failure = already in the pause/remove flow).
    pub(crate) fn request_seed_pause(&mut self, gid: Gid) -> bool {
        match self.seeding.get_mut(&gid) {
            Some(rec) if !rec.pause_requested && !rec.remove_requested => {
                rec.pause_requested = true;
                true
            }
            _ => false,
        }
    }

    /// Remove request (halt semantics: clears pause — the same override
    /// order as [`ActiveRecord`]).
    pub(crate) fn request_seed_remove(&mut self, gid: Gid) -> bool {
        match self.seeding.get_mut(&gid) {
            Some(rec) => {
                rec.remove_requested = true;
                rec.pause_requested = false;
                true
            }
            None => false,
        }
    }

    /// Release the seed slot while the registry entry stays (the
    /// forceRecheck Seeding arm: the graceful stop is in flight; the
    /// slot is reusable immediately, find()/pause/remove keep working
    /// until the Ended consume clears the entry).
    pub(crate) fn release_seed_slot(&mut self, gid: Gid) -> bool {
        match self.seeding.get_mut(&gid) {
            Some(rec) => {
                rec.slot_released = true;
                true
            }
            None => false,
        }
    }

    /// Append to the seed_wait FIFO (budget-full completions / restart
    /// routing). A duplicate append is absorbed (a gid is parked at
    /// most once — the unique-membership invariant).
    pub(crate) fn push_seed_wait(&mut self, gid: Gid) {
        if !self.seed_wait.contains(&gid) {
            self.seed_wait.push_back(gid);
        }
    }

    /// Leave the seed_wait FIFO (pause / remove on a parked member).
    pub(crate) fn remove_seed_wait(&mut self, gid: Gid) -> bool {
        let before = self.seed_wait.len();
        self.seed_wait.retain(|&g| g != gid);
        self.seed_wait.len() != before
    }

    /// Seed-wait FIFO snapshot (the registry domain-enumeration face —
    /// the tellWaiting projection reads [`Self::waiting_snapshot`];
    /// production consumers go through the budget/promotion faces, the
    /// queue-level governance tests read the registry directly).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn seed_wait_gids(&self) -> Vec<Gid> {
        self.seed_wait.iter().copied().collect()
    }

    /// Seed-pool admission (the promotion half of pump_all's seed
    /// segment): pop the seed_wait front and enter the seeding
    /// registry when the budget allows. `budget = 0` = unlimited
    /// (the two-state default; see GlobalOptions::max_concurrent_seeds).
    /// Returns None when the FIFO is empty or the budget is full.
    /// Never evicts residents (a narrowed budget never preempts: an over-subscribed
    /// registry is tolerated, the narrowing converges via natural
    /// exits).
    pub(crate) fn admit_next_seed(&mut self, budget: usize) -> Option<Gid> {
        if budget > 0 && self.seeding_len() >= budget {
            return None;
        }
        let gid = self.seed_wait.pop_front()?;
        self.seeding.insert(gid, SeedingRecord::default());
        Some(gid)
    }

    // ---- synthesis pool (processing residence + proc_wait) ----

    /// active → proc_wait transfer (the SynthesisGate consume):
    /// the driver reached the Downloading → Processing boundary — the
    /// download slot is released the moment the record moves; the
    /// live-state face (`running`: driver live handle/token) stays
    /// untouched (pure queue accounting). The parked entry **carries
    /// the active record's request flags**, so a pause/remove racing
    /// the gate arrival keeps its halt semantics at the Ended consume.
    /// Returns false when the gid is not a current active resident —
    /// the idempotency guard against a duplicate notice (or the
    /// remove/Ended-first race where the task already finalized), the
    /// [`Self::begin_seeding`] shape.
    pub(crate) fn begin_synthesis_park(&mut self, gid: Gid) -> bool {
        let Some(rec) = self.active.remove(&gid) else {
            return false;
        };
        if !self.proc_wait.iter().any(|p| p.gid == gid) {
            self.proc_wait.push_back(SynthesisPark {
                gid,
                pause_requested: rec.pause_requested,
                remove_requested: rec.remove_requested,
            });
        }
        true
    }

    /// Occupied synthesis-slot count (budget accounting; in-flight
    /// syntheses only — parked members hold no slot).
    pub(crate) fn processing_len(&self) -> usize {
        self.processing.len()
    }

    /// Processing GID snapshot (BTreeMap order = GID order, the same
    /// set-semantics note as `active_gids`).
    pub(crate) fn processing_gids(&self) -> Vec<Gid> {
        self.processing.keys().copied().collect()
    }

    /// Synthesis-pool waiting FIFO snapshot (the tellWaiting appended
    /// segment; FIFO arrival order).
    pub(crate) fn proc_wait_gids(&self) -> Vec<Gid> {
        self.proc_wait.iter().map(|p| p.gid).collect()
    }

    /// The parked FIFO head, unless it carries a pause/remove request —
    /// a flagged head's driver is already tearing down (the token
    /// cancel raced the gate await) and must never receive a permit;
    /// the promotion pauses at it until the Ended consume clears the
    /// entry (release-then-backfill happens at that consume's
    /// trailing pump_all).
    pub(crate) fn proc_wait_front(&self) -> Option<Gid> {
        let head = self.proc_wait.front()?;
        if head.pause_requested || head.remove_requested {
            return None;
        }
        Some(head.gid)
    }

    /// Leave the parked FIFO and enter the processing registry (the
    /// promotion half of pump_all's synthesis segment — the caller
    /// checked the budget via [`Self::processing_len`] and holds the
    /// permit end from the actor-side gate map before calling).
    /// Returns the promoted gid (None = the FIFO drained between the
    /// caller's peek and this pop — structurally impossible in the
    /// single-threaded actor, defensive).
    pub(crate) fn promote_synthesis_head(&mut self) -> Option<Gid> {
        let park = self.proc_wait.pop_front()?;
        self.processing
            .insert(park.gid, ProcessingRecord::default());
        Some(park.gid)
    }

    /// Leave the synthesis faces (the Ended consume cleanup / the
    /// force-remove immediate detach): drops whichever face holds the
    /// gid — processing registry or proc_wait FIFO.
    pub(crate) fn remove_synthesis(&mut self, gid: Gid) -> bool {
        let had = self.processing.remove(&gid).is_some();
        let before = self.proc_wait.len();
        self.proc_wait.retain(|p| p.gid != gid);
        had || self.proc_wait.len() != before
    }

    /// Membership across both synthesis faces (the handle_ended routing
    /// guard: a synthesis-side teardown must dispatch from these faces —
    /// the download slot was released at the gate, the active face is
    /// gone).
    pub(crate) fn contains_synthesis(&self, gid: Gid) -> bool {
        self.processing.contains_key(&gid) || self.proc_wait.iter().any(|p| p.gid == gid)
    }

    /// Request-flag snapshot across both synthesis faces (the
    /// synthesis-domain twin of `active_flags`/`seeding_flags`:
    /// (pause, remove)) — the Ended consume's dispatch basis.
    pub(crate) fn synthesis_flags(&self, gid: Gid) -> Option<(bool, bool)> {
        if let Some(rec) = self.processing.get(&gid) {
            return Some((rec.pause_requested, rec.remove_requested));
        }
        self.proc_wait
            .iter()
            .find(|p| p.gid == gid)
            .map(|p| (p.pause_requested, p.remove_requested))
    }

    /// Pause request across both synthesis faces (failure = already in
    /// the pause/remove flow — the same decision source as
    /// `request_pause`/`request_seed_pause`).
    pub(crate) fn request_synthesis_pause(&mut self, gid: Gid) -> bool {
        if let Some(rec) = self.processing.get_mut(&gid) {
            if !rec.pause_requested && !rec.remove_requested {
                rec.pause_requested = true;
                return true;
            }
            return false;
        }
        match self.proc_wait.iter_mut().find(|p| p.gid == gid) {
            Some(park) if !park.pause_requested && !park.remove_requested => {
                park.pause_requested = true;
                true
            }
            _ => false,
        }
    }

    /// Remove request across both synthesis faces (halt semantics:
    /// clears pause — the same override order as the active/seed
    /// domains).
    pub(crate) fn request_synthesis_remove(&mut self, gid: Gid) -> bool {
        if let Some(rec) = self.processing.get_mut(&gid) {
            rec.remove_requested = true;
            rec.pause_requested = false;
            return true;
        }
        match self.proc_wait.iter_mut().find(|p| p.gid == gid) {
            Some(park) => {
                park.remove_requested = true;
                park.pause_requested = false;
                true
            }
            None => false,
        }
    }

    /// Detach from the synthesis faces and dispatch per the flags:
    /// pause -> requeue to front paused (Some(true)); otherwise ->
    /// DownloadResult. Works from either face (the consume knows the
    /// Ended arrived — a processing member or a still-parked member
    /// whose gate await lost the token race). The synthesis-domain twin
    /// of [`Self::retire_active`]/[`Self::retire_seeding`].
    pub(crate) fn retire_synthesis(
        &mut self,
        gid: Gid,
        result: DownloadResultEntry,
    ) -> Option<bool> {
        // The registry face first, then the parked FIFO (a gid lives in
        // exactly one of them). Flags are read before the removal.
        let requeue = if let Some(rec) = self.processing.remove(&gid) {
            rec.requeue_paused()
        } else {
            let idx = self.proc_wait.iter().position(|p| p.gid == gid)?;
            let park = self.proc_wait.remove(idx)?;
            park.requeue_paused()
        };
        match requeue {
            Some(paused) => {
                self.reserved.push_front(ReservedEntry { gid, paused });
                Some(paused)
            }
            None => {
                self.record_result(result);
                None
            }
        }
    }

    /// Results-table write half (shared by the seeding retire path with
    /// [`Self::retire_active`]: numStoppedTotal++ and the
    /// max-download-result trim).
    pub(crate) fn record_result(&mut self, result: DownloadResultEntry) {
        self.num_stopped_total += 1;
        self.results.push_back(result);
        while self.results.len() > self.max_results {
            self.results.pop_front();
        }
    }

    /// Detach from the seeding registry and dispatch per the record:
    /// pause -> requeue to front paused (Some(true)); otherwise ->
    /// DownloadResult. The seed-domain twin of [`Self::retire_active`].
    pub(crate) fn retire_seeding(&mut self, gid: Gid, result: DownloadResultEntry) -> Option<bool> {
        let rec = self.seeding.remove(&gid)?;
        match rec.requeue_paused() {
            Some(paused) => {
                self.reserved.push_front(ReservedEntry { gid, paused });
                Some(paused)
            }
            None => {
                self.record_result(result);
                None
            }
        }
    }

    /// GID expansion set (the expandUnique candidate set: active ∪
    /// waiting ∪ results — the liveness face of aria2 `GroupId::set_`,
    /// GroupId.cc).
    pub(crate) fn known_gids(&self) -> Vec<Gid> {
        let mut out: Vec<Gid> = self.active.keys().copied().collect();
        out.extend(self.checking.keys().copied());
        out.extend(self.check_pending.iter().map(|e| e.gid));
        out.extend(self.seeding.keys().copied());
        out.extend(self.seed_wait.iter().copied());
        out.extend(self.processing.keys().copied());
        out.extend(self.proc_wait.iter().map(|p| p.gid));
        out.extend(self.reserved.iter().map(|e| e.gid));
        out.extend(self.results.iter().map(|r| r.gid));
        out.sort();
        out.dedup();
        out
    }

    pub(crate) fn find(&self, gid: Gid) -> Option<Location> {
        if self.active.contains_key(&gid) {
            return Some(Location::Active);
        }
        if let Some(paused) = self.checking.get(&gid) {
            return Some(if *paused {
                Location::CheckingPaused
            } else {
                Location::Checking
            });
        }
        // Parked check_pending projects through the same Checking
        // location pair (no new Location variant: the
        // parked face differs from in-flight only in the registry the
        // intent lives in and the tellWaiting segment it appears in;
        // the Checking-arm command semantics — pause/unpause intent
        // rewrite, remove proceeds as usual, forceRecheck rejected as already
        // scheduled, active-semantics status projection — are shared).
        // The tellActive/tellWaiting segmentation does NOT go through
        // find(): the views iterate checking_gids() (in-flight only)
        // and check_pending_gids() respectively.
        if let Some(entry) = self.check_pending.iter().find(|e| e.gid == gid) {
            return Some(if entry.paused {
                Location::CheckingPaused
            } else {
                Location::Checking
            });
        }
        if self.seeding.contains_key(&gid) {
            return Some(Location::Seeding);
        }
        if self.seed_wait.contains(&gid) {
            return Some(Location::SeedWaiting);
        }
        // Synthesis pool: an in-flight synthesis (the
        // processing registry) or a gate-hung driver (proc_wait). One
        // variant per face — no paused twins: the pause/remove intent
        // rides the records' flags (the consume reads them), and the
        // command arms treat both faces uniformly (the parked face
        // shares the Synthesizing-arm semantics, the check pool's
        // shared-pair precedent).
        if self.processing.contains_key(&gid) {
            return Some(Location::Synthesizing);
        }
        if self.proc_wait.iter().any(|p| p.gid == gid) {
            return Some(Location::SynthesisWaiting);
        }
        match self.reserved_entry(gid) {
            Some(e) if e.paused => Some(Location::ReservedPaused),
            Some(_) => Some(Location::Reserved),
            None => {
                if self.results.iter().any(|r| r.gid == gid) {
                    Some(Location::Result)
                } else {
                    None
                }
            }
        }
    }
}

/// The GID's current location (the state-decision face for pause /
/// remove / unpause — the session-side isomorph of aria2 `findGroup`
/// active∪reserved + `findDownloadResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    Active,
    Reserved,
    ReservedPaused,
    /// On-disk recheck in flight (an aria2 verification-period group
    /// has active semantics — the projection face presents it as
    /// active; this variant is only for command-arm dispatch). Since
    /// the check pool landed, the same pair also locates a gid **parked** in
    /// check_pending (no new variant — see `find`): the parked face
    /// shares the Checking-arm command semantics.
    Checking,
    /// Same + user pause intent (stays paused after the post-verification
    /// requeue).
    CheckingPaused,
    /// BT seeding residence: the task's engine is
    /// running in the seed pool — no download slot. Command dispatch
    /// arm (pause = graceful stop -> requeue paused; remove as usual;
    /// forceRecheck = deferred checking via the released slot).
    Seeding,
    /// Parked in the seed-pool waiting FIFO (budget full / restart
    /// routing): no engine running, no slot of any pool occupied.
    /// tellWaiting projects these with the 'seeding' status extension.
    SeedWaiting,
    /// Media synthesis in flight: the driver is past
    /// its gate permit, running Processing/Verifying inside the
    /// synthesis slot — no download slot (released at the gate).
    /// Command arms: pause/remove flag + token cancel (the teardown's
    /// Ended consume dispatches); changeOption = the live-driver face
    /// (the Seeding-arm shape); forceRecheck unreachable (media jobs
    /// reject at the family face before Location dispatch). tellActive
    /// projects the resident with the 'active' status (§5: the driver
    /// is live; the numActive *meter* stays download-slots-only — the
    /// pinned caliber), tellWaiting's proc_wait segment is the parked
    /// twin.
    Synthesizing,
    /// Parked in the synthesis-pool waiting FIFO (the gate hang under a
    /// full `media-synthesis-concurrency` budget): no running slot of
    /// any pool occupied — **but a live driver hangs on the permit**
    /// (the await races the token, so pause/remove cancel it). The row
    /// stays at its download-phase value (no new row state; the gate
    /// hang never crosses a restart) and tellWaiting projects the
    /// 'waiting' existing value (§4.3/§5; the waiting-face
    /// finalization).
    SynthesisWaiting,
    Result,
}

#[cfg(test)]
mod tests {
    use super::super::view::StatusKind;
    use super::*;

    fn g(n: u64) -> Gid {
        Gid::from_u64(n)
    }

    fn entry(gid: Gid, paused: bool) -> ReservedEntry {
        ReservedEntry { gid, paused }
    }

    fn done(gid: Gid) -> DownloadResultEntry {
        DownloadResultEntry {
            gid,
            status: StatusKind::Complete,
            total_length: 100,
            completed_length: 100,
            upload_length: 0,
            download_length: 0,
            dir: ".".into(),
            error_message: None,
            error_engine: None,
            bitfield: None,
            piece_length: 0,
            num_pieces: 0,
            info_hash: None,
            files: Vec::new(),
            num_files_full: None,
            bittorrent: None,
            http: None,
            media: None,
        }
    }

    /// Table-driven: fillup up to max-concurrent, FIFO order, excess
    /// stays queued.
    #[test]
    fn fillup_activates_up_to_max_concurrent_in_fifo_order() {
        let mut q = QueueMan::new();
        for i in 0..7u64 {
            q.insert_reserved(entry(g(0x8000 + i), false), None);
        }
        let batch = q.fillup(5);
        assert_eq!(
            batch,
            (0..5u64).map(|i| g(0x8000 + i)).collect::<Vec<_>>(),
            "FIFO order, exactly max-concurrent activated"
        );
        assert_eq!(q.active_len(), 5);
        assert_eq!(q.reserved_snapshot().len(), 2);
        // No free slots -> no more activations.
        assert!(q.fillup(5).is_empty());
        // Finalize one -> activate one more.
        assert_eq!(q.retire_active(g(0x8000), done(g(0x8000))), None);
        assert_eq!(q.fillup(5), vec![g(0x8005)]);
    }

    /// Table-driven: paused entries skipped, order preserved (the
    /// fillup pending re-insert).
    #[test]
    fn fillup_skips_paused_and_preserves_queue_order() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), true), None); // paused
        q.insert_reserved(entry(g(2), false), None);
        q.insert_reserved(entry(g(3), true), None); // paused
        q.insert_reserved(entry(g(4), false), None);
        assert_eq!(q.fillup(4), vec![g(2), g(4)]);
        assert_eq!(q.reserved_snapshot().len(), 2);
        let left: Vec<u64> = q
            .reserved_snapshot()
            .into_iter()
            .map(|e| e.gid.as_u64())
            .collect();
        assert_eq!(
            left,
            vec![1, 3],
            "paused entries keep relative order at front"
        );
        // After unpause it can be activated.
        q.reserved_entry_mut(g(1))
            .unwrap_or_else(|| panic!("entry"))
            .paused = false;
        assert_eq!(q.fillup(4), vec![g(1)]);
    }

    /// Table-driven: pause finalization requeues to the front
    /// (push_front) — a later task lands ahead of earlier arrivals.
    #[test]
    fn pause_end_requeues_to_front_ahead_of_later_arrivals() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        q.insert_reserved(entry(g(2), false), None); // late arrival
        q.insert_reserved(entry(g(3), false), None);
        // pause: set the request + finalize requeue to front paused.
        assert!(q.request_pause(g(1)));
        assert_eq!(q.retire_active(g(1), done(g(1))), Some(true));
        // The front paused entry is skipped (order preserved); later
        // ready entries fill normally (same rule as aria2: pending
        // entries do not block fillup).
        assert_eq!(q.fillup(1), vec![g(2)]);
        assert_eq!(q.retire_active(g(2), done(g(2))), None);
        assert_eq!(q.reserved_snapshot().len(), 2);
        assert_eq!(
            q.reserved_snapshot()[0].gid,
            g(1),
            "paused task goes to queue FRONT"
        );
        // unpause -> fillup activates it first (ahead of the new task
        // g3).
        q.reserved_entry_mut(g(1))
            .unwrap_or_else(|| panic!("entry"))
            .paused = false;
        assert_eq!(q.fillup(1), vec![g(1)]);
    }

    /// Table-driven: restart (the changeOption restart path) finalizes
    /// to the front and is immediately eligible for reactivation.
    #[test]
    fn restart_end_requeues_unpaused_and_reactivates() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        q.insert_reserved(entry(g(2), false), None);
        if let Some(rec) = q.active_record_mut(g(1)) {
            rec.restart_requested = true;
        }
        assert_eq!(
            q.retire_active(g(1), done(g(1))),
            Some(false),
            "restart requeues unpaused"
        );
        assert_eq!(
            q.fillup(1),
            vec![g(1)],
            "restart task reactivates before newcomers"
        );
        assert_eq!(q.active_len(), 1);
        assert_eq!(q.reserved_snapshot().len(), 1);
    }

    /// Table-driven: bt-detach-seed-only consumption — a Detached
    /// terminal state is accounted as complete, releases the
    /// concurrency slot, and fillup immediately backfills (the
    /// EngineEnd::Detached consumption point; the difference between
    /// releasing at completion time vs finalization time is declared in
    /// the actor module docs boundary).
    #[test]
    fn detached_end_releases_slot_and_next_task_starts() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        q.insert_reserved(entry(g(2), false), None);
        // Detached finalization: result = Complete (seed-release
        // finalization, not an error); the slot is released.
        let detached = done(g(1));
        assert_eq!(q.retire_active(g(1), detached), None);
        assert_eq!(q.fillup(1), vec![g(2)], "slot released → queue fills");
        assert_eq!(q.num_stopped_total(), 1);
        let stored = q.results().next().unwrap_or_else(|| panic!("result"));
        assert_eq!(stored.status, StatusKind::Complete);
    }

    /// remove full chain: active remove -> result(Removed); waiting
    /// remove -> no result; remove clears pause (halt semantics).
    #[test]
    fn remove_paths_and_pause_cleared_by_halt() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), true), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        // active remove (pause was set before -> cleared by halt).
        assert!(q.request_pause(g(1)));
        assert!(q.request_remove(g(1)));
        let rec = q.active_record_mut(g(1)).unwrap_or_else(|| panic!("rec"));
        assert!(!rec.pause_requested && rec.remove_requested);
        assert_eq!(
            q.retire_active(g(1), {
                let mut e = done(g(1));
                e.status = StatusKind::Removed;
                e.total_length = 0;
                e.completed_length = 0;
                e
            }),
            None
        );
        assert_eq!(
            q.results().next().unwrap_or_else(|| panic!("r")).status,
            StatusKind::Removed
        );
        // waiting remove: dequeue directly, no result entry.
        assert!(q.remove_reserved(g(2)));
        assert_eq!(q.results().count(), 1);
        assert_eq!(
            q.num_stopped_total(),
            1,
            "only the removed-active group counted"
        );
    }

    /// DownloadResult table: numStoppedTotal only grows, purge clears
    /// the table but not the count, removeDownloadResult removes
    /// exactly, table length trimmed.
    #[test]
    fn result_table_purge_remove_and_total_accounting() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), false), None);
        assert_eq!(q.fillup(2), vec![g(1), g(2)]);
        assert_eq!(q.retire_active(g(1), done(g(1))), None);
        assert_eq!(q.retire_active(g(2), done(g(2))), None);
        assert_eq!(q.num_stopped_total(), 2);
        assert!(q.remove_result(g(1)));
        assert!(!q.remove_result(g(1)), "second remove must fail");
        q.purge_results();
        assert_eq!(q.results().count(), 0);
        assert_eq!(q.num_stopped_total(), 2, "purge never touches the total");
    }

    /// position semantics: clamped insertion (insertReservedGroup).
    #[test]
    fn insert_position_is_clamped() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), false), Some(0));
        assert_eq!(q.reserved_snapshot()[0].gid, g(2), "pos 0 → front");
        q.insert_reserved(entry(g(3), false), Some(999));
        assert_eq!(
            q.reserved_snapshot()
                .last()
                .unwrap_or_else(|| panic!("e"))
                .gid,
            g(3),
            "pos beyond len → tail"
        );
    }

    /// Reference baseline for move_reserved (a line-by-line
    /// transcription of the reference): the C++ translation of
    /// IndexedList.h `move()` — the dest computation keeps the original
    /// branch structure, the reorder replicates the std::rotate two
    /// branches with remove+insert.
    fn reference_move(seq: &mut Vec<u64>, key: u64, offset: i64, how: OffsetMode) -> Option<usize> {
        let xp = seq.iter().position(|k| *k == key)?;
        let size = seq.len() as i64;
        let dest: i64 = match how {
            OffsetMode::Cur => if offset > 0 {
                (xp as i64 + offset).min(size - 1)
            } else {
                (xp as i64 + offset).max(0)
            }
            .max(0),
            OffsetMode::End => (size - 1 + offset).min(size - 1).max(0),
            OffsetMode::Set => (offset.min(size - 1)).max(0),
        };
        seq.remove(xp);
        seq.insert(dest as usize, key);
        Some(dest as usize)
    }

    /// Cross-check (the full combination matrix): {front/middle/tail} x
    /// POS_SET/POS_CUR/POS_END x {±1, ±large out-of-range, 0, in-place}
    /// — each case compared against the transcribed reference baseline
    /// for both the returned index and the whole queue order.
    #[test]
    fn move_reserved_matches_reference_move_across_full_matrix() {
        for xp_key in [1u64, 3, 5] {
            for how in [OffsetMode::Set, OffsetMode::Cur, OffsetMode::End] {
                for pos in [-9i64, -1, 0, 1, 9] {
                    // Baseline: the reference transcription replayed on
                    // a Vec with the same initial queue.
                    let mut reference_seq: Vec<u64> = (1..=5).collect();
                    let want = reference_move(&mut reference_seq, xp_key, pos, how);
                    // This side: executed on a real QueueMan.
                    let mut q = QueueMan::new();
                    for i in 1..=5u64 {
                        q.insert_reserved(entry(g(0x8000 + i), false), None);
                    }
                    let got = q.move_reserved(g(0x8000 + xp_key), pos, how);
                    assert_eq!(
                        got, want,
                        "destination drift: key={xp_key} how={how:?} pos={pos}"
                    );
                    let got_seq: Vec<u64> = q
                        .reserved_snapshot()
                        .iter()
                        .map(|e| e.gid.as_u64() - 0x8000)
                        .collect();
                    assert_eq!(
                        got_seq, reference_seq,
                        "queue-order drift: key={xp_key} how={how:?} pos={pos}"
                    );
                }
            }
        }
    }

    /// Edges: unknown gid = None (the reference -1 face); a
    /// single-entry queue always dest 0; extreme pos values
    /// (i64::MIN/MAX) do not panic and clamp back into the valid
    /// domain.
    #[test]
    fn move_reserved_edges_unknown_gid_single_and_extremes() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        assert_eq!(
            q.move_reserved(g(99), 0, OffsetMode::Set),
            None,
            "unknown gid -> the reference -1"
        );
        assert_eq!(
            q.move_reserved(g(1), 7, OffsetMode::Cur),
            Some(0),
            "a single-element queue is always 0"
        );
        for how in [OffsetMode::Set, OffsetMode::Cur, OffsetMode::End] {
            for pos in [i64::MIN, i64::MAX] {
                assert_eq!(
                    q.move_reserved(g(1), pos, how),
                    Some(0),
                    "extreme {pos:?} {how:?} clamps to 0"
                );
            }
        }
    }

    /// Paused entries can be moved (the reference reservedGroups_
    /// contains pauseRequested reserved entries) and moving does not
    /// touch the paused flag — the fillup order-preserving re-insert
    /// face is unaffected.
    #[test]
    fn move_reserved_moves_paused_entry_without_flag_change() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), true), None);
        q.insert_reserved(entry(g(3), false), None);
        assert_eq!(q.move_reserved(g(2), 0, OffsetMode::Set), Some(0));
        let snap = q.reserved_snapshot();
        assert_eq!(snap[0].gid, g(2));
        assert!(snap[0].paused, "the paused flag rides the row unchanged");
        assert_eq!(q.find(g(2)), Some(Location::ReservedPaused));
    }

    /// The four-state location of find (the decision source for pause /
    /// remove / unpause).
    #[test]
    fn find_locates_all_four_states() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), true), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        assert_eq!(q.retire_active(g(1), done(g(1))), None);
        assert_eq!(q.find(g(1)), Some(Location::Result));
        assert_eq!(q.find(g(2)), Some(Location::ReservedPaused));
        assert_eq!(q.find(g(99)), None);
    }

    /// Recheck-in-flight bookkeeping — fillup skips it (no concurrency
    /// slot), find locates Checking(Paused), known_gids includes it
    /// (the str2Gid prefix-parse domain), pause-intent rewrite and
    /// unregistration. Extended (the four-pool
    /// promotion): the seed pool is orthogonal to fillup in both
    /// directions — seeding residence and seed_wait parking occupy no
    /// download slot (fillup neither counts nor admits them), and the
    /// seed admission (`admit_next_seed`) ignores the reserved queue.
    /// Extended again (the check-pool slice): check_pending
    /// parking is orthogonal to fillup too (no download slot), and the
    /// check admission (`admit_next_check`) ignores the reserved queue.
    /// Extended a third time (the synthesis slice): both
    /// synthesis faces — the processing registry and the proc_wait
    /// FIFO — are orthogonal to fillup (no download slot), and the
    /// synthesis promotion reads only the parked FIFO.
    #[test]
    fn checking_bookkeeping_is_orthogonal_to_fillup() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(10), false), None);
        q.insert_checking(g(2), false);
        q.insert_checking(g(3), true);
        // Seed pool: one resident (active→seeding transfer) + one parked.
        assert_eq!(q.fillup(2), vec![g(1), g(10)]);
        assert!(q.begin_seeding(g(1)));
        q.push_seed_wait(g(4));
        // Check pool: two parked (one with the pause intent).
        q.insert_check_pending(g(6), false);
        q.insert_check_pending(g(7), true);
        // Synthesis pool: g10 goes active→proc_wait→processing (the gate
        // permit taken); g8 parks (active→proc_wait, budget full — the
        // FIFO keeps it until the release edge).
        assert!(q.begin_synthesis_park(g(10)));
        assert_eq!(q.promote_synthesis_head(), Some(g(10)));
        q.insert_reserved(entry(g(8), false), None);
        assert_eq!(
            q.fillup(2),
            vec![g(8)],
            "the freed download slot backfills immediately"
        );
        assert!(q.begin_synthesis_park(g(8)));
        // fillup activates only ready waiting entries; in-flight
        // verification, parked checks, seeding/seed_wait and both
        // synthesis faces take no download slot.
        q.insert_reserved(entry(g(5), false), None);
        assert_eq!(q.fillup(2), vec![g(5)]);
        assert_eq!(
            q.active_len(),
            1,
            "seeding/synthesis residents never occupy a download slot"
        );
        assert_eq!(q.find(g(1)), Some(Location::Seeding));
        assert_eq!(q.find(g(4)), Some(Location::SeedWaiting));
        assert_eq!(q.find(g(2)), Some(Location::Checking));
        assert_eq!(q.find(g(3)), Some(Location::CheckingPaused));
        assert_eq!(
            q.find(g(6)),
            Some(Location::Checking),
            "a parked member projects at the same location"
        );
        assert_eq!(q.find(g(7)), Some(Location::CheckingPaused));
        assert_eq!(q.find(g(10)), Some(Location::Synthesizing));
        assert_eq!(q.find(g(8)), Some(Location::SynthesisWaiting));
        assert_eq!(
            q.processing_gids(),
            vec![g(10)],
            "the promoted member enters the processing registry"
        );
        assert_eq!(
            q.proc_wait_gids(),
            vec![g(8)],
            "the parked member stays in the proc_wait FIFO"
        );
        // The str2Gid parse domain (known_gids) includes in-flight
        // verification, parked checks, both seed faces and both
        // synthesis faces.
        let known: Vec<u64> = q.known_gids().iter().map(|g| g.as_u64()).collect();
        for n in [1u64, 2, 3, 4, 5, 6, 7, 8, 10] {
            assert!(
                known.contains(&n),
                "gid {n} must be in the resolution domain"
            );
        }
        // Pause-intent rewrite (the admission face for pause/unpause
        // during verification) hits whichever face holds the gid —
        // in-flight or parked.
        assert!(q.set_check_paused(g(2), true));
        assert_eq!(q.find(g(2)), Some(Location::CheckingPaused));
        assert!(
            q.set_check_paused(g(7), false),
            "a parked member is rewritten through the same entry point"
        );
        assert_eq!(q.find(g(7)), Some(Location::Checking));
        assert!(!q.set_check_paused(g(9), true), "not registered = false");
        // Unregister and fetch the intent; after unregistration it can
        // re-enter the waiting queue and activate normally.
        assert_eq!(q.remove_checking(g(2)), Some(true));
        assert_eq!(q.find(g(2)), None);
        q.insert_reserved(entry(g(2), false), Some(0));
        assert_eq!(q.fillup(2), vec![g(2)]);
    }

    // ---- check pool ----

    /// Table-driven: the check budget boundary — parked members promote
    /// in FIFO order strictly within the budget, a completion frees the
    /// slot and the next admission happens in the same round
    /// (release-then-backfill, no idle beat), and a narrowed budget
    /// never preempts in-flight rechecks (⑩: over-subscription is
    /// tolerated, a new budget only constrains subsequent admissions).
    #[test]
    fn check_budget_parks_and_promotes_in_fifo_order_and_narrowing_never_preempts() {
        let mut q = QueueMan::new();
        // Three parked with budget 2: the first two promote (FIFO), the
        // third stays parked.
        q.insert_check_pending(g(1), false);
        q.insert_check_pending(g(2), true);
        q.insert_check_pending(g(3), false);
        assert_eq!(q.admit_next_check(2).map(|x| x.gid), Some(g(1)));
        // The admitted entry moves into the in-flight registry (the
        // actor does this right after admission).
        q.insert_checking(g(1), false);
        assert_eq!(q.admit_next_check(2).map(|x| x.gid), Some(g(2)));
        q.insert_checking(g(2), true);
        assert_eq!(
            q.admit_next_check(2),
            None,
            "budget full at 2: the third stays parked (FIFO order preserved)"
        );
        assert_eq!(q.checking_len(), 2);
        assert_eq!(q.check_pending_gids(), vec![g(3)]);
        // Budget narrowed to 1 with two in flight: nobody is evicted
        // (narrowing never preempts), no admission happens.
        assert_eq!(q.admit_next_check(1), None);
        assert_eq!(q.checking_len(), 2);
        // One completes (the registry entry leaves at the RecheckDone
        // consume) -> the freed slot admits the parked member in the
        // same round under the pre-narrowing budget
        // (release-then-backfill); the entry's paused intent rides
        // through.
        assert_eq!(q.remove_checking(g(1)), Some(false));
        assert_eq!(
            q.admit_next_check(2).map(|x| (x.gid, x.paused)),
            Some((g(3), false))
        );
        q.insert_checking(g(3), false);
        assert!(q.check_pending_gids().is_empty());
        // g2 completes: the narrowed budget stays full while g3 is in
        // flight — the new budget constrains subsequent admissions only,
        // nobody is evicted.
        assert_eq!(q.remove_checking(g(2)), Some(true));
        assert_eq!(
            q.admit_next_check(1),
            None,
            "after narrowing to budget 1: g3 in flight fills it"
        );
        // g3 completes: nothing parked, the pool drains.
        assert_eq!(q.remove_checking(g(3)), Some(false));
        assert_eq!(q.checking_len(), 0);
        assert_eq!(q.admit_next_check(1), None);
    }

    /// Table-driven: the park face dedups (a gid parks at most once —
    /// the unique-membership rule), pause-intent rewrite on a parked
    /// member lands, and removal
    /// clears exactly the parked entry.
    #[test]
    fn check_pending_park_dedup_intent_and_removal() {
        let mut q = QueueMan::new();
        q.insert_check_pending(g(1), false);
        q.insert_check_pending(g(1), false);
        assert_eq!(
            q.check_pending_gids(),
            vec![g(1)],
            "duplicate registration is absorbed (unique ownership)"
        );
        assert!(q.set_check_pending_paused(g(1), true));
        assert_eq!(q.find(g(1)), Some(Location::CheckingPaused));
        assert!(!q.set_check_pending_paused(g(9), true));
        assert!(q.remove_check_pending(g(1)));
        assert!(!q.remove_check_pending(g(1)), "a second removal = false");
        assert_eq!(q.find(g(1)), None);
    }

    // ---- seed pool ----

    /// Table-driven: the active→seeding transfer releases the download
    /// slot immediately (fillup backfills in the same round) and is
    /// idempotent (a duplicate SeedingStarted must not repeat the
    /// transfer — nor displace a fresh active record).
    #[test]
    fn begin_seeding_releases_slot_and_is_idempotent() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), false), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        // Transfer: active empties, seeding registers, slot backfills.
        assert!(q.begin_seeding(g(1)));
        assert_eq!(q.active_len(), 0);
        assert_eq!(q.seeding_len(), 1);
        assert_eq!(
            q.fillup(1),
            vec![g(2)],
            "the download slot backfills immediately"
        );
        // Duplicate arrival: no transfer (not active), and the active
        // slot of a *different* task is never touched.
        assert!(!q.begin_seeding(g(1)));
        assert_eq!(q.seeding_len(), 1);
        assert!(q.contains_active(g(2)));
        // Ended-first race shape: retire from active finalizes without
        // the seeding registry ever being entered; a late transfer
        // attempt stays a no-op.
        assert_eq!(q.retire_active(g(2), done(g(2))), None);
        assert!(!q.begin_seeding(g(2)));
        assert_eq!(q.seeding_len(), 1);
        assert_eq!(q.results().map(|r| r.gid).collect::<Vec<_>>(), vec![g(2)]);
    }

    /// The request flags carry through the active→seeding
    /// transfer (the `begin_synthesis_park` alignment) — a
    /// pause/remove racing the SeedingStarted arrival keeps its halt
    /// semantics at the Ended consume. Pre-fix the transfer inserted
    /// a default `SeedingRecord`, so the racing flag was lost: the
    /// consume dispatched a natural terminal (Complete / keep
    /// seeding) instead of the Removed result / the paused requeue.
    #[test]
    fn seeding_flags_carry_through_begin_seeding_transfer() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), false), None);
        assert_eq!(q.fillup(2), vec![g(1), g(2)]);
        // A remove lands on the active face in the same tick as the
        // transfer: the flag must carry into the seeding record.
        assert!(q.request_remove(g(1)));
        assert!(q.begin_seeding(g(1)));
        assert_eq!(
            q.seeding_flags(g(1)),
            Some((false, true)),
            "the remove flag rides the transfer"
        );
        // Ended dispatch per the carried flags: remove → no requeue
        // (the actor's consume overrides the result to Removed).
        assert_eq!(
            q.retire_seeding(g(1), done(g(1))),
            None,
            "remove does not requeue"
        );
        assert!(q.reserved_snapshot().is_empty());
        // A pause racing the transfer: carries; the Ended requeues to
        // the front paused instead of continuing to seed.
        assert!(q.request_pause(g(2)));
        assert!(q.begin_seeding(g(2)));
        assert_eq!(
            q.seeding_flags(g(2)),
            Some((true, false)),
            "the pause flag rides the transfer"
        );
        assert_eq!(q.retire_seeding(g(2), done(g(2))), Some(true));
        let snap = q.reserved_snapshot();
        assert_eq!(
            (snap[0].gid, snap[0].paused),
            (g(2), true),
            "race pause -> requeue at the paused queue head"
        );
    }

    /// Table-driven: the seed budget boundary — a finite budget parks
    /// the excess in the seed_wait FIFO (FIFO order), promotion admits
    /// strictly within the budget, and 0 = unlimited.
    #[test]
    fn seed_budget_parks_and_promotes_in_fifo_order() {
        let mut q = QueueMan::new();
        // Three residents with budget 2: the third parks, the FIFO
        // order is arrival order.
        for i in 1..=3u64 {
            q.insert_reserved(entry(g(i), false), None);
        }
        assert_eq!(q.fillup(3), (1..=3u64).map(g).collect::<Vec<_>>());
        assert!(q.begin_seeding(g(1)));
        assert!(q.begin_seeding(g(2)));
        // Budget full: park the third (the actor's deferred-stop consume
        // pushes here after the graceful stop lands).
        q.push_seed_wait(g(3));
        assert_eq!(q.seeding_len(), 2);
        assert_eq!(q.seed_wait_gids(), vec![g(3)]);
        // Promotion is refused while the budget is full.
        assert_eq!(q.admit_next_seed(2), None);
        // A resident leaves (seed criteria met) -> the front is admitted
        // within the same round (release-then-backfill, no idle tick).
        assert_eq!(q.retire_seeding(g(1), done(g(1))), None);
        assert_eq!(q.admit_next_seed(2), Some(g(3)));
        assert_eq!(q.seeding_len(), 2);
        assert!(q.seed_wait_gids().is_empty());
        // 0 = unlimited: every parked member admits.
        for i in 4..=9u64 {
            q.push_seed_wait(g(i));
        }
        let mut promoted = Vec::new();
        while let Some(gid) = q.admit_next_seed(0) {
            promoted.push(gid);
        }
        assert_eq!(
            promoted,
            (4..=9u64).map(g).collect::<Vec<_>>(),
            "0 = unlimited, no bound, FIFO-order promotion"
        );
        assert_eq!(q.seeding_len(), 8);
    }

    /// Table-driven: budget narrowing never preempts (
    /// over-subscribed residents stay; the excess converges via natural
    /// exits), and the forceRecheck slot release stops counting against
    /// the budget while the registry entry stays operable.
    #[test]
    fn seed_narrowing_never_preempts_and_slot_release_frees_budget() {
        let mut q = QueueMan::new();
        for i in 1..=3u64 {
            q.insert_reserved(entry(g(i), false), None);
        }
        assert_eq!(q.fillup(3), (1..=3u64).map(g).collect::<Vec<_>>());
        for i in 1..=3u64 {
            assert!(q.begin_seeding(g(i)));
        }
        // Narrowed to 1 with three residents: nobody is evicted, no
        // admission happens (the excess converges via natural exits).
        assert_eq!(q.admit_next_seed(1), None);
        assert_eq!(q.seeding_len(), 3);
        // forceRecheck on a resident: the slot releases immediately
        // (promotable under the pre-narrowing budget) while find()/
        // pause/remove keep working.
        assert!(q.release_seed_slot(g(2)));
        assert_eq!(
            q.seeding_len(),
            2,
            "the freed seed slot is no longer counted"
        );
        assert_eq!(q.find(g(2)), Some(Location::Seeding));
        assert!(q.request_seed_pause(g(2)));
        // Park a completion the way the actor does (drop from the
        // active face first, then the FIFO), then admit both under a
        // budget that has room exactly because of the release above.
        q.insert_reserved(entry(g(7), false), None);
        assert_eq!(q.fillup(1), vec![g(7)]);
        assert!(q.drop_active(g(7)));
        q.push_seed_wait(g(7));
        assert_eq!(
            q.admit_next_seed(3),
            Some(g(7)),
            "the freed slot can backfill immediately"
        );
        // The rechecking resident still finalizes through the registry
        // (pause requeue; the remove override wins as with active).
        assert_eq!(q.retire_seeding(g(2), done(g(2))), Some(true));
        assert_eq!(
            (
                q.reserved_snapshot()[0].gid,
                q.reserved_snapshot()[0].paused
            ),
            (g(2), true),
            "seeding resident pause -> requeue at the paused queue head"
        );
    }

    /// Table-driven (the unique-membership slice): every gid holds at
    /// most one membership across active ∪ checking ∪ check_pending ∪
    /// seeding ∪ seed_wait ∪ processing ∪ proc_wait ∪ reserved ∪
    /// results at each step of a mixed operation script (the property
    /// the actor's single-threaded dispatch must preserve; deferred-side
    /// sets live actor-side and converge by the Ended consume —
    /// exercised in the actor tests). The nine-domain union is complete
    /// as of the four-pool nine-domain completion.
    #[test]
    fn unique_membership_across_pools_under_mixed_script() {
        let mut q = QueueMan::new();
        let assert_unique = |q: &QueueMan| {
            let mut seen: Vec<Gid> = Vec::new();
            seen.extend(q.active_gids());
            seen.extend(q.checking_gids());
            seen.extend(q.check_pending_gids());
            seen.extend(q.seeding_gids());
            seen.extend(q.seed_wait_gids());
            seen.extend(q.processing_gids());
            seen.extend(q.proc_wait_gids());
            seen.extend(q.reserved_snapshot().into_iter().map(|e| e.gid));
            seen.extend(q.results().map(|r| r.gid));
            let total = seen.len();
            seen.sort();
            seen.dedup();
            assert_eq!(seen.len(), total, "unique gid ownership was broken");
        };
        for i in 1..=6u64 {
            q.insert_reserved(entry(g(i), false), None);
        }
        assert_unique(&q);
        assert_eq!(q.fillup(3), (1..=3u64).map(g).collect::<Vec<_>>());
        assert_unique(&q);
        // transfer + park + recheck mix (the park path drops the
        // active membership first; the checking entry dequeues from
        // reserved first — the actor's consume orders).
        assert!(q.begin_seeding(g(1)));
        assert!(q.drop_active(g(2)));
        q.push_seed_wait(g(2));
        assert!(q.remove_reserved(g(5)));
        q.insert_checking(g(5), false);
        assert!(q.remove_reserved(g(6)));
        q.insert_check_pending(g(6), false);
        assert_unique(&q);
        // The synthesis edge: an active member parks into
        // proc_wait at its gate (the active membership moves in one
        // step), then promotes into the processing registry — still
        // exactly one membership per step.
        assert!(q.begin_synthesis_park(g(3)));
        assert_unique(&q);
        assert_eq!(q.promote_synthesis_head(), Some(g(3)));
        assert_unique(&q);
        // The FIFO dedup guard: a repeat park of the same gid is
        // absorbed, not duplicated (all three waiting pools).
        q.push_seed_wait(g(2));
        q.insert_check_pending(g(6), false);
        assert_eq!(
            q.fillup(1),
            vec![g(4)],
            "g4 activates (the vacated download slot backfills)"
        );
        assert!(q.begin_synthesis_park(g(4)));
        assert!(
            !q.begin_synthesis_park(g(4)),
            "a duplicate park: a non-active member is not transferred again, no FIFO duplicate"
        );
        assert_eq!(q.proc_wait_gids(), vec![g(4)]);
        q.push_seed_wait(g(2));
        q.insert_check_pending(g(6), false);
        assert_eq!(q.seed_wait_gids().len(), 1);
        assert_eq!(q.check_pending_gids().len(), 1);
        assert_eq!(
            q.proc_wait_gids(),
            vec![g(4)],
            "g3 was promoted, the FIFO holds only g4"
        );
        assert_unique(&q);
        // retire / promote paths (the check admission moves the entry
        // check_pending → checking — still exactly one membership).
        assert_eq!(q.retire_seeding(g(1), done(g(1))), None);
        assert_eq!(q.admit_next_seed(0), Some(g(2)));
        assert_eq!(q.remove_checking(g(5)), Some(false));
        q.insert_reserved(entry(g(5), false), Some(0));
        // The check admission moves the entry check_pending → checking
        // (still exactly one membership).
        let admitted = q.admit_next_check(1).unwrap_or_else(|| panic!("entry"));
        assert_eq!(admitted.gid, g(6));
        q.insert_checking(g(6), admitted.paused);
        assert_unique(&q);
        // The synthesis retire moves processing → results (or, with a
        // pause flag, processing → reserved front) — one membership.
        assert_eq!(q.retire_synthesis(g(3), done(g(3))), None);
        assert_unique(&q);
        assert_eq!(q.seeding_len(), 1);
        assert_eq!(
            q.proc_wait_gids(),
            vec![g(4)],
            "the parked member keeps its original position"
        );
        assert_eq!(q.results().count(), 2);
    }

    // ---- synthesis pool ----

    /// Table-driven (acceptance ①'s registry slice): the
    /// active→proc_wait transfer releases the download slot immediately
    /// (fillup backfills in the same round) and is idempotent (a
    /// duplicate SynthesisGate must not repeat the transfer — the
    /// transfer also carries the active record's request flags); the
    /// budget-1 promotion admits exactly one member (FIFO) and a
    /// narrowed budget never preempts in-flight syntheses (⑩'s
    /// narrowing-never-preempts clause); the Ended consume releases the slot and the
    /// next promotion happens in the same round (release-then-backfill).
    #[test]
    fn synthesis_gate_parks_promotes_within_budget_and_narrowing_never_preempts() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), false), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        // Task 1 reaches the gate: active → proc_wait (download slot
        // released), the trailing fillup backfills task 2 (the actor
        // orders these in one pump_all tick).
        assert!(q.begin_synthesis_park(g(1)));
        assert_eq!(
            q.active_len(),
            0,
            "the download slot is released at the transfer instant"
        );
        assert_eq!(q.proc_wait_gids(), vec![g(1)]);
        assert_eq!(
            q.fillup(1),
            vec![g(2)],
            "the download slot backfills immediately"
        );
        // Duplicate arrival: no transfer (not active), and another
        // task's active slot is never touched.
        assert!(!q.begin_synthesis_park(g(1)));
        assert_eq!(q.proc_wait_gids(), vec![g(1)]);
        assert!(q.contains_active(g(2)));
        // Budget 1: the promotion admits the parked head into the
        // processing registry; a second parked member stays (FIFO).
        assert_eq!(q.promote_synthesis_head(), Some(g(1)));
        assert_eq!(q.processing_len(), 1);
        assert!(q.proc_wait_gids().is_empty());
        // Park a second synthesis (the actor's gate consume) with the
        // budget still full: it stays parked.
        assert!(q.begin_synthesis_park(g(2)));
        assert_eq!(q.proc_wait_gids(), vec![g(2)]);
        assert_eq!(q.active_len(), 0);
        // Budget narrowed to... (the value domain has no 0=unlimited
        // state; the read side clamps to ≥1) — an over-subscribed
        // registry is tolerated: the head is flagged?? no — the parked
        // member is unflagged, but the budget (1) is held by the
        // in-flight synthesis: no admission.
        assert_eq!(q.processing_len(), 1);
        assert_eq!(
            q.proc_wait_front(),
            Some(g(2)),
            "the unflagged head is readable"
        );
        // narrowing never preempts: the caller (pump) checks processing_len() against
        // the budget before promoting — with budget 1 and one in
        // flight, the head stays parked even though it is unflagged
        // (the budget gate, not a flag, blocks here).
        // In-flight synthesis ends (the Ended consume): the registry
        // entry leaves with a result; the freed slot admits the parked
        // member in the same round.
        assert_eq!(q.retire_synthesis(g(1), done(g(1))), None);
        assert_eq!(q.processing_len(), 0);
        assert_eq!(
            q.promote_synthesis_head(),
            Some(g(2)),
            "release promotes immediately (release-then-backfill)"
        );
        assert_eq!(q.results().map(|r| r.gid).collect::<Vec<_>>(), vec![g(1)]);
        // Flagged heads never admit (a pause/remove racing the gate
        // means the driver is already tearing down — the permit must
        // not fire).
        assert!(q.request_synthesis_pause(g(2)));
        assert_eq!(q.proc_wait_front(), None, "the pause flag blocks the head");
        assert_eq!(
            q.promote_synthesis_head(),
            None,
            "a flagged member is not promoted"
        );
        // The teardown consume dispatches from the flags: pause (no
        // remove) → requeue to the front paused.
        assert_eq!(q.retire_synthesis(g(2), done(g(2))), Some(true));
        let snap = q.reserved_snapshot();
        assert_eq!(
            (snap[0].gid, snap[0].paused),
            (g(2), true),
            "pause while parked in proc_wait -> requeue at the paused queue head"
        );
        assert!(q.proc_wait_gids().is_empty());
        assert!(q.processing_gids().is_empty());
    }

    /// Table-driven (acceptance ②/③'s registry slice): the
    /// remove flag rides the transfer (an active-face remove racing the
    /// gate arrival keeps its halt semantics), remove overrides pause,
    /// and the remove consume records Removed without a requeue.
    #[test]
    fn synthesis_flags_carry_through_transfer_and_remove_overrides_pause() {
        let mut q = QueueMan::new();
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), false), None);
        assert_eq!(q.fillup(2), vec![g(1), g(2)]);
        // A remove lands on the active face just before the gate
        // transfer: the flag carries into the parked entry.
        assert!(q.request_remove(g(1)));
        assert!(q.begin_synthesis_park(g(1)));
        assert_eq!(
            q.synthesis_flags(g(1)),
            Some((false, true)),
            "the remove flag rides the transfer"
        );
        assert_eq!(q.retire_synthesis(g(1), done(g(1))), None);
        assert_eq!(
            q.results().next().map(|r| r.status),
            Some(StatusKind::Complete),
            "the consume side records the injected entry state (the Removed overwrite is the actor side's job)"
        );
        // Pause-then-remove on a parked member: remove overrides pause.
        assert!(q.begin_synthesis_park(g(2)));
        assert!(q.request_synthesis_pause(g(2)));
        assert_eq!(q.synthesis_flags(g(2)), Some((true, false)));
        assert!(q.request_synthesis_remove(g(2)));
        assert_eq!(
            q.synthesis_flags(g(2)),
            Some((false, true)),
            "halt semantics: remove clears pause"
        );
        assert_eq!(
            q.retire_synthesis(g(2), done(g(2))),
            None,
            "remove does not requeue"
        );
        assert_eq!(q.results().count(), 2);
        assert!(q.reserved_snapshot().is_empty());
        // remove_synthesis drops either face (the force arm's immediate
        // detach).
        q.insert_reserved(entry(g(3), false), None);
        assert_eq!(q.fillup(1), vec![g(3)]);
        assert!(q.begin_synthesis_park(g(3)));
        assert!(q.remove_synthesis(g(3)));
        assert!(!q.remove_synthesis(g(3)), "a second removal = false");
        assert_eq!(q.find(g(3)), None);
    }
    // ---- observation-face consolidation ----

    /// ①+② (queue half): the unified waiting snapshot's fixed segment
    /// order and per-segment status matrix — reserved ++ check_pending
    /// ++ seed_wait ++ proc_wait, each segment internally FIFO.
    /// Exact-sequence pin = the degenerate-mutation guard: reverting to
    /// the interim append order (seed_wait before
    /// check_pending), dropping a segment, or moving the order anywhere
    /// else turns this red.
    #[test]
    fn waiting_snapshot_final_segment_order_and_statuses() {
        let mut q = QueueMan::new();
        // Synthesis-pool segment: one parked member ('waiting' — the
        // gate hang is an in-task phase, no extension); constructed via
        // the gate transfer shape (active → proc_wait) while the queue
        // is still empty (fillup pops the FIFO front).
        q.insert_reserved(entry(g(31), false), None);
        assert_eq!(q.fillup(1), vec![g(31)]);
        assert!(q.begin_synthesis_park(g(31)));
        // Reserved segment: three members, the middle one paused (the
        // waiting/paused split is per-entry, the aria2 face).
        for (gid, paused) in [(1u64, false), (2, true), (3, false)] {
            q.insert_reserved(entry(g(gid), paused), None);
        }
        // Check-pool segment: two parked members (the second carries a
        // pause intent — the segment status stays 'checking' on both).
        q.insert_check_pending(g(11), false);
        q.insert_check_pending(g(12), true);
        // Seed-pool segment: two parked members ('seeding' — the
        // extended value, aligned with the row state).
        q.push_seed_wait(g(21));
        q.push_seed_wait(g(22));

        let got: Vec<(u64, StatusKind)> = q
            .waiting_snapshot()
            .into_iter()
            .map(|m| (m.gid.as_u64(), m.status))
            .collect();
        assert_eq!(
            got,
            vec![
                (1, StatusKind::Waiting),
                (2, StatusKind::Paused),
                (3, StatusKind::Waiting),
                (11, StatusKind::Checking),
                (12, StatusKind::Checking),
                (21, StatusKind::Seeding),
                (22, StatusKind::Seeding),
                (31, StatusKind::Waiting),
            ],
            "segment-order/state matrix drift (final order = reserved ++ check_pending ++ seed_wait ++ proc_wait)"
        );

        // Segment-internal FIFO: appends land at each segment's own
        // tail (no interleaving across segments).
        q.push_seed_wait(g(23));
        q.insert_check_pending(g(13), false);
        let gids: Vec<u64> = q
            .waiting_snapshot()
            .iter()
            .map(|m| m.gid.as_u64())
            .collect();
        assert_eq!(gids, vec![1, 2, 3, 11, 12, 13, 21, 22, 23, 31]);

        // numWaiting caliber: the four-segment merge — getGlobalStat
        // reads the snapshot's length, the tellWaiting caliber's exact
        // source.
        assert_eq!(q.waiting_snapshot().len(), 10);
        assert_eq!(
            q.reserved_snapshot().len()
                + q.check_pending_gids().len()
                + q.seed_wait_gids().len()
                + q.proc_wait_gids().len(),
            q.waiting_snapshot().len()
        );
    }

    /// ⑤ (the three phase FIFOs): the segment-local move matrix — the
    /// move_reserved reference-matrix shape (Set/Cur/End x
    /// in-range/0/out-of-range) replayed per segment; the raw
    /// destination clamps into the owning segment's own head/tail, the
    /// other three segments keep their order (the gid never leaves its segment = clamp
    /// evidence), and the check_pending paused flag rides the move
    /// unchanged (the queue.rs reserved-segment precedent).
    #[test]
    fn waiting_segment_move_matrix_is_segment_local() {
        fn setup() -> QueueMan {
            let mut q = QueueMan::new();
            // proc_wait [30..33]: the gate transfer shape.
            for i in 30..34u64 {
                q.insert_reserved(entry(g(i), false), None);
            }
            assert_eq!(q.fillup(4), (30..34).map(g).collect::<Vec<_>>());
            for i in 30..34u64 {
                assert!(q.begin_synthesis_park(g(i)));
            }
            // Reserved [1, 2] (untouched controls), check_pending
            // [10..13] (12 paused), seed_wait [20..23].
            q.insert_reserved(entry(g(1), false), None);
            q.insert_reserved(entry(g(2), false), None);
            for i in 10..14u64 {
                q.insert_check_pending(g(i), i == 12);
            }
            for i in 20..24u64 {
                q.push_seed_wait(g(i));
            }
            q
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Seg {
            CheckPending,
            SeedWait,
            ProcWait,
        }

        impl From<Seg> for WaitingSegment {
            fn from(s: Seg) -> WaitingSegment {
                match s {
                    Seg::CheckPending => WaitingSegment::CheckPending,
                    Seg::SeedWait => WaitingSegment::SeedWait,
                    Seg::ProcWait => WaitingSegment::ProcWait,
                }
            }
        }

        impl Seg {
            fn gids(self) -> Vec<u64> {
                match self {
                    Seg::CheckPending => (10..14).collect(),
                    Seg::SeedWait => (20..24).collect(),
                    Seg::ProcWait => (30..34).collect(),
                }
            }
        }

        // (member index, pos, how, want dest-in-segment)
        let table: [(usize, i64, OffsetMode, usize); 6] = [
            (0, 0, OffsetMode::Set, 0),   // head, in-place
            (1, 0, OffsetMode::Set, 0),   // second -> head
            (1, 1, OffsetMode::Cur, 2),   // relative forward
            (1, 0, OffsetMode::End, 3),   // -> segment tail
            (1, 99, OffsetMode::Set, 3),  // forward overflow clamps to the segment tail
            (3, -99, OffsetMode::Cur, 0), // backward overflow clamps to the segment head
        ];
        for seg in [Seg::CheckPending, Seg::SeedWait, Seg::ProcWait] {
            for (idx, pos, how, want) in table {
                let mut q = setup();
                let members = seg.gids();
                let gid = g(members[idx]);
                let moved = q
                    .move_waiting(gid, pos, how)
                    .unwrap_or_else(|| panic!("waiting member"));
                assert_eq!(
                    moved.segment,
                    WaitingSegment::from(seg),
                    "{seg:?}: segment membership ({idx},{pos},{how:?})"
                );
                assert_eq!(moved.from, idx, "{seg:?}: from ({pos},{how:?})");
                assert_eq!(moved.to, want, "{seg:?}: destination drift ({pos},{how:?})");
                // Segment-local evidence: the snapshot reorders only
                // the owning segment (a contiguous permutation in the
                // gid range), every other segment keeps its order, and
                // the reserved controls stay at the front untouched.
                let all: Vec<u64> = q
                    .waiting_snapshot()
                    .iter()
                    .map(|m| m.gid.as_u64())
                    .collect();
                assert_eq!(
                    &all[..2],
                    &[1, 2],
                    "{seg:?}: the reserved segment stays put"
                );
                let (lo, hi) = match seg {
                    Seg::CheckPending => (10, 14),
                    Seg::SeedWait => (20, 24),
                    Seg::ProcWait => (30, 34),
                };
                assert_eq!(
                    all.len(),
                    2 + 4 + 4 + 4,
                    "{seg:?}: the four-segment total is unchanged (moves never cross segments)"
                );
                let mut reordered = all[2..].to_vec();
                reordered.sort();
                let mut want_all: Vec<u64> = (10..14).chain(20..24).chain(30..34).collect();
                want_all.sort();
                assert_eq!(
                    reordered, want_all,
                    "{seg:?}: the member set is unchanged after the move (still within the three segments)"
                );
                let segment_slice = &all[2..6 + 4 + 4][if seg == Seg::CheckPending {
                    0..4
                } else if seg == Seg::SeedWait {
                    4..8
                } else {
                    8..12
                }];
                assert!(
                    segment_slice.iter().all(|&x| x >= lo && x < hi),
                    "{seg:?}: the segment stays contiguous after the move (no cross-segment): {segment_slice:?}"
                );
                // The paused check_pending member rides the move
                // untouched (the reserved-segment move-paused
                // precedent); re-derive from the location face.
                if seg == Seg::CheckPending {
                    assert_eq!(
                        q.find(g(12)),
                        Some(Location::CheckingPaused),
                        "{pos},{how:?}: the paused flag rides the row unchanged"
                    );
                }
            }
        }
    }

    /// ⑤ (the dispatch gate): `move_waiting` accepts exactly the four
    /// waiting segments' members — a seeding residence, a processing
    /// residence, an in-flight recheck, a result entry, and an unknown
    /// gid all miss (the caller emits the reference waiting-queue
    /// text); every segment's members move (positive control).
    #[test]
    fn move_waiting_rejects_non_waiting_members() {
        let mut q = QueueMan::new();
        // Seeding residence (g1): active → seeding.
        q.insert_reserved(entry(g(1), false), None);
        assert_eq!(q.fillup(1), vec![g(1)]);
        assert!(q.begin_seeding(g(1)));
        // Processing residence (g2): active → proc_wait → processing.
        q.insert_reserved(entry(g(2), false), None);
        assert_eq!(q.fillup(1), vec![g(2)]);
        assert!(q.begin_synthesis_park(g(2)));
        assert_eq!(q.promote_synthesis_head(), Some(g(2)));
        // In-flight recheck (g3): active → checking.
        q.insert_reserved(entry(g(3), false), None);
        assert_eq!(q.fillup(1), vec![g(3)]);
        assert!(q.drop_active(g(3)));
        q.insert_checking(g(3), false);
        // Result entry (g4): active → results.
        q.insert_reserved(entry(g(4), false), None);
        assert_eq!(q.fillup(1), vec![g(4)]);
        q.retire_active(g(4), done(g(4)));
        // The four waiting segments' members (positive controls):
        // proc_wait g8 (parked, NOT promoted — parked while the queue
        // is empty so fillup pops it), then reserved g5, check_pending
        // g6, seed_wait g7.
        q.insert_reserved(entry(g(8), false), None);
        assert_eq!(q.fillup(1), vec![g(8)]);
        assert!(q.begin_synthesis_park(g(8)));
        q.insert_reserved(entry(g(5), false), None);
        q.insert_check_pending(g(6), false);
        q.push_seed_wait(g(7));

        for bad in [g(1), g(2), g(3), g(4), g(99)] {
            assert!(
                q.move_waiting(bad, 0, OffsetMode::Set).is_none(),
                "a non-waiting-domain member {bad} must be rejected (waiting-queue miss)"
            );
        }
        for good in [g(5), g(6), g(7), g(8)] {
            assert!(
                q.move_waiting(good, 0, OffsetMode::Set).is_some(),
                "a waiting-domain member {good} is movable"
            );
        }
    }

    /// ⑧: the periodic summary's member caliber — the download pool's
    /// active set only, under a fully-populated nine-domain session
    /// (the emit_summary iteration source reads through
    /// `summary_gids`; extending the seam to any phase pool turns this
    /// red).
    #[test]
    fn summary_caliber_download_pool_only_under_mixed_load() {
        let mut q = QueueMan::new();
        // processing g8: the gate shape (parked while the queue is
        // empty so fillup pops it), then promoted out of proc_wait.
        q.insert_reserved(entry(g(8), false), None);
        assert_eq!(q.fillup(1), vec![g(8)]);
        assert!(q.begin_synthesis_park(g(8)));
        assert_eq!(q.promote_synthesis_head(), Some(g(8)));
        // proc_wait g6 (parked): the same gate shape.
        q.insert_reserved(entry(g(6), false), None);
        assert_eq!(q.fillup(1), vec![g(6)]);
        assert!(q.begin_synthesis_park(g(6)));
        // results g10: active → retire.
        q.insert_reserved(entry(g(10), false), None);
        assert_eq!(q.fillup(1), vec![g(10)]);
        q.retire_active(g(10), done(g(10)));
        // The download pool's actives g1, g2.
        q.insert_reserved(entry(g(1), false), None);
        q.insert_reserved(entry(g(2), false), None);
        assert_eq!(q.fillup(2), vec![g(1), g(2)]);
        // The other domains: seeding g3 (direct, the promotion face),
        // check_pending g4, seed_wait g5, checking g7, reserved g9.
        q.insert_seeding(g(3));
        q.insert_check_pending(g(4), false);
        q.push_seed_wait(g(5));
        q.insert_checking(g(7), false);
        q.insert_reserved(entry(g(9), false), None);

        assert_eq!(
            q.summary_gids(),
            vec![g(1), g(2)],
            "the periodic summary iterates only download-pool actives (seeding/processing stay out of summary rows)"
        );
        assert_eq!(q.summary_gids(), q.active_gids());
    }
}

#[cfg(test)]
mod bt_queue_caps {
    use super::*;

    /// Anchors the queue-cap constants (1024 entries x 30 MiB flood
    /// face -> the 256 MiB budget).
    #[test]
    fn queue_cap_constants_anchored() {
        assert_eq!(MAX_RESERVED_QUEUE_ENTRIES, 1024);
        assert_eq!(MAX_QUEUED_METAINFO_BYTES, 256 * 1024 * 1024);
    }

    /// Queue-pressure meter (the estimated sum of the entry->jobs
    /// mapping) and length semantics.
    #[test]
    fn reserved_entries_view_reports_pressure() {
        let mut q = QueueMan::default();
        assert!(q.reserved_entries().is_empty());
        for i in 0..3 {
            q.insert_reserved(
                ReservedEntry {
                    gid: Gid::from_u64(i),
                    paused: false,
                },
                None,
            );
        }
        assert_eq!(q.reserved_entries().len(), 3);
        assert_eq!(q.reserved_entries()[0].gid, Gid::from_u64(0));
    }
}
