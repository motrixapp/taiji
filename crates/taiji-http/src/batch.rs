//! Same-host transient batch-group scheduling primitive (the scheduling
//! base of the batch aggregation scheduler: a cross-file byte-range
//! queue + in-batch work stealing + a connection-budget soft-cap gate).
//!
//! Group key = [`crate::perhost::HostCap::host_key`] (the same key as
//! the per-host cap — the batch budget and the host cap stack in one
//! scope, no second key shape). Transient groups: same-host small tasks
//! (driver candidates) join on activation ([`BatchGroups::join`]); a
//! file leaves on completion/failure/cancel ([`BatchGroups::leave`]);
//! the last file out disbands the group (registry entry removed; the
//! budget returns to the pool naturally as [`GatePermit`]s drop).
//!
//! Cross-file byte-range queue: one FIFO sub-queue per file; the group
//! takes shortest-remaining-first (SRPT) — the file with the fewest
//! queued items is harvested first, so files leave the group early
//! (worker labor returns to the pool, budget frees up) and tail
//! harvesting concentrates (full connections in the tail, no
//! parallelism collapse). Fast-path length differences are bounded
//! (small tasks of ≤2 blocks), so there is no starvation face.
//! In-batch work stealing: a group worker may take items from any file
//! (the SRPT scan is the stealing face); a leaving file's remaining
//! sub-queue is voided immediately (workers skip it).
//!
//! Hard invariant — three stacked caps (see docs/design/http.md for the
//! full stacking rules): per-task `min(split,
//! --max-connection-per-server)` (domain 1-16); the group budget
//! [`DEFAULT_BATCH_BUDGET`], in force only at ≥ [`BATCH_MIN_FILES`]
//! active files, with ceiling `max(budget, host cap − outside
//! occupancy)` (work-conserving, polite under contention); the per-host
//! cap counting batch connections in full ([`HostCap::acquire`] before
//! every fetch — no exemption).
//!
//! Concurrency discipline: group state is a std Mutex with
//! nanosecond-scale critical sections, never held across an await;
//! waiting goes through the group-level [`Notify`] with
//! register-then-check (no lost-wakeup window); gate reservation
//! guards are all RAII — when a worker future is aborted
//! (cancellation), the active count and the host permit return via
//! Drop, so process-level group state never leaks on task
//! cancellation.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Notify;

use crate::perhost::{HostCap, HostPermit};

/// Batch-group budget default (`--http-batch-budget`; the same
/// magnitude as the single-task cap ceiling — the "polite share", see
/// the stacking rules in docs/design/http.md).
pub const DEFAULT_BATCH_BUDGET: u32 = 16;
/// Batch-group budget domain floor (≥2: a budget of 1 serializes the
/// group — no aggregation value).
pub const MIN_BATCH_BUDGET: u32 = 2;
/// Batch-group budget domain ceiling (≤64: the per-host cap default is
/// 32; a budget above the host cap is always constrained by the host
/// cap's first-come-first-served anyway, so the knob stops at 64 to
/// prevent meaningless configurations).
pub const MAX_BATCH_BUDGET: u32 = 64;

/// Grouping threshold K (engine constant; rationale in
/// docs/design/http.md).
pub const BATCH_MIN_FILES: usize = 2;

/// Per-file sub-queue (the unit of the in-group rotation).
struct FileQueue<T> {
    id: u64,
    items: VecDeque<T>,
    /// Terminal marker (done/failed/cancelled): takers skip its
    /// remaining items and the owner worker exits ([`BatchGroups::next`]
    /// returns None).
    closed: bool,
}

struct GroupInner<T> {
    /// In-group file sub-queues (the SRPT take face).
    files: StdMutex<VecDeque<FileQueue<T>>>,
    /// Group-level take wakeup (push/terminal/leave broadcast).
    notify: Notify,
    /// Group active-connection count (gate reservation + in transit;
    /// RAII return, see [`GatePermit`]).
    active: AtomicU64,
    /// Batch-form flag (set once the group has held ≥K files in its
    /// lifetime, never unset): a single-file-window gate reservation
    /// must not cross the batch-form boundary — workers that reserved
    /// under "no ceiling" before the second file joined already hold
    /// counts; if soft-cap activation were judged by the instantaneous
    /// file count, those crossing reservations would distort the batch
    /// ceiling. Dies with the group entry on disband; a new group
    /// re-evaluates.
    batch_form: std::sync::atomic::AtomicBool,
    /// Group-level first-wave stagger ordinal counter (cross-file
    /// stagger): each file's first-wave worker stagger ordinals are
    /// allocated globally within the group (when K tasks join at the
    /// same moment their first-wave connects differ — see
    /// [`BatchFile::stagger_ordinal_base`]). Resets when the group
    /// disbands: the counter dies with the [`GroupInner`] registry
    /// entry ([`BatchGroups::leave`] removes an empty group); the
    /// trade-off is written up in
    /// [`BatchFile::stagger_ordinal_base`].
    stagger_seq: AtomicU64,
}

/// Group observation snapshot (e2e assertions / logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchGroupStats {
    /// In-group active (not yet left) file count.
    pub files: usize,
    /// Group active-connection count (gate holders, queued included).
    pub active: u64,
    /// Items queued in the group (not yet taken).
    pub queued: usize,
}

/// Gate busy (overflow rejected: the budget is full and the per-host
/// cap has no immediately free slot) — the worker yields briefly and
/// retries (the yielding face under host contention).
#[derive(Debug)]
pub struct GateBusy;

/// Three-way exit of an immediate take ([`BatchGroups::try_next`]; the
/// permit-idling elimination face — queue-empty and owner-terminal are
/// distinguished, returning the wait decision to the caller, which may
/// release the connection gate before waiting).
pub enum Work<T> {
    /// Got an item (SRPT cross-file stealing).
    Item(T),
    /// Nothing takable in the group (all in flight / the owner pushed
    /// nothing new): the caller may wait ([`BatchGroups::wait_work`])
    /// or yield.
    Empty,
    /// Owner file terminal/left: worker exits.
    Terminal,
}

/// Batch-group file handle (held by the driver; cloned per worker).
pub struct BatchFile<T> {
    group: Arc<GroupInner<T>>,
    /// Owning group key (host; the single-argument leave face).
    host: String,
    /// File id (unique in the group, allocated by the registry).
    pub id: u64,
    /// This file's unfinished item count (+1 on enqueue, -1 on
    /// completion; zero = file complete).
    remaining: Arc<AtomicUsize>,
    /// Zero-count wakeup (the driver main loop's completion wait
    /// face).
    done: Arc<Notify>,
}

impl<T> Clone for BatchFile<T> {
    fn clone(&self) -> Self {
        BatchFile {
            group: Arc::clone(&self.group),
            host: self.host.clone(),
            id: self.id,
            remaining: Arc::clone(&self.remaining),
            done: Arc::clone(&self.done),
        }
    }
}

impl<T> BatchFile<T> {
    /// This file's unfinished item count (the completion check face):
    /// +1 on enqueue ([`BatchGroups::push`]), -1 when an item completes
    /// ([`BatchGroups::note_item_done`]); abort/cancel does NOT zero
    /// it — after the driver's workers drain, non-zero means the file
    /// has items that never completed (failure/cancel residue); zero =
    /// all items complete. Distinct from the group snapshot's `queued`
    /// (queued item count): in-flight items are out of the queue but
    /// still unfinished. With cross-file stealing, an abort on a
    /// failure-exhausted item lands on the item's owning file, and the
    /// owner worker drains all-Ok — this reading is the owner driver
    /// side's only failure signal (fail-closed: a preallocated `.part`
    /// with zero holes must not be recorded as Done).
    pub fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }

    /// Group-level first-wave stagger ordinal assignment (cross-file
    /// stagger): the task's (this file's) first `workers` workers
    /// pre-reserve one contiguous ordinal range
    /// `[base, base+workers)`; worker i staggers with `base+i`
    /// (consumed by the driver-side `stagger_delay(ordinal, warmth)` —
    /// first-connect delay = ordinal x step). Before the fix the
    /// ordinal was the per-file range index (`0..ranges.len()`), so K
    /// tasks joining at the same moment opened K ordinal-0 connections
    /// at once (the group-forming burst was not staggered inside the
    /// group — the ramp only ran within one file).
    ///
    /// The counter resets when the group disbands (it dies with the
    /// [`GroupInner`] registry entry; a new group re-ramps from 0).
    /// Trade-off: a same-moment connect burst only exists among tasks
    /// joining concurrently within one group's lifetime — a new batch
    /// after disbanding is a new burst and should re-ramp from 0 (the
    /// group lifetime is the natural boundary of the burst window).
    /// Keeping a monotonic counter across group lifetimes would pin
    /// ordinals at the driver-side ordinal cap
    /// (`CONNECT_STAGGER_MAX_ORDINAL`): post-disband tasks would all
    /// wait the same saturated delay and the same-moment herd would
    /// reappear at +saturated-delay while paying the startup latency
    /// for nothing (uniform delay != stagger). Within a long-lived
    /// group, natural growth is absorbed by the same cap (delay
    /// bounded ~320ms; the stagger-step semantics hold).
    pub fn stagger_ordinal_base(&self, workers: usize) -> u64 {
        self.group
            .stagger_seq
            .fetch_add(workers.max(1) as u64, Ordering::Relaxed)
    }
}

/// Reservation guard (the gate's two-phase intermediate state: CAS
/// reserve, then wait for the host permit; when the await is dropped
/// (cancellation) the active count is returned — the guarantee that
/// process-level group state does not leak).
struct ReserveGuard<T> {
    group: Arc<GroupInner<T>>,
    confirmed: bool,
}

impl<T> Drop for ReserveGuard<T> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.group.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Batch-group connection gate permit: while held, the group active
/// count is +1 and the per-host permit is in hand; Drop returns
/// everything (the minimal unit of the budget returning to the pool).
pub struct GatePermit<T> {
    group: Arc<GroupInner<T>>,
    #[expect(
        dead_code,
        reason = "the permit returns on Drop (held for the fetch round)"
    )]
    host: Option<HostPermit>,
}

impl<T> Drop for GatePermit<T> {
    fn drop(&mut self) {
        self.group.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Same-host transient batch-group registry. Generic `T` = the queue
/// item payload (defined by the driver: byte range + owner write-back
/// handle etc.); this module only schedules (queues/rotation/gate/
/// terminal) and knows nothing about transport or disk writes.
pub struct BatchGroups<T> {
    groups: StdMutex<HashMap<String, Arc<GroupInner<T>>>>,
    next_file_id: AtomicU64,
}

impl<T> Default for BatchGroups<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> BatchGroups<T> {
    pub fn new() -> Self {
        BatchGroups {
            groups: StdMutex::new(HashMap::new()),
            next_file_id: AtomicU64::new(1),
        }
    }

    fn group_of(&self, host: &str) -> Option<Arc<GroupInner<T>>> {
        crate::lock(&self.groups).get(host).map(Arc::clone)
    }

    /// Register a file into the group (creates the group when missing;
    /// the grouping test is "the group enters batch form when the
    /// second file joins", see [`BATCH_MIN_FILES`]). Returns the file
    /// handle.
    pub fn join(&self, host: &str) -> BatchFile<T> {
        let id = self.next_file_id.fetch_add(1, Ordering::Relaxed);
        let mut groups = crate::lock(&self.groups);
        let group = Arc::clone(groups.entry(host.to_string()).or_insert_with(|| {
            Arc::new(GroupInner {
                files: StdMutex::new(VecDeque::new()),
                notify: Notify::new(),
                active: AtomicU64::new(0),
                batch_form: std::sync::atomic::AtomicBool::new(false),
                stagger_seq: AtomicU64::new(0),
            })
        }));
        drop(groups);
        {
            let mut files = crate::lock(&group.files);
            files.push_back(FileQueue {
                id,
                items: VecDeque::new(),
                closed: false,
            });
            if files.len() >= BATCH_MIN_FILES {
                group
                    .batch_form
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }
        BatchFile {
            group,
            host: host.to_string(),
            id,
            remaining: Arc::new(AtomicUsize::new(0)),
            done: Arc::new(Notify::new()),
        }
    }

    /// Enqueue items (owner sub-queue FIFO tail; `remaining` +n; wake
    /// takers). Items for a terminal file are silently discarded (the
    /// driver close-out path's fallback).
    pub fn push(&self, file: &BatchFile<T>, items: impl IntoIterator<Item = T>) {
        let mut n = 0usize;
        {
            let mut files = crate::lock(&file.group.files);
            if let Some(fq) = files.iter_mut().find(|f| f.id == file.id) {
                if fq.closed {
                    return;
                }
                for item in items {
                    fq.items.push_back(item);
                    n += 1;
                }
            }
        }
        if n > 0 {
            file.remaining.fetch_add(n, Ordering::AcqRel);
            file.group.notify.notify_waiters();
        }
    }

    /// Re-enqueue a failed item (driver retry semantics: attempts are
    /// accounted on the item payload; the driver switches to
    /// [`BatchGroups::abort`] at the exhaustion threshold). `remaining`
    /// is untouched (the item was never counted complete).
    pub fn requeue(&self, file: &BatchFile<T>, item: T) {
        let mut pushed = false;
        {
            let mut files = crate::lock(&file.group.files);
            if let Some(fq) = files.iter_mut().find(|f| f.id == file.id) {
                if !fq.closed {
                    fq.items.push_back(item);
                    pushed = true;
                }
            }
        }
        if pushed {
            file.group.notify.notify_waiters();
        }
    }

    /// Worker take (group-level rotation; `None` = owner file
    /// terminal/left, worker exits). Suspends when every sub-queue in
    /// the group is empty (woken by push/terminal/leave).
    /// `remaining` semantics = unfinished item count: taking does not
    /// decrement (an item held by a worker is still unfinished);
    /// completion is accounted in [`BatchGroups::note_item_done`].
    pub async fn next(&self, file: &BatchFile<T>) -> Option<T> {
        loop {
            match self.try_next(file) {
                // Queue empty: suspend and wait (equivalent to the old
                // register→check→wait loop body).
                Work::Empty => self.wait_work(file).await,
                Work::Terminal => return None,
                Work::Item(item) => return Some(item),
            }
        }
    }

    /// Immediate worker take (no waiting): returns [`Work::Empty`] when
    /// the queue is empty (the caller decides whether to wait — the
    /// permit-idling elimination face: the connection gate can be
    /// released before waiting), and [`Work::Terminal`] when the owner
    /// is terminal/left (worker exits). SRPT selection shares one
    /// implementation with [`BatchGroups::next`] (single
    /// implementation, two entries).
    pub fn try_next(&self, file: &BatchFile<T>) -> Work<T> {
        let mut files = crate::lock(&file.group.files);
        // Owner terminal/left = worker exit (worker lifetime = owner
        // file lifetime).
        match files.iter().find(|f| f.id == file.id) {
            None => return Work::Terminal,
            Some(fq) if fq.closed => return Work::Terminal,
            _ => {}
        }
        // Shortest-remaining-first (SRPT) stealing: the head item of
        // the non-empty, non-terminal sub-queue with the fewest queued
        // items (ties broken by smallest id — deterministic). A taker
        // may take from any file (the work-stealing take face). Why
        // SRPT over round-robin: round-robin spreads progress evenly
        // across all files, so several files finish their tails at the
        // same time and group parallelism collapses; SRPT lets the
        // fastest-advancing file leave the group early (its workers
        // return to the pool) and concentrates tail harvesting on a
        // few files' large remaining sets — the tail keeps full
        // connections. Cross-file length differences are bounded
        // (fast paths are ≤2-block small tasks), so there is no
        // starvation face.
        let pick = files
            .iter()
            .filter(|f| !f.closed && !f.items.is_empty())
            .min_by_key(|f| (f.items.len(), f.id));
        let idx = pick.map(|f| {
            files
                .iter()
                .position(|q| q.id == f.id)
                .unwrap_or_else(|| unreachable!())
        });
        match idx.and_then(|i| files[i].items.pop_front()) {
            Some(item) => Work::Item(item),
            // All empty: terminal leftover sub-queues are cleaned up by
            // abort/leave; their wakeup goes through the same group
            // Notify (see [`BatchGroups::wait_work`]).
            None => Work::Empty,
        }
    }

    /// Wait for the group's work face to change (new items pushed /
    /// file terminal / leave broadcast). Discipline = register the
    /// wakeup BEFORE checking state (closes the lost-wakeup window —
    /// the same rule as the old [`BatchGroups::next`] loop body):
    /// after registering, return immediately if the state already
    /// changed (an item is takable or the owner is terminal),
    /// otherwise suspend for the broadcast.
    pub async fn wait_work(&self, file: &BatchFile<T>) {
        loop {
            let notified = file.group.notify.notified();
            tokio::pin!(notified);
            {
                let files = crate::lock(&file.group.files);
                let terminal = match files.iter().find(|f| f.id == file.id) {
                    None => true,
                    Some(fq) => fq.closed,
                };
                let has_work = files.iter().any(|f| !f.closed && !f.items.is_empty());
                if terminal || has_work {
                    return;
                }
            }
            notified.await;
        }
    }

    /// Item completion accounting (`remaining` -1; zero = file
    /// complete: set terminal + clear the leftover queue + wake the
    /// owner worker and the driver main loop).
    pub fn note_item_done(&self, file: &BatchFile<T>) {
        let prev = file.remaining.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            {
                let mut files = crate::lock(&file.group.files);
                if let Some(fq) = files.iter_mut().find(|f| f.id == file.id) {
                    fq.closed = true;
                    fq.items.clear();
                }
            }
            file.done.notify_one();
            file.group.notify.notify_waiters();
        } else if prev == 0 {
            // Underflow defense: if the driver contract (one push, one
            // done per item) is ever broken, don't let usize wrap into
            // an astronomical number — pin 0 and continue (close-out
            // judges by worker join/first_error, not this counter).
            file.remaining.store(0, Ordering::Release);
        }
    }

    /// Void a file to terminal (the failure/cancel face): clear
    /// remaining items, owner worker exits. (The completion face is
    /// built into [`BatchGroups::note_item_done`]'s zero path.)
    pub fn abort(&self, file: &BatchFile<T>) {
        {
            let mut files = crate::lock(&file.group.files);
            if let Some(fq) = files.iter_mut().find(|f| f.id == file.id) {
                fq.closed = true;
                fq.items.clear();
            }
        }
        file.group.notify.notify_waiters();
    }

    /// File leaves the group (the final step of done/fail/cancel):
    /// remove the sub-queue; an empty group disbands (registry entry
    /// removed — the observation endpoint of the budget returning to
    /// the pool: active reaches zero as gates Drop, and the entry goes
    /// with the last file).
    pub fn leave(&self, file: &BatchFile<T>) {
        {
            let mut files = crate::lock(&file.group.files);
            files.retain(|f| f.id != file.id);
        }
        file.group.notify.notify_waiters();
        let mut groups = crate::lock(&self.groups);
        if let Some(g) = groups.get(&file.host) {
            let empty = crate::lock(&g.files).is_empty();
            if empty {
                groups.remove(&file.host);
            }
        }
    }

    /// Wait for file completion (the `remaining`-zero unicast wakeup;
    /// the driver main loop's wait face — dual channel with worker
    /// join, first arrival wins).
    pub async fn wait_file_done(&self, file: &BatchFile<T>) {
        loop {
            let notified = file.done.notified();
            tokio::pin!(notified);
            if file.remaining.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Group observation snapshot (missing group = all zeros — the e2e
    /// "group disbanded" criterion).
    pub fn stats(&self, host: &str) -> BatchGroupStats {
        let Some(group) = self.group_of(host) else {
            return BatchGroupStats {
                files: 0,
                active: 0,
                queued: 0,
            };
        };
        let files = crate::lock(&group.files);
        BatchGroupStats {
            files: files.len(),
            active: group.active.load(Ordering::Relaxed),
            queued: files.iter().map(|f| f.items.len()).sum(),
        }
    }

    /// Live group count in the registry (the e2e "group disbanded"
    /// assertion).
    pub fn live_groups(&self) -> usize {
        crate::lock(&self.groups).len()
    }

    /// Connection gate (where the three-layer stacking is cashed out;
    /// see the module docs): ceiling = max(budget, host cap − outside
    /// occupancy) (soft cap not active = no ceiling). Active (host-
    /// permit waiters included) < ceiling → CAS reserve, then block
    /// for the per-host permit (fair queueing, no polling ramp);
    /// ≥ ceiling → [`GateBusy`] (group share full: the worker yields
    /// briefly and retries).
    ///
    /// The active-count CAS reservation happens BEFORE acquiring the
    /// host permit (the ceiling accounts atomically); cancellation
    /// while waiting (future drop) returns the count via
    /// [`ReserveGuard`].
    pub async fn gate_enter(
        &self,
        host: &str,
        budget: u32,
        per_host: &HostCap,
    ) -> Result<GatePermit<T>, GateBusy> {
        let group = self.group_of(host).ok_or(GateBusy)?;
        // Batch form, once on, stays on for the group's lifetime (see
        // GroupInner.batch_form).
        let soft = group.batch_form.load(std::sync::atomic::Ordering::Acquire)
            || crate::lock(&group.files).len() >= BATCH_MIN_FILES;
        // Ceiling formula (work-conserving and polite under contention,
        // no polling ramp):
        //
        // ```text
        // ceiling = max(budget, host_cap − outside occupancy)
        // outside occupancy = host_active − group_active (atomic
        // snapshot, possibly slightly stale)
        // ```
        //
        // - Host idle (outside 0) → ceiling = host cap: the group takes
        // the full cap in one step, no "within budget → overflow"
        // two-phase ramp (an earlier overflow-try + yield-poll design
        // left connection-utilization gaps in the half-idle regime);
        // - Host contention (outside ≥ host cap − budget) → ceiling =
        // budget: the group falls back to its polite share; the
        // host-permit fair queue applies as usual (in-flight
        // connections are never preempted);
        // - The host cap itself stays the hard ceiling (acquire per
        // connection); stale instantaneous readings only jitter the
        // ceiling by the concurrent-connect count — a politeness, not
        // a correctness, property.
        let ceiling = if soft {
            let host_cap = u64::from(per_host.cap());
            let outside = per_host
                .active(host)
                .saturating_sub(group.active.load(Ordering::Acquire));
            u64::from(budget).max(host_cap.saturating_sub(outside))
        } else {
            u64::MAX
        };
        // CAS-reserve an active slot (the ceiling test covers waiters —
        // the reservation happens before joining the host queue, and
        // the group active count includes in-flight + queued, so the
        // bound holds).
        loop {
            let cur = group.active.load(Ordering::Acquire);
            if cur >= ceiling {
                return Err(GateBusy); // group share full: yield briefly, retry.
            }
            match group
                .active
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        let mut reserve = ReserveGuard {
            group: Arc::clone(&group),
            confirmed: false,
        };
        let host_permit = per_host.acquire(host).await;
        reserve.confirmed = true; // ownership handed to GatePermit (its Drop returns it).
        drop(reserve);
        Ok(GatePermit {
            group,
            host: Some(host_permit),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Lifecycle: join → push → rotation takes → completion zeroes the
    /// count → terminal → leave → group disbands (registry entry
    /// removed).
    #[tokio::test]
    async fn lifecycle_join_drain_done_leave_group_disbands() {
        let g = BatchGroups::<u64>::new();
        let host = "http://life.test:80";
        assert_eq!(g.live_groups(), 0, "no groups at the start");
        let f1 = g.join(host);
        let f2 = g.join(host);
        assert_eq!(
            g.stats(host).files,
            2,
            "two files in the group (batch shape K=2)"
        );
        g.push(&f1, [1, 2]);
        g.push(&f2, [3]);
        assert_eq!(g.stats(host).queued, 3);
        // SRPT take (cross-file stealing): all three items can be
        // taken by any worker.
        let mut got = Vec::new();
        got.push(g.next(&f1).await.unwrap_or_else(|| panic!("f1 #1")));
        assert_eq!(
            f1_remaining(&g, &f1),
            2,
            "taking an item does not decrement remaining \
             (incomplete semantics — an item in hand is still unfinished)"
        );
        got.push(g.next(&f2).await.unwrap_or_else(|| panic!("f2 #1")));
        got.push(g.next(&f1).await.unwrap_or_else(|| panic!("f1 #2")));
        got.sort_unstable();
        assert_eq!(
            got,
            vec![1, 2, 3],
            "all three items taken (cross-file stealing)"
        );
        assert_eq!(g.stats(host).queued, 0);
        // Completion accounting (item 3 was taken by f2's worker but
        // its owner is f1 — done is recorded on the item's owner file;
        // see the driver contract).
        g.note_item_done(&f1);
        assert_eq!(f1_remaining(&g, &f1), 1);
        g.note_item_done(&f1);
        assert!(
            g.next(&f1).await.is_none(),
            "owner worker of a finished file exits"
        );
        g.abort(&f2);
        assert!(
            g.next(&f2).await.is_none(),
            "owner worker of an aborted file exits"
        );
        g.leave(&f1);
        assert_eq!(
            g.stats(host).files,
            1,
            "after f1 leaves the group, f2 remains"
        );
        g.leave(&f2);
        assert_eq!(
            g.live_groups(),
            0,
            "the group disbands when the last file leaves"
        );
        assert_eq!(g.stats(host).files, 0, "snapshot all zeros after disband");
    }

    /// remaining observation seam (test face: direct read of the
    /// unfinished count).
    fn f1_remaining<T>(_g: &BatchGroups<T>, f: &BatchFile<T>) -> usize {
        f.remaining.load(Ordering::Acquire)
    }

    /// Budget returns to the pool: holding gates raises the count,
    /// Drop zeroes it (the unit basis of the e2e peak assertion).
    #[tokio::test]
    async fn gate_budget_return_on_drop() {
        let g = BatchGroups::<u64>::new();
        let host = "http://gate.test:80";
        let cap = HostCap::new(32);
        let f1 = g.join(host);
        let f2 = g.join(host);
        let a = g
            .gate_enter(host, DEFAULT_BATCH_BUDGET, &cap)
            .await
            .unwrap_or_else(|_| panic!("gate a"));
        let b = g
            .gate_enter(host, DEFAULT_BATCH_BUDGET, &cap)
            .await
            .unwrap_or_else(|_| panic!("gate b"));
        let c = g
            .gate_enter(host, DEFAULT_BATCH_BUDGET, &cap)
            .await
            .unwrap_or_else(|_| panic!("gate c"));
        assert_eq!(g.stats(host).active, 3, "three gates held, count 3");
        assert_eq!(cap.active(host), 3, "host count synced at 3");
        drop((a, b, c));
        assert_eq!(
            g.stats(host).active,
            0,
            "gate Drop returns the budget to the pool, zeroed"
        );
        assert_eq!(cap.active(host), 0);
        g.leave(&f1);
        g.leave(&f2);
    }

    /// Ceiling formula: host idle → ceiling = host cap (full in one
    /// step, no ramp); outside contention → ceiling converges to the
    /// budget (polite share); the single-file shape has no ceiling.
    #[tokio::test]
    async fn gate_ceiling_work_conserving_and_politeness() {
        let g = BatchGroups::<u64>::new();
        let host = "http://soft.test:80";
        // Host cap 4, budget 2.
        let cap = HostCap::new(4);
        let f1 = g.join(host);
        let f2 = g.join(host);
        // Idle (outside 0): ceiling = max(2, 4-0) = 4 → all four gates
        // pass.
        let gates = (
            g.gate_enter(host, 2, &cap)
                .await
                .unwrap_or_else(|_| panic!("gate")),
            g.gate_enter(host, 2, &cap)
                .await
                .unwrap_or_else(|_| panic!("gate")),
            g.gate_enter(host, 2, &cap)
                .await
                .unwrap_or_else(|_| panic!("gate")),
            g.gate_enter(host, 2, &cap)
                .await
                .unwrap_or_else(|_| panic!("gate")),
        );
        assert_eq!(
            cap.active(host),
            4,
            "with the host idle the group fills the host cap"
        );
        assert_eq!(g.stats(host).active, 4);
        drop(gates);
        // Contention: outside pre-holds 3 (host cap 4 leaves 1) →
        // ceiling = max(2, 1) = 2. Gate a takes the last slot
        // instantly; gate b queues on the full host (blocks within the
        // ceiling waiting for a permit — the fair contention face);
        // from the third gate on the ceiling is full → GateBusy.
        let mut outside: Vec<_> = (0..3)
            .map(|_| cap.try_acquire(host).unwrap_or_else(|| panic!("outside")))
            .collect();
        let a = g
            .gate_enter(host, 2, &cap)
            .await
            .unwrap_or_else(|_| panic!("gate"));
        // b queues on the full host (blocks within the ceiling waiting
        // for a permit — the fair contention face); not yet granted,
        // but its CAS reservation already counts toward the ceiling.
        let b_fut = g.gate_enter(host, 2, &cap);
        tokio::pin!(b_fut);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            r = &mut b_fut => panic!(
                "with the host full, a gate within the ceiling \
                 must not be granted immediately ({})",
                r.is_ok()
            ),
        }
        assert_eq!(
            g.stats(host).active,
            2,
            "in-flight orders within the ceiling = 2 (a in transit + b queued)"
        );
        assert!(
            g.gate_enter(host, 2, &cap).await.is_err(),
            "group share full -> GateBusy"
        );
        // Outside yields 1 slot → the queued b is granted (fair relay,
        // no polling).
        drop(outside.pop());
        let b = tokio::time::timeout(Duration::from_secs(2), b_fut)
            .await
            .unwrap_or_else(|_| panic!("the queued gate is granted after a slot is yielded"))
            .unwrap_or_else(|_| panic!("gate b granted"));
        drop((a, b));
        drop(outside);
        // Single-file shape (1 file in group): no ceiling — budget 2
        // does not constrain.
        g.leave(&f1);
        g.leave(&f2);
        assert_eq!(g.stats(host).files, 0);
        let solo = g.join(host);
        let gates = (
            g.gate_enter(host, 2, &cap)
                .await
                .unwrap_or_else(|_| panic!("gate")),
            g.gate_enter(host, 2, &cap)
                .await
                .unwrap_or_else(|_| panic!("gate")),
            g.gate_enter(host, 2, &cap)
                .await
                .unwrap_or_else(|_| panic!("gate")),
        );
        assert_eq!(
            g.stats(host).active,
            3,
            "a single file is not budget-constrained"
        );
        drop(gates);
        g.leave(&solo);
        assert_eq!(g.live_groups(), 0);
    }

    /// Cross-file stagger: group-level first-wave ordinals — the
    /// ordinal ranges pre-reserved by two files in one group are
    /// disjoint (the fix for K same-moment ordinal-0 connects); after
    /// disband (last file leaves, registry entry removed) a new group
    /// re-ramps from 0 (reset trade-off in the
    /// [`BatchFile::stagger_ordinal_base`] write-up).
    #[test]
    fn stagger_ordinals_are_group_global_and_reset_on_disband() {
        let g = BatchGroups::<u64>::new();
        let host = "http://stagger.test:80";
        let f1 = g.join(host);
        let f2 = g.join(host);
        // Both files' first waves are 3 workers: ordinal ranges [0,3)
        // and [3,6) — staggered globally in the group.
        let b1 = f1.stagger_ordinal_base(3);
        let b2 = f2.stagger_ordinal_base(3);
        assert_eq!(b1, 0, "a new group's first segment starts at 0");
        assert_eq!(
            b2, 3,
            "later files in the same group get reserved segments right after (not back to 0)"
        );
        // Contiguous within a range, zero overlap across ranges (before
        // the fix each file had an independent 0..3 — K ordinal-0s).
        let all: Vec<u64> = (b1..b1 + 3).chain(b2..b2 + 3).collect();
        let distinct: std::collections::HashSet<u64> = all.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            all.len(),
            "first-wave ordinals within the group are globally distinct: {all:?}"
        );
        // Disband reset: group empty → entry removed → new group, new
        // counter from 0.
        g.leave(&f1);
        g.leave(&f2);
        assert_eq!(
            g.live_groups(),
            0,
            "group disbanded (the precondition of the reset face)"
        );
        let f3 = g.join(host);
        assert_eq!(
            f3.stagger_ordinal_base(2),
            0,
            "after disband a new group's ordinals unfold from 0 again (new storm, new ramp)"
        );
        g.leave(&f3);
    }

    /// Mid-flight abort: remaining items voided, takers never take an
    /// aborted file's items.
    #[tokio::test]
    async fn abort_discards_pending_items() {
        let g = BatchGroups::<u64>::new();
        let host = "http://abort.test:80";
        let f1 = g.join(host);
        let f2 = g.join(host);
        g.push(&f1, [10, 11]);
        g.abort(&f1);
        assert_eq!(g.stats(host).queued, 0, "abort empties the sub-queue");
        assert!(
            g.next(&f1).await.is_none(),
            "owner worker of an aborted file exits"
        );
        g.push(&f2, [20]);
        assert_eq!(
            g.next(&f2)
                .await
                .unwrap_or_else(|| panic!("f2 after abort")),
            20,
            "other files still take items normally"
        );
        g.note_item_done(&f2);
        g.leave(&f1);
        g.leave(&f2);
        assert_eq!(g.live_groups(), 0);
    }

    /// Empty-group wait wakeup: a waiting taker wakes on push (no
    /// lost wakeup).
    #[tokio::test]
    async fn next_waits_until_push() {
        let g = Arc::new(BatchGroups::<u64>::new());
        let host = "http://wait.test:80";
        let f1 = g.join(host);
        let f2 = g.join(host);
        let waiter = {
            let g = Arc::clone(&g);
            let f = f2.clone();
            tokio::spawn(async move { g.next(&f).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "the empty-group taker suspends waiting"
        );
        g.push(&f1, [42]);
        let got = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .unwrap_or_else(|_| panic!("wake does not time out"))
            .unwrap_or_else(|_| panic!("join"))
            .unwrap_or_else(|| panic!("got an item"));
        assert_eq!(
            got, 42,
            "the other file's item was taken by the waiter (stealing face)"
        );
        g.note_item_done(&f1);
        g.leave(&f1);
        g.leave(&f2);
    }

    /// File-completion wait face: wait_file_done returns as soon as
    /// the count zeroes.
    #[tokio::test]
    async fn wait_file_done_returns_at_zero() {
        let g = BatchGroups::<u64>::new();
        let host = "http://done.test:80";
        let f = g.join(host);
        g.push(&f, [1, 2]);
        g.note_item_done(&f);
        g.note_item_done(&f);
        tokio::time::timeout(Duration::from_secs(1), g.wait_file_done(&f))
            .await
            .unwrap_or_else(|_| panic!("returns once zeroed"));
        assert!(g.next(&f).await.is_none(), "finished means terminal");
        g.leave(&f);
    }

    /// Immediate-take tri-state: item present → take it (SRPT
    /// stealing, no waiting) / all in flight = [`Work::Empty`] (no
    /// suspension) / owner terminal = [`Work::Terminal`] — the unit
    /// basis of the worker "gate first, then take" ordering's take
    /// face.
    #[tokio::test]
    async fn try_next_tri_state_immediate() {
        let g = BatchGroups::<u64>::new();
        let host = "http://trynext.test:80";
        let f1 = g.join(host);
        let f2 = g.join(host);
        g.push(&f1, [7]);
        match g.try_next(&f2) {
            Work::Item(7) => {}
            Work::Item(other) => panic!("got an unexpected item {other}"),
            _ => panic!("an available item must be taken immediately (cross-file stealing)"),
        }
        match g.try_next(&f1) {
            Work::Empty => {}
            _ => panic!(
                "no queued items in the group (all in flight) = Empty; must not suspend or exit"
            ),
        }
        g.abort(&f2);
        match g.try_next(&f2) {
            Work::Terminal => {}
            _ => panic!("owner terminal = Terminal (worker exits)"),
        }
        g.note_item_done(&f1);
        g.leave(&f1);
        g.leave(&f2);
        assert_eq!(g.live_groups(), 0);
    }

    /// Permit-idling elimination contract: while waiting for an item
    /// the worker drops its gate first — group active and the host
    /// permit return to the pool immediately (waiting holds no
    /// permit); after push, [`BatchGroups::wait_work`] wakes
    /// immediately (register-then-check, no lost wakeup), and
    /// re-taking the gate can grab the new item (fair loop-back).
    #[tokio::test]
    async fn waiting_worker_releases_gate_permit() {
        let g = BatchGroups::<u64>::new();
        let host = "http://release.test:80";
        let cap = HostCap::new(4);
        let f1 = g.join(host);
        let f2 = g.join(host);
        // Worker take phase, simulated (the small_batch_worker
        // ordering):
        let gate = g
            .gate_enter(host, DEFAULT_BATCH_BUDGET, &cap)
            .await
            .unwrap_or_else(|_| panic!("gate enter"));
        assert_eq!(
            g.stats(host).active,
            1,
            "group active 1 while the gate is held"
        );
        assert_eq!(cap.active(host), 1);
        match g.try_next(&f2) {
            Work::Empty => {
                drop(gate); // yield while waiting (permit returns to the pool).
                assert_eq!(
                    g.stats(host).active,
                    0,
                    "group active drops to zero while waiting (idle-spin eliminated)"
                );
                assert_eq!(cap.active(host), 0, "host permit synced back to the pool");
                // After push the waiter wakes immediately
                // (register-then-check — not dependent on this
                // ordering's timing luck: wait_work re-checks the
                // state itself).
                g.push(&f1, [42]);
                tokio::time::timeout(Duration::from_secs(1), g.wait_work(&f2))
                    .await
                    .unwrap_or_else(|_| panic!("the waiter wakes immediately after push"));
                // Fair loop-back: re-take the gate → get the new item.
                let gate = g
                    .gate_enter(host, DEFAULT_BATCH_BUDGET, &cap)
                    .await
                    .unwrap_or_else(|_| panic!("gate re-enter"));
                match g.try_next(&f2) {
                    Work::Item(42) => {}
                    _ => panic!("after the loop-back a new item should be taken"),
                }
                drop(gate);
            }
            _ => panic!("an empty group should be Empty"),
        }
        g.note_item_done(&f1);
        g.leave(&f1);
        g.leave(&f2);
        assert_eq!(g.live_groups(), 0);
    }
}
