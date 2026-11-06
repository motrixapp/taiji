//! Face-level read pool (async upload read path): inbound-request disk
//! reads move out of the peer event loop — [`crate::peer::sources::
//! PieceSource`] is a synchronous blocking read (direct syscalls) and
//! used to run inline in the peer_loop frame-handling body, occupying a
//! tokio worker (contrary to peer/mod.rs's "no blocking operations"
//! rule).
//!
//! # Reference shape
//!
//! libtorrent runs a single network thread plus a pool of disk threads:
//! all network state is serialized on one io_context, disk I/O is split
//! into an independent thread pool (`session_impl.hpp` `m_disk_thread`;
//! `disk_io_thread_pool` scales on demand, `aio_threads` default 10 =
//! `settings_pack.cpp`). Read-serving jobs run on disk threads and are
//! posted back to the network thread with merged completions (the
//! `mmap_disk_io` job pipeline) — the peer read path never blocks the
//! event loop. This pool is that disk-thread-pool counterpart: the
//! peer_loop is the "network thread" (the select message loop); serve
//! reads enter a bounded queue as jobs, dispatchers execute them in
//! `spawn_blocking`, and completions are re-injected to PeerTask in
//! request order (divergence note: libtorrent posts completions out of
//! order and lets the request bookkeeping realign them; here [`ServeQueue`]
//! preserves order by seq, keeping the wire frame order of the existing
//! inline path unchanged).
//!
//! # Structure
//!
//! - [`ReadPool`]: face-level shared (`Arc` distributed via
//! `PeerConfig::read_pool`). Dispatcher count = the capacity cap
//! (min(4, workers)); the job queue is bounded — full makes
//! [`ReadPool::try_serve`] fail and the caller falls back to inline
//! (semantics = the existing synchronous serving path, correctness
//! unchanged, requests are never dropped).
//! - 16KiB aligned block buffer pool: `#[repr(align)]` safe alignment
//! (the workspace sets `unsafe_code = forbid`, so no hand-written
//! alloc), free-list recycling; zero-copy outbound via
//! `Bytes::from_owner` (bytes >= 1.9, safe trait bound
//! `AsRef<[u8]> + Send`), the buffer returns to the pool as soon as
//! the frame is written — removes the per-request `vec![0u8; length]`
//! zero-page allocation (a VM churn contributor).
//! - [`ServeQueue`]: per-connection in-order re-injection bookkeeping
//! (held by peer_loop; the inbound arm pushes, the completion arm
//! sends in ascending seq order).
//!
//! # Discipline
//!
//! - bounded channels: the job queue / completion channel are both
//! bounded (unbounded forbidden);
//! - no lock across await: the `tokio::sync::Mutex` only serializes the
//! dispatcher taking jobs (holding the async lock across recv is its
//! intended use); the buffer free-list is a std Mutex critical section
//! (no await);
//! - blocking syscalls run only inside `spawn_blocking` (same
//! concurrency discipline as disk.rs).
//!
//! Upstream anchor mapping: docs/design/peer-protocol.md

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::mpsc;

use super::sources::PieceSource;

/// Dispatcher count cap = min(4, workers) (workers proxied by
/// [`std::thread::available_parallelism`] — the tokio multi-thread
/// runtime default worker count has the same source). Deliberately below
/// libtorrent's `aio_threads` default of 10 (`settings_pack.cpp`;
/// deliberate divergence): loopback/page-cache reads dominate, 4-way
/// concurrency covers it; an engineering value, revisit under load.
pub const READ_POOL_DISPATCHERS_CAP: usize = 4;
/// Job queue capacity: bounded-channel discipline (unbounded forbidden);
/// full = inline fallback (the `try_serve` try-send-full-to-inline branch
/// semantics unchanged). The value is a face-level **single** value (one
/// [`ReadPool`] is shared across all connections, not per connection) —
/// steady-state in-flight = dispatchers <= 4 x batch 16 x tens per
/// connection, so 512 covers a single connection's pending cap of 256 at
/// multi-connection high water (~50KiB resident per face).
const QUEUE_CAP: usize = 512;
/// Per-connection completion channel capacity: >= the request window cap
/// of 256 (the doubling-adaptive upper bound); full = the dispatcher side
/// `send().await` backpressures (pauses taking new jobs), results are
/// never dropped.
const OUTCOME_CAP: usize = 256;
/// Cap on jobs per batch (the try_recv drain merge cap after a dispatcher
/// takes the first job; an engineering value, revisit under load).
const MAX_BATCH_CAP: usize = 16;
/// Buffer free-list recycle cap (blocks; >= dispatchers x batch, an
/// engineering value).
const BUFFER_POOL_CAP: usize = 64;
/// Read block buffer length = 16KiB: the BT wire request block cap
/// (SPEC §6.2 / BEP3; the inbound.rs `length > 16 * 1024` disconnect
/// rule), so serve-path requests are <= this value.
const BLOCK_LEN: usize = 16 * 1024;

/// 16KiB aligned block (safe aligned allocation: `#[repr(align(16384))]`
/// = BLOCK_LEN, so `Box<Block>` is 16KiB aligned — alignment
/// pre-provisioning for future O_DIRECT / arena use).
#[repr(align(16384))]
struct Block([u8; BLOCK_LEN]);

/// Buffer free-list (std Mutex critical section, no await; recycled
/// within the cap, released beyond it).
struct BufferPool {
    free: Mutex<Vec<Box<Block>>>,
    cap: usize,
}

impl BufferPool {
    fn new(cap: usize) -> BufferPool {
        BufferPool {
            free: Mutex::new(Vec::new()),
            cap,
        }
    }

    fn take(&self) -> Box<Block> {
        crate::lock(&self.free)
            .pop()
            .unwrap_or_else(|| Box::new(Block([0u8; BLOCK_LEN])))
    }

    fn recycle(&self, b: Box<Block>) {
        let mut free = crate::lock(&self.free);
        if free.len() < self.cap {
            free.push(b);
        }
    }
}

/// Ownership wrapper for a pooled block: the owner side of
/// `Bytes::from_owner` (safe trait bound); when the Bytes dies (frame
/// written) the block returns to the pool — zero per-request allocation
/// on the read-serving path.
struct PooledBlock {
    block: Option<Box<Block>>,
    len: usize,
    pool: Arc<BufferPool>,
}

impl AsRef<[u8]> for PooledBlock {
    fn as_ref(&self) -> &[u8] {
        &self
            .block
            .as_ref()
            .unwrap_or_else(|| unreachable!("block held until Drop (from_owner contract)"))
            .0[..self.len]
    }
}

impl Drop for PooledBlock {
    fn drop(&mut self) {
        if let Some(b) = self.block.take() {
            self.pool.recycle(b);
        }
    }
}

/// Admission token for one in-flight serve slot: produced by
/// [`ServeQueue::push`], consumed by [`ReadPool::try_serve`]. `started` =
/// the "read has started" flag — set once a dispatcher takes the job; the
/// BEP6 choke prune ([`ServeQueue::take_unstarted`]) cuts only unstarted
/// slots, while started slots run to completion per "requests that are
/// being processed are allowed to complete".
pub(super) struct ServeSlot {
    pub(super) seq: u64,
    started: Arc<AtomicBool>,
}

/// One serve read job (the disk-read unit of an inbound request).
/// `started` semantics: see [`ServeSlot`].
struct ServeJob {
    src: Arc<dyn PieceSource>,
    index: u32,
    begin: u32,
    len: usize,
    seq: u64,
    started: Arc<AtomicBool>,
    out: mpsc::Sender<ServeOutcome>,
}

/// A completed read job (the payload re-injected to PeerTask).
pub(super) struct ServeOutcome {
    pub(super) seq: u64,
    pub(super) result: Result<Bytes, String>,
}

/// An in-order delivery item: `(wire index, begin, length, upload
/// counter, read result)` (the PeerTask completion arm sends Piece /
/// Reject from this).
pub(super) type ServeReply = (
    u32,
    u32,
    u32,
    Option<Arc<std::sync::atomic::AtomicU64>>,
    Result<Bytes, String>,
);

struct JobDone {
    out: mpsc::Sender<ServeOutcome>,
    outcome: ServeOutcome,
}

/// Face-level read pool: see the module docs. The `Clone` surface is not
/// exposed — always distributed as `Arc<ReadPool>`. Note: the buffer pool
/// is owned by the dispatcher tasks and [`PooledBlock`] (the `Arc`
/// chain); this struct holds only the job enqueue end.
pub struct ReadPool {
    jobs_tx: mpsc::Sender<ServeJob>,
}

impl std::fmt::Debug for ReadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadPool").finish_non_exhaustive()
    }
}

impl ReadPool {
    /// Production constructor: dispatcher count =
    /// min([`READ_POOL_DISPATCHERS_CAP`], available_parallelism). Must be
    /// called in a runtime context (dispatcher tasks are spawned).
    /// Returns an `Arc` (face-level shared form —
    /// `PeerConfig::read_pool` / `FaceState::read_pool` always distribute
    /// an Arc).
    pub fn new() -> Arc<ReadPool> {
        Self::with_limits(Self::dispatcher_count(), MAX_BATCH_CAP)
    }

    /// Fixed-parameter constructor (test injection: small dispatcher
    /// count / batch depth 1 to construct deterministic interleavings).
    pub fn with_limits(dispatchers: usize, batch: usize) -> Arc<ReadPool> {
        let (jobs_tx, jobs_rx) = mpsc::channel(QUEUE_CAP);
        let buffers = Arc::new(BufferPool::new(BUFFER_POOL_CAP));
        let rx = Arc::new(tokio::sync::Mutex::new(jobs_rx));
        for _ in 0..dispatchers.max(1) {
            tokio::spawn(dispatch_loop(
                Arc::clone(&rx),
                Arc::clone(&buffers),
                batch.max(1),
            ));
        }
        Arc::new(ReadPool { jobs_tx })
    }

    fn dispatcher_count() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, READ_POOL_DISPATCHERS_CAP)
    }

    /// Non-blocking enqueue (called in the peer event loop's
    /// frame-handling arm): full = `Err` (the caller falls back to inline
    /// — bounded backpressure exchanged for a bounded degradation,
    /// requests never dropped). `slot` is borrowed, not consumed — on the
    /// Err path the caller still needs `slot.seq` to undo the
    /// registration.
    pub(super) fn try_serve(
        &self,
        src: Arc<dyn PieceSource>,
        index: u32,
        begin: u32,
        length: usize,
        slot: &ServeSlot,
        out: mpsc::Sender<ServeOutcome>,
    ) -> Result<(), ()> {
        self.jobs_tx
            .try_send(ServeJob {
                src,
                index,
                begin,
                len: length,
                seq: slot.seq,
                started: Arc::clone(&slot.started),
                out,
            })
            .map_err(|_| ())
    }
}

// Note: `Default` is not implemented — the only constructors are
// [`ReadPool::new`] / [`ReadPool::with_limits`] (returning the shared
// `Arc<ReadPool>` form).

/// Dispatcher main loop: take a batch under the mutex (holding the async
/// lock across recv is the tokio Mutex's intended use; try_recv drains
/// without waiting), run `spawn_blocking` **outside** the lock (all
/// blocking work on blocking threads), then re-inject completions one by
/// one into each connection's completion channel (full = await
/// backpressure).
async fn dispatch_loop(
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ServeJob>>>,
    buffers: Arc<BufferPool>,
    max_batch: usize,
) {
    loop {
        let batch = {
            let mut g = rx.lock().await;
            let Some(first) = g.recv().await else {
                // Pool released (all ReadPools dropped) -> dispatcher exits.
                return;
            };
            let mut batch = vec![first];
            while batch.len() < max_batch {
                match g.try_recv() {
                    Ok(job) => batch.push(job),
                    Err(_) => break,
                }
            }
            batch
        };
        // Set "read has started" (the choke-prune boundary): set as soon as
        // a dispatcher takes the job — from then on the SendChoke prune
        // (ServeQueue::take_unstarted) no longer cuts this slot; it runs to
        // completion per BEP6 "requests that are being processed are
        // allowed to complete". The store happens before any read executes
        // and is a synchronous SeqCst write: the prune side reads the same
        // flag synchronously, so there is no race window across awaits.
        for job in &batch {
            job.started.store(true, Ordering::SeqCst);
        }
        // Blocking work in spawn_blocking (disk.rs concurrency discipline:
        // synchronous IO primitives must not occupy async workers). Note: a
        // source panic loses this batch of jobs (in-flight serve slots
        // stall, that connection's later serves stop while the loop lives
        // on) — sources are in-repo implementations (FaceSource/Partial/
        // test stubs), so a panic means an engine bug and is not swallowed.
        let buffers = Arc::clone(&buffers);
        let done = tokio::task::spawn_blocking(move || execute_batch(batch, &buffers)).await;
        if let Ok(done) = done {
            for jd in done {
                let _ = jd.out.send(jd.outcome).await;
            }
        }
    }
}

/// Execute a batch of reads: group by source (jobs on the same `Arc`
/// source merge — their buffers are disjoint), each group goes through
/// [`PieceSource::read_batch`] (default = per range; FaceSource overrides
/// with read_coalesced adjacent merging), results fill the `Bytes`
/// (short read / error -> Err, serve_request semantics: n < len =
/// unservable -> reject).
fn execute_batch(batch: Vec<ServeJob>, buffers: &Arc<BufferPool>) -> Vec<JobDone> {
    // Source grouping by pointer identity (jobs on the same Arc data source
    // merge into one read_batch call — the grouping precondition for
    // adjacent-cursor merging).
    let mut order: Vec<(usize, Vec<usize>)> = Vec::new(); // (first batch index, same-source job index group)
    for (ji, job) in batch.iter().enumerate() {
        match order
            .iter_mut()
            .find(|(si, _)| std::ptr::addr_eq(Arc::as_ptr(&batch[*si].src), Arc::as_ptr(&job.src)))
        {
            Some((_, group)) => group.push(ji),
            None => order.push((ji, vec![ji])),
        }
    }
    // Buffer lease: one block per job (all leased up front; buf views are
    // assembled per group).
    let mut blocks: Vec<Option<Box<Block>>> = batch.iter().map(|_| None).collect();
    for slot in blocks.iter_mut() {
        *slot = Some(buffers.take());
    }
    let mut done = Vec::with_capacity(batch.len());
    for (_, group) in order {
        let src = Arc::clone(&batch[group[0]].src);
        // Take the leased blocks (in group order); slice each buf view to
        // its request length.
        let mut leased: Vec<(usize, Box<Block>)> = group
            .iter()
            .map(|&ji| {
                (
                    ji,
                    blocks[ji]
                        .take()
                        .unwrap_or_else(|| unreachable!("leased once")),
                )
            })
            .collect();
        let mut bufrefs: Vec<&mut [u8]> = leased
            .iter_mut()
            .map(|(ji, b)| {
                let len = batch[*ji].len.min(BLOCK_LEN);
                &mut b.0[..len]
            })
            .collect();
        let reqs: Vec<(u32, u32)> = group
            .iter()
            .map(|&ji| (batch[ji].index, batch[ji].begin))
            .collect();
        let results = src.read_batch(&reqs, &mut bufrefs);
        drop(bufrefs); // release the view borrows of leased; consumed by value next
        let mut results = results.into_iter();
        for (ji, block) in leased {
            let result = results
                .next()
                .unwrap_or_else(|| unreachable!("read_batch len == reqs len"));
            let len = batch[ji].len;
            let seq = batch[ji].seq;
            let out = batch[ji].out.clone();
            let outcome = match result {
                Ok(n) if n == len => {
                    // Zero-copy outbound: block ownership moves with the
                    // Bytes; the pool gets it back when the frame is
                    // written (PooledBlock::drop).
                    Ok(Bytes::from_owner(PooledBlock {
                        block: Some(block),
                        len: n,
                        pool: Arc::clone(buffers),
                    }))
                }
                Ok(n) => {
                    buffers.recycle(block);
                    Err(format!(
                        "short read {n}/{len} (unallocated or out of range)"
                    ))
                }
                Err(e) => {
                    buffers.recycle(block);
                    Err(e)
                }
            };
            done.push(JobDone {
                out,
                outcome: ServeOutcome {
                    seq,
                    result: outcome,
                },
            });
        }
    }
    done
}

/// Per-connection in-order re-injection bookkeeping: the inbound arm
/// registers via [`ServeQueue::push`] (seq = arrival order), the
/// completion arm uses [`ServeQueue::note_result`] +
/// [`ServeQueue::drain_ready`] to hand results to PeerTask sending in
/// ascending seq order — out-of-order completing reads wait buffered in
/// `pending`, so the wire frame order exactly matches the inline path.
/// The SendChoke arm prunes "read not started" slots via
/// [`ServeQueue::take_unstarted`] (the BEP6 MUST-reject surface).
///
/// # pending cap (OOM backstop)
///
/// `pending` is semantically an unbounded BTreeMap — under normal
/// pipelining the peer's in-flight requests stay <= the target window cap
/// (256); at the cap [`ServeQueue::push`] refuses (`None`): the caller
/// answers with a BEP6 Reject Request and skips enqueueing (no
/// registration, no seq burned, no chain break). The cap defaults to 256
/// and is configurable via `BH_SERVE_PENDING_CAP` (clamped [32, 1024];
/// registered in knobs.rs).
pub(super) struct ServeQueue {
    out_tx: mpsc::Sender<ServeOutcome>,
    next_seq: u64,
    next_send: u64,
    pending: BTreeMap<u64, PendingServe>,
    /// In-flight bookkeeping cap (`pending.len() >= pending_cap` refuses;
    /// default = the knob reading, [`ServeQueue::with_pending_cap`] for
    /// test injection).
    pending_cap: usize,
}

/// Re-injection payload for one in-flight serve (coordinates + upload
/// counter + read-result slot). `started` = the "read has started" flag
/// (set once the dispatcher takes the job, semantics in [`ServeJob`]) —
/// the slot-level criterion of the SendChoke prune.
struct PendingServe {
    index: u32,
    begin: u32,
    length: u32,
    uploaded: Option<Arc<std::sync::atomic::AtomicU64>>,
    started: Arc<AtomicBool>,
    result: Option<Result<Bytes, String>>,
}

impl ServeQueue {
    /// Build the bookkeeping + completion receiver: the pending cap = the
    /// `BH_SERVE_PENDING_CAP` reading (default 256 clamped [32, 1024];
    /// evaluated once at construction and kept, registered in knobs.rs).
    pub(super) fn new() -> (ServeQueue, mpsc::Receiver<ServeOutcome>) {
        Self::with_pending_cap(taiji_io::knobs::serve_pending_cap() as usize)
    }

    /// Fixed-parameter constructor (test injection: a small cap to
    /// construct deterministic cap-reached states; same pattern as
    /// [`ReadPool::with_limits`]).
    pub(super) fn with_pending_cap(
        pending_cap: usize,
    ) -> (ServeQueue, mpsc::Receiver<ServeOutcome>) {
        let (out_tx, rx) = mpsc::channel(OUTCOME_CAP);
        (
            ServeQueue {
                out_tx,
                next_seq: 0,
                next_send: 0,
                pending: BTreeMap::new(),
                pending_cap,
            },
            rx,
        )
    }

    pub(super) fn out_tx(&self) -> mpsc::Sender<ServeOutcome> {
        self.out_tx.clone()
    }

    /// Register one in-flight serve (seq = arrival order) and return the
    /// admission token [`ServeSlot`] — the token rides with the job into
    /// the read pool ([`ReadPool::try_serve`]), and "read has started" is
    /// set as soon as a dispatcher takes the job. Read results arrive
    /// asynchronously over the completion channel; if enqueueing fails
    /// (queue full -> inline fallback) the caller MUST undo the
    /// registration with [`ServeQueue::remove`] — otherwise the seq chain
    /// breaks and every later completing read stays buffered (sending
    /// stalls).
    ///
    /// `None` = pending at cap (in-flight bookkeeping >= cap, default 256
    /// ≈ the peer's target window cap — unreachable under normal
    /// pipelining): **no registration, no seq burned** (no chain break,
    /// no remove needed), the caller answers with a BEP6 Reject Request
    /// and skips enqueueing (OOM backstop; cap semantics in the struct
    /// docs).
    pub(super) fn push(
        &mut self,
        index: u32,
        begin: u32,
        length: u32,
        uploaded: Option<Arc<std::sync::atomic::AtomicU64>>,
    ) -> Option<ServeSlot> {
        if self.pending.len() >= self.pending_cap {
            return None;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let started = Arc::new(AtomicBool::new(false));
        self.pending.insert(
            seq,
            PendingServe {
                index,
                begin,
                length,
                uploaded,
                started: Arc::clone(&started),
                result: None,
            },
        );
        Some(ServeSlot { seq, started })
    }

    /// Undo a registration (the inline-fallback path after a failed
    /// enqueue).
    pub(super) fn remove(&mut self, seq: u64) {
        self.pending.remove(&seq);
    }

    /// Record a completion result.
    pub(super) fn note_result(&mut self, seq: u64, result: Result<Bytes, String>) {
        if let Some(p) = self.pending.get_mut(&seq) {
            p.result = Some(result);
        }
        // seq not in the bookkeeping = the slot was already pruned (the
        // SendChoke prune; its answer was already given as Reject) or
        // undone after a failed enqueue — the result is dropped; BEP6
        // "EXACTLY ONE response" (reject or piece, never both) is
        // guaranteed by the prune side.
    }

    /// SendChoke prune: pop every in-flight item whose "read has not
    /// started" (`started` unset and no completed result), returning
    /// coordinates for the caller to Reject slot by slot. Started slots
    /// (`started` set, including completed ones waiting for in-order
    /// re-injection) are kept — BEP6 "requests that are being processed
    /// are allowed to complete". Later completions of pruned slots are
    /// dropped by [`ServeQueue::note_result`]'s defensive branch (the
    /// answer was already given as Reject; no piece is delivered on top).
    pub(super) fn take_unstarted(&mut self) -> Vec<(u32, u32, u32)> {
        let cut: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| !p.started.load(Ordering::SeqCst) && p.result.is_none())
            .map(|(seq, _)| *seq)
            .collect();
        cut.into_iter()
            .filter_map(|seq| {
                self.pending
                    .remove(&seq)
                    .map(|p| (p.index, p.begin, p.length))
            })
            .collect()
    }

    /// Pop ready items in request order (coordinates + upload counter +
    /// result) — only pops consecutive completed items starting at
    /// `next_send`: incomplete ones wait; removed seqs (the chain break
    /// of a failed enqueue's [`ServeQueue::remove`]) are skipped and the
    /// walk continues.
    pub(super) fn drain_ready(&mut self) -> Vec<ServeReply> {
        let mut out = Vec::new();
        loop {
            match self.pending.get_mut(&self.next_send) {
                Some(p) => {
                    let Some(result) = p.result.take() else { break };
                    let uploaded = p.uploaded.clone();
                    let (index, begin, length) = (p.index, p.begin, p.length);
                    self.pending.remove(&self.next_send);
                    self.next_send += 1;
                    out.push((index, begin, length, uploaded, result));
                }
                None => {
                    // Broken-chain seq (already removed) -> skip; past the
                    // highest issued seq -> stop on an empty pop.
                    if self.next_send >= self.next_seq {
                        break;
                    }
                    self.next_send += 1;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Deterministic source: reads at index 0 block on a test gate, all
    /// others immediately fill 0xCD.
    struct GatedSource {
        started: Arc<AtomicU64>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl PieceSource for GatedSource {
        fn read_block(&self, index: u32, _begin: u32, buf: &mut [u8]) -> Result<usize, String> {
            self.started.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                // Block until the test releases (inside a spawn_blocking
                // thread, blocking allowed).
                match self
                    .release
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .recv()
                {
                    Ok(()) => {}
                    Err(_) => panic!("release channel closed"),
                }
            }
            buf.fill(0xCD);
            Ok(buf.len())
        }
        fn total_len(&self) -> u64 {
            2 * BLOCK_LEN as u64
        }
    }

    fn gated_source() -> (
        Arc<GatedSource>,
        std::sync::mpsc::Sender<()>,
        Arc<AtomicU64>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let started = Arc::new(AtomicU64::new(0));
        let src = Arc::new(GatedSource {
            started: Arc::clone(&started),
            release: Mutex::new(rx),
        });
        (src, tx, started)
    }

    /// Poll-wait (tokio sleep yields the runtime — on a single-threaded
    /// test runtime std::thread::sleep would starve the dispatcher
    /// tasks).
    async fn wait_until(v: &AtomicU64, want: u64) {
        for _ in 0..2000 {
            if v.load(Ordering::SeqCst) >= want {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!(
            "condition not reached: {} < {want}",
            v.load(Ordering::SeqCst)
        );
    }

    /// Out-of-order completions replay in request order: seq0's read is
    /// held by the gate, seq1 completes first -> its result waits
    /// buffered; after releasing seq0, drain_ready delivers both in
    /// ascending seq order.
    #[tokio::test]
    async fn out_of_order_completions_replay_in_request_order() {
        let (src, release_tx, started) = gated_source();
        let pool = ReadPool::with_limits(2, 1);
        let (mut queue, mut rx) = ServeQueue::new();
        let out_tx = queue.out_tx();

        let src: Arc<dyn PieceSource> = src;
        let slot0 = queue
            .push(0, 0, 4096, None)
            .unwrap_or_else(|| panic!("push 0 (under cap)"));
        pool.try_serve(Arc::clone(&src), 0, 0, 4096, &slot0, out_tx.clone())
            .unwrap_or_else(|()| panic!("enqueue 0"));
        wait_until(&started, 1).await;
        let slot1 = queue
            .push(1, 0, 4096, None)
            .unwrap_or_else(|| panic!("push 1 (under cap)"));
        pool.try_serve(Arc::clone(&src), 1, 0, 4096, &slot1, out_tx)
            .unwrap_or_else(|()| panic!("enqueue 1"));

        // seq1 completed (gate not released -> seq0 still held): drain is
        // empty before seq0's result arrives.
        let o1 = rx.recv().await.unwrap_or_else(|| panic!("outcome 1"));
        assert_eq!(o1.seq, slot1.seq);
        queue.note_result(o1.seq, o1.result);
        assert!(
            queue.drain_ready().is_empty(),
            "seq0 unfinished -> no out-of-order skip"
        );

        // Release seq0 -> both results delivered in ascending seq order.
        release_tx
            .send(())
            .unwrap_or_else(|e| panic!("release: {e}"));
        let o0 = rx.recv().await.unwrap_or_else(|| panic!("outcome 0"));
        assert_eq!(o0.seq, slot0.seq);
        queue.note_result(o0.seq, o0.result);
        let ready = queue.drain_ready();
        assert_eq!(ready.len(), 2, "both results delivered in order");
        assert_eq!(
            ready[0].0, 0,
            "seq0 first (first in, first out; frame order = request order)"
        );
        assert_eq!(ready[1].0, 1);
        match &ready[0].4 {
            Ok(b) => assert_eq!(b.len(), 4096),
            other => panic!("seq0 must succeed, got {other:?}"),
        }
    }

    /// Failed-enqueue removal: after remove, the seq chain break does not
    /// block later in-order delivery.
    #[tokio::test]
    async fn removed_seq_does_not_stall_replay() {
        let (mut queue, _rx) = ServeQueue::new();
        let slot0 = queue
            .push(0, 0, 16, None)
            .unwrap_or_else(|| panic!("push 0 (under cap)"));
        let slot1 = queue
            .push(1, 0, 16, None)
            .unwrap_or_else(|| panic!("push 1 (under cap)"));
        queue.note_result(slot1.seq, Ok(Bytes::from_static(b"abcd")));
        assert!(
            queue.drain_ready().is_empty(),
            "seq0 unfinished (still booked) = seq1 must wait its turn, no out-of-order skip"
        );
        queue.remove(slot0.seq); // simulate the failed-enqueue fallback
        let ready = queue.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(
            ready[0].0, 1,
            "seq1 ready immediately once seq0 is cancelled"
        );
    }

    /// SendChoke prune: slots with `started` unset are popped one by one
    /// (for per-slot Rejects); set slots (read in flight / completed) are
    /// kept — their later completions re-inject as usual ("requests that
    /// are being processed are allowed to complete"), and late results of
    /// pruned slots are dropped (the BEP6 EXACTLY ONE answer was already
    /// given as Reject).
    #[test]
    fn take_unstarted_cuts_only_unstarted_slots() {
        let (mut queue, _rx) = ServeQueue::new();
        let slot0 = queue
            .push(0, 0, 16, None)
            .unwrap_or_else(|| panic!("push 0 (under cap)"));
        let slot1 = queue
            .push(1, 0, 16, None)
            .unwrap_or_else(|| panic!("push 1 (under cap)"));
        let slot2 = queue
            .push(2, 0, 16, None)
            .unwrap_or_else(|| panic!("push 2 (under cap)"));
        slot0.started.store(true, Ordering::SeqCst); // s0: dispatcher took it (read in flight)
        slot2.started.store(true, Ordering::SeqCst); // s2: read completed, waiting for in-order re-injection
        queue.note_result(slot2.seq, Ok(Bytes::from_static(b"abcdefghijklmnop")));

        let cut = queue.take_unstarted();
        assert_eq!(cut, vec![(1, 0, 16)], "only the not-yet-started s1 is cut");

        // Late completion of a pruned slot: dropped, must not be delivered.
        queue.note_result(slot1.seq, Ok(Bytes::from_static(b"xxxxxxxxxxxxxxxx")));
        // Kept slots complete normally: after s0 completes, s0/s2 pop in
        // request order and s1's broken chain is skipped.
        queue.note_result(slot0.seq, Ok(Bytes::from_static(b"yyyyyyyyyyyyyyyy")));
        let ready = queue.drain_ready();
        assert_eq!(
            ready.len(),
            2,
            "in-flight/completed slots delivered as usual"
        );
        assert_eq!(
            (ready[0].0, ready[1].0),
            (0, 2),
            "request-order re-injection unaffected by pruning"
        );
    }

    /// Buffer return to pool: the free-list recovers once the Bytes is
    /// released (16KiB aligned block reuse).
    #[tokio::test]
    async fn pooled_block_recycled_on_bytes_drop() {
        let pool = ReadPool::with_limits(1, 1);
        struct Fill;
        impl PieceSource for Fill {
            fn read_block(&self, _i: u32, _b: u32, buf: &mut [u8]) -> Result<usize, String> {
                buf.fill(0x11);
                Ok(buf.len())
            }
            fn total_len(&self) -> u64 {
                BLOCK_LEN as u64
            }
        }
        let (mut q, mut rx) = ServeQueue::new();
        let queue_tx = q.out_tx();
        let slot = q
            .push(0, 0, BLOCK_LEN as u32, None)
            .unwrap_or_else(|| panic!("push (under cap)"));
        pool.try_serve(Arc::new(Fill), 0, 0, BLOCK_LEN, &slot, queue_tx)
            .unwrap_or_else(|()| panic!("enqueue"));
        let o = rx.recv().await.unwrap_or_else(|| panic!("outcome"));
        q.note_result(o.seq, o.result);
        let mut ready = q.drain_ready();
        assert_eq!(ready.len(), 1);
        let (_, _, _, _, result) = ready.remove(0);
        let bytes = result.unwrap_or_else(|e| panic!("serve must succeed: {e}"));
        assert_eq!(bytes.len(), BLOCK_LEN);
        assert!(bytes.iter().all(|&b| b == 0x11));
        assert_eq!(bytes.as_ptr() as usize % 16384, 0, "16KiB aligned");
        drop(bytes); // back to the pool
    }

    /// pending cap-reached behavior: refuses (`None`) and **does not burn
    /// a seq** (a refused push never enters the bookkeeping, so there is
    /// no chain break — later enqueues keep seqs consecutive and existing
    /// in-flight items deliver in order regardless of refusals); the cap
    /// counts the `pending` map size (including completed items waiting
    /// for in-order delivery — the memory-backstop semantics); a slot
    /// frees up only after its completion is popped by re-injection.
    #[test]
    fn pending_cap_rejects_push_without_burning_seq() {
        let (mut queue, _rx) = ServeQueue::with_pending_cap(2);
        let s0 = queue
            .push(0, 0, 16, None)
            .unwrap_or_else(|| panic!("under cap"));
        let s1 = queue
            .push(1, 0, 16, None)
            .unwrap_or_else(|| panic!("under cap"));
        assert_eq!(
            (s0.seq, s1.seq),
            (0, 1),
            "consecutive enqueues under the cap"
        );

        // At cap: refused (repeatedly) — the caller answers BEP6 Reject
        // and does not enqueue.
        assert!(queue.push(2, 0, 16, None).is_none(), "rejected once at cap");
        assert!(
            queue.push(3, 0, 16, None).is_none(),
            "still rejected while at cap"
        );

        // Completed-but-waiting frees no slot: note_result only fills the
        // result slot, the map size is unchanged -> still refused.
        queue.note_result(s0.seq, Ok(Bytes::from_static(b"abcdefghijklmnop")));
        assert!(
            queue.push(4, 0, 16, None).is_none(),
            "completed waiters still hold the cap (memory backstop counts the map size)"
        );

        // In-order re-injection pops s0 -> slot freed; later enqueues keep
        // seqs consecutive (refusals burned none).
        let ready = queue.drain_ready();
        assert_eq!(ready.len(), 1, "only s0 complete, s1 waiting");
        assert_eq!(ready[0].0, 0);
        let s4 = queue
            .push(5, 0, 16, None)
            .unwrap_or_else(|| panic!("re-accepted after a slot frees"));
        assert_eq!(
            s4.seq, 2,
            "refusal burns no seq (2 right after 0/1, no chain break)"
        );

        // Refusals do not disturb the existing in-flight chain: after
        // s1/s4 complete, delivery follows request order (ascending seq).
        queue.note_result(s4.seq, Ok(Bytes::from_static(b"qqqqqqqqqqqqqqqq")));
        queue.note_result(s1.seq, Ok(Bytes::from_static(b"yyyyyyyyyyyyyyyy")));
        let ready = queue.drain_ready();
        assert_eq!(
            ready.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![1, 5],
            "in-flight chain delivers in order, unaffected by refusals"
        );
    }

    /// Job queue cap anchored: the face-level shared queue is 512 (full =
    /// inline fallback, a semantics owned by `try_serve`'s try_send
    /// branch and covered by the existing read_pool/inbound tests); this
    /// test only pins the constant against accidental rebound.
    #[test]
    fn queue_cap_anchored_at_512() {
        assert_eq!(QUEUE_CAP, 512);
    }
}
