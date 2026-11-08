//! Verify/write worker pool: offloads the per-piece "assemble -> hash
//! verify -> persist" tail from the pipeline's serial single point into a
//! parameterized worker pool (the throughput-ceiling lever).
//!
//! # Shape (concurrency discipline)
//!
//! - N workers, each with a bounded queue (depth
//!   [`VerifyPoolConfig::queue_per_worker`]). The dispatcher round-robins
//!   `try_send` from the last placement; when every queue is full it
//!   blocks on `send` to the next placement — a full pool makes
//!   [`VerifyPool::dispatch`] await, which backs up the pipeline's block
//!   input channel and ultimately the peer read loop (natural
//!   backpressure, no unbounded channel). Total in-flight job bound =
//!   `workers x queue_per_worker` (memory bound = that x longest-piece
//!   bytes, accounted together with the write-cache limit).
//! - Shared write handle ([`SharedDiskWriter`]) deserializes writes.
//!   Lock domains: write-external operations (fsync/allocate/truncate)
//!   take the exclusive write lock; the write hot path takes the read
//!   lock concurrently on unix when `BH_PARALLEL_WRITES=1` (concurrent
//!   pwrite to one fd at different offsets is POSIX-safe; libtorrent's
//!   mmap backend follows the same zero-serialization philosophy). The
//!   default is off = writes take the write lock = the old
//!   global-mutex semantics (see
//!   `taiji_store::verified::parallel_writes_env`). Piece goff ranges
//!   never overlap, so interleaving is harmless; cells within one piece
//!   are written by a single worker in ascending goff — intra-piece
//!   write order is unchanged. All locks are synchronous std locks;
//!   worker blocking work runs inside `spawn_blocking`, never held
//!   across an `await`.
//! - Verify before write: a worker runs [`PieceJob::verify`] (pure CPU)
//!   first and only then [`PieceJob::write_to`]; a failure/mismatch
//!   verdict goes back to the pipeline for the existing reset/refetch or
//!   fatal handling — pooling changes where the discipline executes, not
//!   the discipline.
//! - Eviction semantics untouched: eviction happens in the pipeline's
//!   buffer step (`buffer_block`) and never intersects this pool;
//!   finished-piece cells leave the cache with their job.
//! - Shutdown order: pipeline drops the pool -> `dispatch_tx` closes ->
//!   the dispatcher drains and exits -> worker queues close -> workers
//!   finish in-flight jobs and exit (in-flight writes complete
//!   naturally, same semantics as the pre-pool per-job
//!   `spawn_blocking`).
//!
//! # Reference
//!
//! libtorrent (BSD-3) `docs/features.rst`: "multiple disk I/O threads" +
//! "verifying SHA-1 hash of pieces in multiple threads" — parallel
//! verify/write is an established performance surface in mainstream
//! implementations; this pool is its verify-before-write equivalent.

use std::sync::Arc;

use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::debug;

use super::pipeline::{BUFFER_BATCH_BLOCKS, PIECE_GROUP_MAX};

use taiji_store::error::StoreError;
use taiji_store::verified::{CrossCheckFailed, PieceJob, SharedDiskWriter};

/// Worker pool parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VerifyPoolConfig {
    /// Worker count (parallel verify+write lanes; >= 1).
    pub(super) workers: usize,
    /// Per-worker queue depth (in-flight job bound = workers x
    /// queue_per_worker).
    pub(super) queue_per_worker: usize,
}

impl VerifyPoolConfig {
    /// Defaults: workers = min(CPU count, 4) (hashing scales with cores;
    /// writes go through the shared handle and are exclusive/serial by
    /// default — the parallel-write surface defaults off, see the
    /// [`SharedDiskWriter`] docs — so extra workers only serve hash
    /// parallelism; with BH_PARALLEL_WRITES=1 the write hot path is
    /// concurrent and workers serve both). `BH_VERIFY_WORKERS` overrides
    /// explicitly (tuning seam). Queue depth = 2 per worker (in-flight
    /// bytes bound ~ 4 workers x 2 x piece_len, ~8MiB for 1MiB pieces,
    /// same order as the 16MiB write cache).
    pub(super) fn auto() -> VerifyPoolConfig {
        // Env-override parsing lives in `taiji_io::knobs` (read at
        // construction; no cache mutation).
        let override_workers = taiji_io::knobs::verify_workers_override();
        let workers = override_workers
            .or_else(|| {
                std::thread::available_parallelism()
                    .ok()
                    .map(|n| n.get().min(4))
            })
            .unwrap_or(1);
        VerifyPoolConfig {
            workers,
            queue_per_worker: 2,
        }
    }

    // With groups occupying queue slots, the queued/executing job byte
    // bound = workers x (queue+1) x [`PIECE_GROUP_MAX`] x piece_len
    // (default 4/2 shape: ~8MiB for 256KiB pieces, ~32MiB for 1MiB
    // pieces; x1 per slot pre-grouping). Job bytes live outside the
    // write-cache cells; bounded, for capacity and memory profiling.

    fn checked(self) -> VerifyPoolConfig {
        VerifyPoolConfig {
            workers: self.workers.max(1),
            queue_per_worker: self.queue_per_worker.max(1),
        }
    }
}

/// Job execution result from the worker pool (the pipeline folds it into
/// the existing `PushOutcome` semantics).
///
/// Two-phase verdict: `Verified` (hash-pass, write in flight) returns
/// first — the pipeline immediately raises `Progress::PieceVerified`
/// (early HAVE advertise; libtorrent commit `7f691246a` passed->have) —
/// and `Written` (the flushed half) follows once the write completes.
/// At most two messages per job, arriving in order (worker monotonic
/// send order + channel FIFO).
#[derive(Debug)]
pub(super) enum PoolVerdict {
    /// Hash verified (write not yet committed): the advertise phase — the
    /// main loop broadcasts HAVE and advances verified progress;
    /// upload gating/persistence do not follow this verdict.
    Verified,
    /// Persisted (= the write half of the old `VerifiedWritten`): the
    /// written bitmap advances (upload-service gating lifted), the
    /// persistence bitmap advances, and face completion is judged.
    Written,
    /// Main-hash mismatch (= the old `PieceFailed`: the cell is destroyed
    /// with the job, the piece resets for refetch, nothing hit disk).
    HashMismatch,
    /// Cross-check inconsistent (BEP 52 metadata contradiction,
    /// torrent-level failure, nothing hit disk).
    CrossInconsistent(CrossCheckFailed),
    /// Write failed (= the old write-path Err: torrent-level Fatal).
    WriteFailed(StoreError),
    /// Blocking job task join failed (= the old spawn_blocking join Err:
    /// Fatal).
    JoinFailed(String),
}

/// Converged result of a completed-piece job.
pub(super) struct PoolResult {
    pub(super) piece: u64,
    pub(super) bytes: u64,
    pub(super) verdict: PoolVerdict,
    /// Verify-phase duration in microseconds — the full
    /// `PieceJob::verify` span (assembly + main-format hash + hybrid
    /// cross-check). 0 on JoinFailed (honestly missing).
    pub(super) verify_us: u64,
    /// Write-phase observation at group granularity: `Some((duration us,
    /// write-call count))` rides only the FIRST Written verdict of each
    /// group — the observation granularity is the write call (a group
    /// write is one `write_batch`); other Written verdicts in the group
    /// carry None (duplicate observations would inflate the histogram
    /// count/sum). Single-job writes (fallback path) carry Some per
    /// piece, matching the old per-piece write_us granularity. All other
    /// verdicts never touched disk and are always None (honestly
    /// missing; the Verified phase is always None).
    pub(super) write: Option<(u64, u64)>,
    /// Per-block SHA-1 snapshot of a failed piece (smart_ban evidence;
    /// only on `HashMismatch` with a v1 job —
    /// [`PieceJob::failed_block_digests`] produced in the worker before
    /// the job's cell is destroyed. Always None otherwise).
    pub(super) failed_digests: Option<Arc<Vec<[u8; 20]>>>,
}

/// Dispatch group: write-path batching — the pipeline coalesces
/// adjacent-goff completed pieces in a batch into one `write_batch`
/// (`BH_WRITE_COALESCE`, default on); the fallback path degenerates to a
/// single-job group (the `pool.dispatch` convenience). Channel-capacity
/// semantics cannot carry over from the single-job era: a group lets one
/// slot carry multiple pieces (bound =
/// [`super::pipeline::PIECE_GROUP_MAX`], flushed when the pipeline hits
/// the cap), so the verdict channel capacity must be re-budgeted in
/// pieces — see the [`verdict_channel_capacity`] deadlock-exemption
/// argument.
pub(super) type PieceJobGroup = Vec<PieceJob>;

/// Verdict channel capacity (load-bearing for the deadlock exemption;
/// single source of truth, locked by
/// `verdict_capacity_covers_grouped_inflight_piece_bound`).
///
/// Rebuilt for groups: a channel slot can carry multiple jobs, so the
/// budget must count PIECES, not slots (the pre-group job-count formula
/// underestimated and could be overrun — the four-way send ring below).
///
/// 1. In-flight PIECE bound = pieces produced-but-not-drained by the
///    current batch (<= [`BUFFER_BATCH_BLOCKS`], including pending
///    in-batch groups — undispatched groups produce no verdict) + pool
///    resident group slots x pieces per slot: slots = worker queues
///    (queue/worker) + executing (1/worker) + dispatch channel in
///    flight (workers, stragglers of the previous batch) =
///    workers x (queue+2) slots, each <=
///    [`super::pipeline::PIECE_GROUP_MAX`] pieces (the pipeline
///    flushes at the cap — the structural bound).
/// 2. Each piece has at most 2 messages in flight (two-phase: early
///    Verified + final).
/// 3. Capacity >= 2 x the piece bound => worker return sends (early
///    `blocking_send` and the final send) never block => workers always
///    return to the take-group loop => the dispatch chain (queues ->
///    dispatcher -> dispatch channel) must keep draining => a pipeline
///    blocked in dispatch inside a batch (not polling verdicts) always
///    unblocks. Without it: pipeline dispatch blocks -> dispatcher
///    blocks on a full worker queue -> worker blocks returning a
///    verdict -> nobody drains (a four-way send ring).
///
/// Still bounded, not unbounded: memory = capacity x PoolResult (a
/// small fixed-size struct, ~80B; 192 entries in the default 4/2 shape
/// is ~16KB per face) — job bytes stay in the workers' hands.
fn verdict_channel_capacity(workers: usize, queue_per_worker: usize) -> usize {
    2 * (BUFFER_BATCH_BLOCKS + PIECE_GROUP_MAX * workers * (queue_per_worker + 2))
}

/// Verify/write worker pool (one per face; lifetime = the store pipeline
/// task).
pub(super) struct VerifyPool {
    /// Dispatch entry (pipeline side); dropping it triggers the shutdown
    /// order (module docs). `pub(super)` only so the terminal data-flush
    /// barrier (pipeline.rs tail) can destructure and drain: drop the
    /// dispatch side first, then drain verdicts to None = all in-flight
    /// writes have returned. The live loop never touches the field
    /// directly.
    pub(super) dispatch_tx: mpsc::Sender<PieceJobGroup>,
    /// Verdict receiver (same: the terminal drain consumes it in the
    /// pipeline.rs tail).
    pub(super) result_rx: mpsc::Receiver<PoolResult>,
}

impl VerifyPool {
    /// Build the pool: N workers (one blocking task per group, blocking
    /// work isolated) + one dispatcher (round-robin try_send; blocking
    /// send when all full = backpressure). Verdict channel capacity =
    /// [`verdict_channel_capacity`] (deadlock-exemption argument in that
    /// function's docs — budgeted in pieces, not job slots).
    pub(super) fn new(writer: SharedDiskWriter, cfg: VerifyPoolConfig) -> VerifyPool {
        let cfg = cfg.checked();
        let (dispatch_tx, dispatch_rx) = mpsc::channel::<PieceJobGroup>(cfg.workers);
        let (result_tx, result_rx) = mpsc::channel::<PoolResult>(verdict_channel_capacity(
            cfg.workers,
            cfg.queue_per_worker,
        ));
        let (worker_txs, worker_rxs): (Vec<_>, Vec<_>) = (0..cfg.workers)
            .map(|_| mpsc::channel::<PieceJobGroup>(cfg.queue_per_worker))
            .unzip();
        for (wid, rx) in worker_rxs.into_iter().enumerate() {
            let writer = writer.clone();
            let result_tx = result_tx.clone();
            tokio::spawn(run_worker(wid, rx, writer, result_tx));
        }
        tokio::spawn(run_dispatcher(dispatch_rx, worker_txs));
        VerifyPool {
            dispatch_tx,
            result_rx,
        }
    }

    /// Dispatch one completed-piece job (convenience = single-job group).
    /// Awaits here when the pool is full (= upstream backpressure).
    pub(super) async fn dispatch(&self, job: PieceJob) {
        self.dispatch_group(vec![job]).await;
    }

    /// Dispatch a completed-piece job group (write-path batching: the
    /// pipeline coalesces adjacent-goff pieces within a batch). Awaits
    /// here when the pool is full (= upstream backpressure).
    pub(super) async fn dispatch_group(&self, jobs: PieceJobGroup) {
        if jobs.is_empty() {
            return;
        }
        if self.dispatch_tx.send(jobs).await.is_err() {
            // Pool closed (pipeline shutdown path). Unreachable in the
            // live loop; jobs are dropped with the shutdown and the data
            // is recoverable via engine refetch (observable).
            tracing::warn!(
                target: "taiji::core::engine::store",
                "verify pool dispatch closed: piece job group dropped for re-fetch"
            );
        }
    }

    /// Clone of the dispatch entry's sender (test seam: the real pipeline
    /// dispatches and drains verdicts concurrently inside its select
    /// loop; test harnesses mirror that — dispatch from a separate task,
    /// drain in the main loop — so "dispatch all, then recv" does not
    /// deadlock on the pool's own backpressure, which is exactly the
    /// semantics under test).
    #[cfg(test)]
    pub(super) fn dispatch_sender(&self) -> mpsc::Sender<PieceJobGroup> {
        self.dispatch_tx.clone()
    }

    /// Receive the next job result (None once all workers have exited —
    /// reachable only on the pipeline shutdown path).
    pub(super) async fn recv(&mut self) -> Option<PoolResult> {
        self.result_rx.recv().await
    }
}

/// Worker main loop: take a group -> `spawn_blocking` (verify + write)
/// -> return verdicts. Returns never block by construction (verdict
/// channel capacity >= 2 x the in-flight PIECE bound — group budget, see
/// [`verdict_channel_capacity`]) — workers always get back to the
/// take-group loop, so the dispatch chain (queues -> dispatcher ->
/// dispatch channel) must keep draining. The hash-pass `Verified`-phase
/// message is returned early inside the job closure (`blocking_send` on
/// the blocking thread — a spawn_blocking thread is not an async
/// context, which is legal), while the final verdict (Written/failures)
/// is returned async by this loop.
async fn run_worker(
    wid: usize,
    mut rx: mpsc::Receiver<PieceJobGroup>,
    writer: SharedDiskWriter,
    result_tx: mpsc::Sender<PoolResult>,
) {
    loop {
        let Some(group) = rx.recv().await else {
            break;
        };
        let head = group
            .first()
            .map(|j| (j.piece(), j.bytes()))
            .unwrap_or((0, 0));
        let writer = writer.clone();
        let tx = result_tx.clone();
        // Group execution — one final verdict per job in the group (the
        // result-channel capacity argument counts pieces; a group does
        // not change the 2-messages-per-piece shape).
        let results =
            match tokio::task::spawn_blocking(move || run_piece_jobs(group, &writer, &tx)).await {
                Ok(results) => results,
                Err(e) => vec![PoolResult {
                    piece: head.0,
                    bytes: head.1,
                    verdict: PoolVerdict::JoinFailed(e.to_string()),
                    verify_us: 0,
                    write: None,
                    failed_digests: None,
                }],
            };
        debug!(target: "taiji::core::engine::store", worker = wid, piece = head.0,
            group = results.len(), "piece job group done");
        for result in results {
            if result_tx.send(result).await.is_err() {
                break; // pipeline already shut down
            }
        }
    }
}

/// Job-group execution (on the blocking thread): verify before write.
/// Each completed piece returns its verify duration and each write call
/// returns (duration, call count) — `Instant::now` sampling is
/// negligible after amortization; histogram feeds live in the pipeline's
/// verdict arm (workers hold no metrics handle).
///
/// Execution order (grouped; a single-job group = the old per-job
/// semantics):
/// 1. Verify the whole group (in-piece order): `Ok(true)` returns
///    [`PoolVerdict::Verified`] via `early` (early HAVE advertise —
///    libtorrent commit `7f691246a` passed->have; advertise does not
///    wait for the write); `Ok(false)` / `Err` = this piece's final
///    verdict (HashMismatch + smart_ban snapshot / Cross) and the GROUP
///    WRITE IS SKIPPED (verify-before-write discipline: any unverified
///    piece falls the whole group back to the old single-job write path,
///    writing passing pieces individually — exactly the pre-grouping
///    independent per-job writes).
/// 2. Group write (when the whole group passed): one `write_batch` lock
///    domain, [`PieceJob::write_group`] — adjacent piece cells coalesce
///    into contiguous segments written vectorized. Write failure maps by
///    the returned `first_failed`: `[..idx)` = Written (bytes on disk),
///    `[idx..)` = WriteFailed (refetch + rewrite is idempotent).
/// 3. Early channel closed (pipeline shutdown race) = the write has no
///    consumer: skip the group's write and converge on JoinFailed
///    finals (job bytes freed with the job; data recoverable via engine
///    refetch — the existing shutdown semantics, observable).
///
/// Write observation granularity: a group write is one call, so only the
/// group's FIRST Written verdict carries
/// `write = Some((group write duration us, calls issued))`; the rest
/// carry None (histogram count = write calls, the same granularity as
/// the single-job era's one-sample-per-write_to; duplicates would
/// inflate count/sum). Failed writes carry no sample (None — no
/// complete write call to observe).
///
/// On HashMismatch with a v1 job, the per-block SHA-1 snapshot is
/// produced before the cell is destroyed (smart_ban evidence — a failed
/// piece never lands, so this is the last point the data is in hand;
/// failure path only, zero hot-path cost).
fn run_piece_jobs(
    jobs: Vec<PieceJob>,
    writer: &SharedDiskWriter,
    early: &mpsc::Sender<PoolResult>,
) -> Vec<PoolResult> {
    let mut results: Vec<Option<PoolResult>> = (0..jobs.len()).map(|_| None).collect();
    let mut verify_us = vec![0u64; jobs.len()];
    let mut verified = Vec::new();
    for (i, job) in jobs.iter().enumerate() {
        let t0 = std::time::Instant::now();
        let verdict = job.verify();
        verify_us[i] = t0.elapsed().as_micros() as u64;
        match verdict {
            Ok(true) => {
                let early_res = PoolResult {
                    piece: job.piece(),
                    bytes: job.bytes(),
                    verdict: PoolVerdict::Verified,
                    verify_us: verify_us[i],
                    write: None,
                    failed_digests: None,
                };
                if early.blocking_send(early_res).is_err() {
                    // Early channel closed: skip the group's write (the
                    // consumer is gone); everything converges on
                    // JoinFailed finals (existing shutdown semantics).
                    for (k, job) in jobs.iter().enumerate() {
                        results[k].get_or_insert_with(|| PoolResult {
                            piece: job.piece(),
                            bytes: job.bytes(),
                            verdict: PoolVerdict::JoinFailed(
                                "verdict channel closed (write skipped)".into(),
                            ),
                            verify_us: verify_us[k],
                            write: None,
                            failed_digests: None,
                        });
                    }
                    return results.into_iter().flatten().collect();
                }
                verified.push(i);
            }
            Ok(false) => {
                let digests = job.failed_block_digests().map(Arc::new);
                results[i] = Some(PoolResult {
                    piece: job.piece(),
                    bytes: job.bytes(),
                    verdict: PoolVerdict::HashMismatch,
                    verify_us: verify_us[i],
                    write: None,
                    failed_digests: digests,
                });
            }
            Err(cross) => {
                results[i] = Some(PoolResult {
                    piece: job.piece(),
                    bytes: job.bytes(),
                    verdict: PoolVerdict::CrossInconsistent(cross),
                    verify_us: verify_us[i],
                    write: None,
                    failed_digests: None,
                });
            }
        }
    }
    if verified.is_empty() {
        return results.into_iter().flatten().collect();
    }
    // Write hot-path domain (unix concurrent read lock / exclusive write
    // lock on BH_PARALLEL_WRITES=0 or Windows). Whole group passed = one
    // lock acquisition covers the group write (adjacent pieces
    // coalesced, vectorized); any unverified piece = fall back to
    // per-piece writes (the existing path, one write_batch per piece —
    // the existing semantics when passing and failing pieces are
    // intermixed in a group).
    if verified.len() == jobs.len() {
        let tw = std::time::Instant::now();
        let refs: Vec<&PieceJob> = jobs.iter().collect();
        let written = writer.write_batch(|w| PieceJob::write_group(&refs, w));
        let write_us = tw.elapsed().as_micros() as u64;
        match written {
            Ok(calls) => {
                // Group write done: the first Written carries the
                // observation sample (granularity = write call, see this
                // function's docs); the rest carry None (duplicate
                // observations would inflate histogram count/sum).
                let total: u64 = calls.iter().sum::<usize>() as u64;
                let mut sample_used = false;
                for (i, job) in jobs.iter().enumerate() {
                    let write = if sample_used {
                        None
                    } else {
                        sample_used = true;
                        Some((write_us, total))
                    };
                    results[i].get_or_insert_with(|| PoolResult {
                        piece: job.piece(),
                        bytes: job.bytes(),
                        verdict: PoolVerdict::Written,
                        verify_us: verify_us[i],
                        write,
                        failed_digests: None,
                    });
                }
            }
            Err((e, first_failed)) => {
                // Group write failed: [..first_failed) bytes fully on
                // disk = Written (no complete sample to observe on the
                // failing face); [first_failed..] = WriteFailed (refetch
                // + rewrite is idempotent — same coordinates, same
                // bytes; see [`PieceJob::write_group`]).
                for (i, job) in jobs.iter().enumerate() {
                    let verdict = if i < first_failed {
                        PoolVerdict::Written
                    } else {
                        PoolVerdict::WriteFailed(clone_store_error(&e))
                    };
                    results[i].get_or_insert_with(|| PoolResult {
                        piece: job.piece(),
                        bytes: job.bytes(),
                        verdict,
                        verify_us: verify_us[i],
                        write: None,
                        failed_digests: None,
                    });
                }
            }
        }
    } else {
        // Mixed-group fallback: per-piece independent writes (the old
        // path, bit-for-bit), each piece with its own final verdict; the
        // write observation sample goes to the first successful piece
        // (count = write-call granularity).
        let mut sample_used = false;
        for &i in &verified {
            let t = std::time::Instant::now();
            let res = writer.write_batch(|w| jobs[i].write_to(w));
            let piece_write_us = t.elapsed().as_micros() as u64;
            match res {
                Ok(calls) => {
                    let write = if sample_used {
                        None
                    } else {
                        sample_used = true;
                        Some((piece_write_us, calls as u64))
                    };
                    results[i].get_or_insert_with(|| PoolResult {
                        piece: jobs[i].piece(),
                        bytes: jobs[i].bytes(),
                        verdict: PoolVerdict::Written,
                        verify_us: verify_us[i],
                        write,
                        failed_digests: None,
                    });
                }
                Err(e) => {
                    results[i].get_or_insert_with(|| PoolResult {
                        piece: jobs[i].piece(),
                        bytes: jobs[i].bytes(),
                        verdict: PoolVerdict::WriteFailed(e),
                        verify_us: verify_us[i],
                        write: None,
                        failed_digests: None,
                    });
                }
            }
        }
    }
    results.into_iter().flatten().collect()
}

/// StoreError has no Clone (io::Error source) — a group-write failure
/// must report the same error on multiple verdicts: the first job keeps
/// the original error, the rest carry a message-level rebuild
/// (`Internal` with the same text — equivalent content, no log loss;
/// only the WriteFailed arm consumes the error classification and
/// downstream does not distinguish Io/FileIo variants).
fn clone_store_error(e: &StoreError) -> StoreError {
    StoreError::Internal(e.to_string())
}

/// Dispatcher: round-robins worker queues with `try_send` starting from
/// the last placement (idle-first, approximately fair load spread); when
/// all are full, blocks on `send` to the next placement — backpressure
/// propagates through the pipeline's block input channel to the peer
/// read loop. When every worker queue is closed (pool shutdown order),
/// drains and exits.
async fn run_dispatcher(
    mut rx: mpsc::Receiver<PieceJobGroup>,
    txs: Vec<mpsc::Sender<PieceJobGroup>>,
) {
    let n = txs.len();
    if n == 0 {
        // workers >= 1 guaranteed by [`VerifyPoolConfig::checked`];
        // defensive drain.
        while let Some(_job) = rx.recv().await {}
        return;
    }
    let mut rr = 0usize;
    while let Some(job) = rx.recv().await {
        let mut pending = Some(job);
        let mut placed: Option<usize> = None;
        for k in 0..n {
            let i = (rr + k) % n;
            // Invariant: the job is held in `pending` at the top of every
            // placement attempt (Full hands it back; Ok/Closed leave the
            // loop before the next take).
            let Some(job) = pending.take() else {
                unreachable!("job not held before try_send (worker={i}, attempt={k})")
            };
            match txs[i].try_send(job) {
                Ok(()) => {
                    placed = Some(i);
                    break;
                }
                Err(TrySendError::Full(j)) => pending = Some(j),
                Err(TrySendError::Closed(_)) => return,
            }
        }
        let i = match placed {
            Some(i) => i,
            None => {
                // All full: block on the next placement (await = the
                // backpressure surface).
                let i = rr;
                // Invariant: every try_send above returned Full and handed
                // the job back, so `pending` still holds it here.
                let Some(job) = pending.take() else {
                    unreachable!("job not held before blocking send (worker={i})")
                };
                if txs[i].send(job).await.is_err() {
                    return;
                }
                i
            }
        };
        rr = (i + 1) % n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest as _, Sha1};
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use taiji_store::disk::DiskWriter;
    use taiji_store::hashpool::HashPool;
    use taiji_store::verified::VerifiedWriter;

    const PIECE: u32 = 16384;
    const BLK: usize = 4096;

    fn pattern(len: usize) -> Vec<u8> {
        const P: &[u8] = b"taiji-verify-pool-";
        P.iter().cycle().take(len).copied().collect()
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "taiji-vpool-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Write recorder (order-assertion surface): records the (offset,
    /// len) sequence of every write_at.
    struct RecordingWriter {
        inner: taiji_store::disk::FileDiskWriter,
        record: Arc<std::sync::Mutex<Vec<(u64, usize)>>>,
    }

    impl DiskWriter for RecordingWriter {
        fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            self.inner.open(path, read_only)
        }
        fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            self.inner.open_existing(path, read_only)
        }
        fn create(&mut self, path: &Path) -> Result<(), StoreError> {
            self.inner.create(path)
        }
        fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
            self.inner.truncate(len)
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            self.record
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((offset, data.len()));
            self.inner.write_at(offset, data)
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            self.inner.read_at(offset, buf)
        }
        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            self.inner.flush_os_buffers()
        }
        fn size(&self) -> Result<u64, StoreError> {
            self.inner.size()
        }
        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            self.inner.set_bypass_page_cache()
        }
    }

    /// Gate writer: every `gate_on`-th write_at blocks on an independent
    /// gate (handing the test a sender on each hit); others pass through
    /// — deterministic driving of concurrency/backpressure.
    struct GatedWriter {
        inner: taiji_store::disk::FileDiskWriter,
        gate_on: usize,
        hits: std::sync::atomic::AtomicUsize,
        entered: Arc<std::sync::atomic::AtomicUsize>,
        relay: Arc<std::sync::Mutex<std::sync::mpsc::Sender<std::sync::mpsc::Sender<()>>>>,
    }

    impl DiskWriter for GatedWriter {
        fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            self.inner.open(path, read_only)
        }
        fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            self.inner.open_existing(path, read_only)
        }
        fn create(&mut self, path: &Path) -> Result<(), StoreError> {
            self.inner.create(path)
        }
        fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
            self.inner.truncate(len)
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            let n = self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n % self.gate_on == 0 {
                self.entered
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (tx, rx) = std::sync::mpsc::channel();
                let send = self
                    .relay
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .send(tx);
                if send.is_err() {
                    // Test side is gone: pass through (no blocking).
                    return self.inner.write_at(offset, data);
                }
                let _ = rx.recv(); // gate
            }
            self.inner.write_at(offset, data)
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            self.inner.read_at(offset, buf)
        }
        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            self.inner.flush_os_buffers()
        }
        fn size(&self) -> Result<u64, StoreError> {
            self.inner.size()
        }
        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            self.inner.set_bypass_page_cache()
        }
    }

    /// v1 pool + single-file writer (table-driven harness).
    fn setup_v1(
        content: &[u8],
        tag: &str,
        wrap: impl FnOnce(taiji_store::disk::FileDiskWriter) -> Box<dyn DiskWriter>,
    ) -> (VerifiedWriter, PathBuf, TempDir) {
        let tmp = TempDir::new(tag);
        let path = tmp.0.join("blob.bin");
        let mut base = taiji_store::disk::FileDiskWriter::new();
        base.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let disk = wrap(base);
        let mut expected = Vec::new();
        for c in content.chunks(PIECE as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, PIECE, content.len() as u64);
        (VerifiedWriter::new(disk, pool, 1 << 20), path, tmp)
    }

    /// Table-driven body: `workers` workers, `pieces` pieces x 16KiB,
    /// in-piece blocks delivered in REVERSE order (forcing multiple
    /// cells), pieces rotated round-robin. Criteria: Verified->Written
    /// pairs per piece, on-disk content equality, ascending goff writes
    /// within each piece; write-continuity assertions split by
    /// SharedDiskWriter mode (parallel mode: cross-piece interleaving is
    /// legal / fallback mode: whole-piece contiguous runs — see the
    /// assertion).
    async fn table_case(workers: usize, pieces: usize, content: &[u8]) {
        let record = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut vw, path, _tmp) = setup_v1(content, "table", |base| {
            Box::new(RecordingWriter {
                inner: base,
                record: Arc::clone(&record),
            })
        });
        let cfg = VerifyPoolConfig {
            workers,
            queue_per_worker: 2,
        };
        let mut pool = VerifyPool::new(vw.writer_handle(), cfg);
        // Round-robin across pieces x reversed in-piece order:
        // out-of-order arrival and interleaved piece completion (job
        // production order != piece order).
        let mut jobs = Vec::new();
        for off in (0..4usize).rev() {
            for p in 0..pieces {
                let begin = (off * BLK) as u32;
                let goff = p as u64 * u64::from(PIECE) + u64::from(begin);
                let start = p * PIECE as usize + off * BLK;
                match vw
                    .push_block_pooled_at(
                        p as u64,
                        goff,
                        begin,
                        &bytes::Bytes::copy_from_slice(&content[start..start + BLK]),
                    )
                    .unwrap_or_else(|e| panic!("{e}"))
                {
                    PooledOutcome::Buffered { .. } => {}
                    PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(jobs.len(), pieces, "exactly one job per piece");
        // Dispatch and drain run concurrently (isomorphic to the real
        // pipeline's select shape, see `VerifyPool::dispatch_sender`) —
        // serial "dispatch all then recv" would deadlock on the pool's
        // own backpressure (dispatch blocks once the result channel
        // fills, which is exactly the semantics under test).
        let tx = pool.dispatch_sender();
        let dispatcher = tokio::spawn(async move {
            for job in jobs {
                if tx.send(vec![job]).await.is_err() {
                    break;
                }
            }
        });
        let mut verified = vec![false; pieces];
        // Two-phase verdict: per piece, Verified (hash-pass, write in
        // flight) then Written (persisted), paired in worker send order.
        for _ in 0..(2 * pieces) {
            let r = tokio::time::timeout(Duration::from_secs(10), pool.recv())
                .await
                .unwrap_or_else(|_| panic!("pool recv timeout (workers={workers})"));
            let r = r.unwrap_or_else(|| panic!("pool closed"));
            match r.verdict {
                PoolVerdict::Verified => {
                    assert!(
                        r.write.is_none(),
                        "the Verified phase touches no disk (honest missing data)"
                    );
                }
                PoolVerdict::Written => {
                    assert_eq!(r.bytes, u64::from(PIECE));
                    verified[r.piece as usize] = true;
                }
                PoolVerdict::HashMismatch
                | PoolVerdict::CrossInconsistent(_)
                | PoolVerdict::WriteFailed(_)
                | PoolVerdict::JoinFailed(_) => panic!(
                    "workers={workers} piece={} unexpected verdict (not Verified/Written)",
                    r.piece
                ),
            }
        }
        assert!(
            verified.iter().all(|&v| v),
            "all pieces complete Verified->Written"
        );
        // Order assertions (split by mode). Parallel-write surface (unix
        // default): writes from different jobs may interleave at piece
        // boundaries — invariants: each piece's write subsequence is
        // ascending in goff and each piece is written by exactly one job
        // (intra-piece order guaranteed by the single worker's program
        // order and unique job ownership; content equality is backed by
        // the read-back assertion). Fallback surface (BH_PARALLEL_WRITES=
        // 0 / Windows exclusive write lock): the old stronger assertions
        // additionally hold — each piece's writes are contiguous, exactly
        // one run (the whole piece is held mutually exclusive).
        let parallel = vw.writer_handle().parallel_writes();
        let rec = record.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            !rec.is_empty(),
            "the worker pool must write via the shared handle (workers={workers})"
        );
        let mut per_piece: std::collections::HashMap<usize, Vec<(u64, usize)>> =
            std::collections::HashMap::new();
        for &(off, len) in &rec {
            let piece_of = (off / u64::from(PIECE)) as usize;
            per_piece.entry(piece_of).or_default().push((off, len));
        }
        assert_eq!(
            per_piece.len(),
            pieces,
            "every piece must have a write record (workers={workers})"
        );
        for (piece_of, segs) in &per_piece {
            let mut prev_off = None;
            for &(off, len) in segs {
                assert_eq!(
                    (off / u64::from(PIECE)) as usize,
                    *piece_of,
                    "run crossing pieces (workers={workers})"
                );
                if let Some(p) = prev_off {
                    // Ascending goff (adjacent cells contiguous, i.e.
                    // off == prev_end, is also legal).
                    assert!(
                        off >= p,
                        "piece {piece_of} write order must be goff-ascending"
                    );
                }
                prev_off = Some(off + len as u64);
            }
        }
        if !parallel {
            let mut runs: Vec<Vec<(u64, usize)>> = vec![Vec::new()];
            for &(off, len) in &rec {
                let piece_of = (off / u64::from(PIECE)) as usize;
                match runs.last_mut() {
                    Some(last)
                        if !last.is_empty()
                            && (last[0].0 / u64::from(PIECE)) as usize == piece_of =>
                    {
                        last.push((off, len));
                    }
                    _ => runs.push(vec![(off, len)]),
                }
            }
            runs.remove(0); // sentinel
            let mut seen = std::collections::HashSet::new();
            for run in &runs {
                let piece_of = (run[0].0 / u64::from(PIECE)) as usize;
                assert!(
                    seen.insert(piece_of),
                    "fallback face: piece {piece_of} writes interleaved across jobs \
                     (whole-piece exclusive holding broken, workers={workers})"
                );
            }
            assert_eq!(
                runs.len(),
                pieces,
                "fallback face: exactly one contiguous write run per piece (workers={workers})"
            );
        }
        // On-disk content equality (TempDir drops at function end; the
        // read-back must happen here).
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, content, "workers={workers} on-disk content must match");
        dispatcher
            .await
            .unwrap_or_else(|e| panic!("dispatcher join: {e}"));
    }

    // Pooled-outcome type shared by the table driver and the tests
    // (exported from the store side).
    use taiji_store::verified::PooledOutcome;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_table_driven_order_and_content() {
        for workers in [1usize, 2, 4] {
            let pieces = 8;
            let content = pattern(pieces * PIECE as usize);
            table_case(workers, pieces, &content).await;
        }
    }

    /// The v2 path goes through the pool too: piece-root verification
    /// (job plan = V2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_covers_v2_piece_root_path() {
        let pieces = 3;
        let content = pattern(pieces * PIECE as usize);
        let tmp = TempDir::new("v2");
        let path = tmp.0.join("blob.bin");
        let mut base = taiji_store::disk::FileDiskWriter::new();
        base.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let roots: Vec<[u8; 32]> = content
            .chunks(PIECE as usize)
            .map(taiji_store::merkle::block_hash)
            .collect();
        let pool_hashes = HashPool::new_v2(roots, PIECE, content.len() as u64);
        let mut vw = VerifiedWriter::new(Box::new(base), pool_hashes, 1 << 20);
        let mut pool = VerifyPool::new(
            vw.writer_handle(),
            VerifyPoolConfig {
                workers: 2,
                queue_per_worker: 2,
            },
        );
        let mut jobs = Vec::new();
        for (p, chunk) in content.chunks(PIECE as usize).enumerate() {
            match vw
                .push_block_pooled_at(
                    p as u64,
                    (p * PIECE as usize) as u64,
                    0,
                    &bytes::Bytes::copy_from_slice(chunk),
                )
                .unwrap_or_else(|e| panic!("{e}"))
            {
                taiji_store::verified::PooledOutcome::PieceCompleted(job) => jobs.push(job),
                other => panic!("unexpected {other:?}"),
            }
        }
        for job in jobs {
            pool.dispatch(job).await;
        }
        // Two-phase verdicts drained in pairs (Verified -> Written).
        for p in 0..(2 * pieces) {
            let r = tokio::time::timeout(Duration::from_secs(10), pool.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout"))
                .unwrap_or_else(|| panic!("closed"));
            assert!(
                matches!(r.verdict, PoolVerdict::Verified | PoolVerdict::Written),
                "piece {p}"
            );
        }
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, content, "v2 pool path on-disk content matches");
    }

    /// Group-execution seam: `dispatch_group` with two adjacent jobs ->
    /// one group write ([`PieceJob::write_group`] — adjacent cells
    /// coalesced, vectorized). Criteria: Verified->Written pairs for both
    /// pieces (verify-before-write discipline — the group write being
    /// reached means the whole group verified), exactly one write sample
    /// (group-granularity observation, see [`PoolResult::write`]),
    /// whole-file content equality on disk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pool_group_dispatch_adjacent_pieces_written() {
        let pieces = 2usize;
        let content = pattern(pieces * PIECE as usize);
        let tmp = TempDir::new("grp");
        let path = tmp.0.join("blob.bin");
        let mut base = taiji_store::disk::FileDiskWriter::new();
        base.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool_hashes = HashPool::new_v1(&expected, PIECE, content.len() as u64);
        let mut vw = VerifiedWriter::new(Box::new(base), pool_hashes, 1 << 20);
        let mut pool = VerifyPool::new(
            vw.writer_handle(),
            VerifyPoolConfig {
                workers: 2,
                queue_per_worker: 2,
            },
        );
        // Push pieces 0 and 1 to completion in order (same-batch
        // completion is the pipeline's coalescing precondition).
        let mut jobs = Vec::new();
        for (p, chunk) in content.chunks(PIECE as usize).enumerate() {
            for (off, block) in chunk.chunks(BLK).enumerate() {
                match vw
                    .push_block_pooled_at(
                        p as u64,
                        (p * PIECE as usize + off * BLK) as u64,
                        (off * BLK) as u32,
                        &bytes::Bytes::copy_from_slice(block),
                    )
                    .unwrap_or_else(|e| panic!("{e}"))
                {
                    PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    PooledOutcome::Buffered { .. } => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(
            jobs.len(),
            2,
            "exactly one job per piece for the two pieces"
        );
        pool.dispatch_group(jobs).await;
        // Two-phase verdicts drained in pairs + exactly one group-write
        // sample.
        let mut verified = 0usize;
        let mut written = 0usize;
        let mut write_samples = 0usize;
        for _ in 0..(2 * pieces) {
            let r = tokio::time::timeout(Duration::from_secs(10), pool.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout"))
                .unwrap_or_else(|| panic!("closed"));
            match r.verdict {
                PoolVerdict::Verified => {
                    verified += 1;
                    assert!(r.write.is_none(), "the Verified phase touches no disk");
                }
                PoolVerdict::Written => {
                    written += 1;
                    if r.write.is_some() {
                        write_samples += 1;
                    }
                }
                other => panic!("unexpected verdict: {other:?}"),
            }
        }
        assert_eq!((verified, written), (2, 2), "two pieces, paired two phases");
        assert_eq!(
            write_samples, 1,
            "group write observed once for the whole group (write-call granularity)"
        );
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, content, "group-write on-disk content matches");
    }

    /// Mixed-group fallback: one piece in the group fails verification
    /// (bad bytes) -> that piece gets HashMismatch (nothing written —
    /// verify-before-write discipline); passing pieces fall back to the
    /// old single-job write path and are Written as usual; on disk = only
    /// the passing pieces' ranges.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pool_group_with_verify_failure_falls_back_per_piece() {
        let pieces = 2usize;
        let content = pattern(pieces * PIECE as usize);
        let tmp = TempDir::new("grp-fail");
        let path = tmp.0.join("blob.bin");
        let mut base = taiji_store::disk::FileDiskWriter::new();
        base.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool_hashes = HashPool::new_v1(&expected, PIECE, content.len() as u64);
        let mut vw = VerifiedWriter::new(Box::new(base), pool_hashes, 1 << 20);
        let mut pool = VerifyPool::new(
            vw.writer_handle(),
            VerifyPoolConfig {
                workers: 2,
                queue_per_worker: 2,
            },
        );
        // Piece 0 pushed to completion in order; piece 1 gets bad blocks
        // (same length, wrong bytes -> main hash must fail).
        let mut jobs = Vec::new();
        for (off, block) in content[..PIECE as usize].chunks(BLK).enumerate() {
            match vw
                .push_block_pooled_at(
                    0,
                    (off * BLK) as u64,
                    (off * BLK) as u32,
                    &bytes::Bytes::copy_from_slice(block),
                )
                .unwrap_or_else(|e| panic!("{e}"))
            {
                PooledOutcome::PieceCompleted(job) => jobs.push(job),
                PooledOutcome::Buffered { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        let mut bad = pattern(PIECE as usize);
        bad[0] ^= 0xFF;
        for (off, block) in bad.chunks(BLK).enumerate() {
            match vw
                .push_block_pooled_at(
                    1,
                    (PIECE as usize + off * BLK) as u64,
                    (off * BLK) as u32,
                    &bytes::Bytes::copy_from_slice(block),
                )
                .unwrap_or_else(|e| panic!("{e}"))
            {
                PooledOutcome::PieceCompleted(job) => jobs.push(job),
                PooledOutcome::Buffered { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(jobs.len(), 2);
        pool.dispatch_group(jobs).await;
        let mut verdicts: Vec<(u64, PoolVerdict)> = Vec::new();
        // Message count = piece 0's two phases (Verified+Written) + one
        // final for piece 1 (HashMismatch — a verification failure never
        // enters the early Verified phase, see run_piece_jobs order).
        for _ in 0..3 {
            let r = tokio::time::timeout(Duration::from_secs(10), pool.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout"))
                .unwrap_or_else(|| panic!("closed"));
            verdicts.push((r.piece, r.verdict));
        }
        assert!(
            verdicts
                .iter()
                .any(|(piece, v)| *piece == 0 && matches!(v, PoolVerdict::Verified)),
            "the passing piece's Verified phase present"
        );
        assert!(
            verdicts
                .iter()
                .any(|(piece, v)| *piece == 0 && matches!(v, PoolVerdict::Written)),
            "the passing piece Written (returned to the single-job write path)"
        );
        assert!(
            verdicts
                .iter()
                .any(|(piece, v)| *piece == 1 && matches!(v, PoolVerdict::HashMismatch)),
            "the bad piece HashMismatch (nothing written)"
        );
        assert!(
            !verdicts
                .iter()
                .any(|(piece, v)| *piece == 1 && matches!(v, PoolVerdict::Written)),
            "the bad piece must not be Written"
        );
        // On disk = only piece 0's range (piece 1 never touched disk; the
        // file does not extend past it).
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            got,
            content[..PIECE as usize],
            "only the passing piece's range lands on disk"
        );
    }

    /// Regression test for the verdict-capacity fix (bounded-channel
    /// discipline): capacity must be budgeted in PIECES to cover the
    /// grouped in-flight bound — a channel slot can carry
    /// [`PIECE_GROUP_MAX`] pieces, so the single-job-era slot-count
    /// formula `2x(32 + workersx(queue+1))` (= 88 in the default 4/2
    /// shape) is overrun by 16 in-flight groups (4 dispatch + 8 queue +
    /// 4 executing) at ~96 pieces once groups average >= 3 pieces — the
    /// four-way send-ring deadlock (pipeline blocked in dispatch without
    /// polling verdicts -> dispatcher blocked on a full queue -> worker
    /// blocked returning). The fix: capacity x[`PIECE_GROUP_MAX`] with
    /// slots counted as queue+2 (queue + executing + dispatch channel in
    /// flight), 192 in the default shape.
    #[test]
    fn verdict_capacity_covers_grouped_inflight_piece_bound() {
        // Invariant over the table shapes, against the single source of
        // truth ([`verdict_channel_capacity`]): capacity >= 2 x (pieces
        // produced-not-drained by the current batch + pool resident
        // slots x per-slot piece bound).
        for (workers, queue) in [(1usize, 1usize), (1, 2), (2, 2), (4, 2), (8, 4)] {
            let in_flight_pieces = BUFFER_BATCH_BLOCKS + PIECE_GROUP_MAX * workers * (queue + 2);
            let capacity = verdict_channel_capacity(workers, queue);
            assert!(
                capacity >= 2 * in_flight_pieces,
                "workers={workers} queue={queue}: capacity {capacity} must cover the \
                 in-flight piece bound {in_flight_pieces} x 2 messages (grouped budget)"
            );
        }
        // Default shape pinned (workers=4, queue=2): 2x(32 + 4x4x4) = 192
        // (the pre-fix formula gives 88).
        assert_eq!(verdict_channel_capacity(4, 2), 192);
        // workers=1 (the deadlock's minimal shape): 2x(32 + 4x1x4) = 96.
        assert_eq!(verdict_channel_capacity(1, 2), 96);
    }

    /// Backpressure: with workers=1 x queue depth 1 (+ dispatch channel
    /// 1) all occupied by gated writes, the 5th dispatch must await (the
    /// bounded surface — the pool-side form of upstream natural
    /// backpressure); after the gate opens everything converges.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_backpressure_blocks_when_full() {
        let tmp = TempDir::new("bp");
        let path = tmp.0.join("blob.bin");
        let mut base = taiji_store::disk::FileDiskWriter::new();
        base.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let (relay_tx, relay_rx) = std::sync::mpsc::channel::<std::sync::mpsc::Sender<()>>();
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let disk = Box::new(GatedWriter {
            inner: base,
            gate_on: 1, // gate every write (one cell, one write per piece)
            hits: std::sync::atomic::AtomicUsize::new(0),
            entered: Arc::clone(&entered),
            relay: Arc::new(std::sync::Mutex::new(relay_tx)),
        });
        let pieces = 8;
        let content = pattern(pieces * PIECE as usize);
        let mut expected = Vec::new();
        for c in content.chunks(PIECE as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool_hashes = HashPool::new_v1(&expected, PIECE, content.len() as u64);
        let mut vw = VerifiedWriter::new(disk, pool_hashes, 1 << 20);
        let mut pool = VerifyPool::new(
            vw.writer_handle(),
            VerifyPoolConfig {
                workers: 1,
                queue_per_worker: 1,
            },
        );
        let mut jobs = Vec::new();
        for p in 0..pieces {
            match vw
                .push_block_pooled_at(
                    p as u64,
                    (p * PIECE as usize) as u64,
                    0,
                    &bytes::Bytes::copy_from_slice(
                        &content[p * PIECE as usize..(p + 1) * PIECE as usize],
                    ),
                )
                .unwrap_or_else(|e| panic!("{e}"))
            {
                taiji_store::verified::PooledOutcome::PieceCompleted(job) => jobs.push(job),
                other => panic!("unexpected {other:?}"),
            }
        }
        // Deterministic order: dispatch job 1 first and wait for it to
        // actually enter the write (the worker has taken job 1 -> its
        // queue is empty); steady-state absorption is then exactly
        // worker-executing 1 + worker queue 1 + dispatcher-held 1 +
        // dispatch channel 1 = 4; the 5th must block in dispatch (pool
        // full — the pool-side form of upstream natural backpressure).
        let mut jobs = jobs.into_iter();
        pool.dispatch(jobs.next().unwrap_or_else(|| panic!("not enough jobs")))
            .await;
        let first_gate = relay_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| panic!("the first job never entered write: {e}"));
        for _ in 0..3 {
            let job = jobs.next().unwrap_or_else(|| panic!("not enough jobs"));
            pool.dispatch(job).await;
        }
        let fifth = jobs.next().unwrap_or_else(|| panic!("not enough jobs"));
        let dispatch5 = pool.dispatch(fifth);
        let blocked = tokio::time::timeout(Duration::from_millis(300), dispatch5).await;
        assert!(
            blocked.is_err(),
            "dispatch must backpressure-block once the pool is full (the 5th job \
             absorbed immediately = no-surface regression)"
        );
        // Open the gate -> a drainer thread releases the remaining gates
        // (the worker completes jobs 2-4 in order) -> everything
        // converges. Drain exactly 3 gates (jobs 2-4; the senders live
        // with vw/pool until test end — bounded drain rather than
        // waiting for channel close, which would deadlock on join).
        drop(first_gate);
        let drainer = std::thread::spawn(move || {
            for _ in 0..3 {
                match relay_rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(tx) => drop(tx),
                    Err(e) => panic!("gate drain: {e}"),
                }
            }
        });
        let mut done = 0;
        while done < 8 {
            let r = tokio::time::timeout(Duration::from_secs(10), pool.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout"))
                .unwrap_or_else(|| panic!("closed"));
            assert!(
                matches!(r.verdict, PoolVerdict::Verified | PoolVerdict::Written),
                "piece {}",
                r.piece
            );
            done += 1;
        }
        drainer
            .join()
            .unwrap_or_else(|_| panic!("gate drainer panicked"));
    }

    /// Deadlock regression (see the [`VerifyPool::new`]
    /// deadlock-exemption argument): dispatching many completed-piece
    /// jobs within one batch WITHOUT draining verdicts mid-way (the real
    /// pipeline's batch-loop shape) must not stall — the original verdict
    /// channel capacity = workers x queue_per_worker; once undrained
    /// verdicts filled the channel, workers blocked returning, the
    /// dispatcher blocked on full queues, and the pipeline blocked on the
    /// full dispatch channel (a four-way send ring). Under the old
    /// capacity this test hangs permanently from the
    /// `workersx(queue+1)+2`-th dispatched job. workers=1 x 12 pieces,
    /// batch-dispatch then drain; every verdict must arrive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_batch_dispatch_without_draining_never_deadlocks() {
        let pieces = 12usize;
        let content = pattern(pieces * PIECE as usize);
        let (mut vw, path, _tmp) = setup_v1(&content, "batch", |base| Box::new(base));
        let mut pool = VerifyPool::new(
            vw.writer_handle(),
            VerifyPoolConfig {
                workers: 1,
                queue_per_worker: 2,
            },
        );
        let mut jobs = Vec::new();
        for (p, chunk) in content.chunks(PIECE as usize).enumerate() {
            match vw
                .push_block_pooled_at(
                    p as u64,
                    (p * PIECE as usize) as u64,
                    0,
                    &bytes::Bytes::copy_from_slice(chunk),
                )
                .unwrap_or_else(|e| panic!("{e}"))
            {
                PooledOutcome::PieceCompleted(job) => jobs.push(job),
                other => panic!("unexpected {other:?}"),
            }
        }
        // Batch dispatch without draining (the pipeline's batch-loop
        // shape: zero recv while dispatching).
        let dispatch_all = async {
            for job in jobs {
                pool.dispatch(job).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(30), dispatch_all)
            .await
            .unwrap_or_else(|_| {
                panic!("in-batch consecutive dispatch hangs = verdict channel deadlock regression")
            });
        let mut verified = 0;
        tokio::time::timeout(Duration::from_secs(30), async {
            while verified < 2 * pieces {
                let r = pool.recv().await.unwrap_or_else(|| panic!("pool closed"));
                assert!(matches!(
                    r.verdict,
                    PoolVerdict::Verified | PoolVerdict::Written
                ));
                verified += 1;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("verdict drain hangs"));
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, content, "on-disk content matches after batch dispatch");
    }

    /// Slow-write injection: the advertise phase precedes write
    /// completion — `Verified` (hash-pass) arrives first, `Written` does
    /// not appear while the write gate stays closed (the observable
    /// window where serving/persistence/completion are bounded by what
    /// is on disk), and `Written` follows once the gate opens. Criterion
    /// = libtorrent commit `7f691246a` (advertise does not wait for the
    /// write; fixes pipeline idling).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pool_verified_verdict_arrives_before_write_completes() {
        let content = pattern(PIECE as usize);
        let (relay_tx, relay_rx) = std::sync::mpsc::channel::<std::sync::mpsc::Sender<()>>();
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (mut vw, _path, _tmp) = setup_v1(&content, "early-adv", |base| {
            Box::new(GatedWriter {
                inner: base,
                gate_on: 1, // gate every write (one cell, one write per piece)
                hits: std::sync::atomic::AtomicUsize::new(0),
                entered: Arc::clone(&entered),
                relay: Arc::new(std::sync::Mutex::new(relay_tx)),
            })
        });
        let mut pool = VerifyPool::new(
            vw.writer_handle(),
            VerifyPoolConfig {
                workers: 1,
                queue_per_worker: 1,
            },
        );
        // Single piece, single block -> one job.
        let job = match vw
            .push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&content))
            .unwrap_or_else(|e| panic!("{e}"))
        {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("unexpected {other:?}"),
        };
        pool.dispatch(job).await;
        // First verdict = Verified (hash-pass first, write outcome still
        // open).
        let first = tokio::time::timeout(Duration::from_secs(10), pool.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout"))
            .unwrap_or_else(|| panic!("closed"));
        assert!(
            matches!(first.verdict, PoolVerdict::Verified),
            "the first verdict must be Verified (the advertise phase goes first)"
        );
        assert_eq!(first.piece, 0);
        // Write gate stays closed (write in flight): Written must not
        // appear — under slow-disk injection the "advertised but not yet
        // on disk" window is observable (upload gating and completion
        // must not cross it).
        let not_yet = tokio::time::timeout(Duration::from_millis(300), pool.recv()).await;
        assert!(
            not_yet.is_err(),
            "write gate not open: Written should not appear (proof the advertise \
             phase precedes disk)"
        );
        // Gate opens (write completes): Written follows.
        let gate = relay_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| panic!("write never entered the gate: {e}"));
        drop(gate);
        let second = tokio::time::timeout(Duration::from_secs(10), pool.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout"))
            .unwrap_or_else(|| panic!("closed"));
        assert!(matches!(second.verdict, PoolVerdict::Written));
        assert_eq!(second.piece, 0);
        assert!(
            entered.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the write must really happen before Written (the GatedWriter entry count)"
        );
    }

    /// smart_ban evidence (worker side): on v1 hash failure the
    /// PoolResult carries a per-block SHA-1 snapshot (= per-block digests
    /// of the assembly buffer, one-to-one with the delivered bytes); the
    /// passing path is always None (zero hot-path cost).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pool_hash_mismatch_carries_failed_block_digests() {
        let pieces = 2usize;
        let content = pattern(pieces * PIECE as usize);
        // Expected hashes are built from good content; a bad block is
        // injected while delivering piece 1 -> that piece must fail.
        let tmp = TempDir::new("digest");
        let _path = tmp.0.join("blob.bin");
        let mut base = taiji_store::disk::FileDiskWriter::new();
        base.create(&_path)
            .unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool_hashes = HashPool::new_v1(&expected, PIECE, content.len() as u64);
        let mut vw = VerifiedWriter::new(Box::new(base), pool_hashes, 1 << 20);
        let mut pool = VerifyPool::new(
            vw.writer_handle(),
            VerifyPoolConfig {
                workers: 1,
                queue_per_worker: 2,
            },
        );
        for (p, chunk) in content.chunks(PIECE as usize).enumerate() {
            let mut block = chunk.to_vec();
            if p == 1 {
                // Bad block injection (block 0 of the piece) — the whole
                // piece must fail verification.
                block[0] ^= 0xFF;
            }
            for (off, blk) in block.chunks(BLK).enumerate() {
                match vw
                    .push_block_pooled_at(
                        p as u64,
                        (p * PIECE as usize + off * BLK) as u64,
                        (off * BLK) as u32,
                        &bytes::Bytes::copy_from_slice(blk),
                    )
                    .unwrap_or_else(|e| panic!("{e}"))
                {
                    PooledOutcome::PieceCompleted(job) => pool.dispatch(job).await,
                    PooledOutcome::Buffered { .. } => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        // Fold to per-piece outcomes: a passing piece produces two
        // messages (early Verified + final Written), a failing piece one
        // HashMismatch — converge on finals, ignore early Verified.
        let mut failed = std::collections::HashMap::new();
        let mut digests_of = std::collections::HashMap::new();
        let mut finals = 0;
        while finals < pieces {
            let r = tokio::time::timeout(Duration::from_secs(10), pool.recv())
                .await
                .unwrap_or_else(|_| panic!("timeout"))
                .unwrap_or_else(|| panic!("closed"));
            match r.verdict {
                PoolVerdict::Verified => continue, // early phase, not final
                PoolVerdict::Written => {
                    failed.insert(r.piece, false);
                    finals += 1;
                }
                PoolVerdict::HashMismatch => {
                    failed.insert(r.piece, true);
                    digests_of.insert(r.piece, r.failed_digests);
                    finals += 1;
                }
                other => panic!("unexpected terminal state {other:?}"),
            }
        }
        // Piece 0 (good): passes with no snapshot.
        assert!(!failed[&0], "piece 0 should pass");
        // Piece 1 (bad): HashMismatch + snapshot = per-block SHA-1 of the
        // bad assembly (block granularity = merkle::BLOCK_SIZE = 16KiB =
        // one block per piece; the test's BLK=4096 delivery is only
        // sub-block segmentation — the cache merges it into a single
        // cell).
        assert!(failed[&1], "piece 1 should fail");
        let digests = digests_of
            .get(&1)
            .and_then(|d| d.as_ref())
            .unwrap_or_else(|| panic!("a failed piece must have a snapshot"));
        assert_eq!(digests.len(), (PIECE as usize).div_ceil(16384));
        let mut bad = content[PIECE as usize..2 * PIECE as usize].to_vec();
        bad[0] ^= 0xFF;
        let want: [u8; 20] = Sha1::digest(&bad).into();
        assert_eq!(
            digests[0], want,
            "block digests must match the failed assembly bytes (smart_ban \
             evidence = the delivered bytes themselves)"
        );
    }

    /// Concurrency (verify-path parallel liveness): the same job set with
    /// workers=2 should be clearly faster than workers=1 (writes are
    /// naturally serialized through the shared handle, so the win is in
    /// [`PieceJob::verify`]'s assembly+hash CPU work; on unix the write
    /// half is concurrent too, so the bound is loose by design). 8MiB
    /// pieces x 4: serial ~4T, two workers ~2T; assert t(2) < 0.8 x t(1)
    /// (far looser than the theoretical 0.5, tolerant of environment
    /// jitter).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_verifies_in_parallel() {
        const BIG_PIECE: u32 = 8 * 1024 * 1024; // 8MiB (512 blocks/piece)
        async fn run(workers: usize) -> Duration {
            let pieces = 4usize;
            let content: Vec<u8> = (0..pieces * BIG_PIECE as usize)
                .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
                .collect();
            let tmp = TempDir::new("par");
            let path = tmp.0.join("blob.bin");
            let mut base = taiji_store::disk::FileDiskWriter::new();
            base.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
            let mut expected = Vec::new();
            for c in content.chunks(BIG_PIECE as usize) {
                expected.extend_from_slice(&Sha1::digest(c));
            }
            let pool_hashes = HashPool::new_v1(&expected, BIG_PIECE, content.len() as u64);
            // The cache must hold all in-flight pieces (8MiB x 4 exceeds
            // the default test limit).
            let mut vw = VerifiedWriter::new(Box::new(base), pool_hashes, 64 << 20);
            let mut pool = VerifyPool::new(
                vw.writer_handle(),
                VerifyPoolConfig {
                    workers,
                    queue_per_worker: 2,
                },
            );
            let mut jobs = Vec::new();
            for (p, chunk) in content.chunks(BIG_PIECE as usize).enumerate() {
                for (off, block) in chunk.chunks(16384).enumerate() {
                    match vw
                        .push_block_pooled_at(
                            p as u64,
                            (p * BIG_PIECE as usize + off * 16384) as u64,
                            (off * 16384) as u32,
                            &bytes::Bytes::copy_from_slice(block),
                        )
                        .unwrap_or_else(|e| panic!("{e}"))
                    {
                        taiji_store::verified::PooledOutcome::Buffered { .. } => {}
                        taiji_store::verified::PooledOutcome::PieceCompleted(job) => jobs.push(job),
                        other => panic!("unexpected {other:?}"),
                    }
                }
            }
            let tx = pool.dispatch_sender();
            let dispatcher = tokio::spawn(async move {
                for job in jobs {
                    if tx.send(vec![job]).await.is_err() {
                        break;
                    }
                }
            });
            let start = std::time::Instant::now();
            // Two-phase verdicts drained in pairs (Verified -> Written).
            for _ in 0..(2 * pieces) {
                let r = tokio::time::timeout(Duration::from_secs(120), pool.recv())
                    .await
                    .unwrap_or_else(|_| panic!("timeout (workers={workers})"))
                    .unwrap_or_else(|| panic!("closed"));
                assert!(matches!(
                    r.verdict,
                    PoolVerdict::Verified | PoolVerdict::Written
                ));
            }
            let elapsed = start.elapsed();
            dispatcher
                .await
                .unwrap_or_else(|e| panic!("dispatcher join: {e}"));
            elapsed
        }
        let t1 = run(1).await;
        let t2 = run(2).await;
        assert!(
            t2 < t1.mul_f64(0.8),
            "workers=2 ({t2:?}) must be clearly faster than workers=1 ({t1:?}) — \
             the verify-parallelism face is broken"
        );
    }
}
