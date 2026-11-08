//! URI-sequence scheduling/worker wiring — the runtime behind
//! [`crate::traits::SegmentPlan::UriSequence`] (the media spec's
//! download-line (b) face: the
//! vocabulary sat in the frozen plan enum with zero wiring; this
//! module is the 0.3 implementation item, living in the foundation
//! crate because a URI sequence is not a media-private concept —
//! any consumer handing segments as an ordered URI list rides it).
//!
//! Form (the no-range degraded precedent): **no
//! grid, no extent pre-split** — segments are taken in playlist
//! order, each fetched whole (one GET per URI, no offset resume
//! inside a segment; the checkpoint unit is the segment). Out-of-order
//! *completion* within a bounded lookahead window is what makes the
//! fetch parallel: up to `workers` segments in flight, results held
//! in a bounded reorder buffer and delivered strictly in index order
//! to the [`SequenceSink`] (the single-writer ordered-append shape —
//! the media staging layer's archive append is the first consumer).
//!
//! # Out-of-order write-back window (named constant anchor)
//!
//! The lookahead window anchor is a named constant pair
//! (the media spec's measured form: window =
//! concurrency × 8 segments ahead, single writer, 32MiB reorder
//! buffer cap):
//! - [`LOOKAHEAD_SEGMENTS_PER_WORKER`] × workers = the leading window
//!   (segments claimed but not yet delivered);
//! - [`LOOKAHEAD_BUFFER_CAP_BYTES`] = the window byte cap.
//!
//! **Anchor semantics of the 32MiB cap**: the cap governs ONE task-level shared
//! account — the reorder buffer **plus** the bytes held by in-flight
//! whole-body collectors ([`WindowBudget`]; pre-fix only the
//! completed-body half was counted, so in-flight collection ran under
//! independent per-fetch valves = `workers × 256MiB`, up to ~16GiB at
//! the concurrency domain 1..64). The claim gate backpressures
//! on the whole account; a write valve at `cap + one segment valve`
//! bounds residency for ANY worker count. The spec's "32MiB buffer cap"
//! anchor's semantics is thereby widened from "reorder buffer" to
//! "reorder buffer + in-flight collectors" — an errata suggestion upthrown
//! at implementation time (the anchor VALUE is unchanged).
//!
//! Per-segment accumulation cap (OOM valve on a whole-body fetch):
//! [`MAX_SEGMENT_BUFFER_BYTES`].
//!
//! Resume: the caller supplies a segment-done predicate (the persisted
//! `seg_bitmap` face); it must be a **prefix** (the delivery side is
//! ordered, so "completed" is always a prefix of the sequence). The
//! engine skips the done prefix and starts delivery at the first
//! incomplete index.
//!
//! AIMD applicability (the media spec: "the AIMD connection decision face applies"): the
//! connection decision face for a sequence is its worker count — the
//! caller bounds it with the per-task segment concurrency
//! (`--media-segment-concurrency`, domain 1..64); the engine carries
//! the per-segment failure budget the same way the extent path does
//! (`--max-tries` per-extent semantics: retry with backoff, then the
//! job fails).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::error::{HttpError, Result};
use crate::traits::{Extent, RequestCtx, SegId, SegmentSink, SegmentTransport};

/// Leading-window segments per worker (the media spec's
/// anchor: concurrency × 8 segments; the initial anchor — the
/// final value is revisited with field data, this named constant is
/// the single source).
pub const LOOKAHEAD_SEGMENTS_PER_WORKER: u64 = 8;

/// Reorder-buffer byte cap (32MiB, the media spec's anchor;
/// backpressure boundary — workers stop claiming beyond it).
pub const LOOKAHEAD_BUFFER_CAP_BYTES: u64 = 32 * 1024 * 1024;

/// Per-segment whole-body accumulation cap (the OOM valve on a single
/// segment's fetch; no spec number is pinned — segments are seconds
/// of media, 256MiB is two orders above the real shape and one order
/// below the stream cap, a sanity bound not a sizing hint).
pub const MAX_SEGMENT_BUFFER_BYTES: u64 = 256 * 1024 * 1024;

/// Parked-claimer repoll interval (the base worker's timed-park
/// precedent: bounded latency without wakeup-bookkeeping races).
const WORKER_PARK: Duration = Duration::from_millis(25);

/// EOF-delimited extent length sentinel (the unknown-length form the
/// body transport's cap face recognizes, [`crate::transport::stream_cap`]).
pub(crate) const EOF_SENTINEL_LEN: u64 = u64::MAX - 1;

/// Leading window for `workers` workers (concurrency ×
/// [`LOOKAHEAD_SEGMENTS_PER_WORKER`]; at least the worker count so
/// every worker can hold one segment).
pub fn lookahead_segments(workers: u32) -> u64 {
    u64::from(workers)
        .saturating_mul(LOOKAHEAD_SEGMENTS_PER_WORKER)
        .max(u64::from(workers))
}

/// Claim-bound verdict (pure): the highest exclusive index a worker
/// may claim next, given the delivery cursor and the window. Claims
/// are strictly `index < delivered + window`.
pub fn claim_bound(delivered: u64, window: u64) -> u64 {
    delivered.saturating_add(window)
}

/// Reorder-buffer admission verdict (pure): `true` while the buffered
/// byte total stays within the cap. A single segment that alone
/// exceeds the cap is not this face's rejection (its own valve is
/// [`MAX_SEGMENT_BUFFER_BYTES`]); the window cap backpressures
/// *accumulated* out-of-order bytes.
pub fn buffer_allows(buffered_bytes: u64, cap: u64) -> bool {
    buffered_bytes < cap
}

/// The task-level shared in-flight ledger: the reorder
/// buffer's bytes **plus** every in-flight collector's bytes in ONE
/// account. Two consumption faces:
///
/// * the **claim gate**: workers stop claiming new segments while the
///   account holds the cap (backpressure — pre-fix the gate saw only
///   the reorder half, so in-flight collection was unaccounted);
/// * the **write valve**: a collector write that would push the
///   account past `cap + one segment valve` fails the fetch (the
///   single-segment completion allowance — a body already streaming
///   must be able to finish past the cap, else every claim/write race
///   at the cap would kill the job; the liveness shape
///   depends on in-flight bodies completing). The failed fetch
///   re-enters the retry machinery; when the window drains (the
///   ordered delivery frees bytes) the retry succeeds — under a
///   forged big-segment list the retries may exhaust the budget,
///   which is the task-level rejection (the honest OOM defense).
///
/// The resident bound is `cap + one segment valve` for ANY worker
/// count — pre-fix each fetch carried an independent valve
/// (`workers × 256MiB`, up to ~16GiB at the concurrency domain
/// 1..64).
#[derive(Debug)]
struct WindowBudget {
    /// Reorder-buffer bytes (completed bodies the drain has not
    /// reached yet).
    buffered: AtomicU64,
    /// Bytes held by in-flight whole-body collectors.
    inflight: AtomicU64,
}

impl WindowBudget {
    fn new() -> Self {
        Self {
            buffered: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
        }
    }

    /// The whole account (both halves) — the claim gate's and the
    /// shared valve's input.
    fn total(&self) -> u64 {
        self.buffered
            .load(Ordering::Relaxed)
            .saturating_add(self.inflight.load(Ordering::Relaxed))
    }
}

/// Ordered-delivery sink: completed segments land here **strictly in
/// index order**, one call per segment, body included (the sink is
/// the single writer — the media staging layer's archive-append
/// consumer implements this face).
pub trait SequenceSink: Send + Sync {
    /// Deliver segment `index` (body bytes; the engine has already
    /// confirmed completion and the reorder buffer is drained in
    /// order — no cross-segment interleaving is possible).
    fn segment_complete(&self, index: u64, body: Bytes) -> BoxFuture<'_, Result<()>>;
}

/// Whole-body collector for one segment fetch: the transport streams
/// `write_at` chunks; the collector accumulates — bounded by its own
/// per-segment valve ([`MAX_SEGMENT_BUFFER_BYTES`] by default) and by
/// the shared [`WindowBudget`] write valve (`cap + one valve`, the
/// shared-account fix). The engine takes the body at fetch completion.
struct CollectingSink {
    buf: std::sync::Mutex<Vec<u8>>,
    len: AtomicU64,
    /// Per-segment accumulation valve (the OOM bound of ONE fetch).
    valve: u64,
    /// The shared window cap (the write valve allows `cap + valve`).
    cap: u64,
    window: Arc<WindowBudget>,
}

impl CollectingSink {
    fn new(valve: u64, cap: u64, window: Arc<WindowBudget>) -> Self {
        Self {
            buf: std::sync::Mutex::new(Vec::new()),
            len: AtomicU64::new(0),
            valve,
            cap,
            window,
        }
    }

    fn len(&self) -> u64 {
        self.len.load(Ordering::Relaxed)
    }

    fn take(&self) -> Vec<u8> {
        let body = std::mem::take(&mut *crate::lock(&self.buf));
        // The body leaves the in-flight half; `deliver` adds it to
        // the reorder half (the account total is unchanged by the
        // hand-off).
        let l = self.len.swap(0, Ordering::Relaxed);
        self.window.inflight.fetch_sub(l, Ordering::Relaxed);
        body
    }
}

impl Drop for CollectingSink {
    fn drop(&mut self) {
        // A failed/discarded fetch (valve rejection, cancelled fetch)
        // releases its bytes back to the account — a leaked
        // contribution would park the claim gate forever.
        let l = self.len.swap(0, Ordering::Relaxed);
        if l > 0 {
            self.window.inflight.fetch_sub(l, Ordering::Relaxed);
        }
    }
}

impl SegmentSink for CollectingSink {
    fn write_at(&self, _seg: SegId, _off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let n = bytes.len() as u64;
            if self.len().saturating_add(n) > self.valve {
                return Err(HttpError::Transport(format!(
                    "segment body exceeds the {}-byte accumulation valve",
                    self.valve
                )));
            }
            // Shared write valve: this write may not
            // push the whole window (reorder + collectors) past
            // `cap + one valve` — the completion allowance that keeps
            // in-flight bodies finishing past the cap (the
            // liveness shape). A rejection fails the fetch into the
            // retry machinery (task-level rejection once the budget
            // is spent — the honest OOM defense).
            if self.window.total().saturating_add(n) > self.cap.saturating_add(self.valve) {
                return Err(HttpError::Transport(format!(
                    "segment body would push the shared window past the \
                     {}-byte budget (in-flight backpressure)",
                    self.cap
                )));
            }
            let mut buf = crate::lock(&self.buf);
            buf.extend_from_slice(&bytes);
            self.len.fetch_add(n, Ordering::Relaxed);
            self.window.inflight.fetch_add(n, Ordering::Relaxed);
            Ok(())
        })
    }

    fn complete_block(&self, _block: u64) -> BoxFuture<'_, Result<()>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Sequence engine configuration. `workers` = the per-task segment
/// concurrency (the connection decision face; the 1..=64 domain is
/// validated by the options layer — the engine clamps only to >= 1
/// as defense). `max_tries` = the per-segment failure budget (the
/// per-extent `--max-tries` semantics carried over), `retry_wait`
/// the backoff between attempts.
#[derive(Clone, Copy, Debug)]
pub struct SequenceConfig {
    /// Worker count (segments concurrently in flight).
    pub workers: u32,
    /// Per-segment attempts before the job fails.
    pub max_tries: u32,
    /// Backoff between retries of a failed segment.
    pub retry_wait: Duration,
    /// Task-level shared window budget in bytes — the reorder buffer
    /// **plus** the bytes held by in-flight whole-body collectors
    /// (the spec's 32MiB anchor semantics cover in-flight
    /// collection; workers stop claiming while the window holds it).
    /// Default = [`LOOKAHEAD_BUFFER_CAP_BYTES`]; the regression
    /// injects a small scale.
    pub window_budget_bytes: u64,
    /// Per-segment whole-body accumulation valve (one fetch's own OOM
    /// bound). Default = [`MAX_SEGMENT_BUFFER_BYTES`]; the regression
    /// injects a small scale.
    pub segment_valve_bytes: u64,
}

impl Default for SequenceConfig {
    fn default() -> Self {
        Self {
            workers: 8,
            max_tries: 5,
            retry_wait: Duration::from_millis(250),
            window_budget_bytes: LOOKAHEAD_BUFFER_CAP_BYTES,
            segment_valve_bytes: MAX_SEGMENT_BUFFER_BYTES,
        }
    }
}

/// Transport factory: one whole-body transport per segment index (the
/// base's [`crate::transport::HttpBodyTransport`] is URI-bound — one
/// instance per URI; the factory keeps the engine free of protocol
/// knowledge, mirroring the scheduler-agnostic principle).
pub type TransportFor = Arc<dyn Fn(u64) -> Arc<dyn SegmentTransport> + Send + Sync>;

/// Job completion statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SequenceStats {
    /// Segments delivered to the sink this run (the resumed prefix is
    /// not re-delivered).
    pub delivered: u64,
    /// Segments skipped by the resume predicate.
    pub resumed: u64,
    /// Body bytes delivered this run.
    pub bytes: u64,
}

/// A re-queued segment with its remaining attempt budget.
#[derive(Clone, Copy, Debug)]
struct RetryEntry {
    index: u64,
    attempts_left: u32,
}

/// Shared engine state (worker-side faces are methods here so the
/// loop body stays protocol-only).
struct Engine {
    total: u64,
    /// Next index to claim (starts after the resumed prefix).
    next_claim: AtomicU64,
    /// Failed-segment retry queue (FIFO; each entry carries its own
    /// remaining attempt budget — the per-segment `--max-tries`
    /// semantics, not a per-worker consecutive counter).
    retry: std::sync::Mutex<std::collections::VecDeque<RetryEntry>>,
    /// Reorder buffer (index -> body), drained strictly in order.
    buffer: std::sync::Mutex<BTreeMap<u64, Bytes>>,
    /// The shared in-flight ledger (reorder + collectors; the claim
    /// gate and the shared valve consume it).
    window: Arc<WindowBudget>,
    /// Delivered cursor (next index the drain wants).
    delivered: AtomicU64,
    /// Delivered byte total (stats).
    bytes: AtomicU64,
    /// One-drainer-at-a-time lock (delivery order is the invariant;
    /// the lock serializes the drain, not the sink call granularity).
    drain_lock: tokio::sync::Mutex<()>,
    token: CancellationToken,
    sink: Arc<dyn SequenceSink>,
}

impl Engine {
    fn all_delivered(&self) -> bool {
        self.delivered.load(Ordering::Acquire) >= self.total
    }

    /// Whether the retry queue holds pending entries.
    ///
    /// Liveness anchor: `claim()` is the retry queue's
    /// ONLY drainer, so the worker-side backpressure gate must not
    /// park a worker while entries wait — with a full reorder buffer
    /// AND a pending retry, someone must still reach `claim()` or the
    /// delivered cursor (usually waiting exactly on the retried head)
    /// never advances and the job deadlocks. The gate consults this
    /// before parking.
    fn retry_nonempty(&self) -> bool {
        !crate::lock(&self.retry).is_empty()
    }

    /// Claim the next segment within the lookahead window (retries
    /// first, then fresh claims); the reply carries the segment's
    /// remaining attempt budget. `None` = park (window full, sequence
    /// exhausted, or cancelled). Parked claimers repoll on a timer
    /// (the base worker's timed-park precedent — no wakeup
    /// bookkeeping races).
    async fn claim(&self, window: u64, attempts: u32) -> Option<(u64, u32)> {
        loop {
            if self.token.is_cancelled() || self.all_delivered() {
                return None;
            }
            // Retry queue first (a retried index was claimed within
            // the window already; the buffer-cap backpressure still
            // applies at the worker level before this call).
            if let Some(entry) = crate::lock(&self.retry).pop_front() {
                return Some((entry.index, entry.attempts_left));
            }
            let delivered = self.delivered.load(Ordering::Acquire);
            let bound = claim_bound(delivered, window).min(self.total);
            let cur = self.next_claim.load(Ordering::Acquire);
            if cur >= bound {
                tokio::select! {
                    _ = self.token.cancelled() => return None,
                    _ = tokio::time::sleep(WORKER_PARK) => {}
                }
                continue;
            }
            if self
                .next_claim
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some((cur, attempts));
            }
        }
    }

    /// Re-queue a failed segment with one attempt consumed; returns
    /// the remaining budget (0 = exhausted, the caller fails the job).
    fn requeue(&self, index: u64, attempts_left: u32) {
        if attempts_left > 0 {
            crate::lock(&self.retry).push_back(RetryEntry {
                index,
                attempts_left,
            });
        }
    }

    /// Buffer a completed (possibly out-of-order) body and drain the
    /// in-order prefix to the sink. The drain lock plus the ordered
    /// cursor make delivery strictly sequential even with many
    /// workers buffering concurrently.
    async fn deliver(&self, index: u64, body: Bytes) -> Result<()> {
        let len = body.len() as u64;
        {
            let mut buf = crate::lock(&self.buffer);
            debug_assert!(
                !buf.contains_key(&index),
                "each index is claimed exactly once"
            );
            buf.insert(index, body);
            self.window.buffered.fetch_add(len, Ordering::Relaxed);
        }
        let _drain = self.drain_lock.lock().await;
        loop {
            let next = self.delivered.load(Ordering::Acquire);
            let body = {
                let mut buf = crate::lock(&self.buffer);
                match buf.remove(&next) {
                    Some(body) => body,
                    None => break,
                }
            };
            let blen = body.len() as u64;
            self.sink.segment_complete(next, body).await?;
            self.window.buffered.fetch_sub(blen, Ordering::Relaxed);
            self.bytes.fetch_add(blen, Ordering::Relaxed);
            self.delivered.store(next + 1, Ordering::Release);
            if self.all_delivered() {
                // Wake every remaining face (parked claimers included)
                // — the job is done.
                self.token.cancel();
            }
        }
        Ok(())
    }
}

/// Run a URI-sequence download to completion (the whole job; returns
/// when every segment is delivered or the failure budget is spent).
///
/// - `uris`: the ordered sequence ([`crate::traits::SegmentPlan::UriSequence`]
///   payload);
/// - `is_done`: resume prefix predicate (the persisted `seg_bitmap`
///   face; a `true` after the first `false` is ignored — resume
///   domains are prefixes by construction);
/// - `transport_for`: whole-body transport per index;
/// - `ctx`: per-source request context (the same face the extent
///   workers consume);
/// - `sink`: ordered-delivery sink.
pub async fn run_sequence(
    uris: Vec<String>,
    cfg: &SequenceConfig,
    is_done: &(dyn Fn(u64) -> bool + Send + Sync),
    transport_for: TransportFor,
    ctx: &RequestCtx,
    sink: Arc<dyn SequenceSink>,
) -> Result<SequenceStats> {
    let total = uris.len() as u64;
    let mut resumed = 0u64;
    let mut start = 0u64;
    while start < total && is_done(start) {
        start += 1;
        resumed += 1;
    }
    if start >= total {
        // Fully resumed: nothing to do.
        return Ok(SequenceStats {
            delivered: 0,
            resumed,
            bytes: 0,
        });
    }

    let window_budget = Arc::new(WindowBudget::new());
    let engine = Arc::new(Engine {
        total,
        next_claim: AtomicU64::new(start),
        retry: std::sync::Mutex::new(std::collections::VecDeque::new()),
        buffer: std::sync::Mutex::new(BTreeMap::new()),
        window: Arc::clone(&window_budget),
        delivered: AtomicU64::new(start),
        bytes: AtomicU64::new(0),
        drain_lock: tokio::sync::Mutex::new(()),
        token: CancellationToken::new(),
        sink,
    });
    let worker_cfg = WorkerCfg {
        window: lookahead_segments(cfg.workers.max(1)),
        max_tries: cfg.max_tries.max(1),
        retry_wait: cfg.retry_wait,
        segment_valve: cfg.segment_valve_bytes.max(1),
        budget_cap: cfg.window_budget_bytes.max(1),
    };
    let workers = cfg.workers.max(1);
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..workers {
        let engine = Arc::clone(&engine);
        let window_budget = Arc::clone(&window_budget);
        let transport_for = Arc::clone(&transport_for);
        let ctx = ctx.clone();
        set.spawn(async move {
            sequence_worker(engine, window_budget, &transport_for, &ctx, worker_cfg).await
        });
    }
    let mut first_err: Option<HttpError> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                engine.token.cancel();
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
            Err(e) => {
                engine.token.cancel();
                if first_err.is_none() {
                    first_err = Some(HttpError::Transport(format!("worker join: {e}")));
                }
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => {
            let delivered = engine.delivered.load(Ordering::Acquire);
            debug_assert_eq!(delivered, total, "no error path exits with work left");
            Ok(SequenceStats {
                delivered: delivered - start,
                resumed,
                bytes: engine.bytes.load(Ordering::Relaxed),
            })
        }
    }
}

/// The worker's static configuration (the claim window + the shared
/// budget pair + the retry shape — one copy per worker).
#[derive(Clone, Copy)]
struct WorkerCfg {
    /// Leading claim window (segments).
    window: u64,
    /// Per-segment attempts before the job fails.
    max_tries: u32,
    /// Backoff between retries of a failed segment.
    retry_wait: Duration,
    /// Per-segment whole-body valve.
    segment_valve: u64,
    /// The shared window budget cap (claim gate + write valve input).
    budget_cap: u64,
}

/// One sequence worker: claim (window-bounded) -> whole-body fetch ->
/// buffer + ordered deliver, with a per-segment retry budget.
async fn sequence_worker(
    engine: Arc<Engine>,
    window_budget: Arc<WindowBudget>,
    transport_for: &TransportFor,
    ctx: &RequestCtx,
    cfg: WorkerCfg,
) -> Result<()> {
    while !engine.token.is_cancelled() && !engine.all_delivered() {
        // Backpressure: the shared window budget's byte cap (reorder
        // buffer + in-flight collectors, the shared account)
        // parks the claimer until delivery frees bytes (the
        // segment-count half of the window is inside `claim`).
        // **Retry exemption**: a pending retry entry
        // must stay claimable — `claim()` is the retry queue's only
        // drainer, and the delivered cursor usually waits on exactly
        // the retried head; parking everyone here with a full window
        // is the deadlock the liveness regression pins. The claimed
        // retry is bounded by the queue's own length (entries already
        // inside the window), and the head's completion (valve-exempt
        // in the collectors) drains the window back under the cap.
        while !buffer_allows(window_budget.total(), cfg.budget_cap)
            && !engine.token.is_cancelled()
            && !engine.retry_nonempty()
        {
            tokio::select! {
                _ = engine.token.cancelled() => return Ok(()),
                _ = tokio::time::sleep(WORKER_PARK) => {}
            }
        }
        if engine.token.is_cancelled() {
            return Ok(());
        }
        let Some((index, attempts_left)) = engine.claim(cfg.window, cfg.max_tries).await else {
            return Ok(()); // cancelled or sequence exhausted
        };
        let transport = transport_for(index);
        let collector = CollectingSink::new(
            cfg.segment_valve,
            cfg.budget_cap,
            Arc::clone(&window_budget),
        );
        let extent = Extent {
            start: 0,
            len: EOF_SENTINEL_LEN,
        };
        match transport.fetch(&extent, ctx, &collector).await {
            Ok(()) => {
                let body = collector.take();
                engine.deliver(index, Bytes::from(body)).await?;
            }
            Err(e) => {
                let left = attempts_left.saturating_sub(1);
                if left == 0 {
                    // Budget exhausted for this segment: the job
                    // fails (the media layer maps the error onto the
                    // track's necessity role).
                    return Err(e);
                }
                engine.requeue(index, left);
                if !cfg.retry_wait.is_zero() {
                    tokio::select! {
                        _ = engine.token.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(cfg.retry_wait) => {}
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicU32;

    /// Scripted whole-body transport: body + artificial completion
    /// delay per index (to force reorder), optional scripted failure.
    struct ScriptTransport {
        body: Vec<u8>,
        delay: Duration,
        fail: bool,
    }

    impl SegmentTransport for ScriptTransport {
        fn fetch<'a>(
            &'a self,
            seg: &'a Extent,
            _ctx: &'a RequestCtx,
            sink: &'a dyn SegmentSink,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                if self.fail {
                    return Err(HttpError::UnexpectedResponse { status: 500 });
                }
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                let seg_id = SegId {
                    source: 0,
                    extent: 0,
                };
                let mut off = seg.start;
                for chunk in self.body.chunks(4) {
                    sink.write_at(seg_id, off, Bytes::copy_from_slice(chunk))
                        .await?;
                    off += chunk.len() as u64;
                }
                Ok(())
            })
        }
    }

    /// Recording sink: (index, body) pairs in arrival order.
    type RecBody = (u64, Vec<u8>);

    #[derive(Clone, Default)]
    struct RecSink(Arc<StdMutex<Vec<RecBody>>>);

    impl SequenceSink for RecSink {
        fn segment_complete(&self, index: u64, body: Bytes) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((index, body.to_vec()));
                Ok(())
            })
        }
    }

    fn factory(bodies: Vec<Vec<u8>>, delays: Vec<Duration>, fail_at: Option<u64>) -> TransportFor {
        Arc::new(move |index: u64| {
            let body = bodies.get(index as usize).cloned().unwrap_or_default();
            let delay = delays.get(index as usize).copied().unwrap_or_default();
            Arc::new(ScriptTransport {
                body,
                delay,
                fail: fail_at == Some(index),
            }) as Arc<dyn SegmentTransport>
        })
    }

    /// End-to-end shape: reversed completion order still delivers
    /// strictly in index order; bodies match.
    #[tokio::test]
    async fn out_of_order_completions_deliver_in_order() {
        let n = 10u64;
        let bodies: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![i as u8; (i as usize + 1) * 3])
            .collect();
        // Later indexes finish first (reverse delays).
        let delays: Vec<Duration> = (0..n)
            .map(|i| Duration::from_millis(30 * (n - i)))
            .collect();
        let sink = RecSink::default();
        let stats = run_sequence(
            (0..n)
                .map(|i| format!("http://example.test/s{i}"))
                .collect(),
            &SequenceConfig {
                workers: 4,
                max_tries: 2,
                retry_wait: Duration::ZERO,
                ..SequenceConfig::default()
            },
            &|_| false,
            factory(bodies.clone(), delays, None),
            &RequestCtx::default(),
            Arc::new(sink.clone()),
        )
        .await
        .unwrap_or_else(|e| panic!("run_sequence: {e}"));
        assert_eq!(stats.delivered, n);
        assert_eq!(stats.resumed, 0);
        assert_eq!(
            stats.bytes,
            bodies.iter().map(|b| b.len() as u64).sum::<u64>()
        );
        let got = sink.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            got.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            (0..n).collect::<Vec<_>>(),
            "delivery must be strictly in order"
        );
        for (i, body) in &got {
            assert_eq!(body, &bodies[*i as usize], "body of segment {i}");
        }
    }

    /// Resume prefix: the done prefix is neither fetched nor
    /// delivered; only the tail runs.
    #[tokio::test]
    async fn resume_prefix_skips_done_segments() {
        let fetched = Arc::new(StdMutex::new(Vec::<u64>::new()));
        let fetched_t = Arc::clone(&fetched);
        let tf: TransportFor = Arc::new(move |index: u64| {
            fetched_t
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(index);
            Arc::new(ScriptTransport {
                body: vec![index as u8; 8],
                delay: Duration::ZERO,
                fail: false,
            }) as Arc<dyn SegmentTransport>
        });
        let sink = RecSink::default();
        let stats = run_sequence(
            (0..6)
                .map(|i| format!("http://example.test/s{i}"))
                .collect(),
            &SequenceConfig {
                workers: 2,
                max_tries: 2,
                retry_wait: Duration::ZERO,
                ..SequenceConfig::default()
            },
            &|i| i < 4,
            tf,
            &RequestCtx::default(),
            Arc::new(sink.clone()),
        )
        .await
        .unwrap_or_else(|e| panic!("run_sequence: {e}"));
        assert_eq!(stats.resumed, 4);
        assert_eq!(stats.delivered, 2);
        let fetched = fetched.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(fetched, vec![4, 5], "only the tail is fetched");
        let got = sink.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(got.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![4, 5]);
    }

    /// Failure budget: a permanently failing segment errors the job
    /// (the error shape propagates verbatim — the media layer maps it
    /// onto the track's necessity role).
    #[tokio::test]
    async fn failing_segment_exhausts_budget_and_errors() {
        let err = run_sequence(
            vec![
                "http://example.test/a".into(),
                "http://example.test/b".into(),
            ],
            &SequenceConfig {
                workers: 1,
                max_tries: 3,
                retry_wait: Duration::ZERO,
                ..SequenceConfig::default()
            },
            &|_| false,
            factory(vec![vec![1; 4], vec![2; 4]], vec![], Some(1)),
            &RequestCtx::default(),
            Arc::new(RecSink::default()),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("must fail"));
        assert!(
            matches!(err, HttpError::UnexpectedResponse { status: 500 }),
            "error shape: {err:?}"
        );
    }

    /// Single-worker sequential form: no reorder machinery engaged,
    /// delivery order is trivially the claim order.
    #[tokio::test]
    async fn single_worker_sequential_form() {
        let bodies: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; 16]).collect();
        let sink = RecSink::default();
        run_sequence(
            (0..5)
                .map(|i| format!("http://example.test/s{i}"))
                .collect(),
            &SequenceConfig {
                workers: 1,
                max_tries: 2,
                retry_wait: Duration::ZERO,
                ..SequenceConfig::default()
            },
            &|_| false,
            factory(bodies.clone(), vec![], None),
            &RequestCtx::default(),
            Arc::new(sink.clone()),
        )
        .await
        .unwrap_or_else(|e| panic!("run_sequence: {e}"));
        let got = sink.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            got.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            (0..5).collect::<Vec<_>>()
        );
    }

    struct NoopSeqSink;

    impl SequenceSink for NoopSeqSink {
        fn segment_complete(&self, _index: u64, _body: Bytes) -> BoxFuture<'_, Result<()>> {
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// Named-anchor table: the window
    /// math and both caps pinned as constants — the
    /// "out-of-order write-back window constant anchor assertion"
    /// face (asserted here at the base; the
    /// media-layer copy asserts the same numbers through the public
    /// re-exports).
    #[test]
    fn lookahead_anchor_constants() {
        assert_eq!(LOOKAHEAD_SEGMENTS_PER_WORKER, 8);
        assert_eq!(LOOKAHEAD_BUFFER_CAP_BYTES, 32 * 1024 * 1024);
        assert_eq!(lookahead_segments(1), 8);
        assert_eq!(lookahead_segments(8), 64);
        assert_eq!(lookahead_segments(64), 512);
        // Worker-count floor (every worker holds one segment).
        assert!(lookahead_segments(16) >= 16);
        // Claim bound: strictly leading, never lagging.
        assert_eq!(claim_bound(0, 64), 64);
        assert_eq!(claim_bound(10, 8), 18);
        // Buffer admission: closed at the cap.
        assert!(buffer_allows(0, 32 * 1024 * 1024));
        assert!(!buffer_allows(32 * 1024 * 1024, 32 * 1024 * 1024));
        // Config defaults = the named anchors (the shared-window
        // budget consumes the same anchor the reorder cap did).
        let cfg = SequenceConfig::default();
        assert_eq!(cfg.window_budget_bytes, LOOKAHEAD_BUFFER_CAP_BYTES);
        assert_eq!(cfg.segment_valve_bytes, MAX_SEGMENT_BUFFER_BYTES);
    }

    /// Collecting-sink valve faces (small injected anchors, the same
    /// expressions the production constants feed):
    /// 1. the per-segment valve refuses a write that crosses it;
    /// 2. the shared write valve refuses a write that would push the
    /// account past `cap + one valve`;
    /// 3. a write landing **inside** the completion allowance (at the
    /// cap, under cap + valve) passes — in-flight bodies must be
    /// able to finish past the cap (the liveness shape);
    /// 4. Drop/take release the in-flight bytes back to the account.
    #[tokio::test]
    async fn collector_valve_and_shared_window_faces() {
        let seg_id = SegId {
            source: 0,
            extent: 0,
        };
        // (1) Per-segment valve (injected small: a 300KiB write
        // against a 256KiB valve).
        let window = Arc::new(WindowBudget::new());
        let collector = CollectingSink::new(256 * 1024, 1024 * 1024, Arc::clone(&window));
        let sink: &dyn SegmentSink = &collector;
        let res = sink
            .write_at(seg_id, 0, Bytes::from(vec![0u8; 300 * 1024]))
            .await;
        assert!(
            res.is_err(),
            "the per-segment valve refuses the oversize write"
        );

        // (2) Shared valve: the account already holds cap + valve
        // bytes; any further write is refused.
        let window = Arc::new(WindowBudget::new());
        window
            .buffered
            .store(1024 * 1024 + 256 * 1024, Ordering::Relaxed);
        let collector = CollectingSink::new(256 * 1024, 1024 * 1024, Arc::clone(&window));
        let sink: &dyn SegmentSink = &collector;
        let res = sink.write_at(seg_id, 0, Bytes::from(vec![0u8; 1024])).await;
        assert!(res.is_err(), "a write past cap + valve is refused");

        // (3) Completion allowance: the account at the cap, a write
        // inside the one-valve allowance passes.
        let window = Arc::new(WindowBudget::new());
        window.buffered.store(1024 * 1024, Ordering::Relaxed);
        let collector = CollectingSink::new(256 * 1024, 1024 * 1024, Arc::clone(&window));
        let sink: &dyn SegmentSink = &collector;
        let res = sink.write_at(seg_id, 0, Bytes::from(vec![0u8; 1024])).await;
        assert!(
            res.is_ok(),
            "an in-flight write inside the completion allowance passes"
        );

        // (4) take/Drop release: after take, the account's in-flight
        // half is back to zero (and a Drop alone releases too).
        let window = Arc::new(WindowBudget::new());
        let collector = CollectingSink::new(256 * 1024, 1024 * 1024, Arc::clone(&window));
        let sink: &dyn SegmentSink = &collector;
        sink.write_at(seg_id, 0, Bytes::from(vec![0u8; 4096]))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        assert_eq!(window.inflight.load(Ordering::Relaxed), 4096);
        let taken = collector.take();
        assert_eq!(taken.len(), 4096);
        assert_eq!(
            window.inflight.load(Ordering::Relaxed),
            0,
            "take hands the bytes out of the in-flight half"
        );
        sink.write_at(seg_id, 0, Bytes::from(vec![0u8; 2048]))
            .await
            .unwrap_or_else(|e| panic!("second write: {e}"));
        drop(collector);
        assert_eq!(
            window.inflight.load(Ordering::Relaxed),
            0,
            "drop releases a discarded fetch's bytes"
        );
    }

    /// Empty sequence: immediate Ok, zero delivery.
    #[tokio::test]
    async fn empty_sequence_is_noop() {
        let stats = run_sequence(
            Vec::new(),
            &SequenceConfig::default(),
            &|_| false,
            factory(vec![], vec![], None),
            &RequestCtx::default(),
            Arc::new(NoopSeqSink),
        )
        .await
        .unwrap_or_else(|e| panic!("empty run: {e}"));
        assert_eq!(stats, SequenceStats::default());
    }

    /// Fully-resumed sequence: zero delivery, resume count = total.
    #[tokio::test]
    async fn fully_resumed_sequence_is_noop() {
        let stats = run_sequence(
            vec!["http://example.test/a".into()],
            &SequenceConfig::default(),
            &|_| true,
            factory(vec![vec![1; 4]], vec![], None),
            &RequestCtx::default(),
            Arc::new(NoopSeqSink),
        )
        .await
        .unwrap_or_else(|e| panic!("resumed run: {e}"));
        assert_eq!(stats.resumed, 1);
        assert_eq!(stats.delivered, 0);
    }

    /// Liveness regression (the PoC finding): the
    /// head segment failing once into the retry queue while the
    /// reorder buffer fills past the 32MiB cap must NOT deadlock.
    ///
    /// Pre-fix shape: every worker parks in the backpressure loop
    /// BEFORE `claim()`, but the retry queue is only drained INSIDE
    /// `claim()` — the head never re-runs, `delivered` never advances,
    /// the buffer never drains, and `run_sequence` never returns (the
    /// PoC recorded "DEADLOCK CONFIRMED" within 20 s). The invariant
    /// under test: with a pending retry and a full buffer the system
    /// still makes progress (the retry entry is claimable).
    ///
    /// Parameters replicate the PoC exactly: 32 segments (window =
    /// 4 workers × 8), head first-attempt sleeps 500 ms then 503s,
    /// the other 31 bodies 3 MiB each (11 completions = 33MiB > the
    /// 32MiB cap while the head sits in retry), 4 workers, 3 tries,
    /// 10 ms backoff.
    #[tokio::test]
    async fn backpressure_with_pending_retry_stays_live() {
        struct FlakyHead {
            calls: AtomicU32,
        }
        impl SegmentTransport for FlakyHead {
            fn fetch<'a>(
                &'a self,
                _seg: &'a Extent,
                _ctx: &'a RequestCtx,
                sink: &'a dyn SegmentSink,
            ) -> BoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        // Slow-then-fail: the window's other segments
                        // complete and cross the buffer cap while this
                        // one is still in flight.
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        return Err(HttpError::UnexpectedResponse { status: 503 });
                    }
                    let id = SegId {
                        source: 0,
                        extent: 0,
                    };
                    sink.write_at(id, 0, Bytes::from_static(b"head")).await?;
                    Ok(())
                })
            }
        }
        struct OkBig(Vec<u8>);
        impl SegmentTransport for OkBig {
            fn fetch<'a>(
                &'a self,
                _seg: &'a Extent,
                _ctx: &'a RequestCtx,
                sink: &'a dyn SegmentSink,
            ) -> BoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    let id = SegId {
                        source: 0,
                        extent: 0,
                    };
                    sink.write_at(id, 0, Bytes::copy_from_slice(&self.0))
                        .await?;
                    Ok(())
                })
            }
        }
        let n = 32u64;
        let seg_bytes = 3 * 1024 * 1024usize;
        let flaky = Arc::new(FlakyHead {
            calls: AtomicU32::new(0),
        });
        let big = Arc::new(OkBig(vec![2u8; seg_bytes]));
        let head = Arc::clone(&flaky);
        let tf: TransportFor = Arc::new(move |index: u64| {
            if index == 0 {
                head.clone() as Arc<dyn SegmentTransport>
            } else {
                big.clone() as Arc<dyn SegmentTransport>
            }
        });
        let cfg = SequenceConfig {
            workers: 4,
            max_tries: 3,
            retry_wait: Duration::from_millis(10),
            ..SequenceConfig::default()
        };
        let ctx = RequestCtx::default();
        let run = run_sequence(
            (0..n).map(|i| format!("http://x.test/s{i}")).collect(),
            &cfg,
            &|_| false,
            tf,
            &ctx,
            Arc::new(NoopSeqSink),
        );
        // The PoC's own bound: the pre-fix engine never returned
        // within 20 s; a live engine finishes in ~1 s (the head's
        // 500 ms delay dominates).
        match tokio::time::timeout(Duration::from_secs(20), run).await {
            Ok(Ok(stats)) => assert_eq!(stats.delivered, n, "the whole window delivered"),
            Ok(Err(e)) => panic!("errored (still live, but the scripted run must succeed): {e}"),
            Err(_) => panic!(
                "DEADLOCK CONFIRMED: run_sequence did not return within 20 s \
                 (backpressure gate vs the retry-queue drainer)"
            ),
        }
    }

    /// The out-of-order window's in-flight memory is
    /// bounded by ONE task-level shared budget (the reorder buffer +
    /// every in-flight collector's bytes), not by independent
    /// per-fetch valves. Injected small anchors (1MiB window /
    /// 256KiB valve) with 8 workers x 200KiB bodies and staggered
    /// first writes (the adversarial trickle: every worker claims
    /// before any bytes lands — the shape that pre-fix let each
    /// fetch fill its own independent valve): the observed concurrent
    /// residency must stay within budget + one valve; pre-fix it
    /// reached the full 8 x 200KiB. The job itself must still
    /// complete (the head's completion drains the window).
    #[tokio::test]
    async fn shared_window_budget_bounds_inflight_residency() {
        /// Transport-side residency probe: every live fetch registers
        /// its written-so-far total; the high-water mark = the max
        /// over time of the sum (exactly the collector-held bytes the
        /// budget accounts).
        struct Probe {
            id: u64,
            live: Arc<StdMutex<std::collections::BTreeMap<u64, u64>>>,
            high_water: Arc<AtomicU64>,
        }
        impl Probe {
            fn note(&self, id: u64, total: u64) {
                let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
                live.insert(id, total);
                let sum: u64 = live.values().sum();
                self.high_water.fetch_max(sum, Ordering::SeqCst);
            }
            fn retire(&self, id: u64) {
                let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
                live.remove(&id);
                let sum: u64 = live.values().sum();
                self.high_water.fetch_max(sum, Ordering::SeqCst);
            }
        }
        struct BudgetedTransport {
            body: Vec<u8>,
            first_write_delay: Duration,
            id: u64,
            probe: Arc<Probe>,
        }
        impl SegmentTransport for BudgetedTransport {
            fn fetch<'a>(
                &'a self,
                _seg: &'a Extent,
                _ctx: &'a RequestCtx,
                sink: &'a dyn SegmentSink,
            ) -> BoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    // Uniform pre-write park: every worker claims
                    // before any bytes land (the adversarial trickle).
                    if !self.first_write_delay.is_zero() {
                        tokio::time::sleep(self.first_write_delay).await;
                    }
                    let seg_id = SegId {
                        source: 0,
                        extent: 0,
                    };
                    let mut written = 0u64;
                    for chunk in self.body.chunks(16 * 1024) {
                        // Yield between chunks so the in-flight
                        // fetches genuinely interleave (a ready
                        // write_at future never yields on its own —
                        // without this the fetches serialize and the
                        // residency probe sees nothing).
                        tokio::task::yield_now().await;
                        if let Err(e) = sink
                            .write_at(seg_id, 0, Bytes::copy_from_slice(chunk))
                            .await
                        {
                            // Deregister on the valve rejection too
                            // (the collector is dropped on Err).
                            self.probe.retire(self.id);
                            return Err(e);
                        }
                        written += chunk.len() as u64;
                        self.probe.note(self.id, written);
                    }
                    self.probe.retire(self.id);
                    Ok(())
                })
            }
        }
        let live: Arc<StdMutex<std::collections::BTreeMap<u64, u64>>> =
            Arc::new(StdMutex::new(std::collections::BTreeMap::new()));
        let high_water = Arc::new(AtomicU64::new(0));
        let budget = 1024 * 1024u64;
        let valve = 256 * 1024u64;
        let body = vec![7u8; 200 * 1024];
        let live_c = Arc::clone(&live);
        let hw_c = Arc::clone(&high_water);
        let id_c = Arc::new(AtomicU64::new(0));
        let tf: TransportFor = Arc::new(move |index: u64| {
            let probe = Arc::new(Probe {
                id: id_c.fetch_add(1, Ordering::SeqCst),
                live: Arc::clone(&live_c),
                high_water: Arc::clone(&hw_c),
            });
            Arc::new(BudgetedTransport {
                body: body.clone(),
                // The head (index 0) starts earliest — the ordered
                // drain leads the fill, so the run completes while
                // the valve still rejects the tail's overflow writes
                // (the retry/drain cycle then lands them).
                first_write_delay: Duration::from_millis(20 + index * 5),
                id: probe.id,
                probe,
            }) as Arc<dyn SegmentTransport>
        });
        let stats = run_sequence(
            (0..8u64).map(|i| format!("http://x.test/s{i}")).collect(),
            &SequenceConfig {
                workers: 8,
                max_tries: 64,
                retry_wait: Duration::from_millis(5),
                window_budget_bytes: budget,
                segment_valve_bytes: valve,
            },
            &|_| false,
            tf,
            &RequestCtx::default(),
            Arc::new(NoopSeqSink),
        )
        .await
        .unwrap_or_else(|e| panic!("the budgeted run completes: {e}"));
        assert_eq!(stats.delivered, 8, "every segment lands");
        let hw = high_water.load(Ordering::SeqCst);
        assert!(
            hw <= budget + valve,
            "observed in-flight residency {hw} must stay within \
             budget {budget} + one segment valve {valve}"
        );
    }
}
