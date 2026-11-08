//! ExtentCoordinator actor: one per HTTP task, the single serial decision
//! point for runtime extent allocation and block-completion bookkeeping.
//!
//! Mechanism: workers talk to the actor over a bounded mpsc channel
//! (acquire / block-done / abandon / heartbeat / steal request / AIMD
//! samples). Block completion is first-report-wins, later reports are
//! dropped, and the first report is the only path that advances the
//! persisted bitmap via [`SegmentSink::complete_block`]. Leases are
//! byte-granular, so a block completes when its per-block written-byte
//! watermark fills, not when one worker crosses the block boundary.
//! Stealing is granted only on byte-level heartbeat stall evidence
//! re-verified at this single point. Dynamic mode adds EWMA-weighted
//! share arbitration, source demotion/removal with failover, and an AIMD
//! connection controller; static mode assembles none of these.
//!
//! Upstream anchor mapping: docs/design/http.md
//!
//! Hard invariants:
//! - block completion and steal grants are decided only at this single
//!   serial point, in message FIFO order;
//! - the persisted bitmap is written only through the sink; a sink
//!   failure is a task-level fault that ends the actor (handles then get
//!   `Err`, never a hang);
//! - channel capacity = 2 x workers; a full queue backpressures the
//!   worker call sites (no unbounded queues);
//! - no `Mutex`/`RwLock` crosses an `await`: grid and queue state are
//!   actor-exclusive (message passing is the synchronization point);
//! - a steal race can only waste bandwidth (at most one sub-block of
//!   write overshoot per steal), never corrupt already-written bytes.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::aimd::{AimdBook, AimdConfig, CongestionKind};
use crate::error::HttpError;
use crate::grid::BlockGrid;
use crate::limiter::RateSampleReporter;
use crate::rate::SourceRateBook;
use crate::scheduler::{self, GuidedPlan, StaticPlan};
use crate::stall::StallWatch;
use crate::traits::{Extent, SegId, SegmentSink};

/// Byte-level heartbeat cadence ("workers report every second"): the
/// driver-side write path reports on this period. The stall window
/// (`--http-stall-window`, default 15s) should be a multiple of this
/// period (validated in the options layer) so a window always contains
/// at least one growth opportunity.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// worker -> coordinator message surface (only messages and `Bytes` cross the actor boundary).
pub enum CoordinatorMsg {
    /// Claim the next extent (`source` = task-local source index, bookkeeping domain).
    Acquire {
        /// Task-local source index.
        source: u32,
        /// Allocation reply (`None` = nothing to allocate; the worker closes out).
        reply: oneshot::Sender<Result<Option<Allocation>, HttpError>>,
    },
    /// Block completion report (decision face: first
    /// report wins, later ones dropped — see module docs).
    BlockDone {
        /// Completed block number (block-grid index).
        block: u64,
    },
    /// Abandon an extent (failure recovery): the unfinished extent goes back
    /// to the scheduler for reuse (static: queue-head reinsert keeping the
    /// original sequence number; dynamic: per-block pool return with the
    /// grid decision face as the source of truth — already-recorded blocks
    /// are covered by the idempotent decision face). Under multi-source
    /// assembly this message doubles as the source's extent-failure record:
    /// an abandon by the current owner counts one windowed failure (demote/
    /// remove thresholds in [`crate::sources`]); an abandon by a stale owner
    /// after a steal does not count — that is the tail of a write-ownership
    /// transfer, not a transport failure.
    Abandon {
        /// The abandoned allocation (returned as-is).
        allocation: Allocation,
    },
    /// Deferred extent abandon (Retry-After steal-gap close-out): the
    /// abandon of a `RetryAfter`-class failure carries the service-window
    /// delay `defer` — the extent is held with `not_before = now + defer`
    /// (returned to the pool on expiry). Claim/allocation queries filter it
    /// while held (the pool contains no unexpired extent), so other workers
    /// cannot claim and re-send while the failed worker backs off — the
    /// server's wait applies only to the failed worker (the steal gap). All
    /// other semantics (source-failure bookkeeping / steal-watermark
    /// recovery / empty-extent defense) are shared with
    /// [`CoordinatorMsg::Abandon`]; other error classes carry no delay (use
    /// the plain message, preserving current behavior). Expiry uses
    /// `Instant` (monotonic clock).
    AbandonDeferred {
        /// The abandoned allocation (returned as-is — pooled on expiry).
        allocation: Allocation,
        /// Service-window delay (= the failure path's clamped Retry-After; the
        /// expiry pool return is driven by the actor's message scan).
        defer: Duration,
    },
    /// Extent success report (source-health bookkeeping success face): the
    /// worker reports when one fetch runs to completion without Abandon —
    /// under multi-source assembly this clears the source's windowed failure
    /// count and can restore a demoted source; no-op for single-source
    /// assembly. Sent with `send().await` (never dropped — losing success
    /// evidence would wrongly demote a healthy source).
    ExtentSucceeded {
        /// Reporting source index.
        source: u32,
    },
    /// Write-path rate observation (observation-seam consumption):
    /// `(source, bytes, permit_waited, cap_waited)` reported by the rate
    /// limiter sink's write path; the coordinator closes windows into a
    /// per-source rate EWMA ([`crate::rate`]). Dropped by the sender when
    /// the bounded channel is full (sampling telemetry semantics — the EWMA
    /// is robust to lost samples; the observation face never backpressures
    /// the write path).
    RateSample {
        /// Task-local source index.
        source: u32,
        /// Bytes admitted by the permit in this sample.
        bytes: u64,
        /// This permit's wait duration (`Permit::waited()`).
        permit_waited: Duration,
        /// Cap-competition wait carried by this observation (the per-host cap
        /// held by another task; input to the exclusion criterion — the
        /// connection driver reports it during activation; write-path samples
        /// carry zero).
        cap_waited: Duration,
    },
    /// Byte-level heartbeat: each worker reports per second "bytes written
    /// since the last heartbeat" (stall detection only — never enters the
    /// bitmap or completion bookkeeping). The actor folds it into
    /// [`crate::stall::StallWatch`] per in-flight extent (a full window of
    /// zero byte growth = stall evidence). The reply carries the extent's
    /// write-ownership state — the owner must consume it before the next
    /// block boundary; [`HeartbeatAck::Cancelled`] means stop writing
    /// (ownership was granted to another party at the single point). Sent
    /// with `send().await` (never dropped — a dropped growth heartbeat
    /// would fabricate stall evidence).
    Heartbeat {
        /// Reporting source index (ownership check domain).
        source: u32,
        /// In-flight extent number (`SegId.extent` echoed from allocation).
        extent: u64,
        /// Bytes written since the last heartbeat (0 = zero-growth
        /// heartbeat — does not refresh the stall baseline).
        bytes: u64,
        /// Write-ownership state reply.
        reply: oneshot::Sender<HeartbeatAck>,
    },
    /// Steal decision request (worker -> coordinator): every steal passes
    /// this actor's single decision point — the same serial point as block
    /// completion (message FIFO). The requester does not name a target (it
    /// cannot know who stalled): the actor re-verifies stall evidence from
    /// its own in-flight bookkeeping, selects the stalled extent, and grants
    /// the tail from `last_acked+1` with the safety margin. Always denied in
    /// endgame (single-block granularity there forbids stealing, preventing
    /// endgame thrash and livelock).
    StealRequest {
        /// Stealing source index (bookkeeping domain; never steals its own in-flight extent).
        source: u32,
        /// Decision reply.
        reply: oneshot::Sender<StealVerdict>,
    },
    /// Congestion signal (AIMD multiplicative-decrease trigger): worker
    /// transport-path reports of server-side throttling/reset features ->
    /// the source's AIMD connection count drops multiplicatively to
    /// `max(1, floor(n * 0.75))` (immediate; in-flight gain windows and the
    /// baseline are invalidated together). Rate-limit waiting is not
    /// congestion: local limiter waits only participate in the window
    /// exclusion via [`CoordinatorMsg::RateSample`] and must not be reported
    /// here. Sent with `send().await` (never dropped — losing congestion
    /// evidence delays the decrease, same reasoning as heartbeats).
    CongestionSignal {
        /// Source index the signal belongs to (bookkeeping domain).
        source: u32,
        /// Server-side feature class.
        kind: CongestionKind,
    },
    /// AIMD snapshot query: current AIMD connection counts for all sources
    /// (ascending by source; sources without AIMD state are absent). Data
    /// source for /metrics `conn_aimd` and the worker-scale execution ring
    /// ([`crate::pool`]).
    AimdSnapshot {
        /// Snapshot reply.
        reply: oneshot::Sender<Vec<(u32, u32)>>,
    },
    /// Scheduler runtime stats query: the driver-side polling face for
    /// /metrics `stolen_total`/`conn_aimd` — the steal-grant counter
    /// accumulates inside the single decision point (counted on grant), and
    /// AIMD connection counts share the ledger with
    /// [`CoordinatorMsg::AimdSnapshot`] ([`AimdBook`]).
    RuntimeStats {
        /// Stats reply.
        reply: oneshot::Sender<RuntimeStats>,
    },
}

/// Scheduler runtime stats (the reply to [`CoordinatorMsg::RuntimeStats`];
/// static mode has no AIMD book and always denies steals, so both
/// counters stay zero — honest zeros).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeStats {
    /// Total steal grants (counted inside the single decision
    /// point; a grant = a real write-ownership transfer).
    pub steals_granted: u64,
    /// Current AIMD connection counts for all sources (ascending; the same
    /// view as [`CoordinatorHandle::aimd_snapshot`]).
    pub aimd_connections: Vec<(u32, u32)>,
    /// Multi-source health snapshot (ascending; `(source, state, windowed
    /// failure count)`). Always empty for single-source assembly (no source
    /// ledger).
    pub source_states: Vec<(u32, crate::sources::SourceState, u32)>,
    /// Total heartbeats received (counted on every [`CoordinatorMsg::
    /// Heartbeat`]): the pacer-liveness observation face and leak-regression
    /// test data source (after the host dies the pacer must freeze — no
    /// more heartbeats arrive).
    pub heartbeats_total: u64,
    /// Whether slow start has settled (true at any source's first `Hold`
    /// window decision — a gain below ~10% means the aggregate rate has
    /// reached ~90%+ of baseline, or the cap): the rate-arm fact source for
    /// the `taiji_http_slowstart_seconds` metric's end determination.
    /// Always false for the static baseline (no AIMD).
    pub slowstart_settled: bool,
}

/// Byte-level heartbeat reply (extent write-ownership
/// state; consumed by the owner at the next block boundary).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeartbeatAck {
    /// Ownership still ours; keep writing.
    Continue,
    /// Ownership was stolen (granted to another party as
    /// `[last_acked+1, extent end)` at the single point): stop writing the
    /// extent immediately (the thief finishes the unwritten blocks; recorded
    /// blocks are covered by first-report-wins adjudication). Extents no
    /// longer registered (completed and deregistered, or abandoned) get the
    /// same reply — nothing left to write.
    Cancelled,
}

/// Steal decision result (produced at the single decision point; the
/// endgame boundary and the stall re-verification are fixed here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StealVerdict {
    /// Denied: endgame (remaining blocks < worker count) — stealing is
    /// forbidden at single-block granularity, preventing endgame thrash and
    /// livelock.
    DeniedEndgame,
    /// Denied: not endgame, but re-verification found no grantable stall
    /// evidence (in-flight extents with less than a full window of zero
    /// growth / the only stalled extent is the requester's own / the
    /// stalled extent has no stealable tail). No stall evidence, no grant
    /// (a normally slow source is never stolen; rate-independent).
    DeniedNoStallEvidence,
    /// Steal granted; carries the stolen allocation — `seg` = the write
    /// bookkeeping identity (`source` = the thief, `extent` = the stolen
    /// extent's original number, the sink write-range instrumentation and
    /// single-point reconciliation domain); `extent` = the stolen range
    /// `[last_acked+1 block, extent end)` (block aligned, 1-block safety
    /// margin, the last block may be partial). The thief writes the range
    /// like a normal allocation and reports per block (the same
    /// `complete_block` decision face); on failure it is returned via a
    /// normal `Abandon` (the current owner's abandon -> undecided blocks
    /// past the watermark return to the pool).
    Approved(Allocation),
}

/// One extent allocation: scheduler output + bookkeeping identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    /// Write bookkeeping identity (`source` = the requester's source index;
    /// `extent` = the allocation sequence number, a runtime identifier that
    /// is never persisted and is reused across recycles).
    pub seg: SegId,
    /// Block-aligned byte range (the tail may end mid-block; sub-block extents are forbidden).
    pub extent: Extent,
}

/// Coordinator handle: cheap to clone (holds a bounded mpsc sender).
#[derive(Clone)]
pub struct CoordinatorHandle {
    tx: mpsc::Sender<CoordinatorMsg>,
    /// Channel capacity (`2 x workers`, frozen at construction
    /// — an observable face for backpressure-contract tests).
    capacity: usize,
}

impl CoordinatorHandle {
    /// Claim the next extent (`None` = nothing to allocate; the worker closes out).
    ///
    /// `Err` = the coordinator has stopped (a task-level fault such as a
    /// sink persistence failure — the task close-out face; the original
    /// error is exposed via the actor's JoinHandle). The actor answers each
    /// task one-to-one with no timeout-hang face (the actor loop answers
    /// serially, message by message).
    pub async fn acquire(&self, source: u32) -> Result<Option<Allocation>, HttpError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CoordinatorMsg::Acquire { source, reply })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)?;
        rx.await
            .map_err(|_| HttpError::CoordinatorStopped)
            .and_then(|res| res)
    }

    /// Block completion report (decided serially inside the actor; duplicate
    /// blocks are covered by first-report-wins, so this call always succeeds
    /// — a dropped late report is not an error).
    ///
    /// `Err` = the coordinator has stopped (the task-level fault face, same as [`Self::acquire`]).
    pub async fn complete_block(&self, block: u64) -> Result<(), HttpError> {
        self.tx
            .send(CoordinatorMsg::BlockDone { block })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Abandon an extent (failure recovery; semantics in [`CoordinatorMsg::Abandon`]).
    ///
    /// `Err` = the coordinator has stopped (the task-level fault face, same as [`Self::acquire`]).
    pub async fn abandon(&self, allocation: Allocation) -> Result<(), HttpError> {
        self.tx
            .send(CoordinatorMsg::Abandon { allocation })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Deferred extent abandon: within the Retry-After service window the
    /// extent cannot be claimed (preventing steal-retries), semantics in
    /// [`CoordinatorMsg::AbandonDeferred`]. `defer` = the failure path's
    /// clamped Retry-After value (not fuzzed — the service-window boundary
    /// uses the server's value; the worker's own backoff fuzz only sleeps
    /// longer and never reclaims before the window).
    ///
    /// `Err` = the coordinator has stopped (the task-level fault face, same as [`Self::acquire`]).
    pub async fn abandon_deferred(
        &self,
        allocation: Allocation,
        defer: Duration,
    ) -> Result<(), HttpError> {
        self.tx
            .send(CoordinatorMsg::AbandonDeferred { allocation, defer })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Extent success report (the source-health bookkeeping success face;
    /// see [`CoordinatorMsg::ExtentSucceeded`]). Like abandon, sent with
    /// `send().await` backpressure (never dropped — losing success evidence
    /// would wrongly demote a healthy source).
    ///
    /// `Err` = the coordinator has stopped (the task-level fault face, same as [`Self::acquire`]).
    pub async fn extent_succeeded(&self, source: u32) -> Result<(), HttpError> {
        self.tx
            .send(CoordinatorMsg::ExtentSucceeded { source })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Write-path rate observation report (observation-seam consumption,
    /// non-blocking — samples are dropped when the channel is full;
    /// sampling telemetry semantics in [`CoordinatorMsg::RateSample`]).
    ///
    /// `Err` = the coordinator has stopped (the task close-out face).
    pub fn report_rate_sample(
        &self,
        source: u32,
        bytes: u64,
        permit_waited: Duration,
        cap_waited: Duration,
    ) -> Result<(), HttpError> {
        match self.tx.try_send(CoordinatorMsg::RateSample {
            source,
            bytes,
            permit_waited,
            cap_waited,
        }) {
            Ok(()) => Ok(()),
            // Channel full: drop the sample (the EWMA is robust to lost
            // samples; the observation face never backpressures the write path).
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(HttpError::CoordinatorStopped),
        }
    }

    /// Byte-level heartbeat report (cadence [`HEARTBEAT_INTERVAL`]).
    ///
    /// Driver contract: `bytes` = bytes newly written on this extent since
    /// the last heartbeat (aggregated over the write path; 0 = zero growth
    /// in the window). The reply must be consumed before the next block
    /// boundary — [`HeartbeatAck::Cancelled`] means stop writing the extent
    /// (ownership was granted elsewhere; continuing only wastes bandwidth,
    /// and correctness is covered by single-point block adjudication).
    ///
    /// Unlike `report_rate_sample`'s drop semantics, heartbeats use
    /// `send().await` backpressure (never dropped — a dropped growth
    /// heartbeat would fabricate stall evidence and mis-trigger steals).
    ///
    /// `Err` = the coordinator has stopped (the task-level fault face, same as [`Self::acquire`]).
    pub async fn heartbeat(
        &self,
        source: u32,
        extent: u64,
        bytes: u64,
    ) -> Result<HeartbeatAck, HttpError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CoordinatorMsg::Heartbeat {
                source,
                extent,
                bytes,
                reply,
            })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)?;
        rx.await.map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Steal decision request (the reply is the decision; decided in the
    /// actor at the same serial point as block completion — single-point
    /// semantics). Always [`StealVerdict::DeniedEndgame`] during endgame;
    /// [`StealVerdict::DeniedNoStallEvidence`] without stall evidence (a
    /// normally slow source is never stolen); [`StealVerdict::Approved`]
    /// (the stolen allocation, extent number kept) when stall evidence
    /// holds.
    ///
    /// `Err` = the coordinator has stopped (the task-level fault face, same as [`Self::acquire`]).
    pub async fn request_steal(&self, source: u32) -> Result<StealVerdict, HttpError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CoordinatorMsg::StealRequest { source, reply })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)?;
        rx.await.map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Congestion signal report (the AIMD decrease trigger; see
    /// [`CoordinatorMsg::CongestionSignal`]). Unlike rate observations'
    /// drop semantics, sent with `send().await` backpressure (never
    /// dropped — server features are deterministic events, and losing them
    /// delays the decrease).
    ///
    /// `Err` = the coordinator has stopped (the task-level fault face, same as [`Self::acquire`]).
    pub async fn report_congestion(
        &self,
        source: u32,
        kind: CongestionKind,
    ) -> Result<(), HttpError> {
        self.tx
            .send(CoordinatorMsg::CongestionSignal { source, kind })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)
    }

    /// AIMD snapshot for all sources (ascending; always empty in static
    /// mode — the control baseline assembles no AIMD). `Err` = the
    /// coordinator has stopped (the task-level fault face, same as
    /// [`Self::acquire`]).
    pub async fn aimd_snapshot(&self) -> Result<Vec<(u32, u32)>, HttpError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CoordinatorMsg::AimdSnapshot { reply })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)?;
        rx.await.map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Scheduler runtime stats (total steal grants + AIMD connection counts
    /// for all sources; see [`RuntimeStats`]). The driver-side polling face
    /// for the /metrics HTTP family (`stolen_total`/`conn_aimd`) — a
    /// telemetry query; after task close-out it returns `Err` (callers skip
    /// it per telemetry semantics; never treat it as a task failure face).
    pub async fn runtime_stats(&self) -> Result<RuntimeStats, HttpError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(CoordinatorMsg::RuntimeStats { reply })
            .await
            .map_err(|_| HttpError::CoordinatorStopped)?;
        rx.await.map_err(|_| HttpError::CoordinatorStopped)
    }

    /// Message channel capacity (= `2 x workers`; the backpressure-contract observation face).
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Assemble the ExtentCoordinator actor (static mode): returns the
/// handle (held by workers) and the actor's close-out `JoinHandle`
/// (`Err` = a persistence/bookkeeping fault, the task-level error
/// boundary).
///
/// - `grid`: the task's block grid (`block_size` frozen);
/// - `plan`: the static allocation plan ([`StaticPlan::build`]; its
///   `block_size` must match the grid's — both products of one validated
///   task configuration);
/// - `sink`: the core-injected persistence write face (the only
///   bookkeeping entry point, see module docs);
/// - `workers`: the upper bound on task workers (channel capacity =
///   2 x workers).
pub fn spawn(
    gid: &str,
    grid: BlockGrid,
    plan: StaticPlan,
    sink: Arc<dyn SegmentSink>,
    workers: usize,
) -> (CoordinatorHandle, JoinHandle<Result<(), HttpError>>) {
    // Static has no in-flight stall bookkeeping (stealing is a dynamic
    // scheduling capability; static is the control baseline), so the stall
    // window placeholder is zero (clamped to a floor in spawn_plan; used in
    // no decision). Likewise no AIMD (connection-count adaptation is a
    // dynamic capability) and no source ledger (multi-source management is
    // a dynamic capability).
    spawn_plan(
        gid,
        grid,
        PlanSource::Static(plan),
        sink,
        workers,
        Duration::ZERO,
        None,
        SourceRateBook::new(),
        None,
    )
}

/// Assemble the ExtentCoordinator actor (dynamic mode, guided
/// self-scheduling): `plan` = the [`GuidedPlan::build`] product (its
/// `block_size` matches the grid's; the recovery-bitmap predicate was
/// consumed at build time). Rate observations flow in via
/// [`CoordinatorHandle::report_rate_sample`] (or the rate limiter sink's
/// [`crate::limiter::RateSampleReporter`] face); before the EWMA is
/// established, allocations are pure guided. `stall_window` = the stall
/// steal detection window (the task-level value of
/// `--http-stall-window`, default 15s; domain validation belongs to the
/// options layer — only a floor clamp is applied here as defense).
/// `aimd` = the connection-count AIMD config (the growth cap = the
/// `--max-connection-per-server` domain; the eval window defaults to
/// [`crate::aimd::EVAL_WINDOW`]) — the actor exclusively owns the
/// [`AimdBook`], driven by the RateSample observation stream and
/// [`CoordinatorHandle::report_congestion`] congestion signals (see the
/// module docs' AIMD wiring section).
///
/// Other contracts as in [`spawn`].
pub fn spawn_dynamic(
    gid: &str,
    grid: BlockGrid,
    plan: GuidedPlan,
    sink: Arc<dyn SegmentSink>,
    workers: usize,
    stall_window: Duration,
    aimd: AimdConfig,
) -> (CoordinatorHandle, JoinHandle<Result<(), HttpError>>) {
    spawn_plan(
        gid,
        grid,
        PlanSource::Dynamic(plan),
        sink,
        workers,
        stall_window,
        Some(AimdBook::new(aimd)),
        SourceRateBook::new(),
        None,
    )
}

/// Assemble a multi-source ExtentCoordinator actor (dynamic mode +
/// source-set management): `source_count` = the number of sources from
/// the probe merge table ([`crate::probe::merge_probes`] ->
/// `Segmented.sources`) that participate in splitting; source indices
/// `0..source_count` are the [`crate::traits::SegId::source`]
/// bookkeeping domain. Adds to the [`spawn_dynamic`] contract:
///
/// - EWMA-weighted share arbitration: allocations that would exceed a
///   source's weighted share are clamped to min-chunk (the weight =
///   per-source rate EWMA, halved when demoted, equal before
///   establishment; the composition formula's output is not rewritten);
/// - source demote/remove: extent failures count by windowed failure
///   rate (see [`crate::sources`]) — 3 in the window demotes, 5
///   removes; success reports enter the window; a demoted source
///   recovers when windowed failures fall back below the demotion
///   threshold;
/// - failover: a failed extent returns to the pool via Abandon and is
///   reallocated to surviving sources; all sources removed with pool
///   work remaining -> [`CoordinatorHandle::acquire`] answers
///   [`HttpError::NoSource`].
///
/// Source health snapshots are consumed via
/// [`CoordinatorHandle::runtime_stats`]'s [`RuntimeStats::source_states`].
/// Other contracts as in [`spawn_dynamic`].
#[expect(
    clippy::too_many_arguments,
    reason = "the multi-source assembly face carries the whole task surface explicitly; the arity is the seam contract"
)]
pub fn spawn_dynamic_multi(
    gid: &str,
    grid: BlockGrid,
    plan: GuidedPlan,
    sink: Arc<dyn SegmentSink>,
    workers: usize,
    stall_window: Duration,
    aimd: AimdConfig,
    source_count: u32,
) -> (CoordinatorHandle, JoinHandle<Result<(), HttpError>>) {
    spawn_plan(
        gid,
        grid,
        PlanSource::Dynamic(plan),
        sink,
        workers,
        stall_window,
        Some(AimdBook::new(aimd)),
        SourceRateBook::new(),
        Some(crate::sources::SourceBook::new(source_count)),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the shared actor assembly seam passes the full execution surface explicitly; the arity is the seam contract"
)]
fn spawn_plan(
    gid: &str,
    grid: BlockGrid,
    plan: PlanSource,
    sink: Arc<dyn SegmentSink>,
    workers: usize,
    stall_window: Duration,
    aimd: Option<AimdBook>,
    rates: SourceRateBook,
    sources: Option<crate::sources::SourceBook>,
) -> (CoordinatorHandle, JoinHandle<Result<(), HttpError>>) {
    // Capacity = 2 x workers; workers clamped >= 1 (single-worker tasks).
    let workers = workers.max(1);
    let capacity = 2 * workers;
    let (tx, rx) = mpsc::channel(capacity);
    let actor = ExtentCoordinator {
        gid: gid.to_string(),
        grid,
        plan,
        sink,
        rx,
        workers,
        checked: BTreeMap::new(),
        block_covered: HashMap::new(),
        rates,
        // Zero-window defense: degenerate input is clamped to a 1ms floor
        // (decision granularity stays message-arrival driven; no timer busy
        // wait). The production domain (default 15s) is validated in the
        // options layer.
        stall_window: stall_window.max(Duration::from_millis(1)),
        aimd,
        steals_granted: 0,
        sources,
        heartbeats_total: 0,
        deferred: BTreeMap::new(),
        metrics: taiji_io::metrics::registry_default(),
    };
    let handle = CoordinatorHandle { tx, capacity };
    (handle, tokio::spawn(actor.run()))
}

/// A `#[cfg(test)]` observation seam for multi-source assembly: pre-seed
/// established per-source rate EWMAs
/// ([`crate::rate::SourceRateBook::seed_established`]) — the weighted
/// share arbitration fixtures need deterministic weights, and the
/// establishment window accrues on the real clock, so filling
/// [`crate::rate::RATE_WARMUP`] through the seam is not feasible. The
/// production path's only rate source is [`CoordinatorMsg::RateSample`].
#[cfg(test)]
/// Assemble a single-source coordinator actor (dynamic mode, a seeded
/// rate book injected — a test fixture that pins allocation sizing under
/// an established-EWMA view; no source ledger, same domain as
/// [`spawn_dynamic`]).
#[expect(
    clippy::too_many_arguments,
    reason = "the seeded-rate fixture face carries the whole task surface explicitly; the arity is the seam contract"
)]
pub(crate) fn spawn_dynamic_with_rates(
    gid: &str,
    grid: BlockGrid,
    plan: GuidedPlan,
    sink: Arc<dyn SegmentSink>,
    workers: usize,
    stall_window: Duration,
    aimd: AimdConfig,
    rates: SourceRateBook,
) -> (CoordinatorHandle, JoinHandle<Result<(), HttpError>>) {
    spawn_plan(
        gid,
        grid,
        PlanSource::Dynamic(plan),
        sink,
        workers,
        stall_window,
        Some(AimdBook::new(aimd)),
        rates,
        None,
    )
}
#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "the multi-source seeded-rate fixture face carries the whole task surface explicitly; the arity is the seam contract"
)]
pub(crate) fn spawn_dynamic_multi_with_rates(
    gid: &str,
    grid: BlockGrid,
    plan: GuidedPlan,
    sink: Arc<dyn SegmentSink>,
    workers: usize,
    stall_window: Duration,
    aimd: AimdConfig,
    source_count: u32,
    rates: SourceRateBook,
) -> (CoordinatorHandle, JoinHandle<Result<(), HttpError>>) {
    spawn_plan(
        gid,
        grid,
        PlanSource::Dynamic(plan),
        sink,
        workers,
        stall_window,
        Some(AimdBook::new(aimd)),
        rates,
        Some(crate::sources::SourceBook::new(source_count)),
    )
}

impl RateSampleReporter for CoordinatorHandle {
    fn report(&self, source: u32, bytes: u64, permit_waited: std::time::Duration) {
        // Write-path samples carry no cap-competition wait (cap waits happen
        // during connection activation and are carried by report_rate_sample's
        // cap_waited field); the drop policy is cohesive in report_rate_sample
        // (Full -> Ok, sampling telemetry).
        let _ = self.report_rate_sample(source, bytes, permit_waited, Duration::ZERO);
    }
}

/// Allocation source (mode dispatch; fixed once at construction,
/// immutable at runtime — the scheduling policy can evolve while bitmap
/// semantics stay put).
enum PlanSource {
    Static(StaticPlan),
    Dynamic(GuidedPlan),
}

/// In-flight extent record (dynamic's active-W face, byte granularity):
/// byte range + written-byte watermark + undecided block count +
/// ownership/stall state (the bookkeeping unit for steal decisions and
/// ownership transfer).
struct CheckedExtent {
    /// Extent byte range (sub-block aligned start; `start < end <= total_len`).
    start_byte: u64,
    end_byte: u64,
    /// Spanned block range (floor/ceil division; see [`BlockGrid::blocks_spanned`]).
    first_block: u64,
    last_block: u64,
    /// Undecided block count (already-recorded blocks excluded at
    /// registration; the first decision on any spanned block decrements it;
    /// zero deregisters the extent — active W shrinks).
    pending_blocks: u64,
    /// Current write owner (the Cancelled decision basis for heartbeat
    /// [`HeartbeatAck`] replies; transfers to the thief on a steal grant).
    owner_source: u32,
    /// Written-byte watermark (the length of the written prefix from
    /// `start_byte`): advanced by [`CoordinatorMsg::Heartbeat`] increments
    /// and the fetch-final flush (message FIFO — the watermark is current
    /// at decision time). Not reset by a steal transfer: the thief resumes
    /// from the break point (`start_byte + covered_bytes`) and its
    /// increments keep accumulating. The truth source for the steal break
    /// point and block-completion watermark decisions.
    covered_bytes: u64,
    /// Byte-level heartbeat stall detection (reuses the [`crate::stall::
    /// StallWatch`] decision table; rate-independent — a full window of
    /// zero growth is what counts as stalled).
    stall_watch: StallWatch,
    /// Cumulative heartbeat bytes (the `total` input to
    /// [`StallWatch::stalled`]; growth-detection evidence only — the
    /// absolute value takes part in no decision).
    stall_bytes: u64,
}

impl CheckedExtent {
    /// Unwritten bytes (the recovery-domain and in-flight-byte accounting view).
    fn remaining_bytes(&self) -> u64 {
        (self.end_byte - self.start_byte).saturating_sub(self.covered_bytes)
    }

    /// Steal break point (byte coordinates): the real written-byte
    /// watermark = `start_byte + covered_bytes` (the watermark break point
    /// — the thief resumes where the owner actually stopped, rewriting zero
    /// written bytes; the former last_acked+1-block safety margin converges
    /// to at most one sub-block of in-flight write overshoot, bounded by
    /// the cancel stop-writing discipline). Transports write streams
    /// sequentially, so the watermark is a contiguous prefix.
    fn steal_start_byte(&self) -> u64 {
        self.start_byte + self.covered_bytes
    }
}

struct ExtentCoordinator {
    gid: String,
    grid: BlockGrid,
    plan: PlanSource,
    sink: Arc<dyn SegmentSink>,
    rx: mpsc::Receiver<CoordinatorMsg>,
    /// Task worker count (clamped >= 1): the shared-source view for the
    /// endgame predicate and the channel capacity (fixed once at spawn;
    /// task-level immutable).
    workers: usize,
    /// In-flight extents (seq -> record; dynamic only, always empty in static mode).
    checked: BTreeMap<u64, CheckedExtent>,
    /// Block -> written-byte watermark (the accumulation face for
    /// single-point block-completion decisions: when adjacent leases or a
    /// thief and an owner split a block, the full watermark decides
    /// completion here — the persisted bitmap semantics are unchanged).
    /// Holds only undecided blocks (removed on decision), at boundary-block
    /// granularity of in-flight extents; memory-bounded.
    block_covered: HashMap<u64, u64>,
    /// Per-source rate EWMA (the rate-term input for dynamic allocation).
    rates: SourceRateBook,
    /// Stall steal detection window (the task-level `--http-stall-window`;
    /// dynamic only — unused in static mode).
    stall_window: Duration,
    /// Per-source connection-count AIMD book (dynamic only — the static
    /// control baseline assembles none; with `None` the congestion/snapshot
    /// faces are no-ops).
    aimd: Option<AimdBook>,
    /// Total steal grants (counted inside the single decision point; the
    /// /metrics `stolen_total` source — a grant means a real ownership
    /// transfer, denials are not counted).
    steals_granted: u64,
    /// Per-source health ledger (multi-source assembly only: demote/remove
    /// counts + the source set for weighted share arbitration; `None` for
    /// single-source assembly — the related message arms are no-ops).
    sources: Option<crate::sources::SourceBook>,
    /// Total heartbeats received (counted in the [`CoordinatorMsg::
    /// Heartbeat`] arm; the [`RuntimeStats::heartbeats_total`] source —
    /// the pacer-liveness / leak-regression observation face).
    heartbeats_total: u64,
    /// Deferred pool-return queue: `not_before -> due restore jobs` — the
    /// hold face for RetryAfter abandons (claim-side filtering = the pool
    /// contains no unexpired extent). Expiry returns are driven by a scan
    /// on every message arrival (worker acquire/heartbeat/park re-polls are
    /// all messages — 500ms-scale park polling returns extents promptly
    /// after expiry; no independent timer). Keys are monotonic `Instant`s;
    /// the scan removes the `first_key` prefix.
    deferred: BTreeMap<Instant, Vec<DeferredRestore>>,
    /// Metrics registry (the transport-face feed seam — reassign/mirror/
    /// stall/aimd counters; production = the process default instance,
    /// tests assert via isolated registries — no bare global counters).
    metrics: Arc<taiji_io::metrics::MetricsRegistry>,
}

/// A deferred restore job (a value of [`ExtentCoordinator::deferred`]):
/// at abandon time the recoverable domain is decided from ownership and
/// watermark; on expiry it lands in the pool per the plan's shape.
#[derive(Debug, Clone)]
enum DeferredRestore {
    /// static: queue-head reinsert on expiry (the original extent number
    /// is kept — the same semantics as an immediate abandon's
    /// `push_front`, only later in time).
    Static { seq: u64, extent: Extent },
    /// dynamic: the unwritten domain returns to the pool on expiry (the
    /// grid decision face's truth is evaluated at expiry — blocks other
    /// workers completed during the window are not recovered twice).
    Dynamic { live: Extent },
}

impl ExtentCoordinator {
    /// Endgame predicate ([`scheduler::in_endgame`]): dynamic = pool
    /// remaining blocks < worker count; static has no pool accounting and
    /// approximates with the count of unallocated extents (an extent is >=
    /// 1 block, so fewer unallocated than workers means the tail — the
    /// granularity never degrades in static anyway; this check only serves
    /// the steal-ban boundary's synchronized close-out).
    fn in_endgame(&self) -> bool {
        match &self.plan {
            PlanSource::Dynamic(plan) => {
                scheduler::in_endgame(plan.remaining_blocks(), self.workers)
            }
            PlanSource::Static(plan) => plan.remaining() < self.workers,
        }
    }

    async fn run(mut self) -> Result<(), HttpError> {
        while let Some(msg) = self.rx.recv().await {
            // Deferred-restore expiry scan (driven on every message — acquire/
            // heartbeat/park re-polls are all messages; runs before dispatching
            // this message so expired extents return promptly).
            self.restore_expired_deferred(Instant::now());
            match msg {
                CoordinatorMsg::Acquire { source, reply } => {
                    // Source-set management precedes allocation: all sources removed with
                    // pool work remaining -> the task-level negative close-out (no_source);
                    // a removed source -> close-out None (the worker exits; its unfinished
                    // blocks return to the pool via Abandon for the survivors — failover
                    // reuses the existing semantics).
                    if let Some(book) = &self.sources {
                        if book.all_removed() && self.pool_remaining_blocks() > 0 {
                            warn!(target: "taiji::http::coordinator", gid = %self.gid,
                                "all sources removed with work remaining");
                            let _ = reply.send(Err(HttpError::NoSource));
                            continue;
                        }
                        if book.is_removed(source) {
                            let _ = reply.send(Ok(None));
                            continue;
                        }
                    }
                    // Endgame check precedes the plan borrow (the predicate only reads the
                    // pool view: pool remaining blocks < worker count -> single-block
                    // granularity).
                    let endgame = self.in_endgame();
                    // Weighted share arbitration cap, computed before the &mut plan borrow
                    // (arbitration only reads the pool view: the share = pool remaining +
                    // in-flight; holdings are snapshotted before allocation, consistent
                    // with this slice's booking point).
                    let share_cap = if endgame || self.sources.is_none() {
                        u64::MAX
                    } else {
                        self.weighted_share_cap(source)
                    };
                    let allocation = match &mut self.plan {
                        PlanSource::Static(plan) => {
                            plan.pop_next().map(|(extent_seq, extent)| Allocation {
                                seg: SegId {
                                    source,
                                    extent: extent_seq,
                                },
                                extent,
                            })
                        }
                        PlanSource::Dynamic(plan) => {
                            if endgame {
                                // Endgame degradation: the predicate
                                // is unchanged, but the allocation
                                // granularity becomes a single
                                // sub-block (the composition formula is
                                // bypassed — fragmentation lands in
                                // the sub-block domain so no worker
                                // idles in the endgame). The W snapshot, rate term, and share
                                // arbitration do not apply here.
                                plan.pop_single_granule().map(|(extent_seq, extent)| {
                                    self.register_checked(extent_seq, &extent, source);
                                    Allocation {
                                        seg: SegId {
                                            source,
                                            extent: extent_seq,
                                        },
                                        extent,
                                    }
                                })
                            } else {
                                // W = the snapshot at allocation time:
                                // the in-flight extent count + the
                                // requester (active_workers is the
                                // allocation-time snapshot, >= 1, no
                                // division by zero).
                                let w = self.checked.len().saturating_add(1);
                                let rate = self.rates.rate(source);
                                let allocation = if self.sources.is_some() {
                                    // Weighted share arbitration: formula value first, clamped to
                                    // min-chunk when over share (fast
                                    // sources claim more — slow/demoted
                                    // sources hit their share cap early).
                                    let want = plan.next_len(w, rate);
                                    let want = if share_cap < want {
                                        // The share is clamped to sub-block
                                        // granularity (the wire-level lease
                                        // domain), floor = the sub-block floor.
                                        let g = plan.min_granule();
                                        let floored = ((share_cap / g) * g).max(g);
                                        floored.min(want)
                                    } else {
                                        want
                                    };
                                    plan.pop_len(want)
                                } else {
                                    plan.pop_next(w, rate)
                                };
                                // Allocation decision sampling (debug
                                // level, a high-frequency face):
                                // W / slice length / pool remaining / in-flight — the attribution
                                // observation seam for guided self-feedback dynamics (ramp/balance/
                                // collapse shapes).
                                tracing::debug!(target: "taiji::http::coordinator",
                                    gid = %self.gid, source, w, rate_bps = ?rate,
                                    pool_bytes = plan.remaining_bytes(),
                                    in_flight = self.checked.len(),
                                    alloc = ?allocation.as_ref().map(|(_, e)| e.len),
                                    "extent allocated");
                                allocation.map(|(extent_seq, extent)| {
                                    self.register_checked(extent_seq, &extent, source);
                                    Allocation {
                                        seg: SegId {
                                            source,
                                            extent: extent_seq,
                                        },
                                        extent,
                                    }
                                })
                            }
                        }
                    };
                    // Reply receiver dropped = the worker already exited: nobody consumes the
                    // allocation, dropping is fine (a failed oneshot send is not a fault).
                    let _ = reply.send(Ok(allocation));
                }
                CoordinatorMsg::BlockDone { block } => {
                    // Single-point decision (first report wins, later dropped), then
                    // advance in-flight bookkeeping by the recorded truth: both parties
                    // spanning this block (adjacent leases/thief) get pending recomputed —
                    // robust to decision arrival order (the boundary block's first record
                    // may land on either side, equivalently).
                    self.adjudicate(block).await?;
                    self.refresh_spanned_extents(block);
                }
                CoordinatorMsg::Abandon { allocation } => {
                    self.handle_abandon(allocation, None).await;
                }
                CoordinatorMsg::AbandonDeferred { allocation, defer } => {
                    self.handle_abandon(allocation, Some(defer)).await;
                }
                CoordinatorMsg::ExtentSucceeded { source } => {
                    // Success face: windowed failure count reset + demotion recovery;
                    // single-source assembly has no ledger, so no-op. The Restored
                    // transition is counted into mirror_events via the return value
                    // (metrics feed — read-only consumption).
                    if let Some(book) = &mut self.sources {
                        let event = book.note_success(source);
                        if event.is_some() {
                            self.metrics
                                .http()
                                .note_mirror_event(taiji_io::metrics::MirrorEventKind::Restore);
                        }
                        tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
                            source, ?event, "extent succeeded; failure streak reset");
                    }
                }
                CoordinatorMsg::RateSample {
                    source,
                    bytes,
                    permit_waited,
                    cap_waited,
                } => {
                    let now = Instant::now();
                    self.rates.observe_at(source, bytes, permit_waited, now);
                    // AIMD gain window (exclusion-criterion input signal): fed from the
                    // same source's observation seam; cap-competition waits are reported
                    // accurately by the connection driver with the sample (write-path
                    // samples carry zero; activation-phase cap waits come via dedicated
                    // samples). Decision direction counts (aimd_events — read-only
                    // consumption at the decision return point; metrics feed).
                    if let Some(book) = &mut self.aimd
                        && let Some(decision) =
                            book.observe_at(source, bytes, permit_waited, cap_waited, now)
                    {
                        use taiji_io::metrics::AimdDirection;
                        match decision {
                            crate::aimd::AimdDecision::Grow { .. } => {
                                self.metrics.http().note_aimd_event(AimdDirection::Grow);
                            }
                            crate::aimd::AimdDecision::Decrease { .. } => {
                                self.metrics.http().note_aimd_event(AimdDirection::Shrink);
                            }
                            crate::aimd::AimdDecision::Hold { .. } => {}
                        }
                        tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
                                source, ?decision, "aimd window decision");
                    }
                }
                CoordinatorMsg::CongestionSignal { source, kind } => {
                    // Multiplicative-decrease trigger: immediate multiplicative decrease +
                    // baseline reset (opening the recovery path). Static mode assembles no
                    // AIMD — the control baseline no-ops (the signal is accepted without
                    // error: the signal face is decoupled from the scheduling mode).
                    match &mut self.aimd {
                        Some(book) => {
                            let decision = book.note_congestion(source, kind, Instant::now());
                            self.metrics
                                .http()
                                .note_aimd_event(taiji_io::metrics::AimdDirection::Shrink);
                            tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
                                source, kind = ?kind, ?decision, "aimd congestion decrease");
                        }
                        None => {
                            tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
                                source, kind = ?kind, "congestion signal ignored (static baseline)");
                        }
                    }
                }
                CoordinatorMsg::AimdSnapshot { reply } => {
                    let snap = self.aimd.as_ref().map_or_else(Vec::new, AimdBook::snapshot);
                    // Reply receiver dropped = the querier already exited:
                    // nobody consumes the snapshot, dropping is fine.
                    let _ = reply.send(snap);
                }
                CoordinatorMsg::RuntimeStats { reply } => {
                    let stats = RuntimeStats {
                        steals_granted: self.steals_granted,
                        aimd_connections: self
                            .aimd
                            .as_ref()
                            .map_or_else(Vec::new, AimdBook::snapshot),
                        source_states: self
                            .sources
                            .as_ref()
                            .map_or_else(Vec::new, crate::sources::SourceBook::snapshot),
                        heartbeats_total: self.heartbeats_total,
                        slowstart_settled: self.aimd.as_ref().is_some_and(AimdBook::settled_any),
                    };
                    // Reply receiver dropped = the querier already
                    // exited: nobody consumes the stats, dropping is fine.
                    let _ = reply.send(stats);
                }
                CoordinatorMsg::Heartbeat {
                    source,
                    extent,
                    bytes,
                    reply,
                } => {
                    self.heartbeats_total = self.heartbeats_total.saturating_add(1);
                    // The heartbeat doubles as the block-completion watermark driver — a
                    // watermark advance may trigger a block decision; a persistence
                    // failure propagates as a task-level fault (`?` ends the actor; the
                    // reply side then sees CoordinatorStopped, same as the sink fault
                    // face).
                    let ack = self.heartbeat(source, extent, bytes).await?;
                    // Reply receiver dropped = the reporter already
                    // exited: nobody consumes the cancel, dropping is fine.
                    let _ = reply.send(ack);
                }
                CoordinatorMsg::StealRequest { source, reply } => {
                    // Single-point decision (the same serial point as block completion):
                    // always denied in endgame; otherwise re-verify byte-level heartbeat
                    // stall evidence from this actor's own bookkeeping and grant the tail
                    // from last_acked+1 with the safety margin only if it holds. The
                    // requester's claim is never trusted.
                    let verdict = self.adjudicate_steal(source);
                    tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
                        source, ?verdict, "steal request adjudicated");
                    // The requester already exited: nobody consumes the decision, dropping is fine.
                    let _ = reply.send(verdict);
                }
            }
        }
        Ok(())
    }

    /// dynamic: register an in-flight extent (the active-W face + initial
    /// ownership/stall/watermark bookkeeping; byte granularity — the
    /// extent start may land on a sub-block boundary inside a block;
    /// spanned blocks use floor/ceil). A grid geometry mismatch (a
    /// plan-side defect shape) only degrades bookkeeping (W reads high)
    /// and never blocks allocation — the allocation was already answered;
    /// a bookkeeping failure cannot corrupt the decision face.
    fn register_checked(&mut self, seq: u64, extent: &Extent, source: u32) {
        match self.grid.blocks_spanned(extent) {
            Some((first, last)) => {
                let pending = (first..=last)
                    .filter(|b| !self.grid.is_recorded(*b))
                    .count() as u64;
                self.checked.insert(
                    seq,
                    CheckedExtent {
                        start_byte: extent.start,
                        end_byte: extent.end(),
                        first_block: first,
                        last_block: last,
                        pending_blocks: pending,
                        owner_source: source,
                        covered_bytes: 0,
                        stall_watch: StallWatch::new(self.stall_window, 0, Instant::now()),
                        stall_bytes: 0,
                    },
                );
            }
            None => {
                warn!(target: "taiji::http::coordinator", gid = %self.gid,
                    seq, "dynamic allocation outside grid; in-flight bookkeeping skipped");
            }
        }
    }

    /// In-flight bookkeeping advance after a block decision (first record
    /// or watermark full): the block -> in-flight extent index degrades to
    /// a linear scan under byte granularity (the in-flight extent count =
    /// active workers, bounded). pending is recomputed from the grid's
    /// recorded truth rather than decremented: a block can be spanned by
    /// both adjacent leases and a thief, and the boundary block's first
    /// record may land on either side (the late party's duplicate decision
    /// no longer fires); recomputation is robust to decision arrival
    /// order. Extents whose pending reaches zero are deregistered (active
    /// W shrinks).
    fn refresh_spanned_extents(&mut self, block: u64) {
        let mut finished = Vec::new();
        for (seq, entry) in self.checked.iter_mut() {
            if block < entry.first_block || block > entry.last_block {
                continue;
            }
            entry.pending_blocks = (entry.first_block..=entry.last_block)
                .filter(|b| !self.grid.is_recorded(*b))
                .count() as u64;
            if entry.pending_blocks == 0 {
                finished.push(*seq);
            }
        }
        for seq in finished {
            self.checked.remove(&seq);
        }
    }

    /// Written-byte watermark advance for an in-flight extent (the core of
    /// single-point block completion): `delta` folds into the watermark (a
    /// contiguous prefix, saturating at the extent length), newly covered
    /// ranges fold per block into [`Self::block_covered`], and a block
    /// whose watermark fills is decided inside this actor
    /// ([`Self::adjudicate`] first-report-wins ->
    /// [`SegmentSink::complete_block`] persistence — blocks split across
    /// leases/thief are judged full by summed watermarks; single-point
    /// adjudication and fsync discipline unchanged). A persistence failure
    /// propagates as a task-level fault.
    async fn advance_watermark(&mut self, extent_seq: u64, delta: u64) -> Result<(), HttpError> {
        let bs = self.grid.block_size();
        let total = self.grid.total_len();
        let Some(entry) = self.checked.get_mut(&extent_seq) else {
            return Ok(());
        };
        let len = entry.end_byte - entry.start_byte;
        let prev = entry.covered_bytes;
        let cur = entry.covered_bytes.saturating_add(delta).min(len);
        entry.covered_bytes = cur;
        if cur <= prev {
            return Ok(()); // zero growth (or already saturated)
        }
        // Accumulate the newly covered range [start+prev,
        // start+cur) per block; a full block is decided.
        let from = entry.start_byte + prev;
        let to = entry.start_byte + cur;
        let mut block = from / bs;
        while block * bs < to {
            let b_start = block * bs;
            let b_end = ((block + 1) * bs).min(total);
            let full = b_end - b_start;
            let seg_lo = from.max(b_start);
            let seg_hi = to.min(b_end);
            let covered = self.block_covered.entry(block).or_insert(0);
            *covered += seg_hi - seg_lo;
            if *covered >= full {
                self.block_covered.remove(&block);
                // Watermark full -> decide (with persistence), then advance in-flight
                // bookkeeping by the recorded truth (a late party's duplicate
                // full-watermark decision is idempotent).
                self.adjudicate(block).await?;
                self.refresh_spanned_extents(block);
            }
            block += 1;
        }
        Ok(())
    }

    /// Byte-level heartbeat booking (doubles as the block-completion
    /// watermark driver): when the extent is registered and ownership is
    /// still ours, the increment folds into [`StallWatch`] (growth
    /// refreshes the stall baseline) and advances the written-byte
    /// watermark (a full block is decided immediately); every other shape
    /// replies Cancelled (not registered = nothing to write; ownership
    /// transferred = we were stolen from — overshoot increments are not
    /// booked, and the double-write waste is covered by the thief's
    /// resumed range).
    async fn heartbeat(
        &mut self,
        source: u32,
        extent_seq: u64,
        bytes: u64,
    ) -> Result<HeartbeatAck, HttpError> {
        let delta = {
            let Some(entry) = self.checked.get_mut(&extent_seq) else {
                return Ok(HeartbeatAck::Cancelled);
            };
            if entry.owner_source != source {
                return Ok(HeartbeatAck::Cancelled);
            }
            entry.stall_bytes = entry.stall_bytes.saturating_add(bytes);
            // Evaluate-as-maintain: growth pushes the baseline to now (the stall
            // timer resets); zero growth keeps the accumulated stall duration
            // (stalled's return value is irrelevant here).
            let _ = entry.stall_watch.stalled(entry.stall_bytes, Instant::now());
            bytes
        };
        // The watermark advance may trigger a block decision (a
        // persistence failure = a task-level fault, propagated).
        self.advance_watermark(extent_seq, delta).await?;
        Ok(HeartbeatAck::Continue)
    }

    /// Steal endgame check: the same predicate [`scheduler::in_endgame`]
    /// (same threshold) as the allocation arm's endgame check, but
    /// "remaining" counts total live work = unallocated pool + undecided
    /// in-flight blocks. The two views diverge only when the pool is empty
    /// while an in-flight tail is visible — exactly the stall steal's main
    /// battlefield (workers idle precisely because the pool is empty; under
    /// the pool view this would always read endgame and stealing would
    /// never grant, killing the feature). The total-live view puts the
    /// "no stealing at single-block granularity" rule in its literal
    /// domain: a true tail where each worker's remaining share is < 1
    /// block (stealing would leave a 1-block scrap and pure endgame
    /// thrash/livelock risk); there it is always denied.
    fn steal_denied_endgame(&self) -> bool {
        // Byte view: undecided in-flight bytes + pool remaining bytes,
        // converted to blocks with ceiling division (the byte-wise equivalent
        // of "remaining blocks" per extent — the predicate is unchanged).
        let in_flight: u64 = self
            .checked
            .values()
            .map(|e| e.remaining_bytes().div_ceil(self.grid.block_size()))
            .sum();
        let pool = match &self.plan {
            PlanSource::Dynamic(plan) => plan.remaining_blocks(),
            PlanSource::Static(plan) => plan.remaining() as u64,
        };
        scheduler::in_endgame(in_flight.saturating_add(pool), self.workers)
    }

    /// Steal decision (single-point re-verification): always denied in
    /// endgame; always denied for removed sources (the removal terminal
    /// state closes at the decision face — the ledger transition takes
    /// effect immediately, while the worker pool's expectation decrease is
    /// consumed at the driver's tick, so a parked worker's steal request
    /// can arrive before the pool update; without this re-check a removed
    /// source could re-enter by stealing). Otherwise re-verify stall
    /// evidence in this actor's own bookkeeping (a full window of byte
    /// zero growth from byte-level heartbeats — heartbeats and rate
    /// observations that arrived before the request was enqueued were
    /// consumed first under FIFO, so the evidence is current), cross-check
    /// the owner source's rate-limit wait activity shadow
    /// ([`SourceRateBook::rate_limit_shadow`] — rate-limit waiting is not
    /// stall evidence; zero growth from a low rate limit stretching chunk
    /// gaps past the stall window is pacing, not stalling), then pick the
    /// longest-stalled in-flight extent (lowest allocation sequence =
    /// deterministic) and grant the tail from `last_acked+1` with the
    /// safety margin, transferring ownership. A grant also resets the
    /// stall baseline (a full window of grace for the new owner) —
    /// concurrent steal requests on the same evidence never double grant.
    ///
    /// # The endgame-domain boundary
    ///
    /// Under fine-grained leases (single-block leases while the EWMA is
    /// unestablished, see [`crate::scheduler::compose_len`]) the endgame
    /// domain is common — an unconditional steal ban would deadlock the
    /// stall recovery path: a hung extent never advances -> live blocks
    /// run out -> permanent endgame -> permanent denial -> the hung worker
    /// never gets stopped. The literal ban targets endgame steal thrash
    /// between active workers; that risk is constrained by the evidence
    /// gate (a full window of byte zero growth + a grant resets the
    /// baseline + single-point serial decisions), and a byte-stalled hung
    /// owner is not a competitor. So the endgame domain grants only when
    /// stall evidence holds and the stealable tail is non-empty (the
    /// evidence gate runs first, below); unevidenced requests in the
    /// endgame domain still get [`StealVerdict::DeniedEndgame`] (the
    /// endgame ban semantics is preserved).
    fn adjudicate_steal(&mut self, source: u32) -> StealVerdict {
        // Removed sources are always denied: a removed source's parked worker
        // should only exit via the pool expectation decrease, never re-enter
        // writing by stealing.
        if self
            .sources
            .as_ref()
            .is_some_and(|book| book.is_removed(source))
        {
            tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
                source, "steal request from removed source denied");
            return StealVerdict::DeniedNoStallEvidence;
        }
        let now = Instant::now();
        let mut grant = None;
        for (seq, entry) in self.checked.iter_mut() {
            if entry.owner_source == source {
                continue; // never steal our own in-flight extent
            }
            if !entry.stall_watch.stalled(entry.stall_bytes, now) {
                continue; // no stall evidence (re-verification failed)
            }
            // Stall-evidence-established counter (metrics feed): a read-only
            // consumption point of the [`StallWatch::stalled`] truth — the decision
            // face confirming a full window of byte zero growth (whether the steal
            // is granted is decided by the tail/exclusion checks below; counted
            // as soon as evidence holds).
            self.metrics.http().note_stall_detected();
            // Rate-limit wait exclusion ("rate-limit waiting is not stall
            // evidence"): the owner source inside its rate-limit wait activity
            // shadow means the zero growth is a pacing gap of the local rate
            // limiter (the falsified-evidence shape of a low rate limit);
            // re-verification fails. The shadow is maintained by RateSample
            // observations (the same FIFO channel, consumed before this decision —
            // consistent with the heartbeat evidence).
            if self
                .rates
                .rate_limit_shadow(entry.owner_source, now, self.stall_window)
            {
                tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
                    seq, owner = entry.owner_source,
                    "steal candidate excluded: owner within rate-limit wait shadow");
                continue;
            }
            let start = entry.steal_start_byte();
            if start >= entry.end_byte {
                continue; // no stealable tail past the watermark
            }
            grant = Some((*seq, start));
            break;
        }
        let Some((seq, start_byte)) = grant else {
            // No evidence / no tail: in the endgame domain return the endgame ban
            // verdict (anti-thrash — the evidence gate already ran above),
            // otherwise the evidence-face denial.
            return if self.steal_denied_endgame() {
                StealVerdict::DeniedEndgame
            } else {
                StealVerdict::DeniedNoStallEvidence
            };
        };
        let extent = Extent {
            start: start_byte,
            len: {
                let entry = match self.checked.get(&seq) {
                    Some(entry) => entry,
                    None => return StealVerdict::DeniedNoStallEvidence,
                };
                entry.end_byte - start_byte
            },
        };
        match self.checked.get_mut(&seq) {
            Some(entry) => {
                entry.owner_source = source;
                // The watermark break point is the ownership transfer point
                // (covered_bytes is not reset — the thief resumes from the break
                // point and its heartbeat increments keep accumulating; block
                // completion is judged by summed watermarks).
                entry.stall_watch = StallWatch::new(self.stall_window, entry.stall_bytes, now);
            }
            None => return StealVerdict::DeniedNoStallEvidence,
        }
        tracing::debug!(target: "taiji::http::coordinator", gid = %self.gid,
            seq, thief = source, start_byte, "stall steal granted at byte watermark");
        self.steals_granted = self.steals_granted.saturating_add(1);
        StealVerdict::Approved(Allocation {
            seg: SegId {
                source,
                extent: seq,
            },
            extent,
        })
    }

    /// Unified abandon arm (shared by [`CoordinatorMsg::Abandon`] /
    /// [`CoordinatorMsg::AbandonDeferred`]): the abandon decision +
    /// source-failure bookkeeping. `defer = Some` = a RetryAfter
    /// service-window delayed pool return (see the message docs).
    async fn handle_abandon(&mut self, allocation: Allocation, defer: Option<Duration>) {
        // Multi-source assembly: an abandon by the current owner = one extent
        // transport failure -> windowed failure count (demote/remove
        // thresholds in [`crate::sources`]); abandons by stale owners after a
        // steal and unregistered/empty-extent shapes do not count (not a
        // transport failure of this source).
        let failed_source = allocation.seg.source;
        if self.abandon_with_defer(allocation, defer) {
            // Non-steal reassignment counter (metrics feed): the decision face
            // confirmed a real return (the current owner's abandon = the extent
            // returns to the pool for reassignment); steal grants use the existing
            // stolen counter and a stale owner's abandon (returns false) is not
            // counted — reassign counts only non-steal returns.
            self.metrics.http().note_extent_reassign();
            if let Some(book) = &mut self.sources {
                use taiji_io::metrics::MirrorEventKind;
                match book.note_failure(failed_source) {
                    Some(crate::sources::SourceEvent::Demoted) => {
                        self.metrics
                            .http()
                            .note_mirror_event(MirrorEventKind::Demote);
                        tracing::info!(target: "taiji::http::coordinator",
                                gid = %self.gid, source = failed_source,
                                "source demoted after consecutive extent failures");
                    }
                    Some(crate::sources::SourceEvent::Removed) => {
                        self.metrics
                            .http()
                            .note_mirror_event(MirrorEventKind::Remove);
                        tracing::warn!(target: "taiji::http::coordinator",
                                gid = %self.gid, source = failed_source,
                                "source removed after consecutive extent failures");
                    }
                    _ => {}
                }
            }
        }
    }

    /// Deferred-restore expiry scan: jobs with `not_before <= now` land in
    /// the pool per the plan's shape (static queue-head reinsert / dynamic
    /// unwritten-domain return). The dynamic grid decision face's truth is
    /// evaluated at expiry time (blocks other workers completed during the
    /// window are not recovered twice).
    fn restore_expired_deferred(&mut self, now: Instant) {
        while let Some((&not_before, _)) = self.deferred.first_key_value() {
            if not_before > now {
                break;
            }
            let Some((_, jobs)) = self.deferred.pop_first() else {
                break;
            };
            for job in jobs {
                match job {
                    DeferredRestore::Static { seq, extent } => {
                        if let PlanSource::Static(plan) = &mut self.plan {
                            plan.push_front(seq, extent);
                        }
                    }
                    DeferredRestore::Dynamic { live } => {
                        if let PlanSource::Dynamic(plan) = &mut self.plan {
                            if live.is_empty() {
                                continue;
                            }
                            let grid = &self.grid;
                            plan.restore_extent(&live, &|b| grid.is_recorded(b));
                        }
                    }
                }
            }
        }
    }

    /// dynamic extent abandon: deregister the in-flight record and return
    /// unfinished blocks to the pool with the grid decision face as truth
    /// (blocks already decided are not recovered — progress is recorded
    /// once). Returns `true` = the current owner's abandon (the extent
    /// really returned; source-health bookkeeping counts one extent
    /// failure); `false` = stale owner / unregistered / empty-extent
    /// shapes (not a transport-failure face, not counted).
    ///
    /// `defer = Some(d)`: the recoverable domain does not land in the pool
    /// immediately but is recorded with `not_before = now + d` in
    /// [`ExtentCoordinator::deferred`] — claim/allocation queries filter
    /// it naturally during the window (the pool contains no unexpired
    /// extent), and [`ExtentCoordinator::restore_expired_deferred`] returns
    /// it on expiry. The decision face (ownership check / watermark
    /// recovery domain / source failure count) is identical to an
    /// immediate abandon.
    ///
    /// Steal awareness: if the abandoning party is not the current owner
    /// (its range already transferred in an earlier steal — everything
    /// before the watermark was decided, everything after belongs to the
    /// current owner) there is nothing to recover and bookkeeping stands
    /// (the current owner is still in flight); a current owner's abandon
    /// recovers only undecided blocks past the steal watermark (everything
    /// before the watermark was decided; progress is recorded once).
    fn abandon_with_defer(&mut self, allocation: Allocation, defer: Option<Duration>) -> bool {
        // Defensively drop an empty extent (an impossible shape; same policy as static recovery).
        if allocation.extent.is_empty() {
            warn!(target: "taiji::http::coordinator", gid = %self.gid,
                seq = allocation.seg.extent, "abandoned empty extent dropped");
            return false;
        }
        let not_before = defer.map(|d| Instant::now() + d);
        match &mut self.plan {
            PlanSource::Static(plan) => {
                match not_before {
                    Some(t) => self
                        .deferred
                        .entry(t)
                        .or_default()
                        .push(DeferredRestore::Static {
                            seq: allocation.seg.extent,
                            extent: allocation.extent,
                        }),
                    None => plan.push_front(allocation.seg.extent, allocation.extent),
                }
                true
            }
            PlanSource::Dynamic(plan) => {
                let live_owner = match self.checked.get(&allocation.seg.extent) {
                    Some(entry) => entry.owner_source,
                    // Already deregistered: duplicate or uninformed
                    // abandon; ignore (bookkeeping already closed).
                    None => return false,
                };
                if live_owner != allocation.seg.source {
                    // Stale owner: nothing to recover (see function docs).
                    return false;
                }
                let entry = match self.checked.remove(&allocation.seg.extent) {
                    Some(entry) => entry,
                    None => return false,
                };
                // Recovery domain = the unwritten domain past the real written-byte
                // watermark [start + covered, end). Message FIFO guarantees all
                // heartbeats enqueued before the abandon were consumed — the watermark
                // is the exact contiguous prefix at abandon time; the written prefix
                // (including the partial straddling block) does not return to the
                // pool; its block completion is closed by the watermark face
                // (including the successor lease's writes).
                let live_start = entry.start_byte + entry.covered_bytes;
                let live = Extent {
                    start: live_start,
                    len: entry.end_byte.saturating_sub(live_start),
                };
                if !live.is_empty() {
                    match not_before {
                        Some(t) => self
                            .deferred
                            .entry(t)
                            .or_default()
                            .push(DeferredRestore::Dynamic { live }),
                        None => {
                            let grid = &self.grid;
                            plan.restore_extent(&live, &|b| grid.is_recorded(b));
                        }
                    }
                }
                true
            }
        }
    }

    /// Pool remaining blocks (the "work remaining" domain of the no_source
    /// decision). Multi-source assembly is dynamic-only; the static face
    /// approximates with the unallocated extent count (a type-completeness
    /// defense).
    fn pool_remaining_blocks(&self) -> u64 {
        match &self.plan {
            PlanSource::Dynamic(plan) => plan.remaining_blocks(),
            PlanSource::Static(plan) => plan.remaining() as u64,
        }
    }

    /// Weighted share arbitration: this source's byte cap for this
    /// allocation = weighted share - in-flight holdings (share =
    /// `live * w_i / sum(w)`, live = pool remaining + all sources'
    /// undecided in-flight bytes; w = per-source rate EWMA with demotion
    /// halving, removed/unregistered = zero weight). No source ledger
    /// (single-source assembly) means no cap.
    fn weighted_share_cap(&self, source: u32) -> u64 {
        let Some(book) = &self.sources else {
            return u64::MAX;
        };
        let in_flight = self.in_flight_bytes_total();
        let pool = match &self.plan {
            PlanSource::Dynamic(plan) => plan.remaining_bytes(),
            PlanSource::Static(_) => 0,
        };
        let weights = book.weights(&|s| self.rates.rate(s));
        let total: f64 = weights.values().copied().sum();
        let w = weights.get(&source).copied().unwrap_or(0.0);
        crate::sources::share_cap(
            self.in_flight_bytes_of(source),
            w,
            total,
            pool.saturating_add(in_flight),
        )
    }

    /// This source's in-flight unwritten bytes (holdings; exact watermark
    /// values — share arbitration is an allocation-preference face and
    /// takes part in no correctness bookkeeping).
    fn in_flight_bytes_of(&self, source: u32) -> u64 {
        self.checked
            .values()
            .filter(|e| e.owner_source == source)
            .map(|e| e.remaining_bytes())
            .sum()
    }

    /// In-flight unwritten bytes across all sources.
    fn in_flight_bytes_total(&self) -> u64 {
        self.checked.values().map(|e| e.remaining_bytes()).sum()
    }

    /// Block-completion decision (serial single point; semantics in the
    /// module docs). Persistence failure = task-level fault: the error
    /// propagates and ends the actor (a broken bookkeeping face must not
    /// silently drop progress). Returns whether this was the first record
    /// (`true` = the block's first booking; the caller advances in-flight
    /// bookkeeping accordingly; a dropped late report returns `false` — a
    /// late same-block duplicate report is not an error face).
    async fn adjudicate(&mut self, block: u64) -> Result<bool, HttpError> {
        match self.grid.record(block) {
            Ok(true) => {
                if let Err(e) = self.sink.complete_block(block).await {
                    error!(target: "taiji::http::coordinator", gid = %self.gid,
                        block, code = e.code(), "block completion persist failed; task aborts");
                    return Err(e);
                }
                Ok(true)
            }
            // Late report dropped: a late same-block duplicate
            // booking; progress is recorded once (not an error face).
            Ok(false) => Ok(false),
            // Out-of-grid block = a scheduler-side defect (a
            // programming-error face); closed as a task-level error.
            Err(e) => {
                error!(target: "taiji::http::coordinator", gid = %self.gid,
                    block, code = e.code(), "block completion out of grid");
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HttpError;
    use crate::grid::MIN_BLOCK_SIZE;
    use crate::scheduler::SchedulerConfig;
    use crate::traits::RequestCtx;
    use bytes::Bytes;
    use futures::future::BoxFuture;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Decision-observing sink: records the complete_block call sequence
    /// (including duplicate call counts) and written bytes; can inject a
    /// persistence failure.
    struct RecordingSink {
        completions: Mutex<Vec<u64>>,
        write_calls: AtomicU64,
        fail_complete: bool,
    }

    impl RecordingSink {
        fn new(fail_complete: bool) -> Self {
            RecordingSink {
                completions: Mutex::new(Vec::new()),
                write_calls: AtomicU64::new(0),
                fail_complete,
            }
        }

        fn completions(&self) -> Vec<u64> {
            self.completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl SegmentSink for RecordingSink {
        fn write_at(
            &self,
            _seg: SegId,
            _off: u64,
            _bytes: Bytes,
        ) -> BoxFuture<'_, crate::error::Result<()>> {
            self.write_calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(())))
        }

        fn complete_block(&self, block: u64) -> BoxFuture<'_, crate::error::Result<()>> {
            if self.fail_complete {
                return Box::pin(std::future::ready(Err(HttpError::Transport(
                    "injected persist failure".into(),
                ))));
            }
            self.completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(block);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// Synthetic worker: acquire extents -> write in 4KiB steps to the sink
    /// -> report per block -> until exhausted. The block-range derivation
    /// uses the same algebra as the grid ([`BlockGrid::blocks_spanned`]) —
    /// worker-inline geometry derivation was merged into the same algebra
    /// so same-view duplicate implementations cannot drift; `grid_ref` is a
    /// reference grid built with the same parameters as the actor's grid.
    async fn synthetic_worker(
        handle: &CoordinatorHandle,
        source: u32,
        sink: &dyn SegmentSink,
        grid_ref: &BlockGrid,
    ) -> Result<(), HttpError> {
        while let Some(alloc) = handle.acquire(source).await? {
            let seg = alloc.seg;
            let mut off = alloc.extent.start;
            while off < alloc.extent.end() {
                let n = 4096u64.min(alloc.extent.end() - off);
                sink.write_at(seg, off, Bytes::new()).await?;
                off += n;
            }
            let (first, last) = grid_ref
                .blocks_spanned(&alloc.extent)
                .unwrap_or_else(|| panic!("allocation extent must be in-grid: {:?}", alloc.extent));
            for block in first..=last {
                handle.complete_block(block).await?;
            }
        }
        Ok(())
    }

    /// Block-completion single-point decision: duplicate reports hit the
    /// sink only once (first report wins, later dropped); block 0 has
    /// priority; allocation sequence numbers are stable; Acquire closes out
    /// None once the grid is complete.
    #[tokio::test]
    async fn adjudication_is_first_wins_and_block0_prioritized() {
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, 6 * bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 3,
            min_split_size: bs,
            ..SchedulerConfig::default()
        };
        let plan = StaticPlan::build(6 * bs, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn(
            "8000000000000501",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
        );

        assert_eq!(
            handle.capacity(),
            2 * 2,
            "capacity = 2 x workers (the backpressure contract)"
        );

        // Block 0 priority: the first claimer gets block 0 (1-block granularity).
        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        let head = head.unwrap_or_else(|| panic!("head allocation"));
        assert_eq!(
            head.extent,
            Extent { start: 0, len: bs },
            "block 0 claims 1-block granularity first"
        );
        assert_eq!(head.seg.extent, 0, "the head block = extent 0");

        // The second claimer gets segment 0 (start = block 1).
        let second = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        let second = second.unwrap_or_else(|| panic!("seg allocation"));
        assert_eq!(
            second.extent.start, bs,
            "the fixed segment comes after the head block"
        );
        assert_eq!(
            second.seg.source, 1,
            "SegId.source = the requesting source ordinal"
        );

        // Block 1 double-write shape: both workers report block 1 — the sink sees it once.
        handle
            .complete_block(1)
            .await
            .unwrap_or_else(|e| panic!("report: {e}"));
        handle
            .complete_block(1)
            .await
            .unwrap_or_else(|e| panic!("report: {e}"));
        // Barrier: this Acquire's reply means reports enqueued earlier were
        // serially consumed by the actor (message FIFO + single-point serial
        // decision — a deterministic observation point).
        let barrier = handle
            .acquire(2)
            .await
            .unwrap_or_else(|e| panic!("barrier: {e}"));
        assert!(
            barrier.is_some(),
            "the barrier claim should get the remaining segment"
        );
        assert_eq!(
            sink.completions(),
            vec![1],
            "first arrival books, later arrivals are dropped"
        );

        handle
            .abandon(second)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));
        let reused = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        let reused = reused.unwrap_or_else(|| panic!("reused allocation"));
        assert_eq!(
            reused.seg.extent, second.seg.extent,
            "recycling keeps the original sequence number"
        );
        assert_eq!(reused.extent, second.extent);

        drop(handle);
        let outcome = actor.await.unwrap_or_else(|e| panic!("actor join: {e}"));
        outcome.unwrap_or_else(|e| panic!("actor: {e}"));
        assert!(sink.completions().contains(&1));
    }

    /// End-to-end skeleton (static scheduling + bookkeeping + a throttled
    /// sink wrapper): multiple workers acquire -> write (through
    /// ThrottledSink's pass-through face) -> report per block -> close out
    /// when allocations run out; the sink decision sequence == every block
    /// exactly once (no duplicates, no omissions, partial last block
    /// included).
    #[tokio::test]
    async fn static_skeleton_end_to_end_multi_worker() {
        let bs = MIN_BLOCK_SIZE;
        // 9 blocks + 100B partial last block; 3 workers.
        let total = 9 * bs + 100;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 8,
            ..SchedulerConfig::default()
        };
        let plan = StaticPlan::build(total, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn(
            "8000000000000502",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            3,
        );

        // Rate-limit wrapper (unlimited): bookkeeping still goes through the
        // decision face — the full chain does not bypass the frozen seam.
        let throttled = Arc::new(crate::limiter::ThrottledSink::new(
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            crate::limiter::HttpLimiter::new(None),
        ));
        // Reference grid (same parameters as the actor's grid): the shared
        // algebra face for worker block-range derivation.
        let grid_ref = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));

        let mut workers = Vec::new();
        for source in 0..3u32 {
            let handle = handle.clone();
            let throttled = Arc::clone(&throttled);
            let grid_ref = grid_ref.clone();
            workers.push(tokio::spawn(async move {
                synthetic_worker(&handle, source, throttled.as_ref(), &grid_ref).await
            }));
        }
        for w in workers {
            w.await
                .unwrap_or_else(|e| panic!("worker join: {e}"))
                .unwrap_or_else(|e| panic!("worker: {e}"));
        }
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        // Decision sequence: 0..=9 each exactly once (order unspecified —
        // workers report concurrently; compare after sorting).
        let mut completions = sink.completions();
        completions.sort_unstable();
        assert_eq!(
            completions,
            (0..=9).collect::<Vec<u64>>(),
            "each block booked exactly once"
        );
    }

    /// Persistence failure = task-level fault: the actor ends with an
    /// error; later handle calls report the stopped face (no hang).
    #[tokio::test]
    async fn sink_failure_aborts_actor_task_scoped() {
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let cfg = SchedulerConfig::default();
        let plan = StaticPlan::build(bs, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(true));
        let (handle, actor) = spawn(
            "8000000000000503",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
        );

        // Report block 0 -> sink fails -> the actor ends with Err.
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("report: {e}"));
        let outcome = actor.await.unwrap_or_else(|e| panic!("actor join: {e}"));
        match outcome {
            Err(e) => assert_eq!(
                e.code(),
                "taiji.http.transport",
                "sink errors propagate verbatim"
            ),
            Ok(()) => panic!("a sink failure must close out as a task-level error"),
        }

        // Handle face: calls after the actor stops return Err immediately (no hang).
        assert!(matches!(
            handle.complete_block(0).await,
            Err(HttpError::CoordinatorStopped)
        ));
        assert!(matches!(
            handle.acquire(0).await,
            Err(HttpError::CoordinatorStopped)
        ));
    }

    /// Empty-file grid: nothing to allocate, the worker
    /// closes out immediately (the total = 0 shape).
    #[tokio::test]
    async fn empty_file_yields_no_allocation() {
        let grid = BlockGrid::new(MIN_BLOCK_SIZE, 0).unwrap_or_else(|e| panic!("grid: {e}"));
        let cfg = SchedulerConfig::default();
        let plan = StaticPlan::build(0, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn(
            "8000000000000504",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
        );
        let none = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        assert!(none.is_none(), "an empty file has nothing to allocate");
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
        assert!(sink.completions().is_empty());
        assert_eq!(
            sink.write_calls.load(Ordering::Relaxed),
            0,
            "an empty file makes zero write-face calls"
        );
    }

    /// Transport-face reference keepalive (RequestCtx/Extent default smoke — avoids dead code).
    #[test]
    fn request_ctx_default_smoke() {
        let ctx = RequestCtx::default();
        assert!(ctx.headers.is_empty());
        let ext = Extent { start: 0, len: 4 };
        assert_eq!(ext.end(), 4);
    }

    // ------- dynamic (guided + rate composition + rate observation) -------

    /// Guided config (an extent domain aligned to the grid granularity;
    /// the lease floor is the engine-internal sub-block constant block/4 —
    /// no configured min-chunk anymore).
    fn guided_cfg(max_blocks: u64) -> crate::scheduler::GuidedConfig {
        crate::scheduler::GuidedConfig {
            block_size: MIN_BLOCK_SIZE,
            max_chunk: max_blocks * MIN_BLOCK_SIZE,
        }
    }

    /// Drain driver (fixtures drive the decision face directly): acquire
    /// until the pool is empty and report every block each extent spans
    /// (the equivalent of whole-extent completion under whole-block leases —
    /// under sub-block-granularity leases shared blocks are closed by both
    /// parties, so this drives the decision face directly to simulate an
    /// ideal owner). Returns the drain rounds.
    async fn drain_pool(handle: &CoordinatorHandle, source: u32, grid_ref: &BlockGrid) -> usize {
        let mut rounds = 0;
        while let Some(a) = handle
            .acquire(source)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
        {
            let (f, l) = grid_ref
                .blocks_spanned(&a.extent)
                .unwrap_or_else(|| panic!("extent must be in-grid: {:?}", a.extent));
            for b in f..=l {
                handle
                    .complete_block(b)
                    .await
                    .unwrap_or_else(|e| panic!("complete: {e}"));
            }
            rounds += 1;
        }
        rounds
    }

    /// Seeded rate book (EWMA established, the rate lease term untied from
    /// slices): keeps allocation sizing in the guided-term-dominated
    /// multi-block in-flight fixture regime — the block-granularity lease
    /// semantics of the unestablished-EWMA period are pinned by scheduler's
    /// compose_len table; these tests focus on the W snapshot / steal /
    /// abandon / share mechanics themselves.
    fn seeded_rates(n: u32) -> crate::rate::SourceRateBook {
        crate::rate::SourceRateBook::seed_established(
            &(0..n)
                .map(|s| (s, 64.0 * MIN_BLOCK_SIZE as f64))
                .collect::<Vec<_>>(),
        )
    }

    /// Test AIMD config: cap 16, default eval window (wiring tests use
    /// their own small-window configs — the actor does not validate the
    /// window domain; the observation cadence is up to the test).
    fn aimd_test_cfg() -> AimdConfig {
        AimdConfig::new(16)
    }

    /// W snapshot semantics ("active_workers is the allocation-time
    /// snapshot"): allocation registers in-flight -> W grows; block
    /// decisions complete -> W shrinks; with in-flight empty it returns to
    /// W=1 pure guided splitting. All lengths block aligned.
    #[tokio::test]
    async fn dynamic_w_snapshot_grows_and_recovers() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 32u64;
        let total = blocks * bs;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(blocks), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001601",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            4,
            Duration::from_secs(15),
            aimd_test_cfg(),
            seeded_rates(4),
        );

        // Block 0 special case (1-block granularity).
        let a0 = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        assert_eq!(
            a0.extent.len, bs,
            "the head block claims 1-block granularity first"
        );

        // W=2: remaining 31bs -> guided 31/4 = 7.75 blocks (the sub-block
        // domain; no longer clamped back to 7).
        let a1 = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a1"));
        assert_eq!(
            a1.extent.len,
            31 * bs / 4,
            "W=2 guided split (sub-block aligned)"
        );

        // W=3: remaining 23.25bs -> guided 23.25/6 = 3.875 blocks -> sub-block
        // aligned to 3.75 blocks.
        let a2 = handle
            .acquire(2)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a2"));
        assert_eq!(a2.extent.len, 15 * bs / 4, "W=3 shrink (sub-block aligned)");

        // a1 fully decided -> in-flight is head + a2 (W=3): remaining 19.5bs
        // -> 19.5/6 = 3.25 blocks.
        let (f, l) = (a1.extent.start / bs, (a1.extent.end() - 1) / bs);
        for b in f..=l {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        let a3 = handle
            .acquire(3)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a3"));
        assert_eq!(
            a3.extent.len,
            13 * bs / 4,
            "W shrinks as in-flight accounting takes effect"
        );

        // In-flight cleared (head + a2 + a3 all decided) -> back to W=1:
        // remaining 16.25bs -> guided 8.125 blocks -> sub-block aligned 8
        // blocks (a pure guided half-pool split).
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let (f, l) = (a2.extent.start / bs, (a2.extent.end() - 1) / bs);
        for b in f..=l {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        let (f, l) = (a3.extent.start / bs, (a3.extent.end() - 1) / bs);
        for b in f..=l {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        let a4 = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a4"));
        assert_eq!(
            a4.extent.len,
            8 * bs,
            "after in-flight clears, W=1 half-pool split"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Abandon recovery (dynamic): decided blocks do not return to the
    /// pool (progress recorded once); unfinished blocks return and are
    /// re-split; re-claims do not repeat and final coverage is complete.
    #[tokio::test]
    async fn dynamic_abandon_restores_undone_blocks_only() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 8u64;
        let total = blocks * bs;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(blocks), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001602",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
            Duration::from_secs(15),
            aimd_test_cfg(),
            seeded_rates(4),
        );

        let _head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));

        // W=1: remaining 7bs -> guided 3.5 blocks (the
        // first half of blocks 1..=4, sub-block domain).
        let a1 = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a1"));
        assert_eq!(a1.extent.len, 7 * bs / 2);
        // Blocks 1 and 2 decided (the write face done); the watermark books 2
        // blocks via heartbeat; then it fails and abandons the unwritten rest.
        handle
            .complete_block(1)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        handle
            .complete_block(2)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let ack = handle
            .heartbeat(0, a1.seg.extent, 2 * bs)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(ack, HeartbeatAck::Continue, "the write right is still ours");
        handle
            .abandon(a1)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));

        // Re-claim: blocks 1 and 2 not repeated (decided + the watermark
        // prefix does not return to the pool); slicing resumes at block 3
        // (remaining 5bs -> guided 2.5 blocks).
        let a2 = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a2"));
        assert_eq!(
            a2.extent.start,
            3 * bs,
            "resumes from the written-byte watermark breakpoint"
        );
        assert_eq!(a2.extent.len, 5 * bs / 2);

        // Drain: all remaining blocks claimed; claimed covers the grid exactly once.
        let mut claimed = vec![0u64, 1, 2, a2.extent.start / bs, a2.extent.start / bs + 1];
        while let Some(a) = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
        {
            let first = a.extent.start / bs;
            let last = (a.extent.end() - 1) / bs;
            claimed.extend(first..=last);
        }
        claimed.sort_unstable();
        claimed.dedup();
        assert_eq!(
            claimed,
            (0..blocks).collect::<Vec<u64>>(),
            "the whole grid exactly once"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// End-to-end (dynamic): guided allocation + rate limiter sink
    /// observation reporting (RateSampleReporter -> RateSample message) +
    /// a single-point decision closed loop — multiple workers acquire ->
    /// write (observation reporting on the write path) -> report per block
    /// -> each block recorded exactly once. Rate sample messages are
    /// consumed by the actor (the loop is not blocked by the observation
    /// face).
    #[tokio::test]
    async fn dynamic_end_to_end_with_rate_reporting() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 12u64;
        let total = blocks * bs;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(4), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic(
            "8000000000001603",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            3,
            Duration::from_secs(15),
            aimd_test_cfg(),
        );

        // Observation face assembly: the rate limiter sink carries the
        // coordinator handle to report write observations. (Scope close-out:
        // throttled contains a sender — attaching the handle to the
        // observation face means the sink holds a channel sender; all must be
        // dropped before the actor closes out or rx.recv() never sees closed —
        // this test is the regression carrier for that contract.)
        let throttled = Arc::new(crate::limiter::ThrottledSink::with_rate_reporter(
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            crate::limiter::HttpLimiter::new(None),
            Arc::new(handle.clone()) as Arc<dyn crate::limiter::RateSampleReporter>,
        ));

        // Rate sample message face: try_send succeeds while the actor is alive
        // (channel-full drops are sampling semantics; at this low frequency it
        // always enqueues).
        handle
            .report_rate_sample(0, 4096, std::time::Duration::from_millis(1), Duration::ZERO)
            .unwrap_or_else(|e| panic!("rate sample: {e}"));

        let grid_ref = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let mut workers = Vec::new();
        for source in 0..3u32 {
            let handle = handle.clone();
            let throttled = Arc::clone(&throttled);
            let grid_ref = grid_ref.clone();
            workers.push(tokio::spawn(async move {
                synthetic_worker(&handle, source, throttled.as_ref(), &grid_ref).await
            }));
        }
        for w in workers {
            w.await
                .unwrap_or_else(|e| panic!("worker join: {e}"))
                .unwrap_or_else(|e| panic!("worker: {e}"));
        }
        // Close-out order: drop the rate limiter sink (with its observation
        // face sender) first, then the handle — only a closed channel lets the
        // actor end.
        drop(throttled);
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        let mut completions = sink.completions();
        completions.sort_unstable();
        assert_eq!(
            completions,
            (0..blocks).collect::<Vec<u64>>(),
            "each block exactly once"
        );
        assert!(
            sink.write_calls.load(Ordering::Relaxed) > 0,
            "the write path goes through the throttled sink (the observation reporting point)"
        );
    }

    /// Observation reporting lifecycle: report_rate_sample succeeds while
    /// the actor is alive; after the bookkeeping fault ends the actor (the
    /// actor is stopped but the handle remains) it reports the stopped
    /// face — no hang, no false negative. (Note: the handle is the channel
    /// sender; while any handle lives the actor cannot close out from
    /// idleness — the only reachable stopped path is a bookkeeping fault,
    /// same as the static face.)
    #[tokio::test]
    async fn rate_sample_lifecycle_ok_then_coordinator_stopped() {
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(bs, &guided_cfg(1), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(true)); // inject a bookkeeping fault
        let (handle, actor) = spawn_dynamic(
            "8000000000001604",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
            Duration::from_secs(15),
            aimd_test_cfg(),
        );

        // Actor alive: the sample enqueues.
        handle
            .report_rate_sample(0, 4096, std::time::Duration::ZERO, Duration::ZERO)
            .unwrap_or_else(|e| panic!("rate sample while alive: {e}"));

        // Bookkeeping fault -> the actor ends with a
        // task-level error; the handle face turns to stopped.
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let outcome = actor.await.unwrap_or_else(|e| panic!("actor join: {e}"));
        assert!(
            outcome.is_err(),
            "an injected fault must close out as a task-level error"
        );
        assert!(matches!(
            handle.report_rate_sample(0, 1, std::time::Duration::ZERO, Duration::ZERO),
            Err(HttpError::CoordinatorStopped)
        ));
    }

    // ---------- endgame degradation + steal ban ----------

    /// Claim one extent and report all blocks it covers (a deterministic
    /// driver: in-flight is cleared before the next claim, so the
    /// allocation sequence does not depend on concurrency timing).
    /// Returns the allocation's block range.
    async fn acquire_and_complete(
        handle: &CoordinatorHandle,
        source: u32,
        grid_ref: &BlockGrid,
    ) -> Option<(u64, u64)> {
        let alloc = handle
            .acquire(source)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))?;
        let (first, last) = grid_ref
            .blocks_spanned(&alloc.extent)
            .unwrap_or_else(|| panic!("allocation must be in-grid: {:?}", alloc.extent));
        for b in first..=last {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        Some((first, last))
    }

    /// Endgame degradation (the allocation arm): once pool remaining blocks
    /// < workers, allocations are always a single sub-block (bypassing the
    /// composition formula; endgame fragmentation lands in the sub-block
    /// domain — every worker can always claim work); before that the
    /// guided granularity holds; exhaustion closes out None; the whole
    /// grid is covered exactly once.
    #[tokio::test]
    async fn endgame_degrades_to_single_block_allocations() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 10u64;
        let total = blocks * bs;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001701",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            4,
            Duration::from_secs(15),
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        // Not endgame: guided granularity (head 1 block -> 4.5 blocks -> 2.25 blocks).
        let (f0, l0) = acquire_and_complete(&handle, 0, &grid_ref)
            .await
            .unwrap_or_else(|| panic!("head"));
        assert_eq!((f0, l0), (0, 0), "the head block is 1 block granule");
        let a1 = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a1"));
        assert_eq!(
            a1.extent.len,
            9 * bs / 2,
            "W=1 guided half-pool split (9bs/2)"
        );
        let (f, l) = grid_ref
            .blocks_spanned(&a1.extent)
            .unwrap_or_else(|| panic!("cover"));
        for b in f..=l {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        let a2 = handle
            .acquire(2)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a2"));
        assert_eq!(
            a2.extent.len,
            9 * bs / 4,
            "a 4.5-block pool (>= workers) still at guided granularity"
        );
        let (f, l) = grid_ref
            .blocks_spanned(&a2.extent)
            .unwrap_or_else(|| panic!("cover"));
        for b in f..=l {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }

        // Pool 2.25 blocks < workers(4) -> endgame: allocations are single sub-blocks from here on.
        let mut claimed: Vec<u64> = vec![0, 1, 2, 3, 4, 5, 6];
        let mut source = 3u32;
        let g = crate::scheduler::sub_block_granule(bs);
        while let Some((f, l)) = acquire_and_complete(&handle, source, &grid_ref).await {
            assert_eq!(
                f, l,
                "endgame allocations are always single sub-blocks \
                 (<= 1-block domain): blocks {f}..={l}"
            );
            claimed.extend(f..=l);
            source = (source + 1) % 4;
        }
        let _ = g;
        claimed.sort_unstable();
        claimed.dedup();
        assert_eq!(
            claimed,
            (0..blocks).collect::<Vec<u64>>(),
            "the whole grid exactly once"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
        let mut completions = sink.completions();
        completions.sort_unstable();
        assert_eq!(
            completions,
            (0..blocks).collect::<Vec<u64>>(),
            "each block booked exactly once"
        );
    }

    /// Steal-ban boundary (denied at the single decision point): during
    /// endgame a steal request always gets DeniedEndgame — decided in the
    /// actor at the same serial point as block completion; outside
    /// endgame without stall evidence (no in-flight extent with a full
    /// window of heartbeat zero growth) it gets DeniedNoStallEvidence;
    /// static mode approximates with the unallocated extent count to the
    /// same close-out; denials never harm the allocation face.
    #[tokio::test]
    async fn steal_request_refused_at_single_adjudication_point() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 10u64;
        let total = blocks * bs;

        // dynamic: pool full (10 blocks >= workers 4) -> the non-endgame denial face.
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001702",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            4,
            Duration::from_secs(15),
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        let v = handle
            .request_steal(3)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert_eq!(
            v,
            StealVerdict::DeniedNoStallEvidence,
            "non-endgame: no stall evidence, no grant (no pretending to allow)"
        );

        // Drain to pool 3 blocks < workers: head + a 4-block
        // slice + a 2-block slice (7 blocks on record).
        let _ = acquire_and_complete(&handle, 0, &grid_ref).await;
        let a1 = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a1"));
        let (f, l) = grid_ref
            .blocks_spanned(&a1.extent)
            .unwrap_or_else(|| panic!("cover"));
        for b in f..=l {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        let a2 = handle
            .acquire(2)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a2"));
        let (f, l) = grid_ref
            .blocks_spanned(&a2.extent)
            .unwrap_or_else(|| panic!("cover"));
        for b in f..=l {
            handle
                .complete_block(b)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }

        // endgame: the steal request is denied at the single decision point (anti-thrash/livelock).
        let v = handle
            .request_steal(2)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert_eq!(v, StealVerdict::DeniedEndgame, "endgame always denies");

        // Denials do not harm the allocation face: endgame
        // allocations keep advancing as single sub-blocks.
        let a3 = handle
            .acquire(3)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a3"));
        assert_eq!(
            a3.extent.len,
            crate::scheduler::sub_block_granule(bs),
            "allocations during endgame are still single usable sub-blocks"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        // static: 6 unallocated extents (>= workers 4) -> the non-endgame
        // denial face; after claiming 3, 3 < 4 -> endgame denial (granularity
        // does not degrade — static has no pool to fragment; the steal-ban
        // boundary closes in sync).
        let cfg = crate::scheduler::SchedulerConfig {
            block_size: bs,
            split: 5,
            min_split_size: bs,
            ..crate::scheduler::SchedulerConfig::default()
        };
        let splan = crate::scheduler::StaticPlan::build(total, &cfg)
            .unwrap_or_else(|e| panic!("static plan: {e}"));
        let sgrid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let (shandle, sactor) = spawn(
            "8000000000001703",
            sgrid,
            splan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            4,
        );
        let v = shandle
            .request_steal(0)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert_eq!(v, StealVerdict::DeniedNoStallEvidence);
        for _ in 0..3 {
            let _ = shandle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"));
        }
        let v = shandle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert_eq!(
            v,
            StealVerdict::DeniedEndgame,
            "static tail segments close out in sync"
        );

        drop(shandle);
        sactor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    // ---------------- stall steal----------------

    /// Heartbeat reply decision table: registered and ownership ours ->
    /// Continue (growth feeds stall detection); ownership elsewhere /
    /// extent not registered (completed and deregistered / unknown
    /// number) -> Cancelled (nothing left to write).
    #[tokio::test]
    async fn heartbeat_ack_decision_table() {
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, 4 * bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(4 * bs, &guided_cfg(2), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic(
            "8000000000001801",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            Duration::from_secs(15),
            aimd_test_cfg(),
        );

        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        assert_eq!(head.seg.extent, 0, "the head block = extent 0");

        // Registered + ownership ours + growth -> Continue.
        let ack = handle
            .heartbeat(0, head.seg.extent, 100)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(ack, HeartbeatAck::Continue);

        // Ownership elsewhere (this extent's registered owner is 0) -> Cancelled.
        let ack = handle
            .heartbeat(1, head.seg.extent, 100)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(ack, HeartbeatAck::Cancelled, "a non-owner gets Cancelled");

        // Unknown extent number (not registered) -> Cancelled.
        let ack = handle
            .heartbeat(0, 99, 100)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(
            ack,
            HeartbeatAck::Cancelled,
            "an unregistered extent gets Cancelled"
        );

        // Deregistered after all blocks decided -> Cancelled (nothing left to write).
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let ack = handle
            .heartbeat(0, head.seg.extent, 0)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(
            ack,
            HeartbeatAck::Cancelled,
            "after deregistration gets Cancelled"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The grant point = the written-byte watermark break point (pinned by
    /// the wire/bookkeeping decoupling decision face): the owner's
    /// watermark covers 2 blocks (booked via heartbeat), then it stalls —
    /// the stolen range is exactly [3bs, extent end). After the transfer
    /// the owner's heartbeat gets Cancelled; a grant resets the stall
    /// baseline (concurrent steal requests never double grant); the stolen
    /// tail is recorded by the thief and the grid is covered exactly once.
    #[tokio::test]
    async fn stall_steal_grant_starts_at_last_acked_plus_one() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 10u64;
        let total = blocks * bs;
        let window = Duration::from_millis(100);
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001802",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        // Owner (source 0): head (block 0) + a 4.5-block
        // slice (the first half of blocks 1..=5, seq 1).
        handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));
        assert_eq!(held.seg.extent, 1);
        assert_eq!(
            held.extent,
            Extent {
                start: bs,
                len: 9 * bs / 2
            },
            "W=1 guided half-pool split ([bs, 5.5bs))"
        );

        // The idle side (source 1) drains the pool (all other in-flight closed out).
        let _ = drain_pool(&handle, 1, &grid_ref).await;

        // The owner's watermark covers 2 blocks (blocks 1 and 2 decided +
        // booked via heartbeat), then it stalls: one growth heartbeat, then
        // silence (a hung transport shape — silence and zero growth are
        // judged the same).
        handle
            .complete_block(1)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        handle
            .complete_block(2)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let ack = handle
            .heartbeat(0, held.seg.extent, 2 * bs)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(
            ack,
            HeartbeatAck::Continue,
            "the write right is still ours before the silence"
        );
        tokio::time::sleep(window + Duration::from_millis(60)).await;

        // Steal decision: the granted range = [written-byte watermark, extent end) = [3bs, 5.5bs).
        let verdict = handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        let stolen = match verdict {
            StealVerdict::Approved(a) => a,
            other => panic!("stall evidence standing must grant, got {other:?}"),
        };
        assert_eq!(
            stolen.extent,
            Extent {
                start: 3 * bs,
                len: 5 * bs / 2
            },
            "the steal point = the written-byte watermark breakpoint (2 blocks booked)"
        );
        assert_eq!(
            stolen.seg.extent, held.seg.extent,
            "the extent sequence number keeps the original"
        );
        assert_eq!(stolen.seg.source, 1, "SegId.source = the stealer");

        // A grant resets the stall baseline: an immediately
        // following third-party steal request must not double grant.
        let again = handle
            .request_steal(2)
            .await
            .unwrap_or_else(|e| panic!("steal again: {e}"));
        assert_eq!(
            again,
            StealVerdict::DeniedNoStallEvidence,
            "the same evidence does not grant twice (a full-window grace for the new write owner)"
        );

        // The thief finishes the tail; once the owner wakes its heartbeat
        // is cancelled (stop writing past the watermark break point).
        for block in 3..5u64 {
            handle
                .complete_block(block)
                .await
                .unwrap_or_else(|e| panic!("thief complete: {e}"));
        }
        let ack = handle
            .heartbeat(0, held.seg.extent, 0)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(
            ack,
            HeartbeatAck::Cancelled,
            "the owner gets Cancelled at the next block boundary"
        );

        // Owner turns idle: pool empty and in-flight closed
        // -> the endgame steal ban (total live 0 < 2).
        assert!(
            handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .is_none()
        );
        let v = handle
            .request_steal(0)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert_eq!(
            v,
            StealVerdict::DeniedEndgame,
            "total active drained = the endgame forbidden zone"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        let mut completions = sink.completions();
        completions.sort_unstable();
        completions.dedup();
        assert_eq!(
            completions,
            (0..blocks).collect::<Vec<u64>>(),
            "the stolen tail segment is booked to the stealer, \
             the whole grid exactly once (the decision face's first-arrival-wins)"
        );
    }

    /// Slow-alive false-positive check (rate-independent semantics — only
    /// a full window of byte zero growth counts as stalled): while a
    /// normally slow source keeps making small growth, repeated steal
    /// requests are always denied and the owner's heartbeats keep returning
    /// Continue; after a real full window of silence the same decision face
    /// grants (positive control — proving the denial is evidence-driven,
    /// not unconditional).
    #[tokio::test]
    async fn slow_alive_source_is_never_stolen() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 8u64;
        let total = blocks * bs;
        let window = Duration::from_millis(200);
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001803",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        // Owner (source 0): head + a 3.5-block slice ([bs, 4.5bs)).
        handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));

        // The idle side (source 1) empties the pool.
        let _ = drain_pool(&handle, 1, &grid_ref).await;
        // Owner decides block 1 (then crawls slowly — growth heartbeats show it writing).
        handle
            .complete_block(1)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));

        // Slow source: one growth heartbeat every 30ms (far faster than the
        // 200ms window) for 500ms; steal requests are repeatedly denied
        // meanwhile.
        let hb = handle.clone();
        let extent_seq = held.seg.extent;
        // Exactly 15 beats (450ms < 6x80ms main-loop window): covered is deterministically 120.
        let ticker = tokio::spawn(async move {
            for i in 0..15u32 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                let ack = hb.heartbeat(0, extent_seq, u64::from(i) + 1).await;
                if ack.is_err() {
                    break; // the actor ended (test tail); heartbeats stop naturally.
                }
            }
        });
        for round in 0..6u32 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let v = handle
                .request_steal(1)
                .await
                .unwrap_or_else(|e| panic!("steal round {round}: {e}"));
            assert_eq!(
                v,
                StealVerdict::DeniedNoStallEvidence,
                "round {round}: a slow source that is writing \
                 must not judge stalled (rate-independent)"
            );
        }
        ticker.abort();

        // Positive control: a real full window of silence -> the same decision
        // face grants (start = written-byte watermark = growth heartbeat total
        // 1+2+...+15 = 120 bytes).
        tokio::time::sleep(window + Duration::from_millis(100)).await;
        let verdict = handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        match verdict {
            StealVerdict::Approved(a) => assert_eq!(
                a.extent,
                Extent {
                    start: bs + 120,
                    len: 7 * bs / 2 - 120
                },
                "after a full silent window grants [written watermark, extent end)"
            ),
            other => panic!("a full silent window must grant, got {other:?}"),
        }

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
        assert!(
            sink.completions().contains(&0),
            "the decision chain is undisturbed by steal requests"
        );
    }

    /// Rate-limit wait exclusion (the mis-steal shape of rate limiting):
    /// byte growth is zero for a full window but the owner source's
    /// rate-limit permit waits keep arriving (the falsified-evidence shape
    /// of a low rate limit stretching chunk gaps past the stall window) ->
    /// steals are always denied; once the waits stop and the activity
    /// shadow expires, the same zero-growth evidence grants (positive
    /// control — the exclusion does not over-reject: a server that really
    /// stops is still stolen from).
    #[tokio::test]
    async fn rate_limit_permit_waits_veto_falsified_stall_evidence() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 8u64;
        let total = blocks * bs;
        let window = Duration::from_millis(400);
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001805",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        // Owner (source 0): head + a 3.5-block slice ([bs,
        // 4.5bs)); the idle side (source 1) drains the pool.
        handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));
        // The idle side (source 1) empties the pool.
        let _ = drain_pool(&handle, 1, &grid_ref).await;

        // Rate-limit throttling shape: the owner sends zero-growth heartbeat
        // pings as usual (stall evidence maturing) while rate-limit permit
        // waits keep arriving (each waited = 200ms, above the noise floor; the
        // shadow window = max(400ms, 200ms) is constantly refreshed by the
        // latest one) — after 12 beats x 60ms the evidence is past a full
        // window but the activity shadow is in place.
        for round in 0..12u32 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            handle
                .report_rate_sample(0, 64, Duration::from_millis(200), Duration::ZERO)
                .unwrap_or_else(|e| panic!("sample round {round}: {e}"));
            let ack = handle
                .heartbeat(0, held.seg.extent, 0)
                .await
                .unwrap_or_else(|e| panic!("heartbeat round {round}: {e}"));
            assert_eq!(
                ack,
                HeartbeatAck::Continue,
                "round {round}: the write right is still ours"
            );
        }
        let v = handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert_eq!(
            v,
            StealVerdict::DeniedNoStallEvidence,
            "zero growth inside the throttle-wait shadow is not stall evidence \
             (the forged-evidence shape of a low-throttle chunk interval > the stall window)"
        );

        // Positive control: waits stop -> the shadow expires (> max(window,
        // waited)) -> the same zero-growth evidence grants (the owner's
        // written watermark is 0 -> start = the extent's first byte).
        tokio::time::sleep(window + Duration::from_millis(120)).await;
        let verdict = handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        match verdict {
            StealVerdict::Approved(a) => {
                assert_eq!(
                    a.seg.extent, held.seg.extent,
                    "the extent sequence number keeps the original"
                );
                assert_eq!(
                    a.extent,
                    Extent {
                        start: bs,
                        len: 7 * bs / 2
                    },
                    "after the shadow expires grants [first byte, extent end)"
                );
            }
            other => panic!("stall evidence must stand after the shadow expires, got {other:?}"),
        }

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    // ------ multi-source allocation (demote/remove/failover/weights) ------

    /// Guided config for multi-source tests (a grid-granularity domain for a `max_blocks` total).
    fn multi_plan(
        blocks: u64,
        max_chunk_blocks: u64,
    ) -> (BlockGrid, crate::scheduler::GuidedPlan, BlockGrid) {
        let total = blocks * MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(MIN_BLOCK_SIZE, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan =
            crate::scheduler::GuidedPlan::build(total, &guided_cfg(max_chunk_blocks), &|_| false)
                .unwrap_or_else(|e| panic!("plan: {e}"));
        let grid_ref =
            BlockGrid::new(MIN_BLOCK_SIZE, total).unwrap_or_else(|e| panic!("grid: {e}"));
        (grid, plan, grid_ref)
    }

    /// Source health snapshot query (the reconciliation face: state + windowed failure count).
    async fn source_states(
        handle: &CoordinatorHandle,
    ) -> Vec<(u32, crate::sources::SourceState, u32)> {
        handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"))
            .source_states
    }

    /// Demote/remove threshold wiring (3 windowed extent failures demote,
    /// 5 remove) + removal close-out + the no_source negative (session
    /// failure propagates via the core driver side's `acquire` Err):
    /// each current-owner Abandon counts — the 3rd demotes (allocations
    /// clamped to min-chunk level), the 5th removes (Acquire closes out
    /// None); with both sources removed and pool work remaining ->
    /// `taiji.http.no_source`.
    #[tokio::test]
    async fn multi_source_demote_remove_and_no_source() {
        let (grid, plan, _grid_ref) = multi_plan(6, 6);
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_multi(
            "8000000000002401",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            Duration::from_secs(15),
            aimd_test_cfg(),
            2,
        );

        // Two abandons in a row: still Active (no transition).
        for _ in 0..2 {
            let a = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            handle
                .abandon(a)
                .await
                .unwrap_or_else(|e| panic!("abandon: {e}"));
        }
        assert_eq!(
            source_states(&handle).await,
            vec![
                (0, crate::sources::SourceState::Active, 0),
                (1, crate::sources::SourceState::Active, 2)
            ],
        );

        // The 3rd: demotion transition.
        let a = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        handle
            .abandon(a)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));
        assert_eq!(
            source_states(&handle).await[1],
            (1, crate::sources::SourceState::Demoted, 3),
        );

        // The 4th and 5th: the 5th removes -> the source's Acquire closes out None.
        for _ in 0..2 {
            let a = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            handle
                .abandon(a)
                .await
                .unwrap_or_else(|e| panic!("abandon: {e}"));
        }
        assert_eq!(
            source_states(&handle).await[1],
            (1, crate::sources::SourceState::Removed, 5),
        );
        assert!(
            handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .is_none(),
            "a removed source's Acquire closes out \
             (the surviving sources take over its unfinished blocks)"
        );

        // Source 0 allocates normally (removal does not affect survivors);
        // after 5 consecutive failures all sources are removed; with pool work
        // remaining -> Acquire gets the task-level no_source negative.
        assert!(
            handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .is_some()
        );
        for _ in 0..5 {
            let a = handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            handle
                .abandon(a)
                .await
                .unwrap_or_else(|e| panic!("abandon: {e}"));
        }
        let err = match handle.acquire(0).await {
            Err(e) => e,
            Ok(None) => panic!("all removed + pool surplus must be no_source, got None"),
            Ok(Some(_)) => panic!("all removed + pool surplus must be no_source, got allocation"),
        };
        assert_eq!(err.code(), "taiji.http.no_source");
        assert_eq!(
            source_states(&handle).await,
            vec![
                (0, crate::sources::SourceState::Removed, 5),
                (1, crate::sources::SourceState::Removed, 5)
            ],
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// A removed source's steal requests are always denied (re-entry
    /// blockage during the removal landing window): source removal takes
    /// effect at the ledger transition, while the worker pool's expectation
    /// decrease lands via the driver's tick snapshot — inside that window a
    /// parked worker's in-flight steal request can arrive before the pool
    /// update, so the decision-face entry re-checks the ledger's terminal
    /// state and always denies (the decision half of the "removed sources
    /// must not re-enter by stealing" invariant); surviving sources are
    /// still granted on the same stall evidence (the removal gate does not
    /// over-apply).
    #[tokio::test]
    async fn removed_source_steal_request_is_always_denied() {
        let (grid, plan, _grid_ref) = multi_plan(12, 12);
        let sink = Arc::new(RecordingSink::new(false));
        let window = Duration::from_millis(200);
        let (handle, actor) = spawn_dynamic_multi(
            "8000000000002407",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            3,
            window,
            aimd_test_cfg(),
            3,
        );

        // Owner (source 1): head + a 5-block in-flight extent (blocks 1..=5,
        // the stall-evidence carrier); source 0 claims 1 block in flight;
        // source 2 claims 1 block then goes to failure removal.
        handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));
        assert_eq!(held.seg.extent, 1);
        let _idle = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("idle alloc"));
        let doomed = handle
            .acquire(2)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("doomed alloc"));

        // Source 2's current owner abandons x5 -> windowed
        // failures reach the removal threshold -> Removed.
        handle
            .abandon(doomed)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));
        for _ in 0..4 {
            let a = handle
                .acquire(2)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("removal cycle alloc"));
            handle
                .abandon(a)
                .await
                .unwrap_or_else(|e| panic!("abandon: {e}"));
        }
        assert_eq!(
            source_states(&handle).await[2],
            (2, crate::sources::SourceState::Removed, 5),
            "the removal transition takes effect in the ledger immediately"
        );

        // Source 1's in-flight extent stalls a full window
        // (no heartbeat = a full window of zero growth).
        tokio::time::sleep(window + Duration::from_millis(120)).await;

        // Removed source 2's steal request is always denied — even though
        // stall evidence holds and the target is not its own in-flight
        // (without this gate a parked worker could re-enter writing by
        // stealing).
        let v = handle
            .request_steal(2)
            .await
            .unwrap_or_else(|e| panic!("steal from removed: {e}"));
        assert_eq!(
            v,
            StealVerdict::DeniedNoStallEvidence,
            "a removed source's steal requests are always denied (blocking re-entry)"
        );

        // Surviving source 0 is granted as usual on the same
        // evidence (the removal gate does not over-apply).
        let v = handle
            .request_steal(0)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert!(
            matches!(v, StealVerdict::Approved(_)),
            "surviving sources' steals are unaffected by the removal gate: {v:?}"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Success reports enter the window and recovery (the windowed failure
    /// rate view): an isolated failure does not demote (a healthy source
    /// tolerates flapping); demotion requires windowed failures to reach
    /// the threshold; a demoted source recovers only when windowed
    /// failures fall below the threshold (an isolated success does not
    /// clear the record — failure-success flapping must not evade demotion,
    /// see [`crate::sources::OUTCOME_WINDOW`]). ExtentSucceeded message
    /// wiring.
    #[tokio::test]
    async fn extent_success_resets_failure_streak_and_recovers_demotion() {
        let (grid, plan, _grid_ref) = multi_plan(6, 6);
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_multi(
            "8000000000002402",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            Duration::from_secs(15),
            aimd_test_cfg(),
            2,
        );

        // Isolated-failure tolerance: failure-success interleaving (2 windowed
        // failures < threshold) -> stays Active (a plain "consecutive" count
        // would be reset by the successes and never demote — under the window
        // view an isolated success also does not clear the record; the
        // threshold is just not reached yet).
        for _ in 0..2 {
            let a = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            handle
                .abandon(a)
                .await
                .unwrap_or_else(|e| panic!("abandon: {e}"));
            handle
                .extent_succeeded(1)
                .await
                .unwrap_or_else(|e| panic!("succeeded: {e}"));
        }
        assert_eq!(
            source_states(&handle).await[1],
            (1, crate::sources::SourceState::Active, 2),
            "in-window failures 2 (an isolated success does not clear the account, \
             but the demotion threshold is not reached either)"
        );

        // Windowed failures reach 3 -> demoted; an isolated success does not
        // clear the record (windowed failures still >= 3) -> no recovery;
        // successes push failures out of the window (below the threshold) ->
        // recovery.
        let a = handle
            .acquire(1)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        handle
            .abandon(a)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));
        assert_eq!(
            source_states(&handle).await[1],
            (1, crate::sources::SourceState::Demoted, 3),
        );
        handle
            .extent_succeeded(1)
            .await
            .unwrap_or_else(|e| panic!("succeeded: {e}"));
        assert_eq!(
            source_states(&handle).await[1],
            (1, crate::sources::SourceState::Demoted, 3),
            "an isolated success does not clear the account \
             (no recovery while in-window failures >= the demotion threshold)"
        );
        for _ in 0..4 {
            handle
                .extent_succeeded(1)
                .await
                .unwrap_or_else(|e| panic!("succeeded: {e}"));
        }
        assert_eq!(
            source_states(&handle).await[1],
            (1, crate::sources::SourceState::Active, 2),
            "successes push in-window failures out of the window (< 3) -> demotion recovers"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Failover: after a failed source is removed by 5 consecutive extent
    /// failures, its abandoned unfinished blocks are completed by the
    /// survivors — the whole grid recorded exactly once (reuses the
    /// Abandon pool-return semantics, no new transfer mechanism).
    #[tokio::test]
    async fn failover_reassigns_failed_source_work_to_survivors() {
        let blocks = 8u64;
        let (grid, plan, grid_ref) = multi_plan(blocks, 4);
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_multi(
            "8000000000002403",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            Duration::from_secs(15),
            aimd_test_cfg(),
            2,
        );

        // Source 1: 5 consecutive extent failures (abandon returns to the pool) -> removed.
        for _ in 0..5 {
            let a = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            handle
                .abandon(a)
                .await
                .unwrap_or_else(|e| panic!("abandon: {e}"));
        }
        assert_eq!(
            source_states(&handle).await[1],
            (1, crate::sources::SourceState::Removed, 5),
        );
        assert!(
            handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .is_none(),
            "the removed source closes out"
        );

        // The survivor (source 0) takes over all remaining work to
        // close-out — including the blocks source 1 repeatedly abandoned.
        while acquire_and_complete(&handle, 0, &grid_ref).await.is_some() {}
        assert!(
            handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .is_none(),
            "pool drained and closed out \
             (no no_source — the completion face is not wrongly hit by all-removed)"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
        let mut completions = sink.completions();
        completions.sort_unstable();
        assert_eq!(
            completions,
            (0..blocks).collect::<Vec<u64>>(),
            "after failover the whole grid is booked exactly once"
        );
    }

    /// A stale owner's abandon after a steal does not count as a source
    /// failure (the counting-face boundary): an owner handing back its
    /// original allocation after ownership transferred = the tail of the
    /// transfer, not a transport failure — source 0's count stays 0 and
    /// the state stays Active.
    #[tokio::test]
    async fn stale_owner_abandon_after_steal_not_counted_as_failure() {
        let window = Duration::from_millis(100);
        let (grid, plan, _grid_ref) = multi_plan(10, 8);
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_multi_with_rates(
            "8000000000002404",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            aimd_test_cfg(),
            2,
            seeded_rates(2),
        );

        // Owner (source 0): head + a 4-block slice; decides 2 blocks then stalls silently.
        let _head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("alloc"));
        handle
            .complete_block(1)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        handle
            .complete_block(2)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let ack = handle
            .heartbeat(0, held.seg.extent, MIN_BLOCK_SIZE)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(ack, HeartbeatAck::Continue);
        tokio::time::sleep(window + Duration::from_millis(60)).await;

        // The thief (source 1) obtains tail write ownership.
        let verdict = handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert!(matches!(verdict, StealVerdict::Approved(_)));

        // The stale owner (source 0) abandons the original
        // allocation: not counted as a source failure.
        handle
            .abandon(held)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));
        assert_eq!(
            source_states(&handle).await,
            vec![
                (0, crate::sources::SourceState::Active, 0),
                (1, crate::sources::SourceState::Active, 0),
            ],
            "a stale write owner's abandon does not count as an extent failure"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The demotion effect on weighted share arbitration (a controlled
    /// experiment quantifying demotion on the allocation face): from the
    /// same pool state (head completed + 32bs in-flight holdings), an
    /// Active source claims 15bs by the formula value; after its weight is
    /// halved the same-position allocation is clamped to min-chunk — the
    /// halved share is directly visible. The abandon-driven demotion loop
    /// is pool-neutral (takes out and returns the same amount), so both
    /// runs see the same pool state at the e2 point.
    #[tokio::test]
    async fn demotion_shrinks_allocation_share() {
        async fn run(demote: bool, gid: &'static str) -> u64 {
            let (grid, plan, _grid_ref) = multi_plan(96, 32);
            let sink = Arc::new(RecordingSink::new(false));
            let (handle, actor) = spawn_dynamic_multi_with_rates(
                gid,
                grid,
                plan,
                Arc::clone(&sink) as Arc<dyn SegmentSink>,
                2,
                Duration::from_secs(15),
                aimd_test_cfg(),
                2,
                seeded_rates(2),
            );
            // Source 0 completes head (block 0); afterwards only source 1 holds in-flight work.
            let head = handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            assert_eq!(head.extent.len, MIN_BLOCK_SIZE, "the head is 1 block");
            handle
                .complete_block(0)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));

            // Source 1 claims 32bs of in-flight holdings (e1).
            let e1 = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            assert_eq!(
                e1.extent.len,
                32 * MIN_BLOCK_SIZE,
                "W=1 claims a full max-chunk"
            );

            if demote {
                // 3 abandon rounds demote (each takes 15bs and returns 15bs; pool-neutral).
                for _ in 0..3 {
                    let a = handle
                        .acquire(1)
                        .await
                        .unwrap_or_else(|e| panic!("acquire: {e}"))
                        .unwrap_or_else(|| panic!("alloc"));
                    handle
                        .abandon(a)
                        .await
                        .unwrap_or_else(|e| panic!("abandon: {e}"));
                }
                assert_eq!(
                    source_states(&handle).await[1],
                    (1, crate::sources::SourceState::Demoted, 3),
                );
            }

            // Same position e2: pool 63bs, holdings 32bs, W=2.
            let e2 = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            drop(handle);
            actor
                .await
                .unwrap_or_else(|e| panic!("actor join: {e}"))
                .unwrap_or_else(|e| panic!("actor: {e}"));
            e2.extent.len
        }
        let active = run(false, "8000000000002405").await;
        let demoted = run(true, "8000000000002406").await;
        assert_eq!(
            active,
            62 * MIN_BLOCK_SIZE / 4,
            "Active: the 15.5bs share cap fully claimed (the share cap is sub-block aligned)"
        );
        assert_eq!(
            demoted,
            MIN_BLOCK_SIZE / 4,
            "Demoted: the halved share exhausts -> clamped to the sub-block floor (min-granule)"
        );
    }

    /// EWMA-weighted rotation ("fast sources claim more"): seeded rates
    /// 3:1 -> shares 3:1; share arbitration applies to concurrent holdings
    /// (undecided in-flight bytes). From the same claim position (source 0
    /// first, identical formula inputs), swap the weights as the control:
    /// - 3:1 favored (source 0 = fast): the first slice takes its full
    /// 8bs formula value, the next stays within the 19.5bs share as
    /// usual (the 4bs guided value);
    /// - 1:3 restricted (source 0 = slow): the first slice is clamped to
    /// 6bs by the share (6.5bs share - alignment), then 1bs crumbs —
    /// once the share is exhausted the clamp bites (the fast source
    /// takes the remainder).
    /// The only difference is the rate EWMA weight. Both directions close
    /// out with the grid covered exactly once.
    #[tokio::test]
    async fn ewma_weights_split_pool_proportionally() {
        async fn run(weights: [(u32, f64); 2], blocks: u64, gid: &'static str) -> Vec<u64> {
            let (grid, plan, grid_ref) = multi_plan(blocks, 8);
            let sink = Arc::new(RecordingSink::new(false));
            let rates = crate::rate::SourceRateBook::seed_established(&weights);
            let (handle, actor) = spawn_dynamic_multi_with_rates(
                gid,
                grid,
                plan,
                Arc::clone(&sink) as Arc<dyn SegmentSink>,
                2,
                Duration::from_secs(15),
                aimd_test_cfg(),
                2,
                rates,
            );
            // Source 1 claims and completes head (block 0): removes the block-0
            // special case from the assertion sequence — afterwards the grid is a
            // pure pool (25bs).
            let head = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            assert_eq!(head.extent.len, MIN_BLOCK_SIZE, "the head is 1 block");
            handle
                .complete_block(0)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
            // Source 0 takes the first three slices (the assertion face),
            // then both sources alternate claims until the pool is empty.
            let mut allocs: Vec<(u32, Allocation)> = Vec::new();
            let mut sizes0 = Vec::new();
            for _ in 0..3 {
                let a = handle
                    .acquire(0)
                    .await
                    .unwrap_or_else(|e| panic!("acquire: {e}"))
                    .unwrap_or_else(|| panic!("alloc"));
                sizes0.push(a.extent.len);
                allocs.push((0, a));
            }
            loop {
                let mut none = true;
                for source in 0..2u32 {
                    if let Some(a) = handle
                        .acquire(source)
                        .await
                        .unwrap_or_else(|e| panic!("acquire: {e}"))
                    {
                        none = false;
                        allocs.push((source, a));
                    }
                }
                if none {
                    break;
                }
            }
            // All held blocks completed -> the whole grid recorded exactly once.
            for (_, a) in &allocs {
                let (f, l) = grid_ref
                    .blocks_spanned(&a.extent)
                    .unwrap_or_else(|| panic!("in-grid: {:?}", a.extent));
                for b in f..=l {
                    handle
                        .complete_block(b)
                        .await
                        .unwrap_or_else(|e| panic!("complete: {e}"));
                }
            }
            drop(handle);
            actor
                .await
                .unwrap_or_else(|e| panic!("actor join: {e}"))
                .unwrap_or_else(|e| panic!("actor: {e}"));
            let mut completions = sink.completions();
            completions.sort_unstable();
            assert_eq!(
                completions,
                (0..blocks).collect::<Vec<u64>>(),
                "weighted allocation does not break the completion face's exactly-once"
            );
            sizes0
        }
        let bs = MIN_BLOCK_SIZE;
        let m = 1024.0 * 1024.0;
        // Control run (source 0 favored, 3:1 share 19.5bs): all three slices
        // are formula values (8bs / 4bs / 2bs, natural W-snapshot shrink); the
        // share never clamps.
        let favored_run = run([(0, 3.0 * m), (1, m)], 26, "8000000000002407").await;
        assert_eq!(
            favored_run,
            vec![8 * bs, 17 * bs / 4, 2 * bs],
            "the favored source's three carves are all formula values \
             (r7.0 sub-block domain, no longer clamped back to block alignment)"
        );
        // Main run (source 0 restricted, 1:3 share 6.5bs): the first slice is
        // clamped to 6bs (8bs formula value -> share alignment), then always
        // 1bs crumbs — the share is exhausted so the clamp bites, leaving the
        // remainder to the fast source.
        let underdog_run = run([(0, m), (1, 3.0 * m)], 26, "8000000000002408").await;
        assert_eq!(
            underdog_run,
            vec![25 * bs / 4, bs / 4, bs / 4],
            "the restricted source's first carve is clamped (sub-block-aligned share), \
             later carves fragment (the sub-block floor)"
        );
    }

    /// Single-source assembly assembles no source ledger (a frozen-behavior
    /// regression): 6 consecutive abandons cause no demotion/removal —
    /// allocation behavior stays byte-identical to the existing semantics;
    /// source state snapshots stay empty; success reports are no-ops.
    #[tokio::test]
    async fn legacy_single_source_spawn_has_no_source_ledger() {
        let (grid, plan, _grid_ref) = multi_plan(6, 6);
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic(
            "8000000000002409",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            Duration::from_secs(15),
            aimd_test_cfg(),
        );
        for _ in 0..6 {
            let a = handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("alloc"));
            handle
                .abandon(a)
                .await
                .unwrap_or_else(|e| panic!("abandon: {e}"));
        }
        handle
            .extent_succeeded(0)
            .await
            .unwrap_or_else(|e| panic!("succeeded: {e}"));
        let stats = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"));
        assert!(
            stats.source_states.is_empty(),
            "no ledger -> the snapshot is always empty"
        );
        assert!(
            handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .is_some(),
            "no demotion/removal — the allocation face is unaffected"
        );
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Instrumentation sink for the steal tests (byte domain): records
    /// write ranges per (source, byte range) — double-written bytes =
    /// the union of per-source written ranges minus the total (bytes
    /// covered by >= 2 sources, byte precision; "overlap 0 / waste <= 1
    /// sub-block").
    struct OverlapSink {
        ranges: Mutex<Vec<(u32, u64, u64)>>,
        completions: Mutex<Vec<u64>>,
    }

    impl OverlapSink {
        fn new() -> Self {
            OverlapSink {
                ranges: Mutex::new(Vec::new()),
                completions: Mutex::new(Vec::new()),
            }
        }

        /// Record a write range (byte range [off, off+len) attributed to `seg.source`).
        fn record_write(&self, seg: SegId, off: u64, len: u64) {
            if len == 0 {
                return;
            }
            self.ranges.lock().unwrap_or_else(|e| e.into_inner()).push((
                seg.source,
                off,
                off + len,
            ));
        }

        /// Double-written bytes: bytes written by >= 2 distinct sources (range sweep).
        fn double_written_bytes(&self) -> u64 {
            let ranges = self.ranges.lock().unwrap_or_else(|e| e.into_inner());
            let mut pts: Vec<(u64, i32)> = Vec::new();
            for (_, s, e) in ranges.iter() {
                pts.push((*s, 1));
                pts.push((*e, -1));
            }
            pts.sort_unstable();
            let mut covered2 = 0u64;
            let mut active = 0i32;
            let mut prev = 0u64;
            for (pos, d) in pts {
                if active >= 2 && pos > prev {
                    covered2 += pos - prev;
                }
                active += d;
                prev = pos;
            }
            covered2
        }

        /// Union of per-source write ranges after dedup (a directed verification face).
        fn unique_source_ranges(&self) -> usize {
            self.ranges.lock().unwrap_or_else(|e| e.into_inner()).len()
        }

        fn completions(&self) -> Vec<u64> {
            self.completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl SegmentSink for OverlapSink {
        fn write_at(
            &self,
            seg: SegId,
            off: u64,
            bytes: Bytes,
        ) -> BoxFuture<'_, crate::error::Result<()>> {
            self.record_write(seg, off, bytes.len() as u64);
            Box::pin(std::future::ready(Ok(())))
        }

        fn complete_block(&self, block: u64) -> BoxFuture<'_, crate::error::Result<()>> {
            self.completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(block);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// Instrumentation sink alias for the must-test steal cases (byte
    /// domain; per-source write ranges + double-written byte stats, the
    /// same shape as [`OverlapSink`]).
    type ByteRangeSink = OverlapSink;

    /// Stress-test synthetic worker parameters (the `stealing_worker` argument bundle).
    struct WorkerCfg {
        source: u32,
        sink: Arc<OverlapSink>,
        bs: u64,
        /// An extent pre-allocated by the test body for determinism (pins the
        /// hung block's ownership), consumed before the regular claim loop.
        pre_held: Option<Allocation>,
        /// Hang-injection block (a block-boundary transport stall: the hung
        /// block is unwritten, with no writes and no heartbeats while hung;
        /// mid-block shapes are driven by the bounded-waste test's ordering).
        hang_block: Option<u64>,
        hang_dur: Duration,
        /// Steal polling budget once the pool is empty.
        steal_polls: usize,
        /// Observed cancel replies accumulated (evidence that
        /// stealing really happened and the cancel was delivered).
        cancels: Arc<AtomicU64>,
    }

    /// Stress-test synthetic worker: consume `pre_held` first -> regular
    /// loop: acquire extents -> write/bookkeep/heartbeat in sub-block
    /// steps (byte domain: each sub-block records exactly one write range,
    /// heartbeat deltas = real written bytes -> the written-byte watermark
    /// is exact at block boundaries; a Cancelled reply stops writing at
    /// the watermark break point) -> steal polling once the pool empties
    /// (endgame denial closes it out).
    async fn stealing_worker(handle: CoordinatorHandle, cfg: WorkerCfg) -> Result<(), HttpError> {
        let WorkerCfg {
            source,
            sink,
            bs,
            mut pre_held,
            hang_block,
            hang_dur,
            steal_polls,
            cancels,
        } = cfg;
        let g = crate::scheduler::sub_block_granule(bs);
        let mut hung = false;
        let mut held = pre_held.take();
        loop {
            let alloc = match held.take() {
                Some(a) => a,
                None => match handle.acquire(source).await? {
                    Some(a) => a,
                    None => {
                        // Pool empty: steal polling (retry DeniedNoStallEvidence with a short
                        // backoff; DeniedEndgame = the endgame ban — nothing to steal, close
                        // out).
                        let mut granted = None;
                        for _ in 0..steal_polls {
                            match handle.request_steal(source).await? {
                                StealVerdict::Approved(a) => {
                                    granted = Some(a);
                                    break;
                                }
                                StealVerdict::DeniedEndgame => break,
                                StealVerdict::DeniedNoStallEvidence => {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                            }
                        }
                        match granted {
                            Some(a) => a,
                            None => break,
                        }
                    }
                },
            };
            let end = alloc.extent.end();
            let mut off = alloc.extent.start;
            while off < end {
                let block = off / bs;
                if Some(block) == hang_block && !hung {
                    hung = true;
                    // transport stall: no writes, no heartbeats. Waking = a heartbeat at
                    // the watermark break point (zero new bytes) — Cancelled stops
                    // writing; only Continue resumes this block.
                    tokio::time::sleep(hang_dur).await;
                    let ack = handle.heartbeat(source, alloc.seg.extent, 0).await?;
                    if ack == HeartbeatAck::Cancelled {
                        cancels.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
                let len = g.min(end - off);
                sink.record_write(alloc.seg, off, len);
                handle.complete_block(block).await?;
                let ack = handle.heartbeat(source, alloc.seg.extent, len).await?;
                if ack == HeartbeatAck::Cancelled {
                    cancels.fetch_add(1, Ordering::Relaxed);
                    break; // ownership transferred: stop writing at the watermark break point.
                }
                off += len;
            }
        }
        Ok(())
    }

    /// The tail block's partial bytes are written by several adjacent
    /// sub-block leases — no single writer covers the whole last block,
    /// so block completion can only be closed by the single-point
    /// decision face's full per-block written-byte watermark (first
    /// report wins / persistence / fsync discipline unchanged). Also pins
    /// the resume break point = the written-byte watermark (lease
    /// sequence [bs,1.25bs) -> [1.25bs,1.5bs) -> [1.5bs,1.75bs) ->
    /// [1.75bs,2bs) -> [2bs,2.25bs) -> [2.25bs,2.5bs), zero rewrite, zero
    /// gap); the union covers exactly [0, total).
    #[tokio::test]
    async fn tail_block_partial_bytes_complete_via_watermark_union() {
        let bs = MIN_BLOCK_SIZE;
        let g = crate::scheduler::sub_block_granule(bs);
        let total = 2 * bs + bs / 2; // 2.5 blocks (partial bytes in the last block)
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(OverlapSink::new());
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000002101",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            Duration::from_secs(15),
            aimd_test_cfg(),
            // Seeded rate 0.1bs: with W=1 the rate lease term is 0.3bs (sub-block
            // aligned 0.25bs) < block — the thin-rate regime makes the rate term
            // dominate into sub-block slices (the whole-block floor applies to the
            // guided term and the 3s lease cap semantics stay; the rate term is
            // taken after the floor); the tail block is still split across
            // multiple adjacent sub-block leases.
            crate::rate::SourceRateBook::seed_established(&[
                (0, 0.1 * bs as f64),
                (1, 0.1 * bs as f64),
            ]),
        );
        // Block 0 driven to close-out directly (head = the whole block 0).
        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        assert_eq!(
            head.extent,
            Extent { start: 0, len: bs },
            "the head is 1 block"
        );
        sink.record_write(head.seg, 0, bs);
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));

        // Claim slice by slice -> fill via the heartbeat loop (the production
        // sink chain: report while writing + a final flush — a full in-block
        // watermark is closed by the single-point decision face) -> the next
        // slice. Each previous slice completes before the next claim (W stays
        // 1, a deterministic assertion sequence).
        let mut covered: Vec<(u64, u64)> = vec![(0, bs)];
        let mut expect_starts = vec![bs, 5 * bs / 4, 3 * bs / 2, 7 * bs / 4, 2 * bs, 9 * bs / 4];
        let mut last_block2_recorded = false;
        while let Some(alloc) = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
        {
            let want = expect_starts.remove(0);
            assert_eq!(
                alloc.extent.start, want,
                "the resume breakpoint = the written-byte watermark (zero rewrite, zero gap)"
            );
            let hb = crate::heartbeat::ExtentHeartbeat::new(
                handle.clone(),
                0,
                alloc.seg.extent,
                alloc.extent.start,
                bs,
                Arc::clone(&sink) as Arc<dyn SegmentSink>,
            );
            // Write this slice full in sub-block steps (real byte
            // lengths — the truth source for heartbeat watermark deltas).
            let mut off = alloc.extent.start;
            while off < alloc.extent.end() {
                let n = g.min(alloc.extent.end() - off) as usize;
                sink.record_write(alloc.seg, off, n as u64);
                hb.write_at(alloc.seg, off, Bytes::from(vec![0u8; n]))
                    .await
                    .unwrap_or_else(|e| panic!("write: {e}"));
                off += n as u64;
            }
            hb.flush().await;
            covered.push((alloc.extent.start, alloc.extent.end()));

            let _ = handle.runtime_stats().await; // FIFO barrier
            let completions_now = sink.completions();
            if expect_starts.is_empty() {
                // After the last slice books, the last block (partial bytes) must have
                // been judged full (the bookkeeping observation face = complete_block
                // delivered to the sink; only first records arrive).
                assert!(
                    completions_now.contains(&2),
                    "the last block's partial bytes are booked \
                     via the watermark union: {completions_now:?}"
                );
                last_block2_recorded = true;
            } else if expect_starts.len() == 1 {
                // Block 2 has 1 sub-block written by two slices
                // (half full) — must not be recorded early.
                assert!(
                    !completions_now.contains(&2),
                    "a half-full watermark must not be booked (no half-block state exists, §14.1)"
                );
            }
        }
        assert!(
            expect_starts.is_empty() && last_block2_recorded,
            "the six-carve sequence closes out"
        );

        // The union covers exactly [0, total): zero gaps, zero double writes.
        covered.sort_unstable();
        let mut cursor = 0u64;
        let mut double_written = 0u64;
        for (s, e) in &covered {
            double_written += s.saturating_sub(cursor);
            cursor = (*e).max(cursor);
        }
        double_written += total.saturating_sub(cursor);
        assert_eq!(
            double_written, 0,
            "the union covers [0, total) with no gaps or overlap"
        );

        // The whole grid recorded exactly once (the first-report-wins decision face).
        let mut completions = sink.completions();
        completions.sort_unstable();
        completions.dedup();
        assert_eq!(
            completions,
            (0..3).collect::<Vec<u64>>(),
            "the whole grid exactly once"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Steal stress test (byte domain): under repeated hang injections
    /// (block rotation, watermark-break hangs) the sink write-range overlap
    /// (double-written bytes) stays 0 — hangs land on sub-block boundaries
    /// (the hung sub-block is unwritten), the single-point decision uses
    /// the written-byte watermark as the steal break point, the owner gets
    /// the cancel at the watermark break point on waking and never writes
    /// any granted range; the whole grid is recorded exactly once, and
    /// each round's steal/cancel really happened (counts >= 1 — the
    /// injection is not a no-op).
    #[tokio::test]
    async fn steal_stress_sink_overlap_zero() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 12u64;
        let total = blocks * bs;
        let window = Duration::from_millis(60);
        let hang = Duration::from_millis(200);

        for round in 0..3u32 {
            let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("r{round} grid: {e}"));
            let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
                .unwrap_or_else(|e| panic!("r{round} plan: {e}"));
            let sink = Arc::new(OverlapSink::new());
            let (handle, actor) = spawn_dynamic_with_rates(
                "8000000000001804",
                grid,
                plan,
                Arc::clone(&sink) as Arc<dyn SegmentSink>,
                2,
                window,
                aimd_test_cfg(),
                seeded_rates(4),
            );

            // Deterministic pre-allocation: the owner (source 0) holds head + a
            // large extent ([bs, 6.5bs), W=1 half-pool split); the hang block is
            // pinned inside the extent (rotating 3/4/5).
            let head = handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("r{round} acquire: {e}"))
                .unwrap_or_else(|| panic!("r{round} head"));
            sink.record_write(head.seg, 0, bs);
            handle
                .complete_block(0)
                .await
                .unwrap_or_else(|e| panic!("r{round} complete: {e}"));
            let held = handle
                .acquire(0)
                .await
                .unwrap_or_else(|e| panic!("r{round} acquire: {e}"))
                .unwrap_or_else(|| panic!("r{round} held"));
            assert_eq!(
                held.extent,
                Extent {
                    start: bs,
                    len: 11 * bs / 2
                },
                "r{round}: W=1 guided large extent ([bs, 6.5bs))"
            );
            let hang_block = [3u64, 4, 5][round as usize];

            let cancels = Arc::new(AtomicU64::new(0));
            let joins = vec![
                tokio::spawn(stealing_worker(
                    handle.clone(),
                    WorkerCfg {
                        source: 0,
                        sink: Arc::clone(&sink),
                        bs,
                        pre_held: Some(held),
                        hang_block: Some(hang_block),
                        hang_dur: hang,
                        steal_polls: 200,
                        cancels: Arc::clone(&cancels),
                    },
                )),
                tokio::spawn(stealing_worker(
                    handle.clone(),
                    WorkerCfg {
                        source: 1,
                        sink: Arc::clone(&sink),
                        bs,
                        pre_held: None,
                        hang_block: None,
                        hang_dur: Duration::ZERO,
                        steal_polls: 200,
                        cancels: Arc::clone(&cancels),
                    },
                )),
            ];
            for j in joins {
                j.await
                    .unwrap_or_else(|e| panic!("r{round} join: {e}"))
                    .unwrap_or_else(|e| panic!("r{round} worker: {e}"));
            }
            drop(handle);
            actor
                .await
                .unwrap_or_else(|e| panic!("r{round} actor join: {e}"))
                .unwrap_or_else(|e| panic!("r{round} actor: {e}"));

            let double = sink.double_written_bytes();
            assert_eq!(
                double, 0,
                "r{round}: the sink's write-range overlap must be 0 (byte domain), got {double}"
            );
            let _ = sink.unique_source_ranges();
            assert!(
                cancels.load(Ordering::Relaxed) >= 1,
                "r{round}: the steal cancel must be delivered (the injection is non-spinning)"
            );
            let mut completions = sink.completions();
            completions.sort_unstable();
            completions.dedup();
            assert_eq!(
                completions,
                (0..blocks).collect::<Vec<u64>>(),
                "r{round}: the whole grid booked exactly once \
                 (the decision face's first-arrival-wins)"
            );
        }
    }

    /// Bounded-waste invariant ("waste <= 1 sub-block per steal"): the
    /// steal break point = the written-byte watermark. The owner books its
    /// written watermark via heartbeat, then hangs mid-block — the thief
    /// takes over from the watermark break point, so double-written bytes
    /// (redone written work) = 0; the write overshoot (the final unbooked
    /// heartbeat segment) is confined to <= 1 sub-block by the cancel
    /// stop-writing discipline. Same-block double writes are covered by
    /// single-point adjudication; bookkeeping still covers the grid
    /// exactly once. (Under the old whole-block break point semantics a
    /// mid-block hang would rewrite up to a whole block: the 2.5-sub-block
    /// written watermark would be rewritten by the whole-block break
    /// point — this test is red under that shape.)
    #[tokio::test]
    async fn steal_margin_double_write_confined_to_safety_block() {
        let bs = MIN_BLOCK_SIZE;
        let g = crate::scheduler::sub_block_granule(bs);
        let blocks = 10u64;
        let total = blocks * bs;
        let window = Duration::from_millis(60);
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(ByteRangeSink::new());
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001805",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        // Deterministic order: the owner holds [bs, 5.5bs), decides blocks 1
        // and 2, books a mid-block watermark of 2.5 sub-blocks via heartbeat
        // (2bs + 2.5g), then hangs.
        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        sink.record_write(head.seg, 0, bs);
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));
        assert_eq!(
            held.extent,
            Extent {
                start: bs,
                len: 9 * bs / 2
            },
            "W=1 guided half-pool split ([bs, 5.5bs))"
        );
        let _ = drain_pool(&handle, 1, &grid_ref).await;

        for block in 1..=2u64 {
            sink.record_write(held.seg, block * bs, bs);
            handle
                .complete_block(block)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        // Mid-block hang shape: block 3 has 3 sub-blocks written, 2 booked by
        // heartbeat (watermark = 2bs + 2g); the last sub-block is unbooked
        // write overshoot (the in-flight window of the cancel stop-writing
        // discipline).
        sink.record_write(held.seg, 3 * bs, 3 * g);
        handle
            .heartbeat(0, held.seg.extent, 2 * bs + 2 * g)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        tokio::time::sleep(2 * window).await;

        // The thief is granted [written-byte watermark = 3bs + 2g, extent
        // end): it resumes from the watermark break point — the double write
        // is exactly the owner's 1 unbooked sub-block overshoot (the bound is
        // tight).
        let stolen = match handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"))
        {
            StealVerdict::Approved(a) => a,
            other => panic!("grant: {other:?}"),
        };
        assert_eq!(
            stolen.extent.start,
            3 * bs + 2 * g,
            "the steal breakpoint = the written-byte watermark \
             (the 2nd sub-block boundary inside block 3)"
        );
        // The thief rewrites its whole granted range (block
        // 3's tail half + block 4 + block 5's first half).
        sink.record_write(stolen.seg, stolen.extent.start, stolen.extent.len);
        for block in 3..=5u64 {
            handle
                .complete_block(block)
                .await
                .unwrap_or_else(|e| panic!("thief complete: {e}"));
        }

        // The owner wakes: a late booking (dropped by first-report-wins)
        // + cancellation at the watermark break point.
        handle
            .complete_block(3)
            .await
            .unwrap_or_else(|e| panic!("late complete: {e}"));
        let ack = handle
            .heartbeat(0, held.seg.extent, 0)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(ack, HeartbeatAck::Cancelled, "waking up means cancelled");

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        // Waste-bound assertion: the double write = exactly 1 sub-block (the
        // unbooked overshoot) <= 1 sub-block (under whole-block break points
        // this assertion goes red — rewriting [3bs, 5.5bs) overlaps the
        // owner's written [3bs, 3bs+3g) by 3 sub-blocks > 1).
        let double_written = sink.double_written_bytes();
        assert!(
            double_written <= g,
            "double-write waste {double_written} must be <= 1 sub-block ({g})"
        );
        assert_eq!(
            double_written, g,
            "the double-write is exactly the owner's 1 unaccounted \
             sub-block write overshoot (the bound is tight)"
        );
        let mut completions = sink.completions();
        completions.sort_unstable();
        completions.dedup();
        assert_eq!(
            completions,
            (0..blocks).collect::<Vec<u64>>(),
            "a same-block double-write books exactly once (first-arrival-wins backstop)"
        );
        let _ = grid_ref;
    }

    /// Abandon semantics after a steal (current owner): when the thief
    /// abandons its stolen allocation, only undecided blocks past the
    /// steal watermark return to the pool (decided blocks are recorded
    /// once); returned blocks can be re-claimed and completed — the total
    /// ledger is exactly once.
    #[tokio::test]
    async fn thief_abandon_restores_only_unadjudicated_tail() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 11u64;
        let total = blocks * bs;
        let window = Duration::from_millis(80);
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001806",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        // Owner (source 0): head + blocks 1..=4; decides blocks 1 and 2, then goes silent.
        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));
        let _ = drain_pool(&handle, 1, &grid_ref).await;
        for block in 1..=2u64 {
            handle
                .complete_block(block)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        // Written watermark booked: blocks 1 and 2 (2bs).
        let ack = handle
            .heartbeat(0, held.seg.extent, 2 * bs)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        assert_eq!(ack, HeartbeatAck::Continue);
        tokio::time::sleep(window + Duration::from_millis(60)).await;

        // The thief is granted [3bs, 6bs), completes block 3, then fails and abandons.
        let stolen = match handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"))
        {
            StealVerdict::Approved(a) => a,
            other => panic!("grant: {other:?}"),
        };
        assert_eq!(stolen.extent.start, 3 * bs);
        handle
            .complete_block(3)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        handle
            .abandon(stolen)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));

        // Re-claim: the recovered domain is exactly the byte range past the
        // written watermark — slices merged == [4bs, 6bs) (decided block 3
        // and the written watermark [bs, 3bs) do not return to the pool).
        let mut got: Vec<(u64, u64)> = Vec::new();
        while let Some(a) = handle
            .acquire(2)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
        {
            got.push((a.extent.start, a.extent.end()));
            let (f, l) = grid_ref
                .blocks_spanned(&a.extent)
                .unwrap_or_else(|| panic!("in-grid"));
            for b in f..=l {
                handle
                    .complete_block(b)
                    .await
                    .unwrap_or_else(|e| panic!("complete: {e}"));
            }
        }
        got.sort_unstable();
        assert_eq!(
            got.first().copied().map(|(s, _)| s),
            Some(4 * bs),
            "the return-to-pool start"
        );
        assert_eq!(
            got.last().copied().map(|(_, e)| e),
            Some(6 * bs),
            "the return-to-pool end"
        );
        let got_bytes: u64 = got.iter().map(|(s, e)| e - s).sum();
        assert_eq!(
            got_bytes,
            2 * bs,
            "return-to-pool bytes conserved \
             (no overlap guaranteed by the pool's disjointness)"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        let mut completions = sink.completions();
        completions.sort_unstable();
        completions.dedup();
        assert_eq!(
            completions,
            (0..blocks).collect::<Vec<u64>>(),
            "the total account is exactly once \
             (progress recorded once, the decision face's first-arrival-wins)"
        );
        let _ = head;
        let _ = grid_ref;
    }

    /// Abandon semantics after a steal (stale owner): the stolen owner is
    /// cancelled at the next block boundary; its abandon of the original
    /// allocation is a no-op — everything before the watermark was decided
    /// and everything after belongs to the current owner, so bookkeeping
    /// stands (the current owner is still in flight); it must not return
    /// stolen blocks to the pool causing excess overlap.
    #[tokio::test]
    async fn stale_owner_abandon_after_steal_is_noop() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 10u64;
        let total = blocks * bs;
        let window = Duration::from_millis(80);
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001807",
            grid.clone(),
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            aimd_test_cfg(),
            seeded_rates(4),
        );
        let grid_ref = grid;

        // Same shape as the previous test: the owner holds [bs, 5.5bs), books
        // a 2-block watermark, then goes silent; source 1 drains the pool.
        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));
        let _ = drain_pool(&handle, 1, &grid_ref).await;
        for block in 1..=2u64 {
            handle
                .complete_block(block)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        let _ = handle
            .heartbeat(0, held.seg.extent, 2 * bs)
            .await
            .unwrap_or_else(|e| panic!("heartbeat: {e}"));
        tokio::time::sleep(window + Duration::from_millis(60)).await;
        match handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"))
        {
            StealVerdict::Approved(_) => {}
            other => panic!("grant: {other:?}"),
        }

        // The owner wakes and immediately abandons the original allocation
        // (the failure close-out of the cancelled shape) — a no-op.
        handle
            .abandon(Allocation {
                seg: held.seg,
                extent: held.extent,
            })
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));

        // The thief completes the stolen tail; the abandon returned
        // no blocks to the pool (no third party to claim new work).
        for block in 3..5u64 {
            handle
                .complete_block(block)
                .await
                .unwrap_or_else(|e| panic!("thief complete: {e}"));
        }
        assert!(
            handle
                .acquire(2)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .is_none(),
            "a stale write owner's abandon must not return any block to the pool"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        let mut completions = sink.completions();
        completions.sort_unstable();
        completions.dedup();
        assert_eq!(completions, (0..blocks).collect::<Vec<u64>>());
        let _ = head;
        let _ = grid_ref;
    }

    /// Speedup comparison under a slow tail + hang injection. Deterministic
    /// event simulation (1 tick = 1s, no real sleeps); the same fixture
    /// runs three scheduling shapes: static fixed split (no stealing — the
    /// control baseline), dynamic without stealing, dynamic + stall steal.
    /// Allocation drives the real [`GuidedPlan`]/[`StaticPlan`] and the same
    /// [`scheduler::in_endgame`]; the steal point / stall window /
    /// single-grant rules mirror the actor's scheduling faithfully (the
    /// actor semantics are pinned test by test above). Heartbeat evidence
    /// models "active transferrers grow every tick, frozen ones zero
    /// growth" (a conservative face of the real driver's 1s heartbeat
    /// [`HEARTBEAT_INTERVAL`]).
    ///
    /// Fixture (parameters pinned): the slow-tail source = every block
    /// after the head at 1/24 bandwidth; the pinned stalled connection
    /// (worker 0) hangs 30s before each of its slow-tail blocks (the
    /// 15-30s injection domain pinned to its upper bound; deterministic,
    /// no randomness); stall window 15s. Assertions: stealing really
    /// happens (grants are not vacuous); dynamic+steal is >= 60% faster
    /// than the static baseline; stealing never hurts (for a momentary
    /// suspension model the salvage gain is bounded by (hang - window); a
    /// stricter "completion < 60% of the no-steal control" gate attaches
    /// to connection death/timeout + extent re-fetch paths).
    #[test]
    fn stall_steal_speedup_vs_static_baseline() {
        use crate::scheduler::in_endgame;

        const BLOCKS: u64 = 11;
        const TAIL_FROM: u64 = 1;
        const TAIL_COST: u64 = 24;
        const WORKERS: usize = 4;
        const WINDOW: u64 = 15;
        const FREEZE: u64 = 30;
        /// Sub-block divisor (endgame allocation = single sub-block granularity;
        /// the dynamic side's work unit is a sub-block, its cost inherited from
        /// the containing block; the static side compares per block x SUBS
        /// equivalently).
        const SUBS: u64 = 4;

        let bs = MIN_BLOCK_SIZE;
        let g = crate::scheduler::sub_block_granule(bs);
        let total = BLOCKS * bs;
        // Sub-block cost inherited from the containing
        // block (per-byte cost matches the block model).
        let cost = |gr: u64| {
            if gr / SUBS >= TAIL_FROM { TAIL_COST } else { 1 }
        };
        // static block cost = sub-block cost x sub-block count (per-byte aligned).
        let cost_block = |b: u64| cost(b * SUBS) * SUBS;

        #[derive(Clone, Copy)]
        enum Mode {
            Static,
            DynamicNoSteal,
            DynamicSteal,
        }

        struct Extent {
            owner: usize,
            first: u64,
            last: u64,
            last_acked: Option<u64>,
            last_progress: u64,
        }
        struct Worker {
            /// (extent number, next sub-block).
            cur: Option<(u64, u64)>,
            free_at: u64,
            frozen: bool,
        }

        let run = |mode: Mode| -> (u64, usize) {
            // Rebuild the plan each run (real allocation algebra).
            let mut plan = match mode {
                Mode::Static => (
                    Some(
                        StaticPlan::build(
                            total,
                            &SchedulerConfig {
                                block_size: bs,
                                split: 2,
                                min_split_size: bs,
                                ..SchedulerConfig::default()
                            },
                        )
                        .unwrap_or_else(|e| panic!("static plan: {e}")),
                    ),
                    None,
                ),
                _ => (
                    None,
                    Some(
                        GuidedPlan::build(total, &guided_cfg(32), &|_| false)
                            .unwrap_or_else(|e| panic!("guided plan: {e}")),
                    ),
                ),
            };
            let mut extents: BTreeMap<u64, Extent> = BTreeMap::new();
            let mut workers: Vec<Worker> = (0..WORKERS)
                .map(|_| Worker {
                    cur: None,
                    free_at: 0,
                    frozen: false,
                })
                .collect();
            // static's work unit = a block (block-aligned extents); dynamic's = a
            // sub-block. Termination targets are pinned per coordinate domain.
            let target = if matches!(mode, Mode::Static) {
                BLOCKS
            } else {
                BLOCKS * SUBS
            };
            let mut recorded: std::collections::BTreeSet<(u64, u64)> =
                std::collections::BTreeSet::new();
            let victim = 0usize; // the stalled connection (pinned by the fixture).
            let mut grants = 0usize;
            let mut t = 0u64;

            while recorded.len() as u64 != target {
                // Heartbeat evidence refresh: active, unfrozen holders are fresh this tick.
                for (i, w) in workers.iter().enumerate() {
                    if w.frozen || w.free_at <= t {
                        continue;
                    }
                    if let Some((seq, _)) = w.cur
                        && let Some(e) = extents.get_mut(&seq)
                        && e.owner == i
                    {
                        e.last_progress = t;
                    }
                }
                // Advance to the next event tick.
                t = match workers.iter().map(|w| w.free_at).min() {
                    Some(t) => t,
                    None => panic!("no events left to advance but accounting not closed out"),
                };
                for i in 0..WORKERS {
                    if workers[i].free_at != t {
                        continue;
                    }
                    // Frozen wake-up: equivalent to a heartbeat at the next
                    // sub-block boundary — drop the extent if ownership transferred.
                    if workers[i].frozen {
                        workers[i].frozen = false;
                        if let Some((seq, _)) = workers[i].cur
                            && extents.get(&seq).is_some_and(|e| e.owner != i)
                        {
                            workers[i].cur = None;
                        }
                    }
                    // Block completion (first report wins; a scoped block — the `w` borrow
                    // ends before the claim phase).
                    {
                        let w = &mut workers[i];
                        if let Some((seq, next)) = w.cur {
                            let (e_last, fresh) = {
                                let e = &extents[&seq];
                                (e.last, recorded.insert((seq, next)))
                            };
                            if fresh {
                                let e = extents
                                    .get_mut(&seq)
                                    .unwrap_or_else(|| panic!("extent {seq} is registered"));
                                e.last_acked = Some(match e.last_acked {
                                    Some(a) => a.max(next),
                                    None => next,
                                });
                                e.last_progress = t;
                            }
                            let nb = next + 1;
                            if nb > e_last {
                                w.cur = None;
                            } else {
                                // Hang injection: the stalled connection hangs before each of its
                                // slow-tail blocks (the injection
                                // domain pinned to the upper bound).
                                if next >= TAIL_FROM * SUBS && i == victim {
                                    w.frozen = true;
                                    w.cur = Some((seq, nb));
                                    w.free_at = t + FREEZE;
                                    continue;
                                }
                                // static coordinates = block numbers;
                                // dynamic coordinates = sub-block numbers.
                                let step = if matches!(mode, Mode::Static) {
                                    cost_block(nb)
                                } else {
                                    cost(nb)
                                };
                                w.cur = Some((seq, nb));
                                w.free_at = t + step;
                                continue;
                            }
                        }
                    }
                    // Claim phase.
                    let alloc: Option<(u64, crate::traits::Extent)> =
                        match (&mut plan.0, &mut plan.1) {
                            (Some(static_plan), _) => static_plan.pop_next(),
                            (_, Some(guided)) => {
                                let holders = workers
                                    .iter()
                                    .enumerate()
                                    .filter(|(j, w)| *j != i && w.cur.is_some())
                                    .count();
                                if in_endgame(guided.remaining_blocks(), WORKERS) {
                                    guided.pop_single_granule()
                                } else {
                                    guided.pop_next(holders + 1, None)
                                }
                            }
                            _ => panic!("the plan face must be one of the two"),
                        };
                    if let Some((seq, ext)) = alloc {
                        // static coordinates = block numbers;
                        // dynamic coordinates = sub-block numbers.
                        let (first, last, step) = if matches!(mode, Mode::Static) {
                            let f = ext.start / bs;
                            (f, (ext.end() - 1) / bs, cost_block(f))
                        } else {
                            let f = ext.start / g;
                            (f, ext.end() / g - 1, cost(f))
                        };
                        extents.insert(
                            seq,
                            Extent {
                                owner: i,
                                first,
                                last,
                                last_acked: None,
                                last_progress: t,
                            },
                        );
                        let frozen_start = i == victim && first >= TAIL_FROM * SUBS;
                        let w = &mut workers[i];
                        let step = if frozen_start {
                            w.frozen = true;
                            FREEZE
                        } else {
                            step
                        };
                        w.cur = Some((seq, first));
                        w.free_at = t + step;
                        continue;
                    }
                    // Pool empty: steal polling (a mirror of the single-grant rules:
                    // lowest allocation sequence, stall-window recheck, written-byte
                    // watermark break point, grants reset the baseline).
                    let mut granted = false;
                    if matches!(mode, Mode::DynamicSteal) {
                        for (seq, e) in extents.iter_mut() {
                            if e.owner == i {
                                continue;
                            }
                            if t.saturating_sub(e.last_progress) < WINDOW {
                                continue;
                            }
                            let start = e.last_acked.map_or(e.first, |a| (a + 1).max(e.first));
                            if start > e.last {
                                continue;
                            }
                            e.owner = i;
                            e.last_progress = t;
                            grants += 1;
                            let frozen_start = i == victim && start >= TAIL_FROM * SUBS;
                            let step = if frozen_start {
                                workers[i].frozen = true;
                                FREEZE
                            } else {
                                cost(start)
                            };
                            workers[i].cur = Some((*seq, start));
                            workers[i].free_at = t + step;
                            granted = true;
                            break;
                        }
                    }
                    if !granted {
                        workers[i].free_at = t + 1; // idle backoff and retry.
                    }
                }
            }
            (t, grants)
        };

        let (t_static, _) = run(Mode::Static);
        let (t_nosteal, _) = run(Mode::DynamicNoSteal);
        let (t_steal, grants) = run(Mode::DynamicSteal);

        // Stealing really happened (grants are not vacuous).
        assert!(
            grants >= 1,
            "stall stealing must actually grant: grants={grants}"
        );
        // Speedup >= 60% vs the static baseline.
        let speedup = t_static as f64 / t_steal as f64;
        assert!(
            speedup >= 1.6,
            "speedup vs the static baseline must be >= 60%: \
             static={t_static} steal={t_steal} ({speedup:.2}x)"
        );
        // Stealing never hurts: with freezes as momentary suspensions
        // (resumed after 15-30s), a single-event salvage gain is bounded by
        // (hang - window) — the stricter "completion < 60% of the no-steal
        // control" gate attaches to connection death/read-idle timeout +
        // extent re-fetch paths (retry/abandon).
        assert!(
            t_steal <= t_nosteal,
            "stealing must not degrade: steal={t_steal} nosteal={t_nosteal}"
        );
    }

    // ---------------- AIMD decision wiring ----------------

    /// AIMD wiring (observation seam -> gain window; congestion signal ->
    /// multiplicative decrease; snapshot readback): feeding RateSamples
    /// with a small eval window — the first window establishes the baseline
    /// and optimistically doubles (the snapshot shows Grow); the next
    /// window's flat gain gives Hold; a CongestionSignal decreases
    /// immediately; a source without samples is lazily created by a
    /// congestion signal and decreases from the slow-start start. Sample
    /// gaps >= the eval window => each sample closes exactly one window
    /// (deterministic decisions, independent of jitter — gain is monotone
    /// non-increasing and sleeps only lengthen windows).
    #[tokio::test]
    async fn aimd_wiring_samples_congestion_and_snapshot() {
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(bs, &guided_cfg(1), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let window = Duration::from_millis(30);
        let (handle, actor) = spawn_dynamic(
            "8000000000001901",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            4,
            Duration::from_secs(15),
            AimdConfig {
                max_connections: 8,
                eval_window: window,
                recovery_window: window,
                start_connections: 2,
            },
        );

        // Three samples (gaps 40ms >= window 30ms): the first window
        // establishes + Grow{2,4}; the next window is flat -> Hold{4}; the
        // third closes unchanged.
        for _ in 0..3 {
            handle
                .report_rate_sample(0, 1 << 20, Duration::ZERO, Duration::ZERO)
                .unwrap_or_else(|e| panic!("rate sample: {e}"));
            tokio::time::sleep(window + Duration::from_millis(10)).await;
        }
        let snap = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(
            snap,
            vec![(0, 4)],
            "holds after establishment + the optimistic doubling"
        );

        // Congestion signal (server reset feature): immediate decrease 4->3.
        handle
            .report_congestion(0, CongestionKind::Reset)
            .await
            .unwrap_or_else(|e| panic!("congestion: {e}"));
        let snap = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(
            snap,
            vec![(0, 3)],
            "the multiplicative decrease takes effect immediately"
        );

        // A sample-less source is lazily created by a congestion signal
        // (decreases from the slow-start start 2 -> 1); per-source accounts
        // are isolated (source 0 unaffected).
        handle
            .report_congestion(5, CongestionKind::Throttled)
            .await
            .unwrap_or_else(|e| panic!("congestion: {e}"));
        let snap = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(
            snap,
            vec![(0, 3), (5, 1)],
            "a lazily-created source decreases from min(2,cap), accounts isolated"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The static control baseline assembles no AIMD: congestion signals
    /// are accepted (a no-op without error — the signal face is decoupled
    /// from the scheduling mode) and snapshots stay empty.
    #[tokio::test]
    async fn static_baseline_ignores_aimd_surfaces() {
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let cfg = SchedulerConfig::default();
        let plan = StaticPlan::build(bs, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn(
            "8000000000001902",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
        );

        handle
            .report_congestion(0, CongestionKind::Reset)
            .await
            .unwrap_or_else(|e| panic!("congestion: {e}"));
        let snap = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert!(snap.is_empty(), "the static baseline has no AIMD state");

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// RuntimeStats query face (the /metrics `stolen_total`/`conn_aimd`
    /// data source): the steal-grant counter accumulates inside the single
    /// decision point (counted on grant, not on denial); AIMD connection
    /// counts share the ledger with [`CoordinatorHandle::aimd_snapshot`];
    /// the static control baseline reads zero for both (honest zeros).
    #[tokio::test]
    async fn runtime_stats_counts_steal_grants_and_aimd() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 10u64;
        let total = blocks * bs;
        let window = Duration::from_millis(80);
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(8), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000002201",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            window,
            AimdConfig {
                max_connections: 4,
                eval_window: Duration::from_millis(30),
                recovery_window: Duration::from_millis(30),
                start_connections: 2,
            },
            seeded_rates(4),
        );

        // Initial stats: zero grants, no AIMD state (an honest-zero starting point).
        let stats = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"));
        assert_eq!(stats.steals_granted, 0);
        assert!(stats.aimd_connections.is_empty());

        // Owner (source 0) holds blocks 1..=4, decides block 1, then
        // is silent a full window; source 1 drains the pool and steals.
        let _head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        handle
            .complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        let _held = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("held"));
        for block in 5..blocks {
            let a = handle
                .acquire(1)
                .await
                .unwrap_or_else(|e| panic!("acquire: {e}"))
                .unwrap_or_else(|| panic!("block {block}"));
            handle
                .complete_block(a.extent.start / bs)
                .await
                .unwrap_or_else(|e| panic!("complete: {e}"));
        }
        handle
            .complete_block(1)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        tokio::time::sleep(window + Duration::from_millis(60)).await;
        // Denials are not counted; a grant counts once.
        let v = handle
            .request_steal(1)
            .await
            .unwrap_or_else(|e| panic!("steal: {e}"));
        assert!(matches!(v, StealVerdict::Approved(_)), "grant: {v:?}");
        // AIMD state booked (lazily created via the
        // observation seam) becomes visible in the snapshot.
        handle
            .report_rate_sample(0, 4096, Duration::ZERO, Duration::ZERO)
            .unwrap_or_else(|e| panic!("sample: {e}"));

        let stats = handle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"));
        assert_eq!(stats.steals_granted, 1, "a grant counts once");
        assert_eq!(
            stats.aimd_connections,
            vec![(0, 2)],
            "the AIMD snapshot matches the ledger \
             (the lazily-created source at the slow-start start)"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        // static control baseline: steals always denied, no AIMD -> both counters stay zero.
        let sgrid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let scfg = SchedulerConfig::default();
        let splan = StaticPlan::build(bs, &scfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let (shandle, sactor) = spawn(
            "8000000000002202",
            sgrid,
            splan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
        );
        let stats = shandle
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("static stats: {e}"));
        assert_eq!(
            stats,
            RuntimeStats::default(),
            "static baseline: honest zeros (no AIMD, no stealing)"
        );
        drop(shandle);
        sactor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// AIMD gate (via `AimdSnapshot`/the decision ledger): feeding eval
    /// windows through the actor's observation seam (RateSample) with a
    /// "1MiB/s per connection, unbound ceiling" fixture, the snapshot
    /// readback converges to the growth cap (the ceiling) +/- 1, and the
    /// window-aggregated throughput at the converged count n is >=
    /// single-connection baseline x n x 0.7 (control = a cap-1
    /// single-connection coordinator).
    #[tokio::test]
    async fn aimd_gate_snapshot_convergence_and_aggregate() {
        const CAP: u32 = 8;
        const WINDOWS: usize = 14;
        const TAIL: usize = 4;
        /// Per-connection per-window transfer (1MiB/s x 40ms window).
        const PER_CONN_BYTES: u64 = (1024.0 * 1024.0 * 0.04) as u64;

        let window = Duration::from_millis(40);
        let aimd_cfg = AimdConfig {
            max_connections: CAP,
            eval_window: window,
            recovery_window: window,
            start_connections: 2,
        };

        // AIMD task: feed samples with a small eval window (gaps
        // >= window => each sample closes exactly one window).
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(bs, &guided_cfg(1), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic(
            "8000000000002203",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
            Duration::from_secs(15),
            aimd_cfg,
        );
        // Window-opening baseline (zero-byte boundary observation)
        // + first-window establishment (optimistic probing).
        tokio::time::sleep(window).await;
        handle
            .report_rate_sample(0, 0, Duration::ZERO, Duration::ZERO)
            .unwrap_or_else(|e| panic!("prime: {e}"));

        let mut aimd_bytes = 0u64;
        let mut tail: Vec<u32> = Vec::new();
        for _ in 0..WINDOWS {
            tokio::time::sleep(window + Duration::from_millis(5)).await;
            let n = handle
                .aimd_snapshot()
                .await
                .unwrap_or_else(|e| panic!("snapshot: {e}"))
                .iter()
                .find(|(s, _)| *s == 0)
                .map(|(_, n)| *n)
                .unwrap_or(2);
            tail.push(n);
            if tail.len() > TAIL {
                tail.remove(0);
            }
            // Per-connection rate-limit fixture: the window aggregate = min(n x
            // per-connection, ceiling); the ceiling is unbound => n x
            // per-connection.
            aimd_bytes += PER_CONN_BYTES * u64::from(n);
            handle
                .report_rate_sample(
                    0,
                    PER_CONN_BYTES * u64::from(n),
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .unwrap_or_else(|e| panic!("sample: {e}"));
        }
        // Append the final window's snapshot to the tail
        // (the convergence criterion's last reading).
        let final_n = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"))
            .iter()
            .find(|(s, _)| *s == 0)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        tail.push(final_n);
        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        // Single-connection control (cap 1): the same fixture always holds 1 connection.
        let grid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(bs, &guided_cfg(1), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let (single, sactor) = spawn_dynamic(
            "8000000000002204",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
            Duration::from_secs(15),
            AimdConfig {
                max_connections: 1,
                eval_window: window,
                recovery_window: window,
                start_connections: 1,
            },
        );
        tokio::time::sleep(window).await;
        single
            .report_rate_sample(0, 0, Duration::ZERO, Duration::ZERO)
            .unwrap_or_else(|e| panic!("prime: {e}"));
        for _ in 0..WINDOWS {
            tokio::time::sleep(window + Duration::from_millis(5)).await;
            single
                .report_rate_sample(0, PER_CONN_BYTES, Duration::ZERO, Duration::ZERO)
                .unwrap_or_else(|e| panic!("sample: {e}"));
        }
        let single_n = single
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"))
            .iter()
            .find(|(s, _)| *s == 0)
            .map(|(_, n)| *n)
            .unwrap_or(1);
        let single_bytes = PER_CONN_BYTES * u64::from(WINDOWS as u32);
        drop(single);
        sactor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));

        // Criterion 1: convergence +/- 1 (with per-connection rate limiting,
        // gain stays >= 10% up to the cap -> the tail windows stay at the cap).
        assert!(
            tail.iter().all(|n| n.abs_diff(CAP) <= 1),
            "connections over the last {TAIL} windows must converge on the cap +/- 1: {tail:?}"
        );
        // Criterion 2: aggregate throughput >= single-connection baseline x n x 0.7.
        let aggregate = aimd_bytes as f64 / WINDOWS as f64;
        let baseline = single_bytes as f64 / WINDOWS as f64;
        assert_eq!(single_n, 1, "the single-connection control stays at 1");
        assert!(
            aggregate >= baseline * f64::from(final_n) * 0.7,
            "aggregate {aggregate} < single connection {baseline} x {final_n} x 0.7"
        );
    }

    /// AIMD execution-ring closed loop: the real coordinator decision face
    /// (the RateSample observation seam drives slow-start doubling +
    /// `CongestionSignal` decrease) -> `AimdSnapshot` snapshot ->
    /// [`crate::pool::WorkerPool`] scale realization — grow = spawn
    /// instructions (the driver side spawns workers accordingly), shrink =
    /// stop tickets (workers claim them and exit gracefully at extent
    /// boundaries). Zero mocks between decision and execution: the scale
    /// instructions' magnitudes and timing all come from the actor's
    /// ledger.
    #[tokio::test]
    async fn aimd_decisions_drive_worker_pool_ring() {
        const CAP: u32 = 8;
        /// Per-connection per-window transfer (1MiB/s x 40ms window).
        const PER_CONN_BYTES: u64 = (1024.0 * 1024.0 * 0.04) as u64;
        let window = Duration::from_millis(40);

        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(bs, &guided_cfg(1), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic(
            "8000000000002205",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            2,
            Duration::from_secs(15),
            AimdConfig {
                max_connections: CAP,
                eval_window: window,
                recovery_window: window,
                start_connections: 2,
            },
        );
        let pool = crate::pool::WorkerPool::new(1, CAP);

        // First round (no snapshot yet): the slow-start-start spawn instruction = min(2, cap) = 2.
        let d = pool.apply(&[], &[]);
        assert_eq!(d, vec![(0, 2)], "slow-start start directives");
        pool.note_spawn(0, 2);
        assert_eq!(pool.alive(0), 2);

        // Window-opening baseline (zero-byte boundary observation), then one sample per window.
        tokio::time::sleep(window).await;
        handle
            .report_rate_sample(0, 0, Duration::ZERO, Duration::ZERO)
            .unwrap_or_else(|e| panic!("prime: {e}"));

        // Window 1 establishes + optimistic probe 2->4: realized as +2 spawn instructions.
        tokio::time::sleep(window + Duration::from_millis(5)).await;
        handle
            .report_rate_sample(0, PER_CONN_BYTES * 2, Duration::ZERO, Duration::ZERO)
            .unwrap_or_else(|e| panic!("sample: {e}"));
        let snap = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(snap, vec![(0, 4)], "establishment-window optimistic probe");
        let d = pool.apply(&snap, &[]);
        assert_eq!(d, vec![(0, 2)], "2->4 cashes in as +2 spawn directives");
        pool.note_spawn(0, 2);

        // Window 2 confirms the gain 4->8: +4 instructions (to the cap).
        tokio::time::sleep(window + Duration::from_millis(5)).await;
        handle
            .report_rate_sample(0, PER_CONN_BYTES * 4, Duration::ZERO, Duration::ZERO)
            .unwrap_or_else(|e| panic!("sample: {e}"));
        let snap = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(snap, vec![(0, 8)], "gain confirms doubling to the cap");
        let d = pool.apply(&snap, &[]);
        assert_eq!(d, vec![(0, 4)], "4->8 cashes in as +4 spawn directives");
        pool.note_spawn(0, 4);
        assert_eq!(pool.alive(0), 8);

        // Congestion decreases 8->7 (the Reset-class coefficient floor(8x7/8);
        // Throttled is the spec's original floor(8x3/4)=6 — the class ladder
        // is pinned by aimd.rs's decision-table tests): the shrink is realized
        // as surplus claims — exactly 1 worker claims exit at an extent
        // boundary (CAS mutual exclusion prevents over-kill; the ledger drops
        // to 7).
        handle
            .report_congestion(0, CongestionKind::Reset)
            .await
            .unwrap_or_else(|e| panic!("congestion: {e}"));
        let snap = handle
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(
            snap,
            vec![(0, 7)],
            "multiplicative decrease floor(8x7/8) (the Reset-level coefficient)"
        );
        assert!(
            pool.apply(&snap, &[]).is_empty(),
            "a shrink emits no spawn directives"
        );
        let stopped = (0..8).filter(|_| pool.should_stop(0)).count();
        assert_eq!(stopped, 1, "a shrink of 1 cashes in as exactly 1 exit slot");
        assert_eq!(
            pool.alive(0),
            7,
            "the registered ledger converges to the AIMD decision value"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The steal strict gate ("completion time < 60% of the no-steal
    /// control"). Deterministic event simulation (1 tick = 1s, no real
    /// sleeps); the same fixture runs two shapes: dynamic without stealing
    /// (a stalled connection recovers only via the read-idle `--timeout`
    /// -> connection death -> extent abandon -> undecided blocks return to
    /// the pool and are re-fetched) and dynamic + stall steal (the tail
    /// transfers to an idle connection within the stall window via the
    /// single decision point). Fixture (parameters pinned): the "random
    /// 15-30s hang" injection domain takes the 30s upper bound
    /// (deterministic); the stalled connection's 20th hang (end of the
    /// long chain) escalates to connection death — hanging until the
    /// read-idle timeout (pinned 60s) -> extent abandon (undecided blocks
    /// return to the pool, the re-fetch path) -> reconnect healthy; both
    /// shapes share the fixture. The steal point / stall window /
    /// single-grant rules mirror the actor's scheduling faithfully (actor
    /// semantics pinned test by test above; sink write-range overlap = 0
    /// pinned by [`steal_stress_sink_overlap_zero`]). The main chain
    /// (source 0) holds a half-pool large extent: without stealing the
    /// stalled connections crawl block by block serially (a 30s hang + 24s
    /// write per block); with stealing the tail transfers at the window
    /// boundary to idle connections and is consumed in parallel.
    /// Assertions: stealing really happens, and completion time is < 60%.
    #[test]
    fn stall_steal_strict_gate_completion_under_60pct_of_no_steal() {
        use crate::scheduler::in_endgame;

        const BLOCKS: u64 = 46;
        const COST: u64 = 24;
        const WORKERS: usize = 8;
        /// Stalled connection count (the fixture injection domain;
        /// `0..VICTIMS` are stalled, other connections healthy).
        const VICTIMS: usize = 4;
        const WINDOW: u64 = 15;
        const FREEZE: u64 = 30;
        const TIMEOUT: u64 = 60;
        /// The Nth hang escalates to connection death (pinned at the end of
        /// the long chain; afterwards the reconnect is healthy — the reconnect
        /// face of `--max-tries` semantics).
        const DEATH_AT: u32 = 20;

        let bs = MIN_BLOCK_SIZE;
        let total = BLOCKS * bs;
        let cost = |b: u64| if b == 0 { 1 } else { COST };
        // Lease rate (the established-EWMA view): the rate term is untied from
        // slices, keeping the pre-allocation chain in the guided half-pool-
        // split shape (the unestablished block-granularity lease face belongs
        // to compose_len, outside this simulation).
        let lease_bps = 64.0 * bs as f64;

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Mode {
            NoSteal,
            Steal,
        }

        struct Ext {
            owner: usize,
            first: u64,
            last: u64,
            last_acked: Option<u64>,
            last_progress: u64,
        }
        struct Worker {
            /// (extent number, block to write).
            cur: Option<(u64, u64)>,
            free_at: u64,
            /// Hangs so far (the `DEATH_AT`-th is connection death).
            stalls: u32,
            /// Frozen (hang/timeout); value = this hang's sequence number.
            frozen: Option<u32>,
            /// Died and reconnected (healthy from now on, no more stalls).
            dead: bool,
        }

        let stall_freeze = |stalls: u32| {
            if stalls.is_multiple_of(DEATH_AT) {
                TIMEOUT
            } else {
                FREEZE
            }
        };

        let run = |mode: Mode| -> (u64, usize) {
            let mut plan = crate::scheduler::GuidedPlan::build(
                total,
                &crate::scheduler::GuidedConfig {
                    block_size: bs,
                    max_chunk: 25 * bs,
                },
                &|_| false,
            )
            .unwrap_or_else(|e| panic!("plan: {e}"));
            let mut extents: BTreeMap<u64, Ext> = BTreeMap::new();
            let mut workers: Vec<Worker> = (0..WORKERS)
                .map(|_| Worker {
                    cur: None,
                    free_at: 0,
                    stalls: 0,
                    frozen: None,
                    dead: false,
                })
                .collect();
            let mut recorded: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
            let mut grants = 0usize;
            let mut t = 0u64;

            // Pre-allocation (deterministic, the test body drives the real plan):
            // the head block is decided immediately; then W=1 snapshots slice 4
            // decreasing chains (about 22/11/6/3 blocks), each held by a stalled
            // connection (one extent per connection — the connection model); the
            // remaining healthy connections claim normally from the small residual
            // pool, turning to steal polling (steal) / idling (the no-steal
            // control: a starved shape — recovery waits for the stalled
            // connections themselves or the timeout re-fetch) once it empties.
            {
                let Some((_, head)) = plan.pop_next(1, Some(lease_bps)) else {
                    panic!("head missing");
                };
                recorded.insert(head.start / bs);
                for (source, w) in workers.iter_mut().enumerate().take(VICTIMS) {
                    let Some((seq, ext)) = plan.pop_next(1, Some(lease_bps)) else {
                        break;
                    };
                    let first = ext.start / bs;
                    let last = (ext.end() - 1) / bs;
                    extents.insert(
                        seq,
                        Ext {
                            owner: source,
                            first,
                            last,
                            last_acked: None,
                            last_progress: 0,
                        },
                    );
                    w.stalls = 1;
                    w.frozen = Some(1);
                    w.cur = Some((seq, first));
                    w.free_at = stall_freeze(1);
                }
            }

            // Heartbeat evidence mirror: healthy transferrers are fresh each tick
            // (a conservative face of the 1s heartbeat); frozen connections do not
            // refresh (stall evidence accumulates as zero growth).
            let refresh = |t: u64, workers: &[Worker], extents: &mut BTreeMap<u64, Ext>| {
                for (i, w) in workers.iter().enumerate() {
                    if w.frozen.is_some() || w.free_at <= t {
                        continue;
                    }
                    if let Some((seq, _)) = w.cur
                        && let Some(e) = extents.get_mut(&seq)
                        && e.owner == i
                    {
                        e.last_progress = t;
                    }
                }
            };

            loop {
                if recorded.len() as u64 == BLOCKS {
                    break;
                }
                refresh(t, &workers, &mut extents);
                t = match workers.iter().map(|w| w.free_at).min() {
                    Some(t) => t,
                    None => panic!("no events left to advance but accounting not closed out"),
                };
                for i in 0..WORKERS {
                    if workers[i].free_at != t {
                        continue;
                    }
                    let w = &mut workers[i];
                    // ---- Frozen wake-up (hang window / read-idle timeout) ----
                    if let Some(stall_no) = w.frozen.take() {
                        let death = stall_no % DEATH_AT == 0;
                        let Some((seq, next)) = w.cur else {
                            continue;
                        };
                        let stolen = extents.get(&seq).is_none_or(|e| e.owner != i);
                        if death {
                            // Connection death: read-idle timeout -> fetch fails -> extent abandon
                            // (undecided blocks return to the pool for re-fetch; a stolen extent's
                            // abandon = a stale owner's no-op) -> reconnect healthy.
                            if !stolen {
                                let (first, last) = {
                                    let e = &extents[&seq];
                                    (e.first, e.last)
                                };
                                let start = first * bs;
                                let len = (last + 1) * bs - start;
                                let grid_done = |b: u64| recorded.contains(&b);
                                plan.restore_extent(&Extent { start, len }, &grid_done);
                                extents.remove(&seq);
                            }
                            w.dead = true;
                            w.cur = None;
                            continue;
                        }
                        if stolen {
                            // A momentary hang wakes at the next block boundary: ownership
                            // transferred -> stop writing on cancel (cancel semantics).
                            w.cur = None;
                            continue;
                        }
                        // Ownership still ours: the hang is spent;
                        // the write-face cost is paid as usual.
                        w.free_at = t + cost(next);
                        continue;
                    }
                    // ---- Block completion ----
                    if let Some((seq, next)) = w.cur {
                        let fresh = recorded.insert(next);
                        if fresh {
                            let e = extents
                                .get_mut(&seq)
                                .unwrap_or_else(|| panic!("extent {seq} is registered"));
                            e.last_acked = Some(match e.last_acked {
                                Some(a) => a.max(next),
                                None => next,
                            });
                            e.last_progress = t;
                        }
                        let e_last = extents[&seq].last;
                        let nb = next + 1;
                        if nb > e_last {
                            w.cur = None;
                        } else {
                            // Stall injection: a stalled connection (not yet dead-reconnected)
                            // hangs before each of its slow blocks; a death hang lasts until the
                            // read-idle timeout.
                            if i < VICTIMS && !w.dead {
                                w.stalls += 1;
                                w.frozen = Some(w.stalls);
                                w.cur = Some((seq, nb));
                                w.free_at = t + stall_freeze(w.stalls);
                                continue;
                            }
                            w.cur = Some((seq, nb));
                            w.free_at = t + cost(nb);
                            continue;
                        }
                    }
                    // ---- Claim phase ----
                    let endgame = in_endgame(plan.remaining_blocks(), WORKERS);
                    let alloc = if endgame {
                        plan.pop_single_granule()
                    } else {
                        let holders = workers
                            .iter()
                            .enumerate()
                            .filter(|(j, w)| *j != i && w.cur.is_some())
                            .count();
                        plan.pop_next(holders + 1, Some(lease_bps))
                    };
                    if let Some((seq, ext)) = alloc {
                        let first = ext.start / bs;
                        let last = (ext.end() - 1) / bs;
                        extents.insert(
                            seq,
                            Ext {
                                owner: i,
                                first,
                                last,
                                last_acked: None,
                                last_progress: t,
                            },
                        );
                        let w = &mut workers[i];
                        if i < VICTIMS && !w.dead && first >= 1 {
                            w.stalls += 1;
                            w.frozen = Some(w.stalls);
                            w.cur = Some((seq, first));
                            w.free_at = t + stall_freeze(w.stalls);
                        } else {
                            w.cur = Some((seq, first));
                            w.free_at = t + cost(first);
                        }
                        continue;
                    }
                    // Pool empty: the steal shape turns to steal polling (a mirror of the
                    // single-grant rules: lowest allocation sequence, stall-window
                    // recheck, last_acked+1 start, grants reset the stall baseline); the
                    // no-steal control idles with backoff (a starved shape — recovery
                    // waits for the stalled connections themselves or the timeout
                    // re-fetch).
                    let mut granted = false;
                    if mode == Mode::Steal {
                        let in_flight: u64 = extents
                            .values()
                            .map(|e| {
                                let acked = e.last_acked.map_or(e.first, |a| (a + 1).max(e.first));
                                e.last.saturating_sub(acked) + 1
                            })
                            .sum();
                        if !in_endgame(in_flight + plan.remaining_blocks(), WORKERS) {
                            for (seq, e) in extents.iter_mut() {
                                if e.owner == i {
                                    continue;
                                }
                                if t.saturating_sub(e.last_progress) < WINDOW {
                                    continue;
                                }
                                let start = e.last_acked.map_or(e.first, |a| (a + 1).max(e.first));
                                if start > e.last {
                                    continue;
                                }
                                e.owner = i;
                                e.last_progress = t;
                                grants += 1;
                                let w = &mut workers[i];
                                w.cur = Some((*seq, start));
                                w.free_at = t + cost(start);
                                granted = true;
                                break;
                            }
                        }
                    }
                    if !granted {
                        workers[i].free_at = t + 1;
                    }
                }
            }
            (t, grants)
        };

        let (t_nosteal, _) = run(Mode::NoSteal);
        let (t_steal, grants) = run(Mode::Steal);

        // Stealing really happened (grants are not vacuous).
        assert!(
            grants >= 1,
            "stall stealing must actually grant: grants={grants}"
        );
        // Strict gate: completion time < 60% of the no-steal control.
        assert!(
            t_steal * 5 < t_nosteal * 3,
            "the strict gate failed: steal={t_steal} nosteal={t_nosteal} (share {:.1}%)",
            100.0 * t_steal as f64 / t_nosteal as f64
        );
    }

    /// Retry-After steal gap: an extent under `abandon_deferred` cannot be
    /// claimed within the service window (the pool contains no unexpired
    /// extent — other workers must not claim and re-send while the failed
    /// worker backs off); after the window it returns to the pool,
    /// claimable, with complete coverage. Control face: a plain `abandon`
    /// returns to the pool immediately and is claimable (existing
    /// semantics unchanged).
    #[tokio::test]
    async fn retry_after_deferred_abandon_not_claimable_until_window_elapses() {
        let bs = MIN_BLOCK_SIZE;
        let blocks = 8u64;
        let total = blocks * bs;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = crate::scheduler::GuidedPlan::build(total, &guided_cfg(blocks), &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn_dynamic_with_rates(
            "8000000000001701",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
            Duration::from_secs(15),
            aimd_test_cfg(),
            seeded_rates(1),
        );

        // Drain the pool: all allocations in flight (head +
        // subsequent extents claimed one by one until None).
        let mut inflight = Vec::new();
        while let Some(a) = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
        {
            inflight.push(a);
        }
        assert!(
            inflight.len() >= 3,
            "the fixture needs multiple extents in flight"
        );
        // Control face: a plain abandon returns to the pool immediately ->
        // immediately re-claimable (existing semantics); claim it and then
        // claim everything else out (back to the all-in-flight shape).
        let victim_tmp = inflight.pop().unwrap_or_else(|| panic!("victim"));
        handle
            .abandon(victim_tmp)
            .await
            .unwrap_or_else(|e| panic!("abandon: {e}"));
        let reclaimed = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("a plain abandon must be immediately reclaimable"));
        assert_eq!(reclaimed.extent.start, victim_tmp.extent.start);
        inflight.push(reclaimed);
        // Confirm the pool remainder is zero (all work in flight).
        let drained = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        assert!(
            drained.is_none(),
            "fixture face: all extents in flight (pool empty)"
        );

        // Positive case: RetryAfter abandon with a 300ms service window —
        // claims are filtered inside the window (Acquire answers None; the
        // worker takes the existing park-wait path).
        handle
            .abandon_deferred(reclaimed, Duration::from_millis(300))
            .await
            .unwrap_or_else(|e| panic!("abandon_deferred: {e}"));
        let during_window = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        assert!(
            during_window.is_none(),
            "extents inside the service window must not be claimable (the steal-seam close-out)"
        );

        // After the window: the expiry scan (message-driven) returns it to the
        // pool -> claimable; the start = the held extent's start (re-split
        // from the lowest free address); after draining, the grid is covered
        // exactly once.
        tokio::time::sleep(Duration::from_millis(450)).await;
        let after = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("after the window passes it must be reclaimable"));
        assert_eq!(
            after.extent.start, reclaimed.extent.start,
            "the return-to-pool re-carve start = the held extent's start"
        );
        let mut claimed = Vec::new();
        for a in &inflight {
            if a.seg.extent == reclaimed.seg.extent {
                continue;
            }
            claimed.extend(a.extent.start / bs..=(a.extent.end() - 1) / bs);
        }
        while let Some(a) = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
        {
            claimed.extend(a.extent.start / bs..=(a.extent.end() - 1) / bs);
        }
        claimed.extend(after.extent.start / bs..=(after.extent.end() - 1) / bs);
        claimed.sort_unstable();
        claimed.dedup();
        assert_eq!(
            claimed,
            (0..blocks).collect::<Vec<u64>>(),
            "the whole grid exactly once"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// (static face): a deferred-abandoned extent cannot be claimed within
    /// the window; after it, queue-head reinsert with the original extent
    /// number (the same semantics as an immediate abandon's
    /// `push_front`).
    #[tokio::test]
    async fn deferred_abandon_static_restores_after_window() {
        let bs = MIN_BLOCK_SIZE;
        let grid = BlockGrid::new(bs, 4 * bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 2,
            min_split_size: bs,
            ..SchedulerConfig::default()
        };
        let plan = StaticPlan::build(4 * bs, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let sink = Arc::new(RecordingSink::new(false));
        let (handle, actor) = spawn(
            "8000000000001702",
            grid,
            plan,
            Arc::clone(&sink) as Arc<dyn SegmentSink>,
            1,
        );

        // Claim all fixed segments (head + segment 0 + segment 1; pool empty)
        // -> defer-abandon the middle segment for 200ms.
        let head = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("head"));
        let seg = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("seg"));
        let tail = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("tail"));
        assert_ne!(seg.seg.extent, head.seg.extent);
        assert_ne!(seg.seg.extent, tail.seg.extent);
        handle
            .abandon_deferred(seg, Duration::from_millis(200))
            .await
            .unwrap_or_else(|e| panic!("abandon_deferred: {e}"));

        // Inside the window: the only remainder is held -> claim returns None.
        let during = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        assert!(
            during.is_none(),
            "static extents inside the service window must not be claimable"
        );

        // After the window: queue-head reinsert with the original number and range.
        tokio::time::sleep(Duration::from_millis(350)).await;
        let after = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"))
            .unwrap_or_else(|| panic!("after the window it must be claimable"));
        assert_eq!(
            after.seg.extent, seg.seg.extent,
            "the sequence number is kept (push_front's same semantics)"
        );
        assert_eq!(
            after.extent, seg.extent,
            "the interval is re-inserted verbatim"
        );
        // Pool-empty confirmation: all extents (head/seg/tail) cover the 4 blocks exactly once.
        let none_left = handle
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        assert!(none_left.is_none(), "the static pool must be drained");
        let mut spans: Vec<u64> = [head.extent, tail.extent, after.extent]
            .iter()
            .flat_map(|e| e.start / bs..=(e.end() - 1) / bs)
            .collect();
        spans.sort_unstable();
        spans.dedup();
        assert_eq!(
            spans,
            (0..4u64).collect::<Vec<u64>>(),
            "static: the whole grid exactly once"
        );

        drop(handle);
        actor
            .await
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }
}
