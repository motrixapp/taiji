//! Grid worker execution ring (the worker side of the AIMD connection
//! execution ring).
//!
//! The protocol face is self-contained: the worker loop body (claim
//! extent -> fetch -> block-completion report), WorkerPool shrink
//! claiming, AIMD snapshot -> spawn directive folding, and heartbeat/
//! sink chain assembly (transport -> heartbeat ring -> source
//! attribution -> throttle sink). Persistence / row mirror / task
//! telemetry stay out of the protocol face — they reach the host crate
//! through injection seams:
//!
//! - [`WorkerTelemetry`]: task-level live readings (grid completion /
//!   per-source in-flight / extent and connection counts) — host
//!   implemented; the worker loop holds zero in-protocol telemetry
//!   state;
//! - [`WorkerOpts`]: request identity (per-transport-family credential
//!   slots) and the failure-arm `Retry-After` clamp — the protocol-face
//!   projection of host runtime options;
//! - fatal channels: `WorkerRig::fatal_no_source`/`fatal_restart`
//!   (atomic flags) and `WorkerRig::fatal_protocol` (an
//!   `(HttpError, String)` slot) — a worker sets its flag and exits; the
//!   task driver consumes it as task-level failure/restart (structured
//!   failure mapping is host-side: canonical codes are frozen via
//!   [`HttpError::code`]).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::client::HttpClient;
use crate::coordinator::{self, CoordinatorHandle, RuntimeStats};
use crate::error::HttpError;
use crate::ftp::{FtpConfig, FtpTransport};
use crate::heartbeat::ExtentHeartbeat;
use crate::perhost::{HostCap, HostPermit};
use crate::pool::WorkerPool;
use crate::retry::RetryPolicy;
use crate::sources::SourceState;
use crate::traits::{
    AuthScheme, PlanSource, RequestCtx, SegId, SegmentSink, SegmentTransport, TransportKind,
};
use crate::transport::{HTTP_TOO_MANY_REQUESTS, HttpRangeTransport};

/// Idle-park repoll cadence for workers (`Ok(None)` shape: the plan is
/// fully in flight / finishing / shrinking — claimable again once the
/// worker gives up its pool slot or completes; matches the host driver
/// cadence).
const WORKER_PARK: Duration = Duration::from_millis(500);

/// Single step of the task's first-wave connection ramp: the k-th
/// first-wave worker delays its first connect by k x this step.
/// Spreads the wave so concurrent arrivals per accept window stay
/// bounded and server accept queues are not overrun.
const CONNECT_STAGGER_MS: Duration = Duration::from_millis(5);
/// Stagger ordinal cap (delay ceiling ~320ms; AIMD scale waves carry
/// no delay — the cap only guards pathological first-wave ordinals).
const CONNECT_STAGGER_MAX_ORDINAL: u64 = 64;

/// Shared-client-pool warmth of the source host at stagger-decision
/// time (the [`crate::client::uri_on_warm_pool`] projection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolWarmth {
    /// No recent data-plane success on the shared pool: keep the
    /// first-wave ramp (guards the accept queue against same-instant
    /// connects).
    Cold,
    /// A recent data-plane success landed in-pool: the connect likely
    /// reuses a pooled keep-alive connection with zero setup, and
    /// waiting would be pure loss — skip the stagger.
    Warm,
}

/// First-wave stagger decision (pure function; shared by the grid
/// first wave and the fast path): a warm pool skips the stagger — a
/// recent data-plane success on this source host on the shared client
/// pool ([`crate::client::uri_on_warm_pool`]) means the connect likely
/// lands on a pooled keep-alive connection with zero setup, and
/// waiting would be pure loss; a cold pool keeps the first-wave ramp;
/// ordinal 0 is always zero delay (the grid path's "first worker per
/// source has zero delay" semantics).
pub fn stagger_delay(ordinal: u64, warmth: PoolWarmth) -> Duration {
    match warmth {
        PoolWarmth::Warm => Duration::ZERO,
        PoolWarmth::Cold if ordinal == 0 => Duration::ZERO,
        PoolWarmth::Cold => {
            CONNECT_STAGGER_MS.saturating_mul(ordinal.min(CONNECT_STAGGER_MAX_ORDINAL) as u32)
        }
    }
}

/// Per-worker consecutive extent failure cap (the removal threshold of
/// the "3 downgrades, 5 removals" discipline; removal = the worker
/// exits).
pub const WORKER_FAILURE_CAP: u32 = 5;

/// Task-progress evidence of the failing fetch (the aria2 ADM
/// `mMadeProgress` fact: this fetch wrote bytes — heartbeat write
/// watermark > 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchProgress {
    /// The fetch wrote bytes: progress evidence — the budget resets to 1
    /// (this failure counts as the first).
    WroteBytes,
    /// Zero-byte failure: no progress evidence — the budget keeps
    /// accumulating.
    ZeroBytes,
}

/// Failure budget step (pure function, matrix pinned by unit tests):
/// progress resets the budget to 1 (this failure counts as the first);
/// a zero-byte failure keeps accumulating. The removal ledger (source
/// window failure rate) is not part of this face — progress is
/// task-progress evidence, not source-health evidence, so downgrades
/// and removals are still booked; per-extent `--max-tries` semantics
/// are unchanged.
pub fn failure_budget_step(failures: u32, progress: FetchProgress) -> u32 {
    match progress {
        FetchProgress::WroteBytes => 1,
        FetchProgress::ZeroBytes => failures + 1,
    }
}

/// Retry backoff after an extent failure (grid worker ring): ordinary
/// failures with unknown source health keep 200ms (the existing value
/// — a thundering-herd guard against same-source retries);
/// connection-reset signatures ([`HttpError::is_connection_reset`])
/// drop to 50ms: an RST is a connection-level single event, and other
/// connections to the same host still flowing is direct evidence of
/// source health. The failed extent is already abandoned back to the
/// pool and immediately claimable; this backoff only delays the
/// resetting worker's return to work. The retry-density ceiling is
/// still clamped by [`WORKER_FAILURE_CAP`] and AIMD multiplicative
/// decrease — no retry-storm face.
const EXTENT_RETRY_BACKOFF: Duration = Duration::from_millis(200);
/// Short backoff for connection-reset signatures (consumed at the
/// same value by the fast path's failure arm — pub face).
pub const EXTENT_RETRY_BACKOFF_RESET: Duration = Duration::from_millis(50);

/// Threshold for yielding the permit during a backoff: when the
/// failure-arm backoff sleep is >= this value, the worker releases its
/// per-host permit before sleeping and re-acquires on wake (fair
/// queueing, no queue jumping); short backoffs keep the permit —
/// avoiding acquire/release churn in high-frequency short-backoff
/// shapes (the default 200ms/50ms backoffs plus the 25% fuzz ceiling
/// of 250ms never trigger; triggers are clamped Retry-After values and
/// the high end of exponential backoff).
pub const BACKOFF_PERMIT_RELEASE_THRESHOLD: Duration = Duration::from_millis(500);

/// Task-level live readings injection seam (worker ring telemetry):
/// the host owns task truth (grid completion, per-source in-flight /
/// extents / connection readings) and the worker loop only calls back
/// — the protocol face holds no task telemetry state (host telemetry
/// schema evolution cannot cross the crate boundary).
pub trait WorkerTelemetry: Send + Sync + 'static {
    /// Grid completion check (the worker loop exit condition; total
    /// blocks > 0 and completed blocks >= total — bookkeeping truth is
    /// host-side, the worker caches nothing).
    fn grid_complete(&self) -> bool;

    /// Per-source in-flight worker count delta (+1 on extent claim,
    /// -1 on finish; counting keeps same-source workers from stepping
    /// on each other; the host can show "active" when > 0).
    fn note_source_busy(&self, src_idx: usize, delta: i64);

    /// In-flight extent count delta (+1 on claim, -1 on finish;
    /// success, failure, lost write right, and failure-cap exit all
    /// fall back through the same path).
    fn note_extent_active(&self, delta: i64);

    /// Active connection count delta (one worker = one connection; +1 on claim, -1 on finish).
    fn note_connection(&self, delta: i64);
}

/// Worker run parameters (the protocol-face projection of host runtime
/// options): request identity slotted per transport family (same shape
/// as aria2's http-user/ftp-user split — no cross leakage) plus the
/// failure-arm `Retry-After` clamp. Carries no scheduling/timeout
/// domain (that face belongs to the assembly/driver side).
#[derive(Clone, Debug, Default)]
pub struct WorkerOpts {
    /// HTTP slot credentials (the host `auth_for` projection for non-FTP sources).
    pub http_auth: Option<AuthScheme>,
    /// FTP slot credentials (the host `auth_for` projection for FTP sources).
    pub ftp_auth: Option<AuthScheme>,
    /// Failure-arm `Retry-After` clamp (30s ceiling prevents hangs,
    /// 200ms floor prevents hammering; the server value wins over the
    /// user backoff setting — different domains).
    pub retry: RetryPolicy,
}

impl WorkerOpts {
    /// Credential slot dispatch: FTP sources use the ftp slot, everything else the http slot.
    pub fn auth_for(&self, kind: TransportKind) -> Option<AuthScheme> {
        match kind {
            TransportKind::Ftp => self.ftp_auth.clone(),
            _ => self.http_auth.clone(),
        }
    }
}

/// Per-worker transport dispatch (frozen by merged-table
/// `PlanSource.kind`; a static enum avoids optional arms beyond dyn
/// dispatch — only the Range transport needs its arm).
pub enum WorkerTransport {
    Http(HttpRangeTransport),
    Ftp(Arc<FtpTransport>),
}

impl WorkerTransport {
    /// Registers an in-flight extent before fetch (FTP transports have
    /// no such face — extent ids do not enter the control protocol).
    pub fn arm(&self, seg: SegId) {
        match self {
            WorkerTransport::Http(t) => t.arm(seg),
            WorkerTransport::Ftp(_) => {}
        }
    }

    /// [`SegmentTransport`] view.
    pub fn as_transport(&self) -> &dyn SegmentTransport {
        match self {
            WorkerTransport::Http(t) => t,
            WorkerTransport::Ftp(t) => t.as_ref(),
        }
    }
}

/// Per-worker sink identity wrapper: rewrites `SegId.source` at the
/// transport write point to this worker's bound source. FTP transports
/// write sinks with a placeholder zero SegId under the frozen trait
/// signature (real identity belongs to the scheduling-side assembly);
/// this wrapper is the injection point. HTTP transports carry the true
/// value, so the rewrite is idempotent. Per-source write accounting
/// (rate readings) and the throttle sink's per-source rate report (a
/// coordinator EWMA input) share this attribution.
pub struct SourceTaggedSink {
    /// Inner sink chain (throttle -> the host-assembled grid segment).
    pub inner: Arc<dyn SegmentSink>,
    /// Source bound to this worker (attribution key).
    pub source: u32,
}

impl SegmentSink for SourceTaggedSink {
    fn write_at(
        &self,
        seg: SegId,
        off: u64,
        bytes: Bytes,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<()>> + Send + '_>> {
        self.inner.write_at(
            SegId {
                source: self.source,
                ..seg
            },
            off,
            bytes,
        )
    }

    fn complete_block(
        &self,
        block: u64,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<()>> + Send + '_>> {
        self.inner.complete_block(block)
    }
}

/// Grid worker assembly (bringing up the registered units of the AIMD
/// connection execution ring): the task-level handle bundle shared
/// across workers ([`launch_worker`] clones the needed halves per
/// launch). Does NOT include the coordinator handle and the throttle
/// sink — their clones are managed with the worker task lifetime
/// (teardown order: all workers exit -> the driver side drops handles
/// -> channels close -> the coordinator drains; the rig itself must
/// not extend channel/sink lifetimes).
pub struct WorkerRig {
    pub gid: String,
    /// IO metrics registry handle (feeds the fetch phase of
    /// `taiji_http_request_seconds{phase=total}`; the session metrics
    /// aggregation seam shares the source — tests inject an isolated
    /// instance, production uses the process default registry).
    pub http_metrics: Arc<taiji_io::metrics::MetricsRegistry>,
    pub client: HttpClient,
    /// Data-plane start line: the probe-converged redirect final URL
    /// (`ProbeResult::final_url`) — single-source tasks inject it into
    /// `HttpRangeTransport::request_uri` (per-block fetches skip the
    /// redirect chain); `None` = multi-source/test shape (source entry
    /// URIs start as usual).
    pub authoritative_final: Option<String>,
    /// Task-level live readings injection seam ([`WorkerTelemetry`];
    /// the host injects via an adapter — see the module doc).
    pub telemetry: Arc<dyn WorkerTelemetry>,
    pub per_host: HostCap,
    /// AIMD connection execution ring ledger ([`WorkerPool`]; workers
    /// claim surplus and exit gracefully at extent boundaries via
    /// `should_stop`).
    pub pool: Arc<WorkerPool>,
    /// Worker pool cancellation token (cancelled at completion
    /// teardown; separate from the task-level token — the completion
    /// path must not masquerade as pause).
    pub token: CancellationToken,
    pub total_len: u64,
    pub bs: u64,
    pub count: u64,
    pub ftp_cfg: FtpConfig,
    pub base_ctx: RequestCtx,
    /// All-sources-removed negative closure flag (set when acquire
    /// returns `NoSource`; the task driver tick consumes it as a
    /// task-level failure — same code as the existing no_source
    /// semantics).
    pub fatal_no_source: Arc<AtomicBool>,
    /// Fatal slot for deterministic protocol contradictions: a worker
    /// sets it and exits; the task driver tick consumes it as an
    /// explicit task-level failure (fails once, terminal — no extent
    /// retry burn). Set for `RangeIgnored` (download-time 200 after
    /// the probe confirmed range support = capability drift) and
    /// `BadRange` (download-time 206 echo with a mismatched/missing/
    /// pathological start, [`HttpError::BadRange`] — same family as
    /// range_ignored: deterministic protocol contradictions that do
    /// NOT take the 412 content-restart channel; an echo mismatch is a
    /// protocol contradiction, not content drift). End-point deviation
    /// does not enter this channel: start-matching long deviations are
    /// tolerated by the read loop (over-send books success, under-send
    /// retries as partial progress), so the fatal face is narrowed to
    /// the start dimension. Multi-source note: per-source isolation
    /// (deterministic removal + takeover by the remaining sources)
    /// would need coordinator message extensions; explicit failure is
    /// the fail-closed direction (no silence, no hang).
    pub fatal_protocol: Arc<StdMutex<Option<(HttpError, String)>>>,
    /// Restart channel for content changes: a worker sets it
    /// ([`HttpError::PreconditionFailed`] — the If-Match precondition
    /// was rejected) and exits; the task driver consumes it -> tear
    /// down, then restart from the new content (the outer loop clears
    /// the bitmap and re-downloads from zero). Division of labor vs the
    /// fatal slot: 412 is a self-healing deterministic fact (re-probe
    /// and re-download the new content), not a terminal failure.
    pub fatal_restart: Arc<AtomicBool>,
    /// Stolen-extent worker-side execution ring assembly flag (dynamic
    /// scheduling groups only): true = assemble the heartbeat execution
    /// ring per fetch ([`ExtentHeartbeat`]: heartbeat production /
    /// write-right cancellation consumption / block completion
    /// reported as written) plus steal requests in the park branch;
    /// false = the static baseline is unchanged (extents are not in
    /// the decision face's in-flight ledger there, where a heartbeat
    /// would always read Cancelled and wrongly stop writes — the
    /// assembly decision closes here).
    pub steal: bool,
}

/// AIMD execution ring supervisor folding (snapshot -> spawn
/// directives): extracts the source removal set (`SourceState::Removed`
/// — removed sources must not re-enter via scaling) plus pool scale
/// directives (up = spawn directives fulfilled; down = the desired
/// count is lowered and workers exit gracefully at extent boundaries
/// via `should_stop`). A static baseline snapshot is always empty, so
/// apply is idempotent with zero directives (fixed ring). Telemetry
/// consumption (gauges / steal counts / slow-start sampling / source
/// health writeback) belongs to the host driver loop — this face only
/// folds scheduling directives.
pub fn supervisor_directives(pool: &WorkerPool, stats: &RuntimeStats) -> Vec<(u32, u64)> {
    let removed: Vec<u32> = stats
        .source_states
        .iter()
        .filter(|(_, st, _)| matches!(st, SourceState::Removed))
        .map(|(s, _, _)| *s)
        .collect();
    pool.apply(&stats.aimd_connections, &removed)
}

/// Launches one grid worker (source-bound; claim extent -> fetch ->
/// block-completion report). The source index genuinely enters
/// `SegId` and the coordinator bookkeeping keys. The transport family
/// is dispatched by merged-table `PlanSource.kind`: HTTP -> Range
/// transport; FTP -> [`FtpTransport`] (REST segmentation / pool reuse
/// follow the task FTP options). `coord`/`throttled` are task-level
/// handles (each worker holds a clone, released at task exit).
/// `connect_delay` = the first-connect stagger delay (task first-wave
/// connection ramp; scale waves always `None` — not a storm shape).
#[expect(
    clippy::too_many_arguments,
    reason = "the worker launch face carries the whole task surface explicitly; the arity is the seam contract"
)]
pub fn launch_worker(
    rig: &WorkerRig,
    coord: &CoordinatorHandle,
    throttled: &Arc<dyn SegmentSink>,
    set: &mut JoinSet<()>,
    src_idx: usize,
    sources: &[PlanSource],
    opts: &WorkerOpts,
    connect_delay: Option<Duration>,
) {
    let Some(plan_source) = sources.get(src_idx) else {
        return;
    };
    let uri = plan_source.uri.clone();
    let kind = plan_source.kind;
    let worker_ctx = RequestCtx {
        auth: opts.auth_for(kind),
        ..rig.base_ctx.clone()
    };
    let transport: WorkerTransport = match kind {
        TransportKind::Ftp => {
            // Build failure (URI parse — already filtered at probe
            // time, theoretically unreachable) = that worker is
            // missing; remaining sources/workers proceed as usual.
            match FtpTransport::for_uri(rig.ftp_cfg.clone(), &uri) {
                Ok(t) => WorkerTransport::Ftp(Arc::new(t)),
                Err(e) => {
                    warn!(target: "taiji::http::worker", gid = %rig.gid,
                        uri = %crate::transport::redact_uri(&uri), error = %e,
                        "ftp transport build failed; worker skipped");
                    return;
                }
            }
        }
        _ => WorkerTransport::Http(HttpRangeTransport::new(
            rig.client.clone(),
            uri.clone(),
            // Start-line injection: single-source tasks only — the
            // authoritative probe face is this very source, so
            // `authoritative_final` semantics align; a multi-source
            // task's convergence holds only for its authoritative
            // source, so conservatively re-walk the chain as before.
            if sources.len() == 1 {
                rig.authoritative_final.clone()
            } else {
                None
            },
            src_idx as u32,
            Arc::clone(&rig.http_metrics),
        )),
    };
    let gid = rig.gid.clone();
    let coord = coord.clone();
    let throttled = Arc::clone(throttled);
    let telemetry = Arc::clone(&rig.telemetry);
    let per_host = rig.per_host.clone();
    let pool = Arc::clone(&rig.pool);
    let token = rig.token.clone();
    let fatal_no_source = Arc::clone(&rig.fatal_no_source);
    // Fatal slot for deterministic protocol contradictions (RangeIgnored).
    let fatal_protocol = Arc::clone(&rig.fatal_protocol);
    // 412 content-change restart channel (PreconditionFailed).
    let fatal_restart = Arc::clone(&rig.fatal_restart);
    let (total_len, bs, count, steal) = (rig.total_len, rig.bs, rig.count, rig.steal);
    // Failure-arm `Retry-After` clamp (RetryPolicy sourced from
    // `--retry-wait`; max_wait ceiling = 30s).
    let retry_policy = opts.retry.clone();
    set.spawn(async move {
        let source_idx = src_idx as u32;
        let mut failures: u32 = 0;
        // Connection ramp (task first wave): staggered connects —
        // fully concurrent connects at task start overrun server
        // accept queues (loopback fixture and real servers share the
        // shape: RST -> extent failure retry rounds burn seconds of
        // startup). Cancellation falls straight through to normal
        // teardown (the delay is bounded to a few hundred ms;
        // note_exit stays balanced against the driver's note_spawn).
        if let Some(delay) = connect_delay {
            tokio::select! {
                _ = token.cancelled() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
        // Worker-level sink identity wrapper (attribution face for
        // per-source rate/fair-share accounting): rewrites
        // SegId.source at the transport write point to this worker's
        // bound source — FTP transports write a placeholder zero SegId
        // under the frozen signature, and the real identity is
        // injected here; HTTP transports carry the truth, rewrite
        // idempotent. The throttle sink's per-source rate report (a
        // coordinator EWMA input) shares the attribution. Arc'd as the
        // inner passthrough for the heartbeat execution ring (dynamic
        // assembly).
        let sink: Arc<dyn SegmentSink> = Arc::new(SourceTaggedSink {
            inner: Arc::clone(&throttled),
            source: source_idx,
        });
        // Per-host connection cap (a registry shared across tasks): a
        // worker = one connection, acquiring a permit before
        // activation (cap full = wait — no connection is established);
        // the wait duration is the cap-contention observation, handed
        // once into the AIMD window after activation (a zero-byte
        // sample with the cap_waited bit — input to the cap-contention
        // window exclusion). No host key (unparseable URI) skips the
        // cap check. Parked-period yield: the permit is not held for
        // the worker's whole lifetime — release the slot before
        // parking (the idle repoll) and re-acquire at the
        // re-activation claim point. A parked worker holds no slot, so
        // other tasks' new connections to the same host are not
        // squeezed out by one parked task.
        let host_cap_key = HostCap::host_key(&uri);
        let mut permit: Option<HostPermit> = None;
        // Shrink-claim exits already self-decremented the registered
        // count (`should_stop` CAS); do not fall back again via
        // `note_exit`. All other exit paths (failure cap / cancellation
        // / coordinator shutdown) take the single exit after the loop —
        // the failure-cap path must not record its own exit (a double
        // fallback is a negative count; the registered count would be
        // broken).
        let mut stopped_by_shrink = false;
        // Steal takeover face (worker-side execution ring): steal
        // allocations produced by Approved in the park branch are
        // consumed first at the top of the loop — the write right is
        // already ours, so this runs before the shrink-claim check
        // (once stolen, no mid-flight abandonment).
        let mut held: Option<coordinator::Allocation> = None;
        while !token.is_cancelled() && !telemetry.grid_complete() {
            let alloc = match held.take() {
                Some(a) => a,
                None => {
                    // AIMD shrink (multiplicative decrease / lowered
                    // desired count): claim a surplus slot — graceful
                    // exit (no in-flight extent interrupted; exit at
                    // the boundary).
                    if pool.should_stop(source_idx) {
                        debug!(target: "taiji::http::worker", gid = %gid,
                            source = source_idx, "worker exits at extent boundary (aimd shrink)");
                        stopped_by_shrink = true;
                        break;
                    }
                    // Permit claim point (before activation): cap full
                    // = wait — no connection established; the wait
                    // duration is the cap-contention observation (the
                    // cap_waited bit, a zero-byte sample — input to the
                    // cap-contention window exclusion). The permit is
                    // held for this activation round (claim ->
                    // allocation/park decision -> fetch), not while
                    // parked.
                    if permit.is_none() {
                        if let Some(h) = &host_cap_key {
                            let started = std::time::Instant::now();
                            let p = per_host.acquire(h).await;
                            let waited = started.elapsed();
                            if waited > Duration::ZERO {
                                let _ =
                                    coord.report_rate_sample(source_idx, 0, Duration::ZERO, waited);
                            }
                            permit = Some(p);
                        }
                    }
                    match coord.acquire(source_idx).await {
                        Ok(Some(alloc)) => alloc,
                        Ok(None) => {
                            // Pool momentarily empty (plan fully in
                            // flight / finishing / this source removed
                            // / shrinking): park and repoll — claimable
                            // again once the worker gives up its pool
                            // slot or progresses; cancellation exits.
                            // The old skeleton exited the worker here
                            // (all workers exiting misjudges the task
                            // as failed; momentary emptiness is
                            // recoverable) — under the execution ring,
                            // parking is the precondition for scale
                            // correctness (re-growth after shrink needs
                            // live workers).
                            //
                            // Steal request wiring (dynamic-only
                            // assembly): an empty pool is the steal
                            // battleground (in-flight tails) — an idle
                            // worker sends a single-decision request,
                            // and Approved means taking over
                            // `[last_acked+1 block, extent end)`. Shrink
                            // is checked before stealing (AIMD desired
                            // count lowered / source removal claims exit
                            // first; removed sources must not re-enter
                            // via stealing); endgame always denies, and
                            // no-stall-evidence denials are closed by
                            // the decision face (park and repoll).
                            if steal && pool.should_stop(source_idx) {
                                debug!(target: "taiji::http::worker", gid = %gid,
                                    source = source_idx,
                                    "worker exits parked (aimd shrink)");
                                stopped_by_shrink = true;
                                break;
                            }
                            let mut granted = None;
                            if steal {
                                match tokio::select! {
                                    _ = token.cancelled() => None,
                                    v = coord.request_steal(source_idx) => v.ok(),
                                } {
                                    // Cancelled / coordinator already
                                    // stopped (a request-face Err closes
                                    // the same way).
                                    None => break,
                                    Some(coordinator::StealVerdict::Approved(a)) => {
                                        info!(target: "taiji::http::worker", gid = %gid,
                                            source = source_idx,
                                            extent = a.seg.extent,
                                            start = a.extent.start, len = a.extent.len,
                                            "steal approved; taking over stalled extent tail");
                                        granted = Some(a);
                                    }
                                    // DeniedEndgame (finish zone) /
                                    // DeniedNoStallEvidence (no stall
                                    // evidence — a normally slow source
                                    // is not stolen): park and repoll.
                                    Some(_) => {}
                                }
                            }
                            match granted {
                                Some(a) => a,
                                None => {
                                    // Parked yield: release the permit
                                    // slot before parking (Drop = the
                                    // count falls back + notify_one
                                    // wakes waiters — another task's
                                    // connection to the same host can
                                    // enter immediately); re-acquire at
                                    // the re-activation claim point.
                                    permit = None;
                                    tokio::select! {
                                        _ = token.cancelled() => break,
                                        _ = tokio::time::sleep(WORKER_PARK) => {}
                                    }
                                    continue;
                                }
                            }
                        }
                        Err(HttpError::NoSource) => {
                            // All sources removed with pool slack (the
                            // negative closure): task-level failure
                            // face (the driver tick consumes the fatal
                            // flag).
                            fatal_no_source.store(true, Ordering::Relaxed);
                            break;
                        }
                        Err(_) => break, // coordinator stopped; task teardown goes through the coord_join arm.
                    }
                }
            };
            transport.arm(alloc.seg);
            telemetry.note_source_busy(src_idx, 1);
            telemetry.note_extent_active(1);
            telemetry.note_connection(1);
            let extent_end = alloc.extent.end();
            // Heartbeat execution ring assembly (dynamic only):
            // per-extent byte-heartbeat production (cadence + pause
            // catch-up + final flush — drives the single-decision
            // face's write watermark and block-completion decisions),
            // write-right cancellation consumption (a watchdog for hung
            // transports), and block completion reported as written
            // (the write watermark advances with the writes — the steal
            // resume point is the watermark byte boundary; the owner's
            // written region is never re-granted, keeping double-write
            // waste within <= 1 sub-block of in-flight overshoot). Sink
            // chain: transport -> heartbeat ring -> source attribution
            // -> throttle -> grid; the static baseline connects
            // directly (unchanged).
            let heartbeat = steal.then(|| {
                ExtentHeartbeat::new(
                    coord.clone(),
                    source_idx,
                    alloc.seg.extent,
                    alloc.extent.start,
                    bs,
                    Arc::clone(&sink),
                )
            });
            let ticker = heartbeat.as_ref().map(|h| h.spawn_ticker());
            let sink_ref: &dyn SegmentSink = match &heartbeat {
                Some(h) => h,
                None => sink.as_ref(),
            };
            // biased + fetch polled first: when completion and
            // cancellation become ready together, completion wins (the
            // final catch-up report / success report is not swallowed
            // by cancellation); during a hung fetch (server stopped
            // streaming, reads never return) the Cancelled delivered by
            // the metronome wakes the worker independently — a hung
            // worker can still exit, and finishing is not blocked by
            // it.
            let outcome = tokio::select! {
                biased;
                outcome = transport
                    .as_transport()
                    .fetch(&alloc.extent, &worker_ctx, sink_ref) => Some(outcome),
                _ = async {
                    match &heartbeat {
                        Some(h) => h.cancelled().await,
                        None => std::future::pending().await,
                    }
                } => None,
            };
            if let Some(t) = ticker {
                t.abort();
            }
            // Unified in-flight fallback (success / failure / lost
            // write right / failure-cap exit through the same closure —
            // the old failure-cap break path missed decrementing
            // extents_active/connections; this ring's reorder fixed
            // that).
            telemetry.note_source_busy(src_idx, -1);
            telemetry.note_extent_active(-1);
            telemetry.note_connection(-1);
            // Write-right-lost attribution: the cancellation watchdog
            // fired, or fetch finished with a sink write-right refusal
            // (a pause catch-up learned Cancelled) — the steal was
            // granted to another party / the extent was deregistered.
            // Stop writing and finish: no abandon (a stale write-right
            // holder's abandonment is a no-op), no failure count, no
            // success report; unwritten blocks are completed by the
            // stealer, and same-block double writes are resolved by the
            // block-completion single decision.
            let lost = outcome.is_none() || heartbeat.as_ref().is_some_and(|h| h.is_cancelled());
            if lost {
                info!(target: "taiji::http::worker", gid = %gid,
                    source = source_idx, extent = alloc.seg.extent,
                    "extent write right lost (stolen); stopped at block boundary");
            } else {
                match outcome {
                    Some(Ok(())) => {
                        failures = 0;
                        // Extent success report: clears the consecutive
                        // failure count and restores downgraded sources;
                        // single-source assembly has no ledger, so this
                        // is a no-op.
                        let _ = coord.extent_succeeded(source_idx).await;
                        if let Some(hb) = heartbeat.as_ref() {
                            // dynamic: final watermark flush — report
                            // written bytes outside the catch-up cadence
                            // to the single-decision face immediately
                            // (the "byte watermark full" decision for
                            // the extent tail block / lease-shared
                            // blocks and the task completion chain must
                            // not wait for the next beat). Complete
                            // in-domain blocks were already streamed by
                            // the heartbeat ring; duplicates are absorbed
                            // first-come by the decision face; block
                            // bookkeeping still treats the block as the
                            // only persistence unit.
                            hb.flush().await;
                        } else {
                            // static (block-aligned extent baseline):
                            // the existing whole-block final catch-up
                            // (block b is complete iff (b+1)*bs <= the
                            // written end; extent starts are block-
                            // aligned, so when the last extent reaches
                            // the authoritative total length the tail
                            // partial block safely counts as complete).
                            let first = alloc.extent.start / bs;
                            let last_complete =
                                last_complete_block(extent_end, total_len, bs, count);
                            for b in first..=last_complete {
                                if coord.complete_block(b).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        // Fatal slot for deterministic protocol
                        // contradictions — download-time 200 after the
                        // probe confirmed range support (capability
                        // drift, RangeIgnored) and a 206 echo
                        // contradicting the request (validate_range_echo
                        // -> BadRange) are the same family (code 8:
                        // bad_range/range_ignored, the isRangeSatisfied
                        // failure family). Fatal once, terminal: no
                        // abandon (the extent stays for task-failure
                        // teardown), no failure-cap/backoff burn
                        // (retrying is meaningless — the server behavior
                        // contradicts the request/probe conclusion; a
                        // retry only collects the same response again).
                        // NOT the 412 content-restart channel (412 is
                        // content drift, self-healing after a re-probe;
                        // an echo mismatch / capability drift is a
                        // protocol contradiction, not a content change —
                        // terminal failure). After the slot is set this
                        // worker exits; the driver tick consumes it as
                        // an explicit task-level failure.
                        let fatal_b2 = match &e {
                            HttpError::RangeIgnored => Some((
                                "probe confirmed range support but download got 200 OK \
                                 (range_ignored); failing task"
                                    .to_string(),
                                format!(
                                    "taiji.http.range_ignored: probe confirmed range \
                                     support for {uri}, but download-time range request \
                                     returned 200 OK (expected partial)"
                                ),
                            )),
                            // A 206 echo with a mismatched/missing/
                            // pathological start is judged the same (the
                            // client-layer validate_range_echo converges
                            // all exits to BadRange; end-point dimension
                            // deviation is let through by the validation
                            // face — tolerated by the read loop, never
                            // reaching this arm).
                            HttpError::BadRange => Some((
                                "download got 206 whose content-range echo contradicts \
                                 the request (bad_range); failing task"
                                    .to_string(),
                                format!(
                                    "taiji.http.bad_range: download-time 206 \
                                     content-range echo does not match the requested \
                                     range for {uri} (deterministic protocol \
                                     contradiction)"
                                ),
                            )),
                            _ => None,
                        };
                        if let Some((note, message)) = fatal_b2 {
                            warn!(target: "taiji::http::worker", gid = %gid,
                                source = source_idx, extent = alloc.seg.extent,
                                "{note}");
                            *crate::lock(&fatal_protocol) = Some((e, message));
                            break;
                        }
                        // 412 = server content changed (the If-Match
                        // precondition was rejected) — a deterministic
                        // fact; no failure-cap/backoff burn (a retry
                        // gets 412 again); setting the restart flag
                        // exits, and the driver consumes it as a clear-
                        // bitmap restart from zero (exactly once within
                        // the outer loop's budget).
                        if matches!(e, HttpError::PreconditionFailed) {
                            warn!(target: "taiji::http::worker", gid = %gid,
                                source = source_idx, extent = alloc.seg.extent,
                                "download got 412 (if-match): server content changed; \
                                 restarting task from zero");
                            fatal_restart.store(true, Ordering::Relaxed);
                            break;
                        }
                        // (The ADM `mMadeProgress -> mNumFailed=1`
                        // correspondence): this fetch wrote bytes (the
                        // heartbeat write watermark > 0) = evidence the
                        // transfer is advancing — reset the failure
                        // budget to 1 (this failure counts as the
                        // first), so long transfers are not killed by
                        // the "5 consecutive extent failures" cap (the
                        // server-drops-each-chunk shape: the task is
                        // actually progressing); zero-byte failures
                        // still accumulate. Step semantics in
                        // [`failure_budget_step`]; the static baseline
                        // has no heartbeat ring (no watermark evidence
                        // face) and behaves unchanged.
                        let progress = if heartbeat.as_ref().is_some_and(|h| h.written_bytes() > 0)
                        {
                            FetchProgress::WroteBytes
                        } else {
                            FetchProgress::ZeroBytes
                        };
                        failures = failure_budget_step(failures, progress);
                        // Server throttle signature -> AIMD
                        // multiplicative decrease: only server-side
                        // signatures enter the congestion face — a local
                        // throttle wait is not congestion (excluded via
                        // the observation seam; it must not be reported
                        // here). 429 may carry Retry-After (the
                        // RetryAfter variant) — judged by the same
                        // status code (decrease and polite waiting do
                        // not substitute for each other).
                        let throttled = matches!(
                            &e,
                            HttpError::UnexpectedResponse {
                                status: HTTP_TOO_MANY_REQUESTS
                            } | HttpError::RetryAfter {
                                status: HTTP_TOO_MANY_REQUESTS,
                                ..
                            }
                        );
                        if throttled {
                            let _ = coord
                                .report_congestion(
                                    source_idx,
                                    crate::aimd::CongestionKind::Throttled,
                                )
                                .await;
                        } else if e.is_connection_reset()
                            && heartbeat.as_ref().is_some_and(|h| h.written_bytes() > 0)
                        {
                            // Connection reset / interruption
                            // signature -> Reset decrease. Ramp-phase vs
                            // steady-state distinction (first-wave
                            // connect races overrunning accept queues
                            // produce RSTs): a zero-byte failure is
                            // connect-phase noise and goes through the
                            // existing failure retry + first-wave
                            // stagger ramp — it must not trigger a
                            // decrease that knocks back the AIMD growth
                            // slope. Judge by this extent's real write
                            // watermark (the heartbeat ring byte count):
                            // only an interrupted in-progress transfer
                            // counts as steady-state congestion. The
                            // decision face is dynamic-only (the
                            // heartbeat assembly domain; the static
                            // baseline's AIMD is a no-op anyway).
                            let _ = coord
                                .report_congestion(source_idx, crate::aimd::CongestionKind::Reset)
                                .await;
                        }
                        warn!(target: "taiji::http::worker", code = e.code(),
                            error = %e, failures, "extent fetch failed; extent requeued");
                        // Backoff tiers, three arms in priority order:
                        // a server `Retry-After` wins — clamped (ceiling
                        // = retry.max_wait 30s to prevent hangs, floor
                        // 200ms to prevent hammering) and used as this
                        // backoff; `--retry-wait` does not override the
                        // server value (server values and user backoff
                        // settings are different domains — see
                        // [`crate::retry::clamp_retry_after`]). Without
                        // a hint, tier by failure signature: a
                        // connection reset is a connection-level single
                        // event (direct source-health evidence) with a
                        // short 50ms backoff for a quick return; other
                        // failures keep the existing 200ms (the
                        // thundering-herd guard for unknown source
                        // health). All three arms add random fuzz
                        // ([`crate::retry::fuzz_delay`], 0-25% additive
                        // jitter — prevents synchronized retry storms
                        // when several tasks fail against the same
                        // source; additive only, the priority/floor
                        // semantics are untouched).
                        let wait = crate::retry::fuzz_delay(match &e {
                            HttpError::RetryAfter { after_secs, .. } => {
                                crate::retry::clamp_retry_after(*after_secs, &retry_policy)
                            }
                            _ if e.is_connection_reset() => EXTENT_RETRY_BACKOFF_RESET,
                            _ => EXTENT_RETRY_BACKOFF,
                        });
                        // (The Retry-After steal seam): the abandon of
                        // a `RetryAfter`-class failure carries the
                        // service window delay back to the pool (the
                        // clamped value — not the fuzzed one: the
                        // service window boundary uses the server's
                        // figure, and this worker's backoff fuzz only
                        // sleeps longer, never re-claiming before the
                        // window). The claim side filters within the
                        // window naturally — no other worker may claim
                        // and resend during this worker's backoff (the
                        // server wait applies only to the failed worker);
                        // other error classes carry no delay (immediate
                        // return to the pool, unchanged).
                        // Failure-side final watermark flush: this
                        // attempt's written-byte delta reaches the
                        // decision face before the abandon (the same
                        // FIFO channel keeps order — the reclaim
                        // precondition "all heartbeats enqueued before
                        // the abandonment are consumed" holds thereby).
                        // Without this flush, fast-failure shapes (a
                        // mid-body RST: the first 1s beat never fires
                        // and the metronome aborts with the fetch) leave
                        // covered at 0, and the reclaim domain degrades
                        // to the whole unwritten extent — the written
                        // prefix re-downloads repeatedly, hitting the
                        // failure cap at the same truncation point in a
                        // loop (source wrongly removed, block never
                        // completes). The success arm's flush shares the
                        // same mechanism (duplicate deltas absorbed by
                        // beat_cursor fetch_max).
                        if let Some(hb) = heartbeat.as_ref() {
                            hb.flush().await;
                        }
                        match &e {
                            HttpError::RetryAfter { after_secs, .. } => {
                                let defer =
                                    crate::retry::clamp_retry_after(*after_secs, &retry_policy);
                                let _ = coord.abandon_deferred(alloc, defer).await;
                            }
                            _ => {
                                let _ = coord.abandon(alloc).await;
                            }
                        }
                        if failures >= WORKER_FAILURE_CAP {
                            break;
                        }
                        // (Backoff-period permit yield): for backoffs
                        // >= 500ms, release the per-host permit before
                        // sleeping (Drop returns it + notify wakes
                        // waiters — other tasks' connections to the same
                        // host are not pinned by this worker's long
                        // backoff; closes the K-workers-each-holding-a-
                        // permit-for-30s shape). On wake it re-queues at
                        // the existing claim point at the top of the loop
                        // (no queue jumping; the re-acquire wait is the
                        // existing worker wait path, and coordinator
                        // shutdown takes the existing exit face). Short
                        // backoffs (<500ms) keep the permit — avoiding
                        // acquire/release churn in high-frequency failure
                        // shapes. Releasing the permit is not a worker
                        // exit: the pool ledger note_spawn/note_exit
                        // pairing is unaffected.
                        if wait >= BACKOFF_PERMIT_RELEASE_THRESHOLD {
                            permit = None;
                        }
                        tokio::time::sleep(wait).await;
                    }
                    // Unreachable shape (lost already covers None) — finish as write-right lost.
                    None => {}
                }
            }
        }
        if !stopped_by_shrink {
            pool.note_exit(source_idx);
        }
    });
}

/// The last complete block (inclusive) after an extent finishes
/// writing: block b is complete iff (b+1)*bs <= the written end, i.e.
/// b <= end/bs - 1 (integer division absorbs alignment). When the
/// extent covers the authoritative total length, the tail partial
/// block counts as complete (count-1). The bare subtraction saturates:
/// a half-block end below bs (0/bs-1 underflow) would panic in debug
/// builds — saturation absorbs it as "no complete block".
pub fn last_complete_block(extent_end: u64, total_len: u64, bs: u64, count: u64) -> u64 {
    if extent_end >= total_len {
        count - 1
    } else {
        (extent_end / bs).saturating_sub(1)
    }
}

/// Slow-start end, two-arm decision (the observable criterion for
/// `taiji_http_slowstart_seconds`): evaluated on the existing
/// [`RuntimeStats`] poll —
/// - Arm 1, connections first reach the cap: total AIMD connections
///   across all sources >= cap x registered sources (sources share the
///   growth cap);
/// - Arm 2, aggregate rate first reaches steady state: any source's
///   AIMD has settled (the first `Hold` window decision — a gain below
///   ~10% approximates the engine's own steady-state criterion of the
///   aggregate rate at ~90%+ of baseline, or the cap is reached;
///   [`RuntimeStats::slowstart_settled`] is the source of truth).
///
/// No AIMD state (static baseline / empty snapshot) is always false —
/// the slow-start metric only samples dynamic (AIMD-assembled) tasks.
/// Read-only consumption: the result feeds no scheduling path.
pub fn slowstart_reached(stats: &RuntimeStats, cap: u32) -> bool {
    if stats.slowstart_settled {
        return true;
    }
    let sources = stats.aimd_connections.len();
    if sources == 0 {
        return false;
    }
    let conns: u64 = stats
        .aimd_connections
        .iter()
        .map(|(_, n)| u64::from(*n))
        .sum();
    conns >= u64::from(cap.max(1)) * sources as u64
}
