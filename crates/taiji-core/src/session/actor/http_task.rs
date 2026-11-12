//! HttpTask driver: the execution half of the SessionActor dispatch arm.
//!
//! Mechanism: `Queued -> Probing (multi-source probe) -> Planning (naming/
//! conflict resolution/grid plan) -> Downloading <-> Paused -> Done (incl.
//! empty file and renamePending) | Error`. Queued/Paused live on the
//! SessionActor queue (sharing the `--max-concurrent-downloads` quota with
//! BT); this module owns the activated Probing/Planning/Downloading phases
//! and terminal close-out. Progress truth is the block bitmap (the
//! [`super::super::http::snapshot`] pipeline; its fsync-before-snapshot
//! ordering invariant is closed inside that pipeline).
//!
//! Assembly faces: [`HttpGridSink`] is the store half of `SegmentSink`
//! (`write_at` -> positioned `.part` writes via taiji-http partfile,
//! `complete_block` -> bitmap bookkeeping: the only persistence entry after
//! the ExtentCoordinator decision; throttling via the taiji-http
//! `ThrottledSink` global+task dual buckets). [`PersistJournal`] is the DB
//! half of `RenameJournal` (`record_intent` = one `UpsertHttpTask` row with
//! state=done and `rename_pending=true` in the same statement — the done
//! state and the rename intent land on the row before the action). The
//! transport half lives in taiji-http ([`taiji_http::transport`] for
//! Range-extent fetch and degraded single-connection full GET); core
//! assembles and injects the sink.
//!
//! Upstream anchor mapping: docs/design/core.md
//!
//! # Hard invariants
//!
//! - Never overstate progress: the cancel path takes no forced fsync (1s
//! shutdown budget), so the bitmap may lag by at most ~2s; re-downloading
//! unconfirmed blocks is the safe direction.
//! - The persisted block granularity is immutable per task: an
//! out-of-domain row value is a task-level rejection, never a
//! reinterpretation of an old bitmap under a new granularity.
//! - Runtime options are not persisted: restored tasks are rebuilt from
//! session options (timeouts/credentials/proxy travel with the session);
//! the persisted items are suffix/checksum/remote-time
//! ([`HttpPersistConfig`]).
//! - `--checksum` completion is fail-closed and a mismatch rejects the
//! rename. The grid path prefetches the digest over the contiguous
//! completed prefix ([`ChecksumPrefetch`]: two-phase watermarks plus
//! writer double-checks; invalidation/timeout falls back to a full
//! post-hoc hash); degraded/EOF sequential streams feed a tee digest on
//! the write path (taiji-http `checksum::TeeSink`); `drive_small`
//! (<=2 blocks) and the empty file keep the post-hoc face.
//! - renamePending close-out is three-layer: bootstrap replay of
//! done+pending rows ([`close_out_pending_row`]), in-session periodic
//! polling, and the in-process driver-side journal ledger.
//! `--remote-time` is not replayed on close-out retries (they carry no
//! probe record).
//! - Multi-source probing is serial in user order; ftp/ftps sources are
//! always accepted via [`FtpTransport::probe`] (SIZE +
//! `REST 0`; SIZE unsupported drops the source — a declared divergence);
//! `ftps://` scheme URIs are refused (FTPS = `ftp://` + `--ftp-ssl`).
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

// actor module face: Job/TaskNotice/now_epoch/Gid etc. arrive via `super`.
use super::super::view::{EngineFailure, EngineFailureKind};
use super::*;
use taiji_http::aimd::AimdConfig;
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::cookies::{CookieStore, NetscapeCookie};
use taiji_http::coordinator;
use taiji_http::degraded::DegradedJob;
use taiji_http::error::{HttpError, Result as HttpResult};
use taiji_http::finalize::{FinalizeOutcome, Finalizer, RenameIntent, RenameJournal};
use taiji_http::ftp::{FtpConfig, FtpProbe, FtpTlsMode, FtpTransport, PasvAddressPolicy};
use taiji_http::grid::BlockGrid;
use taiji_http::limiter::{HttpLimiter, RateSampleReporter, ThrottledSink};
use taiji_http::naming::{
    CreationPolicy, FALLBACK_NAME, IncompleteSuffix, OutputPaths, engine_name_budget, plan_output,
    sanitize_generated_name_with_budget, sanitize_user_name_with_budget,
};
use taiji_http::partfile::{FileAllocation, FileSink, HandlesClosed, PartFile, PartOpenPolicy};
use taiji_http::perhost::HostCap;
use taiji_http::probe::{
    MergeInput, MergedPlan, ProbeResult, ProbeVerdict, ProbedSource, probe_uri,
};
use taiji_http::retry::RetryPolicy;
use taiji_http::scheduler::{GuidedConfig, GuidedPlan, SchedulerConfig, SchedulerMode, StaticPlan};
use taiji_http::stall::ByteHeartbeat;
use taiji_segment::traits::{
    AuthScheme, Extent, PlanSource, RequestCtx, SegId, SegmentSink, SegmentTransport, TransportKind,
};
// Transport impls live in taiji-http; core consumes the exported types
// (construction + SegId carrier injection). Protocol checks (206 validation
// / echo consumption / final-url hops) stay with the implementation.
use taiji_http::transport::{HttpBodyTransport, HttpRangeTransport};
// The worker execution loop lives in taiji-http (self-contained protocol
// face): loop body / shrink claims / AIMD snapshot application / heartbeat
// sink chain are consumed here; task telemetry and persistence glue stay in
// core via injection seams (WorkerTelemetry adapter / WorkerOpts projection
// / fatal slot).
use taiji_http::worker::{
    BACKOFF_PERMIT_RELEASE_THRESHOLD, EXTENT_RETRY_BACKOFF_RESET, Fatal, PoolWarmth,
    SourceTaggedSink, WorkerOpts, WorkerRig, WorkerTelemetry, WorkerTransport, launch_worker,
    slowstart_reached, stagger_delay, supervisor_directives,
};
use taiji_store::error::StoreError;
use taiji_store::persist::{HttpTaskRow, PersistHandle, PersistOutcome, TaskCookieRow, TaskPhase};

use super::super::http::{
    PartFileSync, ValidatorFacts, bit_test, recover, recover::PartFileFacts, recover::Resumability,
    snapshot::HttpSnapshotPipeline, strong_etag, validator_digest,
};

/// Future shape of the `RenameJournal` trait (the frozen taiji-http
/// signature is an explicitly desugared BoxFuture; this crate does not
/// depend on futures, so an equivalent alias is used).
type BoxJournalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Driver tick (rate conversion / snapshot due / close-out polling; the
/// snapshot itself keeps its own 2s debounce).
const DRIVER_TICK: Duration = Duration::from_millis(500);

/// Fixed-chain phase timing: monotonic clock traces of the HTTP task driver
/// phases (activation -> row write -> client assembly -> probe -> plan ->
/// `.part` open -> batch enqueue -> ranges drained -> journal/rename
/// close-out). Observed as a single debug line at the terminal state; when
/// disabled, each mark costs one Instant read plus a Vec push.
#[derive(Debug)]
pub(in crate::session) struct ChainTrace {
    t0: std::time::Instant,
    /// (phase name, microseconds since t0).
    marks: Vec<(&'static str, u64)>,
}

impl ChainTrace {
    pub(in crate::session) fn new() -> Self {
        ChainTrace {
            t0: std::time::Instant::now(),
            marks: Vec::new(),
        }
    }

    /// External start point (whole-chain view): for the add path, t0 = the
    /// addUri acceptance time, so the first phase reading includes the
    /// submit-to-activation queuing segment (actor command loop + per-task pump
    /// wait).
    pub(in crate::session) fn with_origin(t0: std::time::Instant) -> Self {
        ChainTrace {
            t0,
            marks: Vec::new(),
        }
    }

    fn mark(&mut self, name: &'static str) {
        self.marks
            .push((name, self.t0.elapsed().as_micros() as u64));
    }
}

impl Default for ChainTrace {
    fn default() -> Self {
        Self::new()
    }
}

/// Timing summary guard: every drive() return path (Done/Cancelled/Failed)
/// emits a one-line phase table via Drop (no per-return instrumentation).
struct TraceOut {
    gid: String,
    trace: ChainTrace,
}

impl Drop for TraceOut {
    fn drop(&mut self) {
        let segs: Vec<String> = self
            .trace
            .marks
            .iter()
            .map(|(n, us)| format!("{n}={us}"))
            .collect();
        debug!(target: "taiji::core::http", gid = %self.gid,
            chain = segs.join(" "), "fixed-chain timing (µs since activation)");
    }
}

/// Fast completion-poll cadence: the shared-check wake-up step after the
/// pool token is cancelled, so the worker-exit / channel-close / completion
/// close-out chain no longer serially waits on the 500ms driver tick.
const COMPLETION_POLL: Duration = Duration::from_millis(10);

/// Scheduler defaults (frozen defaults; wired to the option groups).
const DEFAULT_BLOCK_SIZE: u64 = 4 * 1024 * 1024;
pub(super) const DEFAULT_INCOMPLETE_SUFFIX: &str = ".part";
const DEFAULT_SPLIT: u32 = 5;
const DEFAULT_MIN_SPLIT_SIZE: u64 = 20 * 1024 * 1024;
/// `--max-connection-per-server` default = the domain ceiling 16. The
/// aria2-compatible default of 1 (upstream `-x1` means a single connection
/// for a single-URL download) pins the AIMD growth cap:
/// [`AimdConfig::with_start`] clamps the slow-start start into the cap
/// domain, so with cap 1 the want has no growth room and the download stays
/// single-connection end to end.
///
/// The cap is NOT a connection hard cap: this constant only relaxes the
/// default ceiling. The connection count still climbs adaptively by the
/// AIMD criterion — start = the `--split` default 5, doubling on >=10%
/// gain, with the threshold-convergence and multiplicative-decrease /
/// recovery semantics unchanged. An explicit
/// `--max-connection-per-server=1` still pins a single connection (domain
/// 1..=16 unchanged). The default intentionally deviates from aria2
/// upstream (declared in docs/rpc-api-diff.md).
const DEFAULT_MAX_CONN_PER_SERVER: u32 = 16;
const DEFAULT_MAX_CHUNK: u64 = 32 * 1024 * 1024;
/// `--http-stall-window` default (the stall-steal decision window, 15s).
const DEFAULT_STALL_WINDOW: u64 = 15;

/// Block-size domain (row contract: power of two, 256KiB..=16MiB; an
/// out-of-domain row is rejected at task level — never reinterpret an old
/// bitmap under a new granularity).
const MIN_BLOCK_SIZE: u64 = 256 * 1024;
const MAX_BLOCK_SIZE: u64 = 16 * 1024 * 1024;

/// Task cookie write-back cadence (the cookie persistence wiring; row-level
/// comparison absorbs no-op snapshots: no delta = zero disk writes).
const COOKIE_SYNC_INTERVAL: Duration = Duration::from_secs(2);

/// Cookie write-back loop exit observation seam (compare [`PREFETCH_OBS`]):
/// the loop registers its gid on exit through any cancel face; production
/// never reads it. The test asserts the loop task does not outlive the
/// driver wrapper after a forceRemove hard abort (a loop hanging only off
/// sync_stop/tick would survive the abort — sync_stop is unreachable once
/// the wrapper future is dropped — and would run forever, emitting
/// FK-dangling upsert errors every 2s after row deletion and leaking until
/// process exit).
static COOKIE_LOOP_EXIT_OBS: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

/// Observation seam record (loop exit; keeps the last 32 entries).
fn cookie_loop_exit_obs_record(gid: &str) {
    let mut obs = crate::lock(&COOKIE_LOOP_EXIT_OBS);
    obs.push(gid.to_string());
    let n = obs.len();
    if n > 32 {
        obs.drain(..n - 32);
    }
}

/// Observation seam read (test assertion face).
#[cfg(test)]
pub(super) fn cookie_loop_exit_observations() -> Vec<String> {
    crate::lock(&COOKIE_LOOP_EXIT_OBS).clone()
}

/// Small-task fast-path block-count threshold: tasks with at most this many
/// blocks, no resume progress, and an explicit connection intent >= 2
/// (min(split, cap)) skip the grid/bitmap/AIMD/pool assembly and fetch the
/// whole file as parallel byte ranges ([`drive_small`]; a single-block task
/// on the grid path is permanently single-connection, so the `split` intent
/// is inexpressible there). Factory defaults (cap=1) never trigger it:
/// default-path behavior and bitmap resume semantics are unchanged.
const SMALL_TASK_MAX_BLOCKS: u64 = 2;

/// Fast-path per-range failure cap: higher than the grid worker's
/// `taiji_http::worker::WORKER_FAILURE_CAP` — many small-path tasks in a
/// batch start at once, and the transient connect pressure on the server's
/// accept queue (connect-phase RST noise) is absorbed by the wider retry
/// budget plus exponential backoff instead of failing the task.
const SMALL_PATH_FAILURE_CAP: u32 = 8;

/// Per-host transient batch groups: process-level singleton — single-source
/// HTTP small-path tasks on the same host share one group (cross-file
/// byte-range queue, rotating steal, connection-budget soft gate; the
/// scheduling primitives and the three-layer cap stacking rules live in the
/// [`taiji_http::batch`] module docs). A group dissolves when its last file
/// leaves (transient).
static SMALL_BATCH: std::sync::OnceLock<taiji_http::batch::BatchGroups<SmallBatchItem>> =
    std::sync::OnceLock::new();

fn small_batch() -> &'static taiji_http::batch::BatchGroups<SmallBatchItem> {
    SMALL_BATCH.get_or_init(taiji_http::batch::BatchGroups::new)
}

/// Batch-group observation seam (e2e assertions: lifecycle / budget return
/// / group dissolution).
#[cfg(test)]
pub(super) fn small_batch_stats(host: &str) -> taiji_http::batch::BatchGroupStats {
    small_batch().stats(host)
}

/// Batch item payload (the write-back contract for cross-file steal):
/// whichever worker takes an item advances the OWNER file's write face and
/// live counters — items never know the fetcher's identity.
struct SmallBatchItem {
    /// Byte range (not block-aligned; the fast-path plan as-is).
    extent: Extent,
    /// Item ordinal (SegId.extent; attribution key for owner write/live faces).
    idx: u64,
    /// The owner file's fetch URI (cross-file steal correctness contract: the
    /// fetcher requests the owner's byte interval using the URI carried by the
    /// item — the worker's own URI belongs to its owner file only and is
    /// unusable for stolen items).
    uri: String,
    /// Owner file's sink (throttled chain).
    sink: Arc<dyn SegmentSink>,
    /// Owner file's live counter face.
    live: Arc<HttpLive>,
    /// Owner file handle (completion / requeue / terminal bookkeeping).
    owner: taiji_http::batch::BatchFile<SmallBatchItem>,
    /// Failure retry count (exhausting [`SMALL_PATH_FAILURE_CAP`] aborts the
    /// file).
    attempts: u32,
}

/// Backoff for a rejected batch-gate overflow attempt: an over-budget
/// worker retries after a short stay instead of busy-waiting or abandoning
/// the work (yielding under per-host cap contention).
const BATCH_GATE_RETRY: Duration = Duration::from_millis(50);

/// Drop guard for leaving the batch group (backstop): every drive_small
/// exit ends with abort+leave for this file (the explicit abort+leave at
/// normal close-out is the preferred face). A forceRemove hard abort drops
/// the driver future at an await point, so the explicit leave on the cancel
/// branch never runs and the SMALL_BATCH entry would stay forever (the
/// group never dissolves and remaining items keep being stolen into a
/// removed task's `.part`); this guard leaves on the future's drop.
/// Idempotent: abort/leave are no-ops for already-terminal or already-left
/// files, so the explicit face running first does not conflict.
struct BatchLeaveGuard(taiji_http::batch::BatchFile<SmallBatchItem>);

impl Drop for BatchLeaveGuard {
    fn drop(&mut self) {
        let batch = small_batch();
        batch.abort(&self.0);
        batch.leave(&self.0);
    }
}

/// The `http_task` row's config_json payload (items persisted at creation;
/// serde shape mirrors the torrent `PersistedTaskConfig`). Visibility
/// `pub(in crate::session)`: shared by the runtime face (this module) and
/// the migration importer (session::persist::import_http, which folds
/// serialized option rows into the config_json inventory).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(in crate::session) struct HttpPersistConfig {
    /// Incomplete suffix (persisted at creation; a default change never cuts an
    /// in-flight download).
    #[serde(default = "default_suffix")]
    pub incomplete_suffix: String,
    /// renamePending flag (frozen seam: STATE_DONE plus this key).
    #[serde(default)]
    pub rename_pending: bool,
    /// Raw `--checksum=<scheme>=<hex>` (persisted at creation so the
    /// completion-time verdict survives a restart; "DB as journal". None or
    /// missing = unset).
    #[serde(default)]
    pub checksum: Option<String>,
    /// `--remote-time` (persisted at creation: after completion the file mtime
    /// is set from the remote Last-Modified).
    #[serde(default)]
    pub remote_time: bool,
    /// Full option inventory from the migration importer (serialized option
    /// rows verbatim). Runtime items (header/UA/proxy/credentials) are rebuilt
    /// from session options by the resume face and never enter the runtime, but
    /// migration does not silently drop them: the key/value pairs are stored
    /// verbatim for contract consumption. Ordered key/value pairs (duplicate
    /// keys allowed — cumulative options such as header keep every row). Some
    /// only for imported tasks; None writes no bytes (zero drift for existing
    /// payloads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_options: Option<Vec<(String, String)>>,
    /// Imported-bitmap flag: the row carries a fork piece->block bitmap (set by
    /// the importer only for bitmap rows). Activation semantics:
    /// - auto-rename is disabled — imported data meeting an existing final file
    ///   is an explicit conflict (`taiji.http.path_conflict`), never a silent
    ///   rename to `f.1.iso` that would sever the `.part` association and
    ///   orphan the data;
    /// - the digest gate is downgraded on first activation (probe_json
    ///   absent): the import-time strong validators are unknowable (the fork
    ///   keeps no etag/last_modified while a real server always sends them),
    ///   so the seeded digest necessarily drifts; bitmap trust falls to the
    ///   "exists + size" second line of defense. After the first activation
    ///   probe, probe_json/validator_digest are backfilled from observations
    ///   and later resumes return to the strict gate.
    ///
    /// false writes no bytes (zero drift for existing payloads).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub imported_progress: bool,
    /// Fork source identity key: the dedup criterion lives on the task row —
    /// row present + key equal = already imported, skip; row absent =
    /// re-import allowed. (`session_kv.imported_from` is demoted to a reverse
    /// index, cleaned up with the delete close-out; no dead-marker shape
    /// exists.) Value = the importer's
    /// [`crate::session::persist::import::ImportSource::source_key`] (same key
    /// space as the reverse index, so re-importing the same source yields the
    /// same key). Some only for imported tasks; None writes no bytes (zero
    /// drift for engine-built task payloads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_fork_key: Option<String>,
    /// Concurrency intent (persisted at creation: the effective values of
    /// split/max-connection-per-server are frozen). Resume/reactivation starts
    /// with the same concurrency as the first run (the same `with_start`
    /// assembly: AIMD start + loop cap), so a kill -9 no longer degrades the
    /// resume to session defaults. This is the narrow exception to "runtime
    /// options are not persisted": only the two values that decide the starting
    /// concurrency are replayed; identity items (credentials/proxy/timeouts)
    /// stay out of the store. None (old or imported rows) = new-session
    /// defaults — an unrecorded intent cannot be fabricated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<HttpConcurrencyPersist>,
    /// Per-host connection cap intent (persisted at creation: an addUri
    /// `http-max-per-host` adjustment is frozen onto the row). On daemon
    /// restart / resume activation it is restored for THIS task through the
    /// same channel addUri uses (`HostCap::set_cap`, last-set-wins). Same
    /// narrow exception as [`Self::concurrency`]: rows without the option
    /// carry nothing and activation is a no-op (no cross-infection); the
    /// session HostCap initialization semantics (CLI/global options) are
    /// untouched — restore goes through the runtime-adjustment channel, not the
    /// initialization face. None (old or unadjusted rows) = no intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_cap: Option<u32>,
}

/// Concurrency-intent payload: the two [`HttpTaskOpts`] members that decide
/// the starting concurrency (`--split` + `--max-connection-per-server`).
/// The value domains match the parse face (split
/// 1..=[`taiji_http::scheduler::MAX_SPLIT`], cap 1..=16); replay still
/// clamps defensively (row payloads come from disk: a poisoned
/// out-of-domain row stored before the ceiling gate cannot rely on
/// store-time validation — replay is the sanitization seam).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(in crate::session) struct HttpConcurrencyPersist {
    /// Effective `--split` (lower-bound input for the starting concurrency).
    pub split: u32,
    /// Effective `--max-connection-per-server` (the AIMD growth cap).
    pub max_conn_per_server: u32,
}

impl HttpConcurrencyPersist {
    /// Project from the runtime options (shared by the creation freeze and
    /// changeOption sync).
    pub(super) fn of(opts: &HttpTaskOpts) -> HttpConcurrencyPersist {
        HttpConcurrencyPersist {
            split: opts.split,
            max_conn_per_server: opts.max_conn_per_server,
        }
    }

    /// Replay onto the runtime options (bootstrap restore): defensive clamping
    /// — the target domains match the parse face (split
    /// 1..=[`taiji_http::scheduler::MAX_SPLIT`], cap 1..=16); an
    /// out-of-domain payload is narrowed to the domain, never amplified (the
    /// static scheduler's first wave `WorkerPool::fixed(sources, split)` spawns
    /// unconditionally from split, so passing a poisoned value through would
    /// keep the OOM alive across restarts).
    pub(super) fn apply_to(self, opts: &mut HttpTaskOpts) {
        opts.split = self.split.clamp(1, taiji_http::scheduler::MAX_SPLIT);
        opts.max_conn_per_server = self
            .max_conn_per_server
            .clamp(1, super::MAX_CONN_PER_SERVER_MAX as u32);
    }
}

fn default_suffix() -> String {
    DEFAULT_INCOMPLETE_SUFFIX.to_string()
}

impl Default for HttpPersistConfig {
    fn default() -> Self {
        HttpPersistConfig {
            incomplete_suffix: default_suffix(),
            rename_pending: false,
            checksum: None,
            remote_time: false,
            imported_options: None,
            imported_progress: false,
            origin_fork_key: None,
            concurrency: None,
            host_cap: None,
        }
    }
}

impl HttpPersistConfig {
    pub(in crate::session) fn from_json(raw: &str) -> HttpPersistConfig {
        serde_json::from_str(raw).unwrap_or_default()
    }

    pub(in crate::session) fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// HTTP task runtime option face (the wired option groups:
/// `--timeout/--connect-timeout/--max-tries/--retry-wait/--user-agent/
/// --header/--http-user/--http-passwd/--all-proxy/--check-certificate/
/// --ca-certificate`; the product of addUri option parsing, immutable
/// during activation). Persisted items (suffix/checksum/remote-time) go
/// through [`HttpPersistConfig`]; this struct is the runtime face — after a
/// restart tasks are rebuilt from the new options (timeouts/credentials/
/// proxy travel with the session, never stored).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HttpTaskOpts {
    /// `--timeout` (read-idle seconds; shared by the reqwest read_timeout and
    /// the task-level stall window — read idle resolves here).
    pub read_timeout: Duration,
    /// `--connect-timeout`.
    pub connect_timeout: Duration,
    /// `--max-tries`/`--retry-wait` (consumed by the extent-level backoff
    /// drivers).
    pub retry: RetryPolicy,
    /// `--all-proxy` (http/https; auth via URL userinfo).
    pub proxy: Option<String>,
    /// `--https-proxy` (dedicated HTTPS proxy slot; auth via URL
    /// userinfo). Precedence = **dedicated slot > [`Self::proxy`] > no
    /// proxy** — projected onto `ClientConfig.proxy_https` and
    /// registered ahead of the global slot at transport build time
    /// (reqwest evaluates multiple proxies first-match-wins by
    /// registration order; the `Proxy::https` matcher only intercepts
    /// https targets). `None` = unset (https targets fall to the
    /// global slot, semantics unchanged).
    pub proxy_https: Option<String>,
    /// `--referer` (the Referer header value): projected onto the task's
    /// `RequestCtx.referer`, carried by the client on every hop (probe
    /// and fetch share the same seam). `None` = not sent.
    pub referer: Option<String>,
    /// `--http-accept-gzip` (default false = the explicit
    /// `Accept-Encoding: identity` status quo): true = hand negotiation
    /// back to reqwest — the data plane decompresses transparently
    /// (the checksum applies to the decompressed bytes), the probe face
    /// reads a non-identity encoding -> decision-table row 7
    /// single-connection downgrade + the bitmap stays off (an explicit
    /// fragmentation-for-compression trade-off). Projection =
    /// `ClientConfig.identity_encoding = !self.accept_gzip`.
    pub accept_gzip: bool,
    /// `--http-user/--http-passwd` (one credential pair for Basic pre-auth and
    /// Digest challenge response; aria2 `DigestAuth.cc` isomorphic).
    pub auth: Option<AuthScheme>,
    /// `--ftp-user/--ftp-passwd` (FTP-source credential slot, separate from
    /// http-user/http-passwd, aria2 isomorphic; applies to FTP probing and
    /// fetching. Precedence: URI userinfo > this slot > anonymous/anonymous@,
    /// the same chain as taiji-http [`taiji_http::ftp::FtpTransport`]). None =
    /// unset.
    pub ftp_auth: Option<AuthScheme>,
    /// `--ftp-ssl=none|auth|implicit` (taiji extension — aria2 has no FTPS;
    /// default auth = explicit TLS negotiated via FEAT).
    pub ftp_tls: FtpTlsMode,
    /// `--ftp-reuse-connection` (default true, aria2-aligned): reuse the
    /// control connection across extents; false = a new one per extent.
    pub ftp_reuse_connection: bool,
    /// `--ftp-pasv-address-check=peer|strict|off` (taiji extension — aria2
    /// hardwires the aligned behavior and has no such option name; default peer
    /// = the SSRF-hardened aligned state): the PASV/EPSV data-connection
    /// address decision policy. The value grammar has a single source, the
    /// `FromStr` of taiji-http [`PasvAddressPolicy`] (out-of-domain =
    /// `taiji.option.invalid` rejection); applied via
    /// [`HttpTaskOpts::to_ftp_config`] projecting `FtpConfig.pasv_policy` into
    /// every `FtpTransport::for_uri` construction site. Runtime face.
    pub ftp_pasv_policy: PasvAddressPolicy,
    /// `--user-agent` (None = the default `taiji/<semver>`).
    pub user_agent: Option<String>,
    /// `--header` (order preserved).
    pub headers: Vec<(String, String)>,
    /// `--check-certificate=false` sets true (default false = verification on).
    pub accept_invalid_certs: bool,
    /// `--ca-certificate` (task-level CA face; path to a PEM `CERTIFICATE`
    /// file): a task-level root REPLACES the platform trust store (aria2
    /// replacement semantics, not append). Parse time already validated
    /// readability/PEM shape (bad path/PEM = an option-error rejection); the
    /// path is projected via [`HttpTaskOpts::to_client_config`] and re-read at
    /// transport build time (load failure = a client build error, never
    /// silently ignored). `None` = unset (roots = the platform trust store).
    pub ca_cert_path: Option<PathBuf>,
    /// PEM->DER snapshot of the `--ca-certificate` file (frozen at parse time
    /// from the single load source
    /// `taiji_http::client::load_ca_certificates_der`): fed by
    /// [`HttpTaskOpts::to_ftp_config`] into `FtpConfig.extra_ca_certs_der`
    /// (non-empty = replaces the platform roots). The HTTP face does not
    /// consume this snapshot (it re-reads the path).
    pub ca_cert_der: Vec<Vec<u8>>,
    /// `--split` (default 5; aria2-compatible name): in dynamic mode it is only
    /// an initial-extent reference (redefined semantics, declared in the diff
    /// doc); in static mode it is the segment count (a [`StaticPlan`]
    /// construction input).
    pub split: u32,
    /// `--min-split-size` (default 20MiB): redefined like `split`; in static
    /// mode it is the minimum segment length.
    pub min_split_size: u64,
    /// `--max-connection-per-server` (domain 1..=16, aria2-native; the
    /// effective default is [`DEFAULT_MAX_CONN_PER_SERVER`]): the AIMD growth
    /// cap of the connection execution loop (a runtime lowering is closed out
    /// through the changeOption restart semantics).
    pub max_conn_per_server: u32,
    /// `--http-stall-window` (default 15s; domain >= 3s, a multiple of the
    /// heartbeat period; taiji extension): the stall-steal decision window
    /// (task-level read idle still belongs to `--timeout`; the two windows are
    /// separate domains).
    pub stall_window: Duration,
    /// `--http-scheduler` (default dynamic; taiji extension): the scheduler
    /// mode — dynamic = guided self-scheduling + the AIMD connection loop;
    /// static = fixed segmentation, the control/fallback baseline
    /// ([`StaticPlan`], no AIMD/steal). A runtime change goes through the
    /// changeOption restart semantics (scheduling is changeable mid-run and
    /// never affects bitmap semantics).
    pub scheduler: SchedulerMode,
    /// `--http-block-size` (default 4MiB; taiji extension, domain = powers of
    /// two 256KiB..16MiB): the block grid granularity. Immutable per task
    /// (frozen into the row at creation — the row value is the resume truth;
    /// changeOption rejects it explicitly).
    pub block_size: u64,
    /// `--http-max-chunk` (default 32MiB; taiji extension, >= the effective
    /// min-chunk): the guided extent ceiling. Runtime changes take effect via
    /// the changeOption restart semantics (scheduling class).
    pub max_chunk: u64,
    /// `--http-protocol` (default auto; taiji extension, declared in the diff
    /// doc): the protocol shape — auto = status quo (cleartext h1; https
    /// negotiates h2/h1 via rustls ALPN); h1 = http1_only (upgrade closed, the
    /// fallback/control knob); h2 = prior HTTP/2 knowledge (cleartext endpoints
    /// speak h2c with no Upgrade and no fallback — fails outright against
    /// h1-only peers). Runtime face: projected via
    /// [`HttpTaskOpts::to_client_config`]; rebuilt from session defaults after
    /// a restart.
    pub http_protocol: taiji_http::client::HttpProtocol,
    /// `--http2-adaptive-window` (default false = the engine's static default
    /// windows 8MiB/16MiB; the hyper library defaults of 2MiB/5MiB are
    /// reachable only through the programmatic None path; taiji extension,
    /// declared in the diff doc): h2 flow-control adaptive windows — ping/
    /// BDP-estimated dynamic window growth (hyper `http2_adaptive_window`) to
    /// hedge the ~2MiB/RTT single-stream ceiling on long fat pipes. Runtime
    /// face.
    pub http2_adaptive_window: bool,
    /// `--http2-stream-window` (default = the engine default 8MiB; taiji
    /// extension): the h2 stream-level initial receive window in bytes (domain
    /// 65535..=2^31-1, RFC 7540 §5.2.2). `None` = the hyper library default
    /// 2MiB (programmatic control path only). Runtime face.
    pub http2_stream_window: Option<u32>,
    /// `--http2-connection-window` (default = the engine default 16MiB;
    /// declared in the diff doc): the h2 connection-level initial receive
    /// window in bytes (same domain), shared by all streams. Rate-limit
    /// backpressure semantics are unchanged (flow-control waits stay excluded
    /// from stall evidence). Runtime face.
    pub http2_connection_window: Option<u32>,
    /// `--http2-max-connections` (default 1; taiji extension, declared in the
    /// diff doc): the per-origin connection cap of the h2 transport face
    /// (domain 1..=8) — K independent transport instances with data-plane
    /// requests spread round-robin; ineffective when negotiation lands on h1.
    /// Default 1 = status quo (single-connection multiplexing). Every
    /// connection counts against the per-host cap. Runtime face.
    pub http2_max_connections: u32,
    /// `--http2-keep-alive-interval` (default off; taiji extension, declared in
    /// the diff doc): the h2 PING keep-alive interval (domain 0..=3600
    /// seconds; 0/absent = off) — liveness probing of idle pooled connections,
    /// timeout = 2x the interval. Runtime face.
    pub http2_keep_alive_interval: Option<Duration>,
    /// `--http-batch-budget` (default 16, domain 2..=64; taiji extension,
    /// declared in the diff doc): the group-wide cross-file aggregate
    /// connection budget (unit = connections) of a per-host transient batch
    /// group. Three-layer cap stacking: a single file's intent min(split, cap)
    /// is never amplified; with >= 2 active files in a group the aggregate
    /// connections stay within this budget (exception: work-conserving overflow
    /// while the per-host cap has free slots); batch connections count fully
    /// against the per-host cap (shared across tasks). Single-file mode is not
    /// constrained by this budget (fast-path semantics unchanged). Runtime
    /// face: batch groups are a process-level transient scheduler, rebuilt from
    /// session defaults after a restart (not part of the concurrency-intent
    /// persistence).
    pub batch_budget: u32,
}

impl Default for HttpTaskOpts {
    fn default() -> Self {
        HttpTaskOpts {
            read_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(60),
            retry: RetryPolicy::default(),
            proxy: None,
            proxy_https: None,
            referer: None,
            accept_gzip: false,
            auth: None,
            ftp_auth: None,
            ftp_tls: FtpTlsMode::default(),
            ftp_reuse_connection: true,
            ftp_pasv_policy: PasvAddressPolicy::default(),
            user_agent: None,
            headers: Vec::new(),
            accept_invalid_certs: false,
            ca_cert_path: None,
            ca_cert_der: Vec::new(),
            split: DEFAULT_SPLIT,
            min_split_size: DEFAULT_MIN_SPLIT_SIZE,
            max_conn_per_server: DEFAULT_MAX_CONN_PER_SERVER,
            stall_window: Duration::from_secs(DEFAULT_STALL_WINDOW),
            scheduler: SchedulerMode::default(),
            block_size: DEFAULT_BLOCK_SIZE,
            max_chunk: DEFAULT_MAX_CHUNK,
            http_protocol: taiji_http::client::HttpProtocol::default(),
            http2_adaptive_window: false,
            http2_stream_window: Some(taiji_http::client::DEFAULT_H2_STREAM_WINDOW),
            http2_connection_window: Some(taiji_http::client::DEFAULT_H2_CONN_WINDOW),
            http2_max_connections: 1,
            http2_keep_alive_interval: None,
            batch_budget: taiji_http::batch::DEFAULT_BATCH_BUDGET,
        }
    }
}

impl HttpTaskOpts {
    /// -> [`ClientConfig`] (transport projection; a missing UA falls to the
    /// client-layer default). The CA path is passed through as-is (ordering
    /// resolves in the client layer's `build_transport`:
    /// `accept_invalid_certs` set means the CA file is ignored —
    /// `--check-certificate=false` wins, aria2 semantics).
    pub(super) fn to_client_config(&self) -> ClientConfig {
        ClientConfig {
            read_timeout: self.read_timeout,
            connect_timeout: self.connect_timeout,
            retry: self.retry.clone(),
            proxy: self.proxy.clone(),
            proxy_https: self.proxy_https.clone(),
            // Transparent-decompression switch (`--http-accept-gzip`):
            // true = no identity header (reqwest negotiates and
            // decompresses on the data plane); default false = the
            // identity status quo unchanged.
            identity_encoding: !self.accept_gzip,
            accept_invalid_certs: self.accept_invalid_certs,
            ca_cert_path: self.ca_cert_path.clone(),
            http_protocol: self.http_protocol,
            http2_adaptive_window: self.http2_adaptive_window,
            http2_stream_window: self.http2_stream_window,
            http2_connection_window: self.http2_connection_window,
            http2_max_connections: self.http2_max_connections,
            http2_keep_alive_interval: self.http2_keep_alive_interval,
            ..ClientConfig::default()
        }
    }

    /// -> [`FtpConfig`] (FTP transport projection): TLS mode / connection reuse
    /// / PASV address decision / timeouts / certificate verification come from
    /// the task runtime options; FTP has no proxy face (FTP over an HTTP proxy
    /// is a declared divergence). A non-empty CA snapshot replaces the platform
    /// roots (aria2 `--ca-certificate` replacement semantics); with
    /// `--check-certificate=false` the latter wins (verification off, snapshot
    /// not fed — same ordering as the HTTP face).
    pub(super) fn to_ftp_config(&self) -> FtpConfig {
        FtpConfig {
            tls: self.ftp_tls,
            reuse_connection: self.ftp_reuse_connection,
            pasv_policy: self.ftp_pasv_policy,
            connect_timeout: self.connect_timeout,
            read_idle_timeout: self.read_timeout,
            check_certificate: !self.accept_invalid_certs,
            extra_ca_certs_der: if self.accept_invalid_certs {
                Vec::new()
            } else {
                self.ca_cert_der.clone()
            },
        }
    }

    /// Source credential slot dispatch (aria2 http-user/ftp-user slot
    /// isomorphism): FTP sources use the ftp slot, everything else the http
    /// slot — no cross-leakage (ftp credentials never reach http sources and
    /// vice versa).
    pub(super) fn auth_for(&self, kind: TransportKind) -> Option<AuthScheme> {
        match kind {
            TransportKind::Ftp => self.ftp_auth.clone(),
            _ => self.auth.clone(),
        }
    }

    /// -> the worker loop parameter carrier (taiji-http `worker::WorkerOpts`,
    /// the injection face since the loop moved into the protocol crate): slotted
    /// request-identity projection plus the failure-arm `Retry-After` clamp
    /// parameters. Scheduling/timeout domains are not projected (they belong to
    /// assembly/drive); built once per drive attempt (from the values folded
    /// after import).
    pub(super) fn worker_opts(&self) -> WorkerOpts {
        WorkerOpts {
            http_auth: self.auth.clone(),
            ftp_auth: self.ftp_auth.clone(),
            retry: self.retry.clone(),
        }
    }
}

/// Import-option folding (the consumer half of the migration inventory):
/// fork serialized option rows (stored verbatim in `imported_options` by
/// the import_http collection face) are folded in when activation
/// assembles the request. The foldable key domain = the import_fold bit of
/// [`super::HTTP_TASK_OPTION_TABLE`], dispatched across two faces: runtime
/// rows (header/user-agent/all-proxy/http-user/http-passwd/ftp-user/
/// ftp-passwd) fold into the `HttpTaskOpts` request-identity domain
/// (without this, an authenticated task 401s after a cancel/pause and a
/// proxied task bypasses the proxy — request identity must be restored from
/// the row); persistence rows (checksum/remote-time/http-incomplete-suffix)
/// fold into [`HttpPersistConfig`] — otherwise end-to-end verification
/// explicitly declared by the fork session silently dies, because the
/// verdict faces (task_checksum/task_remote_time/suffix restore) read the
/// row payload and a value that never lands on the row has no consumer.
///
/// Merge/reject semantics reuse the two existing parse drivers as the
/// single source (a present key replaces the baseline; invalid values are
/// explicitly rejected with `taiji.option.invalid`, the addUri rule — never
/// silently falling back to defaults while pretending to apply): runtime
/// keys via [`super::http_task_runtime_options`], persistence keys via
/// [`super::http_task_options`] (checksum algorithm domain
/// md5|sha-1|sha-224|sha-256|sha-384|sha-512 with hex shape,
/// incomplete-suffix via the existing `IncompleteSuffix::parse` domain,
/// remote-time bool — the addUri domain and arm). The existing defense line
/// rides on this single point: the proxy scheme gate (http/https, socks
/// rejected) and the header `Name: value` shape gate; redirect credential
/// stripping stays in the client layer. Imported values are trusted at
/// user-input level (the fork's own configuration migrates verbatim).
///
/// check-certificate/ca-certificate never fold in (fail-closed stance):
/// silently migrating the fork's TLS trust face (verify or replace roots)
/// would carry the previous session's downgrade decision into the new one
/// invisibly; not folding means imported tasks verify with the new session
/// defaults (a tightening, never a security weakening).
///
/// Scheduling/timeout keys (split/timeout/min-split-size/...) never fold
/// in: an imported task's runtime scheduling face is rebuilt from the new
/// session defaults (the existing "runtime options are not stored"
/// boundary). Cumulative keys (header, `face.cumulative`) join their rows
/// in serialized order with `\n` into a single value (the same shape the
/// runtime parser accepts); scalar keys are last-wins (the writer emits one
/// row per key, so a repeat = a tolerant re-import).
pub(super) fn fold_imported_options(
    base_opts: HttpTaskOpts,
    base_cfg: HttpPersistConfig,
    imported: &[(String, String)],
) -> Result<(HttpTaskOpts, HttpPersistConfig), SessionError> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in imported {
        // Foldable key domain = the declaration table's import_fold projection
        // (keys outside the table do not fold — baseline kept).
        let Some(decl) = super::HTTP_TASK_OPTION_TABLE
            .iter()
            .find(|d| d.face.import_fold && d.name == key.as_str())
        else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        if decl.face.cumulative {
            // Cumulative keys join in order (the parser splits on `\n` — same value
            // shape).
            let entry = map.entry(key.clone()).or_default();
            if !entry.is_empty() {
                entry.push('\n');
            }
            entry.push_str(value.trim());
        } else {
            map.insert(key.clone(), value.trim().to_string());
        }
    }
    if map.is_empty() {
        return Ok((base_opts, base_cfg));
    }
    // Two-face dispatch: each driver takes its domain's rows by face bit (a
    // driver skips keys of the other domain on its own), with merge/validation
    // semantics from the same single point as addUri.
    let opts = super::http_task_runtime_options(&map, &base_opts)?;
    let cfg = super::http_task_options(&map, &base_cfg)?;
    Ok((opts, cfg))
}

/// Session-side live counters of an active HttpTask (atomics only; the RPC
/// view reads them synchronously through the RunningTask backend's Http
/// variant, never occupying the command channel).
///
/// Lock policy: every `StdMutex` field is taken through [`crate::lock`] —
/// poisoning is fatal, and the accounting write-backs on `sources` /
/// `source_busy` are never silently skipped behind an `if let Ok(..)`.
pub(super) struct HttpLive {
    pub total_len: AtomicU64,
    /// Completed bytes (byte-level live counter): seeded from the block
    /// bookkeeping base during activation assembly, then accumulated
    /// monotonically with real written bytes (fed from sink write points
    /// and the degraded path's `.part` size deltas). This is the projection
    /// face (`completed_bytes`) — block bookkeeping remains the persistence
    /// authority (projection != bookkeeping); the rate-conversion swap
    /// never touches this counter (always monotonic).
    done_bytes: AtomicU64,
    /// Bytes written during this activation (the rate-conversion base).
    written: AtomicU64,
    /// Byte-level heartbeat (the stall-detection source): accumulated by
    /// any write-path progress — the grid path at sink write points, the
    /// degraded path via `.part` size deltas (TickGuard); `written` is
    /// zeroed by the rate-conversion swap, the heartbeat never resets.
    stall: ByteHeartbeat,
    pub rate: AtomicU64,
    pub blocks_done: AtomicU64,
    pub blocks_total: AtomicU64,
    pub connections: AtomicU64,
    pub extents_active: AtomicU64,
    pub rename_pending: AtomicBool,
    final_url: StdMutex<String>,
    encoding: StdMutex<Option<String>>,
    sources: StdMutex<Vec<super::super::view::HttpSourceView>>,
    /// Per-source in-flight worker count (workers report real state when
    /// claiming/finishing an extent: >0 = "active", zero = "waiting";
    /// counted so overlapping workers do not stomp each other).
    source_busy: StdMutex<Vec<u64>>,
    /// Per-source written-byte deltas (accumulated at sink write points by
    /// `SegId.source`; the driver tick swaps them into per-source rates —
    /// measured source-level readings instead of a total-spread
    /// projection).
    source_written: Vec<AtomicU64>,
    /// Per-source rate readings (bytes/s; converted at the driver tick,
    /// smoothed like the total rate).
    source_rates: Vec<AtomicU64>,
    out_path: StdMutex<String>,
    /// Block-completion event face: block bookkeeping progress wakes the
    /// driver loop immediately — completion detection no longer waits for
    /// the next 500ms driver tick (notify_one permits coalescing
    /// concurrent completions; the wake rate stays at or below the block
    /// rate).
    progress_notify: tokio::sync::Notify,
}

impl HttpLive {
    fn new(uris: &[String]) -> Self {
        HttpLive {
            total_len: AtomicU64::new(0),
            done_bytes: AtomicU64::new(0),
            written: AtomicU64::new(0),
            stall: ByteHeartbeat::new(),
            rate: AtomicU64::new(0),
            blocks_done: AtomicU64::new(0),
            blocks_total: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            extents_active: AtomicU64::new(0),
            rename_pending: AtomicBool::new(false),
            final_url: StdMutex::new(String::new()),
            encoding: StdMutex::new(None),
            sources: StdMutex::new(
                uris.iter()
                    .map(|u| super::super::view::HttpSourceView {
                        url: u.clone(),
                        rate: 0,
                        state: "waiting".into(),
                    })
                    .collect(),
            ),
            source_busy: StdMutex::new(vec![0; uris.len().max(1)]),
            source_written: (0..uris.len().max(1)).map(|_| AtomicU64::new(0)).collect(),
            source_rates: (0..uris.len().max(1)).map(|_| AtomicU64::new(0)).collect(),
            out_path: StdMutex::new(String::new()),
            progress_notify: tokio::sync::Notify::new(),
        }
    }

    /// Grid completion check (the worker close-out face).
    fn is_complete(&self) -> bool {
        let total = self.blocks_total.load(Ordering::Relaxed);
        total > 0 && self.blocks_done.load(Ordering::Relaxed) >= total
    }

    /// Driver-tick rate conversion (500ms window bytes x2 -> B/s, linear
    /// smoothing).
    fn note_tick(&self) {
        let now = self.written.swap(0, Ordering::Relaxed) * 2;
        let prev = self.rate.load(Ordering::Relaxed);
        self.rate.store((prev + now) / 2, Ordering::Relaxed);
    }

    /// Monotonic millisecond clock (snapshot debounce window input).
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Adjust the per-source in-flight count and write back the real
    /// state: +1 when a worker claims an extent ("active"), -1 when it
    /// finishes (back to "waiting" at zero); counting keeps multiple
    /// workers on one source from stomping each other. Terminal states
    /// (demoted/removed) are owned by [`Self::set_source_state`] — a busy
    /// countdown no longer overwrites non-waiting states.
    fn note_source_busy(&self, idx: usize, delta: i64) {
        let active = {
            let mut busy = crate::lock(&self.source_busy);
            let Some(slot) = busy.get_mut(idx) else {
                return;
            };
            *slot = ((*slot as i64) + delta).max(0) as u64;
            *slot > 0
        };
        let mut s = crate::lock(&self.sources);
        if let Some(slot) = s.get_mut(idx) {
            // Migrate only between waiting <-> active; demoted/removed/
            // failed are ledger-level terminal states (coordinator
            // snapshot / probe verdicts) — busy churn never rewrites
            // them.
            if slot.state != "waiting" && slot.state != "active" {
                return;
            }
            slot.state = if active { "active" } else { "waiting" }.into();
        }
    }

    /// Source terminal-state write-back (probe failure / merge-table eviction
    /// / coordinator demotion-removal snapshot).
    fn set_source_state(&self, idx: usize, state: &str) {
        let mut s = crate::lock(&self.sources);
        if let Some(slot) = s.get_mut(idx) {
            slot.state = state.to_string();
        }
    }

    /// Source written-byte delta (accumulated at sink write points by
    /// `SegId.source`; converted in [`Self::source_rate_tick`]).
    fn note_source_written(&self, source: u32, delta: u64) {
        if let Some(slot) = self.source_written.get(source as usize) {
            slot.fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// Per-source rate conversion (called at the driver tick; smoothed like
    /// [`Self::note_tick`]).
    fn source_rate_tick(&self) {
        for (w, r) in self.source_written.iter().zip(self.source_rates.iter()) {
            let now = w.swap(0, Ordering::Relaxed) * 2;
            let prev = r.load(Ordering::Relaxed);
            r.store((prev + now) / 2, Ordering::Relaxed);
        }
    }

    /// Coordinator source-health snapshot write-back (demoted/removed
    /// states enter the sources face): `(source, SourceState)` pairs
    /// projected by ledger state. The Active arm hands a stale "demoted"
    /// view back to the busy-count driver (>0 = active, zero = waiting) —
    /// after a demoted source recovers, the busy driver does not take over
    /// non-waiting/active slots, so without this reset the RPC view would
    /// stay demoted forever.
    fn apply_source_book_states(&self, states: &[(u32, taiji_http::sources::SourceState)]) {
        use taiji_http::sources::SourceState;
        let mut s = crate::lock(&self.sources);
        for (source, st) in states {
            let Some(slot) = s.get_mut(*source as usize) else {
                continue;
            };
            match st {
                SourceState::Demoted => slot.state = "demoted".into(),
                SourceState::Removed => slot.state = "removed".into(),
                SourceState::Active => {
                    if slot.state == "demoted" {
                        // Lock order: source_busy is taken and
                        // released first (no nested inversion —
                        // note_source_busy only takes the sources lock
                        // while not holding the busy lock).
                        let busy = crate::lock(&self.source_busy)
                            .get(*source as usize)
                            .copied()
                            .unwrap_or(0);
                        slot.state = if busy > 0 { "active" } else { "waiting" }.into();
                    }
                }
            }
        }
    }

    /// Unified feed point for written-byte deltas: the grid sink write
    /// point and the degraded path's size deltas land here — the
    /// rate-conversion base (`written`) and the byte-level completion
    /// projection (`done_bytes`) advance together; the projection counter
    /// is never consumed by rate conversion (always monotonic).
    fn note_written_bytes(&self, delta: u64) {
        if delta > 0 {
            self.written.fetch_add(delta, Ordering::Relaxed);
            self.done_bytes.fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// Byte-level completed reading (read-only live projection): the block
    /// bookkeeping base plus this activation's real written bytes. Clamped
    /// down when the total length is known — wasted bytes from
    /// double-writes/retry rewrites never leak out (the projection stays
    /// <= totalLength); the final value is pinned to the bookkeeping final
    /// (the Done-tail store).
    pub(super) fn completed_bytes(&self) -> u64 {
        let bytes = self.done_bytes.load(Ordering::Relaxed);
        let total = self.total_len.load(Ordering::Relaxed);
        if total > 0 { bytes.min(total) } else { bytes }
    }

    /// External progress injection (the degraded path's tick face: the
    /// DegradedJob's own sink has no counting seam, so written/the
    /// completion projection are fed from `.part` size deltas — honest
    /// readings). The byte-level heartbeat is fed at the same point (the
    /// stall-detection source). A degraded task is single-source = source
    /// 0; the per-source write ledger is fed there too (honest source
    /// rates in the sources face).
    fn note_progress(&self, delta: u64) {
        if delta > 0 {
            self.note_written_bytes(delta);
            self.stall.note(delta);
            self.note_source_written(0, delta);
        }
    }

    /// Wait for a task-level stall: returns once byte growth stays at zero
    /// for `window` (the task-level home of `--timeout` read idle;
    /// cancellation via the caller's select/drop).
    pub(super) async fn wait_stalled(&self, window: Duration) {
        self.stall.wait_stall(window).await;
    }

    /// Output file path (available after Planning; empty before).
    pub(super) fn out_path_str(&self) -> String {
        crate::lock(&self.out_path).clone()
    }

    /// User URI order (the data source for the files[].uris face).
    pub(super) fn source_uris(&self) -> Vec<String> {
        crate::lock(&self.sources)
            .iter()
            .map(|s| s.url.clone())
            .collect()
    }

    /// RPC `http` sub-dictionary view (the promised fields). Per-source
    /// rates = measured sink-write-point readings (per-source conversion;
    /// sources with no readings yet are honestly 0). Source state values =
    /// waiting | active | demoted | removed | failed (probe failure /
    /// merge-table eviction / ledger terminal states).
    pub(super) fn http_view(&self) -> super::super::view::HttpView {
        let mut sources = crate::lock(&self.sources).clone();
        for (slot, r) in sources.iter_mut().zip(self.source_rates.iter()) {
            slot.rate = r.load(Ordering::Relaxed);
        }
        super::super::view::HttpView {
            final_url: crate::lock(&self.final_url).clone(),
            connections: self.connections.load(Ordering::Relaxed),
            extents_active: self.extents_active.load(Ordering::Relaxed),
            blocks_done: self.blocks_done.load(Ordering::Relaxed),
            blocks_total: self.blocks_total.load(Ordering::Relaxed),
            encoding: crate::lock(&self.encoding).clone(),
            rename_pending: self.rename_pending.load(Ordering::Relaxed),
            sources,
        }
    }
}

/// [`HttpLive`] adapter for the worker loop telemetry injection seam
/// (taiji-http [`WorkerTelemetry`]): the task telemetry write-back face
/// since the worker loop moved into the protocol crate — completion
/// detection / source in-flight / extents / connections all forward here,
/// while the live truth stays owned by this crate (the worker loop holds
/// zero telemetry state; reading semantics unchanged: paired +1/-1, and
/// note_source_busy is counted so same-source workers do not stomp).
struct LiveTelemetry(Arc<HttpLive>);

impl WorkerTelemetry for LiveTelemetry {
    fn grid_complete(&self) -> bool {
        self.0.is_complete()
    }

    fn note_source_busy(&self, src_idx: usize, delta: i64) {
        self.0.note_source_busy(src_idx, delta);
    }

    fn note_extent_active(&self, delta: i64) {
        if delta >= 0 {
            self.0
                .extents_active
                .fetch_add(delta as u64, Ordering::Relaxed);
        } else {
            self.0
                .extents_active
                .fetch_sub(delta.unsigned_abs(), Ordering::Relaxed);
        }
    }

    fn note_connection(&self, delta: i64) {
        if delta >= 0 {
            self.0
                .connections
                .fetch_add(delta as u64, Ordering::Relaxed);
        } else {
            self.0
                .connections
                .fetch_sub(delta.unsigned_abs(), Ordering::Relaxed);
        }
    }
}

/// Terminal payload (TaskOutcome::Http; `note` = Some for a task-level
/// error, `error_engine` = the engine-side structured failure (`taiji.*`
/// canonical code + refinement dimension; None = not refined). The
/// numeric-code refinement chain rides through DownloadResultEntry/
/// TorrentStatusView into the taiji-rpc rendering map).
pub(super) struct HttpEnd {
    pub total_len: u64,
    pub completed_len: u64,
    pub note: Option<String>,
    pub error_engine: Option<super::super::view::EngineFailure>,
}

/// The store half of RenameJournal (the "DB as journal" injection face):
/// record_intent = a single `UpsertHttpTask` row write — state=done and
/// the http sub-dictionary `rename_pending=true` land in one statement
/// (the done state and the intent share one transaction); clear_intent
/// clears the flag the same way. The pending list is session in-memory
/// bookkeeping (cross-restart read-back is the bootstrap replay face).
struct PersistJournal {
    persist: Option<PersistHandle>,
    /// Row mirror (shared with the driver; the critical section only
    /// clones — the lock is never held across an await).
    row: Arc<StdMutex<HttpTaskRow>>,
    pending: StdMutex<Vec<RenameIntent>>,
}

impl PersistJournal {
    fn new(persist: Option<PersistHandle>, row: Arc<StdMutex<HttpTaskRow>>) -> Self {
        PersistJournal {
            persist,
            row,
            pending: StdMutex::new(Vec::new()),
        }
    }

    /// Upsert a snapshot of the mirror row (one statement carries state +
    /// rename_pending).
    async fn upsert_mirror(&self, phase: TaskPhase, rename_pending: bool) -> HttpResult<()> {
        let row = {
            let mut r = crate::lock(&self.row);
            r.state = phase.as_v1_str().to_string();
            let mut cfg = HttpPersistConfig::from_json(&r.config_json);
            cfg.rename_pending = rename_pending;
            r.config_json = cfg.to_json();
            r.updated_at = now_epoch();
            r.clone()
        };
        match &self.persist {
            Some(p) => p
                .upsert_http_task(row)
                .await
                .map(|_| ())
                .map_err(|e| HttpError::Disk(e.to_string())),
            // No-persistence form (tests / bare runs): in-memory bookkeeping is the
            // truth.
            None => Ok(()),
        }
    }
}

impl RenameJournal for PersistJournal {
    fn record_intent<'a>(
        &'a self,
        intent: &'a RenameIntent,
    ) -> BoxJournalFuture<'a, HttpResult<()>> {
        Box::pin(async move {
            self.upsert_mirror(TaskPhase::Done, true).await?;
            {
                let mut pending = crate::lock(&self.pending);
                // gid dedup: repeated records for one task do not grow the
                // list — retry close-out is idempotent per task, and
                // multiple same-gid intents would only produce duplicate
                // close-outs.
                if !pending.iter().any(|i| i.gid == intent.gid) {
                    pending.push(intent.clone());
                }
            }
            info!(target: "taiji::core::http", gid = %intent.gid,
                "rename intent recorded before action (state=done + rename_pending)");
            Ok(())
        })
    }

    fn clear_intent<'a>(&'a self, gid: &'a str) -> BoxJournalFuture<'a, HttpResult<()>> {
        Box::pin(async move {
            self.upsert_mirror(TaskPhase::Done, false).await?;
            crate::lock(&self.pending).retain(|i| i.gid != gid);
            Ok(())
        })
    }

    fn load_pending(&self) -> BoxJournalFuture<'_, HttpResult<Vec<RenameIntent>>> {
        Box::pin(std::future::ready(Ok(crate::lock(&self.pending).clone())))
    }
}

/// The grid task's persistence sink (core provides the "SegmentSink store
/// implementation"): `write_at` -> positioned `.part` writes;
/// `complete_block` -> bitmap pipeline bookkeeping (the only persistence
/// entry after the coordinator decision). The pipeline is owned by the
/// driver loop; the sink accesses it under short `AsyncMutex` critical
/// sections (bookkeeping is synchronous).
struct HttpGridSink {
    file: FileSink,
    pipeline: Arc<AsyncMutex<HttpSnapshotPipeline>>,
    live: Arc<HttpLive>,
    /// The completion pre-hash coordinator (assembled when `--checksum` is
    /// set with a valid scheme; None = zero added surface on the write
    /// path, behavior unchanged). Write-path double-checks plus
    /// contiguous-prefix advance at the bookkeeping point.
    prefetch: Option<Arc<ChecksumPrefetch>>,
    /// IO metrics registry (the disk write-path feed seam —
    /// `taiji_disk_sink_writes_total`/`_bytes_total`/`sink_inflight`); the
    /// driver passes the session metrics registry, tests inject their own
    /// instance (bare global counters are banned).
    metrics: Arc<taiji_io::metrics::MetricsRegistry>,
}

impl SegmentSink for HttpGridSink {
    fn write_at(
        &self,
        seg: SegId,
        off: u64,
        bytes: Bytes,
    ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
        let n = bytes.len() as u64;
        self.live.note_written_bytes(n);
        self.live.note_source_written(seg.source, n);
        self.live.stall.note(n);
        // Pre-write check (the pre-hash gate): the target already inside
        // the declared/consumed zone means the block is already recorded
        // and this write is a late duplicate from a stolen lease —
        // rejecting it is lossless (duplicate-write waste is bounded by
        // the single decision point; here the consumed zone is tightened
        // to zero duplicates on disk). The post-write check runs after the
        // data lands (below).
        if let Some(pf) = self.prefetch.as_ref() {
            if pf.pre_write_reject(off) {
                return Box::pin(std::future::ready(Err(HttpError::Transport(
                    PREFETCH_ZONE_REJECTED.into(),
                ))));
            }
        }
        let prefetch = self.prefetch.clone();
        let metrics = Arc::clone(&self.metrics);
        Box::pin(async move {
            // Feed point (read-only counters): the disk write path —
            // write attempts + bytes; the in-flight enter/exit pair
            // balances (guard drop = the exit point, an early failure
            // return restores it too). Pre-write rejections are not
            // counted (that path never touches the disk).
            metrics.disk().note_sink_write(n);
            let _inflight = metrics.disk().enter_sink_write();
            self.file.write_at(seg, off, bytes).await?;
            // Post-write check: if the watermark crossed the target while
            // the write was in flight (an in-flight overshoot landing in
            // the consumed zone) -> invalidate the pre-hash and fall back
            // to full post-hoc verification at completion.
            if let Some(pf) = prefetch.as_ref() {
                pf.post_write_check(off);
            }
            Ok(())
        })
    }

    fn complete_block(
        &self,
        block: u64,
    ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
        let live = Arc::clone(&self.live);
        Box::pin(async move {
            let mut pipe = self.pipeline.lock().await;
            let fresh = pipe
                .complete_block(block)
                .map_err(|e| HttpError::Disk(e.to_string()))?;
            if fresh {
                // Incremental counting: block bookkeeping is always
                // "newly recorded" semantics, so +1 suffices (a full
                // bitmap rescan would be O(n^2); the resume base is seeded
                // once by the activation chain). The byte-level completion
                // projection does not advance here — the write point
                // (note_written_bytes) already advanced with the real
                // bytes (projection != bookkeeping).
                live.blocks_done.fetch_add(1, Ordering::Relaxed);
                // Block-completion event: wake the driver loop to re-check
                // completion immediately — the last block no longer waits
                // for the driver tick to be noticed as done.
                live.progress_notify.notify_one();
                // Contiguous completed-prefix advance (pre-hash face; under
                // the pipeline lock — the lock guarantees bitmap
                // consistency, the cursor advance is O(1) amortized).
                if let Some(pf) = self.prefetch.as_ref() {
                    let blocks_total = pipe.blocks_total();
                    if let Some(bm) = pipe.row().block_bitmap.as_deref() {
                        pf.note_block_recorded(bm, blocks_total);
                    }
                }
            }
            Ok(())
        })
    }
}
/// Driver inputs (assembled by the actor activation arm; payload clones
/// decouple it from actor state).
pub(super) struct HttpTaskRun {
    pub gid: Gid,
    pub uris: Vec<String>,
    pub dir: PathBuf,
    pub out: Option<String>,
    /// Restore row (registered by bootstrap/add; seeds the mirror on first
    /// activation only — reactivation is driven by `row_mirror` and
    /// resumes from the mirror's latest row).
    pub restore: Option<HttpTaskRow>,
    /// Existing row mirror (reactivation; None = first activation, the
    /// driver builds it).
    pub row_mirror: Option<Arc<StdMutex<HttpTaskRow>>>,
    /// Restored cookie rows (the cookie-replay seed; empty on the add
    /// path).
    pub cookies: Vec<TaskCookieRow>,
    /// Task cookie store (assembled by spawn_http_task: the replay seed and
    /// the capture face share one instance; the write-back loop and the
    /// driver reconcile through it).
    pub task_cookies: CookieStore,
    /// Runtime option face (wired: timeouts/credentials/proxy/UA/header/
    /// cert faces).
    pub opts: HttpTaskOpts,
    /// Per-host connection cap registry (session-level shared: counted
    /// across tasks per host; workers = connections acquire permits).
    pub per_host: HostCap,
    pub queue_pos: i64,
    pub persist: Option<PersistHandle>,
    pub limiter: Option<Arc<taiji_io::rate_limit::LimiterSet>>,
    pub token: CancellationToken,
    /// Session metrics face (the /metrics HTTP-family feed: task gauge
    /// slots + steal counters; injected by SessionActor).
    pub metrics: Arc<SessionMetrics>,
    /// Fixed-chain timing (started at the activation point — see
    /// [`ChainTrace`]).
    pub trace: ChainTrace,
}

/// Drive exit (consumed by the activate arm and turned into
/// TaskNotice::Ended).
pub(super) enum DriveStop {
    /// Download complete (incl. the empty file; the renamePending face shows
    /// via live/http_view).
    Done {
        total_len: u64,
        completed_len: u64,
    },
    Cancelled,
    /// Task-level failure: `failure` = the engine-side structured failure
    /// (canonical code + refinement dimension), `message` = the diagnostic
    /// face (numeric refinement flows through HttpEnd.error_engine into
    /// the taiji-rpc map, per code and per dimension).
    Failed {
        failure: super::super::view::EngineFailure,
        message: String,
    },
    /// If-Match conditional resume hit a 412 (server content changed) —
    /// this attempt ends; the bitmap is NOT cleared here, the [`drive`]
    /// outer loop handles it uniformly (clear bitmap/progress -> re-probe
    /// -> restart from zero; budget exhausted -> explicit failure).
    /// Normally never leaks to the actor watcher (digested inside the
    /// outer loop; the tasks.rs defensive arm is an invariant backstop).
    ContentRestart,
}

/// Activation entry: spawns the driver task and returns the live counters
/// handle, the row mirror, the pause flag and the driver `JoinHandle` (the
/// actor watcher consumes `DriveStop` into `TaskNotice::Ended` — the same
/// close-out split as the torrent engine).
pub(super) fn spawn_http_task(
    mut run: HttpTaskRun,
) -> (
    Arc<HttpLive>,
    Arc<StdMutex<HttpTaskRow>>,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<DriveStop>,
) {
    let live = Arc::new(HttpLive::new(&run.uris));
    // Task cookie store: the capture face = the shared store
    // passed in at activation assembly (the driver never resets it — a
    // reset would erase the persisted set from memory and, with the
    // write-back loop, amount to clearing the store on activation);
    // Set-Cookie capture goes into it, restore replay goes through the
    // request face (restored_cookie_pairs) — the frozen `CookieStore`
    // surface only has `absorb(&Url, ..)` as a mutating entry and core has
    // no Url construction seam (taiji-http is frozen and the dependency
    // face must not grow), so jar-level direct replay waits for that seam.
    // The persisted set's survival is carried by the write-back loop's
    // baseline merge (below).
    let mirror: Arc<StdMutex<HttpTaskRow>> = match run.row_mirror.take() {
        Some(m) => m,
        None => Arc::new(StdMutex::new(match &run.restore {
            Some(r) => r.clone(),
            None => HttpTaskRow {
                gid: run.gid.to_string(),
                url: run.uris.first().cloned().unwrap_or_default(),
                final_url: String::new(),
                mirrors_json: None,
                state: TaskPhase::Queued.as_v1_str().into(),
                queue_pos: run.queue_pos,
                dir: run.dir.display().to_string(),
                out: String::new(),
                // The concurrency intent is frozen onto the row: the
                // starting concurrency on resume/reactivation is the same
                // value as the first run (AIMD start + loop cap) — after a
                // kill -9, bootstrap replays this face instead of degrading
                // to a single connection via session defaults.
                config_json: HttpPersistConfig {
                    concurrency: Some(HttpConcurrencyPersist::of(&run.opts)),
                    ..HttpPersistConfig::default()
                }
                .to_json(),
                probe_json: None,
                validator_digest: None,
                block_size: run.opts.block_size as i64,
                block_bitmap: None,
                block_count: None,
                total_done: 0,
                error_code: None,
                error_msg: None,
                created_at: now_epoch(),
                updated_at: now_epoch(),
            },
        })),
    };
    let pause = Arc::new(AtomicBool::new(false));
    // Cookie write-back loop (the cookie persistence wiring): periodically
    // snapshot the CookieStore during activation -> a full-set replacement
    // in sqlite (row-level comparison absorbs no-op snapshots). Under
    // full-set replacement the payload = the persisted baseline
    // ([`HttpTaskRun::cookies`]) union the capture snapshot — the snapshot
    // only holds this run's captures, so skipping the baseline would wash
    // away the previously persisted set (clearing the store on activation,
    // violating the "clear on completion/removal — never on
    // activation"); an empty snapshot skips the tick (an empty payload =
    // clear-all, the same root cause as wiping on the first tick). The
    // loop stops at drive close-out — clear-on-completion runs only after
    // the loop has stopped (no concurrent write-back), structurally
    // excluding the clear-then-revive race.
    let sync_stop = CancellationToken::new();
    // The run token is cloned before `run` moves into the driver — the
    // loop's second cancel face.
    let run_token = run.token.clone();
    let sync_join = run.persist.as_ref().map(|p| {
        let persist = p.clone();
        let store = run.task_cookies.clone();
        let gid_hex = run.gid.to_string();
        let base = run.cookies.clone();
        let stop = sync_stop.clone();
        let token = run_token.clone();
        tokio::spawn(async move {
            // creation_utc is frozen at assembly time (a write-amplification
            // bound): stable (name, domain, path) bookkeeping, stamped once
            // at first sight; baseline rows keep their stored value.
            // Restamping every tick would make the row-level comparison
            // always see a delta -> a full rewrite every 2s.
            let mut creation: HashMap<(String, String, String), i64> = base
                .iter()
                .map(|c| {
                    (
                        (c.name.clone(), c.domain.clone(), c.path.clone()),
                        c.creation_utc,
                    )
                })
                .collect();
            let mut tick = tokio::time::interval(COOKIE_SYNC_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    // If the wrapper is hard-aborted (the forceRemove
                    // token.cancel -> abort.abort() ordering), the wrapper
                    // future is dropped at any point in `drive().await` and
                    // the later `sync_stop.cancel()` is unreachable — this
                    // loop uses the run token as a second cancel face
                    // (cancel precedes abort; propagation does not depend
                    // on the wrapper surviving) and exits gracefully
                    // instead of living forever after row deletion,
                    // spamming FK-dangling upserts. On graceful shutdown
                    // the two arms coincide in time (token.cancel and the
                    // ordered drive exit), so behavior is unchanged.
                    _ = token.cancelled() => break,
                    _ = tick.tick() => {
                        let snap = store.snapshot();
                        if snap.is_empty() {
                            continue; // empty snapshot skips the tick (never a full clear)
                        }
                        let rows =
                            merged_cookie_rows(&gid_hex, &snap, &base, &mut creation);
                        if let Err(e) = persist
                            .upsert_task_cookies(
                                &gid_hex,
                                taiji_store::persist::TASK_KIND_HTTP,
                                rows,
                            )
                            .await
                        {
                            warn!(target: "taiji::core::http", gid = %gid_hex, %e,
                                "task cookie persist failed");
                        }
                    }
                }
            }
            cookie_loop_exit_obs_record(&gid_hex);
        })
    });
    let live_handle = Arc::clone(&live);
    let mirror_handle = Arc::clone(&mirror);
    let pause_handle = Arc::clone(&pause);
    let join = tokio::spawn(async move {
        let outcome = drive(
            run,
            Arc::clone(&live_handle),
            Arc::clone(&mirror_handle),
            Arc::clone(&pause_handle),
        )
        .await;
        sync_stop.cancel();
        if let Some(h) = sync_join {
            let _ = h.await;
        }
        // Terminal cookie clearing moved to the actor's close-out
        // (the unified close-out): the full terminal set done|error
        // clears there — both families share the one face, and the
        // error form raises the bypass alert with the exact
        // cleared count (the actor loads the count before clearing;
        // this wrapper has no store read face). What stays here is
        // only the ordering guarantee the close-out relies on: the
        // write-back loop has exited before the outcome surfaces.
        live_handle.connections.store(0, Ordering::Relaxed);
        live_handle.extents_active.store(0, Ordering::Relaxed);
        outcome
    });
    (live, mirror, pause, join)
}

/// Drive error (internal convergence).
enum HttpDriveError {
    Cancelled,
    Failed {
        failure: super::super::view::EngineFailure,
        message: String,
    },
}

/// Return guard for the degraded path's rate tick: any return path
/// (Done/Cancelled/Failed) aborts the tick task.
struct TickGuard(tokio::task::JoinHandle<()>);
impl Drop for TickGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Restart budget for changed content: at most one "clear bitmap, re-probe,
/// restart from zero" per activation. With a mirror whose ETag keeps
/// drifting from the authoritative source (a sick mirror / odd server), an
/// unbounded loop would burn bandwidth forever — a second 412 becomes an
/// explicit failure (the bad_range family code, distinguishable in the
/// diagnostic face).
const CONTENT_RESTART_BUDGET: u32 = 1;

/// The drive outer loop: a single attempt is unchanged; the only addition
/// is the bounded re-entry of [`DriveStop::ContentRestart`] — If-Match 412
/// (content changed) -> clear bitmap/progress/probe facts -> re-probe from
/// zero (resume detection necessarily starts from zero: the probe facts are
/// cleared, and the `.part` second line of defense falls back to the length
/// comparison).
async fn drive(
    mut run: HttpTaskRun,
    live: Arc<HttpLive>,
    mirror: Arc<StdMutex<HttpTaskRow>>,
    pause: Arc<AtomicBool>,
) -> DriveStop {
    let gid_hex = run.gid.to_string();
    let mut restarts_left = CONTENT_RESTART_BUDGET;
    loop {
        let stop = drive_attempt(
            &mut run,
            Arc::clone(&live),
            Arc::clone(&mirror),
            Arc::clone(&pause),
        )
        .await;
        if !matches!(stop, DriveStop::ContentRestart) {
            return stop;
        }
        if restarts_left == 0 {
            warn!(target: "taiji::core::http", gid = %gid_hex,
                "if-match 412 again after from-zero restart; failing task");
            return fail(
                run.persist.as_ref(),
                &mirror,
                EngineFailure::of_http_error(&HttpError::PreconditionFailed),
                "taiji.http.bad_range: server content changed again after \
                 from-zero restart (etag keeps drifting)"
                    .into(),
            )
            .await;
        }
        restarts_left -= 1;
        warn!(target: "taiji::core::http", gid = %gid_hex,
            "if-match 412: content changed mid-download; clearing bitmap, \
             re-probing and restarting from zero");
        {
            // Clear bitmap/progress/probe facts (the identity face
            // dir/out/config is kept): the next attempt re-enters the row
            // state at probing, and the `.part` is truncated by FromZero.
            let mut m = crate::lock(&mirror);
            m.block_bitmap = None;
            m.total_done = 0;
            m.probe_json = None;
            m.validator_digest = None;
        }
        // Reset live readings: keep completion detection from consuming the
        // previous attempt's leftovers (authoritative values are re-stored
        // by the next attempt's assembly).
        live.blocks_done.store(0, Ordering::Relaxed);
        live.done_bytes.store(0, Ordering::Relaxed);
    }
}

/// Final-path claim lease (the core-side ownership face of the claim
/// domain): [`plan_output`] already claims the final path when it decides
/// the output name (holder key = the task gid); this lease is the Drop
/// backstop of that claim for the driver attempt's lifetime — every
/// non-finalize exit (fail/cancel/pause/412 restart/empty-file direct
/// write) releases the claim (including a forceRemove hard abort dropping
/// the driver future: the lease is a future-local value and drops with
/// it). The rename-settled exits bypass Drop: Completed is released by the
/// finalize close-out (a repeated release is harmless); RenamePending
/// hands the claim to the renamePending polling bookkeeping via
/// [`FinalClaimLease::persist`] (the claim lasts until a later close-out
/// or task removal — in the window, a new task's plan_output hits
/// `taiji.http.path_conflict`).
struct FinalClaimLease {
    /// None = handed over (persist) — Drop no longer releases.
    path: Option<PathBuf>,
    holder: String,
}

impl FinalClaimLease {
    fn new(path: PathBuf, holder: String) -> Self {
        FinalClaimLease {
            path: Some(path),
            holder,
        }
    }

    /// Hand over (the RenamePending exit): the final-path claim stays in
    /// the registry to be released by the polling close-out; this lease's
    /// Drop no longer touches it.
    fn persist(&mut self) {
        self.path = None;
    }
}

impl Drop for FinalClaimLease {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            taiji_http::partfile::release_final_path(&p, &self.holder);
        }
    }
}

/// One drive attempt (probe -> plan -> dispatch; `run` passes through the
/// [`drive`] outer loop by `&mut` — the 412 restart face is re-entrant).
async fn drive_attempt(
    run: &mut HttpTaskRun,
    live: Arc<HttpLive>,
    mirror: Arc<StdMutex<HttpTaskRow>>,
    pause: Arc<AtomicBool>,
) -> DriveStop {
    let gid_hex = run.gid.to_string();
    let mut row = crate::lock(&mirror).clone();
    // Timing guard: a one-line summary across all exits; marks advance in
    // place.
    let mut trace = TraceOut {
        gid: gid_hex.clone(),
        trace: std::mem::take(&mut run.trace),
    };
    trace.trace.mark("drive");
    debug!(target: "taiji::core::http", gid = %gid_hex, "http task driver entered");

    // ---- Import-option folding (before any row-state write: a task whose
    // fold is rejected terminates without entering the probing phase) ----
    // The row payload's option subset is parsed at this single point (the
    // naming/suffix/checksum faces below reuse the same parse).
    // imported_options = the fork serialized option rows' migration
    // inventory — request identity (header/UA/proxy/credentials) folds
    // into the runtime options and the whole probe/fetch/degraded chain
    // consumes the folded values (without this, an authenticated task 401s
    // after a cancel/pause and a proxied task bypasses the proxy); the
    // three persistence keys (checksum/remote-time/incomplete-suffix) fold
    // into persisted_cfg and freeze onto the row ("DB as journal": the
    // verdict faces task_checksum/task_remote_time/suffix restore read the
    // row payload — a value that never lands on the row has no consumer).
    // Folding is idempotent: every activation re-folds from the verbatim
    // inventory and scalar keys overwrite with the same value, so repeated
    // activations produce zero drift.
    let mut persisted_cfg = HttpPersistConfig::from_json(&row.config_json);
    if let Some(imported) = persisted_cfg.imported_options.as_deref() {
        match fold_imported_options(run.opts.clone(), persisted_cfg.clone(), imported) {
            Ok((opts, cfg)) => {
                run.opts = opts;
                if cfg != persisted_cfg {
                    // The folded result syncs onto the row (local row +
                    // mirror + the upcoming probing-state upsert): without
                    // the mirror sync, mirror-replay faces like fail/pause
                    // would write the pre-fold payload back to the DB.
                    persisted_cfg = cfg;
                    let json = persisted_cfg.to_json();
                    crate::lock(&mirror).config_json = json.clone();
                    row.config_json = json;
                }
            }
            Err(e) => {
                return fail(
                    run.persist.as_ref(),
                    &mirror,
                    EngineFailure::bare("taiji.option.invalid"),
                    format!("imported options: {e}"),
                )
                .await;
            }
        }
    }

    // ---- Probing ----
    set_state(&mirror, TaskPhase::Probing);
    row.state = TaskPhase::Probing.as_v1_str().into();
    let _ = upsert_row(run.persist.as_ref(), &row).await;
    trace.trace.mark("probe_row");
    // Transport config (option wiring): timeout/retry/proxy/cert faces are
    // projected from the task runtime options (the defaults backstop in
    // HttpTaskOpts).
    let client = match HttpClient::new(run.opts.to_client_config()) {
        Ok(c) => c,
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                &mirror,
                EngineFailure::of_http_error(&e),
                format!("client: {e}"),
            )
            .await;
        }
    };
    trace.trace.mark("client");
    // Task cookie store (per-task isolation): the capture face =
    // the shared store assembled at spawn (holding the restore replay
    // seed); the replay face = restored cookies matched against the first
    // source request by domain/path/Secure (see the restored_cookie_pairs
    // divergence note). Auth/UA/header faces ride the runtime options
    // (Basic pre-auth + 401 Digest challenge response live in the client
    // layer, credentials = --http-user/--http-passwd).
    let mut ctx = RequestCtx {
        task_cookies: Some(run.task_cookies.clone()),
        auth: run.opts.auth.clone(),
        user_agent: run.opts.user_agent.clone(),
        headers: run.opts.headers.clone(),
        // `--referer` (the domain 2 knob): carried on every hop (probe
        // and fetch share the same seam — the ctx clone propagates the
        // whole worker face).
        referer: run.opts.referer.clone(),
        ..RequestCtx::default()
    };
    ctx.cookies = restored_cookie_pairs(&run.uris, &run.cookies);
    let mut probed: Vec<ProbedSource> = Vec::new();
    for uri in &run.uris {
        let kind = if uri.starts_with("ftp://") || uri.starts_with("ftps://") {
            TransportKind::Ftp
        } else {
            TransportKind::Http
        };
        // Cancellation: a pause/shutdown during probing exits immediately
        // (a probe can park for a long time — slow origins / hung
        // connections; the token wins).
        let probe: Pin<Box<dyn Future<Output = HttpResult<ProbeVerdict>> + Send>> = match kind {
            TransportKind::Ftp => Box::pin(probe_ftp_source(&run.opts, uri, &ctx)),
            _ => Box::pin(probe_uri(&client, uri, &ctx)),
        };
        let outcome = tokio::select! {
            _ = run.token.cancelled() => {
                return cancelled_row(run, &mirror, &pause).await;
            }
            r = probe => r,
        };
        if let Err(e) = &outcome {
            warn!(target: "taiji::core::http", gid = %gid_hex, code = e.code(),
                uri = %redact_uri(uri), "probe failed; source dropped");
            live.set_source_state(probed.len(), "failed");
        }
        probed.push(ProbedSource {
            uri: uri.clone(),
            kind,
            outcome,
        });
    }
    trace.trace.mark("probe_ret");
    // `--checksum` (merge table): a length mismatch is not a hard failure —
    // the verifiable-by-checksum source wins (the first source's length
    // group is authoritative), and the completion-time verdict decides.
    let checksum = task_checksum(&row.config_json).and_then(|raw| {
        let (scheme, digest) = raw.split_once('=')?;
        let scheme = scheme.trim();
        let digest = digest.trim();
        (!scheme.is_empty() && !digest.is_empty()).then(|| (scheme.to_string(), digest.to_string()))
    });
    let plan = match taiji_http::probe::merge_probes(MergeInput {
        sources: probed,
        checksum,
    }) {
        Ok(p) => p,
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                &mirror,
                EngineFailure::of_http_error(&e),
                format!("{}: probe merge failed", e.code()),
            )
            .await;
        }
    };
    let authoritative_url = match &plan {
        MergedPlan::Segmented { authoritative, .. }
        | MergedPlan::SingleConnection { authoritative, .. } => {
            let url = authoritative.final_url.clone();
            *crate::lock(&live.final_url) = url.clone();
            *crate::lock(&live.encoding) = authoritative.encoding.clone();
            url
        }
        MergedPlan::EmptyFile { .. } => run.uris.first().cloned().unwrap_or_default(),
    };

    // ---- Planning (naming/conflict resolution; blocking face on
    // spawn_blocking) ----
    // The row stays probing: planning is a runtime-only phase and the
    // http_task.state value domain (queued|probing|downloading|paused|
    // error|done) has no planning — a row that crashes/shuts down in this
    // window stays probing (inside the resume read set), never an orphan.
    // The runtime-phase distinction never enters the persisted payload.
    //
    // Incomplete suffix: the task's persisted value wins over the current
    // default — a default change never cuts an in-flight resume; an
    // externally corrupted persisted value is defensively rejected (never
    // a silent fallback to the default pretending to apply). The payload
    // was parsed at the activation entry (the same source as the fold).
    // The suffix resolves before the name: the sanitizer's byte budget
    // shrinks by the task suffix.
    let persisted_suffix = persisted_cfg.incomplete_suffix;
    // Imported-bitmap rows disable auto-rename: when imported data (the
    // `.part`) meets an existing final file, a silent rename would point
    // the task at `f.1.iso`, severing the `.part` association and orphaning
    // the data; disabled, the creation-time check reports the explicit
    // conflict (`taiji.http.path_conflict`).
    let auto_file_renaming = !persisted_cfg.imported_progress;
    let suffix = match IncompleteSuffix::restore_from_config(
        Some(&persisted_suffix),
        &IncompleteSuffix::default(),
    ) {
        Ok(s) => s,
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                &mirror,
                EngineFailure::of_http_error(&e),
                e.to_string(),
            )
            .await;
        }
    };
    //
    // Channel tiering: URL-derived names go through full sanitization
    // (illegal chars/control chars/separators -> `_`, reserved names
    // suffixed, trailing dots/spaces stripped, byte truncation preserving
    // the extension — sanitization instead of pure rejection:
    // URL names are the main source of dirty data and pure
    // rejection causes a real failure rate). User-explicit names (`out=`)
    // take the light channel (strip path components + length + reserved
    // names, no character replacement — the cross-product consensus; the
    // acceptance face `sanitize_out_option` already rejects
    // separators/colons/reserved names/trailing dot-space/deceptive code
    // points and applies a 255-byte cap; shrinking a capped name to the
    // engine budget is the light channel's job). The sanitized name is the
    // task's final name, reported back through out_path/the row mirror
    // (the actual name is reported — a declared divergence). The byte
    // budget = 254 - suffix length - 2 (the `.N` candidate marker): the
    // full `<final><candidate><suffix>` shape stays <= 254 <= NAME_MAX — a
    // final name of exactly 254 would make `<final>.part` = 259, over the
    // limit.
    let name_budget = engine_name_budget(&suffix);
    let name = match run.out.as_deref() {
        Some(user) if !user.trim().is_empty() => sanitize_user_name_with_budget(user, name_budget),
        _ => sanitize_generated_name_with_budget(
            &derive_name_from_url(&authoritative_url).unwrap_or_else(|| FALLBACK_NAME.to_string()),
            name_budget,
        ),
    };
    let final_path = run.dir.join(&name);
    let planned = {
        let final_path = final_path.clone();
        let suffix = suffix.clone();
        let holder = gid_hex.clone();
        tokio::task::spawn_blocking(move || {
            plan_output(
                final_path,
                &suffix,
                CreationPolicy { auto_file_renaming },
                &holder,
            )
        })
        .await
    };
    let paths = match planned {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            return fail(
                run.persist.as_ref(),
                &mirror,
                EngineFailure::of_http_error(&e),
                e.to_string(),
            )
            .await;
        }
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                &mirror,
                EngineFailure::bare("taiji.http.failed"),
                format!("plan join: {e}"),
            )
            .await;
        }
    };
    *crate::lock(&live.out_path) = paths.final_path.display().to_string();
    {
        let mut m = crate::lock(&mirror);
        m.dir = run.dir.display().to_string();
        m.out = paths
            .final_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        row.dir = m.dir.clone();
        row.out = m.out.clone();
    }
    trace.trace.mark("plan");
    // Final-path claim lease: plan_output has claimed the path; every exit
    // of this attempt is closed out through it (see [`FinalClaimLease`]).
    let mut final_lease = FinalClaimLease::new(paths.final_path.clone(), gid_hex.clone());

    match plan {
        // ---- Empty file: create a 0-byte output and done ----
        MergedPlan::EmptyFile { .. } => {
            let final_path = paths.final_path.clone();
            let created =
                tokio::task::spawn_blocking(move || std::fs::write(&final_path, b"")).await;
            match created {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    return fail(
                        run.persist.as_ref(),
                        &mirror,
                        EngineFailure::bare("taiji.http.failed"),
                        format!("empty file: {e}"),
                    )
                    .await;
                }
                Err(e) => {
                    return fail(
                        run.persist.as_ref(),
                        &mirror,
                        EngineFailure::bare("taiji.http.failed"),
                        format!("join: {e}"),
                    )
                    .await;
                }
            }
            // `--checksum` completion-time verification (a 0-byte file is
            // judged too — the expected value is the empty-content digest;
            // mismatch = task error. No final file survives a mismatch — a
            // 0-byte file has no `.part` half-done form, so deletion is the
            // degenerate face of "never leave a corrupt final file").
            if let Some(cs) = task_checksum(&row.config_json) {
                if let Err(e) = verify_checksum(&paths.final_path, &cs).await {
                    if let Err(rm) = tokio::fs::remove_file(&paths.final_path).await {
                        warn!(target: "taiji::core::http", gid = %gid_hex, path = %paths.final_path.display(),
                            error = %rm, "checksum mismatch: failed to remove empty final file");
                    }
                    return fail(
                        run.persist.as_ref(),
                        &mirror,
                        EngineFailure::of_http_error(&e),
                        e.to_string(),
                    )
                    .await;
                }
            }
            set_state(&mirror, TaskPhase::Done);
            row.state = TaskPhase::Done.as_v1_str().into();
            let _ = upsert_row(run.persist.as_ref(), &row).await;
            info!(target: "taiji::core::http", gid = %gid_hex, "empty file download done");
            DriveStop::Done {
                total_len: 0,
                completed_len: 0,
            }
        }
        MergedPlan::SingleConnection {
            source,
            authoritative,
            ..
        } => {
            drive_degraded(
                run,
                &live,
                &mirror,
                &pause,
                row,
                paths,
                &mut final_lease,
                suffix,
                source,
                authoritative,
                client,
                ctx,
            )
            .await
        }
        MergedPlan::Segmented {
            total_len,
            sources,
            authoritative,
            ..
        } => {
            drive_segmented(
                run,
                &live,
                &mirror,
                &pause,
                row,
                paths,
                &mut final_lease,
                total_len,
                sources,
                authoritative,
                client,
                ctx,
                &mut trace.trace,
            )
            .await
        }
    }
}

/// The degraded path: single connection, no bitmap, resume is from zero.
/// A known total length runs the full taiji-http `DegradedJob` chain; with
/// no total length, EOF delimits and this function drives directly.
#[expect(
    clippy::too_many_arguments,
    reason = "drive-chain hand-off passes the run state explicitly; bundling is a later phase"
)]
async fn drive_degraded(
    run: &HttpTaskRun,
    live: &Arc<HttpLive>,
    mirror: &Arc<StdMutex<HttpTaskRow>>,
    pause: &Arc<AtomicBool>,
    mut row: HttpTaskRow,
    paths: OutputPaths,
    final_lease: &mut FinalClaimLease,
    suffix: IncompleteSuffix,
    source: PlanSource,
    authoritative: ProbeResult,
    client: HttpClient,
    ctx: RequestCtx,
) -> DriveStop {
    let gid_hex = run.gid.to_string();
    set_state(mirror, TaskPhase::Downloading);
    row.state = TaskPhase::Downloading.as_v1_str().into();
    let _ = upsert_row(run.persist.as_ref(), &row).await;
    live.connections.store(1, Ordering::Relaxed);
    live.note_source_busy(0, 1);
    // Driver tick (the rate-conversion face): the degraded path has no
    // segmented driver loop, so a standalone tick feeds `note_tick` plus
    // `.part` size deltas into written/done (the DegradedJob's own sink has
    // no counting seam; without it live.rate stays 0 and getGlobalStat/
    // tellActive under-report degraded tasks). The guard-style
    // abort covers every return path.
    let _tick_guard = TickGuard({
        let live = Arc::clone(live);
        let part_path = paths.part_path.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(DRIVER_TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_len = 0u64;
            loop {
                tick.tick().await;
                if let Ok(m) = tokio::fs::metadata(&part_path).await {
                    let len = m.len();
                    let delta = len.saturating_sub(last_len);
                    last_len = len;
                    live.note_progress(delta);
                }
                live.note_tick();
                live.source_rate_tick();
            }
        })
    });

    let total = authoritative.total_len;
    // Backfill totalLength mid-download: a known total is visible from
    // activation (filling it only at close-out would leave the
    // mid-download view a fabricated 0).
    if let Some(t) = total {
        live.total_len.store(t, Ordering::Relaxed);
    }
    let finalizer = Finalizer::new(Arc::new(PersistJournal::new(
        run.persist.clone(),
        Arc::clone(mirror),
    )));
    // Known total length: the DegradedJob chain (write -> sync -> close
    // handle -> finalize); no total length: EOF delimits and this function
    // closes out the rename. The cancel window is wrapped in select (biased
    // with the result arm first: when finalize and cancel are ready
    // simultaneously the result wins — an outcome=Done must not be
    // re-judged into a cancellation by a racing pause).
    // Transport-family dispatch (degraded order preserved): an FTP source
    // -> [`FtpTransport`] (the first fetch at offset 0 is a plain RETR —
    // REST appears only on offset-carrying segments); an HTTP source -> a
    // full GET stream. The no-total-length FTP shape is already dropped at
    // probe time ([`probe_ftp_source`]), so the EOF-delimited path is
    // always HTTP.
    // Checksum pipelining (shared by the degraded/EOF streams): with
    // `--checksum` and a valid scheme, the digest advances with the
    // sequential stream through the feed closure (a single connection's
    // write order IS byte order, zero coordination); at completion the
    // final value is compared directly, with no re-read of the final file —
    // the hash is absorbed by the download duration. An invalid/unset
    // scheme leaves the feed absent and completion falls back to the
    // existing full post-hoc verification (same error timing and shape).
    let (cs_opt, digest_holder, feed) = degraded_checksum_faces(&row.config_json);
    let outcome: Result<(u64, FinalizeOutcome), HttpDriveError> = match total {
        Some(total) => {
            let transport: Box<dyn SegmentTransport> = match source.kind {
                TransportKind::Ftp => {
                    let t = match FtpTransport::for_uri(run.opts.to_ftp_config(), &source.uri) {
                        Ok(t) => t,
                        Err(e) => {
                            return fail(
                                run.persist.as_ref(),
                                mirror,
                                EngineFailure::of_http_error(&e),
                                e.to_string(),
                            )
                            .await;
                        }
                    };
                    Box::new(t)
                }
                _ => Box::new(HttpBodyTransport::new(
                    client,
                    source.uri.clone(),
                    run.metrics.io_registry().clone(),
                )),
            };
            let job = DegradedJob {
                gid: gid_hex.clone(),
                final_path: paths.final_path.clone(),
                suffix,
                total_len: total,
                allocation: FileAllocation::None,
                // Throttle gate: the degraded path shares the grid path's
                // assembly — the DegradedJob wraps the sink in a
                // ThrottledSink internally.
                limiter: HttpLimiter::new(run.limiter.clone()),
                checksum_feed: feed,
            };
            let fut = job.run(transport.as_ref(), &ctx, &finalizer);
            tokio::select! {
                biased;
                r = fut => r.map(|o| (total, o))
                    .map_err(|e| HttpDriveError::Failed { failure: EngineFailure::of_http_error(&e), message: e.to_string() }),
                _ = run.token.cancelled() => Err(HttpDriveError::Cancelled),
            }
        }
        None => {
            let transport = HttpBodyTransport::new(
                client,
                source.uri.clone(),
                run.metrics.io_registry().clone(),
            );
            match download_eof_stream(
                &run.token,
                &transport,
                &ctx,
                &paths.part_path,
                &run.limiter,
                live,
                run.opts.read_timeout,
                feed.clone(),
            )
            .await
            {
                Err(e) => Err(e),
                Ok((written, closed)) => {
                    let intent = RenameIntent {
                        gid: gid_hex.clone(),
                        part_path: paths.part_path.clone(),
                        final_path: paths.final_path.clone(),
                        expected_len: written,
                    };
                    match finalizer.finalize(&intent, closed).await {
                        Ok(o) => Ok((written, o)),
                        Err(e) => Err(HttpDriveError::Failed {
                            failure: EngineFailure::bare("taiji.http.failed"),
                            message: format!("finalize journal: {e}"),
                        }),
                    }
                }
            }
        }
    };
    live.connections.store(0, Ordering::Relaxed);
    live.note_source_busy(0, -1);
    let completed = match outcome {
        Ok((written, rename_outcome)) => {
            // `--checksum` completion-time verification. Divergence declared
            // separately: on the degraded path the rename happens first
            // inside DegradedJob, so verification can only run on the final
            // file — a different position than the grid path's
            // "verify before rename". A renamePending (rename not settled)
            // is not verified; the close-out retry face applies as usual.
            // A mismatch rolls back the rename (the final file returns to
            // `.part` for manual inspection; if the rollback fails it is
            // deleted) — in both shapes no final file that fails
            // verification is left on disk, matching the grid path's disk
            // semantics of "failure = no final file".
            // The tee pre-hash face (the sequential-stream digest was
            // already fixed during the download) takes priority; with no
            // digest, the existing full post-hoc read-back runs (EOF-stream
            // form / invalid scheme).
            if let Some(cs) = cs_opt.clone().or_else(|| task_checksum(&row.config_json)) {
                if matches!(rename_outcome, FinalizeOutcome::Completed { .. }) {
                    let verdict = match prefetched_digest_hex(&digest_holder) {
                        Some(hex) => compare_digest(&cs, hex),
                        None => verify_checksum(&paths.final_path, &cs).await,
                    };
                    if let Err(e) = verdict {
                        rollback_final_file(&paths.part_path, &paths.final_path).await;
                        return fail(
                            run.persist.as_ref(),
                            mirror,
                            EngineFailure::of_http_error(&e),
                            e.to_string(),
                        )
                        .await;
                    }
                }
            }
            // `--remote-time`: after the rename settles, set the final
            // file's mtime from the remote Last-Modified; best effort
            // (a parse or set-time failure only warns — not a task
            // failure; aria2 is also best effort). Skipped in the
            // renamePending form (close-out retries carry no probe record —
            // an honest gap, declared separately).
            if matches!(rename_outcome, FinalizeOutcome::Completed { .. }) {
                if let (true, Some(lm)) = (
                    task_remote_time(&row.config_json),
                    authoritative.last_modified.as_deref(),
                ) {
                    if let Err(e) =
                        taiji_http::remotetime::apply_remote_mtime(&paths.final_path, lm).await
                    {
                        warn!(target: "taiji::core::http", gid = %gid_hex,
                            path = %paths.final_path.display(), error = %e,
                            "remote-time apply failed (download completed)");
                    }
                }
            }
            let pending = matches!(rename_outcome, FinalizeOutcome::RenamePending { .. });
            if pending {
                // Final-path claim hand-over: the renamePending polling
                // bookkeeping takes over (released on close-out success;
                // the task-removal path backstops).
                final_lease.persist();
            }
            live.rename_pending.store(pending, Ordering::Relaxed);
            written
        }
        Err(HttpDriveError::Cancelled) => {
            return cancelled_row(run, mirror, pause).await;
        }
        Err(HttpDriveError::Failed { failure, message }) => {
            return fail(run.persist.as_ref(), mirror, failure, message).await;
        }
    };
    // The byte-level projection is pinned to the bookkeeping final: after
    // close-out the live readings match the terminal entry (the bookkeeping
    // authority) and no longer drift with write points.
    live.done_bytes.store(completed, Ordering::Relaxed);
    live.total_len.store(completed, Ordering::Relaxed);
    set_state(mirror, TaskPhase::Done);
    let _ = upsert_row(run.persist.as_ref(), &mirror_row(mirror, TaskPhase::Done)).await;
    DriveStop::Done {
        total_len: completed,
        completed_len: completed,
    }
}

/// The degraded path's flow-control-wait liveness feed (the h2 flow-wait
/// exclusion criterion, [`taiji_http::stall`]): the degraded path has no
/// coordinator observation face, so it only feeds rate-limiter permit-wait
/// events into the task-level heartbeat (liveness evidence in the
/// zero-byte form).
struct FlowWaitPulse(taiji_http::stall::ByteHeartbeat);

impl RateSampleReporter for FlowWaitPulse {
    fn report(&self, _source: u32, _bytes: u64, permit_waited: Duration) {
        if permit_waited > Duration::ZERO {
            self.0.note_flow_wait();
        }
    }
}

/// The no-total-length degraded EOF-delimited stream: truncate-open the
/// `.part` -> full GET streamed positioned writes -> fsync (data before
/// the completion intent) -> close-handle credentials. Returns the bytes
/// received and the handle credentials (the caller closes out finalize).
/// The write face goes through `ThrottledSink` (the EOF stream shares the
/// grid/DegradedJob throttle assembly — a bare FileSink would bypass the
/// rate buckets); rate-limit wait events feed the flow-wait liveness at
/// the same point.
#[expect(
    clippy::too_many_arguments,
    reason = "transport/sink/throttle faces are passed explicitly; bundling is a later phase"
)]
async fn download_eof_stream(
    token: &CancellationToken,
    transport: &HttpBodyTransport,
    ctx: &RequestCtx,
    part_path: &Path,
    limiter: &Option<Arc<taiji_io::rate_limit::LimiterSet>>,
    live: &Arc<HttpLive>,
    stall_window: Duration,
    checksum_feed: Option<taiji_http::checksum::ByteFeed>,
) -> Result<(u64, HandlesClosed), HttpDriveError> {
    let part = PartFile::open(
        part_path.to_path_buf(),
        None,
        PartOpenPolicy::Restart,
        FileAllocation::None,
    )
    .await
    .map_err(|e| HttpDriveError::Failed {
        failure: EngineFailure::of_http_error(&e),
        message: e.to_string(),
    })?;
    // `--checksum` sequential-stream tee (the EOF stream is also a
    // single-connection sequential write — the digest is fixed as it
    // writes; the inner throttle assembly matches the DegradedJob shape).
    let sink: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::with_rate_reporter(
        Arc::new(taiji_http::checksum::TeeSink::new(
            Arc::new(FileSink::new(part.clone())) as Arc<dyn SegmentSink>,
            checksum_feed,
        )) as Arc<dyn SegmentSink>,
        HttpLimiter::new(limiter.clone()),
        Arc::new(FlowWaitPulse(live.stall.clone())) as Arc<dyn RateSampleReporter>,
    ));
    let extent = Extent {
        start: 0,
        len: u64::MAX - 1,
    };
    let fetch = transport.fetch(&extent, ctx, sink.as_ref());
    tokio::select! {
        _ = token.cancelled() => return Err(HttpDriveError::Cancelled),
        // Task-level stall (the `--timeout` home; the heartbeat is fed via
        // the TickGuard's disk-size deltas).
        _ = live.wait_stalled(stall_window) => {
            return Err(HttpDriveError::Failed {
                failure: EngineFailure {
                    code: "taiji.http.transport".into(),
                    kind: EngineFailureKind::TransportTimeout,
                },
                message: format!(
                    "read idle: no byte progress for {}s (--timeout)",
                    stall_window.as_secs()
                ),
            });
        }
        r = fetch => r.map_err(|e| HttpDriveError::Failed {
            failure: EngineFailure::of_http_error(&e),
            message: e.to_string(),
        })?,
    }
    part.sync_all().await.map_err(|e| HttpDriveError::Failed {
        failure: EngineFailure::of_http_error(&e),
        message: e.to_string(),
    })?;
    // Bytes received = the `.part` length (sequential writes advance from
    // 0; the sink face has no counter — FileSink drives directly, the
    // count takes the disk's word).
    let written = tokio::fs::metadata(part_path)
        .await
        .map(|m| m.len())
        .map_err(|e| HttpDriveError::Failed {
            failure: EngineFailure::bare("taiji.http.failed"),
            message: format!("part stat: {e}"),
        })?;
    Ok((written, part.close()))
}

/// Rate-observation relay (decouples the dynamic assembly order): the
/// throttled sink is constructed before the coordinator spawns, but the
/// report target (the coordinator handle) only exists after spawn returns —
/// this relay hangs off the sink first and backfills the handle after
/// spawn. Samples dropped before the backfill are sampling telemetry
/// semantics (the observation face never backpressures the write path); at
/// close-out it is set to `None`, withdrawing the handle (the channel
/// close joins the coordinator close-out order). Also carries the
/// task-level flow-wait liveness feed: any permit wait > 0 counts once
/// (the h2 flow-wait exclusion criterion, [`taiji_http::stall`]).
struct DeferredReporter {
    inner: StdMutex<Option<Arc<dyn RateSampleReporter>>>,
    /// Task-level flow-wait liveness (a `live.stall` clone — the same
    /// ledger as the byte counts).
    flow: taiji_http::stall::ByteHeartbeat,
}

impl DeferredReporter {
    /// Backfill/withdraw the report target (`None` = withdraw — the
    /// channel-close face of the drive close-out order).
    fn set(&self, reporter: Option<Arc<dyn RateSampleReporter>>) {
        *crate::lock(&self.inner) = reporter;
    }
}

impl RateSampleReporter for DeferredReporter {
    fn report(&self, source: u32, bytes: u64, permit_waited: Duration) {
        // Flow-wait event: a wait on the rate-limit face means data is
        // arriving and the write path is locally backpressured (including
        // h2 flow-control waits) — not stall evidence (the liveness face
        // of the exclusion criterion).
        if permit_waited > Duration::ZERO {
            self.flow.note_flow_wait();
        }
        if let Some(r) = crate::lock(&self.inner).as_ref() {
            r.report(source, bytes, permit_waited);
        }
    }
}

/// The grid path: probe the authoritative total length + the scheduling
/// plan (dynamic by default, static kept as the control/fallback baseline) +
/// the coordinator's single decision point + the bitmap snapshot pipeline
/// (fsync before the row lands) + finalize. The slow-start-endpoint
/// two-arm detection is a read-only consumer of the existing RuntimeStats
/// polling ([`taiji_http::worker::slowstart_reached`], zero scheduling
/// involvement).
#[expect(
    clippy::too_many_arguments,
    reason = "drive-chain hand-off passes the run state explicitly; bundling is a later phase"
)]
async fn drive_segmented(
    run: &HttpTaskRun,
    live: &Arc<HttpLive>,
    mirror: &Arc<StdMutex<HttpTaskRow>>,
    pause: &Arc<AtomicBool>,
    mut row: HttpTaskRow,
    paths: OutputPaths,
    final_lease: &mut FinalClaimLease,
    total_len: u64,
    sources: Vec<PlanSource>,
    authoritative: ProbeResult,
    client: HttpClient,
    ctx: RequestCtx,
    trace: &mut ChainTrace,
) -> DriveStop {
    let gid_hex = run.gid.to_string();
    // Block granularity: immutable per task — a row with a persisted
    // (non-zero) block_size wins (the default only fills absence); an
    // out-of-domain value is a task-level rejection. Unconditionally
    // overwriting with DEFAULT_BLOCK_SIZE would let a resume reinterpret an
    // old bitmap under a new granularity and fabricate progress.
    let row_bs = row.block_size.max(0) as u64;
    let bs = if row_bs == 0 {
        DEFAULT_BLOCK_SIZE
    } else {
        match block_size_domain(row_bs) {
            Ok(()) => row_bs,
            Err(msg) => {
                return fail(
                    run.persist.as_ref(),
                    mirror,
                    EngineFailure::bare("taiji.option.invalid"),
                    msg,
                )
                .await;
            }
        }
    };
    let count = total_len.div_ceil(bs);
    row.block_size = bs as i64;
    row.block_count = Some(count as i64);

    // Resume decision (the condensed form): a row digest matching this
    // probe -> the bitmap is a candidate; otherwise the bitmap is cleared
    // (and the "exists + size" second line of defense in recover closes it
    // out).
    //
    // Imported-bitmap rows on FIRST activation (probe_json absent) get a
    // downgraded digest gate: the imported seeded digest only knows
    // path + total length (the fork keeps no etag/last_modified), while a
    // real server always sends the strong validators — the digest
    // necessarily drifts, so gating the bitmap on it would void imported
    // progress at activation. The downgrade skips the digest comparison and
    // bitmap trust falls to the immediately following "exists + size"
    // second line (the probe's authoritative total still participates in
    // last-block truncation); once the first activation lands
    // probe_json/digest (written back unconditionally below), later resumes
    // return to the strict gate — a row whose resource truly drifted still
    // restarts from zero from the second activation on.
    let imported_resume = HttpPersistConfig::from_json(&row.config_json).imported_progress
        && row.probe_json.is_none();
    let fresh_validator = authoritative.resume_validator();
    let fresh_facts = ValidatorFacts {
        final_url_path: fresh_validator.final_url_path.clone(),
        total_len: fresh_validator.total_len,
        etag: fresh_validator.etag.clone(),
        last_modified: fresh_validator.last_modified.clone(),
        encoding_ok: fresh_validator.encoding_ok,
    };
    let fresh_digest = validator_digest(&fresh_facts).ok();
    let resume_ok = imported_resume
        || row
            .validator_digest
            .as_deref()
            .zip(fresh_digest.as_deref())
            .is_some_and(|(a, b)| a == b);
    if !resume_ok {
        row.block_bitmap = None;
        row.total_done = 0;
    }
    row.probe_json = Some(serde_json::to_string(&fresh_facts).unwrap_or_default());
    row.validator_digest = fresh_digest;

    // If-Match conditional resume: when the probe response confirmed a
    // strong ETag, every Range fetch carries `If-Match: <etag>` — pushing
    // the response-side ETag validation to the server as a precondition
    // (content changed -> 412 -> [`DriveStop::ContentRestart`] clears the
    // bitmap and restarts from zero), so misaligned bytes never land and
    // are not discovered only by the checksum verdict after everything is
    // written. Enablement is pinned to "strong ETag" ([`strong_etag`]:
    // W/ weak tags and whitespace count as missing) — weak-ETag/no-ETag
    // paths are unchanged (no If-Match, dodging servers with non-compliant
    // If-Match handling); a user-supplied if-match header is not
    // overridden (same-header double-value ambiguity under reqwest's
    // append semantics).
    let mut ctx = ctx;
    if let Some(etag) = strong_etag(fresh_validator.etag.as_deref())
        && !ctx
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("if-match"))
    {
        info!(target: "taiji::core::http", gid = %gid_hex,
            "strong etag confirmed by probe; range requests carry if-match");
        ctx.headers.push(("if-match".into(), etag));
    }

    // Second line of defense (per-block "exists + size" checks; with
    // prealloc the size check always passes). For imported rows the `.part`
    // length = the fork's write frontier (the fork is not a prealloc form),
    // so differing from the probed total is normal, not a foreign file —
    // the length-equality gate does not apply (the expected_len = None
    // channel: skip the length-vs-total comparison, the per-block
    // cumulative size checks still decide; a partial last block is judged
    // conservatively at whole-block granularity, so a complete download
    // re-fetches at most ~1 extra block — the safe direction).
    let expected_len = if imported_resume {
        None
    } else {
        Some(total_len)
    };
    let part_facts = part_facts_of(&paths.part_path).await;
    let rec = recover::recover_http_task(&row, part_facts, expected_len);
    row = rec.row;
    let from_zero = matches!(rec.resumability, Resumability::FromZero { .. });
    if !from_zero {
        info!(target: "taiji::core::http", gid = %gid_hex,
            done = rec.blocks_done, total = rec.blocks_total,
            "resuming from validated bitmap");
    }
    // Activation assembly mirrors back-sync: written back as soon as the
    // resume/clear/probe-facts settle, so the saveSession/pause row write
    // before the first snapshot tick no longer carries stale progress (the
    // sync-point contract lives in [`sync_mirror_progress`]).
    sync_mirror_progress(mirror, &row);

    // ---- Small-task fast-path dispatch: at most [`SMALL_TASK_MAX_BLOCKS`]
    // blocks, no resume progress (bitmap/recovery all zero), AND an
    // explicit concurrency intent >= 2 (min(split, cap) — a parallel intent
    // must be present to be expressible) -> skip the grid assembly and
    // fetch the whole file as parallel byte ranges ([`drive_small`]). The
    // explicit intent is detected against the frozen defaults (with the
    // default cap raised to 16, the default (5,16) min is also >= 2 — the
    // fast path's role is to honor an EXPLICIT user intent; the default
    // shape keeps the grid path, whose AIMD start is already parallel and
    // which carries the bitmap resume/block bookkeeping invariants; an
    // explicit parameter equal to the default is treated as the default
    // face, an acceptable equivalence). A row with any completed blocks
    // keeps the grid path: bitmap resume and block bookkeeping unchanged.
    let explicit_conn_intent = run.opts.split != DEFAULT_SPLIT
        || run.opts.max_conn_per_server != DEFAULT_MAX_CONN_PER_SERVER;
    if count <= SMALL_TASK_MAX_BLOCKS
        && rec.blocks_done == 0
        && explicit_conn_intent
        && run.opts.split.min(run.opts.max_conn_per_server) >= 2
    {
        return drive_small(
            run,
            live,
            mirror,
            pause,
            row,
            paths,
            final_lease,
            total_len,
            sources,
            authoritative,
            client,
            ctx,
            trace,
        )
        .await;
    }

    set_state(mirror, TaskPhase::Downloading);
    row.state = TaskPhase::Downloading.as_v1_str().into();
    if let Err(e) = upsert_row(run.persist.as_ref(), &row).await {
        warn!(target: "taiji::core::http", gid = %gid_hex, %e, "http row persist failed");
    }
    live.total_len.store(total_len, Ordering::Relaxed);
    live.blocks_total.store(count, Ordering::Relaxed);
    live.blocks_done.store(rec.blocks_done, Ordering::Relaxed);
    // Byte-level projection seed = the block bookkeeping base (the resumed
    // bitmap's completed bytes — the projection starts from the bookkeeping
    // truth, then advances monotonically with sink write points).
    live.done_bytes
        .store(row.total_done.max(0) as u64, Ordering::Relaxed);
    // The sources face aligns with the merge-table product: sources
    // participating in segmentation are matched by URI identity (probe
    // redirects are paired by user URI order); non-participating sources =
    // "failed" (probe-failure eviction / merge-table eviction / no-range
    // degradation not selected — an honest terminal state within this
    // task).
    {
        let mut srcs = crate::lock(&live.sources);
        for slot in srcs.iter_mut() {
            if sources.iter().any(|s| s.uri == slot.url) {
                continue;
            }
            slot.state = "failed".into();
        }
    }

    // Pipeline + `.part` (Restart truncates from zero / Resume only grows
    // and pads; prealloc lays out the total length — the resume decision
    // depends on `.part` length == total length).
    let pipeline = match HttpSnapshotPipeline::new(
        row.clone(),
        Some(total_len),
        Arc::new(PartFileSync::new(paths.part_path.clone())),
    ) {
        Ok(p) => Arc::new(AsyncMutex::new(p)),
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::bare("taiji.http.failed"),
                format!("pipeline: {e}"),
            )
            .await;
        }
    };
    let policy = if from_zero {
        PartOpenPolicy::Restart
    } else {
        PartOpenPolicy::Resume
    };
    let part = match PartFile::open(
        paths.part_path.clone(),
        Some(total_len),
        policy,
        FileAllocation::Prealloc,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::of_http_error(&e),
                e.to_string(),
            )
            .await;
        }
    };

    // Grid (the resumed bitmap is preloaded: done blocks are not refetched).
    let mut grid = match BlockGrid::new(bs, total_len) {
        Ok(g) => g,
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::of_http_error(&e),
                e.to_string(),
            )
            .await;
        }
    };
    {
        let pipe = pipeline.lock().await;
        if let Some(bm) = pipe.row().block_bitmap.as_deref() {
            for b in 0..count {
                if bit_test(bm, b) {
                    let _ = grid.record(b);
                }
            }
        }
    }

    // Completion pre-hash assembly: with `--checksum` set and a valid
    // scheme, start the coordinator (the reader task follows the contiguous
    // completed prefix reading back from the `.part`, overlapping the
    // download; the resumed bitmap's initial prefix is seeded up front, so
    // a resume's completed portion amortizes over the remaining download
    // time). An invalid scheme does not assemble; completion reports
    // OptionInvalid from `verify_checksum` (same timing and shape).
    let checksum_prefetch = if let Some(cs) = task_checksum(&row.config_json) {
        let initial_prefix = {
            let pipe = pipeline.lock().await;
            let mut p = 0u64;
            if let Some(bm) = pipe.row().block_bitmap.as_deref() {
                while p < count && bit_test(bm, p) {
                    p += 1;
                }
            }
            (p * bs).min(total_len)
        };
        ChecksumPrefetch::new(
            &gid_hex,
            paths.part_path.clone(),
            total_len,
            bs,
            &cs,
            initial_prefix,
        )
        .map(Arc::new)
    } else {
        None
    };

    // Sink (the store half).
    let grid_sink: Arc<dyn SegmentSink> = Arc::new(HttpGridSink {
        file: FileSink::new(part.clone()),
        pipeline: Arc::clone(&pipeline),
        live: Arc::clone(live),
        prefetch: checksum_prefetch.clone(),
        metrics: run.metrics.io_registry().clone(),
    });

    // Scheduling plan (`--http-scheduler` defaults to dynamic, static kept
    // as the control/fallback baseline). dynamic = guided self-scheduling
    // (resumed bitmap holes are dropped by the build predicate — no need
    // for static's queue-head trimming) + stall window / connection AIMD
    // assembly: the stall window = `--http-stall-window` (default 15s;
    // task-level read idle still belongs to `--timeout` — separate
    // domains); the AIMD growth cap = `--max-connection-per-server`; the
    // AIMD execution loop = `taiji_http::pool::WorkerPool` (the supervisor
    // lives in the driver loop). The channel capacity upper bound =
    // sources x the per-source worker bound (dynamic = the AIMD cap
    // `--max-connection-per-server`; static = the fixed `--split` loop —
    // the connection face of aria2's fixed-segmentation semantics). The
    // max of the two modes' bounds is taken (a bounded channel with a
    // little headroom is harmless).
    let per_source_bound = run.opts.max_conn_per_server.max(run.opts.split).max(1) as usize;
    let workers_bound = sources.len() * per_source_bound;
    // Scheduler mode = `--http-scheduler` (dynamic by default, static kept
    // as the control/fallback baseline; a mid-run change takes effect via
    // the changeOption restart semantics).
    let sched_mode = run.opts.scheduler;
    // Slow-start start raise: the starting concurrency = max(user's
    // explicit concurrency intent (`--split`, aria2 semantics — N
    // connections start immediately, the reference has no slow start) and
    // the spec's min(2, cap)), clamped to the cap. When the start decouples
    // from the user's intent, the ramp amortization becomes the dominant
    // loss for short tasks; the raise only changes "where it starts" — the
    // AIMD gain doubling / multiplicative decrease / threshold convergence
    // semantics are unchanged. dynamic-only assembly (the static fixed loop
    // has no AIMD).
    let aimd_cfg = AimdConfig::with_start(run.opts.max_conn_per_server, run.opts.split);
    let (coord, coord_join, throttled, reporter) = match sched_mode {
        SchedulerMode::Dynamic => {
            // Line/ledger decoupling: the per-line lease floor is an engine
            // internal sub-block constant of block/4 (no CLI knob) —
            // GuidedConfig only carries the block granularity and
            // max-chunk; persistence/bookkeeping stay block-aligned.
            let guided = match GuidedPlan::build(
                total_len,
                &GuidedConfig {
                    block_size: bs,
                    max_chunk: run.opts.max_chunk,
                },
                &|b| grid.is_recorded(b),
            ) {
                Ok(p) => p,
                Err(e) => {
                    return fail(
                        run.persist.as_ref(),
                        mirror,
                        EngineFailure::of_http_error(&e),
                        e.to_string(),
                    )
                    .await;
                }
            };
            // Observation seam (consumer face): the throttled sink reports
            // write observations carrying the coordinator handle (the
            // handle is backfilled after spawn, see DeferredReporter);
            // permit-wait events feed the task-level flow-wait liveness at
            // the same point (the h2 exclusion criterion).
            let reporter = Arc::new(DeferredReporter {
                inner: StdMutex::new(None),
                flow: live.stall.clone(),
            });
            let throttled: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::with_rate_reporter(
                grid_sink,
                HttpLimiter::new(run.limiter.clone()),
                Arc::clone(&reporter) as Arc<dyn RateSampleReporter>,
            ));
            // Multi-source assembly: the source ledger (demotion/removal/
            // weighted shares) activates when sources > 1; the
            // single-source assembly is byte-for-byte identical to the
            // existing semantics.
            let (coord, join) = if sources.len() > 1 {
                coordinator::spawn_dynamic_multi(
                    &gid_hex,
                    grid,
                    guided,
                    Arc::clone(&throttled),
                    workers_bound,
                    run.opts.stall_window,
                    aimd_cfg,
                    sources.len() as u32,
                )
            } else {
                coordinator::spawn_dynamic(
                    &gid_hex,
                    grid,
                    guided,
                    Arc::clone(&throttled),
                    workers_bound,
                    run.opts.stall_window,
                    aimd_cfg,
                )
            };
            reporter.set(Some(Arc::new(coord.clone())));
            (Arc::new(coord), Some(join), throttled, Some(reporter))
        }
        SchedulerMode::Static => {
            let sched = SchedulerConfig {
                mode: SchedulerMode::Static,
                block_size: bs,
                split: run.opts.split,
                min_split_size: run.opts.min_split_size,
            };
            let mut plan = match StaticPlan::build(total_len, &sched) {
                Ok(p) => p,
                Err(e) => {
                    return fail(
                        run.persist.as_ref(),
                        mirror,
                        EngineFailure::of_http_error(&e),
                        e.to_string(),
                    )
                    .await;
                }
            };
            trim_done_extents(&mut plan, &grid, bs, count, total_len);
            // Flow-wait liveness assembly (the same shape as dynamic — any
            // permit wait > 0 counts once; the liveness face of the h2
            // flow-wait exclusion criterion): static has no coordinator
            // observation seam (no RateSample consumer), so observations
            // only feed the task-level byte heartbeat (the exclusion
            // criterion for `--timeout` read idle).
            let throttled: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::with_rate_reporter(
                grid_sink,
                HttpLimiter::new(run.limiter.clone()),
                Arc::new(FlowWaitPulse(live.stall.clone())) as Arc<dyn RateSampleReporter>,
            ));
            let (coord, join) =
                coordinator::spawn(&gid_hex, grid, plan, Arc::clone(&throttled), workers_bound);
            (Arc::new(coord), Some(join), throttled, None)
        }
    };
    let mut coord_join = coord_join;
    // /metrics HTTP family task slots: extents_active/AIMD connection SET +
    // steal-grant counter increments; slots deactivate when the driver
    // close-out drops them.
    let http_gauges = run.metrics.register_http_task();
    let mut stolen_seen = 0u64;

    // Worker pool (the AIMD connection execution loop): per-source desired
    // values are honored by the supervisor (the driver tick) from the
    // coordinator's AIMD snapshots — grow = spawn directives, shrink =
    // surplus claims with graceful exit ([`taiji_http::pool`]). dynamic's
    // first round = the slow-start start (the snapshot-absent domain after
    // the explicit-intent raise); the static control baseline has no AIMD —
    // a fixed split loop (each source = `--split` workers, the connection
    // face of aria2's fixed segmentation), constant desired, zero
    // grow/shrink.
    let pool = Arc::new(match sched_mode {
        SchedulerMode::Dynamic => {
            // The start and the decision face share the same source and
            // value (aimd_cfg.start_connections) — the desired value in the
            // snapshot-absent domain = the decision face's start, so the
            // first snapshot produces zero spurious grow/shrink directives.
            taiji_http::pool::WorkerPool::with_start(
                sources.len(),
                run.opts.max_conn_per_server,
                aimd_cfg.start_connections,
            )
        }
        SchedulerMode::Static => taiji_http::pool::WorkerPool::fixed(sources.len(), run.opts.split),
    });
    let pool_token = CancellationToken::new();
    // Worker loop parameters (the effective values after import folding,
    // constant within the attempt): slotted credentials + the Retry-After
    // clamp face, injected into the protocol loop via the WorkerOpts
    // carrier.
    let worker_opts = run.opts.worker_opts();
    let rig = WorkerRig {
        gid: gid_hex.clone(),
        http_metrics: run.metrics.io_registry().clone(),
        client: client.clone(),
        // Jump-off face (the connection build-cost face): the probe's
        // converged final URL; final_url is never empty (a probe-failure
        // degraded form = the source URI itself, so the jump-off face
        // degrades to the plain source-URI fetch at zero cost).
        authoritative_final: Some(authoritative.final_url.to_string()),
        // Task telemetry injection seam: the live truth stays in core; the
        // worker loop writes back via the trait.
        telemetry: Arc::new(LiveTelemetry(Arc::clone(live))),
        per_host: run.per_host.clone(),
        pool: Arc::clone(&pool),
        token: pool_token.clone(),
        total_len,
        bs,
        count,
        ftp_cfg: run.opts.to_ftp_config(),
        base_ctx: ctx.clone(),
        fatal: Arc::new(StdMutex::new(None)),
        // The stall-steal execution loop assembly point: dynamic-only (the
        // heartbeat producer + park steal requests); the static control
        // baseline is untouched.
        steal: matches!(sched_mode, SchedulerMode::Dynamic),
    };
    let mut worker_set: JoinSet<()> = JoinSet::new();
    // First-round spawn (the slow-start start / the static fixed loop): the
    // task's first connection wave is staggered — first-connection delay =
    // wave ordinal x CONNECT_STAGGER_MS, preventing a full concurrent
    // connect burst from blowing through the server's accept queue (RST ->
    // failed retries burning seconds of startup; the reference's connection
    // establishment is likewise not simultaneous). Ordinals are assigned
    // round-robin per source (each wave admits one slot per source): each
    // source's first worker connects with zero delay — multi-source
    // participation is not squeezed out by one source's stagger
    // (multi-source dispatch face). Grow/shrink waves from the supervisor
    // carry no delay.
    let directives = pool.apply(&[], &[]);
    let waves = directives.iter().map(|&(_, n)| n).max().unwrap_or(0);
    for wave in 0..waves {
        for &(source, n) in &directives {
            if wave >= n {
                continue;
            }
            // Precise stagger: if the source's host is already warm (a
            // data-plane success inside the shared pool's window —
            // cross-task keep-alive pooling), the first wave's ramp is
            // skipped entirely; cold sources keep the ramp (judged per
            // source, the multi-source dispatch face).
            let warm = sources
                .get(source as usize)
                .map(|s| taiji_http::client::uri_on_warm_pool(&s.uri))
                .unwrap_or(false);
            let warmth = if warm {
                PoolWarmth::Warm
            } else {
                PoolWarmth::Cold
            };
            let delay = stagger_delay(wave, warmth);
            launch_worker(
                &rig,
                coord.as_ref(),
                &throttled,
                &mut worker_set,
                source as usize,
                &sources,
                &worker_opts,
                if delay.is_zero() { None } else { Some(delay) },
            );
        }
    }
    for &(source, n) in &directives {
        pool.note_spawn(source, n);
    }
    // Driver-side handle (an Option: closed once all workers exit — the
    // channel EOF joins the coordinator close-out order; before that it
    // stays alive for the /metrics telemetry polling).
    let mut coord = Some(coord);

    // Unified teardown face: the cancel exit and ALL fail exits tear down
    // the worker pool / coordinator / sink chain / `.part` in the same
    // order — a bare fail return would leave detached workers claiming
    // extents and sending requests (burning bandwidth and pool slots after
    // the task is already error) and delay the `.part` occupancy-handle
    // release. A macro (not a fn:
    // teardown moves ownership via drop(throttled); all referenced locals
    // are visible at the definition point — hygiene binds at the
    // definition). Every step is idempotent, so the cancel face running the
    // same order explicitly first does not conflict. The coord handle drops
    // naturally with the return after this macro (the coordinator task is
    // already aborted+joined; the handle is only a channel sender clone —
    // no close-out-order dependency).
    macro_rules! teardown_segmented {
        () => {{
            pool_token.cancel();
            worker_set.abort_all();
            while let Some(done) = worker_set.join_next().await {
                if let Err(e) = done {
                    debug!(target: "taiji::core::http", gid = %gid_hex,
                        error = %e, "worker aborted during teardown");
                }
            }
            if let Some(j) = coord_join.as_mut() {
                j.abort();
                let _ = j.await;
            }
            if let Some(r) = reporter.as_ref() {
                r.set(None);
            }
            drop(throttled);
            // Explicit close (not drop): the `.part` occupancy registry
            // holds on the shared inner, so close releases synchronously —
            // late handle clones in the sink chain no longer delay the
            // re-activation's PartFile::open (the path_conflict
            // misjudgment face). No fsync (shutdown budget discipline; the
            // `.part` stays on disk as-is).
            part.close();
        }};
    }

    // Driver loop: tick polling (rate/panic/close-out/snapshot) + cancel.
    let mut tick = tokio::time::interval(DRIVER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Slow-start duration observation state (a read-only consumer of the
    // existing polling, participating in no scheduling decision): the
    // start = grid driver assembly (the task activation's execution face);
    // the end = the two arms on the existing RuntimeStats polling —
    // "connections first reach the cap OR any source's AIMD first settles"
    // (see [`slowstart_reached`]). Tasks that never reach the end are not
    // sampled (right-censored honestly — the histogram only takes tasks
    // whose slow start was observed to end).
    let slowstart_t0 = std::time::Instant::now();
    let mut slowstart_done = false;
    loop {
        tokio::select! {
        _ = run.token.cancelled() => {
                   // Cancel close-out order (before the row write): stop
                   // the worker pool + tear down the worker/coordinator
                   // tasks and WAIT for exit — the `.part` in-process
                   // occupancy handles (the grid sink chain) release as the
                   // tasks exit; async teardown after returning could be
                   // slower than a pause->resume re-activation, and
                   // PartFile::open would hit the occupancy registry's
                   // path_conflict (misjudged as a conflict while the
                   // progress bitmap is still there). Abort closes out
                   // immediately: a half-block in-flight write is bounded
                   // by the single block-completion decision (refetching
                   // unconfirmed blocks is the safe direction). Then
                   // cancel: no forced fsync (shutdown budget discipline;
                   // the bitmap lags by at most ~2s — the safe direction).
                   // The row state distinguishes pause (paused) from the
                   // rest (downloading as-is — the restart-resumes face).
                   // Before the paused row is written, the progress face
                   // back-syncs to the LAST SUCCESSFUL SNAPSHOT (the
                   // fsynced upper bound) — pause/saveSession/restart row
                   // payloads all take the mirror as their source, and a
                   // payload without progress would overwrite a newer
                   // snapshot (a re-activation would then restart the
                   // whole file from zero); un-snapshotted
                   // completed blocks never enter that row (the row-write
                   // extension of "a power-loss bitmap never runs ahead of
                   // the data").
            teardown_segmented!();
            {
                let pipe = pipeline.lock().await;
                if let Some(flushed) = pipe.flushed_row() {
                    sync_mirror_progress(mirror, flushed);
                }
            }
            return cancelled_row(run, mirror, pause).await;
        }
               // Coordinator close-out (the first completion consumes it;
               // the branch is disabled after).
        r = async {
            match coord_join.as_mut() {
                Some(j) => j.await,
                None => std::future::pending().await,
            }
        }, if coord_join.is_some() => {
            coord_join = None;
            match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    // Fail exits tear down in the same order (detached
                    // workers stop claiming items, the `.part` occupancy
                    // registry releases synchronously) before the error
                    // row lands.
                    teardown_segmented!();
                    return fail(
                        run.persist.as_ref(),
                        mirror,
                        EngineFailure::of_http_error(&e),
                        format!("{}: block ledger", e.code()),
                    )
                    .await;
                }
                Err(e) => {
                    teardown_segmented!();
                    return fail(
                        run.persist.as_ref(),
                        mirror,
                        EngineFailure::bare("taiji.http.failed"),
                        format!("coordinator join: {e}"),
                    )
                    .await;
                }
            }
        }
        _ = tick.tick() => {}
               // Block-completion event: the last block's bookkeeping wakes
               // completion detection immediately — no 500ms driver-tick
               // gap (notify_one permits coalescing concurrent completions).
        _ = live.progress_notify.notified() => {}
               // Fast completion-close polling: after the pool token is
               // cancelled, a short cadence wakes the shared check face —
               // the worker-exit/channel-close/completion close-out chain
               // no longer serially waits on the 500ms driver tick (the
               // cancel/coordinator close-out arms are untouched; both wake
               // paths share the check face).
        _ = tokio::time::sleep(COMPLETION_POLL), if pool_token.is_cancelled() => {}
        }
        // Shared per-wake checks (used by both the driver tick and the fast
        // completion poll).
        live.note_tick();
        live.source_rate_tick();
        // Worker panic check (a panic = a task-level fault). Teardown in
        // the same order (other workers may still be transferring — the
        // error row lands only after teardown).
        while let Some(done) = worker_set.try_join_next() {
            if let Err(e) = done {
                teardown_segmented!();
                return fail(
                    run.persist.as_ref(),
                    mirror,
                    EngineFailure::bare("taiji.http.failed"),
                    format!("worker join: {e}"),
                )
                .await;
            }
        }
        // On completion, close out the worker pool (the pool token is
        // separate from the task token — completion must not masquerade as
        // pause); the supervisor stops with it — grow/shrink or respawn
        // after completion would only delay the close-out (the desired
        // count stays >= 1, so 0 registered would re-pull forever).
        if live.is_complete() {
            pool_token.cancel();
        }
        // /metrics HTTP family feed: extents_active write-back + AIMD
        // connection/steal-grant polling (the `RuntimeStats` query face;
        // the static baseline reads honestly zero). A telemetry query
        // failure (a coordinator close-out race) is never a task failure.
        // The supervisor (honoring the execution loop) runs only while
        // incomplete.
        if !pool_token.is_cancelled() {
            if let Some(c) = coord.as_ref() {
                match c.runtime_stats().await {
                    Ok(stats) => {
                        let conns = stats
                            .aimd_connections
                            .iter()
                            .map(|(_, n)| u64::from(*n))
                            .sum();
                        http_gauges.set(live.extents_active.load(Ordering::Relaxed), conns);
                        if stats.steals_granted > stolen_seen {
                            run.metrics
                                .note_http_stolen(stats.steals_granted - stolen_seen);
                            stolen_seen = stats.steals_granted;
                        }
                        // Slow-start duration observation (read-only): one
                        // sample is taken when the snapshot's two-arm
                        // detection (connections first reach the cap / any
                        // source's AIMD settles) holds; see
                        // [`slowstart_reached`] — scheduling never consumes
                        // it.
                        if !slowstart_done
                            && slowstart_reached(&stats, run.opts.max_conn_per_server)
                        {
                            slowstart_done = true;
                            run.metrics
                                .io_registry()
                                .http()
                                .observe_slowstart(slowstart_t0.elapsed());
                        }
                        // Source-health snapshot write-back into the
                        // sources face (demoted/removed states; Active
                        // sources hand back to the busy-count driver).
                        if !stats.source_states.is_empty() {
                            let states: Vec<(u32, taiji_http::sources::SourceState)> = stats
                                .source_states
                                .iter()
                                .map(|(s, st, _)| (*s, *st))
                                .collect();
                            live.apply_source_book_states(&states);
                        }
                        // The AIMD execution loop supervisor: snapshot +
                        // source-removal set -> spawn directives honored
                        // (shrink = a lowered desired count; workers exit
                        // gracefully at extent boundaries via should_stop).
                        // The static baseline's snapshot is always empty ->
                        // apply is idempotent with zero directives (the
                        // fixed loop).
                        for (source, n) in supervisor_directives(&pool, &stats) {
                            for _ in 0..n {
                                launch_worker(
                                    &rig,
                                    c.as_ref(),
                                    &throttled,
                                    &mut worker_set,
                                    source as usize,
                                    &sources,
                                    &worker_opts,
                                    None,
                                );
                            }
                            pool.note_spawn(source, n);
                        }
                    }
                    Err(_) => {
                        http_gauges.set(live.extents_active.load(Ordering::Relaxed), 0);
                    }
                }
            }
        }
        // Fatal-slot consumption (before the supervisor — once fatal is
        // set no more workers are pulled, zero superfluous requests inside
        // the close-out window). The lock guard never crosses an await:
        // taken then released. The slot carries only the raw signal
        // ([`Fatal`]; the protocol arm holds the raw HttpError +
        // diagnostic text); the structured failure mapping (canonical
        // code + refinement dimension) is finalized on this side. The
        // three outcomes are the historical per-channel outcomes kept
        // verbatim; the slot's rank order (see `Fatal::rank`) decides
        // which signal wins a same-tick race — exactly the channel the
        // driver would have consumed first before the merge.
        let fatal = crate::lock(&rig.fatal).take();
        if let Some(fatal) = fatal {
            // The "fatal once = done, zero superfluous requests" promise is
            // honored here (detached workers would otherwise keep claiming
            // extents and sending requests).
            teardown_segmented!();
            return match fatal {
                // Deterministic protocol-contradiction terminal failure.
                Fatal::Protocol(failure, message) => {
                    fail(
                        run.persist.as_ref(),
                        mirror,
                        EngineFailure::of_http_error(&failure),
                        message,
                    )
                    .await
                }
                // 412 content change: torn down above in the fatal order —
                // detached workers stop claiming items, the `.part`
                // occupancy registry releases synchronously — then handed
                // to the outer loop to clear the bitmap and re-probe from
                // zero (self-healing, not terminal).
                Fatal::Restart => DriveStop::ContentRestart,
                // Task-level negative close-out: a worker hit the
                // all-sources-removed face (acquire -> `NoSource`).
                Fatal::NoSource => {
                    fail(
                        run.persist.as_ref(),
                        mirror,
                        EngineFailure::bare("taiji.http.no_source"),
                        "all sources removed with work remaining".into(),
                    )
                    .await
                }
            };
        }
        // Handle closing (close-out order): once all workers exit,
        // withdraw the coordinator handle clones inside the throttled sink
        // and close the driver-side handle -> the channel closes -> the
        // actor drains its message queue and closes out (completion and
        // incomplete-failure share the same close-out order).
        if worker_set.is_empty() {
            if let Some(r) = reporter.as_ref() {
                r.set(None);
            }
            coord = None;
        }
        let complete = live.is_complete();
        let all_exited = worker_set.is_empty() && coord_join.is_none();
        if complete && all_exited {
            break; // -> finalize.
        }
        if all_exited && !complete {
            // Desired count already at zero (all sources removed / the
            // ledger emptied) and the grid is not full: an explicit failure
            // (never pretend it could complete). Although all workers have
            // exited, the `.part` occupancy handles are still released
            // synchronously via the unified teardown.
            teardown_segmented!();
            return fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::bare("taiji.http.no_source"),
                "all workers exited before completion".into(),
            )
            .await;
        }
        // Debounced snapshot (fsync-before-land guaranteed by the pipeline;
        // a failure stays dirty with backoff, the task is not interrupted).
        // Inside the persistence seam, the pipeline -> mirror back-sync
        // runs first — the payload row is the authoritative row at commit
        // time, so by the time the DB write completes the mirror is already
        // synced (saveSession's mirror flush never lags a landed snapshot).
        let persist = run.persist.clone();
        let mirror_sync = Arc::clone(mirror);
        let mut pipe = pipeline.lock().await;
        if let Err(e) = pipe
            .flush_due(HttpLive::now_ms(), move |row| {
                sync_mirror_progress(&mirror_sync, &row);
                persist_snapshot(persist, row)
            })
            .await
        {
            debug!(target: "taiji::core::http", gid = %gid_hex,
                        error = %e, "snapshot deferred");
        }
    }
    // The shared check face keeps waking with each fast completion poll
    // (the select arms above have closed; the driver tick and the fast
    // completion poll share the same check face).

    // ---- finalize: forced snapshot -> row finals -> rename (intent before
    // action) ----
    {
        let persist = run.persist.clone();
        let mirror_sync = Arc::clone(mirror);
        let mut pipe = pipeline.lock().await;
        if let Err(e) = pipe
            .flush_now(HttpLive::now_ms(), move |row| {
                // The final row's progress face takes the same
                // authoritative row as its source: mirror sync + persistence
                // in the same tick (saveSession races on mirror freshness
                // are backstopped by the write-side terminal guard; here
                // the rename/done row carries full progress by
                // construction).
                sync_mirror_progress(&mirror_sync, &row);
                persist_snapshot(persist, row)
            })
            .await
        {
            return fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::bare("taiji.http.failed"),
                format!("final snapshot: {e}"),
            )
            .await;
        }
        // `--checksum` completion-time verdict (the same position as aria2
        // ChecksumCheckIntegrityEntry: verify before rename; failure = task
        // error, the `.part` stays on disk for inspection and the bitmap is
        // untouched. Honest note: an error row is not in bootstrap's active
        // resume read set (terminal rows are not rebuilt) — rerunning the
        // same parameters = a new task downloading from zero, not a
        // whole-file reverification; the on-disk `.part` is for manual
        // forensics only and is not a resume face).
        // Verdict pipelining: the pre-hash finish takes priority (the
        // digest was consumed during the download along the contiguous
        // completed prefix — flush_now and the reader's tail chase are
        // naturally parallel, so this only waits for the final value +
        // comparison); invalidation/timeout/no assembly -> fall back to the
        // full post-hoc hash (the existing semantics, unchanged). The lock
        // is released early: the verdict never touches the pipeline, so the
        // lock is dropped before verifying (pause/saveSession are not
        // blocked by the verdict wait — the wait overlaps flush_now's
        // fsync/persistence, not a new serialization point).
        drop(pipe);
        if let Some(cs) = task_checksum(&row.config_json) {
            let verdict = match checksum_prefetch.as_ref() {
                Some(pf) => pf.finish_and_compare().await,
                None => None,
            };
            match verdict {
                Some(Ok(())) => {
                    info!(target: "taiji::core::http", gid = %gid_hex,
                            scheme = cs.split('=').next().unwrap_or(""),
                            "checksum verified before finalize (prefetched)");
                }
                Some(Err(e)) => {
                    return fail(
                        run.persist.as_ref(),
                        mirror,
                        EngineFailure::of_http_error(&e),
                        e.to_string(),
                    )
                    .await;
                }
                None => {
                    if let Err(e) = verify_checksum(&paths.part_path, &cs).await {
                        return fail(
                            run.persist.as_ref(),
                            mirror,
                            EngineFailure::of_http_error(&e),
                            e.to_string(),
                        )
                        .await;
                    }
                    info!(target: "taiji::core::http", gid = %gid_hex,
                            scheme = cs.split('=').next().unwrap_or(""),
                            "checksum verified before finalize (full)");
                }
            }
        }
        set_state(mirror, TaskPhase::Done);
        let intent = RenameIntent {
            gid: gid_hex.clone(),
            part_path: paths.part_path.clone(),
            final_path: paths.final_path.clone(),
            expected_len: total_len,
        };
        let journal = PersistJournal::new(run.persist.clone(), Arc::clone(mirror));
        let finalizer = Finalizer::new(Arc::new(journal));
        let closed = part.close();
        drop(throttled); // sink chain lets go of its handle clones (close handles before rename)
        match finalizer.finalize(&intent, closed).await {
            Ok(FinalizeOutcome::Completed { .. }) => {
                live.rename_pending.store(false, Ordering::Relaxed);
                let _ =
                    upsert_row(run.persist.as_ref(), &mirror_row(mirror, TaskPhase::Done)).await;
                // `--remote-time`: after the rename settles, set the final
                // file's mtime from the remote Last-Modified; best effort
                // (never a task failure).
                if let (true, Some(lm)) = (
                    task_remote_time(&row.config_json),
                    authoritative.last_modified.as_deref(),
                ) {
                    if let Err(e) =
                        taiji_http::remotetime::apply_remote_mtime(&paths.final_path, lm).await
                    {
                        warn!(target: "taiji::core::http", gid = %gid_hex,
                            path = %paths.final_path.display(), error = %e,
                            "remote-time apply failed (download completed)");
                    }
                }
                info!(target: "taiji::core::http", gid = %gid_hex,
                    path = %paths.final_path.display(), "download finalized");
                DriveStop::Done {
                    total_len,
                    completed_len: total_len,
                }
            }
            Ok(FinalizeOutcome::RenamePending { .. }) => {
                // Final-path claim hand-over: the renamePending polling
                // bookkeeping takes over (released on close-out success;
                // the task-removal path backstops).
                final_lease.persist();
                live.rename_pending.store(true, Ordering::Relaxed);
                let _ =
                    upsert_row(run.persist.as_ref(), &mirror_row(mirror, TaskPhase::Done)).await;
                info!(target: "taiji::core::http", gid = %gid_hex,
                    path = %paths.final_path.display(),
                    "download done with renamePending (retry closes out)");
                DriveStop::Done {
                    total_len,
                    completed_len: total_len,
                }
            }
            Err(e) => {
                // Journal write-face failure (the done state cannot land) —
                // never enter the terminal state.
                fail(
                    run.persist.as_ref(),
                    mirror,
                    EngineFailure::bare("taiji.http.failed"),
                    format!("finalize journal: {e}"),
                )
                .await
            }
        }
    }
}

/// Fast-path range planning (a pure function, the [`drive_small`] input):
/// the whole file is cut into k near-equal byte intervals —
/// k = min(`--split`, `--max-connection-per-server`), clamped to >= 1 and
/// <= the total length (at least 1 byte per segment). NOT bound by the
/// min-split-size floor (a divergence declared in docs/rpc-api-diff.md).
fn small_task_ranges(total_len: u64, split: u32, max_conn_per_server: u32) -> Vec<(u64, u64)> {
    if total_len == 0 {
        return Vec::new();
    }
    let k = u64::from(split.min(max_conn_per_server).max(1)).min(total_len);
    let base = total_len / k;
    let rem = total_len % k;
    let mut ranges = Vec::with_capacity(k as usize);
    let mut off = 0u64;
    for i in 0..k {
        let len = base + u64::from(i < rem);
        ranges.push((off, off + len));
        off += len;
    }
    ranges
}

/// The fast-path sink (the [`drive_small`] write face): `.part` positioned
/// writes + live write-face feeds (rate base / byte-level projection / byte
/// heartbeat / per-source write ledger — the same feed seam as the grid
/// path's [`HttpGridSink`]) + completion wake. No bitmap —
/// `complete_block` degenerates to a no-op (FileSink-shaped); the block
/// bookkeeping finals are pinned once at the close-out point.
struct SmallSink {
    file: FileSink,
    live: Arc<HttpLive>,
}

impl SegmentSink for SmallSink {
    fn write_at(
        &self,
        seg: SegId,
        off: u64,
        bytes: Bytes,
    ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
        let n = bytes.len() as u64;
        self.live.note_written_bytes(n);
        self.live.note_source_written(seg.source, n);
        self.live.stall.note(n);
        self.live.progress_notify.notify_one();
        Box::pin(self.file.write_at(seg, off, bytes))
    }

    fn complete_block(
        &self,
        _block: u64,
    ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// The small-task lightweight fast path (dispatched at
/// [`SMALL_TASK_MAX_BLOCKS`]): tasks with <=2 blocks, no resume progress,
/// and connection intent >= 2 skip the grid/bitmap/AIMD/pool/coordinator
/// assembly and fetch the whole file as near-equal parallel Ranges by the
/// user's connection intent (min(`--split`,
/// `--max-connection-per-server`)) — a 1MiB task is no longer pinned to
/// "1 block = 1 connection". Factory defaults (cap=1) never reach it —
/// the default face's bitmap resume/block bookkeeping are unchanged.
///
/// # Semantic boundary vs the grid path
///
/// - Range = runtime near-equal byte intervals (not block-aligned, outside
///   the extent concept — no bitmap to resume): an interrupted row =
///   downloading/zero progress, and re-activation refetches the whole file
///   from zero (never overstate progress — the safe direction; the refetch
///   cost for <=2-block tasks is bounded);
/// - completion = all Ranges drained (each segment's transport carries its
///   own length check; a short read/overrun fails into retry); the block
///   bookkeeping finals (blocks_done/done_bytes) are pinned once at the
///   close-out point — projection != bookkeeping (no double-write face);
/// - the per-host cap applies as usual (permits acquired at the activation
///   point, held for this fetch round), first-connection per-wave
///   staggering, the throttled sink, the `--checksum` verdict before
///   rename, and finalize intent-before-action — all the same assembly as
///   the grid path;
/// - multi-source: Ranges start from a source-rotated assignment and
///   switch sources on failure up to
///   `taiji_http::worker::WORKER_FAILURE_CAP` (no demotion ledger — source
///   health arbitration belongs to the coordinator, which this path does
///   not assemble).
#[expect(
    clippy::too_many_arguments,
    reason = "drive-chain hand-off passes the run state explicitly; bundling is a later phase"
)]
async fn drive_small(
    run: &HttpTaskRun,
    live: &Arc<HttpLive>,
    mirror: &Arc<StdMutex<HttpTaskRow>>,
    pause: &Arc<AtomicBool>,
    mut row: HttpTaskRow,
    paths: OutputPaths,
    final_lease: &mut FinalClaimLease,
    total_len: u64,
    sources: Vec<PlanSource>,
    authoritative: ProbeResult,
    client: HttpClient,
    ctx: RequestCtx,
    trace: &mut ChainTrace,
) -> DriveStop {
    let gid_hex = run.gid.to_string();
    // If-Match conditional resume (the fast-path face, same semantics as
    // the grid path's [`drive_segmented`]): a probe-confirmed strong ETag
    // -> all Range fetches carry If-Match; 412 ->
    // [`DriveStop::ContentRestart`] (the fast path has no bitmap; the outer
    // loop clears progress and re-probes from zero the same way). Weak/
    // no-ETag paths are unchanged.
    let mut ctx = ctx;
    if let Some(etag) = strong_etag(authoritative.resume_validator().etag.as_deref())
        && !ctx
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("if-match"))
    {
        info!(target: "taiji::core::http", gid = %gid_hex,
            "strong etag confirmed by probe; range requests carry if-match");
        ctx.headers.push(("if-match".into(), etag));
    }
    set_state(mirror, TaskPhase::Downloading);
    row.state = TaskPhase::Downloading.as_v1_str().into();
    if let Err(e) = upsert_row(run.persist.as_ref(), &row).await {
        warn!(target: "taiji::core::http", gid = %gid_hex, %e, "http row persist failed");
    }
    trace.mark("dl_row");
    let blocks_total = row
        .block_count
        .filter(|c| *c > 0)
        .map(|c| c as u64)
        .unwrap_or(1);
    live.total_len.store(total_len, Ordering::Relaxed);
    live.blocks_total.store(blocks_total, Ordering::Relaxed);
    live.blocks_done.store(0, Ordering::Relaxed);
    live.done_bytes.store(0, Ordering::Relaxed);

    // `.part` truncated from zero (only zero-progress tasks reach the fast
    // path — equivalent to the recovery face's FromZero; prealloc lays out
    // the total length so out-of-order Range writes converge).
    let part = match PartFile::open(
        paths.part_path.clone(),
        Some(total_len),
        PartOpenPolicy::Restart,
        FileAllocation::Prealloc,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::of_http_error(&e),
                e.to_string(),
            )
            .await;
        }
    };
    trace.mark("part");

    // Sink chain: SmallSink -> throttle (the same assembly as the grid/
    // degraded paths); rate-limit wait events feed the task-level byte
    // heartbeat (the FlowWaitPulse shape — the liveness face of the
    // `--timeout` read-idle exclusion criterion).
    let throttled: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::with_rate_reporter(
        Arc::new(SmallSink {
            file: FileSink::new(part.clone()),
            live: Arc::clone(live),
        }),
        HttpLimiter::new(run.limiter.clone()),
        Arc::new(FlowWaitPulse(live.stall.clone())) as Arc<dyn RateSampleReporter>,
    ));

    let ranges = small_task_ranges(total_len, run.opts.split, run.opts.max_conn_per_server);
    info!(target: "taiji::core::http", gid = %gid_hex, ranges = ranges.len(),
        total_len, "small-task fast path: parallel range direct fetch");
    let auths: Vec<Option<AuthScheme>> =
        sources.iter().map(|s| run.opts.auth_for(s.kind)).collect();
    let ftp_cfg = run.opts.to_ftp_config();
    let mut worker_set: JoinSet<(usize, HttpResult<()>)> = JoinSet::new();

    // ---- Batch-group dispatch: single-source HTTP candidates join ----
    // The group key = the authoritative source's (post-redirect) host —
    // where the connection actually lands; multi-source/FTP keep the
    // per-item path (the group key is a single-host semantic, multiple
    // hosts complicate budget stacking; FTP's single-connection model has
    // no aggregation face).
    let batch_host: Option<String> = if sources.len() == 1 && sources[0].kind != TransportKind::Ftp
    {
        HostCap::host_key(&authoritative.final_url)
    } else {
        None
    };
    let batch_file = batch_host
        .as_ref()
        .map(|host| (host.clone(), small_batch().join(host)));
    // Leave-group Drop guard (the forceRemove hard-abort face — the future
    // is dropped at an await point, so the cancel branch's explicit leave
    // may never run; this is the backstop). Lives to the end of the
    // function (all exits), idempotent and conflict-free with the explicit
    // face.
    let _batch_leave_guard = batch_file
        .as_ref()
        .map(|(_, file)| BatchLeaveGuard(file.clone()));
    if let Some((host, file)) = batch_file.as_ref() {
        let batch = small_batch();
        let items = ranges
            .iter()
            .enumerate()
            .map(|(idx, &(start, end))| SmallBatchItem {
                extent: Extent {
                    start,
                    len: end - start,
                },
                idx: idx as u64,
                uri: sources[0].uri.clone(),
                sink: Arc::clone(&throttled),
                live: Arc::clone(live),
                owner: file.clone(),
                attempts: 0,
            })
            .collect::<Vec<_>>();
        batch.push(file, items);
        let stats = batch.stats(host);
        info!(target: "taiji::core::http", gid = %gid_hex, host = %host,
            group_files = stats.files, budget = run.opts.batch_budget,
            queued = stats.queued,
            "small-task batch group: cross-file range queue + steal");
        // Cross-file stagger: the batch group's first-wave stagger ordinals
        // are allocated GLOBALLY at group level — this task's first-wave
        // workers pre-reserve a contiguous ordinal run (when K tasks join
        // at once, their first waves are staggered across the whole group;
        // with per-file allocation each file's Range ordinals start at 0
        // independently and K ordinal-0s connect simultaneously). The
        // counter resets when the group dissolves (see
        // [`taiji_http::batch::BatchFile::stagger_ordinal_base`]).
        let stagger_base = file.stagger_ordinal_base(ranges.len());
        for i in 0..ranges.len() {
            // Ordinal overflow: the group-level counter grows monotonically
            // for the group's life; the driver-side [`stagger_delay`]
            // absorbs truncation via `ordinal as u32` plus the ordinal cap
            // (CONNECT_STAGGER_MAX_ORDINAL) — the saturating clamp here
            // only prevents a 32-bit wraparound (a u64 ordinal never
            // realistically reaches u32::MAX scale).
            let ordinal = stagger_base.saturating_add(i as u64).min(u32::MAX as u64) as usize;
            let client = client.clone();
            let ctx = RequestCtx {
                auth: auths[0].clone(),
                ..ctx.clone()
            };
            let token = run.token.clone();
            let per_host = run.per_host.clone();
            let gid = gid_hex.clone();
            let host = host.clone();
            let budget = run.opts.batch_budget;
            let file = file.clone();
            // The batch failure arm's Retry-After clamp parameters (the
            // same semantics as the grid/per-item arms — the server value
            // and the user backoff parameters are separate domains).
            let retry_policy = run.opts.retry.clone();
            // Phase-timing feed handle (`request_seconds{phase=total}`;
            // same source as the session metrics aggregation seam).
            let http_metrics = run.metrics.io_registry().clone();
            worker_set.spawn(async move {
                small_batch_worker(
                    ordinal,
                    &host,
                    budget,
                    client,
                    ctx,
                    &file,
                    per_host,
                    &token,
                    &gid,
                    &retry_policy,
                    http_metrics,
                )
                .await
            });
        }
        // The driver loop and close-out share the body below; the
        // leave-group point = after the terminal verdict (cancel/failure/
        // completion all leave after the worker join drains).
    } else {
        for (idx, &(start, end)) in ranges.iter().enumerate() {
            let extent = Extent {
                start,
                len: end - start,
            };
            let client = client.clone();
            let ctx = ctx.clone();
            let sink = Arc::clone(&throttled);
            let token = run.token.clone();
            let per_host = run.per_host.clone();
            let live = Arc::clone(live);
            let sources = sources.clone();
            let auths = auths.clone();
            let ftp_cfg = ftp_cfg.clone();
            let gid = gid_hex.clone();
            // The failure arm's `Retry-After` clamp parameters (the same
            // semantics as the grid worker's failure arm).
            let retry_policy = run.opts.retry.clone();
            // Phase-timing feed handle (`request_seconds{phase=total}`;
            // same source as the session metrics aggregation seam).
            let http_metrics = run.metrics.io_registry().clone();
            // Jump-off face clone (captured by the async move loop —
            // ProbeResult does not enter the loop; the connection
            // build-cost face, single-source only).
            let authoritative_final = if sources.len() == 1 {
                Some(authoritative.final_url.to_string())
            } else {
                None
            };
            worker_set.spawn(async move {
                // First-connection stagger (the grid path's first-wave
                // discipline: prevents a simultaneous connect burst from
                // blowing through the server's accept queue; this path
                // opens one connection per Range, waves = Range ordinals).
                // Precise stagger: if any source's host is already warm (a
                // data-plane success inside the shared pool's window —
                // cross-task keep-alive pooling) the ramp is skipped
                // entirely (in-pool reuse is zero-delay); the first task /
                // a cold host keeps the ramp against storms.
                let warm = sources
                    .iter()
                    .any(|s| taiji_http::client::uri_on_warm_pool(&s.uri));
                let warmth = if warm {
                    PoolWarmth::Warm
                } else {
                    PoolWarmth::Cold
                };
                let delay = stagger_delay(u64::from(idx as u32), warmth);
                if !delay.is_zero() {
                    tokio::select! {
                        _ = token.cancelled() => {}
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
                // Source rotation: the starting source = Range ordinal %
                // source count; failures switch sources.
                let n_sources = sources.len();
                let mut attempts = 0u32;
                loop {
                    let slot = (idx + attempts as usize) % n_sources;
                    let plan_source = &sources[slot];
                    let worker_ctx = RequestCtx {
                        auth: auths[slot].clone(),
                        ..ctx.clone()
                    };
                    // Per-host permit (acquired at the activation point):
                    // a full cap waits — no connection is opened; the
                    // permit is held for this fetch round and returned on
                    // Drop.
                    let _permit = match HostCap::host_key(&plan_source.uri) {
                        Some(h) => Some(per_host.acquire(&h).await),
                        None => None,
                    };
                    live.connections.fetch_add(1, Ordering::Relaxed);
                    live.note_source_busy(slot, 1);
                    live.extents_active.fetch_add(1, Ordering::Relaxed);
                    let seg = SegId {
                        source: slot as u32,
                        extent: idx as u64,
                    };
                    // Source-attribution wrapper (injects the real source
                    // into FTP's placeholder SegId; idempotent for HTTP —
                    // the same face as the grid path's SourceTaggedSink).
                    let tagged: Arc<dyn SegmentSink> = Arc::new(SourceTaggedSink {
                        inner: Arc::clone(&sink),
                        source: slot as u32,
                    });
                    let built = match plan_source.kind {
                        TransportKind::Ftp => {
                            FtpTransport::for_uri(ftp_cfg.clone(), &plan_source.uri)
                                .map(|t| WorkerTransport::Ftp(Arc::new(t)))
                        }
                        _ => Ok(WorkerTransport::Http(HttpRangeTransport::new(
                            client.clone(),
                            plan_source.uri.clone(),
                            // Jump-off face injection: the fast path also
                            // enables it for single-source only (the same
                            // rule as the grid path).
                            authoritative_final
                                .as_deref()
                                .filter(|u| !u.is_empty())
                                .map(str::to_string),
                            slot as u32,
                            Arc::clone(&http_metrics),
                        ))),
                    };
                    let outcome = match built {
                        Ok(t) => {
                            t.arm(seg);
                            t.as_transport()
                                .fetch(&extent, &worker_ctx, tagged.as_ref())
                                .await
                        }
                        Err(e) => Err(e),
                    };
                    live.extents_active.fetch_sub(1, Ordering::Relaxed);
                    live.note_source_busy(slot, -1);
                    live.connections.fetch_sub(1, Ordering::Relaxed);
                    match outcome {
                        Ok(()) => return (idx, Ok(())),
                        Err(e) => {
                            // Deterministic protocol contradictions do not
                            // burn the retry cap — once and done (the grid
                            // worker's fatal semantics). RangeIgnored = a
                            // mid-download 200 (capability drift). A 412 =
                            // content changed (a retry would 412 again — the
                            // outer loop clears progress and re-probes from
                            // zero). BadRange = the mid-download 206 echo
                            // mismatching the request — the same
                            // deterministic contradiction family, terminal
                            // failure (it does not enter the 412
                            // ContentRestart channel).
                            if matches!(
                                e,
                                HttpError::RangeIgnored
                                    | HttpError::PreconditionFailed
                                    | HttpError::BadRange
                            ) {
                                return (idx, Err(e));
                            }
                            attempts += 1;
                            warn!(target: "taiji::core::http", gid = %gid, range = idx,
                            source = slot, code = e.code(), attempts, %e,
                            "small-path range fetch failed; retrying");
                            if attempts >= SMALL_PATH_FAILURE_CAP {
                                return (idx, Err(e));
                            }
                            // Exponential backoff + per-segment dephasing
                            // (when many tasks in a batch start at once,
                            // connect-phase RSTs (accept-backlog noise)
                            // cluster at the same retry phase across tasks —
                            // fixed backoff would reproduce the thundering
                            // herd; the segment-ordinal offset spreads the
                            // retry phases and the exponential term absorbs
                            // sustained backlog). The server's `Retry-After`
                            // wins (clamped, then it replaces the
                            // exponential backoff — the grid worker failure
                            // arm's semantics). All three arms share one
                            // random fuzz (0-25% additive jitter — spreads
                            // phases across same-ordinal tasks; additive
                            // only, the server value and the floor are
                            // untouched).
                            let backoff = taiji_http::retry::fuzz_delay(match &e {
                                HttpError::RetryAfter { after_secs, .. } => {
                                    taiji_http::retry::clamp_retry_after(*after_secs, &retry_policy)
                                }
                                _ => {
                                    Duration::from_millis(200)
                                        .saturating_mul(1u32 << (attempts - 1).min(4))
                                        + Duration::from_millis(7 * (idx as u64 % 16))
                                }
                            });
                            // Permit release during long backoff (the
                            // per-item arm's rule): for backoff >= 500ms the
                            // per-host permit is released before sleeping —
                            // `_permit` would otherwise stay held in the
                            // iteration scope for the whole sleep (pinning
                            // other tasks on the same host during long
                            // backoffs). After waking, the loop
                            // re-acquires at the top (fair queueing); short
                            // backoffs keep the permit to avoid churn.
                            if backoff >= BACKOFF_PERMIT_RELEASE_THRESHOLD {
                                drop(_permit);
                            }
                            tokio::select! {
                                _ = token.cancelled() => return (idx, Err(e)),
                                _ = tokio::time::sleep(backoff) => {}
                            }
                        }
                    }
                }
            });
        }
    } // multi-source/FTP per-item path (the batch-dispatch else branch)
    trace.mark("spawned");

    // Driver loop: cancel + tick (rate conversion/panic checks) + Range
    // close-out.
    let mut tick = tokio::time::interval(DRIVER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut first_error: Option<HttpError> = None;
    loop {
        tokio::select! {
            _ = run.token.cancelled() => {
                worker_set.abort_all();
                while let Some(done) = worker_set.join_next().await {
                    if let Err(e) = done {
                        debug!(target: "taiji::core::http", gid = %gid_hex,
                            error = %e, "small-path range aborted during cancel teardown");
                    }
                }
                // Leave the batch group (cancel face): void remaining items
                // + remove the sub-queue; gates return with the workers'
                // abort Drops (budget back to the pool), and an empty group
                // dissolves.
                if let Some((_, file)) = batch_file.as_ref() {
                    small_batch().abort(file);
                    small_batch().leave(file);
                }
                part.close();
                return cancelled_row(run, mirror, pause).await;
            }
            _ = tick.tick() => {
                live.note_tick();
                live.source_rate_tick();
            }
            done = worker_set.join_next(), if !worker_set.is_empty() => {
                match done {
                    Some(Ok((_, Ok(())))) => {}
                    Some(Ok((idx, Err(e)))) => {
                        first_error.get_or_insert(e);
                        debug!(target: "taiji::core::http", gid = %gid_hex,
                            range = idx, "small-path range exhausted retries");
                    }
                    Some(Err(e)) => {
                        // A Range task panic = a task-level fault (the grid
                        // path's worker panic check semantics).
                        run.metrics.note_panic();
                        first_error
                            .get_or_insert_with(|| HttpError::Transport(format!("range task: {e}")));
                    }
                    None => {}
                }
            }
        }
        if worker_set.is_empty() {
            break;
        }
    }
    trace.mark("drained");
    // Leave the batch group (the completion/failure face): all workers gone
    // = the file's terminal verdict is in — void remaining items + remove
    // the sub-queue, the budget returns with the gate Drops, an empty group
    // dissolves (a file leaves when it completes — the end of its
    // lifecycle).
    if let Some((host, file)) = batch_file.as_ref() {
        let batch = small_batch();
        batch.abort(file);
        batch.leave(file);
        let stats = batch.stats(host);
        debug!(target: "taiji::core::http", gid = %gid_hex, host = %host,
            group_files = stats.files, group_active = stats.active,
            "small-task left batch group (budget returned)");
    }
    if let Some(e) = first_error {
        // 412 content change -> the outer loop clears progress and
        // re-probes from zero (the fast path has no bitmap; re-download =
        // from-zero, the same shape). The `.part` is closed synchronously
        // first (the occupancy registry releases — the next attempt's
        // PartFile::open does not hit path_conflict).
        if matches!(e, HttpError::PreconditionFailed) {
            part.close();
            drop(throttled);
            return DriveStop::ContentRestart;
        }
        // The deterministic protocol-contradiction family (RangeIgnored/
        // BadRange) lands its terminal state with the canonical engine
        // codes (`taiji.http.range_ignored`/`taiji.http.bad_range`, mapping
        // straight to the RPC numeric code-8 family); other failures keep
        // the existing `taiji.http.failed` collapse (semantics unchanged).
        let failure = match &e {
            HttpError::RangeIgnored | HttpError::BadRange => EngineFailure::of_http_error(&e),
            _ => EngineFailure::bare("taiji.http.failed"),
        };
        // Failure = task-level error (the `.part` stays on disk, the same
        // semantics as the grid path; the fast path has no bitmap, so
        // re-activation refetches the whole file).
        return fail(
            run.persist.as_ref(),
            mirror,
            failure,
            format!("small-path range: {e}"),
        )
        .await;
    }
    // Completion check: in batch form, all workers exiting Ok is NOT
    // completion evidence — the owner worker's drain exit Terminal is
    // identical for "completed" and "aborted" (under cross-file steal, an
    // abort from exhausted failures lands on this file from ANOTHER
    // driver's worker, and the first_error channel never carries it). The
    // completion criterion = `remaining() == 0` (every item booked done);
    // non-zero means some Range never converged — the `.part` is
    // `Prealloc(total_len)`, so a non-zero remainder is a zero-hole file,
    // and fail-closed makes it a task error (never fabricate completion:
    // without `--checksum`, a truncated rename to the final name must not
    // record Done).
    if let Some((_, file)) = batch_file.as_ref().filter(|(_, f)| f.remaining() > 0) {
        return fail(
            run.persist.as_ref(),
            mirror,
            EngineFailure::bare("taiji.http.failed"),
            format!(
                "small-batch file aborted with {} range(s) unfinished",
                file.remaining()
            ),
        )
        .await;
    }

    // Completion close-out: the block bookkeeping finals are pinned once
    // (all Ranges drained = the total length; the byte-level projection is
    // pinned to the bookkeeping final). The row's full progress syncs with
    // the mirror.
    live.blocks_done.store(blocks_total, Ordering::Relaxed);
    live.done_bytes.store(total_len, Ordering::Relaxed);
    row.total_done = total_len as i64;
    sync_mirror_progress(mirror, &row);

    // `--checksum` verdict before rename (the grid path's position:
    // failure = task error, the `.part` stays on disk).
    if let Some(cs) = task_checksum(&row.config_json) {
        if let Err(e) = verify_checksum(&paths.part_path, &cs).await {
            return fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::of_http_error(&e),
                e.to_string(),
            )
            .await;
        }
        info!(target: "taiji::core::http", gid = %gid_hex,
            scheme = cs.split('=').next().unwrap_or(""),
            "checksum verified before finalize");
    }
    set_state(mirror, TaskPhase::Done);
    let intent = RenameIntent {
        gid: gid_hex.clone(),
        part_path: paths.part_path.clone(),
        final_path: paths.final_path.clone(),
        expected_len: total_len,
    };
    let journal = PersistJournal::new(run.persist.clone(), Arc::clone(mirror));
    let finalizer = Finalizer::new(Arc::new(journal));
    let closed = part.close();
    drop(throttled); // sink chain lets go of its handle clones (close handles before rename)
    trace.mark("closed");
    match finalizer.finalize(&intent, closed).await {
        Ok(FinalizeOutcome::Completed { .. }) => {
            live.rename_pending.store(false, Ordering::Relaxed);
            trace.mark("fin");
            let _ = upsert_row(run.persist.as_ref(), &mirror_row(mirror, TaskPhase::Done)).await;
            trace.mark("row_done");
            // `--remote-time`: after the rename settles, set the final
            // file's mtime from the remote Last-Modified; best effort
            // (never a task failure).
            if let (true, Some(lm)) = (
                task_remote_time(&row.config_json),
                authoritative.last_modified.as_deref(),
            ) {
                if let Err(e) =
                    taiji_http::remotetime::apply_remote_mtime(&paths.final_path, lm).await
                {
                    warn!(target: "taiji::core::http", gid = %gid_hex,
                        path = %paths.final_path.display(), error = %e,
                        "remote-time apply failed (download completed)");
                }
            }
            info!(target: "taiji::core::http", gid = %gid_hex,
                path = %paths.final_path.display(), "small download finalized");
            DriveStop::Done {
                total_len,
                completed_len: total_len,
            }
        }
        Ok(FinalizeOutcome::RenamePending { .. }) => {
            // Final-path claim hand-over: the renamePending polling
            // bookkeeping takes over (released on close-out success; the
            // task-removal path backstops).
            final_lease.persist();
            live.rename_pending.store(true, Ordering::Relaxed);
            let _ = upsert_row(run.persist.as_ref(), &mirror_row(mirror, TaskPhase::Done)).await;
            info!(target: "taiji::core::http", gid = %gid_hex,
                path = %paths.final_path.display(),
                "small download done with renamePending (retry closes out)");
            DriveStop::Done {
                total_len,
                completed_len: total_len,
            }
        }
        Err(e) => {
            // Journal write-face failure (the done state cannot land) —
            // never enter the terminal state.
            fail(
                run.persist.as_ref(),
                mirror,
                EngineFailure::bare("taiji.http.failed"),
                format!("finalize journal: {e}"),
            )
            .await
        }
    }
}

/// Gate acquisition (the worker loop's first step, shared by both arms):
/// block for a host permit within budget / try-only on overflow (yielding
/// to host contention — a short-stay retry); cancellation = `None` (the
/// worker exits).
async fn batch_gate_acquire(
    batch: &taiji_http::batch::BatchGroups<SmallBatchItem>,
    host: &str,
    budget: u32,
    per_host: &HostCap,
    token: &CancellationToken,
) -> Option<taiji_http::batch::GatePermit<SmallBatchItem>> {
    loop {
        tokio::select! {
            _ = token.cancelled() => return None,
            gate = batch.gate_enter(host, budget, per_host) => match gate {
                Ok(g) => return Some(g),
                // Overflow rejected (budget full + host full): retry after a
                // short stay — in-budget connections completing will release
                // the gate/host permits for re-evaluation.
                Err(_) => {
                    tokio::select! {
                        _ = token.cancelled() => return None,
                        _ = tokio::time::sleep(BATCH_GATE_RETRY) => {}
                    }
                }
            },
        }
    }
}

/// The batch worker: a resident item-taking loop — connection gate (group
/// budget soft cap + per-host permit) -> take from the group queue
/// (cross-file rotating steal, items write straight to their owner's face)
/// -> completion bookkeeping. A failed item requeues + exponential backoff
/// (segment dephasing, the per-item arm's rule); exhausting
/// [`SMALL_PATH_FAILURE_CAP`] voids the ITEM OWNER's file as terminal and
/// reports the error (the attribution contract: when the owner is this
/// driver's file the error returns via the return value; when the owner is
/// another driver's, this worker reports Ok and the owner driver learns of
/// it via `remaining() > 0`). Exit condition: the owner file is terminal
/// or has left the group ([`taiji_http::batch::Work::Terminal`] —
/// completion/failure/cancel all converge to the terminal marker).
///
/// # Semantic boundary vs the per-item path
///
/// - First-wave stagger discipline is the same (warm pool skips / cold
///   pool ramps; the ordinal = the worker's); the host permit is acquired
///   at the activation point and held for the fetch round;
/// - failure retry = the ITEM requeues (the worker is not bound to an
///   item: after backoff it takes the next item, possibly another file's —
///   retry phases spread naturally and connect-phase RST noise in the
///   batch does not cluster);
/// - write attribution: the item carries its owner's sink/live, so any
///   worker's writes land on the owner file's `.part`/rate/heartbeat
///   faces (the cross-file steal write-back contract).
#[expect(
    clippy::too_many_arguments,
    reason = "batch worker takes its host/budget/retry faces explicitly; bundling is a later phase"
)]
async fn small_batch_worker(
    ordinal: usize,
    host: &str,
    budget: u32,
    client: HttpClient,
    ctx: RequestCtx,
    file: &taiji_http::batch::BatchFile<SmallBatchItem>,
    per_host: HostCap,
    token: &CancellationToken,
    gid: &str,
    retry_policy: &taiji_http::retry::RetryPolicy,
    http_metrics: Arc<taiji_io::metrics::MetricsRegistry>,
) -> (usize, HttpResult<()>) {
    let batch = small_batch();
    // First-wave stagger (ordinal 0 = zero delay, the original semantics; a
    // warm host skips — in-pool reuse means no connect).
    let warm = taiji_http::client::uri_on_warm_pool(host);
    let warmth = if warm {
        PoolWarmth::Warm
    } else {
        PoolWarmth::Cold
    };
    let delay = stagger_delay(u64::from(ordinal as u32), warmth);
    if !delay.is_zero() {
        tokio::select! {
            _ = token.cancelled() => return (ordinal, Ok(())),
            _ = tokio::time::sleep(delay) => {}
        }
    }
    loop {
        // Per-loop-phase instrumentation (an observation face): gate relay /
        // item take / fetch — locates the engine-side share of each gap in
        // the worker loop. The fetch total includes the network itself
        // (~bytes/rate).
        let loop_t0 = std::time::Instant::now();
        // Connection gate: block for a host permit within budget / try-only
        // on overflow (yielding to host contention).
        let gate = match batch_gate_acquire(batch, host, budget, &per_host, token).await {
            Some(g) => g,
            None => return (ordinal, Ok(())),
        };
        let t_gate = loop_t0.elapsed();
        // Take an item immediately; an empty queue = release the connection
        // gate BEFORE waiting (eliminates permit idle): parking inside the
        // gate keeps the host permit and the group's active reservation
        // occupied by a wait with no transfer, and when the steady-state
        // item pool hugs the cap that idle directly eats cap utilization.
        // Gate semantics unchanged: the
        // permit-holding window shrinks to "the take instant + the fetch",
        // and waits return it symmetrically to the pool.
        let mut item = match batch.try_next(file) {
            taiji_http::batch::Work::Item(item) => item,
            // Owner terminal: the labor exits (the gate returns to the pool
            // via the scope's Drop).
            taiji_http::batch::Work::Terminal => return (ordinal, Ok(())),
            taiji_http::batch::Work::Empty => {
                drop(gate); // yield while waiting for items (permit back to the pool)
                batch.wait_work(file).await;
                // After waking, loop back into gate contention (fairness: on
                // equal footing with new permit contenders).
                continue;
            }
        };
        let t_next = loop_t0.elapsed();
        // fetch (owner attribution: live/write faces all go through the
        // item's owner handles).
        item.live.connections.fetch_add(1, Ordering::Relaxed);
        item.live.note_source_busy(0, 1);
        item.live.extents_active.fetch_add(1, Ordering::Relaxed);
        let seg = SegId {
            source: 0,
            extent: item.idx,
        };
        let tagged: Arc<dyn SegmentSink> = Arc::new(SourceTaggedSink {
            inner: Arc::clone(&item.sink),
            source: 0,
        });
        let transport = WorkerTransport::Http(HttpRangeTransport::new(
            client.clone(),
            // The owner URI carried by the item (the cross-file steal
            // contract — see SmallBatchItem.uri).
            item.uri.clone(),
            // The jump-off face is not enabled: the owner URI has no
            // correspondence with the authoritative converged face (the
            // cross-file steal form), so the chain is conservatively
            // re-walked as usual.
            None,
            0,
            Arc::clone(&http_metrics),
        ));
        transport.arm(seg);
        let outcome = transport
            .as_transport()
            .fetch(&item.extent, &ctx, tagged.as_ref())
            .await;
        debug!(target: "taiji::core::http", gid = %gid, range = item.idx,
            gate_us = t_gate.as_micros() as u64,
            next_us = (t_next - t_gate).as_micros() as u64,
            fetch_ms = (loop_t0.elapsed() - t_next).as_millis() as u64,
            bytes = item.extent.len,
            "worker loop phases (gate | next | fetch)");
        item.live.extents_active.fetch_sub(1, Ordering::Relaxed);
        item.live.note_source_busy(0, -1);
        item.live.connections.fetch_sub(1, Ordering::Relaxed);
        drop(gate); // budget/host permit returns as soon as the fetch completes
        match outcome {
            Ok(()) => {
                batch.note_item_done(&item.owner);
            }
            Err(e) => {
                item.attempts += 1;
                // RangeIgnored fast-terminal — a deterministic protocol
                // contradiction does not burn the retry cap (the per-item
                // path's rule; the grid arm's fatal is the same idea). A 412
                // (PreconditionFailed) is judged the same way — a retry
                // would 412 again; the outer loop clears progress and
                // re-probes from zero. BadRange (the mid-download 206 echo
                // mismatching the request) likewise — the same
                // deterministic contradiction family, once and done as a
                // terminal failure (it does not enter the 412
                // ContentRestart channel).
                if matches!(
                    e,
                    HttpError::RangeIgnored | HttpError::PreconditionFailed | HttpError::BadRange
                ) || item.attempts >= SMALL_PATH_FAILURE_CAP
                {
                    batch.abort(&item.owner);
                    warn!(target: "taiji::core::http", gid = %gid, range = item.idx,
                        attempts = item.attempts, code = e.code(), %e,
                        "small-batch range exhausted retries; file aborted");
                    // Attribution close-out: under cross-file steal, the
                    // reporting worker's owner (this driver's file) and the
                    // item owner (item.owner) routinely differ — the error
                    // goes back only to the ITEM OWNER's driver: when the
                    // owner matches, it flows out via this worker's Err
                    // return (the first_error channel); when the owner is
                    // another driver's, this worker reports Ok (this driver
                    // has no error and must not fail on the owner's behalf),
                    // and the owner driver sees the failure after draining
                    // via `remaining() > 0` (abort does not zero remaining —
                    // see [`taiji_http::batch::BatchFile::remaining`]).
                    // Misplaced attribution would break both directions:
                    // the owner driver's all-Ok join fabricates Done (a
                    // preallocated zero-hole `.part` gets the final name)
                    // while the reporting driver is dragged into Error by
                    // someone else's file.
                    if item.owner.id == file.id {
                        return (ordinal, Err(e));
                    }
                    return (ordinal, Ok(()));
                }
                warn!(target: "taiji::core::http", gid = %gid, range = item.idx,
                    attempts = item.attempts, code = e.code(), %e,
                    "small-batch range failed; requeued");
                // The batch failure arm restores the three-way priority
                // (the grid/per-item arms' rule): the server's
                // `Retry-After` ranks highest — clamped (upper =
                // retry.max_wait 30s to avoid hanging, lower = 200ms
                // against hammering) and then it replaces the exponential
                // backoff (`--retry-wait` never overrides the server
                // value); a connection reset = a connection-level one-off
                // event with a short 50ms backoff back to work; other
                // failures keep the existing 200ms exponential + segment
                // dephasing (same-instant retry clustering in a batch = a
                // thundering herd; dephasing spreads it). All three arms
                // share one random fuzz (0-25% additive jitter — cross-file
                // batches are the main same-instant failure-clustering
                // shape, and fuzz spreads the tasks' retry phases; additive
                // only, the three-way priority and floors are untouched).
                let backoff = taiji_http::retry::fuzz_delay(match &e {
                    HttpError::RetryAfter { after_secs, .. } => {
                        taiji_http::retry::clamp_retry_after(*after_secs, retry_policy)
                    }
                    _ if e.is_connection_reset() => EXTENT_RETRY_BACKOFF_RESET,
                    _ => {
                        Duration::from_millis(200)
                            .saturating_mul(1u32 << (item.attempts - 1).min(4))
                            + Duration::from_millis(7 * (item.idx % 16))
                    }
                });
                tokio::select! {
                    _ = token.cancelled() => return (ordinal, Ok(())),
                    _ = tokio::time::sleep(backoff) => {}
                }
                let owner = item.owner.clone();
                batch.requeue(&owner, item);
            }
        }
    }
}

/// Persist a snapshot (PersistWriter is the single writer; the
/// no-persistence form = a no-op success — the pipeline's in-memory truth
/// advances as usual).
async fn persist_snapshot(
    persist: Option<PersistHandle>,
    row: HttpTaskRow,
) -> Result<PersistOutcome, StoreError> {
    match persist {
        Some(p) => p.upsert_http_task(row).await,
        None => Ok(PersistOutcome::Written),
    }
}

// ---- Shared small pieces ----

/// The multi-source list's persistence shape (`http_task.mirrors_json`;
/// the addUri multi-URI array's carrier): `[{"url":"..."},...]` (an array
/// of source objects, the url key authoritative; the migration importer's
/// serialized first-line multi-URI restores to the same shape — both
/// producers share this function to prevent shape drift). Serialization
/// never fails (a pure-string payload); an empty string falls back to the
/// None semantics.
pub(in crate::session) fn mirrors_json_of(uris: &[String]) -> Option<String> {
    if uris.len() <= 1 {
        // A single-source task's url column is the truth; no redundant payload
        // (write-time dedup also skips the row delta).
        return None;
    }
    let payload: Vec<serde_json::Value> = uris
        .iter()
        .map(|u| serde_json::json!({ "url": u }))
        .collect();
    serde_json::to_string(&payload).ok()
}

/// The resume face's multi-source expansion (the inverse of
/// [`mirrors_json_of`]): parse the url entries of mirrors_json (string
/// entries tolerated — forward defense), dedup preserving order; the row's
/// url is always the first entry (the first source at add time; imported
/// rows follow the same rule). A missing/corrupt payload -> single-source
/// fallback (the url column) — the resume face never degrades a row into
/// being un-downloadable.
pub(super) fn uris_from_mirrors(mirrors_json: Option<&str>, url: &str) -> Vec<String> {
    let mut uris: Vec<String> = Vec::new();
    if let Some(raw) = mirrors_json
        && let Ok(vals) = serde_json::from_str::<Vec<serde_json::Value>>(raw)
    {
        for v in vals {
            let u = match v {
                serde_json::Value::String(s) => Some(s),
                serde_json::Value::Object(m) => m
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                _ => None,
            };
            if let Some(u) = u
                && !u.is_empty()
                && !uris.contains(&u)
            {
                uris.push(u);
            }
        }
    }
    if !url.is_empty() && !uris.iter().any(|u| u == url) {
        uris.insert(0, url.to_string());
    }
    if uris.is_empty() {
        uris.push(url.to_string());
    }
    uris
}

/// FTP/FTPS source probing: the taiji-http [`FtpTransport::probe`] chain
/// (login -> TYPE I -> CWD -> SIZE -> `REST 0` -> FEAT) mapped to verdicts:
///
/// - SIZE 0 -> the empty-file shape (create a 0-byte output and done);
/// - SIZE + `REST 0` both pass -> the rangeable shape (SIZE is the
///   authoritative total length);
/// - `REST 0` rejected (5xx) -> the degraded shape (single connection, no
///   bitmap, resume from zero — the degraded semantics);
/// - SIZE unsupported (no authoritative total) -> the source is dropped: a
///   total-less FTP stream cannot satisfy block-grid bookkeeping or the
///   `--checksum` completion verdict, so taiji tightens here (aria2 can
///   stream without a total — a declared divergence).
///
/// Credential chain = URI userinfo > `--ftp-user/--ftp-passwd` >
/// anonymous/anonymous@ by default (the transport layer uses the same
/// order; a separate slot from http-user/http-passwd, aria2's http/ftp
/// credential slot isomorphism). FTPS (`--ftp-ssl`) is expressed by the
/// FtpConfig TLS mode; a `ftps://` scheme URI is refused -> the source is
/// dropped (a declared divergence).
async fn probe_ftp_source(
    opts: &HttpTaskOpts,
    uri: &str,
    base_ctx: &RequestCtx,
) -> HttpResult<ProbeVerdict> {
    let transport = FtpTransport::for_uri(opts.to_ftp_config(), uri)?;
    let ctx = RequestCtx {
        auth: opts.auth_for(TransportKind::Ftp),
        ..base_ctx.clone()
    };
    let probe: FtpProbe = transport.probe(&ctx).await?;
    let result = ProbeResult {
        final_url: uri.to_string(),
        total_len: probe.validator.total_len,
        etag: None,
        // MDTM (RFC 3659) is normalized into the HTTP face's Last-Modified
        // exit format (IMF-fixdate) — the resume check and the
        // `--remote-time` face consume it through the same seam as HTTP
        // tasks.
        last_modified: probe.validator.last_modified.clone(),
        accept_ranges: probe.resume_supported,
        encoding: None,
        content_type: None,
    };
    match probe.validator.total_len {
        None => Err(HttpError::Transport(
            "ftp SIZE unsupported (no authoritative length); source dropped".into(),
        )),
        Some(0) => Ok(ProbeVerdict::EmptyFile(result)),
        Some(_) if probe.resume_supported => Ok(ProbeVerdict::RangeWithLength(result)),
        Some(_) => Ok(ProbeVerdict::NoRangeWithLength(result)),
    }
}

/// Disk rollback for a degraded-path verification mismatch: the final file
/// returns to `.part` (the data stays on disk for inspection, aligning
/// with the grid path's "failure = `.part` on disk, no final file"
/// semantics); if the rename-back fails (cross-device/handle held, etc.)
/// the final file is deleted as the fallback — neither shape leaves a
/// final file that fails verification. Best effort: a rollback failure of
/// its own never masks the checksum mismatch, which is the primary error.
async fn rollback_final_file(part_path: &Path, final_path: &Path) {
    let restore = tokio::fs::rename(final_path, part_path).await;
    match restore {
        Ok(()) => {
            warn!(target: "taiji::core::http", part = %part_path.display(),
                "checksum mismatch: final file rolled back to .part for inspection");
        }
        Err(rename_err) => match tokio::fs::remove_file(final_path).await {
            Ok(()) => warn!(target: "taiji::core::http",
                    part = %part_path.display(), error = %rename_err,
                    "checksum mismatch: rollback rename failed; corrupt final file removed"),
            Err(remove_err) => warn!(target: "taiji::core::http",
                    part = %part_path.display(), path = %final_path.display(),
                    error = %remove_err, rename_error = %rename_err,
                    "checksum mismatch: failed to remove corrupt final file (manual cleanup required)"),
        },
    }
}

/// Read the task's `--checksum` face (the row's config_json payload; None
/// = unset).
fn task_checksum(config_json: &str) -> Option<String> {
    HttpPersistConfig::from_json(config_json)
        .checksum
        .filter(|c| !c.trim().is_empty())
}

/// Read the task's `--remote-time` face (the row's config_json payload;
/// default false).
fn task_remote_time(config_json: &str) -> bool {
    HttpPersistConfig::from_json(config_json).remote_time
}

/// Read the task's per-host cap intent (the row's config_json payload;
/// None = the cap was never adjusted via addUri — activation is a no-op).
/// Consumed at the session activation point (the `session::actor::tasks`
/// Job::Http arm; the restore channel is documented there).
pub(super) fn task_host_cap(config_json: &str) -> Option<u32> {
    HttpPersistConfig::from_json(config_json).host_cap
}

// ---------------------------------------------------------------------------
// `--checksum` verdict pipelining: the grid path's pre-hash coordinator.
//
// Baseline: all four verdict points (the grid finalize, drive_small,
// drive_degraded, and the empty file) did a full sequential post-hoc hash
// after completion (`verify_checksum`: spawn_blocking whole-file read +
// digest) — the hash sat serially between "last byte lands" and "rename".
//
// Pipelined shape (reconciling sha-256's sequential nature with the
// blocks' out-of-order writes): a CONTIGUOUS-PREFIX PRE-HASH — the
// bookkeeping face (the single block-completion decision point) derives
// the contiguous completed prefix in bytes, and the pre-hash task follows
// the prefix, reading [hashed, prefix) back from the `.part` into the
// digest (page-cache warm; reading back is far cheaper than hashing); at
// completion only the tail segment is topped up + finalize. Digest
// consumption overlaps the download, so the verdict latency shrinks from
// O(whole file) to O(tail segment).
//
// # Semantic equivalence (frozen seam: fail-closed / mismatch rejects the
// rename)
//
// The bytes the pre-hash consumes must equal the final file bytes of that
// interval. Achieved by TWO-PHASE WATERMARKS + WRITER DOUBLE-CHECKS
// (lock-free: two atomic loads on the write path):
//
// - `reading_to`: declared BEFORE the pre-hash task reads a segment
// (writers seeing the zone from then on reject the write);
// - `hashed_to`: confirmed after the read completes (consumption frozen);
// - the pre-write check ([`ChecksumPrefetch::pre_write_reject`]): the
// target interval intersecting the declared/consumed zone -> REJECT the
// write (the data must be a duplicate — the block is already recorded
// and the writer is the late side of a stolen lease; dropping is
// lossless, and duplicate-write waste stays bounded by the single
// decision point while the consumed zone is tightened to zero
// duplicates on disk);
// - the post-write check ([`ChecksumPrefetch::post_write_check`]): the
// watermark crossing the target while the write was in flight -> an
// in-flight overshoot landed in the consumed zone -> INVALIDATE the
// pre-hash (`invalidated`), falling back to the full post-hoc hash at
// completion (the baseline semantics).
//
// Exhaustive timing (writer W(X) vs reader R reading [hashed, end)
// containing X):
// - W's pre-write check passes before R's declaration (X >= the watermark
// then) and W completes before R declares -> R's read happens after W's
// data lands -> R consumes W's bytes (the final state);
// - W straddles R's declaration point (pre-write check first, data lands
// later) -> W's post-write check necessarily sees the declared watermark
// > X -> invalidated;
// - W's pre-write check runs after R's declaration -> the write is
// rejected.
// After the completion verdict all workers have exited
// (`complete && all_exited`) = no writers remain, so finish's tail-read is
// absolutely safe.
// ---------------------------------------------------------------------------

/// The pre-hash task's fallback polling cadence (self-heals lost notify
/// pulses; the prefix-advance main path is the notify_one in
/// [`ChecksumPrefetch::note_block_recorded`]).
const PREFETCH_POLL: Duration = Duration::from_millis(100);

/// Upper bound for waiting on the pre-hash finish (tail catch-up +
/// finalize; a disk-fault timeout -> fall back to the full hash — which
/// fails the same way on the same disk, so the task error path matches).
const PREFETCH_FINISH_TIMEOUT: Duration = Duration::from_secs(30);

/// The pre-write rejection message (diagnostic face; lands in the worker's
/// failure-retry arm — the block is already recorded, so the worker finds
/// nothing to claim and exits with no data loss).
const PREFETCH_ZONE_REJECTED: &str =
    "checksum prefetch zone write rejected (block already recorded; stale duplicate)";

/// The task digesters (`--checksum` algorithm domain, six hashes:
/// md5/sha-1/sha-224/sha-256/sha-384/sha-512 — RFC 1321 + FIPS 180-4; the
/// same value domain as [`verify_checksum`]. Feeding contract: sequential,
/// along the contiguous prefix).
enum TaskDigest {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl TaskDigest {
    /// Parse the algorithm half of the raw `--checksum` value (the same
    /// value domain as [`verify_checksum`]; the caller holds the hex
    /// expectation).
    fn parse_scheme(checksum: &str) -> Option<&'static str> {
        let (scheme_raw, _) = checksum.split_once('=')?;
        match scheme_raw.trim().to_ascii_lowercase().as_str() {
            "md5" => Some("md5"),
            "sha-1" => Some("sha-1"),
            "sha-224" => Some("sha-224"),
            "sha-256" => Some("sha-256"),
            "sha-384" => Some("sha-384"),
            "sha-512" => Some("sha-512"),
            _ => None,
        }
    }

    fn new(scheme: &str) -> Option<TaskDigest> {
        use sha1::Digest as _;
        match scheme {
            "md5" => Some(TaskDigest::Md5(md5::Md5::new())),
            "sha-1" => Some(TaskDigest::Sha1(sha1::Sha1::new())),
            "sha-224" => Some(TaskDigest::Sha224(sha2::Sha224::new())),
            "sha-256" => Some(TaskDigest::Sha256(sha2::Sha256::new())),
            "sha-384" => Some(TaskDigest::Sha384(sha2::Sha384::new())),
            "sha-512" => Some(TaskDigest::Sha512(sha2::Sha512::new())),
            _ => None,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        use sha1::Digest as _;
        match self {
            TaskDigest::Md5(h) => h.update(bytes),
            TaskDigest::Sha1(h) => h.update(bytes),
            TaskDigest::Sha224(h) => h.update(bytes),
            TaskDigest::Sha256(h) => h.update(bytes),
            TaskDigest::Sha384(h) => h.update(bytes),
            TaskDigest::Sha512(h) => h.update(bytes),
        }
    }

    fn finalize_hex(self) -> String {
        use sha1::Digest as _;
        let bytes = match self {
            TaskDigest::Md5(h) => h.finalize().to_vec(),
            TaskDigest::Sha1(h) => h.finalize().to_vec(),
            TaskDigest::Sha224(h) => h.finalize().to_vec(),
            TaskDigest::Sha256(h) => h.finalize().to_vec(),
            TaskDigest::Sha384(h) => h.finalize().to_vec(),
            TaskDigest::Sha512(h) => h.finalize().to_vec(),
        };
        hex_lower(&bytes)
    }
}

/// Pre-hash task commands.
enum PrefetchCommand {
    /// Terminal finish: catch up to total_len -> finalize -> return the
    /// digest hex (invalidated = None).
    Finish {
        reply: tokio::sync::oneshot::Sender<Option<String>>,
    },
}

/// Handle for the digest slot (hands items across blocking threads).
fn digest_arc(inner: &PrefetchInner) -> Arc<StdMutex<Option<TaskDigest>>> {
    Arc::clone(&inner.digest)
}

/// Pre-hash shared state (the reader task holds the `Arc`; handle clones
/// fan out to the sink/verdict faces).
struct PrefetchInner {
    gid: String,
    part_path: PathBuf,
    total_len: u64,
    block_size: u64,
    digest: Arc<StdMutex<Option<TaskDigest>>>,
    /// Next candidate block number (the prefix-advance cursor; advanced
    /// only under the pipeline lock).
    prefix_block: AtomicU64,
    /// Contiguous completed-prefix bytes (a bookkeeping-derived quantity;
    /// the reader's catch-up target).
    prefix_upto: AtomicU64,
    /// The reader's declared watermark (stored before the read; the
    /// writers' rejection reference).
    reading_to: AtomicU64,
    /// The reader's confirmed watermark (stored after read+feed; consumption
    /// frozen).
    hashed_to: AtomicU64,
    /// Invalidation flag (a post-write check crossing / an IO failure on
    /// the reader's read).
    invalidated: AtomicBool,
    /// Prefix-advance wake (notify_one at the bookkeeping point; consumed
    /// by the reader's select).
    notify: tokio::sync::Notify,
}

impl PrefetchInner {
    /// The reject-write watermark (max of declared/confirmed; Acquire loads
    /// pair with Release stores).
    fn gate(&self) -> u64 {
        let r = self.reading_to.load(Ordering::Acquire);
        let h = self.hashed_to.load(Ordering::Acquire);
        r.max(h)
    }
}

/// The grid path's verdict pre-hash coordinator (assembled when
/// `--checksum` is set with a valid scheme; otherwise sink/verdict faces
/// get `None` — zero behavior change for non-checksum tasks).
struct ChecksumPrefetch {
    inner: Arc<PrefetchInner>,
    expected_hex: String,
    finish_tx: StdMutex<Option<tokio::sync::mpsc::Sender<PrefetchCommand>>>,
}

impl ChecksumPrefetch {
    /// Assemble + start the reader task (`initial_prefix` = the resumed
    /// bitmap's initial prefix — the reader chases from the start, so a
    /// resume's completed portion amortizes over the remaining download
    /// time).
    fn new(
        gid: &str,
        part_path: PathBuf,
        total_len: u64,
        block_size: u64,
        checksum: &str,
        initial_prefix: u64,
    ) -> Option<ChecksumPrefetch> {
        let scheme = TaskDigest::parse_scheme(checksum)?;
        // Expected hex (lowercase-normalized; the single comparison source).
        let expected_hex = checksum.split_once('=')?.1.trim().to_ascii_lowercase();
        let digest = TaskDigest::new(scheme)?;
        let inner = Arc::new(PrefetchInner {
            gid: gid.to_string(),
            part_path,
            total_len,
            block_size,
            digest: Arc::new(StdMutex::new(Some(digest))),
            prefix_block: AtomicU64::new(initial_prefix / block_size),
            prefix_upto: AtomicU64::new(initial_prefix),
            reading_to: AtomicU64::new(0),
            hashed_to: AtomicU64::new(0),
            invalidated: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        let (tx, rx) = tokio::sync::mpsc::channel::<PrefetchCommand>(4);
        tokio::spawn(run_prefetch(Arc::clone(&inner), rx));
        Some(ChecksumPrefetch {
            inner,
            expected_hex,
            finish_tx: StdMutex::new(Some(tx)),
        })
    }

    /// Prefix advance at the bookkeeping point (called UNDER the pipeline
    /// lock — the lock guarantees bitmap consistency; the increment is O(1)
    /// amortized: it only scans forward from the previous prefix cursor
    /// over contiguously completed blocks).
    fn note_block_recorded(&self, bitmap: &[u8], block_count: u64) {
        let inner = &self.inner;
        let mut cursor = inner.prefix_block.load(Ordering::Relaxed);
        while cursor < block_count && bit_test(bitmap, cursor) {
            cursor += 1;
        }
        inner.prefix_block.store(cursor, Ordering::Relaxed);
        let upto = (cursor * inner.block_size).min(inner.total_len);
        let advanced = upto > inner.prefix_upto.load(Ordering::Relaxed);
        if advanced {
            inner.prefix_upto.store(upto, Ordering::Release);
            inner.notify.notify_one();
        }
    }

    /// Pre-write check (true = reject): the target start is already inside
    /// the declared/consumed zone — the data is a late duplicate write and
    /// dropping it is lossless (the target block is necessarily recorded).
    fn pre_write_reject(&self, off: u64) -> bool {
        off < self.inner.gate()
    }

    /// Post-write check: the watermark crossing the target while the write
    /// was in flight -> an in-flight overshoot landed in the consumed zone
    /// -> invalidate the pre-hash (falling back to the full post-hoc hash
    /// at completion).
    fn post_write_check(&self, off: u64) {
        if off < self.inner.gate() {
            self.inner.invalidated.store(true, Ordering::Release);
            warn!(target: "taiji::core::http", gid = %self.inner.gid, off,
                "checksum prefetch invalidated: in-flight write crossed consumed zone");
        }
    }

    /// Terminal finish: the reader catches up to total_len -> finalize ->
    /// compare. Returns `Some(Ok(()))` = verdict passed; `Some(Err(..))` =
    /// mismatch; `None` = the pre-hash is unavailable (invalidated/timeout/
    /// channel lost) — the caller falls back to the full hash.
    async fn finish_and_compare(&self) -> Option<Result<(), HttpError>> {
        let tx = crate::lock(&self.finish_tx).take()?;
        // Observation seam: unconsumed bytes at finish entry (an e2e overlap
        // assertion — consumed during download = total - pending; pending
        // == 0 is the evidence that hashing overlapped the whole download).
        {
            let pending = self
                .inner
                .total_len
                .saturating_sub(self.inner.hashed_to.load(Ordering::Acquire));
            prefetch_obs_record(&self.inner.gid, pending);
        }
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if tx
            .send(PrefetchCommand::Finish { reply: reply_tx })
            .await
            .is_err()
        {
            return None; // the reader is gone (unreachable: the handle holds the sender).
        }
        let hex = match tokio::time::timeout(PREFETCH_FINISH_TIMEOUT, reply_rx).await {
            Ok(Ok(Some(hex))) => hex,
            _ => return None, // timeout / channel lost / reader invalidated (fall back to full)
        };
        if hex != self.expected_hex {
            return Some(Err(HttpError::ChecksumMismatch {
                expected: self.expected_hex.clone(),
                got: hex,
            }));
        }
        Some(Ok(()))
    }
}

/// Global observation record (delivered at finish entry; a test assertion
/// face, never read in production).
static PREFETCH_OBS: StdMutex<Vec<(String, u64)>> = StdMutex::new(Vec::new());

/// Observation seam read (test/e2e assertions: unconsumed bytes at finish
/// entry).
#[cfg(test)]
pub(super) fn prefetch_finish_observations() -> Vec<(String, u64)> {
    crate::lock(&PREFETCH_OBS).clone()
}
/// Observation seam delivery (at the reader's finish close-out; the global
/// record keeps the last 8 — an e2e cross-instance assertion face, never
/// read in production).
fn prefetch_obs_record(gid: &str, pending: u64) {
    let mut obs = crate::lock(&PREFETCH_OBS);
    obs.push((gid.to_string(), pending));
    let n = obs.len();
    if n > 8 {
        obs.drain(..n - 8);
    }
}

/// The reader task's main loop: chase [hashed, prefix) -> wait for
/// advance/commands -> the finish close-out. Disk reads and digest updates
/// both run in `spawn_blocking` (blocking isolation; each segment
/// allocates its own buffer — a segment = the block size, the same scale
/// as the write path's block buffers).
async fn run_prefetch(
    inner: Arc<PrefetchInner>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<PrefetchCommand>,
) {
    // Read one segment + feed the digest + confirm the watermark (failure =
    // false -> invalidated). The read-only handle is opened per segment
    // (open is ~1 syscall and a segment hashes in milliseconds at block
    // size — the 'static cost of reusing a handle is not worth it).
    async fn consume_segment(inner: &PrefetchInner, hashed: u64, end: u64) -> bool {
        use taiji_store::disk::DiskWriter as _;
        inner.reading_to.store(end, Ordering::Release);
        let len = (end - hashed) as usize;
        let path = inner.part_path.clone();
        let read = tokio::task::spawn_blocking(move || -> Option<Vec<u8>> {
            let mut w = taiji_store::disk::FileDiskWriter::new();
            w.open_existing(&path, true).ok()?;
            let mut buf = vec![0u8; len];
            let mut total = 0usize;
            while total < buf.len() {
                match w.read_at(hashed + total as u64, &mut buf[total..]) {
                    Ok(n) if n > 0 => total += n,
                    _ => return None, // IO failure / short read (file behind bookkeeping)
                }
            }
            Some(buf)
        })
        .await;
        let data = match read {
            Ok(Some(data)) => data,
            _ => return false, // join failure / IO failure / short read
        };
        // The digest update runs on a blocking thread (the segment's CPU
        // face at block size).
        let fed = {
            let digest = Arc::clone(&digest_arc(inner));
            tokio::task::spawn_blocking(move || {
                let mut d = crate::lock(&digest);
                d.as_mut().is_some_and(|d| {
                    d.update(&data);
                    true
                })
            })
            .await
            .unwrap_or(false)
        };
        if !fed {
            return false; // the digest was already taken (unreachable: finish is the single taker)
        }
        inner.hashed_to.store(end, Ordering::Release);
        true
    }

    loop {
        // ---- Chase to the current prefix ----
        while !inner.invalidated.load(Ordering::Acquire) {
            let hashed = inner.hashed_to.load(Ordering::Relaxed);
            let prefix = inner.prefix_upto.load(Ordering::Acquire);
            if hashed >= prefix {
                break;
            }

            let end = (hashed + inner.block_size).min(prefix);
            if !consume_segment(&inner, hashed, end).await {
                inner.invalidated.store(true, Ordering::Release);
                warn!(target: "taiji::core::http", gid = %inner.gid,
                    "checksum prefetch read failed; falling back to full verify");
                break;
            }
        }
        // ---- Wait for advance / commands ----
        tokio::select! {
            _ = inner.notify.notified() => {}
            _ = tokio::time::sleep(PREFETCH_POLL) => {}
            cmd = cmd_rx.recv() => {
                let Some(PrefetchCommand::Finish { reply }) = cmd else {
                    return; // handle dropped (the task failure/cancel paths).
                };
                // The terminal chase (prefix already = total_len: the
                // completion verdict ran first).
                while !inner.invalidated.load(Ordering::Acquire) {
                    let hashed = inner.hashed_to.load(Ordering::Relaxed);
                    let prefix = inner.prefix_upto.load(Ordering::Acquire);
                    if hashed >= prefix {
                        break;
                    }
                    let end = (hashed + inner.block_size).min(prefix);
                    if !consume_segment(&inner, hashed, end).await {
                        inner.invalidated.store(true, Ordering::Release);
                        break;
                    }
                }
                let out = if inner.invalidated.load(Ordering::Acquire) {
                    None
                } else {
                    crate::lock(&inner.digest)
                        .take()
                        .map(|d| d.finalize_hex())
                };
                let _ = reply.send(out);
                return;
            }
        }
    }
}

/// The degraded/EOF stream's `--checksum` streaming-face assembly products.
type DegradedChecksumFaces = (
    Option<String>,
    Option<Arc<StdMutex<Option<TaskDigest>>>>,
    Option<taiji_http::checksum::ByteFeed>,
);

/// Assemble the degraded/EOF stream's `--checksum` streaming face: returns
/// (the raw checksum, the digest holder, the feed closure). An invalid/
/// unset scheme -> holder/feed all None (completion falls back to the
/// existing full post-hoc verification, same error timing and shape).
fn degraded_checksum_faces(config_json: &str) -> DegradedChecksumFaces {
    let cs = task_checksum(config_json);
    let digest = cs
        .as_deref()
        .and_then(TaskDigest::parse_scheme)
        .and_then(TaskDigest::new);
    match (cs, digest) {
        (Some(cs), Some(d)) => {
            let holder = Arc::new(StdMutex::new(Some(d)));
            let feed_holder = Arc::clone(&holder);
            let feed = Arc::new(move |b: &[u8]| {
                if let Some(d) = crate::lock(&feed_holder).as_mut() {
                    d.update(b);
                }
            }) as taiji_http::checksum::ByteFeed;
            (Some(cs), Some(holder), Some(feed))
        }
        (cs, _) => (cs, None, None), // no digest = unset/invalid (the latter
                                     // reports OptionInvalid at completion; same timing and shape)
    }
}

/// Take the tee digest's final value (after the fetch drains; None = not
/// assembled/already taken).
fn prefetched_digest_hex(holder: &Option<Arc<StdMutex<Option<TaskDigest>>>>) -> Option<String> {
    holder
        .as_ref()
        .and_then(|h| crate::lock(h).take())
        .map(|d| d.finalize_hex())
}

/// Digest comparison (the expected hex comes from the `--checksum` value's
/// right half; a missing '=' shape is `verify_checksum`'s OptionInvalid —
/// this function only runs on a syntactically valid value).
fn compare_digest(checksum: &str, got: String) -> Result<(), HttpError> {
    let expected = checksum
        .split_once('=')
        .map(|(_, e)| e.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if got == expected {
        Ok(())
    } else {
        Err(HttpError::ChecksumMismatch { expected, got })
    }
}

/// The completion-time checksum verdict (the aria2 `--checksum` face;
/// reference `ChecksumCheckIntegrityEntry.cc`). A mismatch fails the task
/// with the structured `ChecksumMismatch` error (canonical code +
/// expected/got; the numeric-face mapping lives in taiji-rpc `error.rs`).
/// The scheme domain is the six hashes md5|sha-1|sha-224|sha-256|sha-384|
/// sha-512 (RFC 1321 + FIPS 180-4; the same domain across the creation
/// face [`super::validate_checksum_value`], the pre-hash
/// [`TaskDigest::parse_scheme`], and here). Hashing is blocking work and
/// runs in spawn_blocking.
///
/// The post-hoc face is the fallback (pre-hash invalidated/timed out,
/// `drive_small` (<=2 blocks, negligible), the empty file (0 bytes), and
/// the degraded path's renamePending form); the grid main path and the
/// degraded sequential streams close out through the pre-hash.
async fn verify_checksum(path: &Path, checksum: &str) -> Result<(), HttpError> {
    let Some((scheme_raw, expected_raw)) = checksum.split_once('=') else {
        return Err(HttpError::OptionInvalid {
            option: "--checksum",
            value: format!("{checksum:?} (want <scheme>=<hex>)"),
        });
    };
    let scheme = scheme_raw.trim().to_ascii_lowercase();
    let expected = expected_raw.trim().to_ascii_lowercase();
    let p = path.to_path_buf();
    let got = tokio::task::spawn_blocking(move || -> Result<String, HttpError> {
        // The single digest::Digest trait (re-exported from one source by
        // md5/sha1/sha2).
        use sha1::Digest as _;
        let f = std::fs::File::open(&p)
            .map_err(|e| HttpError::Disk(format!("checksum: open failed: {e}")))?;
        let reader = std::io::BufReader::new(f);
        macro_rules! hash_file {
            ($ctor:expr) => {{
                let h = hash_reader(reader, $ctor)
                    .map_err(|e| HttpError::Disk(format!("checksum: read failed: {e}")))?;
                Ok(hex_lower(&h.finalize()))
            }};
        }
        match scheme.as_str() {
            "md5" => hash_file!(md5::Md5::new()),
            "sha-1" => hash_file!(sha1::Sha1::new()),
            "sha-224" => hash_file!(sha2::Sha224::new()),
            "sha-256" => hash_file!(sha2::Sha256::new()),
            "sha-384" => hash_file!(sha2::Sha384::new()),
            "sha-512" => hash_file!(sha2::Sha512::new()),
            other => Err(HttpError::OptionInvalid {
                option: "--checksum",
                value: format!("{other:?} (md5|sha-1|sha-224|sha-256|sha-384|sha-512)"),
            }),
        }
    })
    .await
    .map_err(|e| HttpError::Disk(format!("checksum join: {e}")))??;
    if got != expected {
        // The structured mismatch error: the canonical code
        // `taiji.http.checksum_mismatch` flows through HttpEnd.code into
        // the taiji-rpc numeric mapping (32 CHECKSUM_ERROR).
        return Err(HttpError::ChecksumMismatch { expected, got });
    }
    Ok(())
}

/// Lowercase hex of a byte sequence (the single digest-comparison source).
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Feed the hasher through a 64 KiB chunked read loop (digest 0.11 removed
/// the hasher's `io::Write` impl; the official digest_io crate is not
/// imported, so the read loop is the minimal local face). Returns the
/// hasher at EOF; read errors propagate.
fn hash_reader<D: sha1::Digest>(
    mut reader: impl std::io::Read,
    mut hasher: D,
) -> std::io::Result<D> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher);
        }
        hasher.update(&buf[..n]);
    }
}

/// `.part` file facts (the IO input for the resume's second line of
/// defense; spawn_blocking).
async fn part_facts_of(part_path: &Path) -> PartFileFacts {
    let p = part_path.to_path_buf();
    tokio::task::spawn_blocking(move || match std::fs::metadata(&p) {
        Ok(m) => PartFileFacts {
            exists: true,
            len: m.len(),
        },
        Err(_) => PartFileFacts {
            exists: false,
            len: 0,
        },
    })
    .await
    .unwrap_or(PartFileFacts {
        exists: false,
        len: 0,
    })
}

/// Row upsert (the no-persistence form = a no-op).
async fn upsert_row(p: Option<&PersistHandle>, row: &HttpTaskRow) -> Result<(), StoreError> {
    match p {
        Some(p) => p.upsert_http_task(row.clone()).await.map(|_| ()),
        None => Ok(()),
    }
}

/// Mirror row snapshot (state already set; the upsert input).
fn mirror_row(mirror: &StdMutex<HttpTaskRow>, phase: TaskPhase) -> HttpTaskRow {
    let mut row = crate::lock(mirror).clone();
    row.state = phase.as_v1_str().to_string();
    row
}

/// Mirror row state marker.
fn set_state(mirror: &StdMutex<HttpTaskRow>, phase: TaskPhase) {
    crate::lock(mirror).state = phase.as_v1_str().to_string();
}

/// Pipeline row progress face -> row mirror back-sync: the block-grid
/// persisted fields (granularity/bitmap/count/progress)
/// plus the resume-decision fields (probe facts/validator digest) are
/// written from the authoritative row (the snapshot pipeline's in-memory
/// truth) into the mirror. The row payloads of pause ([`cancelled_row`]),
/// saveSession's mirror flush, and changeOption-restart all take the mirror
/// as their source — without the sync, each point would overwrite a newer
/// fsynced DB snapshot with the stale activation-time mirror (a missing
/// digest -> the re-activation judges FromZero -> the whole file is
/// re-downloaded). The state column is not written here: state-machine
/// fields are maintained by the [`set_state`] driver face.
fn sync_mirror_progress(mirror: &StdMutex<HttpTaskRow>, row: &HttpTaskRow) {
    let mut m = crate::lock(mirror);
    m.block_size = row.block_size;
    m.block_bitmap = row.block_bitmap.clone();
    m.block_count = row.block_count;
    m.total_done = row.total_done;
    m.probe_json = row.probe_json.clone();
    m.validator_digest = row.validator_digest.clone();
}

/// Cancel close-out: a pause origin -> the row state paused (a restart
/// returns it to the paused queue); anything else (shutdown/remove) keeps
/// downloading as-is (the restart-resumes face). No fsync (the shutdown
/// budget discipline).
async fn cancelled_row(
    run: &HttpTaskRun,
    mirror: &Arc<StdMutex<HttpTaskRow>>,
    pause: &Arc<AtomicBool>,
) -> DriveStop {
    if pause.load(Ordering::Relaxed) {
        set_state(mirror, TaskPhase::Paused);
        let paused = mirror_row(mirror, TaskPhase::Paused);
        let _ = upsert_row(run.persist.as_ref(), &paused).await;
    }
    DriveStop::Cancelled
}

/// Task-level failure close-out: the row lands in the error state plus the
/// Failed exit. `failure` = the engine-side structured failure (canonical
/// code + refinement dimension — the row's error_code and
/// HttpEnd.error_engine share the source; numeric refinement flows through
/// the taiji-rpc map per code and per dimension).
async fn fail(
    p: Option<&PersistHandle>,
    mirror: &Arc<StdMutex<HttpTaskRow>>,
    failure: super::super::view::EngineFailure,
    msg: String,
) -> DriveStop {
    set_state(mirror, TaskPhase::Error);
    let mut row = mirror_row(mirror, TaskPhase::Error);
    warn!(target: "taiji::core::http", gid = %row.gid, code = %failure.code, note = %msg, "http task failed");
    row.error_code = Some(failure.code.clone());
    row.error_msg = Some(msg.clone());
    let _ = upsert_row(p, &row).await;
    DriveStop::Failed {
        failure,
        message: msg,
    }
}

/// Done-block trimming: the static plan's extents are shrunk/dropped by
/// the bitmap (a resumed task never refetches existing blocks). Each
/// extent is split into maximal undone block runs (the block-alignment
/// invariant holds).
fn trim_done_extents(plan: &mut StaticPlan, grid: &BlockGrid, bs: u64, count: u64, total_len: u64) {
    let mut kept: Vec<(u64, Extent)> = Vec::new();
    while let Some((seq, extent)) = plan.pop_next() {
        let first = extent.start / bs;
        let last = extent.end().min(total_len).div_ceil(bs).min(count);
        let mut run_start: Option<u64> = None;
        for b in first..last {
            if grid.is_recorded(b) {
                if let Some(s) = run_start.take() {
                    kept.push((seq, block_extent(s, b, bs, total_len)));
                }
            } else if run_start.is_none() {
                run_start = Some(b);
            }
        }
        if let Some(s) = run_start {
            kept.push((seq, block_extent(s, last, bs, total_len)));
        }
    }
    // push_front re-inserts at the segment queue's head, so inserting in
    // reverse restores the original order.
    for (seq, extent) in kept.iter().rev() {
        if !extent.is_empty() {
            plan.push_front(*seq, *extent);
        }
    }
}

/// The byte extent of the block interval `[from, to)` (the last block is
/// truncated to the total length).
fn block_extent(from: u64, to: u64, bs: u64, total_len: u64) -> Extent {
    let start = from * bs;
    let end = (to * bs).min(total_len);
    Extent {
        start,
        len: end.saturating_sub(start),
    }
}

// The "last complete block (inclusive)" judgment after an extent finishes
// lives in the protocol crate
// (taiji_http::worker::last_complete_block — the single source shared by
// static tail reporting and unit tests).

/// Block-size domain validation (row contract: power of two,
/// 256KiB..=16MiB).
pub(super) fn block_size_domain(bs: u64) -> Result<(), String> {
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bs) || !bs.is_power_of_two() {
        return Err(format!(
            "taiji.option.invalid: block size {bs} out of domain \
             (power of two, {MIN_BLOCK_SIZE}..{MAX_BLOCK_SIZE}; --http-block-size)"
        ));
    }
    Ok(())
}

// ---- Task cookie wiring (the core half) ----

/// Cookie identity key (the RFC 6265 primary key: name/domain/path) ->
/// creation_utc bookkeeping.
type CookieCreationMap = HashMap<(String, String, String), i64>;

/// Store snapshot -> persisted rows (the capture persistence
/// face). `creation_utc` is frozen by the `creation` bookkeeping at
/// assembly: a first-seen identity is stamped once with the current time
/// and reused every tick after (restamping every tick would make the
/// row-level comparison always see a delta — a full rewrite every 2s,
/// breaking the write-amplification bound).
fn cookie_rows_of(
    gid: &str,
    snap: &[NetscapeCookie],
    creation: &mut CookieCreationMap,
) -> Vec<taiji_store::persist::TaskCookieRow> {
    let now = now_epoch();
    snap.iter()
        .map(|c| {
            let key = (c.name.clone(), c.domain.clone(), c.path.clone());
            let created = *creation.entry(key).or_insert(now);
            taiji_store::persist::TaskCookieRow {
                gid: gid.to_string(),
                task_kind: taiji_store::persist::TASK_KIND_HTTP.into(),
                name: c.name.clone(),
                domain: c.domain.clone(),
                path: c.path.clone(),
                value: c.value.clone(),
                expires_utc: c.expires,
                secure: c.secure,
                host_only: c.host_only,
                creation_utc: created,
            }
        })
        .collect()
}

/// The write-back payload = the persisted baseline union the capture
/// snapshot: same-key snapshot entries win (this run's freshest captured
/// values); the baseline fills keys absent from the snapshot — the capture
/// snapshot only holds this run's Set-Cookies, and under full-set
/// replacement, skipping the baseline would wash away the previously
/// persisted set (clearing the store on activation). Expired baseline
/// entries are not filled back: cookies the server expired leave naturally
/// through snapshot absence (expiry = deletion is preserved; merging never
/// resurrects).
fn merged_cookie_rows(
    gid: &str,
    snap: &[NetscapeCookie],
    base: &[taiji_store::persist::TaskCookieRow],
    creation: &mut CookieCreationMap,
) -> Vec<taiji_store::persist::TaskCookieRow> {
    let mut rows = cookie_rows_of(gid, snap, creation);
    let now = now_epoch();
    for c in base {
        if c.expires_utc.is_some_and(|exp| now >= exp) {
            continue;
        }
        let dup = rows
            .iter()
            .any(|r| r.name == c.name && r.domain == c.domain && r.path == c.path);
        if dup {
            continue;
        }
        creation
            .entry((c.name.clone(), c.domain.clone(), c.path.clone()))
            .or_insert(c.creation_utc);
        rows.push(c.clone());
    }
    rows
}

/// Request-face replay of restored cookies (the RFC 6265 §5.4 condensed
/// matching): row facts are matched one by one against the first source
/// URI by domain/path/Secure -> explicit cookie pairs (`ctx.cookies`).
/// Expired rows are not replayed (the §5.4 unexpired gate). Divergence
/// declared separately: the pairs inject at the explicit layer (cross-host
/// stripping rides the layer semantics) — the single-source first hop is
/// same-origin and never triggers stripping; jar-level direct replay
/// converges once taiji-http exposes a Url construction seam (taiji-http's
/// frozen surface stays untouched).
fn restored_cookie_pairs(
    uris: &[String],
    rows: &[taiji_store::persist::TaskCookieRow],
) -> Vec<(String, String)> {
    let Some(first) = uris.first() else {
        return Vec::new();
    };
    let Some((scheme, host, path)) = split_request_target(first) else {
        return Vec::new();
    };
    let req_path = if path.is_empty() { "/" } else { path };
    let host_lc = host.to_ascii_lowercase();
    let now = now_epoch();
    rows.iter()
        .filter(|c| !c.expires_utc.is_some_and(|exp| now >= exp))
        .filter(|c| {
            if c.secure && !scheme.eq_ignore_ascii_case("https") {
                return false;
            }
            let domain_lc = c.domain.trim_start_matches('.').to_ascii_lowercase();
            let host_ok = if c.host_only {
                host_lc == domain_lc
            } else {
                host_lc == domain_lc || host_lc.ends_with(&format!(".{domain_lc}"))
            };
            if !host_ok {
                return false;
            }
            let cp = c.path.as_str();
            req_path == cp
                || cp == "/"
                || (req_path.starts_with(cp)
                    && (cp.ends_with('/') || req_path[cp.len()..].starts_with('/')))
        })
        .map(|c| (c.name.clone(), c.value.clone()))
        .collect()
}

/// Split the request target into (scheme/host/path); userinfo and port are
/// stripped.
fn split_request_target(uri: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = uri.split_once("://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    Some((scheme, host, path))
}

/// Idempotent disk close-out of a renamePending row (shared by the
/// bootstrap read-back and the session's periodic polling). The intent is
/// rebuilt from row facts: the `.part` path =
/// the final name + the persisted suffix, and the idempotence length takes
/// the disk facts (a `.part` present = the rename never settled; a final
/// file present = the "rename settled but crashed before clearing the
/// ledger" idempotent close-out form); neither present = the file facts are
/// lost, stay pending for a human decision (never fabricate success).
/// Returns whether close-out completed.
///
/// Claim-domain guard: if the final path is held by another task (an
/// in-flight task's plan_output creation-time claim), this round skips and
/// the next round retries — never jump ahead of the rename; self-held/free
/// -> claim atomically, then close out (prevents a new task from entering the
/// same path inside the close-out window). A successful close-out releases
/// both claims via finalize; staying pending keeps the claims across
/// rounds in the registry bookkeeping.
pub(super) async fn close_out_pending_row(
    persist: &Option<PersistHandle>,
    row: &HttpTaskRow,
) -> bool {
    if row.out.is_empty() || row.dir.is_empty() {
        return false;
    }
    let cfg = HttpPersistConfig::from_json(&row.config_json);
    let final_path = PathBuf::from(&row.dir).join(&row.out);
    let mut os = final_path.clone().into_os_string();
    os.push(&cfg.incomplete_suffix);
    let part_path = PathBuf::from(os);
    let (part_len, final_len) = part_and_final_lengths(&part_path, &final_path).await;
    let expected_len = match (part_len, final_len) {
        (Some(len), _) => len,
        (None, Some(len)) => len,
        (None, None) => {
            warn!(target: "taiji::core::http", gid = %row.gid,
                "renamePending close-out: neither part nor final file present; staying pending");
            return false;
        }
    };
    // Enter the claim domain only when disk facts exist (something to close
    // out): a final path held by another task -> skip this round; a failed
    // claim (a racing entrant) is the same face. Same-key idempotent — a
    // self-held claim from a previous stay-pending round does not block
    // this one.
    if taiji_http::partfile::claim_final_path(&final_path, &row.gid).is_err() {
        info!(target: "taiji::core::http", gid = %row.gid,
            path = %final_path.display(),
            "renamePending close-out: final path held by another task; deferring to next poll");
        return false;
    }
    let intent = RenameIntent {
        gid: row.gid.clone(),
        part_path,
        final_path,
        expected_len,
    };
    let journal = PersistJournal::new(persist.clone(), Arc::new(StdMutex::new(row.clone())));
    crate::lock(&journal.pending).push(intent);
    let finalizer = Finalizer::new(Arc::new(journal));
    match finalizer.retry_pending().await {
        Ok(outcomes) => {
            let closed = outcomes
                .iter()
                .all(|(_, o)| matches!(o, FinalizeOutcome::Completed { .. }));
            if closed {
                info!(target: "taiji::core::http", gid = %row.gid,
                    "renamePending close-out completed (bootstrap/poll retry)");
            }
            closed
        }
        Err(e) => {
            warn!(target: "taiji::core::http", gid = %row.gid,
                error = %e, "renamePending close-out journal failure; staying pending");
            false
        }
    }
}

/// Clear a task's own stale claims before a rerun: when a done+renamePending
/// row re-enters the run via unpause (reopen admits done rows), the
/// part+final claims handed over by the previous finalize would block the
/// rerun (plan_output / `PartFile::open` hit the
/// `taiji.http.path_conflict` misjudgment). At most one driver exists per
/// gid at a time (serial actor activation, a single driver), so only this
/// task's own stale claims can be released — final claims are released
/// wholesale by the holder key (auto-rename's historical candidate paths
/// are not in the row facts); part claims release by path, and the same
/// part path implies the same final path (the final domain already
/// excludes other tasks), so no other task's claim can be wrongly removed.
pub(super) fn release_own_pending_claims(gid_hex: &str, dir: &str, out: &str, config_json: &str) {
    if dir.is_empty() || out.is_empty() {
        return;
    }
    let suffix = HttpPersistConfig::from_json(config_json).incomplete_suffix;
    let final_path = PathBuf::from(dir).join(out);
    let mut os = final_path.into_os_string();
    os.push(&suffix);
    taiji_http::partfile::release_all_final_claims(gid_hex);
    taiji_http::partfile::release_part_claim(Path::new(&os));
}

/// `.part` / final file lengths on disk (blocking face via spawn_blocking;
/// NotFound = None).
async fn part_and_final_lengths(part: &Path, done: &Path) -> (Option<u64>, Option<u64>) {
    let (p, d) = (part.to_path_buf(), done.to_path_buf());
    tokio::task::spawn_blocking(move || {
        let len_of = |path: std::path::PathBuf| std::fs::metadata(&path).ok().map(|m| m.len());
        (len_of(p), len_of(d))
    })
    .await
    .unwrap_or((None, None))
}

/// URL path's last segment -> a candidate output name (percent-decode;
/// strip query/fragment, take the last segment, trim; empty/`.`/`..`
/// shapes return None).
///
/// This function only does "take the last segment + decode + filter empty
/// shapes" — Windows-unsafe names are NOT rejected here (no
/// separators/colons/control-chars/reserved-names/trailing dot-space ->
/// None -> default-name fallback); the downstream
/// [`sanitize_generated_name`] sanitizes the full channel
/// (illegal chars -> `_`, reserved names suffixed, trailing dots/spaces
/// stripped: URL/CD names are the main source of dirty data and
/// sanitization beats rejection — no peer handles illegal characters by
/// rejection). The returned candidate may still
/// contain arbitrary characters; callers must sanitize before joining a
/// path.
fn derive_name_from_url(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let last = path.rsplit('/').next().unwrap_or("");
    let name = percent_decode(last);
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    Some(name.to_string())
}

/// Minimal percent-decode (%XX hex; illegal sequences pass through).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(h) = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(h);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Outbound URI redaction (strip query/fragment; the minimal local face of
/// unified redaction — log/error text outbound strings pass through here).
fn redact_uri(uri: &str) -> String {
    uri.split(['?', '#']).next().unwrap_or(uri).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    // The pure-function/constant unit tests moved with the worker loop into
    // taiji-http (the protocol face's single source).
    use taiji_http::worker::{
        FetchProgress, WORKER_FAILURE_CAP, failure_budget_step, last_complete_block,
    };

    /// The slow-start endpoint's two-arm detection table (the observable
    /// definition): the settled arm true -> true; an empty snapshot / no
    /// AIMD always false; the connection-cap arm = sum(n) >= cap x sources;
    /// cap 0 defensively clamps to 1.
    #[test]
    fn slowstart_reached_two_arm_table() {
        use taiji_http::coordinator::RuntimeStats;
        let mk = |conns: &[(u32, u32)], settled: bool| RuntimeStats {
            aimd_connections: conns.to_vec(),
            slowstart_settled: settled,
            ..RuntimeStats::default()
        };
        // Settled arm: any source holding is true (the connection count is
        // irrelevant).
        assert!(slowstart_reached(&mk(&[(0, 1)], true), 16));
        // Empty snapshot (the static baseline / no-AIMD state) is always false.
        assert!(!slowstart_reached(&mk(&[], false), 16));
        // Connection-cap arm: single source sum=16 >= cap 16 -> true; 15 -> false.
        assert!(slowstart_reached(&mk(&[(0, 16)], false), 16));
        assert!(!slowstart_reached(&mk(&[(0, 15)], false), 16));
        // Multi-source: cap x registered sources (sum=8 < 2x8=16 -> false; sum=16
        // -> true).
        assert!(!slowstart_reached(&mk(&[(0, 4), (1, 4)], false), 8));
        assert!(slowstart_reached(&mk(&[(0, 8), (1, 8)], false), 8));
        // Cap 0 defensively clamps to 1 (a degenerate input never false-positives).
        assert!(slowstart_reached(&mk(&[(0, 1)], false), 0));
        assert!(!slowstart_reached(&mk(&[(0, 1)], false), 16));
    }

    /// The default cap pin: the default assembly (dynamic, no
    /// split/max-connection passed) = cap 16 + slow-start start 5 (the
    /// split default) — the AIMD criterion has room to grow toward the
    /// saturation plateau; the cap is a ceiling, not a connection hard cap.
    /// The explicit pin-1 semantics stay: cap 1 -> start clamped to 1 (the
    /// same shape as aria2 upstream `-x1`, single connection).
    #[test]
    fn default_cap_leaves_aimd_headroom_and_pin_one_still_honored() {
        let opts = HttpTaskOpts::default();
        assert_eq!(opts.max_conn_per_server, DEFAULT_MAX_CONN_PER_SERVER);
        let cfg = AimdConfig::with_start(opts.max_conn_per_server, opts.split);
        assert_eq!(
            cfg.max_connections, 16,
            "default cap = domain ceiling (the plateau)"
        );
        assert_eq!(cfg.start_connections, 5, "slow-start start = split default");
        // Explicit pin 1: cap 1 -> start 1, want stays single-connection end to
        // end (the 1conn control-group semantics).
        let pinned = AimdConfig::with_start(1, 1);
        assert_eq!(pinned.max_connections, 1);
        assert_eq!(pinned.start_connections, 1);
    }

    /// Concurrency-intent replay domain clamping (sanitizing legacy poisoned
    /// rows): a split=u32::MAX poison row stored via addUri before the
    /// ceiling gate replays verbatim into opts at every bootstrap
    /// (lifecycle's [`HttpConcurrencyPersist::apply_to`]) -> the static
    /// scheduler's first wave `WorkerPool::fixed(sources, split)` spawns
    /// unconditionally -> four billion workers (OOM persisting across
    /// restarts). Replay clamping must share the parse face's domain: split
    /// 1..=4096 (pinned to the same source as
    /// `taiji_http::scheduler::MAX_SPLIT` — when the constant changes, this
    /// assertion re-reviews with the domain); out-of-domain narrows to the
    /// domain, never amplifies.
    #[test]
    fn concurrency_replay_clamps_poisoned_split_into_parse_domain() {
        let mut opts = HttpTaskOpts::default();
        // Poison-row shape: split=u32::MAX (4294967295) -> clamped to the upper
        // bound 4096, never passed through verbatim.
        HttpConcurrencyPersist {
            split: u32::MAX,
            max_conn_per_server: 16,
        }
        .apply_to(&mut opts);
        assert_eq!(
            opts.split, 4096,
            "poisoned split must clamp to the parse-face ceiling"
        );
        assert_eq!(opts.max_conn_per_server, 16, "in-domain cap untouched");
        // One past the bound: 4097 -> 4096; exactly on the bound stays; in-domain
        // values are untouched.
        HttpConcurrencyPersist {
            split: 4097,
            max_conn_per_server: 1,
        }
        .apply_to(&mut opts);
        assert_eq!(
            opts.split, 4096,
            "one past the bound clamps back to the ceiling"
        );
        HttpConcurrencyPersist {
            split: 64,
            max_conn_per_server: 1,
        }
        .apply_to(&mut opts);
        assert_eq!(opts.split, 64, "in-domain value kept as-is");
        // split=0 -> clamp to 1 (the existing lower-bound semantics hold).
        HttpConcurrencyPersist {
            split: 0,
            max_conn_per_server: 0,
        }
        .apply_to(&mut opts);
        assert_eq!(opts.split, 1, "lower clamp to 1 holds");
        assert_eq!(opts.max_conn_per_server, 1, "cap lower clamp to 1 holds");

        // The poisoned config_json whole chain (bootstrap replays the same seam:
        // from_json -> concurrency -> apply_to) — a disk poison row reaches the
        // replay face straight through deserialization.
        let raw = r#"{"concurrency":{"split":4294967295,"max_conn_per_server":16}}"#;
        let mut opts = HttpTaskOpts::default();
        if let Some(face) = HttpPersistConfig::from_json(raw).concurrency {
            face.apply_to(&mut opts);
        }
        assert_eq!(
            opts.split, 4096,
            "the poisoned row's whole chain must clamp into the domain (no OOM amplification)"
        );
    }

    /// The failure-budget step matrix: progress -> always 1 (the ADM
    /// `mMadeProgress -> mNumFailed=1` rule); zero bytes -> accumulate; the
    /// cap check consumes the step (>= [`WORKER_FAILURE_CAP`] exits). The
    /// matrix covers both shapes: repeated failures-with-progress never
    /// burn the cap, and five consecutive zero-byte failures do.
    #[test]
    fn failure_budget_step_matrix() {
        // Failures with progress: reset to 1 from any starting point — a long
        // transfer is never mis-killed by the cap.
        assert_eq!(failure_budget_step(0, FetchProgress::WroteBytes), 1);
        assert_eq!(failure_budget_step(3, FetchProgress::WroteBytes), 1);
        assert_eq!(
            failure_budget_step(WORKER_FAILURE_CAP - 1, FetchProgress::WroteBytes),
            1,
            "a failure-with-progress after budget must reset (otherwise the next zero-byte \
             round is mis-killed early)"
        );
        // Zero-byte failures: accumulate.
        assert_eq!(failure_budget_step(0, FetchProgress::ZeroBytes), 1);
        assert_eq!(failure_budget_step(3, FetchProgress::ZeroBytes), 4);
        // End-to-end sequence 1 (the server drops after every segment): progress
        // throughout -> the count stays 1 and never hits the cap.
        let mut f = 0;
        for _ in 0..WORKER_FAILURE_CAP + 3 {
            f = failure_budget_step(f, FetchProgress::WroteBytes);
            assert_eq!(f, 1);
            assert!(f < WORKER_FAILURE_CAP);
        }
        // End-to-end sequence 2 (zero-byte failures that die at connect): 1..=5
        // -> the cap trips exactly on the 5th.
        let mut f = 0;
        let mut hits = 0;
        for _ in 0..WORKER_FAILURE_CAP {
            f = failure_budget_step(f, FetchProgress::ZeroBytes);
            if f >= WORKER_FAILURE_CAP {
                hits += 1;
            }
        }
        assert_eq!(f, WORKER_FAILURE_CAP);
        assert_eq!(hits, 1, "the cap trips exactly once, on the 5th");
        // Mixed sequence (progress once, then the source dies fully): the reset
        // grants one exemption only; afterwards zero-byte failures accumulate from
        // 1 to the cap as usual — the negative close-out is never exempted by past
        // progress.
        let mut f = 0;
        f = failure_budget_step(f, FetchProgress::WroteBytes); // 1 (failure with progress)
        f = failure_budget_step(f, FetchProgress::WroteBytes); // 1
        for expect in 2..=WORKER_FAILURE_CAP {
            f = failure_budget_step(f, FetchProgress::ZeroBytes);
            assert_eq!(
                f, expect,
                "zero-byte failures must keep accumulating from the reset point"
            );
        }
        assert!(
            f >= WORKER_FAILURE_CAP,
            "the cap still burns through once the source is fully dead"
        );
    }

    /// The precise stagger rules: a warm pool = zero delay, a cold pool
    /// keeps the first-wave ramp, ordinal 0 is always zero (the grid's
    /// "each source's first cut has zero delay" original semantics),
    /// out-of-range ordinals clamp; the linkage with taiji-http's warm-pool
    /// signal [`taiji_http::client::uri_on_warm_pool`] (a real cold-host
    /// query) is pinned too — the warm-marker lighting is covered by
    /// taiji-http's e2e (reuse_pool_mock.rs).
    #[test]
    fn stagger_delay_precise_warm_skip_and_cold_ramp() {
        assert_eq!(
            stagger_delay(3, PoolWarmth::Warm),
            Duration::ZERO,
            "warm pool skips entirely (in-pool reuse is zero-delay)"
        );
        assert_eq!(
            stagger_delay(0, PoolWarmth::Cold),
            Duration::ZERO,
            "ordinal 0 is always zero (the grid's per-source first-cut original semantics)"
        );
        assert_eq!(
            stagger_delay(3, PoolWarmth::Cold),
            Duration::from_millis(15),
            "the cold pool keeps the 5ms-per-ordinal ramp"
        );
        assert_eq!(
            stagger_delay(99, PoolWarmth::Cold),
            Duration::from_millis(5 * 64),
            "ordinals clamp to CONNECT_STAGGER_MAX_ORDINAL (~320ms cap, the original semantics)"
        );
        // The linkage (a real query): a host this process never had a data-plane
        // success with (discard port 9, the connection never succeeds) is always
        // cold -> the ramp stays.
        let cold = "http://127.0.0.1:9/never-requested.bin";
        assert!(!taiji_http::client::uri_on_warm_pool(cold));
        let cold_warmth = if taiji_http::client::uri_on_warm_pool(cold) {
            PoolWarmth::Warm
        } else {
            PoolWarmth::Cold
        };
        assert_eq!(
            stagger_delay(5, cold_warmth),
            Duration::from_millis(25),
            "the cold host's real signal chained with the predicate = the ramp preserved"
        );
    }

    /// Fast-path range planning: k = min(split, cap), near-equal splits, no
    /// gaps or overlaps, always covering [0, total).
    #[test]
    fn small_task_ranges_plan_shape_and_coverage() {
        // Intent face: split=16 x cap=16 -> 16 segments (1MiB at 64KiB each).
        let r = small_task_ranges(1024 * 1024, 16, 16);
        assert_eq!(r.len(), 16, "min(split,cap)=16 segments");
        assert_eq!(r.first().copied(), Some((0, 64 * 1024)));
        assert_eq!(
            r.last().copied(),
            Some((1024 * 1024 - 64 * 1024, 1024 * 1024))
        );
        // Near-equal: the first segment takes the remainder (base+1); no gaps, no overlaps.
        let r = small_task_ranges(10, 16, 16);
        assert_eq!(
            r.len(),
            10,
            "segment count clamps to total length (each segment >= 1 byte)"
        );
        assert!(r.iter().all(|(s, e)| e - s == 1));
        // Cap collapse: split=16 x cap=1 -> a single segment (the factory default
        // shape — single-connection behavior).
        assert_eq!(
            small_task_ranges(1024 * 1024, 16, 1),
            vec![(0, 1024 * 1024)]
        );
        // A split intent below the cap.
        assert_eq!(small_task_ranges(1024 * 1024, 4, 16).len(), 4);
        // Coverage invariant: for any (total, split, cap) the pieces always
        // concatenate to exactly [0, total).
        for total in [1u64, 255, 256 * 1024, 1048577, 3 * 1024 * 1024 + 7] {
            for split in [1u32, 2, 5, 16] {
                for cap in [1u32, 3, 16] {
                    let r = small_task_ranges(total, split, cap);
                    let mut off = 0u64;
                    for (s, e) in &r {
                        assert_eq!(*s, off, "no gaps, no overlaps");
                        off = *e;
                    }
                    assert_eq!(off, total, "always covers [0, total)");
                }
            }
        }
        // The empty-file degenerate (theoretically unreachable — the EmptyFile
        // plan comes first; a defensive face).
        assert!(small_task_ranges(0, 16, 16).is_empty());
    }

    /// The cookie row assembly face: creation_utc frozen at assembly (the
    /// same identity on a later tick reuses the first-seen stamp — the
    /// row-level comparison can judge equality, no per-tick full rewrites);
    /// the write-back payload = baseline union snapshot (absent keys
    /// filled, same-key snapshot wins, expired baseline entries never
    /// resurrect); expired rows never enter the request-face replay.
    #[test]
    fn cookie_rows_stable_creation_and_base_merge() {
        let gid = "8000000000000900";
        let mk = |name: &str, value: &str| NetscapeCookie {
            domain: "x.test".into(),
            host_only: true,
            path: "/".into(),
            secure: false,
            expires: None,
            name: name.into(),
            value: value.into(),
        };
        let base_row =
            |name: &str, value: &str, created: i64, expires: Option<i64>| TaskCookieRow {
                gid: gid.into(),
                task_kind: taiji_store::persist::TASK_KIND_HTTP.into(),
                name: name.into(),
                domain: "x.test".into(),
                path: "/".into(),
                value: value.into(),
                expires_utc: expires,
                secure: false,
                host_only: true,
                creation_utc: created,
            };
        let mut creation = CookieCreationMap::new();
        // First tick stamps; a later tick with the same identity reuses it
        // (per-tick restamping = the every-2s-full-rewrite root cause).
        let r1 = cookie_rows_of(gid, &[mk("sid", "v1")], &mut creation);
        assert_eq!(r1.len(), 1);
        let created1 = r1[0].creation_utc;
        let r2 = cookie_rows_of(gid, &[mk("sid", "v2")], &mut creation);
        assert_eq!(
            r2[0].creation_utc, created1,
            "a second stamping of the same identity must reuse the first-seen stamp"
        );
        // Baseline merge: snapshot-absent keys are filled (the stored
        // creation_utc); same-key snapshot wins; expired baseline entries never
        // resurrect.
        let base = vec![
            base_row("kept", "old", 1_700_000_000, None),
            base_row("sid", "stale", 1_700_000_001, None),
            base_row("dead", "old", 1_700_000_002, Some(1)),
        ];
        let merged = merged_cookie_rows(gid, &[mk("sid", "v2")], &base, &mut creation);
        let names: Vec<&str> = merged.iter().map(|r| r.name.as_str()).collect();
        let kept = merged
            .iter()
            .find(|r| r.name == "kept")
            .unwrap_or_else(|| panic!("kept must be merged"));
        assert_eq!(
            kept.creation_utc, 1_700_000_000,
            "baseline row keeps its stored stamp"
        );
        let sid = merged
            .iter()
            .find(|r| r.name == "sid")
            .unwrap_or_else(|| panic!("sid must be present"));
        assert_eq!(sid.value, "v2", "same-key snapshot wins");
        assert_eq!(sid.creation_utc, created1);
        assert!(
            !names.contains(&"dead"),
            "expired baseline entries must not resurrect via merge (expiry = removal semantics preserved)"
        );
        // Request-face replay: expired rows are skipped, unexpired rows still produce pairs.
        let pairs = restored_cookie_pairs(
            &["https://x.test/a".to_string()],
            &[
                base_row("dead", "old", 0, Some(1)),
                base_row("live", "v", 0, None),
            ],
        );
        assert_eq!(
            pairs,
            vec![("live".to_string(), "v".to_string())],
            "expired cookies are not replayed"
        );
    }

    /// URL last-segment derivation: segment extraction, query/fragment
    /// stripping, percent-decode, empty/dot filtering (only takes the last
    /// segment — unsafe shapes go to the sanitization face).
    #[test]
    fn derive_name_from_url_matrix() {
        assert_eq!(
            derive_name_from_url("http://x.test/a/b/file%20name.bin?token=1"),
            Some("file name.bin".into())
        );
        assert_eq!(
            derive_name_from_url("http://x.test/plain"),
            Some("plain".into())
        );
        assert_eq!(derive_name_from_url("http://x.test/"), None);
        assert_eq!(derive_name_from_url("http://x.test/.."), None);
        assert_eq!(derive_name_from_url(""), None);
    }

    /// Windows traversal/unsafe shapes are not rejected at the derivation
    /// layer — they are returned as-is and
    /// [`sanitize_generated_name`]'s full-channel sanitization lands them as
    /// `_`/suffixed/stripped. The two-stage assertion (derived as-is + the
    /// actual sanitized name on disk) pins both stages.
    #[test]
    fn windows_unsafe_shapes_pass_to_full_channel_sanitizer() {
        // (URL, derived candidate name, sanitized on-disk name)
        let cases = [
            // Backslash traversal (the post-decode shape) -> `_`.
            ("http://x.test/a%5Cb", "a\\b", "a_b"),
            ("http://x.test/..%5C..%5Cevil", "..\\..\\evil", ".._.._evil"),
            (r"http://x.test/back\slash", "back\\slash", "back_slash"),
            // Drive prefixes / colons (the ADS stream shape `f:ads` washes the same) -> `_`.
            ("http://x.test/C:%5Cevil", "C:\\evil", "C__evil"),
            ("http://x.test/file.txt:ads", "file.txt:ads", "file.txt_ads"),
            // Control characters (decode restores %01) -> `_`.
            ("http://x.test/a%01b", "a\u{1}b", "a_b"),
            // Zero-width code points as percent-decode shapes (%E2%80%8B = U+200B
            // ZWSP — the name-borrowing face where a URL-derived name is visually
            // identical to `evil.exe`) -> `_`; the line separator %E2%80%A8 = U+2028
            // washes the same.
            (
                "http://x.test/evil%E2%80%8B.exe",
                "evil\u{200B}.exe",
                "evil_.exe",
            ),
            ("http://x.test/a%E2%80%A8b", "a\u{2028}b", "a_b"),
            // Windows reserved device names (incl. extension forms) -> suffix the
            // stem, keep the extension.
            ("http://x.test/con", "con", "con_"),
            ("http://x.test/NUL", "NUL", "NUL_"),
            ("http://x.test/com1", "com1", "com1_"),
            ("http://x.test/lpt9.bin", "lpt9.bin", "lpt9_.bin"),
            ("http://x.test/aux.txt", "aux.txt", "aux_.txt"),
            // Trailing dots/spaces (the Win32 name-borrowing confusion face) -> stripped.
            ("http://x.test/evil.", "evil.", "evil"),
            ("http://x.test/evil.%20", "evil.", "evil"),
            // Control: healthy names with interior dots/spaces are unaffected.
            (
                "http://x.test/my.file name-v2.bin",
                "my.file name-v2.bin",
                "my.file name-v2.bin",
            ),
        ];
        for (url, derived, sanitized) in cases {
            assert_eq!(
                derive_name_from_url(url),
                Some(derived.into()),
                "derive {url}"
            );
            assert_eq!(
                taiji_http::naming::sanitize_generated_name(derived),
                sanitized,
                "sanitize {url}"
            );
        }
    }

    /// percent-decode: legal sequences decode, an illegal % is preserved, a
    /// byte-level round-trip.
    #[test]
    fn percent_decode_preserves_and_decodes() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("plain"), "plain");
    }

    /// Done-block trimming: with the first block done plus a mid hole, the
    /// extent shrinks to the undone run; a fully-done extent is dropped
    /// whole; the block-alignment invariant holds.
    #[test]
    fn trim_done_extents_shrinks_to_undone_runs() {
        let bs = 256 * 1024u64; // the configured domain's floor
        let total = 3 * bs; // 3 blocks
        let mut grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        for b in [0u64, 2] {
            grid.record(b).unwrap_or_else(|e| panic!("record: {e}"));
        }
        let sched = SchedulerConfig {
            mode: SchedulerMode::Static,
            block_size: bs,
            split: 1,
            min_split_size: bs,
        };
        let mut plan = StaticPlan::build(total, &sched).unwrap_or_else(|e| panic!("plan: {e}"));
        trim_done_extents(&mut plan, &grid, bs, 3, total);
        // The remaining allocation = block 1 ([bs, 2*bs)); blocks 0 and 2 are no longer assigned.
        let mut got: Vec<(u64, u64)> = Vec::new();
        while let Some((_, extent)) = plan.pop_next() {
            got.push((extent.start, extent.end()));
        }
        assert_eq!(got, vec![(bs, 2 * bs)], "only the undone block 1 remains");
    }

    /// Block-interval extents: the last block truncates to the total; an empty
    /// run yields an empty extent.
    #[test]
    fn block_extent_clamps_last_partial() {
        assert_eq!(block_extent(0, 3, 4, 10), Extent { start: 0, len: 10 });
        assert_eq!(block_extent(1, 2, 4, 10), Extent { start: 4, len: 4 });
        assert_eq!(block_extent(2, 2, 4, 10), Extent { start: 8, len: 0 });
    }

    /// The last-complete-block judgment (zero tolerance for bitmap
    /// overstatement): an aligned mid extent never overreports (end = k*bs
    /// => the last complete block is k-1); a final extent reaching the total
    /// fills the trailing block; an unaligned end is absorbed by floor. A
    /// partial-block end (extent_end < bs) saturates to "no complete block"
    /// (bare subtraction would panic on underflow in debug builds).
    #[test]
    fn last_complete_block_never_overreports() {
        let bs = 4u64;
        let count = 4u64;
        let total = 14u64; // 3.5 blocks at bs=4
        // Aligned mid [0,8): complete blocks 0, 1 (block 2 unwritten —
        // overstating it would corrupt).
        assert_eq!(last_complete_block(8, total, bs, count), 1);
        // Aligned end [4,12) < total: complete blocks 1, 2.
        assert_eq!(last_complete_block(12, total, bs, count), 2);
        // Reaching the authoritative total: the trailing block fills.
        assert_eq!(last_complete_block(14, total, bs, count), 3);
        // Unaligned end absorbed by floor (a partial block never reports complete).
        assert_eq!(last_complete_block(6, total, bs, count), 0);
        // Underflow saturation: extent_end=0 -> 0/4-1 panics on bare subtraction.
        assert_eq!(last_complete_block(0, total, bs, count), 0);
        assert_eq!(last_complete_block(3, total, bs, count), 0);
    }

    /// The block-size domain (row contract): power of two, 256KiB..=16MiB;
    /// out-of-domain is rejected.
    #[test]
    fn block_size_domain_matrix() {
        for ok_bs in [
            MIN_BLOCK_SIZE,
            1024 * 1024,
            DEFAULT_BLOCK_SIZE,
            MAX_BLOCK_SIZE,
        ] {
            assert!(block_size_domain(ok_bs).is_ok(), "{ok_bs} must be valid");
        }
        for bad in [
            0,
            MIN_BLOCK_SIZE - 1,
            MAX_BLOCK_SIZE + 1,
            3 * 1024 * 1024, // not a power of two
        ] {
            assert!(block_size_domain(bad).is_err(), "{bad} must be rejected");
        }
    }

    /// PersistJournal's intent-list gid dedup: repeated records for one
    /// task do not grow the list; other tasks still append.
    #[tokio::test]
    async fn persist_journal_dedups_intents_by_gid() {
        let mirror = Arc::new(StdMutex::new(HttpTaskRow {
            gid: "8000000000000300".into(),
            url: String::new(),
            final_url: String::new(),
            mirrors_json: None,
            state: taiji_http::finalize::STATE_DONE.into(),
            queue_pos: 0,
            dir: "/dl".into(),
            out: "f.bin".into(),
            config_json: "{}".into(),
            probe_json: None,
            validator_digest: None,
            block_size: 0,
            block_bitmap: None,
            block_count: None,
            total_done: 0,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        }));
        let journal = PersistJournal::new(None, Arc::clone(&mirror));
        async fn record(journal: &PersistJournal, gid: &str) {
            let i = RenameIntent {
                gid: gid.into(),
                part_path: PathBuf::from("/dl/f.bin.part"),
                final_path: PathBuf::from("/dl/f.bin"),
                expected_len: 10,
            };
            journal
                .record_intent(&i)
                .await
                .unwrap_or_else(|e| panic!("record {gid}: {e}"));
        }
        record(&journal, "8000000000000300").await;
        record(&journal, "8000000000000300").await;
        record(&journal, "8000000000000301").await;
        let pending = journal.pending.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            pending.iter().map(|i| i.gid.as_str()).collect::<Vec<_>>(),
            vec!["8000000000000300", "8000000000000301"],
            "same gid deduped, distinct gids kept"
        );
    }

    /// Restored-cookie request-face replay (the §5.4 condensed matching):
    /// host-only exact domain, domain-cookie subdomain match, path prefix
    /// boundaries, secure only over https.
    #[test]
    fn restored_cookie_pairs_match_by_domain_path_secure() {
        let cookie = |domain: &str, host_only: bool, path: &str, secure: bool| TaskCookieRow {
            gid: "8000000000000310".into(),
            task_kind: taiji_store::persist::TASK_KIND_HTTP.into(),
            name: "sid".into(),
            domain: domain.into(),
            path: path.into(),
            value: "v1".into(),
            expires_utc: None,
            secure,
            host_only,
            creation_utc: 0,
        };
        let rows = vec![
            cookie("cdn.example", true, "/", false),
            cookie("example.com", false, "/dl", false),
            cookie("secure.example", true, "/", true),
        ];
        // First source = an exact host hit + the path "/" fully matching.
        let pairs = restored_cookie_pairs(&["http://cdn.example/f.bin".to_string()], &rows);
        assert_eq!(pairs, vec![("sid".to_string(), "v1".to_string())]);
        // A subdomain hits the domain cookie and the path prefix holds; a
        // host-only domain does not match; secure entries are suppressed on http.
        let pairs = restored_cookie_pairs(&["http://a.example.com/dl/file".to_string()], &rows);
        assert_eq!(
            pairs.len(),
            1,
            "only the domain cookie (example.com, /dl) matches"
        );
        // Path boundary: /dlx must not match /dl.
        let pairs = restored_cookie_pairs(&["http://a.example.com/dlx".to_string()], &rows);
        assert!(
            pairs.is_empty(),
            "a non-prefix path boundary does not match"
        );
        // Secure cookies only over https.
        let pairs = restored_cookie_pairs(&["https://secure.example/f".to_string()], &rows);
        assert_eq!(pairs, vec![("sid".to_string(), "v1".to_string())]);
    }

    /// The import-option fold face: request-identity keys go through the
    /// existing runtime parser (merge semantics = a present key replaces
    /// the baseline); cumulative headers join in order; out-of-domain keys
    /// (scheduling/timeout) and unknown keys do not fold (baseline kept).
    #[test]
    fn fold_imported_options_maps_request_identity_domain() {
        let base = HttpTaskOpts::default();
        let (folded, cfg) = fold_imported_options(
            base.clone(),
            HttpPersistConfig::default(),
            &[
                ("user-agent".to_string(), "import-agent/9".to_string()),
                ("header".to_string(), "X-A: 1".to_string()),
                ("header".to_string(), "Authorization: Bearer t".to_string()),
                ("all-proxy".to_string(), "http://127.0.0.1:7890".to_string()),
                ("http-user".to_string(), "u".to_string()),
                ("http-passwd".to_string(), "p".to_string()),
                ("ftp-user".to_string(), "fu".to_string()),
                ("ftp-passwd".to_string(), "fp".to_string()),
                // Out-of-domain keys: the scheduling/timeout domain does not fold (the
                // runtime face is rebuilt from session options).
                ("split".to_string(), "16".to_string()),
                ("timeout".to_string(), "3".to_string()),
                ("unknown-fork-key".to_string(), "v".to_string()),
            ],
        )
        .unwrap_or_else(|e| panic!("fold: {e}"));
        assert_eq!(folded.user_agent.as_deref(), Some("import-agent/9"));
        assert_eq!(
            folded.headers,
            vec![
                ("X-A".to_string(), "1".to_string()),
                ("Authorization".to_string(), "Bearer t".to_string()),
            ],
            "cumulative headers preserve order"
        );
        assert_eq!(folded.proxy.as_deref(), Some("http://127.0.0.1:7890"));
        assert_eq!(
            folded.auth,
            Some(taiji_segment::traits::AuthScheme::Basic {
                user: "u".into(),
                passwd: "p".into(),
            })
        );
        assert_eq!(
            folded.ftp_auth,
            Some(taiji_segment::traits::AuthScheme::Basic {
                user: "fu".into(),
                passwd: "fp".into(),
            })
        );
        // Out-of-domain keys do not fold: baseline defaults hold.
        assert_eq!(folded.split, base.split);
        assert_eq!(folded.read_timeout, base.read_timeout);
        assert_eq!(folded.block_size, base.block_size);
        // Runtime keys never leak into the persistence face.
        assert_eq!(
            cfg,
            HttpPersistConfig::default(),
            "runtime folding leaves zero persist drift"
        );
    }

    /// The import fold face (the three persistence keys): checksum/
    /// remote-time/http-incomplete-suffix fold into [`HttpPersistConfig`]
    /// via the persist driver — the verdict faces read the row payload, so
    /// a value landing in cfg is the start of end-to-end consumption. TLS
    /// trust keys (check-certificate/ca-certificate) do not fold (the
    /// fail-closed stance).
    #[test]
    fn fold_imported_options_maps_persist_face_keys() {
        let digest = "ab".repeat(32);
        let (opts, cfg) = fold_imported_options(
            HttpTaskOpts::default(),
            HttpPersistConfig::default(),
            &[
                ("checksum".to_string(), format!("sha-256={digest}")),
                ("remote-time".to_string(), "true".to_string()),
                (
                    "http-incomplete-suffix".to_string(),
                    ".crdownload".to_string(),
                ),
                // TLS trust keys do not fold: carried on an imported row, they still never
                // take effect (the new session's default verification — the tightening
                // direction).
                ("check-certificate".to_string(), "false".to_string()),
                (
                    "ca-certificate".to_string(),
                    "/nonexistent/ca.pem".to_string(),
                ),
            ],
        )
        .unwrap_or_else(|e| panic!("fold: {e}"));
        assert_eq!(
            cfg.checksum.as_deref(),
            Some(format!("sha-256={digest}").as_str()),
            "imported checksum must fold into the persist face (the start of verdict consumption)"
        );
        assert!(
            cfg.remote_time,
            "imported remote-time must fold into the persist face"
        );
        assert_eq!(
            cfg.incomplete_suffix, ".crdownload",
            "the imported suffix must fold into the persist face"
        );
        assert_eq!(
            opts,
            HttpTaskOpts::default(),
            "persist keys never leak into the runtime face"
        );
    }

    /// The import fold rejection face (the defense line rides the parse
    /// single point): a socks proxy (supported by the fork, a declared
    /// limitation of taiji's transport face) and an illegal header line are
    /// explicitly rejected — never silently bypassed/dropped (bypassing = a
    /// proxied task silently leaking direct). Persistence values follow the
    /// same rule: an unsupported checksum algorithm / bad suffix / bad bool
    /// are explicitly rejected — accepting without effect is a fabrication.
    #[test]
    fn fold_imported_options_rejects_invalid_values() {
        let fold = |imported: &[(&str, &str)]| {
            fold_imported_options(
                HttpTaskOpts::default(),
                HttpPersistConfig::default(),
                &imported
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<Vec<_>>(),
            )
        };
        let err = fold(&[("all-proxy", "socks5://127.0.0.1:7891")])
            .err()
            .unwrap_or_else(|| panic!("socks proxy must be rejected"));
        assert!(
            format!("{err}").contains("taiji.option.invalid"),
            "rejection face = taiji.option.invalid: {err}"
        );
        assert!(
            fold(&[("header", "no-colon")]).is_err(),
            "an illegal header line must be rejected"
        );
        // The checksum value domain = the addUri domain: out-of-domain algorithms
        // (sha3-256/md4 — outside the six-hash domain) and odd-length/non-hex
        // digests are rejected the same way.
        for bad in [
            ("sha3-256", "ab".repeat(32)),
            ("md4", "00".to_string()),
            ("sha-256", "abc".to_string()),
            ("sha-256", "zz".repeat(32)),
        ] {
            let err = fold(&[("checksum", &format!("{}={}", bad.0, bad.1))])
                .err()
                .unwrap_or_else(|| panic!("checksum {bad:?} must be rejected"));
            assert!(
                format!("{err}").contains("taiji.option.invalid"),
                "checksum rejection face = taiji.option.invalid: {err}"
            );
        }
        assert!(
            fold(&[("http-incomplete-suffix", "no-dot")]).is_err(),
            "a bad suffix shape must be rejected (IncompleteSuffix::parse's existing domain)"
        );
        assert!(
            fold(&[("remote-time", "yes")]).is_err(),
            "a non-bool value must be rejected (parse_bool_strict's existing domain)"
        );
    }

    /// The fold identity face: an empty/all-blank inventory = the baseline
    /// as-is (zero drift for existing task payloads).
    #[test]
    fn fold_imported_options_empty_inventory_keeps_base() {
        let base = HttpTaskOpts {
            user_agent: Some("session-agent".into()),
            ..HttpTaskOpts::default()
        };
        let cfg_base = HttpPersistConfig {
            incomplete_suffix: ".tail".into(),
            checksum: Some("sha-1=abcd".into()),
            remote_time: true,
            ..HttpPersistConfig::default()
        };
        let (folded, cfg) = fold_imported_options(base.clone(), cfg_base.clone(), &[])
            .unwrap_or_else(|e| panic!("fold: {e}"));
        assert_eq!(folded, base, "an empty inventory = the baseline as-is");
        assert_eq!(
            cfg, cfg_base,
            "an empty inventory = the persist baseline as-is"
        );
        let (blank, cfg_blank) = fold_imported_options(
            base.clone(),
            cfg_base.clone(),
            &[
                ("user-agent".to_string(), "  ".to_string()),
                ("split".to_string(), "2".to_string()),
            ],
        )
        .unwrap_or_else(|e| panic!("fold: {e}"));
        assert_eq!(
            blank, base,
            "an out-of-domain/blank inventory = the baseline as-is"
        );
        assert_eq!(
            cfg_blank, cfg_base,
            "an out-of-domain/blank inventory = the persist baseline as-is"
        );
    }

    /// Domain 2 knob face: https-proxy / referer / http-accept-gzip
    /// runtime slot landing + transport projection (the proxy_https dual
    /// slots, the identity_encoding inversion, the referer request
    /// identity) + value-domain rejection (a socks dedicated slot shares
    /// the all-proxy gate; a bad bool) + fold bits (the request identity
    /// restores with the rows).
    #[test]
    fn d2_https_slot_referer_gzip_slots_and_projection() {
        use super::super::http_task_runtime_options;
        let opts_of = |pairs: &[(&str, &str)]| {
            http_task_runtime_options(
                &pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                &HttpTaskOpts::default(),
            )
            .unwrap_or_else(|e| panic!("opts: {e}"))
        };
        // Three keys, per-slot landing.
        let opts = opts_of(&[
            ("all-proxy", "http://p.test:8080"),
            ("https-proxy", "https://hs.test:8443"),
            ("referer", "  https://ref.example/page  "),
            ("http-accept-gzip", "true"),
        ]);
        assert_eq!(opts.proxy.as_deref(), Some("http://p.test:8080"));
        assert_eq!(opts.proxy_https.as_deref(), Some("https://hs.test:8443"));
        assert_eq!(opts.referer.as_deref(), Some("https://ref.example/page"));
        assert!(opts.accept_gzip);
        // Transport projection: the dedicated slot travels along + the
        // identity inversion (gzip on = no identity header) + default =
        // the identity status quo unchanged.
        let cfg = opts.to_client_config();
        assert_eq!(cfg.proxy_https.as_deref(), Some("https://hs.test:8443"));
        assert_eq!(cfg.proxy.as_deref(), Some("http://p.test:8080"));
        assert!(
            !cfg.identity_encoding,
            "accept_gzip=true must drop the identity header"
        );
        assert!(
            HttpTaskOpts::default().to_client_config().identity_encoding,
            "default = the identity status quo unchanged"
        );
        // Value-domain rejection: a socks dedicated slot (the shared §8.2
        // defense line) and a bad bool.
        let socks = super::super::http_task_runtime_options(
            &[(
                "https-proxy".to_string(),
                "socks5://127.0.0.1:7891".to_string(),
            )]
            .into_iter()
            .collect(),
            &HttpTaskOpts::default(),
        );
        assert!(socks.is_err(), "a socks dedicated slot must be rejected");
        let bad_bool = super::super::http_task_runtime_options(
            &[("http-accept-gzip".to_string(), "yes".to_string())]
                .into_iter()
                .collect(),
            &HttpTaskOpts::default(),
        );
        assert!(bad_bool.is_err(), "a non-bool value must be rejected");
        // Fold bits: https-proxy / referer restore with the imported rows
        // (the request-identity domain).
        let (folded, _) = fold_imported_options(
            HttpTaskOpts::default(),
            HttpPersistConfig::default(),
            &[
                ("https-proxy".to_string(), "http://hs.test:8443".to_string()),
                ("referer".to_string(), "https://ref.example/".to_string()),
            ],
        )
        .unwrap_or_else(|e| panic!("fold: {e}"));
        assert_eq!(folded.proxy_https.as_deref(), Some("http://hs.test:8443"));
        assert_eq!(folded.referer.as_deref(), Some("https://ref.example/"));
    }

    /// The config_json payload round-trip (creation-time persisted items
    /// survive default-value changes).
    #[test]
    fn http_persist_config_round_trip() {
        let cfg = HttpPersistConfig {
            incomplete_suffix: ".crdownload".into(),
            rename_pending: true,
            checksum: Some("sha-256=abcd".into()),
            remote_time: true,
            imported_options: None,
            imported_progress: true,
            origin_fork_key: None,
            concurrency: Some(HttpConcurrencyPersist {
                split: 16,
                max_conn_per_server: 16,
            }),
            // The cap intent round-trips faithfully.
            host_cap: Some(2),
        };
        let json = cfg.to_json();
        let back = HttpPersistConfig::from_json(&json);
        assert_eq!(back.incomplete_suffix, ".crdownload");
        assert!(back.rename_pending);
        assert_eq!(back.checksum.as_deref(), Some("sha-256=abcd"));
        assert!(back.remote_time);
        assert!(
            back.imported_progress,
            "the imported-bitmap flag round-trips faithfully"
        );
        assert_eq!(
            back.concurrency,
            Some(HttpConcurrencyPersist {
                split: 16,
                max_conn_per_server: 16
            }),
            "the concurrency intent face round-trips faithfully"
        );
        assert_eq!(
            back.host_cap,
            Some(2),
            "the cap intent round-trips faithfully"
        );
        // A false flag writes nothing out (zero drift for existing payloads).
        let off = HttpPersistConfig::default();
        assert!(
            !off.to_json().contains("imported_progress"),
            "a false flag writes no bytes: {}",
            off.to_json()
        );
        assert!(
            !off.to_json().contains("concurrency"),
            "a None concurrency face writes no bytes (zero drift on legacy payloads): {}",
            off.to_json()
        );
        assert!(
            !off.to_json().contains("host_cap"),
            "a None cap face writes no bytes (zero drift on legacy payloads): {}",
            off.to_json()
        );
        // Missing fields are backfilled (tolerant restore for old/empty payloads).
        let bare = HttpPersistConfig::from_json("{}");
        assert_eq!(bare.incomplete_suffix, ".part");
        assert!(!bare.rename_pending);
        assert!(bare.checksum.is_none());
        assert!(!bare.remote_time);
        assert!(!bare.imported_progress);
        assert!(
            bare.concurrency.is_none(),
            "a legacy row without a concurrency face = None"
        );
        assert!(
            bare.host_cap.is_none(),
            "a legacy row without a cap intent = None"
        );
    }

    /// Concurrency-intent replay domain clamps: split >= 1; the cap clamps
    /// to the parse face's 1..=16 — out-of-domain disk payloads narrow to
    /// the domain, never amplify (the resume assembly's AIMD start and loop
    /// cap must not exceed the option parse face's value domain).
    #[test]
    fn concurrency_face_replay_clamps_to_parse_domain() {
        let mut opts = HttpTaskOpts::default();
        HttpConcurrencyPersist {
            split: 0,
            max_conn_per_server: 0,
        }
        .apply_to(&mut opts);
        assert_eq!(opts.split, 1);
        assert_eq!(opts.max_conn_per_server, 1);
        HttpConcurrencyPersist {
            split: 5,
            max_conn_per_server: 99,
        }
        .apply_to(&mut opts);
        assert_eq!(opts.split, 5);
        assert_eq!(
            opts.max_conn_per_server, 16,
            "a cap past the ceiling clamps to 16 (same domain as the parse face)"
        );
    }

    /// The `--checksum` completion verdict: pass/mismatch/format and the
    /// scheme value domain (md5 is explicitly refused — not in the
    /// dependency face, never silently admitted).
    #[tokio::test]
    async fn verify_checksum_matrix() {
        let dir = std::env::temp_dir().join(format!("tj-verify-cs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let p = dir.join("blob.bin");
        std::fs::write(&p, [0u8, 1, 2, 3, 250, 251]).unwrap_or_else(|e| panic!("write: {e}"));
        // sha-256("00010203fafb")
        let sha256 = {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update([0u8, 1, 2, 3, 250, 251]);
            hex_lower(&h.finalize())
        };
        let sha1 = {
            use sha1::Digest as _;
            let mut h = sha1::Sha1::new();
            h.update([0u8, 1, 2, 3, 250, 251]);
            hex_lower(&h.finalize())
        };
        assert!(
            verify_checksum(&p, &format!("sha-256={sha256}"))
                .await
                .is_ok()
        );
        // Uppercase hex expectations normalize before comparison.
        assert!(
            verify_checksum(&p, &format!("SHA-256={}", sha256.to_uppercase()))
                .await
                .is_ok()
        );
        assert!(verify_checksum(&p, &format!("sha-1={sha1}")).await.is_ok());
        // Mismatch = Err (the structured ChecksumMismatch: canonical code +
        // expected/got; the numeric face maps through taiji-rpc to 32
        // CHECKSUM_ERROR).
        let Err(mismatch) = verify_checksum(&p, &format!("sha-256={}", "0".repeat(64))).await
        else {
            panic!("mismatch must be Err");
        };
        assert_eq!(
            mismatch.code(),
            "taiji.http.checksum_mismatch",
            "{mismatch}"
        );
        assert!(
            mismatch.to_string().contains("checksum mismatch"),
            "{mismatch}"
        );
        // Scheme domain/format = structured option.invalid (a non-hex digest like
        // "sha-256=zz" is judged a mismatch at this layer — hex validation lives
        // in the creation-time `validate_checksum_value`, the two layers have
        // separate domains and do not repeat; in-domain six-hash algorithms are no
        // longer part of the value-domain rejection face — good/bad digests see
        // the next test).
        // `verify_checksum_six_hash_matrix`).
        for bad in ["sha3-256=0123", "md4=00", "nodelimiter"] {
            let Err(e) = verify_checksum(&p, bad).await else {
                panic!("{bad} must be rejected");
            };
            assert_eq!(e.code(), "taiji.option.invalid", "{bad}: {e}");
        }
        let Err(non_hex) = verify_checksum(&p, "sha-256=zz").await else {
            panic!("non-hex digest must not verify");
        };
        assert_eq!(non_hex.code(), "taiji.http.checksum_mismatch", "{non_hex}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The widened domain: the `--checksum` six-hash algorithm domain
    /// (md5/sha-1/sha-224/sha-256/sha-384/sha-512) algorithm by algorithm —
    /// a good digest passes, a bad digest = the structured
    /// `taiji.http.checksum_mismatch` (the md5 vector = RFC 1321 A.5 test
    /// suite's "foo" row; the SHA family = the FIPS 180-4 vectors).
    #[tokio::test]
    async fn verify_checksum_six_hash_matrix() {
        let dir = std::env::temp_dir().join(format!("tj-verify-cs6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let p = dir.join("foo.bin");
        std::fs::write(&p, b"foo").unwrap_or_else(|e| panic!("write: {e}"));
        let cases: &[(&str, &str)] = &[
            ("md5", "acbd18db4cc2f85cedef654fccc4a4d8"),
            ("sha-1", "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"),
            (
                "sha-224",
                "0808f64e60d58979fcb676c96ec938270dea42445aeefcd3a4e6f8db",
            ),
            (
                "sha-256",
                "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            ),
            (
                "sha-384",
                "98c11ffdfdd540676b1a137cb1a22b2a70350c9a44171d6b1180c6be5cbb2ee\
                 3f79d532c8a1dd9ef2e8e08e752a3babb",
            ),
            (
                "sha-512",
                "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326\
                 e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7",
            ),
        ];
        for (scheme, good) in cases {
            let ok = verify_checksum(&p, &format!("{scheme}={good}")).await;
            assert!(ok.is_ok(), "{scheme} good digest must pass: {ok:?}");
            // A bad digest (same length, all 'a'): mismatch = the structured mismatch
            // error (not a value-domain rejection).
            let wrong = "a".repeat(good.len());
            let verdict = verify_checksum(&p, &format!("{scheme}={wrong}")).await;
            let Err(e) = verdict else {
                panic!("{scheme} bad digest must mismatch");
            };
            assert_eq!(
                e.code(),
                "taiji.http.checksum_mismatch",
                "{scheme} mismatch error code: {e}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Disk rollback for a degraded-path verification mismatch (never leave
    /// a corrupt final file): the final file returns to `.part` (the main
    /// form); when returning is impossible (the final file no longer
    /// exists — the deletion path) there is no panic. Idempotence: content
    /// already at the part location does not block the rollback rename
    /// (posix replacement semantics).
    #[tokio::test]
    async fn rollback_final_file_restores_part() {
        let dir = std::env::temp_dir().join(format!("tj-rollback-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let part = dir.join("blob.bin.part");
        let final_path = dir.join("blob.bin");
        std::fs::write(&final_path, b"verified-against-wrong-digest")
            .unwrap_or_else(|e| panic!("write: {e}"));

        rollback_final_file(&part, &final_path).await;
        assert!(!final_path.exists(), "the final file must roll back");
        assert!(
            part.exists(),
            "data stays on disk as `.part` for inspection"
        );
        assert_eq!(
            std::fs::read(&part).unwrap_or_else(|e| panic!("read: {e}")),
            b"verified-against-wrong-digest"
        );

        // Rolling back again (the final file missing): the rename fails -> the
        // remove fallback also does not panic (a defensive idempotence face).
        rollback_final_file(&part, &final_path).await;
        assert!(!final_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The disk sink write-path feed: inject an isolated registry ->
    /// [`HttpGridSink::write_at`] counts attempts + bytes + the in-flight
    /// pair restores (the gauge returns to zero once the write completes);
    /// disk content and the call face are unchanged (a read-only counting
    /// seam).
    #[tokio::test]
    async fn grid_sink_write_at_feeds_disk_metrics() {
        use taiji_http::partfile::{FileAllocation, PartOpenPolicy};

        let dir = std::env::temp_dir().join(format!(
            "tj-sink-metrics-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let part_path = dir.join("s.bin.part");
        let part = taiji_http::partfile::PartFile::open(
            part_path.clone(),
            Some(4096),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open: {e}"));

        let registry = Arc::new(taiji_io::metrics::MetricsRegistry::new());
        let row = HttpTaskRow {
            gid: "8000000000000700".into(),
            url: "http://origin/s.bin".into(),
            final_url: "http://origin/s.bin".into(),
            mirrors_json: None,
            state: "downloading".into(),
            queue_pos: 0,
            dir: dir.display().to_string(),
            out: "s.bin".into(),
            config_json: "{}".into(),
            probe_json: None,
            validator_digest: None,
            block_size: 256 * 1024,
            block_bitmap: None,
            block_count: Some(1),
            total_done: 0,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        };
        let pipeline = Arc::new(AsyncMutex::new(
            HttpSnapshotPipeline::new(
                row,
                Some(4096),
                Arc::new(PartFileSync::new(part_path.clone())),
            )
            .unwrap_or_else(|e| panic!("pipeline: {e}")),
        ));
        let sink = HttpGridSink {
            file: FileSink::new(part.clone()),
            pipeline,
            live: Arc::new(HttpLive::new(&["http://origin/s.bin".to_string()])),
            prefetch: None,
            metrics: Arc::clone(&registry),
        };

        let zero = registry.disk().snapshot();
        assert_eq!(zero.sink_writes_total, 0, "honest zero baseline");
        assert_eq!(zero.sink_inflight, 0);

        let seg = SegId {
            source: 0,
            extent: 0,
        };
        sink.write_at(seg, 0, Bytes::from(vec![0xAB; 4096]))
            .await
            .unwrap_or_else(|e| panic!("write_at: {e}"));

        let s = registry.disk().snapshot();
        assert_eq!(s.sink_writes_total, 1, "disk-face write count");
        assert_eq!(
            s.sink_writes_bytes_total, 4096,
            "bytes counted with each write"
        );
        assert_eq!(
            s.sink_inflight, 0,
            "in-flight returns after the write completes (guard drop)"
        );
        assert_eq!(
            std::fs::read(&part_path).unwrap_or_else(|e| panic!("read: {e}")),
            vec![0xAB; 4096],
            "zero change in write-path behavior"
        );

        let _ = part.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------- the stall-steal worker-side execution loop ----------------

    use std::collections::{BTreeMap, BTreeSet};
    use tokio::net::TcpListener;

    /// In-process mock origin (tokio async; zero material threads in this
    /// process): 206 + full `Content-Range` shapes + keep-alive. `stall_at`
    /// = a BLOCK-BOUNDARY HANG POINT: the response body stops after writing
    /// to k (requests starting at >= k get no response — the client-side
    /// fetch hangs on the response head/reads with the socket held open),
    /// the slow-tail/stall injection fixture; `None` = a healthy source.
    /// Byte content is all zeros (this fixture's verdict face is scheduling
    /// bookkeeping, not content comparison).
    async fn spawn_origin(stall_at: Option<u64>, total: u64) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind origin: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr: {e}"));
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    loop {
                        // Read one request head (\r\n\r\n delimited; GET has no body).
                        let head = loop {
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                let taken: Vec<u8> = buf.drain(..pos + 4).collect();
                                break String::from_utf8_lossy(&taken).into_owned();
                            }
                            let mut chunk = [0u8; 4096];
                            match sock.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let range = head.to_ascii_lowercase().split("\r\n").find_map(|l| {
                            l.strip_prefix("range: bytes=").and_then(|v| {
                                let (s, e) = v.trim().split_once('-')?;
                                Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                            })
                        });
                        let Some((s, e)) = range else {
                            let _ = sock
                                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                                .await;
                            return;
                        };
                        if s == 0 && e == 0 {
                            // The probe shape (the worker face never sends it; a defensive
                            // response).
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes 0-0/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Content-Length: 1\r\n\r\n"
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                            let _ = sock.write_all(&[0u8]).await;
                            continue;
                        }
                        if let Some(k) = stall_at
                            && s >= k
                        {
                            // A start past the hang point: no response — the fetch hangs on the
                            // response head (stall injection, the zero-byte form).
                            std::future::pending::<()>().await;
                        }
                        let end = e.min(total.saturating_sub(1));
                        // The hang rule: the serve cap = min(end+1, stall_at) — the body stops at
                        // the block boundary (the hanging block unwritten), so the last_acked
                        // watermark = the block before the boundary.
                        let serve_end = match stall_at {
                            Some(k) => (end + 1).min(k),
                            None => end + 1,
                        };
                        // Content-Length reports the FULL range length (a hanging body = writes
                        // stop inside the announced length — the client side then truly hangs on
                        // reads; announcing the actually-written bytes would make the client see a
                        // complete short body -> the failure-retry path instead of a stall).
                        let resp = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Range: bytes {s}-{end}/{total}\r\n\
                             Accept-Ranges: bytes\r\n\
                             Content-Length: {}\r\n\r\n",
                            end + 1 - s
                        );
                        if sock.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                        let chunk_buf = vec![0u8; 64 * 1024];
                        let mut off = s;
                        while off < serve_end {
                            let n = (chunk_buf.len() as u64).min(serve_end - off) as usize;
                            if sock.write_all(&chunk_buf[..n]).await.is_err() {
                                return;
                            }
                            off += n as u64;
                        }
                        if serve_end <= end {
                            // Block-boundary hang: the body stops unfinished (the socket
                            // is held — the fetch hangs on reads; stall evidence starts
                            // counting here).
                            std::future::pending::<()>().await;
                        }
                    }
                });
            }
        });
        format!("http://{addr}")
    }

    /// The steal-invariant observation sink: records the writer set per block
    /// (overlap = a block written by >= 2 sources) plus the decision face's
    /// booking order (sink.complete_block is called only by the single
    /// decision point's first record — the exactly-once bookkeeping verdict
    /// face).
    struct StealWatchSink {
        bs: u64,
        live: Arc<HttpLive>,
        writers: StdMutex<BTreeMap<u64, BTreeSet<u32>>>,
        completions: StdMutex<Vec<u64>>,
    }

    impl StealWatchSink {
        fn overlap_blocks(&self) -> Vec<u64> {
            self.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(_, srcs)| srcs.len() > 1)
                .map(|(b, _)| *b)
                .collect()
        }

        fn completions_sorted(&self) -> Vec<u64> {
            let mut c = self
                .completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            c.sort_unstable();
            c
        }

        /// Writer snapshot (diagnostic face: `block -> writer source set`).
        fn writers_snapshot(&self) -> Vec<(u64, Vec<u32>)> {
            self.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|(b, srcs)| (*b, srcs.iter().copied().collect()))
                .collect()
        }
    }

    impl SegmentSink for StealWatchSink {
        fn write_at(
            &self,
            seg: SegId,
            off: u64,
            bytes: Bytes,
        ) -> Pin<Box<dyn Future<Output = HttpResult<()>> + Send + '_>> {
            let n = bytes.len() as u64;
            self.live.stall.note(n);
            self.live.note_source_written(seg.source, n);
            self.writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(off / self.bs)
                .or_default()
                .insert(seg.source);
            Box::pin(std::future::ready(Ok(())))
        }

        fn complete_block(
            &self,
            block: u64,
        ) -> Pin<Box<dyn Future<Output = HttpResult<()>> + Send + '_>> {
            self.completions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(block);
            self.live.blocks_done.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// The real-connection steal-grant e2e (the slow-tail scene): source 0
    /// stalls at a block boundary (the body hangs once it writes to stall_at),
    /// source 1 is healthy and drains the pool early -> the park branch
    /// requests a steal -> the single decision point grants
    /// `[last_acked+1, extent end)` -> the stealer takes over and finishes the
    /// tail while the watchdog's tick cancels the victim's hanging fetch.
    /// Assertions: `stolen_total > 0` (runtime stats), zero sink write-interval
    /// overlap (the invariant re-checked), exactly-once bookkeeping across the
    /// whole grid, and the hung worker aborted by the watchdog (the worker
    /// pool can close out — the finish is never blocked by a hung connection).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stall_steal_grant_real_connection_slow_tail() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
        let bs = MIN_BLOCK_SIZE;
        let blocks = 24u64;
        let total = blocks * bs;
        let stall_at = 2 * bs; // the block-boundary hang point (an early large extent spans it)
        // The decision window >= several heartbeat periods (isomorphic to the
        // production domain): the victim's growth heartbeat is booked first (a
        // real last_acked watermark), so the grant start lands on the hanging
        // block.
        let window = Duration::from_millis(2500);
        let stall_url = spawn_origin(Some(stall_at), total).await;
        let fast_url = spawn_origin(None, total).await;

        let gid = "8000000000003304";
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = GuidedPlan::build(
            total,
            &GuidedConfig {
                block_size: bs,
                max_chunk: 8 * bs,
            },
            &|b| grid.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let uris = vec![stall_url.clone(), fast_url.clone()];
        let live = Arc::new(HttpLive::new(&uris));
        live.total_len.store(total, Ordering::Relaxed);
        live.blocks_total.store(blocks, Ordering::Relaxed);

        let watch = Arc::new(StealWatchSink {
            bs,
            live: Arc::clone(&live),
            writers: StdMutex::new(BTreeMap::new()),
            completions: StdMutex::new(Vec::new()),
        });
        let throttled: Arc<dyn SegmentSink> = Arc::clone(&watch) as Arc<dyn SegmentSink>;

        // Multi-source assembly (2 sources); AIMD cap 1 (exactly one worker per
        // source — the steal's main arena = inter-source tail takeover).
        let (coord, actor) = coordinator::spawn_dynamic_multi(
            gid,
            grid,
            plan,
            Arc::clone(&throttled),
            2,
            window,
            AimdConfig::new(1),
            2,
        );
        let coord = Arc::new(coord);

        let opts = HttpTaskOpts {
            stall_window: window,
            ..HttpTaskOpts::default()
        };
        let wopts = opts.worker_opts();
        let pool = Arc::new(taiji_http::pool::WorkerPool::new(2, 1));
        let fatal = Arc::new(StdMutex::new(None));
        let rig = WorkerRig {
            gid: gid.to_string(),
            http_metrics: Arc::new(taiji_io::metrics::MetricsRegistry::new()),
            client: HttpClient::new(opts.to_client_config())
                .unwrap_or_else(|e| panic!("client: {e}")),
            // The test form uses no jump-off face (the owner URI has no correspondence
            // with the authoritative converged face).
            authoritative_final: None,
            telemetry: Arc::new(LiveTelemetry(Arc::clone(&live))),
            per_host: HostCap::new(32),
            pool: Arc::clone(&pool),
            token: CancellationToken::new(),
            total_len: total,
            bs,
            count: blocks,
            ftp_cfg: opts.to_ftp_config(),
            base_ctx: RequestCtx::default(),
            fatal: Arc::clone(&fatal),
            steal: true,
        };
        let sources = vec![
            taiji_segment::traits::PlanSource {
                uri: stall_url,
                kind: TransportKind::Http,
            },
            taiji_segment::traits::PlanSource {
                uri: fast_url,
                kind: TransportKind::Http,
            },
        ];
        let mut worker_set = JoinSet::new();
        for src in 0..2usize {
            launch_worker(
                &rig,
                coord.as_ref(),
                &throttled,
                &mut worker_set,
                src,
                &sources,
                &wopts,
                None,
            );
            pool.note_spawn(src as u32, 1);
        }

        // All workers close out (the victim's hung fetch must be aborted by the
        // steal's cancellation — a hang that never exits fails this timeout: the
        // watchdog's e2e evidence).
        let drain = async {
            while let Some(r) = worker_set.join_next().await {
                r.unwrap_or_else(|e| panic!("worker join: {e}"));
            }
        };
        tokio::time::timeout(Duration::from_secs(60), drain)
            .await
            .unwrap_or_else(|_| panic!("workers must drain; hung fetch was not aborted"));

        // The verdict re-check (while the handle is alive — runtime stats are
        // queried before close-out).
        let stats = coord
            .runtime_stats()
            .await
            .unwrap_or_else(|e| panic!("stats: {e}"));
        assert!(
            stats.steals_granted >= 1,
            "stolen_total must be > 0 (slow-tail steal): {stats:?}; \
             completions={:?} writers={:?}",
            watch.completions_sorted(),
            watch.writers_snapshot()
        );
        assert!(
            watch.overlap_blocks().is_empty(),
            "sink write-range overlap must be 0: {:?}",
            watch.overlap_blocks()
        );
        assert_eq!(
            watch.completions_sorted(),
            (0..blocks).collect::<Vec<u64>>(),
            "the whole grid settles exactly once (first writer wins; no misses, no duplicates)"
        );
        assert!(
            crate::lock(&fatal).is_none(),
            "this fixture has no fatal face (no source elimination / protocol / restart)"
        );

        drop(coord);
        let outcome = tokio::time::timeout(Duration::from_secs(15), actor)
            .await
            .unwrap_or_else(|_| panic!("actor join timeout"))
            .unwrap_or_else(|e| panic!("actor join: {e}"));
        outcome.unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// Parked workers yield the per-host permit: on the same host with cap
    /// = 1, a parked worker (the pool is empty, waiting for allocation) must
    /// not hold the slot — another task's new connection (the same HostCap
    /// registry) can acquire the permit and finish its transfer within the
    /// parked window. Holding the slot for the worker's whole life would
    /// let one parked task squeeze out all of another task's concurrency
    /// on the same host — this test pins that.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parked_worker_does_not_hog_per_host_permit() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
        let bs = MIN_BLOCK_SIZE;
        let window = Duration::from_millis(2500);
        // Shared origin (the total length follows B's grid; A transfers nothing —
        // the parked form has no fetch).
        let total_b = 2 * bs;
        let url = spawn_origin(None, total_b).await;
        let Some(host) = HostCap::host_key(&url) else {
            panic!("host key");
        };
        let fatal = Arc::new(StdMutex::new(None));
        // A cross-task shared registry (the cap scope is engine-global): cap 1 —
        // whether A holds the slot while parked is observably felt by B.
        let per_host = HostCap::new(1);
        let opts = HttpTaskOpts {
            stall_window: window,
            ..HttpTaskOpts::default()
        };
        let wopts = opts.worker_opts();
        let client =
            HttpClient::new(opts.to_client_config()).unwrap_or_else(|e| panic!("client: {e}"));
        let sources = vec![taiji_segment::traits::PlanSource {
            uri: url.clone(),
            kind: TransportKind::Http,
        }];

        // Task A: the parked form with a momentarily drained pool — the pool's
        // single block is pre-acquired in flight by the test face (never
        // completed), so the worker's acquire -> None -> parked re-poll.
        let grid_a = BlockGrid::new(bs, bs).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan_a = GuidedPlan::build(
            bs,
            &GuidedConfig {
                block_size: bs,
                max_chunk: bs,
            },
            &|b| grid_a.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let throttled_a: Arc<dyn SegmentSink> = Arc::new(NullSink);
        let (coord_a, actor_a) = coordinator::spawn_dynamic_multi(
            "8000000000003401",
            grid_a,
            plan_a,
            Arc::clone(&throttled_a),
            1,
            window,
            AimdConfig::new(1),
            1,
        );
        let held = coord_a
            .acquire(0)
            .await
            .unwrap_or_else(|e| panic!("pre-acquire: {e}"))
            .unwrap_or_else(|| panic!("pre-acquire alloc"));
        let _ = held.extent.len;
        let live_a = Arc::new(HttpLive::new(std::slice::from_ref(&url)));
        live_a.total_len.store(bs, Ordering::Relaxed);
        live_a.blocks_total.store(1, Ordering::Relaxed);
        let pool_a = Arc::new(taiji_http::pool::WorkerPool::new(1, 1));
        let token_a = CancellationToken::new();
        let rig_a = WorkerRig {
            gid: "8000000000003401".to_string(),
            http_metrics: Arc::new(taiji_io::metrics::MetricsRegistry::new()),
            client: client.clone(),
            authoritative_final: None,
            telemetry: Arc::new(LiveTelemetry(Arc::clone(&live_a))),
            per_host: per_host.clone(),
            pool: Arc::clone(&pool_a),
            token: token_a.clone(),
            total_len: bs,
            bs,
            count: 1,
            ftp_cfg: opts.to_ftp_config(),
            base_ctx: RequestCtx::default(),
            fatal: Arc::clone(&fatal),
            steal: true,
        };
        let mut set_a = JoinSet::new();
        launch_worker(
            &rig_a,
            &coord_a,
            &throttled_a,
            &mut set_a,
            0,
            &sources,
            &wopts,
            None,
        );
        pool_a.note_spawn(0, 1);
        // The parked-in-place window: A has finished the claim -> acquire(None) ->
        // parked re-poll chain (a coordinator round trip is sub-millisecond; 300ms
        // of margin).
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Task B: a healthy pool — another task's new connection to the same host
        // must be able to acquire the permit and complete the whole grid within
        // the parked window (holding the slot through the park would starve it
        // behind A's permit).
        let grid_b = BlockGrid::new(bs, total_b).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan_b = GuidedPlan::build(
            total_b,
            &GuidedConfig {
                block_size: bs,
                max_chunk: 8 * bs,
            },
            &|b| grid_b.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let live_b = Arc::new(HttpLive::new(std::slice::from_ref(&url)));
        live_b.total_len.store(total_b, Ordering::Relaxed);
        live_b.blocks_total.store(2, Ordering::Relaxed);
        let watch_b = Arc::new(StealWatchSink {
            bs,
            live: Arc::clone(&live_b),
            writers: StdMutex::new(BTreeMap::new()),
            completions: StdMutex::new(Vec::new()),
        });
        let throttled_b: Arc<dyn SegmentSink> = Arc::clone(&watch_b) as Arc<dyn SegmentSink>;
        let (coord_b, actor_b) = coordinator::spawn_dynamic_multi(
            "8000000000003402",
            grid_b,
            plan_b,
            Arc::clone(&throttled_b),
            1,
            window,
            AimdConfig::new(1),
            1,
        );
        let coord_b = Arc::new(coord_b);
        let pool_b = Arc::new(taiji_http::pool::WorkerPool::new(1, 1));
        let token_b = CancellationToken::new();
        let rig_b = WorkerRig {
            gid: "8000000000003402".to_string(),
            http_metrics: Arc::new(taiji_io::metrics::MetricsRegistry::new()),
            client,
            authoritative_final: None,
            telemetry: Arc::new(LiveTelemetry(Arc::clone(&live_b))),
            per_host,
            pool: Arc::clone(&pool_b),
            token: token_b.clone(),
            total_len: total_b,
            bs,
            count: 2,
            ftp_cfg: opts.to_ftp_config(),
            base_ctx: RequestCtx::default(),
            fatal,
            steal: true,
        };
        let mut set_b = JoinSet::new();
        launch_worker(
            &rig_b,
            coord_b.as_ref(),
            &throttled_b,
            &mut set_b,
            0,
            &sources,
            &wopts,
            None,
        );
        pool_b.note_spawn(0, 1);

        // The concurrency verdict: B books the whole grid while A is parked (a
        // timeout = B was squeezed out by the held slot — the parked-worker-holds-
        // slot regression).
        let drain_b = async {
            while let Some(r) = set_b.join_next().await {
                r.unwrap_or_else(|e| panic!("worker b join: {e}"));
            }
        };
        tokio::time::timeout(Duration::from_secs(15), drain_b)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "task B starved while A parked: parked worker hogged the \
                     per-host permit (host={host})"
                )
            });
        assert_eq!(
            watch_b.completions_sorted(),
            vec![0, 1],
            "B settles the whole grid exactly once (evidence A's residence occupies no slot)"
        );

        // Close-out: join everything after A's parked loop is revoked (token).
        token_a.cancel();
        while let Some(r) = set_a.join_next().await {
            r.unwrap_or_else(|e| panic!("worker a join: {e}"));
        }
        drop(coord_a);
        drop(coord_b);
        for (label, actor) in [("a", actor_a), ("b", actor_b)] {
            let outcome = tokio::time::timeout(Duration::from_secs(15), actor)
                .await
                .unwrap_or_else(|_| panic!("actor {label} join timeout"));
            outcome
                .unwrap_or_else(|e| panic!("actor {label} join: {e}"))
                .unwrap_or_else(|e| panic!("actor {label}: {e}"));
        }
    }

    /// RST injection modes (the connect-phase and steady-state forms).
    #[derive(Clone, Copy)]
    enum RstMode {
        /// Connect phase: RST with zero response — the first-wave connect race
        /// blowing through the accept queue; the fetch fails before the response
        /// head (zero bytes).
        ConnectPhase,
        /// Steady state: a 206 head + `k` bytes of body then RST — a mid-transfer
        /// interruption (the client side already has bytes on disk).
        MidBody(u64),
    }

    /// The RST-injection origin (tokio async): the disconnect goes through
    /// SO_LINGER 0 + close — the kernel sends RST instead of FIN, so the
    /// client-side transport sees the "connection reset" signature (the e2e
    /// face of the [`CongestionKind::Reset`] multiplicative-decrease wiring).
    async fn spawn_rst_origin(mode: RstMode, total: u64) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind origin: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr: {e}"));
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut sock = sock;
                    if matches!(mode, RstMode::ConnectPhase) {
                        let Ok(s) = sock.into_std() else {
                            return;
                        };
                        // SO_LINGER 0 (std has no such sockopt face; it goes through socket2's
                        // safe wrapper): close = RST (not FIN).
                        let _ = socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO));
                        drop(s); // RST (not FIN)
                        return;
                    }
                    // Read one request head (\r\n\r\n delimited; GET has no body).
                    let mut buf: Vec<u8> = Vec::new();
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let taken: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&taken).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let Some(range) = head.to_ascii_lowercase().split("\r\n").find_map(|l| {
                        l.strip_prefix("range: bytes=").and_then(|v| {
                            let (s, e) = v.trim().split_once('-')?;
                            Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                        })
                    }) else {
                        return;
                    };
                    let (s, e) = range;
                    let end = e.min(total.saturating_sub(1));
                    // Content-Length reports the full range length (only then does the RST
                    // count as a "body interruption" rather than a complete short body).
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Range: bytes {s}-{end}/{total}\r\n\
                         Accept-Ranges: bytes\r\n\
                         Content-Length: {}\r\n\r\n",
                        end + 1 - s
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    let RstMode::MidBody(k) = mode else {
                        return;
                    };
                    // A partial body (never past the extent edge — more would hit the overrun
                    // check instead of the RST); a grace window lets the written bytes arrive
                    // and land, then the RST.
                    let serve = k.min(end + 1 - s);
                    let body = vec![0u8; 32 * 1024];
                    let mut off = 0u64;
                    while off < serve {
                        let n = (body.len() as u64).min(serve - off) as usize;
                        if sock.write_all(&body[..n]).await.is_err() {
                            return;
                        }
                        off += n as u64;
                    }
                    let _ = sock.flush().await;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let Ok(st) = sock.into_std() else {
                        return;
                    };
                    let _ = socket2::SockRef::from(&st).set_linger(Some(Duration::ZERO));
                    drop(st); // RST (not FIN)
                });
            }
        });
        format!("http://{addr}")
    }

    /// The budgeted RST origin (the loss-face recovery-ramp e2e fixture): the
    /// first `rst_budget` range requests take the [`RstMode::MidBody`] form (a
    /// 206 head + a body of `serve` bytes then an SO_LINGER 0 RST — a
    /// steady-state mid-transfer interruption, the decrease trigger face);
    /// everything after is served healthy (full bodies + keep-alive).
    /// Deterministic injection dose: exactly `rst_budget` steady-state RSTs,
    /// so retries necessarily succeed (the precondition for observing the
    /// recovery path).
    async fn spawn_rst_budget_origin(
        rst_budget: u32,
        serve_cap: u64,
        total: u64,
        chunk_delay: Duration,
    ) -> String {
        use std::sync::Arc as SharedBudget;
        use std::sync::atomic::AtomicU32 as Budget;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind origin: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr origin: {e}"));
        let budget = SharedBudget::new(Budget::new(rst_budget));
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let budget = SharedBudget::clone(&budget);
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    loop {
                        let head = loop {
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                let taken: Vec<u8> = buf.drain(..pos + 4).collect();
                                break String::from_utf8_lossy(&taken).into_owned();
                            }
                            let mut chunk = [0u8; 4096];
                            match sock.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let Some(range) = head.to_ascii_lowercase().split("\r\n").find_map(|l| {
                            l.strip_prefix("range: bytes=").and_then(|v| {
                                let (s, e) = v.trim().split_once('-')?;
                                Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                            })
                        }) else {
                            return;
                        };
                        let (s, e) = range;
                        let end = e.min(total.saturating_sub(1));
                        let resp = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Range: bytes {s}-{end}/{total}\r\n\
                             Accept-Ranges: bytes\r\n\
                             Content-Length: {}\r\n\r\n",
                            end + 1 - s
                        );
                        if sock.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                        let do_rst = budget
                            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| b.checked_sub(1))
                            .is_ok();
                        // An RST request's body cap = half the requested interval (clamped to
                        // <= serve_cap, >= 1 byte) — always smaller than the full body: the RST
                        // necessarily lands inside an in-flight request's body (the steady-state
                        // form). Truncating at a fixed byte count would serve guided sub-block
                        // leases smaller than that count COMPLETELY, the RST would land while the
                        // connection is idle -> a dead-pooled-connection reuse failure of 0 bytes
                        // on the client (the connect-phase form) -> the decrease never triggers
                        // (the flake root cause).
                        let serve_end = if do_rst {
                            s + ((end + 1 - s) / 2).clamp(1, serve_cap.max(1))
                        } else {
                            end + 1
                        };
                        let body = vec![0u8; 64 * 1024];
                        let mut off = s;
                        while off < serve_end {
                            let n = (body.len() as u64).min(serve_end - off) as usize;
                            if sock.write_all(&body[..n]).await.is_err() {
                                return;
                            }
                            off += n as u64;
                            // The slow-source cadence (keeps the write stream alive for the healthy
                            // e2e: if blocks finish instantly the gain window never closes — the
                            // AIMD growth face is unobservable).
                            if !chunk_delay.is_zero() {
                                tokio::time::sleep(chunk_delay).await;
                            }
                        }
                        let _ = sock.flush().await;
                        if do_rst {
                            // The grace window lets the written bytes arrive and land
                            // (written_bytes > 0 = the steady-state criterion), then the RST. The
                            // wait is a safety margin for client read-side scheduling under
                            // concurrent test load (too short loses the steady-state criterion and
                            // the decrease never triggers).
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            let Ok(st) = sock.into_std() else {
                                return;
                            };
                            let _ = socket2::SockRef::from(&st).set_linger(Some(Duration::ZERO));
                            drop(st); // RST (not FIN)
                            return;
                        }
                    }
                });
            }
        });
        format!("http://{addr}")
    }

    /// The positive case for the Reset multiplicative decrease: a steady-state
    /// mid-transfer interruption (an RST inside the body; this extent already
    /// has bytes on disk) -> classified as [`CongestionKind::Reset`], reported
    /// through the coordinator -> that source's AIMD connection count
    /// decreases multiplicatively (start 2 -> max(1, floor(2*3/4)) = 1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mid_transfer_reset_triggers_aimd_decrease() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
        let bs = MIN_BLOCK_SIZE;
        let total = bs;
        let url = spawn_rst_origin(RstMode::MidBody(128 * 1024), total).await;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = GuidedPlan::build(
            total,
            &GuidedConfig {
                block_size: bs,
                max_chunk: bs,
            },
            &|b| grid.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        // The bookkeeping observation sink (NullSink-shaped + a block-completion
        // counter — the direct reading of the all-watermarks-full decision; block
        // bookkeeping reaches the sink only through the coordinator's single
        // decision entry).
        struct ProbeSink {
            completions: AtomicU64,
        }
        impl taiji_segment::traits::SegmentSink for ProbeSink {
            fn write_at(
                &self,
                _seg: taiji_segment::traits::SegId,
                _off: u64,
                _bytes: Bytes,
            ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>>
            {
                Box::pin(std::future::ready(Ok(())))
            }
            fn complete_block(
                &self,
                _block: u64,
            ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>>
            {
                self.completions.fetch_add(1, Ordering::Relaxed);
                Box::pin(std::future::ready(Ok(())))
            }
        }
        let probe = Arc::new(ProbeSink {
            completions: AtomicU64::new(0),
        });
        let throttled: Arc<dyn SegmentSink> = Arc::clone(&probe) as Arc<dyn SegmentSink>;
        let (coord, actor) = coordinator::spawn_dynamic_multi(
            "8000000000003501",
            grid,
            plan,
            Arc::clone(&throttled),
            1,
            Duration::from_secs(15),
            AimdConfig::new(2),
            1,
        );
        let live = Arc::new(HttpLive::new(std::slice::from_ref(&url)));
        live.total_len.store(total, Ordering::Relaxed);
        live.blocks_total.store(1, Ordering::Relaxed);
        let pool = Arc::new(taiji_http::pool::WorkerPool::new(1, 1));
        let token = CancellationToken::new();
        let fatal = Arc::new(StdMutex::new(None));
        let opts = HttpTaskOpts::default();
        let wopts = opts.worker_opts();
        let rig = WorkerRig {
            gid: "8000000000003501".to_string(),
            http_metrics: Arc::new(taiji_io::metrics::MetricsRegistry::new()),
            client: HttpClient::new(opts.to_client_config())
                .unwrap_or_else(|e| panic!("client: {e}")),
            // The test form uses no jump-off face (the owner URI has no correspondence
            // with the authoritative converged face).
            authoritative_final: None,
            telemetry: Arc::new(LiveTelemetry(Arc::clone(&live))),
            per_host: HostCap::new(32),
            pool: Arc::clone(&pool),
            token: token.clone(),
            total_len: total,
            bs,
            count: 1,
            ftp_cfg: opts.to_ftp_config(),
            base_ctx: RequestCtx::default(),
            fatal,
            steal: true,
        };
        let sources = vec![taiji_segment::traits::PlanSource {
            uri: url,
            kind: TransportKind::Http,
        }];
        let mut set = JoinSet::new();
        launch_worker(
            &rig, &coord, &throttled, &mut set, 0, &sources, &wopts, None,
        );
        pool.note_spawn(0, 1);
        // The first steady-state RST already decreases (2 -> 1) and retries have
        // nothing left to decrease (the floor is 1) — poll the AIMD snapshot until
        // the decrease lands. Sub-block lease semantics: a follow-up lease after
        // the mid-body RST failure (a guided half pool, <=128KiB, <= the RST
        // truncation point) can fully drain the truncated response body — the
        // failure-retry loop no longer necessarily walks to the failure cap, and
        // the task closes out via block completion (this test asserts both facts:
        // block completion + the decrease).
        let mut snap = Vec::new();
        for _ in 0..100u32 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            snap = coord
                .aimd_snapshot()
                .await
                .unwrap_or_else(|e| panic!("snapshot: {e}"));
            if snap == vec![(0, 1)] {
                break;
            }
        }
        assert_eq!(
            snap,
            vec![(0, 1)],
            "a steady-state mid-transfer abort must trigger the Reset decrease (start 2 -> 1)"
        );
        // The sub-block follow-up lease: the next cut after the failure (a guided
        // half pool, up to the Content-Length complete body at the RST truncation
        // point) fills the block's byte watermark segment by segment — closing out
        // via block completion (watermarks all full -> the single decision -> the
        // persistence sink books it; polled until it lands).
        let mut done = 0u64;
        for _ in 0..150u32 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            done = probe.completions.load(Ordering::Relaxed);
            if done >= 1 {
                break;
            }
        }
        assert_eq!(
            done, 1,
            "the r7.0 sub-block follow-up lease absorbs the mid-body RST: the block's byte \
             watermark fills fully -> block-completion booking"
        );
        // Close-out: the pool token cancels (production drives the same face from
        // the completion verdict) and all workers exit.
        token.cancel();
        let drain = async {
            while let Some(r) = set.join_next().await {
                r.unwrap_or_else(|e| panic!("worker join: {e}"));
            }
        };
        tokio::time::timeout(Duration::from_secs(30), drain)
            .await
            .unwrap_or_else(|_| panic!("worker must exit after cancel"));
        drop(coord);
        let outcome = tokio::time::timeout(Duration::from_secs(15), actor)
            .await
            .unwrap_or_else(|_| panic!("actor join timeout"));
        outcome
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The negative case for the Reset wiring (the phase discrimination): a
    /// connect-phase RST (failure before the response head, zero bytes) must
    /// not trigger the decrease — first-wave connect races are ramp-phase
    /// noise handled by the existing failure retries + the first-wave stagger
    /// ramp; a decrease triggered by them would knock the AIMD growth ramp
    /// back (the slow-start amortization loss would return).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_phase_reset_does_not_trigger_aimd_decrease() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
        let bs = MIN_BLOCK_SIZE;
        let total = bs;
        let url = spawn_rst_origin(RstMode::ConnectPhase, total).await;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = GuidedPlan::build(
            total,
            &GuidedConfig {
                block_size: bs,
                max_chunk: bs,
            },
            &|b| grid.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let throttled: Arc<dyn SegmentSink> = Arc::new(NullSink);
        let (coord, actor) = coordinator::spawn_dynamic_multi(
            "8000000000003502",
            grid,
            plan,
            Arc::clone(&throttled),
            1,
            Duration::from_secs(15),
            AimdConfig::new(2),
            1,
        );
        let live = Arc::new(HttpLive::new(std::slice::from_ref(&url)));
        live.total_len.store(total, Ordering::Relaxed);
        live.blocks_total.store(1, Ordering::Relaxed);
        let pool = Arc::new(taiji_http::pool::WorkerPool::new(1, 1));
        let token = CancellationToken::new();
        let fatal = Arc::new(StdMutex::new(None));
        let opts = HttpTaskOpts::default();
        let wopts = opts.worker_opts();
        let rig = WorkerRig {
            gid: "8000000000003502".to_string(),
            http_metrics: Arc::new(taiji_io::metrics::MetricsRegistry::new()),
            client: HttpClient::new(opts.to_client_config())
                .unwrap_or_else(|e| panic!("client: {e}")),
            // The test form uses no jump-off face (the owner URI has no correspondence
            // with the authoritative converged face).
            authoritative_final: None,
            telemetry: Arc::new(LiveTelemetry(Arc::clone(&live))),
            per_host: HostCap::new(32),
            pool: Arc::clone(&pool),
            token: token.clone(),
            total_len: total,
            bs,
            count: 1,
            ftp_cfg: opts.to_ftp_config(),
            base_ctx: RequestCtx::default(),
            fatal,
            steal: true,
        };
        let sources = vec![taiji_segment::traits::PlanSource {
            uri: url,
            kind: TransportKind::Http,
        }];
        let mut set = JoinSet::new();
        launch_worker(
            &rig, &coord, &throttled, &mut set, 0, &sources, &wopts, None,
        );
        pool.note_spawn(0, 1);
        // After the workers close out at the failure cap, the AIMD snapshot is
        // final — connect-phase RSTs are zero-byte throughout and never enter the
        // congestion face (the count stays at the slow-start start of 2).
        let drain = async {
            while let Some(r) = set.join_next().await {
                r.unwrap_or_else(|e| panic!("worker join: {e}"));
            }
        };
        tokio::time::timeout(Duration::from_secs(30), drain)
            .await
            .unwrap_or_else(|_| panic!("worker must exit at failure cap"));
        let snap = coord
            .aimd_snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(
            snap,
            vec![(0, 2)],
            "a connect-phase RST (wave-ramp noise, zero bytes) must not trigger the decrease"
        );
        drop(coord);
        let outcome = tokio::time::timeout(Duration::from_secs(15), actor)
            .await
            .unwrap_or_else(|_| panic!("actor join timeout"));
        outcome
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The bookkeeping observation sink (shared by both e2e tests):
    /// NullSink-shaped + a block-completion counter (the direct reading for
    /// the completion assertions).
    struct CountingSink {
        completions: AtomicU64,
    }
    impl taiji_segment::traits::SegmentSink for CountingSink {
        fn write_at(
            &self,
            _seg: taiji_segment::traits::SegId,
            _off: u64,
            _bytes: Bytes,
        ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn complete_block(
            &self,
            _block: u64,
        ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
            self.completions.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// The loss collapse depth + recovery ramp e2e. Cap 8, one steady-state
    /// RST (the budgeted origin keeps injection deterministic):
    /// - collapse depth: the decrease lands at 7 (the Reset-grade 7/8
    /// coefficient);
    /// - recovery ramp: the snapshot must return to cap within the 2s deadline
    /// after the decrease (with a 3s eval window / 0.5s recovery window, the
    /// 0.5s window plus the real write stream closes the loop);
    /// - data face: retries after the RST are served healthy and all blocks
    /// complete (completion under loss never regresses).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loss_reset_recovery_ramp_restores_connections_e2e() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
        let bs = MIN_BLOCK_SIZE;
        let blocks = 8u64;
        let total = blocks * bs;
        // The write stream is paced to outlast the decrease bookkeeping so the
        // 0.5s recovery window still finds it open at close (against a full-speed
        // source the file would finish instantly, the recovery window would never
        // close, and the ramp assertion would be unstable).
        let url = spawn_rst_budget_origin(1, 128 * 1024, total, Duration::from_millis(400)).await;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = GuidedPlan::build(
            total,
            &GuidedConfig {
                block_size: bs,
                max_chunk: bs,
            },
            &|b| grid.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let probe = Arc::new(CountingSink {
            completions: AtomicU64::new(0),
        });
        let live = Arc::new(HttpLive::new(std::slice::from_ref(&url)));
        live.total_len.store(total, Ordering::Relaxed);
        live.blocks_total.store(blocks, Ordering::Relaxed);
        // Production-isomorphic observation seam (the drive_segmented assembly-
        // order decoupling): the sink is constructed before the coordinator spawns
        // and the report handle is backfilled via DeferredReporter — write
        // observations (RateSample -> AIMD window) are driven by the real write
        // stream; the recovery ramp is not fed artificially.
        let reporter = Arc::new(DeferredReporter {
            inner: StdMutex::new(None),
            flow: live.stall.clone(),
        });
        let throttled: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::with_rate_reporter(
            Arc::clone(&probe) as Arc<dyn SegmentSink>,
            HttpLimiter::new(None),
            reporter.clone(),
        ));
        // The AIMD face parameters (the test windows scale proportionally: eval
        // window = 6x recovery window, the same ratio as the production defaults).
        let aimd_cfg = AimdConfig {
            max_connections: 8,
            eval_window: Duration::from_secs(3),
            recovery_window: Duration::from_millis(500),
            start_connections: 8,
        };
        let (coord, actor) = coordinator::spawn_dynamic_multi(
            "8000000000003503",
            grid,
            plan,
            Arc::clone(&throttled),
            1,
            Duration::from_secs(15),
            aimd_cfg,
            1,
        );
        let coord = Arc::new(coord);
        reporter.set(Some(coord.clone()));
        let pool = Arc::new(taiji_http::pool::WorkerPool::with_start(1, 8, 8));
        let token = CancellationToken::new();
        let fatal = Arc::new(StdMutex::new(None));
        let opts = HttpTaskOpts::default();
        let wopts = opts.worker_opts();
        let rig = WorkerRig {
            gid: "8000000000003503".to_string(),
            http_metrics: Arc::new(taiji_io::metrics::MetricsRegistry::new()),
            client: HttpClient::new(opts.to_client_config())
                .unwrap_or_else(|e| panic!("client: {e}")),
            // The test form uses no jump-off face (the owner URI has no correspondence
            // with the authoritative converged face).
            authoritative_final: None,
            telemetry: Arc::new(LiveTelemetry(Arc::clone(&live))),
            per_host: HostCap::new(32),
            pool: Arc::clone(&pool),
            token: token.clone(),
            total_len: total,
            bs,
            count: blocks,
            ftp_cfg: opts.to_ftp_config(),
            base_ctx: RequestCtx::default(),
            fatal,
            steal: true,
        };
        let sources = vec![taiji_segment::traits::PlanSource {
            uri: url,
            kind: TransportKind::Http,
        }];
        let mut set = JoinSet::new();
        for _ in 0..8usize {
            launch_worker(
                &rig,
                coord.as_ref(),
                &throttled,
                &mut set,
                0,
                &sources,
                &wopts,
                None,
            );
        }
        pool.note_spawn(0, 8);

        // Poll the AIMD snapshot: first see the collapse (8->7), then the recovery
        // ramp (7->8). The 2s deadline sits far below the 3s eval window.
        let mut saw_decrease_at: Option<std::time::Instant> = None;
        let mut restored = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let snap = coord
                .aimd_snapshot()
                .await
                .unwrap_or_else(|e| panic!("snapshot: {e}"));
            match (saw_decrease_at, snap.as_slice()) {
                (None, [(0, 7)]) => saw_decrease_at = Some(std::time::Instant::now()),
                (None, [(0, 8)]) => {} // decrease not landed yet (RST in flight / backing off)
                (Some(t0), [(0, 8)]) => {
                    let ramp = t0.elapsed();
                    assert!(
                        ramp < Duration::from_secs(2),
                        "recovery ramp {ramp:?} exceeded the 2s deadline (under the 0.5s recovery-window \
                         semantics the loop should close in ~0.5-0.8s; the old full-eval-window semantics \
                         would take >=3s and fail — this assertion is the ramp-speedup discriminator)"
                    );
                    restored = true;
                    break;
                }
                (Some(_), [(0, 7)]) => {} // still decreased (the recovery window has not closed)
                (Some(_), [(0, n)]) => panic!(
                    "a deeper second collapse during recovery (budget 1 should not trip again): {n}"
                ),
                _ => {}
            }
        }
        assert!(
            saw_decrease_at.is_some(),
            "a steady-state RST must trigger the Reset decrease (collapse depth 8->7, the 7/8 factor)"
        );
        assert!(
            restored,
            "the recovery ramp must restore the cap within the deadline"
        );
        // Data face: after the loss, retries are served healthy and all blocks complete.
        let mut done = 0u64;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
            done = probe.completions.load(Ordering::Relaxed);
            if done >= blocks {
                break;
            }
        }
        assert_eq!(
            done, blocks,
            "retries after the RST must complete the whole grid (loss completeness)"
        );
        // Close-out.
        token.cancel();
        let drain = async {
            while let Some(r) = set.join_next().await {
                r.unwrap_or_else(|e| panic!("worker join: {e}"));
            }
        };
        tokio::time::timeout(Duration::from_secs(30), drain)
            .await
            .unwrap_or_else(|_| panic!("workers must drain"));
        reporter.set(None);
        drop(coord);
        let outcome = tokio::time::timeout(Duration::from_secs(15), actor)
            .await
            .unwrap_or_else(|_| panic!("actor join timeout"));
        outcome
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The no-loss throughput-non-regression e2e. A healthy slow source (keeps
    /// the write stream alive: blocks finishing instantly would never close
    /// the gain window), cap 8, start 2 (the spec slow-start form) +
    /// supervisor emulation (snapshot -> spawn directives honored — an
    /// isomorphic inline of the driver loop's grow/shrink loop): the
    /// gain-window cadence must still double the connection count to the cap
    /// (2->4->8 with each step visible — the first step rides the
    /// establishment window, then the cadence returns to the spec window), and
    /// all blocks complete (data-face throughput never regresses).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn healthy_no_loss_growth_cadence_and_completion_e2e() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
        let bs = MIN_BLOCK_SIZE;
        let blocks = 48u64;
        let total = blocks * bs;
        // Budget 0 = a purely healthy source; 64KiB/128ms per connection paces the
        // timeline: both connections' establishment window closes first (optimistic
        // probing 2->4), then the four-connection spec window closes on the +100%
        // gain (4->8), and the remainder finishes at 8 connections.
        let url = spawn_rst_budget_origin(0, 0, total, Duration::from_millis(128)).await;
        let grid = BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("grid: {e}"));
        let plan = GuidedPlan::build(
            total,
            &GuidedConfig {
                block_size: bs,
                max_chunk: bs,
            },
            &|b| grid.is_recorded(b),
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let probe = Arc::new(CountingSink {
            completions: AtomicU64::new(0),
        });
        let live = Arc::new(HttpLive::new(std::slice::from_ref(&url)));
        live.total_len.store(total, Ordering::Relaxed);
        live.blocks_total.store(blocks, Ordering::Relaxed);
        let reporter = Arc::new(DeferredReporter {
            inner: StdMutex::new(None),
            flow: live.stall.clone(),
        });
        let throttled: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::with_rate_reporter(
            Arc::clone(&probe) as Arc<dyn SegmentSink>,
            HttpLimiter::new(None),
            reporter.clone(),
        ));
        let aimd_cfg = AimdConfig {
            max_connections: 8,
            eval_window: Duration::from_secs(3),
            recovery_window: Duration::from_millis(500),
            start_connections: 2,
        };
        let (coord, actor) = coordinator::spawn_dynamic_multi(
            "8000000000003504",
            grid,
            plan,
            Arc::clone(&throttled),
            1,
            Duration::from_secs(15),
            aimd_cfg,
            1,
        );
        let coord = Arc::new(coord);
        reporter.set(Some(coord.clone()));
        let pool = Arc::new(taiji_http::pool::WorkerPool::with_start(1, 8, 2));
        let token = CancellationToken::new();
        let fatal = Arc::new(StdMutex::new(None));
        let opts = HttpTaskOpts::default();
        let wopts = opts.worker_opts();
        let rig = WorkerRig {
            gid: "8000000000003504".to_string(),
            http_metrics: Arc::new(taiji_io::metrics::MetricsRegistry::new()),
            client: HttpClient::new(opts.to_client_config())
                .unwrap_or_else(|e| panic!("client: {e}")),
            // The test form uses no jump-off face (the owner URI has no correspondence
            // with the authoritative converged face).
            authoritative_final: None,
            telemetry: Arc::new(LiveTelemetry(Arc::clone(&live))),
            per_host: HostCap::new(32),
            pool: Arc::clone(&pool),
            token: token.clone(),
            total_len: total,
            bs,
            count: blocks,
            ftp_cfg: opts.to_ftp_config(),
            base_ctx: RequestCtx::default(),
            fatal,
            steal: true,
        };
        let sources = vec![taiji_segment::traits::PlanSource {
            uri: url,
            kind: TransportKind::Http,
        }];
        let mut set = JoinSet::new();
        for _ in 0..2usize {
            launch_worker(
                &rig,
                coord.as_ref(),
                &throttled,
                &mut set,
                0,
                &sources,
                &wopts,
                None,
            );
        }
        pool.note_spawn(0, 2);

        // The gain cadence (the no-loss non-regression face): the slow-start
        // doubling chain 2->4->8 closes through the spec eval window (3s) — one
        // full window per step, the recovery window never intervenes (no
        // decrease). Supervisor emulation: snapshot -> spawn directives honored
        // (isomorphic to the driver loop's grow/shrink; decision -> real workers
        // -> real write stream -> gain evidence, a complete loop).
        let started = std::time::Instant::now();
        let mut cap_at: Option<std::time::Instant> = None;
        let mut saw_mid = false;
        let mut reached_cap = false;
        let deadline = started + Duration::from_secs(60);
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let stats = coord
                .runtime_stats()
                .await
                .unwrap_or_else(|e| panic!("stats: {e}"));
            for (source, n) in supervisor_directives(&pool, &stats) {
                for _ in 0..n {
                    launch_worker(
                        &rig,
                        coord.as_ref(),
                        &throttled,
                        &mut set,
                        source as usize,
                        &sources,
                        &wopts,
                        None,
                    );
                }
                pool.note_spawn(source, n);
            }
            let snap = stats.aimd_connections;
            match snap.as_slice() {
                [(0, 4)] => {
                    saw_mid = true;
                }
                [(0, 8)] => {
                    if cap_at.is_none() {
                        cap_at = Some(std::time::Instant::now());
                    }
                    reached_cap = true;
                    break;
                }
                _ => {}
            }
        }
        // The gain-cadence discriminator (the full cadence after the cold-start
        // establishment window): the first doubling decision (2->4) belongs to the
        // ESTABLISHMENT window (the baseline-absent window = recovery_window
        // 500ms; establishment and decrease-rebuild are isomorphic) — appearing
        // within ~0.5s is the establishment face itself and is not judged "too
        // early"; once the baseline exists the window length returns to the spec
        // window (3s) — the SECOND doubling (4->8) must not be earlier than ~1
        // eval window (if the spec cadence were invaded by the recovery-window
        // parameter it would reach the cap within ~0.5s; this guard catches
        // that).
        if let Some(t) = cap_at {
            assert!(
                t.duration_since(started) >= Duration::from_millis(2500),
                "second doubling too early ({:?} < 2.5s): with the baseline present, the spec-window \
                 cadence was invaded by the recovery-window parameter",
                t.duration_since(started)
            );
        }
        assert!(
            saw_mid,
            "slow-start must double stepwise (2->4 visible at the relay, not a jump)"
        );
        assert!(
            reached_cap,
            "the healthy source's gain-window cadence must still reach the cap (no throughput regression)"
        );
        // Data face: all blocks complete.
        let mut done = 0u64;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
            done = probe.completions.load(Ordering::Relaxed);
            if done >= blocks {
                break;
            }
        }
        assert_eq!(done, blocks, "healthy source completes the whole grid");
        token.cancel();
        let drain = async {
            while let Some(r) = set.join_next().await {
                r.unwrap_or_else(|e| panic!("worker join: {e}"));
            }
        };
        tokio::time::timeout(Duration::from_secs(30), drain)
            .await
            .unwrap_or_else(|_| panic!("workers must drain"));
        reporter.set(None);
        drop(coord);
        let outcome = tokio::time::timeout(Duration::from_secs(15), actor)
            .await
            .unwrap_or_else(|_| panic!("actor join timeout"));
        outcome
            .unwrap_or_else(|e| panic!("actor join: {e}"))
            .unwrap_or_else(|e| panic!("actor: {e}"));
    }

    /// The demotion-recovery closure of the source-health snapshot write-back:
    /// when the ledger says Active but the view is stuck at "demoted", the
    /// Active arm hands the slot back to the busy-count driver (>0 = active,
    /// zero = waiting) — without this reset the busy driver never takes over
    /// non-waiting/active slots and the RPC view would stay demoted forever.
    /// Demoted/Removed projection and the "busy churn never rewrites terminal
    /// states" semantics are unchanged.
    #[test]
    fn source_book_active_resets_stale_demoted_view() {
        let live = HttpLive::new(&["http://a.test/f".into(), "http://b.test/f".into()]);
        use taiji_http::sources::SourceState;

        // Ledger demotion projection; source 1 has an in-flight worker (busy=1).
        live.note_source_busy(1, 1);
        live.apply_source_book_states(&[(1, SourceState::Demoted)]);
        assert_eq!(
            live.sources.lock().unwrap_or_else(|e| e.into_inner())[1].state,
            "demoted"
        );

        // Ledger back to Active: the busy driver resets it (busy=1 -> active,
        // instead of staying demoted).
        live.apply_source_book_states(&[(1, SourceState::Active)]);
        assert_eq!(
            live.sources.lock().unwrap_or_else(|e| e.into_inner())[1].state,
            "active",
            "after demotion recovery the view hands back to the busy driver (in-flight = active)"
        );

        // Recovery Active after busy reaches zero -> waiting (never fake in-flight).
        live.apply_source_book_states(&[(1, SourceState::Demoted)]);
        live.note_source_busy(1, -1);
        live.apply_source_book_states(&[(1, SourceState::Active)]);
        assert_eq!(
            live.sources.lock().unwrap_or_else(|e| e.into_inner())[1].state,
            "waiting",
            "after demotion recovery the view hands back to the busy driver (no in-flight = waiting)"
        );

        // A one-shot view (failed -> the slot never stuck) is untouched: the
        // Active arm only resets "demoted"; "failed" (the probe-eviction terminal)
        // is never overwritten by the ledger snapshot.
        live.set_source_state(0, "failed");
        live.apply_source_book_states(&[(0, SourceState::Active)]);
        assert_eq!(
            live.sources.lock().unwrap_or_else(|e| e.into_inner())[0].state,
            "failed",
            "the probe-eviction terminal is never overwritten by the ledger's Active snapshot"
        );
    }

    /// The flow-wait liveness assembly (static and degraded share the same
    /// [`FlowWaitPulse`] shape, the liveness face of the h2 flow-wait
    /// exclusion criterion): a rate-limiter permit wait > 0 counts a flow-wait
    /// event into the task-level byte heartbeat — the same convention as
    /// dynamic's DeferredReporter; a pass-through permit (waited = 0) counts
    /// nothing.
    #[tokio::test]
    async fn flow_wait_pulse_feeds_task_stall_liveness() {
        use taiji_io::rate_limit::{LimiterPair, LimiterSet};

        let live = Arc::new(HttpLive::new(&["http://a.test/f".into()]));
        assert_eq!(live.stall.flow_waits(), 0, "no wait events at the start");
        let sink = ThrottledSink::with_rate_reporter(
            Arc::new(NullSink) as Arc<dyn SegmentSink>,
            HttpLimiter::new(Some(Arc::new(LimiterSet {
                global: LimiterPair::new(0, 0),
                // The task bucket at 64KiB/s (capacity ~1s of stock): a single 128KiB
                // write must wait ~1s (draining the stock) — waited > 0 is observable.
                per_torrent: LimiterPair::new(64 * 1024, 0),
            }))),
            Arc::new(FlowWaitPulse(live.stall.clone())) as Arc<dyn RateSampleReporter>,
        );
        let seg = SegId {
            source: 0,
            extent: 0,
        };
        sink.write_at(seg, 0, bytes::Bytes::from(vec![0u8; 128 * 1024]))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        assert!(
            live.stall.flow_waits() > 0,
            "a rate-limiter permit wait counts as flow-wait liveness"
        );
        // The criterion boundary (the FlowWaitPulse contract): zero waits count no
        // event — a pass-through permit is not rate-limit liveness
        // (sub-microsecond measurement noise counts even less; the rate.rs ledger
        // has its own RATE_WAIT_FLOOR noise floor).
        let pulse = FlowWaitPulse(live.stall.clone());
        let before = live.stall.flow_waits();
        pulse.report(0, 8, Duration::ZERO);
        assert_eq!(
            live.stall.flow_waits(),
            before,
            "zero wait (waited = 0) counts no flow-wait event"
        );
        pulse.report(0, 8, Duration::from_millis(5));
        assert!(
            live.stall.flow_waits() > before,
            "a rate-limit wait (waited > 0) counts an event"
        );
    }

    /// The no-op sink (the bookkeeping terminus for assembly-face tests).
    struct NullSink;

    impl SegmentSink for NullSink {
        fn write_at(
            &self,
            _seg: SegId,
            _off: u64,
            _bytes: Bytes,
        ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(())))
        }

        fn complete_block(
            &self,
            _block: u64,
        ) -> Pin<Box<dyn Future<Output = taiji_http::error::Result<()>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// The byte-level completion projection reading (`completed_bytes`) —
    /// seeded from the bookkeeping base, monotonic with writes, clamped down
    /// when the total length is known (double-write waste never leaks, always
    /// <= totalLength), the final value pinned to the bookkeeping final; with
    /// no total length (the EOF form) it is not clamped.
    #[test]
    fn live_completed_bytes_projection_byte_level_monotonic_clamped() {
        const MIB: u64 = 1024 * 1024;
        let live = HttpLive::new(&["http://origin/f.bin".to_string()]);
        // Activation seed = the block bookkeeping base (the resumed bitmap's
        // 2MiB of completed bytes).
        live.total_len.store(5 * MIB, Ordering::Relaxed);
        live.done_bytes.store(2 * MIB, Ordering::Relaxed);
        assert_eq!(
            live.completed_bytes(),
            2 * MIB,
            "the seed = the bookkeeping base"
        );
        // Writes into an unfinished block advance the byte face (monotonic; the
        // count source is the sink's own feed point).
        live.note_written_bytes(256 * 1024);
        assert_eq!(live.completed_bytes(), 2 * MIB + 256 * 1024);
        live.note_written_bytes(64 * 1024);
        assert!(
            live.completed_bytes() > 2 * MIB + 256 * 1024,
            "the byte face is monotonic with writes"
        );
        // Same-block double-writes/retry rewrites: the byte face can exceed the
        // total -> the projection clamps down (<= totalLength; over-collection
        // never leaks).
        live.note_written_bytes(10 * MIB);
        assert_eq!(
            live.completed_bytes(),
            5 * MIB,
            "clamped to the known total length"
        );
        // The final value pins to bookkeeping (the Done-tail store): the byte
        // projection's final = the bookkeeping final.
        live.done_bytes.store(5 * MIB, Ordering::Relaxed);
        assert_eq!(live.completed_bytes(), 5 * MIB);
        // No total length (the EOF-delimited form): total = 0 means no clamping;
        // the byte face advances honestly.
        let eof = HttpLive::new(&["http://origin/g.bin".to_string()]);
        eof.note_written_bytes(1024);
        assert_eq!(
            eof.completed_bytes(),
            1024,
            "no total length means no clamping"
        );
        // The degraded disk-delta feed (note_progress) shares the write-point
        // source: written/done_bytes advance together (the rate-conversion base is
        // never consumed by the projection — the swap zeroing only touches
        // written).
        let deg = HttpLive::new(&["http://origin/h.bin".to_string()]);
        deg.note_progress(4096);
        assert_eq!(deg.completed_bytes(), 4096);
        deg.note_tick();
        assert_eq!(
            deg.completed_bytes(),
            4096,
            "the rate-conversion swap never touches the projection count"
        );
    }
    // ---- verdict pre-hash unit tests ----

    /// The test rig: a real temporary `.part` + content written + manual block
    /// bookkeeping (out-of-order records converging into contiguous-prefix
    /// advances).
    struct PrefetchFixture {
        dir: PathBuf,
        body: Vec<u8>,
        blocks: u64,
        bitmap: Vec<u8>,
        prefetch: Option<Arc<ChecksumPrefetch>>,
    }

    impl PrefetchFixture {
        /// 8 blocks x 1KiB; `checksum` is the expected raw `--checksum` value.
        fn new(tag: &str, checksum: &str) -> PrefetchFixture {
            let bs: u64 = 1024;
            let blocks = 8u64;
            let body: Vec<u8> = (0..blocks * bs).map(|i| (i % 251) as u8).collect();
            let dir = std::env::temp_dir().join(format!(
                "media-pf-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
            let part = dir.join("f.bin.part");
            std::fs::write(&part, &body).unwrap_or_else(|e| panic!("seed: {e}"));
            let prefetch =
                ChecksumPrefetch::new("8000000000000691", part, body.len() as u64, bs, checksum, 0);
            PrefetchFixture {
                dir,
                body,
                blocks,
                bitmap: vec![0u8; 8],
                prefetch: prefetch.map(Arc::new),
            }
        }

        fn pf(&self) -> &Arc<ChecksumPrefetch> {
            self.prefetch.as_ref().unwrap_or_else(|| panic!("prefetch"))
        }

        /// Book one block (set the bit + the prefix-advance notify).
        fn record(&mut self, block: u64) {
            use crate::session::http::bit_set;
            bit_set(&mut self.bitmap, block);
            self.pf().note_block_recorded(&self.bitmap, self.blocks);
        }

        /// Wait for the reader to consume up to `upto` (timeout = failure).
        async fn wait_consumed(&self, upto: u64) {
            let inner = &self.pf().inner;
            for _ in 0..200 {
                if inner.hashed_to.load(Ordering::Acquire) >= upto {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!(
                "reader did not consume up to {upto}: {}",
                inner.hashed_to.load(Ordering::Acquire)
            );
        }
    }

    impl Drop for PrefetchFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn sha256_hex_of(body: &[u8]) -> String {
        use sha2::Digest as _;
        sha2::Sha256::digest(body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Out-of-order bookkeeping convergence: even blocks are recorded first
    /// (the prefix stops at 0), odd blocks fill in (the prefix advances step
    /// by step) — after finish the digest == a single full-file hash (the
    /// correctness invariant: consumed bytes == final file bytes).
    #[tokio::test]
    async fn prefetch_digest_matches_full_hash_under_out_of_order_completion() {
        let want = sha256_hex_of(
            &(0..8u64 * 1024)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let mut fx = PrefetchFixture::new("ooo", &format!("sha-256={want}"));
        // Even blocks first: the prefix = 1 block (block 0 done, block 1 missing)
        // — the reader consumes only 1KiB; completed blocks past the gap (2/4/6)
        // are not consumed (out-of-order never crosses a gap).
        for b in [0u64, 2, 4, 6] {
            fx.record(b);
        }
        fx.wait_consumed(1024).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            fx.pf().inner.hashed_to.load(Ordering::Acquire),
            1024,
            "a prefix gap (block 1 unrecorded) must not consume past the gap into blocks 2+"
        );
        // Odd blocks fill in: the prefix advances block by block and the reader
        // consumes as it goes.
        for b in [1u64, 3, 5, 7] {
            fx.record(b);
        }
        fx.wait_consumed(fx.body.len() as u64).await;
        let verdict = fx.pf().finish_and_compare().await;
        assert!(
            matches!(verdict, Some(Ok(()))),
            "the final verdict passes after out-of-order convergence: {verdict:?}"
        );
    }

    /// Overlap evidence (consumed during the download): wait after partial
    /// bookkeeping — the reader has consumed to the current prefix before any
    /// finish (it does not wait for the terminal command).
    #[tokio::test]
    async fn prefetch_consumes_during_recording_not_only_at_finish() {
        let want = sha256_hex_of(
            &(0..8u64 * 1024)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let mut fx = PrefetchFixture::new("overlap", &format!("sha-256={want}"));
        for b in 0..5u64 {
            fx.record(b);
        }
        // No finish is sent: the reader consumes to the 5KiB prefix on its own
        // (overlap = consumption during the download).
        fx.wait_consumed(5 * 1024).await;
        assert!(
            fx.pf()
                .finish_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some(),
            "finish was never sent"
        );
    }

    /// The gate: writes inside the consumed zone are rejected (late duplicates
    /// dropped losslessly); a prefix-boundary start (the next block) is not
    /// rejected (normal writes unaffected).
    #[tokio::test]
    async fn prefetch_gate_rejects_consumed_zone_and_admits_prefix_edge() {
        let want = sha256_hex_of(
            &(0..8u64 * 1024)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let mut fx = PrefetchFixture::new("gate", &format!("sha-256={want}"));
        fx.record(0);
        fx.wait_consumed(1024).await;
        assert!(
            fx.pf().pre_write_reject(0),
            "a start inside the consumed zone must be rejected (late duplicate data)"
        );
        assert!(
            fx.pf().pre_write_reject(1023),
            "any point inside the consumed zone must be rejected"
        );
        assert!(
            !fx.pf().pre_write_reject(1024),
            "a prefix-boundary start (the next block) must not be rejected (normal writes)"
        );
        assert!(
            !fx.pf().pre_write_reject(4096),
            "the unconsumed zone must not be rejected"
        );
    }

    /// A post-write check crossing -> invalidated -> the finish fallback face
    /// (None): when an in-flight overshoot lands exactly in the consumed zone,
    /// the pre-hash is no longer usable (the backstop arm closing the semantic
    /// equivalence).
    #[tokio::test]
    async fn prefetch_post_write_crossing_invalidates_and_falls_back() {
        let want = sha256_hex_of(
            &(0..8u64 * 1024)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let mut fx = PrefetchFixture::new("inv", &format!("sha-256={want}"));
        // The pre-write check admits (gate=0) -> consume [0,1KiB) -> simulate the
        // write landing only after consumption (the post-write check finds the
        // crossing).
        assert!(!fx.pf().pre_write_reject(0), "admitted before consumption");
        fx.record(0);
        fx.wait_consumed(1024).await;
        fx.pf().post_write_check(0);
        assert!(
            fx.pf().inner.invalidated.load(Ordering::Acquire),
            "a post-write check crossing must invalidate"
        );
        assert!(
            fx.pf().finish_and_compare().await.is_none(),
            "invalidated -> falls back to the full post-hash (None)"
        );
    }

    /// Mismatch: the pre-hash final != expected -> ChecksumMismatch (fail-
    /// closed: no fallback, no loosening).
    #[tokio::test]
    async fn prefetch_mismatch_reports_checksum_error() {
        let mut fx = PrefetchFixture::new("bad", &format!("sha-256={}", "0".repeat(64)));
        for b in 0..8u64 {
            fx.record(b);
        }
        fx.wait_consumed(fx.body.len() as u64).await;
        match fx.pf().finish_and_compare().await {
            Some(Err(HttpError::ChecksumMismatch { .. })) => {}
            other => panic!("must report the mismatch error: {other:?}"),
        }
    }

    /// The resume face: an initial-prefix seed (initial_prefix > 0) — the
    /// reader chases the already-completed prefix from the start (a resume's
    /// completed portion amortizes over the remaining download time).
    #[tokio::test]
    async fn prefetch_seeds_initial_prefix_from_resume_bitmap() {
        let body: Vec<u8> = (0..8u64 * 1024).map(|i| (i % 251) as u8).collect();
        let want = sha256_hex_of(&body);
        let dir = std::env::temp_dir().join(format!("media-pf-resume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::write(dir.join("f.bin.part"), &body).unwrap_or_else(|e| panic!("seed: {e}"));
        // The resume bitmap: blocks 0-2 done -> the initial prefix is 3KiB.
        let pf = ChecksumPrefetch::new(
            "8000000000000692",
            dir.join("f.bin.part"),
            body.len() as u64,
            1024,
            &format!("sha-256={want}"),
            3 * 1024,
        )
        .map(Arc::new)
        .unwrap_or_else(|| panic!("prefetch"));
        let mut fx = PrefetchFixture {
            dir,
            body,
            blocks: 8,
            bitmap: vec![0u8; 8],
            prefetch: Some(pf),
        };
        // The bitmap excludes the initial prefix (the resume-seed face) — record
        // the remaining blocks and finish converges.
        for b in 3..8u64 {
            fx.record(b);
        }
        fx.wait_consumed(8 * 1024).await;
        assert!(matches!(fx.pf().finish_and_compare().await, Some(Ok(()))));
    }
}
