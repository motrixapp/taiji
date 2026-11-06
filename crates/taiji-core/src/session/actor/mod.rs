//! SessionActor: queue scheduling + the task lifecycle command surface
//! (SPEC §3.2/§7.2/§8.2). Real task creation for addUri/addTorrent
//! (metainfo → EngineConfig → [`DownloadEngine`] / magnet →
//! [`MagnetEngine`] full chain / http(s) .torrent URL → metadata fetch →
//! in-place upgrade), remove/pause/unpause lifecycle, the
//! max-concurrent-downloads FIFO queue with bt-detach-seed-only slot
//! consumption (`EngineEnd::Detached`), the DownloadResult table, the
//! option faces, and the six-event notification bus (SPEC §7.4,
//! broadcast(256) → WS push).
//!
//! Hard invariants: the actor exclusively owns all state (no locks); the
//! command mpsc(64) and the internal event mpsc(64) are bounded; locks
//! never span await; per-task `CancellationToken` children form the unified
//! pause/remove/shutdown cancel face; the main loop does zero disk IO
//! (metainfo parsing and EngineConfig assembly run in `spawn_blocking`,
//! pure CPU; row persistence is serialized through the single
//! PersistWriter). The event bus is `broadcast(256)`
//! ([`EVENT_BUS_CAPACITY`]): sends are synchronous and never block the
//! publisher (the engine event path waits for nothing), and slow
//! subscribers lag and are then disconnected by the rpc face (the
//! backpressure policy; upstream has no backlog — aria2 pushes unbounded).
//!
//! Queue semantics and known boundary divergences vs upstream, plus the
//! upstream anchor mapping: docs/design/core.md

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use taiji_bt::peer_policy::IpGuardHandle;
use taiji_bt::tracker::{HttpAnnounce, TrackerOptions, generate_peer_id, trackerslist};

use crate::engine::{
    DownloadEngine, EngineEnd, EngineHandle, EngineStatusSnapshot, TrackerWireConfig,
};
use crate::gid::{Gid, GidAllocator};
use crate::hook::{HookEvent, HookRunner, HookSet};
use crate::magnet::{MagnetEnd, MagnetEngine, MagnetOptions, MagnetTaskConfig};
use crate::metainfo::{Metainfo, TorrentIdentity, TorrentMeta};
use crate::seed::SeedPolicy;

use taiji_io::rate_limit::LimiterSet;
use taiji_io::text::is_spoofing_char;
use taiji_store::persist::{
    PeerBanRow, PersistHandle, TorrentFileRow, TorrentProgressRow, TorrentRow,
};

use crate::peer_guard::ManualBanRule;

use super::bans::{
    CLIENT_BAN_PREFIXES_KV, MAX_MANUAL_BANS, ManualBan, ban_source, now_epoch, parse_manual_target,
};
use super::command::{
    CommandReply, OffsetMode, RPC_METHODS, SessionCommand, SessionEnvelope, SessionError,
    TaskCookieSpec,
};
use super::events::{
    EVENT_BUS_CAPACITY, EventKind, RecoveryEvent, RecoveryEventKind, RecoveryNotice, SessionEvent,
};
use super::limits::SpeedLimits;
use super::metrics::SessionMetrics;
use super::options::{
    OptionDecl, OptionFace, TaskOptionPatch, add_trackers, apply_global_patch, checked_seed_ratio,
    format_minutes, format_seed_ratio, global_option_echo, merge_global_trackers,
    parse_select_file, parse_task_options, remove_trackers, resolve_select_file_for_meta,
    seed_duration_from_minutes, split_bt_tracker, windows_unsafe_basename,
};
use super::persist::{
    PersistedTaskConfig, SessionExportEntry, derive_name, file_rows, serialize_export,
};
use super::queue::{Location, QueueMan, ReservedEntry, WaitingSegment};
use super::view::{
    BanEntryView, BanSource, BittorrentView, DownloadResultEntry, FileEntryView, GidResolveError,
    GlobalStatView, PeerCryptoKind, PeerEntryView, PeerTransportKind, ServerEntryView, StatusKind,
    TorrentStatusView, UriEntryView, expand_unique, file_piece_bases, file_selected,
    per_file_completed, torrent_top_attrs,
};
/// The teardown timeout share for waiting on all running tasks to exit at
/// SessionActor shutdown (of the 1s total budget).
const TORRENT_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Budget yielded to NAT unmap at shutdown (consumed by lifecycle; deletion
/// is advisory — RFC 6886 §3.1, gateway-side automatic expiry reclaims as
/// the backstop — exceeding it gives up waiting and does not erode SPEC
/// §8.1's 1s shutdown budget; slow IGD unmaps have been observed reaching
/// minutes).
const NAT_SHUTDOWN_BUDGET: Duration = Duration::from_millis(250);

/// Internal event channel capacity: at most one event per task teardown and
/// tasks are bounded by the queue; 64 is ample and bounded.
const EVENT_CHANNEL_CAPACITY: usize = 64;

/// renamePending closeout poll period (zero cost while the registry is
/// empty).
const CLOSEOUT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// BT engine status snapshot cache TTL. The trade-off: polling read faces
/// (getGlobalStat aggregation / tellStatus·tellActive live views / periodic
/// summaries) hit the cache within the TTL and lag by at most one sampling
/// period — in exchange the control face is never dragged down by the data
/// face (each query_status must queue through the engine's bounded command
/// channel plus a oneshot round trip; getGlobalStat awaiting engine by
/// engine inside the single-threaded actor would block the command face for
/// O(active task count) engine round trips). The lag is compensated by
/// invalidation: any TaskNotice for that gid (teardown / recheck / upgrade
/// / BtComplete completion-flips-to-seeding, the run event arm) drops the
/// entry on arrival — a post-event query always reads post-event truth; a
/// BT download completing is not task teardown (the task stays resident
/// seeding, `Ended` does not arrive), so the completion event must enqueue
/// its own invalidation ([`TaskNotice::StatusDirty`]), otherwise the first
/// post-completion query hits the pre-completion sample (a 0-byte snapshot
/// — the completion event already sent while the byte face lagged, a
/// self-contradictory reading). Entries die with `running` removal at task
/// end/removal. Detail queries like getPeers/getServers do not use this
/// cache (they read current state directly).
const STATUS_CACHE_TTL: Duration = Duration::from_secs(2);

/// In-flight hot-push snapshot entry: (gid, engine handle, currently
/// effective tracker table) — import_global_trackers snapshots first and
/// pushes later (avoids holding a mutable borrow across await).
type HotPushTarget = (Gid, EngineHandle, Vec<(usize, String)>);

/// Session-side handle for a running task (pause/remove/shutdown via the
/// token; changeUri via the engine handle; forceRemove via abort).
struct RunningTask {
    token: CancellationToken,
    /// Execution backend (mutually exclusive shapes; the convergence source
    /// of the engine handle and the HTTP driver trio, see [`TaskBackend`]).
    backend: TaskBackend,
    /// Current tracker table (the edit target of taiji.addTracker/
    /// removeTracker, plan B; comes from the metainfo announce at
    /// activation).
    tiers: Vec<(usize, String)>,
    total_len: u64,
    /// forceRemove's immediate detach (skips the stopped announce budget —
    /// the engine task is aborted outright, equivalent to aria2 forceHalt's
    /// "do not wait for the stopped sequence" semantics).
    abort: Option<tokio::task::AbortHandle>,
    /// This module's rate-limit chain (the same instance shared with the
    /// engine — changeOption's max-download/upload-limit applies live via
    /// `set_rate`, effective immediately).
    limiter: Option<Arc<LimiterSet>>,
    /// This module's hook trigger face (the same runner instance shared
    /// with the engine — the engine side triggers bt-complete, the session
    /// side triggers the other five points). Torrent/Magnet tasks always
    /// carry a runner (it also relays the engine-side BtComplete onto the
    /// bus); None only remains for engine-less fetch tasks (a new runner
    /// with the relay takes over after the upgrade).
    hook: Option<Arc<HookRunner>>,
}

/// Per-engine status snapshot cache entry (the `status_cache` payload of
/// [`TaskBackend::Engine`]): `query_status` returns the snapshot verbatim
/// plus the sampling instant. The snapshot keeps the engine query seam's
/// field values as-is (consumer shaping logic unchanged); freshness is
/// judged against [`STATUS_CACHE_TTL`] by the sampling instant; the
/// invalidation face = any TaskNotice for that gid (the run event arm).
struct EngineStatusCache {
    snap: EngineStatusSnapshot,
    sampled: Instant,
}

/// A running task's execution backend (mutually exclusive shapes, the
/// convergence source of kind branching). The activation shape is fixed at
/// construction; the only runtime state transition is the magnet upgrade
/// notice swapping the engine in place ([`TaskBackend::Metadata`] →
/// [`TaskBackend::Engine`] — a variant replacement inside the
/// single-threaded actor, no concurrency race). What each family puts
/// behind the four surfaces a task consumes (live reads / row
/// persistence / control / verification position) is stated explicitly
/// in [`super::backend_contract::BackendContract`] (the family key via
/// [`TaskBackend::family`]).
enum TaskBackend {
    /// BT engine task: constructed during torrent activation; a magnet
    /// metadata task swaps it in via the upgrade notice (live readings go
    /// through the engine query seam from then on).
    Engine {
        engine: EngineHandle,
        /// BT engine status snapshot cache (for the polling read face only;
        /// queries within [`STATUS_CACHE_TTL`] cost zero engine round
        /// trips). None = no cache / invalidated by an event / not yet
        /// sampled. Living inside the Engine variant = the entry's lifetime
        /// never outlives the task: pause requeue / teardown / removal die
        /// with `running` removal and re-activation starts from an empty
        /// cache; engine-absent shapes (the metadata phase / HTTP tasks)
        /// always have no cache — presence is structurally isomorphic, no
        /// ambiguous "has engine but no cache slot" state.
        status_cache: Option<EngineStatusCache>,
    },
    /// HTTP driver task (addUri classification / bootstrap restore
    /// activation): live readings, the row mirror, and the pause
    /// cancel-source flag come assembled from the driver in one shot (the
    /// same return bundle as `spawn_http_task`, always all present).
    Http {
        /// HttpTask's live readings (atomics only; the data source of the
        /// tellStatus `http` sub-dictionary).
        live: Arc<http_task::HttpLive>,
        /// HttpTask row mirror (read by the remove tombstone write face;
        /// shared with the driver).
        row: Arc<std::sync::Mutex<taiji_store::persist::HttpTaskRow>>,
        /// HttpTask's pause cancel-source flag (the driver teardown
        /// distinguishes the row state paused / resume faces; set by
        /// pause/pauseAll before cancel).
        pause: Arc<std::sync::atomic::AtomicBool>,
    },
    /// Metadata-phase task (magnet metadata / .torrent URL fetch): no
    /// engine handle, no HTTP driver face — live readings are honestly zero
    /// (the same shape as aria2's metadata group), and the control face is
    /// only the task token (a fetch task has no engine to abort, same
    /// here); swaps in [`TaskBackend::Engine`] when the upgrade notice
    /// arrives.
    Metadata,
    /// Media driver task (the third task family): live
    /// readings = the pipeline's phase/track/progress rollup state
    /// (a small mutex — reads never span await); the row mirror and
    /// pause flag live with the driver (the row writes go through the
    /// pipeline's own persist face).
    Media {
        live: Arc<std::sync::Mutex<crate::session::media::MediaLiveState>>,
        /// Pause cancel-source flag (pause/pauseAll sets it before
        /// cancel — the driver's teardown writes the paused row with
        /// the §3.2 phase memory only for a pause-intent cancel).
        pause: Arc<std::sync::atomic::AtomicBool>,
    },
}

impl TaskBackend {
    /// The family this backend belongs to — the
    /// [`super::backend_contract::BackendContract`] key (three
    /// families across four variants: the Metadata variant is the BT
    /// family's magnet-metadata phase). Pure classification, zero
    /// runtime effect (the contract states surfaces; the enum stays
    /// the shape). Consumed by the backend_family_tests + the future
    /// family cards (ed2k/iroh).
    #[allow(dead_code)]
    fn family(&self) -> super::backend_contract::TaskFamily {
        use super::backend_contract::TaskFamily;
        match self {
            TaskBackend::Engine { .. } | TaskBackend::Metadata => TaskFamily::Bittorrent,
            TaskBackend::Http { .. } => TaskFamily::Http,
            TaskBackend::Media { .. } => TaskFamily::Media,
        }
    }

    /// HTTP driver task check (the runtime shape mirror of jobs-side
    /// Job::Http's activation shape; the single source for shape checks
    /// like getUris' activation projection).
    fn is_http(&self) -> bool {
        matches!(self, TaskBackend::Http { .. })
    }

    /// Media live state (the media sub-dictionary data source;
    /// synchronous mutex reads, never occupies the command channel).
    /// Non-media tasks = None.
    fn media_live(&self) -> Option<&Arc<std::sync::Mutex<crate::session::media::MediaLiveState>>> {
        match self {
            TaskBackend::Media { live, .. } => Some(live),
            _ => None,
        }
    }

    /// Media pause cancel-source flag. Non-media tasks = None.
    fn media_pause(&self) -> Option<&Arc<std::sync::atomic::AtomicBool>> {
        match self {
            TaskBackend::Media { pause, .. } => Some(pause),
            _ => None,
        }
    }

    /// BT engine handle (live queries / ban·tracker·DHT hot-push faces).
    /// The metadata phase and HTTP tasks = None (the same shape as aria2's
    /// metadata group having no engine handle).
    fn engine(&self) -> Option<&EngineHandle> {
        match self {
            TaskBackend::Engine { engine, .. } => Some(engine),
            TaskBackend::Http { .. } | TaskBackend::Metadata | TaskBackend::Media { .. } => None,
        }
    }

    /// HTTP live readings (the http sub-dictionary / getServers source list
    /// / rate aggregation data source; synchronous atomic reads, never
    /// occupies the command channel). Non-HTTP tasks = None.
    fn http_live(&self) -> Option<&Arc<http_task::HttpLive>> {
        match self {
            TaskBackend::Http { live, .. } => Some(live),
            TaskBackend::Engine { .. } | TaskBackend::Metadata | TaskBackend::Media { .. } => None,
        }
    }

    /// HTTP row mirror (renamePending closeout registration / the remove
    /// tombstone write face's reads; the data the teardown classification's
    /// row-write split needs). Non-HTTP tasks = None.
    fn http_row(&self) -> Option<&Arc<std::sync::Mutex<taiji_store::persist::HttpTaskRow>>> {
        match self {
            TaskBackend::Http { row, .. } => Some(row),
            TaskBackend::Engine { .. } | TaskBackend::Metadata | TaskBackend::Media { .. } => None,
        }
    }

    /// HTTP pause cancel-source flag (after pause/pauseAll sets it, the
    /// driver finishes the http_task row as paused — restart returns it to
    /// the paused queue). Non-HTTP tasks = None (torrent tasks have no such
    /// face).
    fn http_pause(&self) -> Option<&Arc<std::sync::atomic::AtomicBool>> {
        match self {
            TaskBackend::Http { pause, .. } => Some(pause),
            TaskBackend::Media { pause, .. } => Some(pause),
            TaskBackend::Engine { .. } | TaskBackend::Metadata => None,
        }
    }

    /// Engine status snapshot cache hit read (freshness judged at the
    /// consumer — only an age ≤ TTL returns the cache). Non-Engine shapes
    /// are always None (cache presence is structurally isomorphic to engine
    /// presence).
    fn status_cache(&self) -> Option<&EngineStatusCache> {
        match self {
            TaskBackend::Engine { status_cache, .. } => status_cache.as_ref(),
            TaskBackend::Http { .. } | TaskBackend::Metadata | TaskBackend::Media { .. } => None,
        }
    }

    /// Status snapshot cache invalidation (any TaskNotice for that gid
    /// drops the entry on arrival — a post-event query always reads
    /// post-event truth). Non-Engine shapes = no-op.
    fn expire_status_cache(&mut self) {
        if let TaskBackend::Engine { status_cache, .. } = self {
            *status_cache = None;
        }
    }

    /// Status snapshot cache backfill (the write half of the `query_status`
    /// read seam). Non-Engine shapes = no-op (the read seam short-circuits
    /// when the engine is absent; this arm is a structural backstop).
    fn store_status_cache(&mut self, snap: EngineStatusSnapshot, sampled: Instant) {
        if let TaskBackend::Engine { status_cache, .. } = self {
            *status_cache = Some(EngineStatusCache { snap, sampled });
        }
    }
}

/// Task payload in the waiting queue (consumed repeatedly across
/// reorders/restarts).
enum Job {
    /// Parsed metainfo (addTorrent / the URL metadata upgrade product).
    Torrent(Box<TorrentJob>),
    /// magnet full-chain task (MagnetTaskConfig rebuilt at every spawn).
    Magnet(Box<MagnetJob>),
    /// http(s) .torrent URL: a metadata download placeholder (upgraded in
    /// place to Torrent after fetch).
    TorrentUrl {
        url: String,
        dir: PathBuf,
        seed: SeedPolicy,
        /// `--max-download-limit` (0 = unlimited; rides the upgrade
        /// payload).
        max_download_limit: u64,
        /// `--max-download-limit` (0 = unlimited).
        max_upload_limit: u64,
        /// Task-final hook set (global + per-task overrides; rides the
        /// upgrade).
        hooks: Arc<HookSet>,
        /// The `select-file` option's effective value (0-based strictly
        /// increasing — rides the upgrade product into
        /// TorrentJob.selected_files from the same source, projected as a
        /// mask at activation).
        select_file: Option<Vec<u32>>,
        /// The `bt-disable-dht` flag (None = follow the session — rides the
        /// upgrade product into TorrentJob.bt_disable_dht from the same
        /// source).
        bt_disable_dht: Option<bool>,
        /// `enable-http-seeding` (BEP19; None = default true — rides the
        /// upgrade product into TorrentJob.enable_http_seeding from the
        /// same source).
        enable_http_seeding: Option<bool>,
    },
    /// HTTP/FTP download task (addUri always on).
    /// Shares the `--max-concurrent-downloads` scheduling slot with BT
    /// (the same queue bookkeeping).
    Http(Box<HttpJob>),
    /// Media task (the third task family; the media phase domain):
    /// shares the scheduling slot like Http.
    Media(Box<media_task::MediaJob>),
}

/// HTTP task payload (the addUri classification product / bootstrap restore
/// rebuild; fixed during activation).
struct HttpJob {
    /// Source URIs (user order; multi-source = mirrors of the same file,
    /// aria2 addUri semantics).
    uris: Vec<String>,
    dir: PathBuf,
    /// `--out` file name (None = derived from the final URL).
    out: Option<String>,
    /// Per-task rate limits (0 = unlimited).
    max_download_limit: u64,
    max_upload_limit: u64,
    /// Task-final hook set (global + per-task overrides, fixed at add
    /// time).
    hooks: Arc<HookSet>,
    /// Runtime option face (fixed at add time; bootstrap restore = the
    /// defaults; narrow exception: the concurrency intent face replays with
    /// the row — see bootstrap_http).
    opts: http_task::HttpTaskOpts,
    /// The startup-restore DB row (injected by bootstrap; None on the add
    /// path — the driver starts from a fresh row; after the first
    /// activation the row mirror takes over and restore is no longer
    /// consumed).
    restore: Option<taiji_store::persist::HttpTaskRow>,
    /// Row mirror (backfilled by the driver at first activation; shared by
    /// reactivation/teardown faces — pause/remove tombstone reads and
    /// writes share the source).
    mirror: Option<Arc<std::sync::Mutex<taiji_store::persist::HttpTaskRow>>>,
    /// Restored cookie rows (the cookie-replay seeds; injected by
    /// bootstrap, an empty set on the add path — they ride HttpTaskRun into
    /// the driver at activation).
    cookies: Vec<taiji_store::persist::TaskCookieRow>,
    /// Cookie injection seeds: the `--load-cookies` file load result or
    /// `taiji.addUriWithCookies` structured direct pass (`setTaskCookies`
    /// overwrites the same slot) — prefills the task store via
    /// `CookieStore::seed` at activation, then persists via the
    /// cookie write-back loop (snapshot ∪ baseline), so restart replay rides the
    /// existing cookie-row replay face. Bootstrap rebuild = an empty set
    /// (file sources are not re-read across restarts — aria2 also loads
    /// once at task creation; the restore face relies on persisted rows).
    cookie_seed: Vec<taiji_http::cookies::NetscapeCookie>,
    /// Submission instant (the fixed-chain trace anchor): on the add path =
    /// the addUri acceptance point, on the restore/restart path = the
    /// construction point (the cross-restart queued segment cannot be
    /// recovered, so timing starts at activation). Purely observational
    /// (the ChainTrace t0), never part of control flow.
    submitted: std::time::Instant,
}

/// addUri URI classification (the always-on classification face): http/https/ftp/ftps
/// = the HTTP download task family; a `.torrent` URL is singled out into
/// the metadata path (Phase A semantics preserved).
fn is_download_uri(u: &str) -> bool {
    ["http://", "https://", "ftp://", "ftps://"]
        .iter()
        .any(|p| u.starts_with(p))
}

/// `.torrent` URL check: the path's last segment (query/fragment stripped)
/// ends with `.torrent` (case-insensitive) — the classification anchor of
/// the metadata fetch path.
fn is_torrent_url(u: &str) -> bool {
    let path = u.split(['?', '#']).next().unwrap_or(u);
    path.rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .ends_with(".torrent")
}

/// Cookie intake gate predicate: the combination semantics declared for
/// manual `Cookie:` lines in `--header` — **for a task with a cookie intake
/// gate present (a load-cookies file source or a structured direct pass),
/// manual Cookie lines are stripped and not passed through; the jar is the
/// task's only cookie source**. Rationale (settled after reading the
/// engine): (1) on the request-build face (taiji-http client) a manual
/// header and the jar's synthesized value are two independent Cookie
/// headers (append semantics), and servers commonly taking the first
/// header would silently void the jar — accepting without effect is a
/// fake; (2) the fork tightens the structured face the same way:
/// "Structured cookies are authoritative. Do not retain ambient or raw
/// Cookie headers" (the fork RpcMethodImpl.cc's verbatim stance, the
/// PREF_HEADER Cookie line strip). Tasks without an intake gate pass
/// manual Cookie headers through unchanged (current behavior, zero
/// change). The gate's three inputs: a session-level file source
/// (GlobalOptions.load_cookies present), a `load-cookies` key present in
/// the payload (per-task add / changeOption payload), and non-empty
/// structured seeds (addUriWithCookies).
fn cookie_intake_active(
    global_source: Option<&Path>,
    options: &BTreeMap<String, String>,
    seed_len: usize,
) -> bool {
    global_source.is_some() || options.contains_key("load-cookies") || seed_len > 0
}

/// Strip manual `Cookie:` lines from `--header` values (case-insensitive
/// prefix; aria2's multi-header "\n"-joined shape). If nothing remains the
/// whole key is removed. Semantics declared in [`cookie_intake_active`]
/// (the fork RpcMethodImpl.cc shape; non-Cookie manual headers are
/// unaffected).
fn strip_manual_cookie_headers(options: &mut BTreeMap<String, String>) {
    if let Some(header) = options.get("header") {
        let retained: Vec<&str> = header
            .split('\n')
            .filter(|l| !l.trim().is_empty())
            .filter(|l| !l.trim_start().to_ascii_lowercase().starts_with("cookie:"))
            .collect();
        match retained.len() {
            n if n == header.split('\n').filter(|l| !l.trim().is_empty()).count() => {}
            0 => {
                options.remove("header");
            }
            _ => {
                options.insert("header".to_string(), retained.join("\n"));
            }
        }
    }
}

/// Structured cookie spec → store entry conversion (step two): fields map
/// directly (`expires_utc`'s unit is already converted from ms to s at the
/// RPC layer), expired entries dropped — same rule as the fork's
/// parseRpcCookies: "Expired records are valid input but must not enter
/// the active store" (RpcCookie.cc).
fn cookies_from_specs(specs: &[TaskCookieSpec]) -> Vec<taiji_http::cookies::NetscapeCookie> {
    let now = now_epoch();
    specs
        .iter()
        .filter(|c| !c.expires_utc.is_some_and(|exp| now >= exp))
        .map(|c| taiji_http::cookies::NetscapeCookie {
            domain: c.domain.clone(),
            host_only: c.host_only,
            path: c.path.clone(),
            secure: c.secure,
            expires: c.expires_utc,
            name: c.name.clone(),
            value: c.value.clone(),
        })
        .collect()
}

/// `--load-cookies` file load (the fail-closed single point; step one):
/// Netscape parsing reuses taiji-http's existing machinery
/// (`CookieJar::load_netscape_file` — the 1MiB cap + disk IO in
/// spawn_blocking). Missing / unreadable / oversized = `taiji.option.
/// invalid` task rejection (accepting without effect is a fake — the
/// message carries the cap anchor); bad rows follow the parse face's
/// lenient discipline (skip the line, not fatal, same as curl — the
/// cookies.rs module doc; an all-bad file = an empty jar is a legal shape,
/// indistinguishable from comments/empty files).
async fn load_cookie_seed(
    path: &str,
) -> Result<Vec<taiji_http::cookies::NetscapeCookie>, SessionError> {
    let jar = taiji_http::cookies::CookieJar::load_netscape_file(std::path::Path::new(path))
        .await
        .map_err(|e| {
            SessionError::failed(format!(
                "taiji.option.invalid: --load-cookies {path:?} ({e}; \
                 max {} bytes per cookie file)",
                taiji_http::cookies::MAX_COOKIE_FILE_BYTES
            ))
        })?;
    Ok(jar.cookies().to_vec())
}

/// The parse/write arm of an HTTP task option declaration table entry (an
/// invalid value is always `taiji.option.invalid` — the same rule as
/// aria2's OptionHandler rejecting the task on parse failure, never a
/// silent fallback to defaults).
#[derive(Clone, Copy, Debug)]
enum HttpTaskApply {
    /// Persist-face arm (the [`HttpPersistConfig`] slot; face.persist
    /// rows).
    Persist(fn(&mut http_task::HttpPersistConfig, &str) -> Result<(), SessionError>),
    /// Runtime-face arm (the [`http_task::HttpTaskOpts`] slot; face.runtime
    /// rows — not persisted, restore takes the session defaults).
    Runtime(fn(&mut http_task::HttpTaskOpts, &str) -> Result<(), SessionError>),
}

/// HTTP task option declaration table (the 0.2 group + scheduling group +
/// protocol/h2/FTP families; parse points = the two drivers
/// [`http_task_options`] (face.persist dispatch) and
/// [`http_task_runtime_options`] (face.runtime dispatch) — a new key is
/// registered as one table row plus an accepted-name mirror constant
/// (cfg(test)), never by editing parse arms in several places).
///
/// Manual arms (`apply = None`, registration completeness pinned by the
/// governance tests): http-user/http-passwd/ftp-user/ftp-passwd — paired
/// credential keys build their slot across two keys (any one present
/// creates the AuthScheme slot), which a single-key arm cannot express;
/// the executors live in the explicit section of
/// [`http_task_runtime_options`]. The fold bit
/// ([`OptionFace::import_fold`]) is the single source of the
/// `fold_imported_options` key set (the manual FOLD_KEYS list and this
/// table were previously maintained twice); it spans both faces — runtime
/// rows fold into `HttpTaskOpts`, persist rows fold into
/// `HttpPersistConfig` (the dispatch driver follows the face).
static HTTP_TASK_OPTION_TABLE: &[OptionDecl<HttpTaskApply>] = &[
    // ---- Persist face (face.persist: legal values persist with task row
    // creation; changeOption's incremental semantics = keys absent from
    // the payload keep the baseline, see each driver) ----
    // Fold slots: the persist-face three keys (suffix/checksum/
    // remote-time) join the fold domain — for imported tasks these keys
    // sit verbatim in imported_options, and if they did not join the fold
    // set the fork session's declared end-to-end verification would fail
    // silently (the verdict face reads the row payload and would never
    // see them). Fold dispatch rides the persist driver (the value domain
    // = the same domain as this arm's addUri). check-certificate/
    // ca-certificate do not fold: the TLS trust face does not silently
    // migrate with the fork config (a fail-closed stance, registered in
    // the fold_imported_options comment).
    OptionDecl::table_row(
        "http-incomplete-suffix",
        OptionFace::http_persist().folding(),
        HttpTaskApply::Persist(|c, v| {
            let suffix = taiji_http::naming::IncompleteSuffix::parse(v)
                .map_err(|e| SessionError::failed(format!("{}: {}", e.code(), e)))?;
            c.incomplete_suffix = suffix.as_str().to_string();
            Ok(())
        }),
    ),
    // `--checksum=<scheme>=<hex>` verbatim (the completion-time verdict
    // restores it with the row).
    OptionDecl::table_row(
        "checksum",
        OptionFace::http_persist().folding(),
        HttpTaskApply::Persist(|c, v| {
            validate_checksum_value(v)?;
            c.checksum = Some(v.trim().to_string());
            Ok(())
        }),
    ),
    OptionDecl::table_row(
        "remote-time",
        OptionFace::http_persist().folding(),
        HttpTaskApply::Persist(|c, v| {
            c.remote_time = parse_bool_strict(v, "--remote-time")?;
            Ok(())
        }),
    ),
    // ---- Runtime face (face.runtime: not persisted, rebuilt from the new
    // session options after restart; narrow exception: the concurrency
    // intent face split/cap replays with the row — see bootstrap_http) ----
    // The task-level CA face's divergence stance lives in the
    // session::options declared-difference block (the ca-certificate
    // entry): parse-time path/PEM validation — a bad path / bad PEM =
    // `taiji.option.invalid` task rejection (the known-key tightening
    // convention, not a silent pass). The DER snapshot is fixed with opts
    // (the FTP face's consumer); the HTTP face re-reads via the path at
    // transport build time (a load failure = a client build error).
    // Replacement semantics (a task-level root replaces rather than
    // appends, same as aria2); combined with `--check-certificate=false`
    // the latter wins (verification off, the CA file's effect face
    // ignored — two wiring points keep the order: this face still accepts
    // the value, the effect order closes at the to_client_config /
    // to_ftp_config projection points).
    OptionDecl::table_row(
        "ca-certificate",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            let path = PathBuf::from(v.trim());
            o.ca_cert_der = taiji_http::client::load_ca_certificates_der(&path).map_err(|e| {
                SessionError::failed(format!("taiji.option.invalid: --ca-certificate {e}"))
            })?;
            o.ca_cert_path = Some(path);
            Ok(())
        }),
    ),
    // Default true = verification on; explicit false = verification off
    // (the ClientConfig face).
    OptionDecl::table_row(
        "check-certificate",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.accept_invalid_certs = !parse_bool_strict(v, "--check-certificate")?;
            Ok(())
        }),
    ),
    OptionDecl::table_row(
        "connect-timeout",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.connect_timeout = Duration::from_secs(parse_u64_domain(v, "--connect-timeout", 1)?);
            Ok(())
        }),
    ),
    // Manual arm: ftp-user/ftp-passwd (paired credentials, an FTP-source
    // -only slot — separate from the http slot, the aria2 shape; executor
    // in the explicit section).
    OptionDecl {
        name: "ftp-passwd",
        face: OptionFace::http_runtime().folding(),
        apply: None,
        manual_match: None,
    },
    OptionDecl {
        name: "ftp-user",
        face: OptionFace::http_runtime().folding(),
        apply: None,
        manual_match: None,
    },
    // ftp-pasv is a value-validation-only face: active mode (false = PORT)
    // is not accepted — taiji is PASV/EPSV only (IPv6 has no PORT
    // semantics; the firewall-friendly passive face is the only
    // implementation) — explicit rejection instead of silent ignoring
    // (accepting without effect is a fake; declared difference).
    OptionDecl::table_row(
        "ftp-pasv",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|_o, v| {
            if !parse_bool_strict(v, "--ftp-pasv")? {
                return Err(SessionError::failed(
                    "taiji.option.invalid: --ftp-pasv=false (active mode unsupported; \
                     PASV/EPSV only — declared difference)",
                ));
            }
            Ok(())
        }),
    ),
    // taiji extension (aria2 hard-wires this face with no such option name
    // — a capability extension, declared difference): a three-state
    // PASV/EPSV data-connection address check. The value syntax's single
    // source = taiji-http `PasvAddressPolicy::FromStr` (exact lowercase
    // peer|strict|off; out of domain = `taiji.option.invalid` rejection,
    // no truncation); the effect face = the to_ftp_config projection →
    // every FtpTransport::for_uri construction point.
    OptionDecl::table_row(
        "ftp-pasv-address-check",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.ftp_pasv_policy = v
                .trim()
                .parse::<taiji_http::ftp::PasvAddressPolicy>()
                .map_err(|e| SessionError::failed(format!("{}: {}", e.code(), e)))?;
            Ok(())
        }),
    ),
    // Default true (aria2-aligned): the control connection is reused
    // across extents.
    OptionDecl::table_row(
        "ftp-reuse-connection",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.ftp_reuse_connection = parse_bool_strict(v, "--ftp-reuse-connection")?;
            Ok(())
        }),
    ),
    // taiji extension (aria2 has no FTPS capability): none|auth
    // (default)|implicit.
    OptionDecl::table_row(
        "ftp-ssl",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.ftp_tls = parse_ftp_tls(v)?;
            Ok(())
        }),
    ),
    // aria2 semantics: multiple headers are delivered as one value joined
    // by "\n"; each line "Name: value". Key present = whole-table
    // replacement (incremental semantics counted per key, not accumulated
    // onto the baseline). The fold face = a cumulative key (import
    // manifests join into a single value in serialized order).
    OptionDecl::table_row(
        "header",
        OptionFace::http_runtime().folding().accumulating(),
        HttpTaskApply::Runtime(|o, v| {
            o.headers = parse_header_lines(v)?;
            Ok(())
        }),
    ),
    // taiji extension (the batch-aggregation scheduler; aria2 has no
    // batch-group concept — a dynamic scheduling extension, declared
    // difference): the cross-file aggregate connection budget within a
    // same-host transient batch group (domain 2..=64, unit = connections).
    // The three-layer cap stacking rules live in the taiji_http::batch
    // module docs (single-file intent is never amplified / a batch soft
    // cap + host idle overflow / fully counted against the per-host cap).
    // Runtime face (batch groups are process-level transients, not
    // persisted into the concurrency intent).
    OptionDecl::table_row(
        "http-batch-budget",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            let n = parse_u64_domain(v, "--http-batch-budget", 2)?;
            if !(u64::from(taiji_http::batch::MIN_BATCH_BUDGET)
                ..=u64::from(taiji_http::batch::MAX_BATCH_BUDGET))
                .contains(&n)
            {
                return Err(SessionError::failed(format!(
                    "taiji.option.invalid: --http-batch-budget {n:?} must be {}..={}",
                    taiji_http::batch::MIN_BATCH_BUDGET,
                    taiji_http::batch::MAX_BATCH_BUDGET
                )));
            }
            o.batch_budget = n as u32;
            Ok(())
        }),
    ),
    // taiji extension (aria2 has no block-grid concept — a dynamic
    // scheduling extension, declared difference): domain = powers of two
    // 256KiB..16MiB (the single source of the row-contract validation).
    // Immutable per task (fixed into the task row at creation — the bitmap
    // is accounted per block granularity, the row value is the resume
    // truth; changeOption's scheduling-increment face explicitly rejects
    // it — the HTTP_SCHED_PATCH_TABLE rejection arm).
    OptionDecl::table_row(
        "http-block-size",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.block_size = parse_block_size_value(v)?;
            Ok(())
        }),
    ),
    // taiji extension (aria2 has no guided-extent concept — a dynamic
    // scheduling extension): the guided allocation cap, domain lower bound
    // = the effective block granularity (a sub-block extent is
    // inexpressible; a cross-key validation — reads this face's
    // already-parsed block_size, relying on table declaration order and
    // key order: "http-block-size" < "http-max-chunk" always parses
    // first).
    OptionDecl::table_row(
        "http-max-chunk",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            let mc = parse_size_value(v, "--http-max-chunk")?;
            if mc < o.block_size {
                return Err(SessionError::failed(format!(
                    "taiji.option.invalid: --http-max-chunk {v:?} below block size {}",
                    o.block_size
                )));
            }
            o.max_chunk = mc;
            Ok(())
        }),
    ),
    // taiji extension (aria2 has no protocol selection option — a
    // capability extension + experiment window, declared difference):
    // auto (default = current behavior) | h1 | h2 (h2c prior knowledge in
    // cleartext, no fallback). Runtime face; a transport-level switch,
    // effective per task via the to_client_config projection.
    OptionDecl::table_row(
        "http-protocol",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.http_protocol = parse_http_protocol(v)?;
            Ok(())
        }),
    ),
    // taiji extension (aria2 has no scheduler-mode option — a dynamic
    // scheduling extension, declared difference): dynamic (default) |
    // static. Parsing reuses taiji-http `SchedulerMode::parse` as the
    // single source; unknown values are rejected, no fallback (the error
    // face shares that parse's wording).
    OptionDecl::table_row(
        "http-scheduler",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.scheduler = parse_scheduler_value(v)?;
            Ok(())
        }),
    ),
    // Domain lower bound = several heartbeat periods (3s): a one-tick
    // lower bound would let a single heartbeat jitter fabricate stall
    // evidence (a false steal); out of domain rejected, not truncated.
    OptionDecl::table_row(
        "http-stall-window",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.stall_window = Duration::from_secs(parse_stall_window_secs(v)?);
            Ok(())
        }),
    ),
    // taiji extension (aria2 has no window option — a capability extension
    // + experiment window, declared difference): h2 flow-control adaptive
    // window growth (ping/BDP estimation). Default false = the static
    // engine default window (8MiB/16MiB); hyper's library defaults of
    // 2MiB/5MiB are only reachable via the programmatic None path.
    // Transport-level switch, effective per task via the to_client_config
    // projection.
    OptionDecl::table_row(
        "http2-adaptive-window",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.http2_adaptive_window = parse_bool_strict(v, "http2-adaptive-window")?;
            Ok(())
        }),
    ),
    // taiji extension: h2 connection-level initial window bytes (domain
    // 65535..=2^31-1; shared across streams). Default = the engine default
    // 16MiB. Rate-limit backpressure semantics unchanged (stall's
    // flow-control-wait exclusion still holds).
    OptionDecl::table_row(
        "http2-connection-window",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.http2_connection_window = Some(parse_http2_window(v, "http2-connection-window")?);
            Ok(())
        }),
    ),
    // taiji extension: h2 PING keep-alive interval (domain 0..=3600 s;
    // 0 = off = the hyper status quo). Timeout = 2× the interval (fixed
    // inside the transport). Bare-name argument: the error template
    // already carries the `--` prefix, so passing `--http2-*` would render
    // `----http2-*` (aligned with parse_http2_window/parse_bool_strict
    // within the family — global sanitization is a separate topic).
    OptionDecl::table_row(
        "http2-keep-alive-interval",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            let n = parse_u64_domain(v, "http2-keep-alive-interval", 0)?;
            if n > 3600 {
                return Err(SessionError::failed(format!(
                    "taiji.option.invalid: --http2-keep-alive-interval {n} must be 0..=3600"
                )));
            }
            o.http2_keep_alive_interval = if n == 0 {
                None
            } else {
                Some(Duration::from_secs(n))
            };
            Ok(())
        }),
    ),
    // taiji extension (no aria2 counterpart — a capability extension +
    // experiment window, declared difference): an h2 per-origin connection
    // cap on the transport face (domain 1..=8; K independent transport
    // instances round-robin the load). Default 1 = the status quo (one
    // connection, multiplexed); ineffective when negotiation lands on h1.
    // Each connection counts against --http-max-per-host.
    OptionDecl::table_row(
        "http2-max-connections",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            let n = parse_u64_domain(v, "http2-max-connections", 1)?;
            if n > 8 {
                return Err(SessionError::failed(format!(
                    "taiji.option.invalid: --http2-max-connections {n} must be 1..=8"
                )));
            }
            o.http2_max_connections = n as u32;
            Ok(())
        }),
    ),
    // taiji extension: h2 stream-level initial window bytes (domain
    // 65535..=2^31-1, RFC 7540 §5.2.2). Default = the engine default
    // 8MiB.
    OptionDecl::table_row(
        "http2-stream-window",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.http2_stream_window = Some(parse_http2_window(v, "http2-stream-window")?);
            Ok(())
        }),
    ),
    // Manual arm: http-user/http-passwd (paired credentials — the same
    // pair serves Basic pre-setting and Digest challenges, aria2's
    // single-slot semantics; executor in the explicit section).
    OptionDecl {
        name: "http-passwd",
        face: OptionFace::http_runtime().folding(),
        apply: None,
        manual_match: None,
    },
    OptionDecl {
        name: "http-user",
        face: OptionFace::http_runtime().folding(),
        apply: None,
        manual_match: None,
    },
    // AIMD growth cap (aria2's native domain 1..=16; out of domain
    // rejected, not truncated).
    OptionDecl::table_row(
        "max-connection-per-server",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.max_conn_per_server = parse_max_conn_per_server_value(v)?;
            Ok(())
        }),
    ),
    // aria2 semantics: 0 = unlimited retries.
    OptionDecl::table_row(
        "max-tries",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            let n = parse_u64_domain(v, "--max-tries", 0)?;
            o.retry.max_tries = if n == 0 { u32::MAX } else { n as u32 };
            Ok(())
        }),
    ),
    OptionDecl::table_row(
        "min-split-size",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.min_split_size = parse_size_value(v, "--min-split-size")?;
            Ok(())
        }),
    ),
    OptionDecl::table_row(
        "retry-wait",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.retry.base_wait = Duration::from_secs(parse_u64_domain(v, "--retry-wait", 0)?);
            Ok(())
        }),
    ),
    // A redefined-semantics item (accepted and effective): under dynamic
    // scheduling it only seeds the initial extent — the declared
    // difference lives in session::options.
    OptionDecl::table_row(
        "split",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.split = parse_split_value(v)?;
            Ok(())
        }),
    ),
    OptionDecl::table_row(
        "timeout",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.read_timeout = Duration::from_secs(parse_u64_domain(v, "--timeout", 1)?);
            Ok(())
        }),
    ),
    // Fold slot (the fold_imported_options request-identity domain): the
    // UA default is left to the client layer.
    OptionDecl::table_row(
        "user-agent",
        OptionFace::http_runtime().folding(),
        HttpTaskApply::Runtime(|o, v| {
            o.user_agent = Some(v.trim().to_string());
            Ok(())
        }),
    ),
    // Proxy scheme gate (a defense line; the socks rejection = the
    // declared limitation of reqwest's socks feature being disabled). A
    // fold slot (a proxied task's request identity restores with the row).
    OptionDecl::table_row(
        "all-proxy",
        OptionFace::http_runtime().folding(),
        HttpTaskApply::Runtime(|o, v| {
            o.proxy = Some(parse_proxy_url(v, "--all-proxy")?);
            Ok(())
        }),
    ),
    // HTTPS-dedicated proxy slot (domain 2; the aria2 name): effect
    // order = dedicated slot > all-proxy > no proxy — projected to
    // `ClientConfig.proxy_https`, registered ahead of the global slot at
    // transport build time (reqwest's registration order is
    // first-match-wins; `Proxy::https` only intercepts https targets).
    // A fold slot (the proxy identity restores with the row, same as
    // all-proxy).
    OptionDecl::table_row(
        "https-proxy",
        OptionFace::http_runtime().folding(),
        HttpTaskApply::Runtime(|o, v| {
            o.proxy_https = Some(parse_proxy_url(v, "--https-proxy")?);
            Ok(())
        }),
    ),
    // Referer header (a domain 2 knob; the aria2 name): projected to the
    // task's `RequestCtx.referer` — carried on every probe and fetch hop
    // (the ctx clone propagates across the whole worker face). When a
    // `--header` Referer line coexists, both values are sent (reqwest's
    // same-name header append semantics) — the CLI face rejects the
    // cross-key conflict explicitly; the session face has no cross-key
    // adjudication seam (row comment). A fold slot (the request identity
    // restores with the row, same as user-agent).
    OptionDecl::table_row(
        "referer",
        OptionFace::http_runtime().folding(),
        HttpTaskApply::Runtime(|o, v| {
            o.referer = Some(v.trim().to_string());
            Ok(())
        }),
    ),
    // Transparent gzip decompression switch (a domain 2 knob; the aria2
    // name, default false same as aria2): true = `Accept-Encoding:
    // identity` is not sent (reqwest negotiates automatically — the data
    // face decompresses transparently; the probe face's line-7
    // single-connection downgrade and the bitmap do not engage).
    OptionDecl::table_row(
        "http-accept-gzip",
        OptionFace::http_runtime(),
        HttpTaskApply::Runtime(|o, v| {
            o.accept_gzip = parse_bool_strict(v, "--http-accept-gzip")?;
            Ok(())
        }),
    ),
];

// HTTP task option parsing shared parts (used by both the declaration
// table arms and changeOption's scheduling-increment face — same key, same
// value domain, same wording; validation at a single point).

/// Proxy URL value domain (shared by `--all-proxy` / `--https-proxy`;
/// `option` = the option name in the error wording): an http/https proxy
/// URL; socks forms are explicitly rejected.
fn parse_proxy_url(v: &str, option: &'static str) -> Result<String, SessionError> {
    let proxy = v.trim();
    let socks = ["socks5://", "socks5h://", "socks4://", "socks4a://"]
        .iter()
        .any(|p| proxy.to_ascii_lowercase().starts_with(p));
    if socks {
        return Err(SessionError::failed(format!(
            "taiji.option.invalid: {option} socks proxies are not supported yet \
             (reqwest socks feature not enabled; declared limitation)"
        )));
    }
    let scheme_ok = ["http://", "https://"]
        .iter()
        .any(|p| proxy.to_ascii_lowercase().starts_with(p));
    if !scheme_ok {
        return Err(SessionError::failed(format!(
            "taiji.option.invalid: {option} {proxy:?} (want http|https proxy URL)"
        )));
    }
    Ok(proxy.to_string())
}

/// `--http-block-size` value parsing + the row-contract domain (powers of
/// two 256KiB..16MiB).
fn parse_block_size_value(v: &str) -> Result<u64, SessionError> {
    let bs = parse_size_value(v, "--http-block-size")?;
    crate::session::actor::http_task::block_size_domain(bs).map_err(SessionError::failed)?;
    Ok(bs)
}

/// Multi-header line parsing ("\n"-separated; each line "Name: value",
/// whitespace trimmed on both sides; empty lines skipped; a line without a
/// colon = `taiji.option.invalid` rejection).
fn parse_header_lines(v: &str) -> Result<Vec<(String, String)>, SessionError> {
    let mut parsed = Vec::new();
    for line in v.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(SessionError::failed(format!(
                "taiji.option.invalid: --header {line:?} must be 'Name: value'"
            )));
        };
        parsed.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(parsed)
}

/// `--max-connection-per-server` value domain (aria2's native 1..=16; out
/// of domain rejected, not truncated; the cap shares its source with
/// taiji-http's AimdConfig growth cap).
fn parse_max_conn_per_server_value(v: &str) -> Result<u32, SessionError> {
    let n = parse_u64_domain(v, "--max-connection-per-server", 1)?;
    if n > MAX_CONN_PER_SERVER_MAX {
        return Err(SessionError::failed(format!(
            "taiji.option.invalid: --max-connection-per-server {n:?} must be 1..={MAX_CONN_PER_SERVER_MAX}"
        )));
    }
    Ok(n as u32)
}

/// Size-family value parsing (bare bytes or a K/M/G suffix; invalid =
/// `taiji.option.invalid`).
fn parse_size_value(v: &str, option: &'static str) -> Result<u64, SessionError> {
    crate::session::options::parse_size(v).ok_or_else(|| {
        SessionError::failed(format!(
            "taiji.option.invalid: --{option} {v:?} (want size with K/M/G suffix)"
        ))
    })
}

/// `--http-scheduler` value parsing (dynamic|static; the parse single
/// point = taiji-http SchedulerMode::parse, the error face shares that
/// parse's wording).
fn parse_scheduler_value(v: &str) -> Result<taiji_http::scheduler::SchedulerMode, SessionError> {
    taiji_http::scheduler::SchedulerMode::parse(v.trim()).map_err(|_| {
        SessionError::failed(format!(
            "taiji.option.invalid: --http-scheduler {v:?} (want dynamic|static)"
        ))
    })
}

/// `--http-stall-window` seconds domain lower bound (several heartbeat
/// periods — the same standard as the creation face; changeOption and task
/// creation follow the same rule).
fn parse_stall_window_secs(v: &str) -> Result<u64, SessionError> {
    parse_u64_domain(v, "--http-stall-window", STALL_WINDOW_MIN_SECS)
}

/// `--split` value domain (1..=[`taiji_http::scheduler::MAX_SPLIT`]; out
/// of domain rejected, not truncated — an in-domain value has no
/// truncation surface in the u32 slot, so a u32::MAX+1-class value is
/// rejected at the domain gate rather than wrapping via `as u32`). The
/// constant's single source = taiji-http (the scheduler/spawn consumer
/// side); the runtime backstop (`SchedulerConfig::validate`) and the
/// replay clamp (`HttpConcurrencyPersist::apply_to`) share the source and
/// domain.
fn parse_split_value(v: &str) -> Result<u32, SessionError> {
    let n = parse_u64_domain(v, "--split", 1)?;
    if n > u64::from(taiji_http::scheduler::MAX_SPLIT) {
        return Err(SessionError::failed(format!(
            "taiji.option.invalid: --split {n:?} must be 1..={}",
            taiji_http::scheduler::MAX_SPLIT
        )));
    }
    Ok(n as u32)
}

/// HTTP task per-task option face (the 0.2 group; the RPC addUri and the
/// CLI `taiji http` share one entry): `--checksum` /
/// `--http-incomplete-suffix` / `--remote-time`. Invalid values are always
/// `taiji.option.invalid` (the same rule as aria2's OptionHandler
/// rejecting the task on parse failure), never a silent fallback to
/// defaults. Validated values persist with task row creation (the
/// completion-time verdict / remote-time resume share the same source).
/// `base` is the merge baseline: keys absent from the payload keep the
/// baseline value (changeOption incremental semantics — a full re-parse
/// from defaults would silently reset persisted keys the payload omitted,
/// e.g. wiping a `--checksum` completion-time verdict); the add path uses
/// the defaults as its baseline.
///
/// Table-driven = the `face.persist` rows of [`HTTP_TASK_OPTION_TABLE`]
/// (payload key order = BTreeMap order — error precedence and the key set
/// are byte-exact regressions).
fn http_task_options(
    options: &BTreeMap<String, String>,
    base: &http_task::HttpPersistConfig,
) -> Result<http_task::HttpPersistConfig, SessionError> {
    let mut cfg = base.clone();
    for (k, v) in options {
        // Blank value = key absent (face convention, same as the
        // reference).
        let Some(v) = non_blank(v) else {
            continue;
        };
        let Some(decl) = HTTP_TASK_OPTION_TABLE.iter().find(|d| d.name == k.as_str()) else {
            continue; // Unknown key ignored (the reference's same rule).
        };
        // Dispatch bits: the accepted bit + the persist bit (this driver
        // only executes the persist face).
        if !decl.face.accepted || !decl.face.persist {
            continue;
        }
        let Some(HttpTaskApply::Persist(apply)) = decl.apply else {
            continue;
        };
        apply(&mut cfg, v)?;
    }
    Ok(cfg)
}

/// `--http-stall-window` domain lower bound (seconds): several times the
/// byte-level heartbeat period
/// ([`taiji_http::coordinator::HEARTBEAT_INTERVAL`] = 1s, take 3×). A
/// stall window must hold several heartbeat growth opportunities — a
/// one-tick lower bound (1s) would let a single heartbeat jitter fabricate
/// stall evidence and trigger a false steal.
const STALL_WINDOW_MIN_SECS: u64 = 3 * taiji_http::coordinator::HEARTBEAT_INTERVAL.as_secs();

/// `--http-protocol` value-domain parsing (the protocol-shape face, a
/// taiji extension — aria2 has no protocol selection option): `auto`
/// (default = the settled status quo: cleartext h1 + rustls ALPN
/// negotiation on https, h1 fallback when the server has no h2) / `h1`
/// (http1_only, upgrade closed) / `h2` (prior knowledge: h2c on cleartext
/// endpoints, h2 directly on TLS endpoints, no fallback — an
/// experiment-window stance; fails outright against h1-only peers).
/// Unknown value = `taiji.option.invalid` task rejection (same rule: no
/// silent fallback to defaults).
fn parse_http_protocol(v: &str) -> Result<taiji_http::client::HttpProtocol, SessionError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(taiji_http::client::HttpProtocol::Auto),
        "h1" => Ok(taiji_http::client::HttpProtocol::Http1),
        "h2" => Ok(taiji_http::client::HttpProtocol::Http2),
        other => Err(SessionError::failed(format!(
            "taiji.option.invalid: --http-protocol {other:?} (want auto|h1|h2)"
        ))),
    }
}

/// h2 window value-domain parsing (the window tuning face, a taiji
/// extension — aria2 has no window option): domain 65535..=2^31-1 (the
/// RFC 7540 §5.2.2 window cap; the value is the advertised
/// SETTINGS_INITIAL_WINDOW_SIZE bytes). Out of domain =
/// `taiji.option.invalid` task rejection (same rule: no silent fallback
/// to defaults).
fn parse_http2_window(v: &str, option: &'static str) -> Result<u32, SessionError> {
    const MIN: u64 = 65535;
    const MAX: u64 = (1u64 << 31) - 1;
    let n = parse_u64_domain(v, option, MIN)?;
    if n > MAX {
        return Err(SessionError::failed(format!(
            "taiji.option.invalid: --{option} {n} must be ≤ {MAX} (RFC 7540 §5.2.2 window cap)"
        )));
    }
    Ok(n as u32)
}

/// HTTP task runtime option parsing (the option-face wiring + scheduling
/// group; the §7.4 0.2 group): the http face = `--timeout`,
/// `--connect-timeout`, `--max-tries`, `--retry-wait`, `--user-agent`,
/// `--header`, `--http-user`, `--http-passwd`, `--all-proxy`,
/// `--https-proxy` (the domain-2 dedicated slot), `--referer`,
/// `--http-accept-gzip` (domain-2 knobs), `--check-certificate`,
/// `--ca-certificate` (the task-level CA face); the FTP family =
/// `--ftp-user`, `--ftp-passwd`, `--ftp-ssl`, `--ftp-pasv`,
/// `--ftp-reuse-connection`, `--ftp-pasv-address-check` (separate-slot
/// credentials and the FTPS / reuse / PASV address-check faces); the
/// scheduling group = `--split`, `--min-split-size`,
/// `--max-connection-per-server`, `--http-stall-window` (domain ≥
/// [`STALL_WINDOW_MIN_SECS`], several heartbeat periods). Invalid values =
/// `taiji.option.invalid` task rejection (the aria2 OptionHandler rule, no
/// silent fallback to defaults). `base` = the merge baseline (keys absent
/// from the payload keep the baseline value — changeOption incremental
/// semantics; a full re-parse from defaults would silently reset runtime
/// keys the payload omitted; the add path uses the defaults as its
/// baseline). Bootstrap-restored tasks take the defaults (the runtime face
/// is not persisted — rebuilt from the new session options after restart;
/// a narrow exception: the concurrency intent face split/cap is fixed with
/// the row and replayed, so restore activation never degrades to a single
/// connection with the session default cap 1).
///
/// Table-driven = the `face.runtime` rows of [`HTTP_TASK_OPTION_TABLE`]
/// (key order = BTreeMap order — error precedence and value shapes are
/// byte-exact regressions; the cross-key check http-max-chunk ≥
/// block-size depends on key order, and the two keys' alphabetical order
/// always holds). Manual arms = the table-registered paired credential
/// keys (http-user/http-passwd/ftp-user/ftp-passwd — any one present
/// creates the AuthScheme slot), executed in this function's explicit
/// section.
fn http_task_runtime_options(
    options: &BTreeMap<String, String>,
    base: &http_task::HttpTaskOpts,
) -> Result<http_task::HttpTaskOpts, SessionError> {
    let mut opts = base.clone();
    for (k, v) in options {
        // Blank value = key absent (face convention, same as the
        // reference).
        let Some(v) = non_blank(v) else {
            continue;
        };
        let Some(decl) = HTTP_TASK_OPTION_TABLE.iter().find(|d| d.name == k.as_str()) else {
            continue; // Unknown key ignored (the reference's same rule).
        };
        // Dispatch bits: the accepted bit + the runtime bit (this driver
        // only executes the runtime face).
        if !decl.face.accepted || !decl.face.runtime {
            continue;
        }
        let Some(HttpTaskApply::Runtime(apply)) = decl.apply else {
            // Manual-arm registration rows / persist-face rows — consumed
            // in the explicit section and outside this driver.
            continue;
        };
        apply(&mut opts, v)?;
    }
    // ---- Manual arms (table rows with apply = None: paired credential
    // keys build the slot across keys) ----
    let user = options
        .get("http-user")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let passwd = options
        .get("http-passwd")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    if !user.is_empty() || !passwd.is_empty() {
        // The same credential pair serves Basic pre-setting and Digest
        // challenges (aria2's `--http-user/--http-passwd` single-slot
        // semantics, the DigestAuth.cc shape).
        opts.auth = Some(taiji_segment::traits::AuthScheme::Basic { user, passwd });
    }
    let ftp_user = options
        .get("ftp-user")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let ftp_passwd = options
        .get("ftp-passwd")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    if !ftp_user.is_empty() || !ftp_passwd.is_empty() {
        // A separate slot from http-user/http-passwd (the aria2 shape):
        // FTP-source-only credentials, never leaking to http sources (the
        // auth_for dispatch).
        opts.ftp_auth = Some(taiji_segment::traits::AuthScheme::Basic {
            user: ftp_user,
            passwd: ftp_passwd,
        });
    }
    Ok(opts)
}

/// Blank values normalize to key-absent (the HTTP task face convention;
/// the raw value passes through untrimmed — trim semantics are owned by
/// each arm).
fn non_blank(v: &str) -> Option<&str> {
    if v.trim().is_empty() { None } else { Some(v) }
}

/// The `--max-connection-per-server` domain cap (aria2's native value; the
/// same source as taiji-http's [`taiji_http::aimd::AimdConfig`] growth
/// cap).
const MAX_CONN_PER_SERVER_MAX: u64 = 16;

/// changeOption's HTTP scheduling-group increment ("split / connection
/// count / scheduler-class can change at runtime (out-of-domain
/// rejected)"): only keys **explicitly given** in the payload participate
/// (changeOption incremental semantics, unlike the creation face's default
/// completion). Value-domain validation reuses the creation face's same
/// parsers (out of domain / invalid = `taiji.option.invalid`, no
/// truncation). Live tasks take effect via the existing restart semantics
/// (payload merged, requeue at the front, re-activate; bitmap progress
/// resumes losslessly); the AIMD shrink path's graceful contraction takes
/// effect at the executor loop's congestion decision face
/// ([`taiji_http::pool`]).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct HttpSchedPatch {
    /// `--split` (None = not given in the payload).
    pub split: Option<u32>,
    /// `--min-split-size`.
    pub min_split_size: Option<u64>,
    /// `--max-connection-per-server` (the AIMD growth cap).
    pub max_conn_per_server: Option<u32>,
    /// `--http-stall-window`.
    pub stall_window: Option<std::time::Duration>,
    /// `--http-scheduler` (a scheduler-mode change rides the existing
    /// restart semantics).
    pub scheduler: Option<taiji_http::scheduler::SchedulerMode>,
    /// `--http-max-chunk` (the guided extent cap; scheduler-class,
    /// changeable at runtime).
    pub max_chunk: Option<u64>,
}

/// The changeOption scheduling-increment domain parse/write arm type (an
/// instantiation alias of the declaration table).
type SchedPatchApply = fn(&mut HttpSchedPatch, &str) -> Result<(), SessionError>;

/// changeOption's HTTP scheduling-group increment declaration table (the
/// parse point = the table-driven [`http_sched_patch`]). Shares parsers
/// with the creation face ([`HTTP_TASK_OPTION_TABLE`]) for the same keys —
/// same value domain, same wording, validation at a single point; this
/// table only carries the "changeable at runtime" key-domain increment.
/// `--http-block-size` is registered as an explicit rejection arm
/// (immutable per task — the bitmap is accounted per block granularity,
/// the row value frozen at creation; any non-empty value =
/// `taiji.option.invalid`).
static HTTP_SCHED_PATCH_TABLE: &[OptionDecl<SchedPatchApply>] = &[
    // `--http-block-size` is immutable per task (the bitmap is accounted
    // per block granularity, the row value frozen at creation — runtime
    // changes explicitly rejected, no truncation, no ignoring).
    OptionDecl::table_row("http-block-size", OptionFace::http_runtime(), |_, _| {
        Err(SessionError::failed(
            "taiji.option.invalid: --http-block-size is immutable per task \
                 (block grid is frozen at creation; bitmap bookkeeping depends on it)",
        ))
    }),
    // The domain lower bound (≥ the block granularity) is cross-key
    // validated at the apply point — the patch face has no task block
    // granularity context (commands.rs holds hj.opts).
    OptionDecl::table_row("http-max-chunk", OptionFace::http_runtime(), |s, v| {
        s.max_chunk = Some(parse_size_value(v, "--http-max-chunk")?);
        Ok(())
    }),
    OptionDecl::table_row("http-scheduler", OptionFace::http_runtime(), |s, v| {
        s.scheduler = Some(parse_scheduler_value(v)?);
        Ok(())
    }),
    // A scheduler-mode change rides the existing restart semantics; the
    // domain lower bound = several heartbeat periods (the same standard as
    // http_task_runtime_options — changeOption and task creation follow
    // the same rule).
    OptionDecl::table_row("http-stall-window", OptionFace::http_runtime(), |s, v| {
        s.stall_window = Some(Duration::from_secs(parse_stall_window_secs(v)?));
        Ok(())
    }),
    OptionDecl::table_row(
        "max-connection-per-server",
        OptionFace::http_runtime(),
        |s, v| {
            s.max_conn_per_server = Some(parse_max_conn_per_server_value(v)?);
            Ok(())
        },
    ),
    OptionDecl::table_row("min-split-size", OptionFace::http_runtime(), |s, v| {
        s.min_split_size = Some(parse_size_value(v, "--min-split-size")?);
        Ok(())
    }),
    OptionDecl::table_row("split", OptionFace::http_runtime(), |s, v| {
        s.split = Some(parse_split_value(v)?);
        Ok(())
    }),
];

/// Parse the HTTP scheduling-group increment in a changeOption payload
/// (validation is the parse — an invalid value for any given key rejects
/// the whole payload).
///
/// Table-driven = [`HTTP_SCHED_PATCH_TABLE`] row lookup per key (key order
/// = BTreeMap order — "http-block-size" always precedes the group's other
/// keys alphabetically, so error precedence is a byte-exact regression;
/// keys outside the table are ignored).
pub(super) fn http_sched_patch(
    options: &BTreeMap<String, String>,
) -> Result<HttpSchedPatch, SessionError> {
    let mut out = HttpSchedPatch::default();
    for (k, v) in options {
        // Blank value = key absent (the same face convention as the
        // creation face; an empty block-size value does not trigger the
        // rejection arm).
        let Some(v) = non_blank(v) else {
            continue;
        };
        let Some(decl) = HTTP_SCHED_PATCH_TABLE.iter().find(|d| d.name == k.as_str()) else {
            continue;
        };
        // Accepted-bit dispatch: pure registration rows are skipped (the
        // explicit rejection arm row has accepted = true — it participates
        // in parsing and rejects with Err).
        if !decl.face.accepted {
            continue;
        }
        let Some(apply) = decl.apply else {
            continue;
        };
        apply(&mut out, v)?;
    }
    Ok(out)
}

/// `--ftp-ssl` value domain (none|auth|implicit; aria2's bool dual forms
/// do not apply — a three-state enum, bare/"1" not accepted, explicit
/// literals only). Invalid = task rejection.
fn parse_ftp_tls(v: &str) -> Result<taiji_http::ftp::FtpTlsMode, SessionError> {
    let mode = match v.trim().to_ascii_lowercase().as_str() {
        "none" => taiji_http::ftp::FtpTlsMode::None,
        "auth" => taiji_http::ftp::FtpTlsMode::Explicit,
        "implicit" => taiji_http::ftp::FtpTlsMode::Implicit,
        other => {
            return Err(SessionError::failed(format!(
                "taiji.option.invalid: --ftp-ssl {other:?} (want none|auth|implicit)"
            )));
        }
    };
    Ok(mode)
}

/// Strict bool parsing (the aria2 bool option face "true"/"false"/"1"/
/// "0"); invalid = `taiji.option.invalid` task rejection.
fn parse_bool_strict(v: &str, option: &'static str) -> Result<bool, SessionError> {
    match v.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(SessionError::failed(format!(
            "taiji.option.invalid: --{option} {other:?} (want true|false)"
        ))),
    }
}

/// Unsigned integer value-domain parsing (`≥ min`; invalid / out of domain
/// = `taiji.option.invalid` task rejection — the aria2 RANGE rule).
fn parse_u64_domain(v: &str, option: &'static str, min: u64) -> Result<u64, SessionError> {
    let trimmed = v.trim();
    let n: u64 = trimmed.parse().map_err(|_| {
        SessionError::failed(format!(
            "taiji.option.invalid: --{option} {v:?} (want unsigned integer ≥ {min})"
        ))
    })?;
    if n < min {
        return Err(SessionError::failed(format!(
            "taiji.option.invalid: --{option} {trimmed:?} must be ≥ {min}"
        )));
    }
    Ok(n)
}

/// `--out` basename sanitization (the out-of-dir write red line):
/// rejects path separators (`/` and Windows `\` — the `%5C` form can
/// escape the dir via percent-decode), absolute paths, parent-directory
/// components (`..`), drive-letter/ADS colons, and option-injection shapes
/// (a leading `-`); empty values rejected too; control characters (the Cc
/// category: C0+DEL+C1, one standard across three channels) and
/// display-spoofing / hidden-injection code points (the single source
/// [`taiji_io::text::is_spoofing_char`]: bidi overrides 12 + zero-width 3 +
/// line/paragraph separators 2 + DEL) rejected as well; byte length >
/// 255 rejected ([`MAX_OUT_BASENAME_BYTES`], aligned with taiji-bt
/// filetree's `MAX_COMPONENT_BYTES` — on a strict filesystem
/// ENAMETOOLONG = the first file create fails and rejects the whole task,
/// so explicit rejection at the acceptance face beats a silent rewrite of
/// the user's explicit name on the write face; shrinking a within-cap name
/// to the engine budget is backstopped by the naming light channel);
/// Windows naming-domain unsafe names (reserved device-name stems /
/// trailing `.`·space, [`windows_unsafe_basename`]) rejected too — one
/// cross-platform validation; metalink flattened names aggregate across
/// documents onto the same (dir,out), and explicit rejection beats a
/// silent rewrite on the write face. A legal basename returns unchanged.
/// Visibility `pub(in crate::session)`: the addUri acceptance face and the
/// migration importer (session::persist::import_http, the same-domain
/// validation of serialized `out=` rows) share one sanitization standard,
/// so the output-path invariants hold regardless of entry.
pub(in crate::session) fn sanitize_out_option(out: &str) -> Result<String, SessionError> {
    let bad = || {
        SessionError::failed(format!(
            "taiji.option.invalid: --out {out:?} must be a plain file name \
             (no path separators, no absolute path, no leading '-', at most \
             255 bytes)"
        ))
    };
    let name = out.trim();
    if name.is_empty()
        || name.starts_with('-')
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('/')
        || name.contains('\\')
        || name.contains(':')
        || name == "."
        || name == ".."
 // Control characters (the Cc category) + display-spoofing /
 // hidden-injection code points (single source; `is_control` does
 // not cover the Cf/Zl/Zp categories — rejected under the same
 // standard as control characters).
        || name.chars().any(|c| c.is_control() || is_spoofing_char(c))
        || name.len() > MAX_OUT_BASENAME_BYTES
        || windows_unsafe_basename(name)
    {
        return Err(bad());
    }
    Ok(name.to_string())
}

/// `--out` basename byte cap: the strictest cross-platform NAME_MAX, the
/// same standard as taiji-bt filetree.rs's `MAX_COMPONENT_BYTES` (255) —
/// only `>` rejects (exactly at the cap is legal). Length counted in UTF-8
/// bytes (POSIX filesystems limit by bytes; multi-byte names get no
/// char-count slack).
const MAX_OUT_BASENAME_BYTES: usize = 255;

/// `--checksum=<scheme>=<hex>` value-domain validation: scheme ∈ md5|
/// sha-1|sha-224|sha-256|sha-384|sha-512 (six hash domains, RFC 1321 +
/// FIPS 180-4 — one domain shared by the verdict face `verify_checksum`
/// and the pre-hash `TaskDigest::parse_scheme`), digest non-empty, even
/// length, all hex (the hex encoding shape matches aria2).
fn validate_checksum_value(v: &str) -> Result<(), SessionError> {
    let bad = || {
        SessionError::failed(format!(
            "taiji.option.invalid: --checksum {v:?} \
             (want md5|sha-1|sha-224|sha-256|sha-384|sha-512=<hex>)"
        ))
    };
    let Some((scheme, digest)) = v.split_once('=') else {
        return Err(bad());
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "md5" | "sha-1" | "sha-224" | "sha-256" | "sha-384" | "sha-512"
    ) {
        return Err(bad());
    }
    let digest = digest.trim();
    if digest.is_empty() || digest.len() % 2 != 0 || !digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(bad());
    }
    Ok(())
}

struct TorrentJob {
    metainfo: Arc<Metainfo>,
    tiers: Vec<(usize, String)>,
    dir: PathBuf,
    seed: SeedPolicy,
    total_len: u64,
    /// Top-level display attrs (comment / creation date / info.name; the
    /// bittorrent dict data source — the addTorrent / URL upgrade paths
    /// capture raw-byte attrs at parse time).
    attrs_top: (Option<String>, Option<i64>, Option<String>),
    /// `--max-download-limit` (0 = unlimited).
    max_download_limit: u64,
    /// `--max-upload-limit` (0 = unlimited).
    max_upload_limit: u64,
    /// Task-final hook set (runner assembled at activation).
    hooks: Arc<HookSet>,
    /// BEP53 `so=`-selected file indices (0-based client file list order,
    /// non-pad entries). None = select all (zero change to the existing
    /// task face). Pushed back via config_json through [`Self::job_config`]
    /// and delivered to the engine at activation (SetFileSelection).
    selected_files: Option<Vec<u32>>,
    /// Sparse file multi-level priority pairs (client file index 0-based →
    /// -1 skip / 0 normal / 1..7 high). None = the default face. Pushed
    /// back via config_json through
    /// [`PersistedTaskConfig::file_priorities`] and delivered at
    /// activation (SetFilePriority); RPC taiji.setFilePriority does a
    /// runtime partial update + mirror rewrite + selected_files
    /// consistency (-1 ⇔ removed from the selection set).
    file_priorities: Option<Vec<(u32, i8)>>,
    /// ut_holepunch switch (default enabled). A config_json internal face
    /// (carried by the restore chain); only a non-default value is
    /// delivered as SetHolepunch(false) at activation.
    holepunch: bool,
    /// Scheduler policy (default rarest_first). A config_json internal
    /// face (carried by the restore chain); only a non-default value is
    /// delivered as SetSchedulerPolicy at activation; RPC
    /// taiji.setSchedulerPolicy switches at runtime + mirror rewrite.
    scheduler_policy: crate::engine::SchedulerPolicy,
    /// Disk protection tier override (`throughput|ssd-protect|
    /// hdd-sequential`; None = the default throughput tier). A config_json
    /// internal face (no RPC/CLI option promised, carried by the restore
    /// chain); injected into `EngineConfig.disk_policy` at activation via
    /// `taiji_store::disk_policy::DiskPolicy::resolve` (an unknown name
    /// warns on the resolve side and degrades to the default tier).
    disk_tier: Option<String>,
    /// The `bt-disable-dht` flag (the counterpart of libtorrent's
    /// `torrent_flags::disable_dht`). **None = follow the session
    /// `enable-dht`** (session hot reload follows along); Some = a
    /// task-level override (true disables / false forces; the private flag
    /// is still suppressed by the BEP27 engine gate). A config_json
    /// internal face (carried by the restore chain); injected into
    /// `EngineConfig.dht.enabled` at activation, and live tasks hot-apply
    /// via the engine's `SetDhtEnabled` (the changeOption live arm).
    bt_disable_dht: Option<bool>,
    /// `enable-http-seeding` (BEP19 webseeding; **None = default true** =
    /// the metainfo url-list projection unchanged). false = clear the
    /// webseed set at activation (BT-only; the url-list original is not
    /// lost in metainfo). A config_json internal face (carried by the
    /// restore chain); effective at activation via build_engine_config's
    /// `webseeds.clear`; changeOption rides restart semantics (an engine
    /// hot push belongs to the webseeding engine integration face).
    enable_http_seeding: Option<bool>,
}

struct MagnetJob {
    magnet_uri: String,
    dest: PathBuf,
    options: MagnetOptions,
    seed: SeedPolicy,
    btih: Option<[u8; 20]>,
    btmh: Option<[u8; 32]>,
    /// magnet `tr` (one tier per tr; the bittorrent dict announceList data
    /// source).
    tiers: Vec<(usize, String)>,
    /// The BEP53 selection face's first source: the RPC `select-file`
    /// option value (**0-based**; the add and changeOption reserved faces
    /// convert at the single point
    /// [`crate::session::options::parse_select_file`]; mutually exclusive
    /// with the magnet URI `so=` — coexistence is an explicit conflict
    /// rejection). The effective selection's merge single point =
    /// [`super::magnet::effective_magnet_selection`] (shared by the
    /// persistence / residency / upgrade chains); None = no option source
    /// (falls back to the URI so=).
    selected_files: Option<Vec<u32>>,
    /// Scheduler policy (a projection of the `bt-sequential-download`
    /// option value; the authoritative face = taiji.setSchedulerPolicy).
    /// Carried by the metadata phase; the upgrade chain projects it into
    /// the torrent task payload via job_config.
    scheduler_policy: crate::engine::SchedulerPolicy,
    /// `--max-download-limit` (0 = unlimited).
    max_download_limit: u64,
    /// `--max-upload-limit` (0 = unlimited).
    max_upload_limit: u64,
    /// Task-final hook set (runner assembled at activation).
    hooks: Arc<HookSet>,
    /// In-place upgrade completed (consumed by the upgrade notice face;
    /// the anchor deciding whether SPEC §7.1's followedBy/following fields
    /// are served — not during the metadata phase, served after the
    /// upgrade).
    upgraded: bool,
    /// The `bt-disable-dht` flag (None = follow the session). Gates the
    /// metadata-phase DHT lease (ahead of spawn_phase_dht) and synthesizes
    /// the upgraded engine's DHT switch (the MagnetTaskConfig.dht_enabled
    /// synthesis point); the changeOption live arm hot-applies to the
    /// upgraded engine (the metadata phase has no engine handle — consumed
    /// by the upgrade chain; the declared face).
    bt_disable_dht: Option<bool>,
    /// `enable-http-seeding` (BEP19; None = default true). The metadata
    /// phase has no webseed face (url-list belongs to .torrent); the
    /// upgraded engine clears at the same point via
    /// MagnetTaskConfig.webseeding_enabled (the same rule as the torrent
    /// activation path's build_engine_config); it rides the payload
    /// through upgrade residency / in-place torrent conversion.
    enable_http_seeding: Option<bool>,
}

/// Task terminal states / intermediate products (internal event payloads;
/// watcher tasks → the actor main loop).
enum TaskOutcome {
    Engine(EngineEnd),
    Magnet(MagnetEnd),
    /// .torrent URL metadata fetch success (the in-place upgrade input).
    Fetched(Vec<u8>),
    /// .torrent URL metadata fetch failure.
    FetchFailed(String),
    /// The metadata phase was cancelled (mid pause/remove/shutdown).
    Cancelled,
    /// HTTP task teardown (Done (including renamePending) / Error /
    /// pause-remove-shutdown cancellation).
    Http(http_task::HttpEnd),
    /// Media task teardown: Done / Failed / Paused (with the
    /// §3.2 phase memory) / Cancelled / DirectLink (the entry
    /// classification's HTTP-family conversion).
    Media(crate::session::media::MediaEnd),
}

/// watcher → actor internal events (engine/task teardown notices; a
/// different face from the outbound event bus `super::events::SessionEvent`
/// — this is the actor's private control flow).
enum TaskNotice {
    Ended {
        gid: Gid,
        outcome: TaskOutcome,
    },
    /// magnet in-place upgrade complete (the
    /// [`MagnetEngine::spawn_with_upgrade_notify`] notice face) — the
    /// session mounts the upgraded engine handle (live readings) + sets
    /// the upgraded flag (followedBy/following served as given, SPEC
    /// §7.1).
    MagnetUpgraded {
        gid: Gid,
        handle: crate::engine::EngineHandle,
    },
    /// On-disk recheck complete (the spawn_blocking completion receipt of
    /// every check-pool member — addTorrent's complete-payload initial
    /// recheck / forceRecheck / bootstrap-recovered rows, all promoted
    /// through check_pending by pump_check's budget gate since the
    /// check pool landed).
    /// Payload = the session::recheck result (verified bitfield / stats /
    /// suspended set) — the actor side writes the progress row back and
    /// routes per the measured bitmap (seed side / reserved requeue).
    RecheckDone {
        gid: Gid,
        outcome: Box<Result<crate::session::recheck::RecheckOutcome, String>>,
    },
    /// Engine-face status transition signal (at BtComplete's
    /// completion-flips-to-seeding moment; enqueued synchronously by the
    /// engine thread's hook relay closure — the tasks.rs notify face). A
    /// BT download completing is not task teardown: the task stays
    /// resident seeding, `Ended` does not arrive, so the status snapshot
    /// cache must be dropped by this signal (the run event arm) —
    /// otherwise the first post-completion poll hits the pre-completion
    /// sample (a 0-byte snapshot, violating [`STATUS_CACHE_TTL`]'s
    /// "post-event queries read post-event truth" invariant). The payload
    /// is only the gid: no teardown semantics, `running` is not removed.
    StatusDirty {
        gid: Gid,
    },
    /// Completion flipped to seeding (the seed-pool
    /// transfer trigger): enqueued at the same hook-relay point as
    /// [`TaskNotice::StatusDirty`] (the engine thread's synchronous
    /// BtComplete notify closure; zero new channel — the frozen engine
    /// protocol face's net addition is this one notice over the existing
    /// relay). The actor arm moves the gid active → seeding (queue
    /// accounting only; `running` keeps the engine/token/cache) and
    /// releases the download slot immediately. Idempotent by
    /// construction (`QueueMan::begin_seeding` only transfers a current
    /// active resident): a duplicate arrival — or the
    /// seed-after-complete=false race where `Ended` lands first and the
    /// task already finalized — is a silent no-op, both orders reaching
    /// the same Complete + results terminal (§4.1.6).
    SeedingStarted {
        gid: Gid,
    },
    /// Media task reached the Downloading → Processing synthesis
    /// boundary (the synthesis-pool transfer trigger):
    /// enqueued by the driver through the gate's arrival face (the
    /// media gate pair constructed at spawn_media_driver — the frozen
    /// media-driver face's net addition is this one notice + the
    /// oneshot permit back-course; zero new polling). The actor arm
    /// moves the gid active → proc_wait (the download slot releases
    /// and backfills in the same tick) and pump_all's synthesis
    /// segment grants the budget-gated permit (proc_wait →
    /// processing). Idempotent (`QueueMan::begin_synthesis_park` only
    /// transfers a current active resident); a notice racing the
    /// remove/Ended is a silent no-op — the driver's gate await loses
    /// the token race and the teardown lands through the normal
    /// paths.
    SynthesisGate {
        gid: Gid,
    },
}

impl TaskNotice {
    /// The owning task's gid (the event arm drops that task's status
    /// snapshot cache accordingly).
    fn gid(&self) -> Gid {
        match self {
            TaskNotice::Ended { gid, .. }
            | TaskNotice::MagnetUpgraded { gid, .. }
            | TaskNotice::RecheckDone { gid, .. }
            | TaskNotice::StatusDirty { gid }
            | TaskNotice::SeedingStarted { gid }
            | TaskNotice::SynthesisGate { gid } => *gid,
        }
        // (Media outcomes ride TaskNotice::Ended — no separate arm.)
    }
}

/// bootstrap single-row rebuild result (dispatch in
/// [`SessionActor::rebuild_from_row`]).
enum Rebuilt {
    /// torrent payload: (metainfo, tracker table); the metadata BLOB is
    /// authoritative from the in-DB row. Box: since BEP19 Metainfo carries
    /// url_list (a Vec), the variant size difference crosses clippy's
    /// large_enum_variant threshold — the rebuild path allocates once per
    /// row, so boxing it fits.
    Torrent(Box<(Metainfo, Vec<(usize, String)>)>),
    /// magnet URI (metadata missing → return to the metadata state and
    /// rerun ut_metadata).
    Magnet(String),
    /// No metadata and no magnet URI (a corrupted row; degraded to an
    /// error result row).
    Unrecoverable(String),
}

/// SessionActor: queue scheduling and the command entry point.
pub struct SessionActor {
    cmd_rx: mpsc::Receiver<SessionEnvelope>,
    events: mpsc::Sender<TaskNotice>,
    event_rx: mpsc::Receiver<TaskNotice>,
    /// The six-event notification bus (broadcast(256); sends never block).
    /// Cloned through [`SessionHandle`] for subscription (the event face).
    bus: broadcast::Sender<SessionEvent>,
    gid: GidAllocator,
    token: CancellationToken,
    global: super::options::GlobalOptions,
    /// Rate-limit execution face: the global bucket is shared across tasks
    /// and hot reload applies immediately (§7.3).
    limits: SpeedLimits,
    session_id: String,
    queue: QueueMan,
    jobs: HashMap<Gid, Job>,
    running: HashMap<Gid, RunningTask>,
    /// Persistence injection (None = nothing persisted; existing tests /
    /// CLI direct-run shapes unchanged). Task registration / lifecycle row
    /// writes, bootstrap, and saveSession all go through the single
    /// PersistWriter.
    persist: Option<PersistHandle>,
    /// torrent row `queue_pos` increasing sequence (the stable key that
    /// ORDER BY restores by). bootstrap seeds from the in-DB global upper
    /// bound of `queue_pos` (monotonic across restarts —
    /// lifecycle::bootstrap; the non-persisted shape stays 0 = recounted
    /// per session, no restore order exists).
    row_seq: i64,
    /// Row mirror: gid → the most recently persisted payload (row + file
    /// set). A state transition only rewrites state/config — the write
    /// side's row-level comparison skip-write is preserved; not the source
    /// of truth (the row lives in the DB), it only spares re-assembly at
    /// every transition.
    rows: HashMap<String, (TorrentRow, Vec<TorrentFileRow>)>,
    /// Metrics counter face: actor feed points (terminal completions /
    /// panics) + shared with the rpc render face via SessionHandle.
    metrics: Arc<SessionMetrics>,
    /// Session-level LSD service handle (lazily spawned when bt-lsd=true
    /// and first needed — aria2's receiver is a process-level singleton,
    /// the BtSetup.cc shape; None = not enabled or a startup-failure
    /// degrade). All torrent/magnet tasks share the announce face and the
    /// subscribe consumption face.
    lsd: Option<taiji_bt::lsd::LsdHandle>,
    /// Tasks currently announcing, gid → v1 infohash (the withdraw basis;
    /// withdrawn at task teardown — pause requeue / upgrade residency
    /// alike, re-announced per the gate on re-activation).
    lsd_announced: HashMap<Gid, [u8; 20]>,
    /// Manual ban bookkeeping (the taiji.banAddr face; the in-memory
    /// source of truth, the persistent mirror = peer_ban rows with
    /// reason=manual. Automatic / client bans are accounted and persisted
    /// by engines, not mirrored on the session side).
    manual_bans: Vec<ManualBan>,
    /// Metadata mirror health table (shared across magnet tasks; in-memory
    /// source of truth, not persisted — one retry round after restart
    /// costs very little). The template set is snapshotted per task from
    /// `global`; health state continues per template string (a hot-swapped
    /// list keeps memory).
    web_health: Arc<crate::magnet::WebMirrorHealth>,
    /// NAT singleton supervisor (powered at spawn_with_persist when either
    /// `--bt-enable-upnp`/`--bt-enable-nat-pmp` is on — SPEC §3.2's one
    /// NatActor per process; SPEC §6.8). The engine clone injects into
    /// activated engines via `EngineConfig::nat` (once listen-port is
    /// settled the engine triggers Map + the external-port watch linkage —
    /// the existing assemble/tick consumers); the shutdown face =
    /// [`Self::shutdown_routine`] unmap + stop pumping. None = both
    /// switches off (the existing nat: None shape unchanged).
    nat: Option<crate::nat::NatSupervisor>,
    /// Recovery event bus (taiji.recoveryStarted/Completed;
    /// broadcast(256) — capacity / backpressure / lag-disconnect semantics
    /// identical to the six-event bus, see the events module doc's
    /// extension-bus section).
    recovery_bus: broadcast::Sender<RecoveryEvent>,
    /// started exactly-once dedup bookkeeping (per gid per session
    /// lifetime): the engine emits Started at every activation, this
    /// bookkeeping only admits the first — "repeated activation does not
    /// re-emit" (the settled standard); a session rebuild = new
    /// bookkeeping = a rebuild re-emits. The Arc<Mutex> is required for
    /// relay closure sharing (the closure is a sync callback in engine
    /// context, no await in the critical section).
    recovery_notified: Arc<std::sync::Mutex<HashSet<Gid>>>,
    /// Metadata-phase session-level IpGuard snapshot handle.
    /// Injected into magnet task construction via
    /// [`crate::magnet::MagnetTaskConfig::ip_guard`] (a uniform ban gate
    /// for spawn_dial's four-way dialing); the hot-reload face = a
    /// re-stored snapshot at ban config change points (the
    /// push_all_ban_configs extension), live tasks read the latest
    /// arc-swap snapshot at each dial. Engines' own BanBook snapshot faces
    /// are unaffected (this handle only serves the metadata phase; the
    /// per-engine automatic-ban ledger / ipfilter read-back remain
    /// engine-local; the metadata-phase snapshot covers the session
    /// management face — manual bans + lists, the standard noted in
    /// refresh_meta_guard).
    meta_guard: IpGuardHandle,
    /// renamePending closeout registry (the in-process half): a task
    /// finishing Done+pending registers its row facts and periodic polling
    /// idempotently closes them on disk; rows read back at bootstrap with
    /// a pending closeout register too. Row deletion (remove) removes the
    /// entry.
    http_rename_pending: HashMap<Gid, taiji_store::persist::HttpTaskRow>,
    /// Per-host connection cap registry: one session-level instance, all
    /// HTTP tasks share the Arc — in-flight connections to the same host
    /// count across tasks. The cap is adjusted at runtime by the addUri
    /// option `http-max-per-host` (a session-level effective value,
    /// last-set-wins — the convergence semantics of multiple tasks with
    /// different values).
    http_per_host: taiji_http::perhost::HostCap,
    /// Recheck-in-progress progress readings: gid → verified piece count
    /// (an atomic counter fed per piece by `session::recheck`). The
    /// checking projection domain of tellActive/tellStatus projects
    /// completedLength as `verified pieces × piece_length` (min-clamped to
    /// total) — the same direction as aria2's during-verification byte
    /// projection. A task not registered = no projection (the entry
    /// leaves at completion).
    checking_progress: HashMap<Gid, Arc<std::sync::atomic::AtomicU64>>,
    /// forceRecheck's deferred-registration mark for active tasks: until
    /// the stop (pause teardown) completes, the task is still on the
    /// active face — the recheck must wait for the engine teardown event
    /// to land before registering (consumed by handle_ended; bitmap
    /// semantics: marked = that gid moves into checking immediately after
    /// its teardown requeue). The forceRecheck **Seeding arm** reuses the
    /// same mark: the seeding registry entry stays operable (find /
    /// pause / remove) with its slot released while the stop is in
    /// flight; the consume at Ended moves it into checking.
    checking_deferred: HashSet<Gid>,
    /// Seed-budget park mark (the seed-domain
    /// twin of `checking_deferred`): a completion that arrived against a
    /// full seed budget was gracefully stopped; when its `Ended` lands,
    /// the task must **not** enter results — it parks in the seed_wait
    /// FIFO instead (consumed by handle_ended / shutdown_routine; a user
    /// pause/remove flag set inside the stop window wins over the park).
    seed_wait_deferred: HashSet<Gid>,
    /// Complete-content provenance for waiting members (the park /
    /// unpark routing face, §4.1.3): gids whose measured content is
    /// complete and were parked out of the seed family by a user pause.
    /// Membership routes unpause to the **seed side** (reactivation
    /// occupies a seed slot, never a download slot — the activate
    /// pipeline stays untouched). Cleared at re-entry into seeding,
    /// removal, terminal end, and entry into checking.
    seed_parked: HashSet<Gid>,
    /// Media extension event bus (`taiji.media.phaseChanged`, the
    /// bypass face; broadcast(EVENT_BUS_CAPACITY) — the same
    /// topology/backpressure policy as the six-event and recovery
    /// buses).
    media_bus: broadcast::Sender<crate::session::events::MediaEvent>,
    /// Task-cookie alert bus (`taiji.task.cookiesClearedOnError` —
    /// the same bypass topology as the
    /// media bus): published when an error terminal clears a task's
    /// cookies (runtime and the startup-GC residue sweep alike).
    cookie_bus: broadcast::Sender<crate::session::events::TaskCookieEvent>,
    /// The probe action face (§4/§10 #7): the token cache + the
    /// in-flight cap + the per-origin rate ledger.
    probe_face: Arc<crate::session::media::ProbeFace>,
    /// The session's ffmpeg discovery cache (None = not yet
    /// discovered; Some(None) = discovered absent — one discovery
    /// per session, the discovery assertion face is expensive).
    media_ffmpeg: Arc<std::sync::Mutex<Option<Option<taiji_media::FfmpegRuntime>>>>,
    /// Synthesis-gate permit ends: gid → the
    /// permit half of the gate pair created at spawn_media_driver.
    /// pump_all's synthesis segment pops the end and fires it per
    /// budget-gated promotion (proc_wait → processing); cleanup rides
    /// the same faces that clear the synthesis registries (the Ended
    /// consume, the remove/force arms, the shutdown dispatch) — an
    /// un-granted permit must never outlive its driver.
    media_gate_tx: HashMap<Gid, crate::session::media::SynthesisGatePermit>,
}

/// SessionActor control handle: held by the RPC layer / CLI.
pub struct SessionHandle {
    cmd_tx: mpsc::Sender<SessionEnvelope>,
    events: broadcast::Sender<SessionEvent>,
    /// Recovery extension event bus (taiji.*; the same topology as the
    /// six-event bus).
    recovery_bus: broadcast::Sender<RecoveryEvent>,
    /// Media extension event bus (`taiji.media.phaseChanged`; the same
    /// topology as the six-event bus — the bypass design).
    media_bus: broadcast::Sender<crate::session::events::MediaEvent>,
    /// Task-cookie alert bus (`taiji.task.cookiesClearedOnError`;
    /// the same bypass topology as the media bus).
    cookie_bus: broadcast::Sender<crate::session::events::TaskCookieEvent>,
    /// Session-level metrics counter face (atomics only; the rpc /metrics
    /// render data source).
    metrics: Arc<SessionMetrics>,
    /// NAT consumption face clone (the watch snapshot reading slot; None =
    /// unpowered). The RPC render face (mapping state / external ports to
    /// JSON) consumes this reading along the rpc track.
    nat: Option<crate::nat::NatEngine>,
}

impl SessionHandle {
    /// Submit a command and await the receipt. Returns
    /// [`SessionError::SessionClosed`] once the actor has exited.
    pub async fn call(&self, cmd: SessionCommand) -> Result<CommandReply, SessionError> {
        let (tx, rx) = oneshot::channel();
        let env = SessionEnvelope { cmd, reply: tx };
        self.cmd_tx
            .send(env)
            .await
            .map_err(|_| SessionError::SessionClosed)?;
        rx.await.map_err(|_| SessionError::SessionClosed)?
    }

    /// Metrics counter face: the rpc `/metrics` render reads
    /// [`MetricsSnapshot`](super::metrics::MetricsSnapshot) through this.
    /// Atomic reads, lock-free, no await — never occupies the command
    /// channel.
    pub fn metrics(&self) -> &Arc<SessionMetrics> {
        &self.metrics
    }

    /// External port snapshot (a watch borrow, atomic lock-free read
    /// without await — the same standard as metrics; None = NAT
    /// unpowered). One slot per tcp/udp; a None slot = that protocol
    /// unmapped (the announce standard falls back to listen-port, the
    /// [`crate::nat::ExternalPorts::effective`] consumer).
    pub fn nat_external_ports(&self) -> Option<crate::nat::ExternalPorts> {
        self.nat.as_ref().map(|e| e.external_ports())
    }

    /// Subscribe to the six-event notification bus (the event face). Each
    /// subscriber has an independent lag count: one falling more than
    /// [`EVENT_BUS_CAPACITY`] behind receives `RecvError::Lagged` (the rpc
    /// WS policy = warn then disconnect that subscriber). With no
    /// subscribers the publisher spins free (sends are dropped, the same
    /// as aria2's notification semantics).
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }

    /// Subscribe to the recovery extension event bus
    /// (`taiji.recoveryStarted/Completed`). Topology / backpressure
    /// semantics match [`Self::subscribe_events`]: capacity
    /// [`EVENT_BUS_CAPACITY`], falling more than that behind receives
    /// `RecvError::Lagged` (the same rpc WS policy — warn then
    /// disconnect), with no subscribers the publisher spins free.
    pub fn subscribe_recovery_events(&self) -> tokio::sync::broadcast::Receiver<RecoveryEvent> {
        self.recovery_bus.subscribe()
    }

    /// Subscribe to the media extension event bus
    /// (`taiji.media.phaseChanged` + the warning payloads riding the
    /// same face). Topology / backpressure semantics match
    /// [`Self::subscribe_events`] (the same rpc WS policy).
    pub fn subscribe_media_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::session::events::MediaEvent> {
        self.media_bus.subscribe()
    }

    /// Subscribe to the task-cookie alert bus
    /// (`taiji.task.cookiesClearedOnError` — the
    /// error-terminal cookie clear's alarm face, both task families).
    /// Topology / backpressure semantics match [`Self::subscribe_events`]
    /// (the same rpc WS policy).
    pub fn subscribe_task_cookie_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::session::events::TaskCookieEvent> {
        self.cookie_bus.subscribe()
    }

    /// Graceful shutdown: send the Shutdown command and await the receipt.
    /// The propagation chain's 1s budget is enforced by the caller via the
    /// actor JoinHandle (CLI and tests own this).
    pub async fn shutdown(&self) {
        match self.call(SessionCommand::Shutdown).await {
            Ok(CommandReply::Accepted) => {}
            other => {
                warn!(target: "taiji::core::session", reply = ?other, "unexpected shutdown reply")
            }
        }
    }
}
impl SessionActor {
    /// Start a SessionActor (all-default options).
    pub fn spawn() -> (SessionHandle, tokio::task::JoinHandle<()>) {
        Self::spawn_with(Default::default())
    }

    /// Start a SessionActor (CLI injects global options / secret; tests
    /// inject queue parameters).
    pub fn spawn_with(
        options: super::options::SessionOptions,
    ) -> (SessionHandle, tokio::task::JoinHandle<()>) {
        Self::spawn_with_persist(options, None)
    }

    /// Start a SessionActor + persistence injection: after the
    /// PersistWriter is ready, session bootstrap (startup rebuild), task
    /// row writes, and saveSession all go through this handle (the single
    /// writer).
    pub fn spawn_with_persist(
        options: super::options::SessionOptions,
        persist: Option<PersistHandle>,
    ) -> (SessionHandle, tokio::task::JoinHandle<()>) {
        // Capacity 64: RPC commands are low-frequency; full = backpressure
        // on the caller.
        let (cmd_tx, cmd_rx) = mpsc::channel::<SessionEnvelope>(64);
        let (events, event_rx) = mpsc::channel::<TaskNotice>(EVENT_CHANNEL_CAPACITY);
        // Six-event bus: broadcast sends synchronously without blocking
        // (full = slow subscribers lag).
        let (bus, _) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);
        // Recovery extension event bus (the same topology in parallel —
        // the payload carries a file set and SessionEvent's frozen shape
        // cannot extend).
        let (recovery_bus, _) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);
        // Media extension event bus (the bypass face — same topology
        // in parallel).
        let (media_bus, _) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);
        // Task-cookie alert bus (the same bypass
        // topology).
        let (cookie_bus, _) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);
        let global = options.global;
        // The per-host cap's initial value comes from the global option
        // (previously always HostCap::default — the CLI/global option
        // never reached session initialization, so under attach-restore a
        // CLI --http-max-per-host was silently dropped and the only
        // effective channel was the addUri option. After the closeout the
        // initialization face takes the CLI/global injection; addUri's
        // runtime last-set-wins semantics are unchanged — task-level
        // overrides still win). new clamps to ≥1.
        let http_per_host = taiji_http::perhost::HostCap::new(global.http_max_per_host);
        let limits = SpeedLimits::new(
            global.max_overall_download_limit,
            global.max_overall_upload_limit,
        );
        let metrics = Arc::new(SessionMetrics::new());
        // NAT powering face (ahead of bootstrap — options → NatConfig →
        // the singleton supervisor). Both switches off = None (the
        // existing zero change); either on = spawn_supervisor (the actor
        // task starts but has zero network face — it only picks a path /
        // discovers when a Map command arrives, the io nat semantics),
        // with the engine clone going into SessionHandle (snapshot
        // readings) + the actor (shutdown unmap + activation injection).
        let nat = if global.nat_enabled() {
            Some(crate::nat::spawn_supervisor(global.build_nat_config()))
        } else {
            None
        };
        let handle_nat = nat.as_ref().map(|s| s.engine());
        let actor = SessionActor {
            cmd_rx,
            events,
            event_rx,
            bus: bus.clone(),
            gid: GidAllocator::new(),
            token: CancellationToken::new(),
            session_id: random_session_id(),
            queue: QueueMan::new(),
            jobs: HashMap::new(),
            running: HashMap::new(),
            global,
            limits,
            persist,
            // Initial 0 = the pre-seed origin; the persisted shape
            // overwrites it in bootstrap with the in-DB max(queue_pos)
            // upper bound (a monotonic key across restarts).
            row_seq: 0,
            rows: HashMap::new(),
            metrics: Arc::clone(&metrics),
            lsd: None,
            lsd_announced: HashMap::new(),
            manual_bans: Vec::new(),
            web_health: Arc::new(crate::magnet::WebMirrorHealth::new()),
            nat,
            // Metadata-phase session-level snapshot (an empty face at
            // startup = no address banned; bootstrap_ban_face seeds manual
            // bans after read-back; the hot-reload face is
            // refresh_meta_guard). Also pre-warms the local address set
            // snapshot (enumerated once at process start — getifaddrs
            // completes in sync context; the dialing hot path only reads).
            meta_guard: IpGuardHandle::new(Default::default()),
            http_rename_pending: HashMap::new(),
            http_per_host,
            checking_progress: HashMap::new(),
            checking_deferred: HashSet::new(),
            seed_wait_deferred: HashSet::new(),
            seed_parked: HashSet::new(),
            recovery_bus: recovery_bus.clone(),
            recovery_notified: Arc::new(std::sync::Mutex::new(HashSet::new())),
            media_bus: media_bus.clone(),
            cookie_bus: cookie_bus.clone(),
            probe_face: Arc::new(crate::session::media::ProbeFace::new()),
            media_ffmpeg: Arc::new(std::sync::Mutex::new(None)),
            media_gate_tx: HashMap::new(),
        };
        let _ = crate::engine::addr_hygiene::LocalIpSet::shared();
        let join = tokio::spawn(async move {
            actor.run().await;
        });
        (
            SessionHandle {
                cmd_tx,
                events: bus,
                recovery_bus,
                media_bus,
                cookie_bus,
                metrics,
                nat: handle_nat,
            },
            join,
        )
    }

    /// Six-event publish point: broadcast sends return synchronously — no
    /// subscribers = spins free (SendError is a drop, matching aria2's
    /// notification semantics); full does not block and the slowest
    /// subscriber enters lag (backpressure is never pushed onto engines).
    fn publish(&self, gid: Gid, kind: EventKind) {
        // Err = no subscribers: a notice nobody consumes is dropped (the
        // same shape as aria2 with no WS session).
        let _ = self.bus.send(SessionEvent { gid, kind });
    }

    /// Recovery event relay closure (the HookRunner recovery notice slot →
    /// extension event bus). Engine payloads are stamped with the task gid
    /// before entering the bus:
    /// - `Started`: exactly once per gid per session lifetime (the engine
    /// emits at every activation, this closure only admits the first via
    /// `recovery_notified` — the "repeated activation does not re-emit"
    /// design standard; a session rebuild = new bookkeeping = re-emits);
    /// - `Completed`: not deduplicated (a convergence-wave event — legal
    /// across activations, see the recovery_admit module docs).
    pub(super) fn recovery_relay(&self, gid: Gid) -> Arc<dyn Fn(RecoveryNotice) + Send + Sync> {
        let bus = self.recovery_bus.clone();
        let seen = Arc::clone(&self.recovery_notified);
        Arc::new(move |notice: RecoveryNotice| {
            let ev = RecoveryEvent {
                gid,
                kind: notice.kind,
                files: notice.files,
            };
            match notice.kind {
                RecoveryEventKind::Started => {
                    let mut seen = crate::lock(&seen);
                    if seen.insert(gid) {
                        let _ = bus.send(ev);
                    }
                }
                RecoveryEventKind::Completed => {
                    let _ = bus.send(ev);
                }
            }
        })
    }

    /// The session-level LSD service readiness face for bt-lsd (lazy
    /// spawn). aria2 builds the receiver at the first BT download's
    /// BtSetup and reuses the BtRegistry entry (BtSetup.cc
    /// `if (!btReg->getLsdMessageReceiver)` singleton-isomorphic);
    /// here the spawn happens at the first task that needs it, and the
    /// handle lives until session teardown (drop -> command channel
    /// closed -> service loop exits). A spawn failure (port in use
    /// etc.) = warn and degrade to running without LSD (aria2
    /// "LpdMessageReceiver not initialized", BtSetup.cc same
    /// rule — no fake capability).
    async fn lsd_ready(&mut self) -> Option<taiji_bt::lsd::LsdHandle> {
        if !self.global.bt_lsd {
            return None;
        }
        if let Some(h) = self.lsd.as_ref() {
            return Some(h.clone());
        }
        match taiji_bt::lsd::spawn(&taiji_bt::lsd::LsdConfig {
            enabled: true,
            ..taiji_bt::lsd::LsdConfig::default()
        })
        .await
        {
            Ok(Some((h, addr, _join))) => {
                info!(target: "taiji::core::session", bind = %addr,
                    "lsd service up (BEP14 multicast 239.192.152.143:6771)");
                self.lsd = Some(h.clone());
                Some(h)
            }
            Ok(None) => None, // bt-lsd hot-reload race defense (the option face already off).
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "lsd service init failed; running WITHOUT lsd (aria2 BtSetup.cc, same behavior)");
                None
            }
        }
    }

    /// Withdraw the LSD announce at task teardown (the same rule as aria2
    /// stopping the dispatcher at group teardown). Covers pause requeue /
    /// magnet upgrade residency / remove / natural terminal states;
    /// re-activation re-announces per the gate. If the service already
    /// finished (a session-exit race), withdraw's send failure is silent —
    /// the bookkeeping is dropped along with it.
    async fn lsd_withdraw(&mut self, gid: Gid) {
        let Some(h) = self.lsd.as_ref() else {
            self.lsd_announced.remove(&gid);
            return;
        };
        let mut hashes: Vec<[u8; 20]> = Vec::new();
        if let Some(ih) = self.lsd_announced.remove(&gid) {
            hashes.push(ih);
        }
        // The magnet metadata phase's announce is self-driven inside
        // magnet.rs (v1 face only), so the bookkeeping closes on the btih
        // (never announced = withdraw is a no-op, harmless).
        if let Some(Job::Magnet(mj)) = self.jobs.get(&gid) {
            if let Some(btih) = mj.btih {
                hashes.push(btih);
            }
        }
        for ih in hashes {
            let _ = h.withdraw(ih).await;
        }
    }

    async fn run(mut self) {
        info!(target: "taiji::core::session",
            "session actor up (queue + lifecycle command surface)");
        // The globally imported tracker set ready (in-DB restore + the
        // CLI-injected bt-tracker/bt-tracker-file initial import +
        // incremental persistence) — before task bootstrap, so rebuilt
        // tasks get the three-layer merge injected at first activation.
        self.bootstrap_global_trackers().await;
        // Ban face ready (the client_ban_prefixes kv restore + manual ban
        // peer_ban row read-back) — before task bootstrap, so rebuilt
        // tasks carry the current rules at first activation.
        self.bootstrap_ban_face().await;
        // Startup bootstrap (SPEC §5.4): PersistWriter ready → active set
        // read-back → per-task rebuild (GID reserve / missing metadata
        // returns to the metadata state).
        self.bootstrap().await;
        self.pump_all().await;
        // The input face for the LSD announce port's external-port follow
        // (the existing cadence consuming the watch snapshot — the same
        // source as the engine's 2s tick DHT linkage; None = unpowered,
        // the select arm suspends forever, zero behavior change). The
        // initial value = the snapshot at subscription time (the same
        // source and base as the tasks.rs activation path), preventing a
        // spin refresh from the watch's missed initial event.
        let mut nat_ports_rx = self
            .nat
            .as_ref()
            .map(|s| s.engine().subscribe_external_ports());
        let mut lsd_announce_port = self.nat.as_ref().map(|s| {
            crate::nat::resolve_announce_port(
                Some(s.engine().external_ports()),
                self.global.listen_port,
            )
        });
        // The renamePending closeout poll cadence (the in-process half —
        // while the registry is non-empty, retry the on-disk closeout
        // every 5s; the empty-table arm returns immediately at zero
        // cost).
        let mut closeout_tick = tokio::time::interval(CLOSEOUT_POLL_INTERVAL);
        closeout_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The periodic task summary cadence (`--summary-interval`; a
        // startup-time option — takes effect on restart, this cadence is
        // assembled once at spawn). 0 = disabled → the arm suspends
        // forever (zero cost); the first summary comes after one full
        // period (`interval_at` pacing, without tokio interval's immediate
        // first tick — no empty summary at startup).
        let summary_period = u64::from(self.global.summary_interval);
        let mut summary_tick = (summary_period > 0).then(|| {
            let period = std::time::Duration::from_secs(summary_period);
            let mut t = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            t
        });
        // The periodic session-save cadence (`--save-session-interval`,
        // domain C; the reference `OptionHandlerFactory.cc`
        // default "0" = disabled). Effective face = a full flush every N
        // seconds (task-row/HTTP-row flush + `--save-session` text
        // export + WAL checkpoint — the same `save_session` entry point
        // as graceful shutdown). The assembly condition includes the
        // persistence layer being present (save_session fails explicitly
        // without a store — no periodic warning noise); 0 = the arm
        // suspends forever (the summary_tick shape); a failure only
        // warns and does not break the loop (the shutdown backstop arm
        // still closes out). The first save also comes after one full
        // period (bootstrap just flushed at startup — no duplicate).
        let save_period = self.global.save_session_interval_secs;
        let mut save_tick = (save_period > 0 && self.persist.is_some()).then(|| {
            let period = std::time::Duration::from_secs(save_period);
            let mut t = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            t
        });
        loop {
            tokio::select! {
                           biased;
                           _ = self.token.cancelled() => break,
                           env = self.cmd_rx.recv() => match env {
                               None => break, // senders dropped: SessionHandle released → graceful shutdown
                               Some(env) => {
                                   let SessionEnvelope { cmd, reply } = env;
                                   if self.handle_command(cmd, reply).await {
                                       break;
                                   }
                               }
                           },
                           _ = closeout_tick.tick() => {
                               self.poll_rename_pending().await;
                           }
                           _ = async {
                               match summary_tick.as_mut() {
                                   Some(t) => {
                                       t.tick().await;
                                   }
            // Disabled shape (summary_interval = 0): the arm
            // suspends forever (the same pattern as the nat
            // watch None arm).
                                   None => std::future::pending::<()>().await,
                               }
                           } => {
                               self.emit_summary().await;
                           }
                           _ = async {
                               match save_tick.as_mut() {
                                   Some(t) => {
                                       t.tick().await;
                                   }
            // Disabled shape (save-session-interval = 0 or
            // the persistence layer absent): the arm suspends
            // forever (the same pattern as the summary_tick
            // None arm).
                                   None => std::future::pending::<()>().await,
                               }
                           } => {
            // Periodic full flush (the sole consumption point of
            // `--save-session-interval`; a failure warns and does
            // not exit — the next period retries, and the shutdown
            // backstop arm still performs the final closing
            // flush).
                               if let Err(e) = self.save_session().await {
                                   warn!(target: "taiji::core::session", e = %e,
                                       "periodic session save failed");
                               }
                           }
                           ev = self.event_rx.recv() => match ev {
                               None => break,
                               Some(notice) => {
            // Status snapshot cache invalidation face (the
            // compensation half of the cache-first read seam;
            // trade-offs under STATUS_CACHE_TTL): any
            // TaskNotice for that gid drops the entry on
            // arrival — a query after the event (teardown /
            // recheck / upgrade / BtComplete
            // completion-flips-to-seeding) always reads
            // post-event truth, never feeding the polling face
            // stale readings (test timing determinism also
            // rides on this). Entries die with `running`
            // removal at task end/removal.
                                   if let Some(t) = self.running.get_mut(&notice.gid()) {
                                       t.backend.expire_status_cache();
                                   }
                                   match notice {
                                       TaskNotice::Ended { gid, outcome } => {
                                           self.handle_ended(gid, outcome).await;
                                       }
                                       TaskNotice::RecheckDone { gid, outcome } => {
                                           self.finish_recheck(gid, *outcome).await;
                                       }
                                       TaskNotice::StatusDirty { .. } => {
            // Invalidation was already done by the
            // generic arm above (StatusDirty's sole
            // purpose is to trigger it) — no further
            // action.
                                       }
                                       TaskNotice::SeedingStarted { gid } => {
            // Seed-pool transfer:
            // active → seeding, download slot released
            // and backfilled in the same tick.
                                           self.on_seeding_started(gid).await;
                                       }
                                       TaskNotice::SynthesisGate { gid } => {
            // Synthesis-pool transfer:
            // active → proc_wait, download slot released
            // and backfilled in the same tick; the
            // budget-gated permit fires from pump_all's
            // synthesis segment.
                                           self.on_synthesis_gate(gid).await;
                                       }
                                       TaskNotice::MagnetUpgraded { gid, handle } => {
            // Mount the upgraded engine handle (live
            // readings) + the upgraded flag
            // (followedBy/following served as given,
            // SPEC §7.1). The task already finished
            // (absent from running/jobs) = a late
            // notice, silently dropped.
                                           if let Some(t) = self.running.get_mut(&gid) {
            // Swap the backend in place (metadata
            // phase → engine shape; the cache
            // starts empty — pre-swap readings
            // belong to the metadata phase and are
            // not reusable).
                                               t.backend = TaskBackend::Engine {
                                                   engine: handle.clone(),
                                                   status_cache: None,
                                               };
            // Backfill total at upgrade (magnet
            // activation has unknown metadata so
            // total_len stays 0 — teardown
            // classification uses it as the
            // terminal entry's total/completed
            // source, and a 0 backfill fakes a
            // complete/0/0 view even when the
            // engine completed every piece). The
            // reading source = the engine query
            // seam (layout.total, which the
            // upgraded engine's loop always
            // answers; failure = the engine died
            // early, keep 0 and the teardown path
            // presents it honestly).
                                               if let Ok(snap) = handle.query_status().await {
                                                   t.total_len = snap.total_length;
                                               }
                                           }
                                           if let Some(Job::Magnet(mj)) = self.jobs.get_mut(&gid) {
                                               mj.upgraded = true;
                                           }
            // The upgraded engine also needs the ban
            // face (identity rules + manual bans; the
            // torrent activation path pushes at the
            // same point in tasks.rs).
                                           if let Some(engine) =
                                               self.running.get(&gid).and_then(|t| t.backend.engine())
                                           {
                                               self.push_ban_config(engine).await;
                                           }
                                       }
                                   }
                               }
                           },
            // External port change → refresh bt::lsd's port slot
            // (existing entries only change the port, timers untouched
            // — the semantics of bt::lsd's Announce command for an
            // already-registered infohash) → the next natural announce
            // cycle carries the new port. This arm triggers no
            // immediate resend and adds no announce cadence (re-announce
            // logic is out of scope); the unpowered shape (None)
            // suspends forever.
                           _ = async {
                               match nat_ports_rx.as_mut() {
                                   Some(rx) => {
                                       if rx.changed().await.is_err() {
            // The watch sender dropped (supervisor
            // teardown): the arm suspends forever
            // (session teardown is driven by the
            // token/command arms).
                                           std::future::pending::<()>().await
                                       }
                                   }
                                   None => std::future::pending::<()>().await,
                               }
                           } => {
                               let Some(rx) = nat_ports_rx.as_ref() else {
                                   continue;
                               };
                               let effective = crate::nat::resolve_announce_port(
                                   Some(*rx.borrow()),
                                   self.global.listen_port,
                               );
                               if Some(effective) == lsd_announce_port {
                                   continue;
                               }
                               lsd_announce_port = Some(effective);
                               if let Some(h) = self.lsd.as_ref() {
                                   for ih in self.lsd_announced.values() {
                                       let _ = h.announce(*ih, effective).await;
                                   }
                               }
                           }
                       }
        }
        self.shutdown_routine().await;
    }

    /// The four-pool promotion pump (the promotion of the
    /// former fillup-only `pump`). Fixed segment order, fillup **last**:
    /// the earlier promotions can free download slots or produce newly
    /// activatable tasks, so a last-position fillup backfills everything
    /// released this tick — no idle beat between release and backfill.
    /// Segments:
    /// 1. check promotion — check_pending admission within
    /// `max-concurrent-checks`: the parked front moves into the
    /// in-flight checking registry and the recheck spawns (the
    /// checking_progress registration lives in spawn_recheck —
    /// the ⟺ in-flight invariant); a completed recheck frees the
    /// slot and the next admission happens in the same tick's
    /// trailing pump (release-then-backfill);
    /// 2. seed promotion — seed_wait reactivation within the seed
    /// budget (FIFO; the reactivation occupies a seed slot only,
    /// never a download slot);
    /// 3. synthesis promotion — proc_wait permit admission
    /// within `media-synthesis-concurrency`: the parked front moves
    /// into the processing registry and its gate permit fires (the
    /// driver's gate await wakes and Processing truly begins inside
    /// the synthesis slot). The permit-end lookup precedes the
    /// registry move (a head whose permit end is gone = the
    /// remove-race defensive residual — the loop breaks, the Ended
    /// consume clears the entry); a flagged head (pause/remove
    /// racing the gate) never admits (`proc_wait_front`). In-flight
    /// syntheses are never evicted (narrowing does not preempt);
    /// 4. download fillup — the former `pump` body (no new engine
    /// spawns after shutdown).
    async fn pump_all(&mut self) {
        if self.token.is_cancelled() {
            return;
        }
        // (1) check promotion: admit until the budget is full or the
        // FIFO drains. Each admission pops the entry; the meta lookup
        // precedes the registry move (a parked entry whose payload
        // vanished is the defensive residual of the remove race —
        // skipped, the loop continues). In-flight rechecks are never
        // evicted: a narrowed budget only gates further admissions
        // (narrowing does not preempt). The budget is the **elastic read-side** face
        // (the elastic-budget revision): the check pool's effective admission cap
        // = its own budget + the download pool's idle slots right now
        // (`elastic_check_budget` — pure arithmetic, zero state: a
        // download appearing fills the slots, the cap falls back the
        // same tick, in-flight checks always run to completion; idle
        // seats' instant use is not a share transfer).
        let budget = elastic_check_budget(
            self.global.check_budget(),
            self.global.max_concurrent_downloads,
            self.queue.active_len(),
        );
        while let Some(entry) = self.queue.admit_next_check(budget) {
            let meta = match self.jobs.get(&entry.gid) {
                Some(Job::Torrent(tj)) => Arc::clone(&tj.metainfo),
                _ => {
                    debug!(target: "taiji::core::session", gid = %entry.gid,
                        "check promotion skipped: job payload gone (removed mid-park)");
                    continue;
                }
            };
            self.queue.insert_checking(entry.gid, entry.paused);
            // The label reads "effective" (a review note): `budget` is the
            // elastic face (base + idle seats, ≤ 2×base), which can
            // exceed the configured max-concurrent-checks — the review's
            // observability note.
            info!(target: "taiji::core::session", gid = %entry.gid,
                checking = self.queue.checking_len(), budget,
                "check_pending promotion (effective check budget = {budget})");
            self.spawn_recheck(entry.gid, meta);
        }
        // (2) seed promotion: admit seed_wait members within the budget
        // until the budget is full or the FIFO drains. Each admission
        // runs the seed-side activation (engine assembly inside the
        // seed slot).
        loop {
            let budget = self.global.seed_budget();
            let Some(gid) = self.queue.admit_next_seed(budget) else {
                break;
            };
            info!(target: "taiji::core::session", gid = %gid,
                seeding = self.queue.seeding_len(),
                "seed_wait promotion (max-concurrent-seeds = {budget})");
            self.activate_seed(gid).await;
        }
        // (3) synthesis promotion: admit proc_wait members within the
        // budget until the budget is full or the FIFO drains (flagged
        // heads included in "drains" — see `proc_wait_front`). Each
        // admission pops the permit end first, then the registry move,
        // then fires the permit (the driver wake is the Processing
        // start).
        loop {
            let budget = self.global.synthesis_budget();
            if self.queue.processing_len() >= budget {
                break;
            }
            let Some(gid) = self.queue.proc_wait_front() else {
                break;
            };
            let Some(permit) = self.media_gate_tx.remove(&gid) else {
                debug!(target: "taiji::core::session", gid = %gid,
                    "synthesis promotion deferred: permit end gone (remove race)");
                break;
            };
            let promoted = self.queue.promote_synthesis_head();
            if promoted != Some(gid) {
                // Structurally unreachable (single-threaded actor, no
                // await between the peek and the pop); defensive.
                continue;
            }
            info!(target: "taiji::core::session", gid = %gid,
                processing = self.queue.processing_len(), budget,
                "proc_wait promotion (media-synthesis-concurrency = {budget})");
            permit.grant();
        }
        // (4) download fillup + spawn backfill (the former pump body).
        let max = self.global.max_concurrent_downloads;
        let batch = self.queue.fillup(max);
        if !batch.is_empty() {
            debug!(
                target: "taiji::core::session",
                active = self.queue.active_len(), spawning = batch.len(),
                "queue fillup (max-concurrent-downloads = {max})"
            );
        }
        for gid in batch {
            self.activate(gid, None).await;
        }
    }

    /// BT engine status snapshot read seam (cache-first, behavior
    /// unchanged; shared by get_global_stat aggregation and
    /// live_status_view — zero engine round trips on the query face, the
    /// control face never dragged by the data face; the TTL and
    /// invalidation trade-offs live under [`STATUS_CACHE_TTL`]). A cache
    /// present with age ≤ TTL → return the cached snapshot directly;
    /// otherwise take the existing oneshot `query_status` and refresh the
    /// cache and sample time. Engine absent (magnet metadata phase / HTTP
    /// task) = None; engine dead (SessionClosed) = None without writing
    /// the cache — the caller falls back to the basic view / skips
    /// aggregation, the same shape as the existing failure face.
    async fn engine_status_cached(&mut self, gid: Gid) -> Option<EngineStatusSnapshot> {
        if let Some(c) = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.status_cache())
            .filter(|c| c.sampled.elapsed() <= STATUS_CACHE_TTL)
        {
            return Some(c.snap.clone());
        }
        let engine = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.engine().cloned())?;
        let snap = engine.query_status().await.ok()?;
        if let Some(t) = self.running.get_mut(&gid) {
            t.backend.store_status_cache(snap.clone(), Instant::now());
        }
        Some(snap)
    }
}

// ---- free functions ----

/// Elastic check budget (a revision of the fixed budget — pure read-side arithmetic,
/// no state/flags/timers): the check pool's admission cap is its own
/// budget plus the download pool's idle seats this instant. A download
/// activating fills the seats and the effective cap falls back in the
/// same tick (the download fillup runs in this same pump, segment 4);
/// in-flight checks are never preempted (the gate only admits).
///
/// Bounds (an adversarial-review fix): the download cap is
/// read-side clamped to the option face's domain high end (0..=64; a
/// raw out-of-domain field must not multiply the admission spike —
/// each admission is a spawn_blocking whole-torrent read+hash, and an
/// unclamped cap with an idle pool would admit the entire check_pending
/// FIFO in one pump), and the elastic component caps at the base check
/// budget: the effective cap never exceeds 2×base. The cap preserves
/// the conservative disk rationale (options.rs: >2 concurrent rechecks
/// start thrashing the disk) — idle seats double the ceiling at most,
/// never scale it by the download cap.
fn elastic_check_budget(base_check: usize, download_cap: usize, active_downloads: usize) -> usize {
    let cap = download_cap.clamp(0, 64);
    let idle = cap.saturating_sub(active_downloads);
    base_check + idle.min(base_check)
}

// ---- Internal shared symbols (consumed by submodules via `use super::*`
// and by this module via direct naming; not a public API. Every name has a
// registered consumer: consumer = a downstream submodule glob or a call in
// this module; a name dropped/added on either side alone turns into an
// unused_imports error, no exceptions) ----
use lifecycle::{fire_stop_family, stop_family_kind};
use magnet::{
    apply_magnet_patch, effective_magnet_selection, magnet_bittorrent_view,
    magnet_options_from_patch, magnet_selected_files, single_tier_from_announce,
};
use tasks::ended_classification;
use views::{group_tiers, random_session_id};

#[cfg(test)]
mod tests;

mod commands;
/// pub(super): the migration importer's HTTP side
/// (session::persist::import_http) reuses [`http_task::mirrors_json_of`]
/// and [`http_task::HttpPersistConfig`] — the single source of the
/// config_json/mirrors_json payload schema (producer and importer share
/// one source, guarding against JSON shape drift).
pub(super) mod http_task;
mod lifecycle;
mod magnet;
/// The media task family's actor glue: the Job payload, the
/// addMedia option-parse face, and the driver spawn; the pipeline is
/// `crate::session::media`.
mod media_task;
mod persist;
/// Periodic task summary log (the `--summary-interval` feed; pub(crate)
/// so the `taiji http` / bare-run doc face can reference the summary
/// format from the same source — a format golden test lives in the
/// module).
pub(crate) mod summary;
mod tasks;
mod views;

/// HTTP task option declaration table governance tests (the registration
/// completeness axis; the table body and parse drivers live in this
/// module — a drift between table ↔ accepted-name mirrors / manual-arm
/// registration / face bits turns red).
#[cfg(test)]
mod option_table_governance {
    use super::*;
    use crate::session::options::{HTTP_PERSIST_OPTION_NAMES, HTTP_RUNTIME_OPTION_NAMES};

    /// Table ↔ accepted-name mirror consistency: persist row names =
    /// HTTP_PERSIST_OPTION_NAMES positionally (the table's first three
    /// rows are the persist face); runtime row names (including manual-arm
    /// rows — the paired credential keys are registered) = set equality
    /// with HTTP_RUNTIME_OPTION_NAMES; the two faces are disjoint (the
    /// storage bit = persisted or runtime or both — the "both" combination
    /// keeps the bit face, currently no dual-face row). Row names are
    /// unique (the precondition of the find-lookup driver).
    #[test]
    fn http_task_option_table_mirrors_name_consts() {
        let mut names: Vec<&str> = HTTP_TASK_OPTION_TABLE.iter().map(|d| d.name).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "HTTP task table row names must be unique");

        let persist_rows: Vec<&str> = HTTP_TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.face.persist)
            .map(|d| d.name)
            .collect();
        assert_eq!(persist_rows, HTTP_PERSIST_OPTION_NAMES);
        let mut runtime_rows: Vec<&str> = HTTP_TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.face.runtime)
            .map(|d| d.name)
            .collect();
        runtime_rows.sort_unstable();
        let mut mirror = HTTP_RUNTIME_OPTION_NAMES.to_vec();
        mirror.sort_unstable();
        assert_eq!(runtime_rows, mirror);
        for d in HTTP_TASK_OPTION_TABLE {
            assert!(
                !(d.face.persist && d.face.runtime),
                "row {:?} holds both face bits — the 'both' combination needs dual arms \
                 in one row; no such key exists today",
                d.name
            );
        }
    }

    /// Manual-arm and fold-bit registration completeness (the governance
    /// axis): rows with apply = None (executors in the explicit section)
    /// are exactly the four paired credential keys; the fold-bit key set =
    /// twelve keys — the request-identity domain's nine keys (the four
    /// credential keys + header/user-agent/all-proxy/https-proxy/referer,
    /// the runtime face) + the persist face's three keys
    /// (checksum/remote-time/http-incomplete-suffix — imported tasks
    /// restore their end-to-end verification / mtime / suffix with the
    /// row); cumulative ⊆ fold and exactly header (the multi-header "\n"
    /// join shape); fold keys ⊆ the runtime face ∪ the persist face
    /// (check-certificate/ca-certificate do not fold — the fail-closed
    /// stance: the TLS trust face does not silently migrate with the fork
    /// config, see the fold function comment).
    #[test]
    fn http_task_option_table_manual_and_fold_bits() {
        let manual: Vec<&str> = HTTP_TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.apply.is_none())
            .map(|d| d.name)
            .collect();
        assert_eq!(
            manual,
            ["ftp-passwd", "ftp-user", "http-passwd", "http-user"],
            "manual arms (apply = None) are exactly the four paired credential keys — \
             executors live in the http_task_runtime_options explicit section"
        );
        let mut fold: Vec<&str> = HTTP_TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.face.import_fold)
            .map(|d| d.name)
            .collect();
        fold.sort_unstable();
        assert_eq!(
            fold,
            [
                "all-proxy",
                "checksum",
                "ftp-passwd",
                "ftp-user",
                "header",
                "http-incomplete-suffix",
                "http-passwd",
                "http-user",
                "https-proxy",
                "referer",
                "remote-time",
                "user-agent"
            ],
            "fold_imported_options key set = the declaration table's fold-bit projection \
             (request-identity domain + the persist face's three keys)"
        );
        let cumulative: Vec<&str> = HTTP_TASK_OPTION_TABLE
            .iter()
            .filter(|d| d.face.cumulative)
            .map(|d| d.name)
            .collect();
        assert_eq!(
            cumulative,
            ["header"],
            "the cumulative key is exactly header (multi-value row join)"
        );
        for d in HTTP_TASK_OPTION_TABLE {
            if d.face.import_fold {
                assert!(
                    d.face.runtime || d.face.persist,
                    "fold key {:?} must belong to the runtime face or the persist face \
                     (folding = dispatch through an existing parser; no executor outside the table)",
                    d.name
                );
            }
            if d.face.cumulative {
                assert!(
                    d.face.import_fold,
                    "cumulative key {:?} must belong to the fold domain",
                    d.name
                );
            }
        }
    }

    /// changeOption scheduling-increment table coverage: the row set = the
    /// scheduling group's six keys + the block-size explicit rejection
    /// arm; the rejection arm always `taiji.option.invalid` for any
    /// non-empty value; changeable keys ⊆ the runtime accepted face (same
    /// value domain, same wording — shared parsers).
    #[test]
    fn http_sched_patch_table_covers_sched_group() {
        let mut names: Vec<&str> = HTTP_SCHED_PATCH_TABLE.iter().map(|d| d.name).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "http-block-size",
                "http-max-chunk",
                "http-scheduler",
                "http-stall-window",
                "max-connection-per-server",
                "min-split-size",
                "split",
            ]
        );
        for d in HTTP_SCHED_PATCH_TABLE {
            assert!(
                d.face.accepted && d.face.runtime,
                "sched table row {:?} bits",
                d.name
            );
            if d.name == "http-block-size" {
                let Some(apply) = d.apply else {
                    panic!("the block-size rejection arm must be in the table");
                };
                let mut s = HttpSchedPatch::default();
                assert!(
                    apply(&mut s, "4M").is_err() && apply(&mut s, "256K").is_err(),
                    "block-size is immutable at task level — any explicit value is rejected"
                );
            } else {
                assert!(
                    HTTP_RUNTIME_OPTION_NAMES.contains(&d.name),
                    "sched-changeable key {:?} must be in the runtime accepted face (same parser)",
                    d.name
                );
            }
        }
    }

    /// Face-bit master check: every table row accepted; bits ↔ arm shape
    /// consistent (persist rows hold a Persist arm; runtime rows hold a
    /// Runtime arm or a manual-arm registration; rejection-bit rows do
    /// not exist — accepted is always true, pure registration rows keep
    /// the bit face unused).
    #[test]
    fn http_task_option_table_face_bit_invariants() {
        for d in HTTP_TASK_OPTION_TABLE {
            assert!(
                d.face.accepted,
                "row {:?} must be accepted (no pure-registration rows today)",
                d.name
            );
            match d.apply {
                Some(HttpTaskApply::Persist(_)) => {
                    assert!(
                        d.face.persist,
                        "Persist-arm row {:?} must hold the persist bit",
                        d.name
                    );
                }
                Some(HttpTaskApply::Runtime(_)) => {
                    assert!(
                        d.face.runtime,
                        "Runtime-arm row {:?} must hold the runtime bit",
                        d.name
                    );
                }
                None => {
                    assert!(
                        d.face.runtime && d.face.import_fold,
                        "manual-arm row {:?} = runtime + fold domain (paired credentials)",
                        d.name
                    );
                }
            }
        }
    }
}

/// BackendContract family-mapping tests: the enum's four
/// variants converge on the three contract families. Engine/Http
/// variants need live driver/engine state to construct (their arms
/// are the trivial one-line match arms above, reviewed alongside);
/// Metadata and Media are constructible here and pin the non-trivial
/// arm (Metadata → Bittorrent, the magnet phase's family key).
#[cfg(test)]
mod backend_family_tests {
    use super::*;
    use crate::session::backend_contract::{BackendContract, TaskFamily};

    /// The metadata phase belongs to the BT family (the magnet
    /// upgrade swaps Engine in place — same family, same contract).
    #[test]
    fn metadata_variant_maps_to_bittorrent_family() {
        assert_eq!(TaskBackend::Metadata.family(), TaskFamily::Bittorrent);
        // The family's stated verification position: verify-before-disk.
        assert_eq!(
            BackendContract::for_family(TaskBackend::Metadata.family()).verification,
            super::super::backend_contract::VerificationPosition::VerifyBeforeDisk
        );
    }

    /// The media variant maps to the media family (the third family's
    /// contract: segment-boundary accounting + synthesis-time final
    /// ruling).
    #[test]
    fn media_variant_maps_to_media_family() {
        let backend = TaskBackend::Media {
            live: Arc::new(std::sync::Mutex::new(
                crate::session::media::MediaLiveState::default(),
            )),
            pause: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        assert_eq!(backend.family(), TaskFamily::Media);
        assert_eq!(
            BackendContract::for_family(backend.family()).verification,
            super::super::backend_contract::VerificationPosition::SegmentBoundaryAccounting
        );
    }
}
