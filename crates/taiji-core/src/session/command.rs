//! The frozen SessionCommand / CommandReply surface (finalized
//! payloads; command face + query face).
//!
//! Variants map 1:1 onto the RPC methods ([`RPC_METHODS`] = the SPEC
//! §8.2 promise table). Payloads keep core-layer semantics (no JSON —
//! RPC JSON assembly is forbidden in core): the aria2 field-name
//! mapping and keys/pagination filtering execute in taiji-rpc (error
//! mapping, same rule).
//!
//! Two exceptions to 1:1, both executed in the RPC layer and never
//! entering the session actor: `system.multicall`/`system.list*`
//! (expanded/answered at the RPC layer; the placeholder variants exist
//! only for surface completeness and the actor always answers
//! NotSupported), and `taiji.createTorrent` / `addMetalink` (no
//! SessionCommand variant — createTorrent calls the
//! `taiji_core::create` facade directly; addMetalink is parsed at the
//! RPC seam and expanded into per-task `AddUri` commands).
//!
//! Parameter-shape changes: every gid-taking method takes
//! `gid: String` (aria2 resolves all gid parameters through
//! `str2Gid` → `GroupId::expandUnique` prefix resolution); the
//! tell* variants carry `keys`/pagination as frozen seam fields —
//! core always returns the full ordered view, and filtering/pagination
//! execute in the RPC layer.
//!
//! Upstream anchor mapping: docs/design/core.md

use std::collections::BTreeMap;

use tokio::sync::oneshot;

use crate::gid::Gid;

use super::view::{
    FileEntryView, GlobalStatView, PeerEntryView, ServerEntryView, TorrentStatusView, UriEntryView,
};

/// The task cookie passthrough spec: the payload shape of
/// `taiji.addUriWithCookies` / `taiji.setTaskCookies` — a semantic
/// projection of the fork's post-`parseRpcCookies` validated shape
/// (JSON parsing is carried by taiji-rpc; core carries no JSON, same
/// module-head discipline; field semantics cross-validated against the
/// fork `RpcCookie.cc`).
///
/// Conversion note: the fork's `expiresAt` = a non-negative Unix
/// **millisecond** value (RpcCookie.cc); the RPC layer converts it to
/// seconds (integer-division truncation, the fork's `expires->i()/1000`
/// caliber) before it reaches `expires_utc`; `None` = a session
/// cookie. `http_only` is accepted faithfully but **not consumed** —
/// the taiji-http storage face has no HttpOnly bit (cookies.rs module
/// doc, same rule; the fork only stores the bit, and the behavioral
/// difference is unobservable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCookieSpec {
    /// Cookie name (non-empty, the RFC 6265 token charset — validated
    /// at the RPC layer).
    pub name: String,
    /// Cookie value (no CTL / `;` — validated at the injection face).
    pub value: String,
    /// Domain (canonical form: no leading `.`, lowercase).
    pub domain: String,
    /// Path (starts with `/`, default `/`).
    pub path: String,
    /// Host-only (the default true when there is no leading-dot
    /// `Domain`; forced true for IP hosts).
    pub host_only: bool,
    /// Sent back over HTTPS only.
    pub secure: bool,
    /// Accepted faithfully, not consumed (see the type doc's
    /// conversion note).
    pub http_only: bool,
    /// Expiry unix seconds (`None` = a session cookie).
    pub expires_utc: Option<i64>,
}

/// changePosition position anchors — a three-mode direct translation
/// of aria2 `OffsetMode` (RpcMethodImpl.cc how ∈ {POS_SET, POS_CUR,
/// POS_END}; the string value domain is closed at the RPC layer, core
/// always holds the legal enum). Execution semantics = the
/// [`super::queue`] move face (IndexedList.h direct translation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetMode {
    /// POS_SET: absolute position (clamped into [0, len-1]).
    Set,
    /// POS_CUR: current position + pos (clamped to len-1 forward, 0
    /// backward).
    Cur,
    /// POS_END: queue tail + pos (size-1+pos, clamped both ways).
    End,
}

/// SessionActor control-plane commands (variants = the SPEC §8.2
/// method subset, one to one).
///
/// Replies ride [`SessionEnvelope`] attached by
/// [`super::SessionHandle::call`] (SPEC §3.2: a control-plane mpsc +
/// oneshot reply).
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionCommand {
    /// addUri. URI classification inside the actor: `magnet:` → a
    /// magnet task (the full chain); http(s) → a .torrent metadata
    /// download (the tracker HTTP client reused, SPEC §8.2); other
    /// schemes fail explicitly (BT-only, never disguised).
    AddUri {
        uris: Vec<String>,
        options: BTreeMap<String, String>,
        position: Option<usize>,
    },
    /// addTorrent. base64 is already decoded to raw .torrent bytes at
    /// the RPC layer (the same shape as the aria2 JSON-RPC branch,
    /// RpcMethodImpl.cc).
    AddTorrent {
        torrent: Vec<u8>,
        options: BTreeMap<String, String>,
        position: Option<usize>,
    },
    /// addUriWithCookies (the canonical `taiji.*` single name; the
    /// compat face does not project an `aria2.*` alias).
    /// Cookies are already validated item-by-item at the RPC layer per
    /// the fork's `parseRpcCookies` (cap 300 / field whitelist /
    /// syntax and domain checks); the actor arm converts them into the
    /// task CookieStore (the same storage face as `--load-cookies`)
    /// and strips manual `Cookie:` headers from options per the fork
    /// ("Structured cookies are authoritative", RpcMethodImpl.cc).
    AddUriWithCookies {
        uris: Vec<String>,
        cookies: Vec<TaskCookieSpec>,
        options: BTreeMap<String, String>,
        position: Option<usize>,
    },
    /// setTaskCookies (a direct translation face of the fork's
    /// SetTaskCookiesRpcMethod): replace the cookie jar of a
    /// waiting/paused HTTP task at runtime (RpcMethodImpl.cc — a
    /// STATE_WAITING gate + whole-set replacement + sqlite
    /// persistence; local persistence goes through the unified cookie
    /// row upsert).
    SetTaskCookies {
        gid: String,
        cookies: Vec<TaskCookieSpec>,
    },
    /// tellStatus: look up active/waiting groups first, then the
    /// DownloadResult table (the two-source semantics of
    /// RpcMethodImpl.cc); gid goes through expandUnique.
    TellStatus {
        gid: String,
        keys: Vec<String>,
    },
    GetFiles {
        gid: String,
    },
    GetPeers {
        gid: String,
    },
    GetServers {
        gid: String,
    },
    GetUris {
        gid: String,
    },
    Pause {
        gid: String,
    },
    ForcePause {
        gid: String,
    },
    Unpause {
        gid: String,
    },
    /// forceRecheck: schedule a disk recheck for a torrent task (gid
    /// prefix resolution inside the actor). Semantics: an active task
    /// = stop (with pause wrap-up semantics) → verify → requeue and
    /// reactivate; a waiting/paused task = dequeue, verify, return to
    /// the queue front. During verification
    /// `torrent.state = 'checking'` (the same shape as crash
    /// recovery), and progress reads truthfully via tellStatus
    /// `completedLength`. Torrent tasks only (magnet / metadata / HTTP
    /// tasks and terminal entries = an explicit Err); a form with no
    /// persistence face = an explicit Err (the sole consumption
    /// channel of a check result is the progress row bitmap, read back
    /// at engine assembly — meaningless without the store, never
    /// disguised). Executed in the actor; upstream aria2 (1.37.0)
    /// registers **no** recheck RPC — this method is a taiji
    /// capability extension (canonical `taiji.` forceRecheck + compat
    /// `aria2.forceRecheck` dual naming).
    ForceRecheck {
        gid: String,
    },
    PauseAll,
    /// forcePauseAll: force-pause all tasks (reference
    /// ForcePauseAllRpcMethod::process → pauseAllDownloads(forcePause=
    /// true), RpcMethodImpl.cc; per-group pauseRequested + a force
    /// halt(NONE) — skipping graceful wrap-up actions such as tracker
    /// notifications; the pauseRequestGroup force branch,
    /// RpcMethodImpl.cc). The local force difference follows the
    /// single-task pause/forcePause equivalence declaration (the actor
    /// `pause` wrap-up note); the active face reuses the PauseAll
    /// traversal skeleton and the reserved face sets paused as
    /// PauseAll does.
    ForcePauseAll,
    UnpauseAll,
    Remove {
        gid: String,
    },
    ForceRemove {
        gid: String,
    },
    PurgeDownloadResult,
    RemoveDownloadResult {
        gid: String,
    },
    /// changeUri — the file-entry URI editing face (aria2
    /// ChangeUriRpcMethod, RpcMethodImpl.cc): the del/add/pos
    /// parameter shapes line up one to one (del removes the first
    /// hit; with pos given, add inserts each at that position and
    /// pos++, otherwise appends at the tail). `file_index` = the
    /// 1-based file-entry ordinal (upstream checkRequiredInteger
    /// IntegerGE(1)); domain validation runs in the actor against the
    /// task's file-entry count (out of range = the verbatim
    /// "fileIndex is out of range"). The local end has no file-entry
    /// URI ledger (BEP19 webseed is not consumed, and the HTTP engine
    /// face has no source-change seam) → every shape returns the
    /// upstream no-op counts [0, 0], with the gap declared in the RPC
    /// diff.
    ChangeUri {
        gid: String,
        file_index: u64,
        del_uris: Vec<String>,
        add_uris: Vec<String>,
        pos: Option<usize>,
    },
    ChangeOption {
        gid: String,
        options: std::collections::BTreeMap<String, String>,
    },
    /// taiji.addTracker: append/insert into a BT task's tracker table
    /// (`urls` ≥ 1, one independent tier each — one URL per tier per
    /// BEP12, aligned with the bt-tracker global import; `position` =
    /// the insertion tier position, default the table tail). Active
    /// tasks take effect immediately via `EngineCommand::SetTrackers`
    /// engine coupling (the announce face); waiting tasks change the
    /// payload + config_json persistence (kept across restarts).
    /// Metadata-phase tasks (magnet / .torrent URL) and HTTP tasks are
    /// explicitly rejected; terminal (results-domain) tasks are
    /// explicitly rejected — the payload was already stripped at
    /// wrap-up and the result row is never rebuilt, so the edit could
    /// never take effect (accepting it would be a disguise; the same
    /// direction as aria2 changeUri's findGroup not covering the
    /// terminal domain). The table-transform pure function =
    /// [`super::options::add_trackers`].
    AddTracker {
        gid: String,
        urls: Vec<String>,
        position: Option<usize>,
    },
    /// taiji.removeTracker: delete trackers by exact URL match
    /// (including announce-list tier cleanup — deleting a URL deletes
    /// its tier and renumbers tightly); after deletion an empty tier
    /// list = a pure DHT face. Effect/persistence/rejection faces are
    /// isomorphic to [`SessionCommand::AddTracker`]. The
    /// table-transform pure function =
    /// [`super::options::remove_trackers`].
    RemoveTracker {
        gid: String,
        urls: Vec<String>,
    },
    /// getOption: a single task's option read (a direct translation
    /// face of aria2 GetOptionRpcMethod, RpcMethodImpl.cc). Task
    /// location = the active + reserved + download-result three
    /// domains (matching the reference `findGroup` ∪
    /// `findDownloadResult` tellStatus domain coverage); the reply =
    /// the accepted-subset option dictionary (a string value table,
    /// [`CommandReply::Options`] — the same shape as the reference
    /// pushRequestOption). An active task's rate limits are echoed
    /// with the live bucket values overwriting (the getGlobalOption
    /// `http-max-per-host` cap-overwrite precedent — the echo face is
    /// the effective face); a stopped task reads the result row's
    /// config_json.
    GetOption {
        gid: String,
    },
    /// changePosition: waiting-queue reordering (a direct translation
    /// of aria2 ChangePositionRpcMethod, RpcMethodImpl.cc +
    /// RequestGroupMan.cc). gid goes through expandUnique; **scope =
    /// the waiting queue** (active/error tasks cannot be moved — a
    /// non Reserved/ReservedPaused position answers the reference's
    /// same text "GID#%s not found in the waiting queue."); pos is a
    /// signed offset (the three-mode semantics in [`OffsetMode`]);
    /// the reply = the destination position after the move
    /// ([`CommandReply::Position`]).
    ChangePosition {
        gid: String,
        pos: i64,
        how: OffsetMode,
    },
    /// changeGlobalOption (finalized: dict shape). The subset = rate
    /// limits / max-concurrent-downloads / dht switches; unknown items
    /// ignored (the RpcMethod.cc gatherChangeableGlobalOption rule).
    ChangeGlobalOption {
        options: BTreeMap<String, String>,
    },
    GetGlobalOption,
    /// getGlobalStat: global speed = Σ active-engine 10s
    /// sliding-window readings + numActive/numWaiting/numStopped/
    /// numStoppedTotal (RpcMethodImpl.cc).
    GetGlobalStat,
    GetVersion,
    GetSessionInfo,
    /// tellActive (payload finalized: keys carried; execution in the
    /// RPC layer).
    TellActive {
        keys: Vec<String>,
    },
    /// tellWaiting/tellStopped: pagination offset/num + keys carried;
    /// a negative offset counts from the tail + reverses the results
    /// (a getPaginationRange direct translation, RpcMethodImpl.h);
    /// the stopped order = completion-time order (DownloadResult
    /// table append order).
    TellWaiting {
        offset: i64,
        num: u32,
        keys: Vec<String>,
    },
    TellStopped {
        offset: i64,
        num: u32,
        keys: Vec<String>,
    },
    SaveSession,
    Shutdown,
    ForceShutdown,
    SystemListMethods,
    /// multicall expansion happens in the RPC layer (never in core);
    /// this variant is kept only for method-surface completeness, and
    /// the actor always answers NotSupported.
    SystemMulticall,
    SystemListNotifications,
    /// This engine's extension methods (gap items): the `taiji.*`
    /// namespace.
    MoveStorage {
        gid: String,
        dir: String,
    },
    RenameFile {
        gid: String,
        old_path: String,
        new_path: String,
    },
    /// taiji.banAddr: a manual ban (IP/CIDR; `minutes` = Some for a
    /// duration (minutes) / None for permanent). Lands a peer_ban row
    /// with reason=manual + hot-pushes to running engines (snapshot
    /// hot update + disconnection of online connections in hit
    /// ranges).
    BanAddr {
        target: String,
        minutes: Option<i64>,
    },
    /// taiji.unbanAddr: lift a manual ban (exact match on the
    /// normalized target). Acts on manual bans only (automatic bans
    /// disappear naturally by expiry / restart).
    UnbanAddr {
        target: String,
    },
    /// taiji.listBans: a snapshot of active bans (automatic + manual +
    /// client identity; sources classified via
    /// [`super::view::BanSource`]).
    ListBans,
    /// taiji.setSchedulerPolicy: per-torrent scheduler-policy switch.
    /// Support validation runs in the actor (rarest_first/streaming
    /// are configurable —
    /// [`crate::engine::SchedulerPolicy::is_supported`]; sequential is
    /// unimplemented = an explicit Err, never a silent fallback).
    /// Active tasks swap the policy object atomically via
    /// `EngineCommand::SetSchedulerPolicy`; the task mirror +
    /// config_json follow (restart recovery).
    SetSchedulerPolicy {
        gid: String,
        policy: crate::engine::SchedulerPolicy,
    },
    /// taiji.getSchedulerPolicy: read back a task's current policy.
    /// Truth source = the task mirror (torrent tasks); magnet/URL
    /// metadata tasks and finished tasks = default (the policy face
    /// persists with the torrent task).
    GetSchedulerPolicy {
        gid: String,
    },
    /// taiji.setFilePriority: a partial update of multi-level file
    /// priorities (libtorrent `prioritize_files` anytime semantics —
    /// decided as pairs). `pairs` = [{index, priority}] (1-based
    /// client file order; level domain -1..=7: -1 skip / 0 normal /
    /// 1..7 high); files not listed are untouched. Torrent tasks only
    /// (metadata/HTTP/terminal = an explicit Err); active tasks take
    /// effect engine-live (SetFilePriority + a mutually consistent
    /// selection-face re-push); waiting/paused tasks mirror + persist
    /// config_json (pushed at activation). -1 ⇔ removed from the
    /// selection set / 0..7 ⇔ merged in (mutually consistent with the
    /// select-file single selection face).
    SetFilePriority {
        gid: String,
        pairs: Vec<(u32, i8)>,
    },
    /// taiji.setStreamingPlayhead: push the stream-while-downloading
    /// playhead. `file` = the client file ordinal (the non-pad entry
    /// order, the BEP53 anchor); `position` = the byte position
    /// within the file; `bytes_per_sec` = the playback bitrate (None
    /// = the default tier). **Advancing = repeated calls**. Runtime
    /// face: only active engines receive it (a non-active task = an
    /// explicit Err — no fabricated replayable state), not persisted
    /// (the caller replays after restart); the policy-switch
    /// combination = `taiji.setSchedulerPolicy(streaming)` + this
    /// command (either order — the two engine commands are
    /// decoupled).
    SetStreamingPlayhead {
        gid: String,
        file: u32,
        position: u64,
        bytes_per_sec: Option<u64>,
    },
    /// taiji.getDiskTier: read back a task's current disk tier (the
    /// read-back placeholder face). Truth source = the torrent task
    /// mirror (the config_json `disk_tier` same source); magnet/URL
    /// metadata tasks and finished tasks = default (the tier face
    /// persists with the torrent task — the getSchedulerPolicy rule).
    GetDiskTier {
        gid: String,
    },
    /// taiji.setDiskTier: per-torrent disk-tier switch (the write
    /// face). The torrent task mirror updates + config_json rewrites
    /// (across restarts) + the running engine applies live via
    /// `EngineCommand::SetDiskPolicy` (IoGate quota / flush cadence /
    /// write-coalescing window shift immediately; the prealloc/falloc
    /// allocation mode takes effect for **new allocations only** —
    /// existing file allocation completed at pipeline construction,
    /// no reallocation).
    SetDiskTier {
        gid: String,
        tier: crate::engine::DiskTier,
    },
    /// taiji.getCapabilities: parameterless structured capability
    /// discovery (the query face). The payload is generated
    /// declaratively from the engine policy/feature registrations
    /// (the single truth source,
    /// [`crate::engine::CapabilitiesView`]); schema_version is
    /// finalized on the RPC render face.
    GetCapabilities,
    /// taiji.addMedia: media task addition.
    /// `options` carries the task payload (dir/out/selector/subtitles/
    /// template/no-metadata + the `media-*` flag family + the
    /// `probe-token` snapshot reference); `cookies` is the structured
    /// direct pass (validated item-by-item at the RPC layer,
    /// the addUriWithCookies shape). Classification (direct link →
    /// the HTTP family / not_media) happens inside the task's
    /// Resolving phase — the reply is the GID on acceptance, never a
    /// synchronous classification verdict.
    AddMedia {
        url: String,
        options: BTreeMap<String, String>,
        cookies: Vec<TaskCookieSpec>,
        position: Option<usize>,
    },
    /// taiji.probeMedia (the **action face**):
    /// fetch + classify the entry, build the format tree, cache the
    /// snapshot server-side and reply an opaque token. The RPC write
    /// gate rejects it with no secret (read_only=false, §9's
    /// adjudication); the actor-side face adds the in-flight cap 2 +
    /// the per-origin rate limit.
    ProbeMedia {
        url: String,
    },
    /// taiji.getMediaFormats: the task's resolved format tree (the
    /// media_format row = the probe snapshot's durable counterpart;
    /// live snapshots win while resolving).
    GetMediaFormats {
        gid: String,
    },
    /// taiji.stopRecording (registration + dispatch; the LIVE
    /// execution body lands in 0.4): a non-recording task
    /// answers an explicit error — never a silent no-op (the §3.2
    /// recording phase is 0.4's; 0.3 tasks can never be recordings).
    StopRecording {
        gid: String,
    },
    /// taiji.clearMediaArchive (the archive face): the
    /// download-archive whole-table destructive clear (the
    /// browsing-history-equivalent sensitivity face's escape hatch; the CLI
    /// counterpart is `--media-archive-clear`). Replies with the
    /// removed row count; after the clear the same fingerprints
    /// re-download.
    ClearMediaArchive,
}

/// Command reply payloads (core semantics; the RPC layer maps to aria2
/// JSON).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CommandReply {
    /// Command accepted (the "OK"-semantic commands:
    /// shutdown/forceShutdown/pauseAll/forcePauseAll/unpauseAll/
    /// purgeDownloadResult/removeDownloadResult etc.).
    Accepted,
    /// The newly allocated GID returned after addUri/addTorrent
    /// success; pause/remove and the other GID-returning replies
    /// (aria2 createGIDResponse, RpcMethodImpl.cc).
    Gid(Gid),
    /// getVersion returns the frozen format version string
    /// `taiji/<semver>` (SPEC §8.2).
    Version { version: String },
    /// The tellActive/tellWaiting/tellStopped status views (full,
    /// ordered; filtering in the RPC layer).
    StatusList(Vec<TorrentStatusView>),
    /// The tellStatus single view (Box to bound the variant size).
    TorrentStatus(Box<TorrentStatusView>),
    /// The getFiles / tellStatus.files file views.
    Files(Vec<FileEntryView>),
    /// The getPeers peer snapshot (the engine QueryPeers face).
    Peers(Vec<PeerEntryView>),
    /// The getServers tracker view (an engine tracker table
    /// snapshot).
    Servers(Vec<ServerEntryView>),
    /// The getUris task URI list.
    Uris(Vec<UriEntryView>),
    /// The getGlobalStat aggregate face.
    GlobalStat(GlobalStatView),
    /// The getGlobalOption echo (a string value table; rpc-secret
    /// never appears — the RpcMethodImpl.cc rule).
    Options(BTreeMap<String, String>),
    /// getSessionInfo: a random session id hex (RpcMethodImpl.cc;
    /// util::toHex(sessionId), 16 random bytes → 32 hex chars).
    SessionInfo { session_id: String },
    /// The changeUri reply [deleted, added] counts (RpcMethodImpl.cc).
    UriChange { deleted: u64, added: u64 },
    /// The taiji.addTracker/removeTracker reply: the actually applied
    /// add/remove counts. One variant carries both counts (each
    /// method always has one side 0) — a later merged editing face
    /// needs no third variant; the counts = the **actual mutation
    /// count** after dedup/miss removal (an idempotent call returns
    /// 0, never inflated). The RPC layer renders
    /// `{"removed":N,"added":M}` — the `taiji.*` extension's
    /// self-describing dict style (getSchedulerPolicy/getDiskTier the
    /// same shape); the counts are bare integers (the same source as
    /// changeUri `[del, add]`'s Integer caliber — a count face, not a
    /// length field, never stringified).
    TrackerChange { removed: u64, added: u64 },
    /// The changePosition reply: the destination position after the
    /// move (RpcMethodImpl.cc `Integer::g(destPos)` — a bare integer,
    /// not a string).
    Position { position: u64 },
    /// The taiji.listBans reply: a snapshot of active bans (automatic +
    /// manual + client identity); no ordering/filtering promised at
    /// the RPC layer (core gives the full set with BanSource
    /// classification).
    Bans(Vec<super::view::BanEntryView>),
    /// The taiji.getSchedulerPolicy reply: the task's current
    /// scheduler policy (a core-semantics payload; the RPC layer maps
    /// to `{"policy": name}`).
    SchedulerPolicy {
        policy: crate::engine::SchedulerPolicy,
    },
    /// The taiji.getDiskTier reply: the task's current disk tier (a
    /// mirror read-back; default = throughput — core carries no
    /// Option empty state, the RPC shape always has a name).
    DiskTier { tier: crate::engine::DiskTier },
    /// The taiji.getCapabilities reply: the engine capability view
    /// (the declarative single truth source; the RPC layer maps to
    /// schema_version=1 JSON). Box to bound the variant size.
    Capabilities(Box<crate::engine::CapabilitiesView>),
    /// The taiji.probeMedia reply: the opaque token + the TTL the
    /// server honors (10min, §4) + the format-tree snapshot the token
    /// maps to (the client sees what it cached; addMedia presents only
    /// the token). Box to bound the variant size.
    MediaProbe {
        token: String,
        ttl_secs: u64,
        formats: Box<taiji_media::FormatTree>,
    },
    /// The taiji.getMediaFormats reply: the task's resolved format
    /// tree (Box to bound the variant size).
    MediaFormats(Box<taiji_media::FormatTree>),
    /// The taiji.clearMediaArchive reply: the removed row count (the
    /// taiji.* extension's self-describing dict face renders
    /// `{"removed": N}`).
    ArchiveCleared { removed: u64 },
}

/// Session-level errors. The mapping between numeric error codes and
/// `taiji.*` string codes has its single source in taiji-rpc; core
/// only carries semantics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The method is defined but not yet implemented (an unlanded
    /// entry of the promise table), or permanently unsupported (the
    /// system.* introspection placeholders, the
    /// taiji.moveStorage/renameFile capability face). The string code
    /// is frozen as `taiji.method.not_supported`.
    #[error("taiji.method.not_supported: {method}")]
    NotSupported { method: &'static str },
    /// The SessionActor has exited (a late command after shutdown).
    #[error("taiji.session.closed")]
    SessionClosed,
    /// A task-level explicit failure (parse failure / duplicate task
    /// / GID not found / the current state cannot pause etc.). The
    /// message is a direct translation of aria2 DL_ABORT_EX texts
    /// (RpcMethodImpl.cc), mapped by the RPC layer to numeric code 1 +
    /// the original text.
    #[error("{message}")]
    Failed { message: String },
}

impl SessionError {
    /// A construction shortcut for [`SessionError::Failed`] (the
    /// error face is code 1 + the original text).
    pub fn failed(message: impl Into<String>) -> Self {
        SessionError::Failed {
            message: message.into(),
        }
    }
}

impl From<crate::engine::EngineError> for SessionError {
    /// An engine command-face error → a session error (a per-variant
    /// direct translation: EngineClosed → SessionClosed, Failed →
    /// Failed). Both sides' Display strings are verbatim from the
    /// same source (the single-source contract in the
    /// `engine::error` module doc), so the mapping cannot drift in
    /// text or match classification — `?` / `map_err(Into::into)`
    /// consumers behave unchanged.
    fn from(err: crate::engine::EngineError) -> Self {
        match err {
            crate::engine::EngineError::EngineClosed => SessionError::SessionClosed,
            crate::engine::EngineError::Failed { message } => SessionError::Failed { message },
            // Forward-compat (EngineError is #[non_exhaustive]): unknown
            // future variants fall through to the task-failure face,
            // carrying the engine Display text verbatim (the
            // single-source contract keeps the message drift-free).
            other => SessionError::Failed {
                message: other.to_string(),
            },
        }
    }
}

/// The envelope of the command + reply channels (the real carrier of
/// actor messages; SPEC §3.2 oneshot replies). The reply sender is
/// extracted only inside the actor main loop (destructure
/// `SessionEnvelope { cmd, reply }`).
pub struct SessionEnvelope {
    pub cmd: SessionCommand,
    pub(crate) reply: oneshot::Sender<Result<CommandReply, SessionError>>,
}

/// The method-face vocabulary single point lives in
/// `taiji_domain::methods` (the shared vocabulary layer); this
/// re-export keeps the public `taiji_core::session::*` path (consumed
/// by taiji-rpc dispatch/metrics). The governance tests (this file's
/// tests module) consume the single source through this re-export —
/// test names and assertions cannot drift.
pub use taiji_domain::methods::{RPC_METHOD_INFO, RPC_METHODS, RpcMethodDescriptor, RpcMethodKind};

#[cfg(test)]
mod tests {
    use super::{RPC_METHOD_INFO, RPC_METHODS, RpcMethodKind};

    /// Frozen anchor: a structured-descriptor upgrade may change form
    /// but not decision — `(method name, read-only bit)` rows align
    /// with the original values one by one (names, bits, and table
    /// order all exactly equal; any single-bit or ordering drift
    /// turns red).
    const FROZEN_READ_ONLY: &[(&str, bool)] = &[
        ("addUri", false),
        ("addTorrent", false),
        ("tellStatus", true),
        ("getFiles", true),
        ("getPeers", true),
        ("getServers", true),
        ("getUris", true),
        ("pause", false),
        ("forcePause", false),
        ("unpause", false),
        ("forceRecheck", false),
        ("pauseAll", false),
        ("forcePauseAll", false),
        ("unpauseAll", false),
        ("remove", false),
        ("forceRemove", false),
        ("purgeDownloadResult", false),
        ("removeDownloadResult", false),
        ("changeUri", false),
        ("changePosition", false),
        ("changeOption", false),
        ("getOption", true),
        ("changeGlobalOption", false),
        ("getGlobalOption", true),
        ("getGlobalStat", true),
        ("getVersion", true),
        ("getSessionInfo", true),
        ("tellActive", true),
        ("tellWaiting", true),
        ("tellStopped", true),
        ("saveSession", false),
        ("shutdown", false),
        ("forceShutdown", false),
        ("system.listMethods", true),
        ("system.multicall", true),
        ("system.listNotifications", true),
        #[cfg(feature = "metalink")]
        ("addMetalink", false),
        ("taiji.moveStorage", false),
        ("taiji.renameFile", false),
        ("taiji.banAddr", false),
        ("taiji.unbanAddr", false),
        ("taiji.listBans", true),
        ("taiji.setSchedulerPolicy", false),
        ("taiji.getSchedulerPolicy", true),
        ("taiji.setFilePriority", false),
        ("taiji.setStreamingPlayhead", false),
        ("taiji.getDiskTier", true),
        ("taiji.setDiskTier", false),
        ("taiji.getCapabilities", true),
        ("taiji.addTracker", false),
        ("taiji.removeTracker", false),
        ("taiji.addUriWithCookies", false),
        ("taiji.setTaskCookies", false),
        ("taiji.createTorrent", false),
        // Media line (the per-method read_only adjudication frozen in
        // this list): addMedia/probeMedia/stopRecording are write
        // faces (probeMedia = the action face; no secret →
        // fail-closed); getMediaFormats is the one read-only
        // face of the four.
        ("taiji.addMedia", false),
        ("taiji.probeMedia", false),
        ("taiji.getMediaFormats", true),
        ("taiji.stopRecording", false),
        // The archive-clear extension to the same frozen list: the
        // archive clear is a destructive face —
        // read_only false, fail-closed with no secret.
        ("taiji.clearMediaArchive", false),
    ];

    /// The kind-face frozen lists: the query-list / query-status /
    /// special three families match by name (Control = the complement
    /// of the whole set, implicitly locked by the whole-set equality).
    /// Growing a table-driven family or editing the special arms must
    /// update these lists explicitly — the list is the review seat of
    /// the classification decision.
    const FROZEN_QUERY_LIST: &[&str] = &["tellActive", "tellWaiting", "tellStopped"];
    const FROZEN_QUERY_STATUS: &[&str] = &[
        "tellStatus",
        "getFiles",
        "getPeers",
        "getServers",
        "getUris",
        "getOption",
    ];
    const FROZEN_SPECIAL: &[&str] = &[
        "changePosition",
        "shutdown",
        "forceShutdown",
        "system.listMethods",
        "system.multicall",
        "system.listNotifications",
        #[cfg(feature = "metalink")]
        "addMetalink",
        "taiji.createTorrent",
    ];

    /// Governance: the registry and the frozen method face match
    /// exactly in both directions — over-registration (an
    /// unregistered name carrying a read-only bit distorts the
    /// exemption face), under-registration (a new method missing,
    /// degrading to the write-gate fail-closed fallback with a
    /// distorted table), and duplicates (two same-name rows with
    /// conflicting bits) all turn red; table order follows the
    /// method-surface registration order; read-only bits align with
    /// the frozen anchor row by row. The feature gate (addMetalink)
    /// has the same cfg on both tables — both feature states compile
    /// and align.
    #[test]
    fn rpc_method_info_matches_method_surface_exactly() {
        // Exact length equality (the fast-fail seat for
        // over/under-registration).
        assert_eq!(
            RPC_METHOD_INFO.len(),
            RPC_METHODS.len(),
            "registry length must equal the method surface"
        );
        // Every registered name has exactly one surface entry
        // (over-registration / duplicates turn red).
        for entry in RPC_METHOD_INFO {
            assert_eq!(
                RPC_METHODS.iter().filter(|m| **m == entry.name).count(),
                1,
                "{}: exactly one surface entry",
                entry.name
            );
        }
        // Every surface name has exactly one registry entry
        // (under-registration / duplicates turn red).
        for name in RPC_METHODS {
            assert_eq!(
                RPC_METHOD_INFO
                    .iter()
                    .filter(|entry| entry.name == *name)
                    .count(),
                1,
                "{name}: exactly one registry entry"
            );
        }
        // Table order follows the surface registration order (zip
        // equality — the registry must not reorder or misalign).
        for (entry, name) in RPC_METHOD_INFO.iter().zip(RPC_METHODS.iter()) {
            assert_eq!(entry.name, *name, "registry order must follow the surface");
        }
        // Read-only bits align with the frozen values row by row
        // (names + bits + order, all exactly equal).
        assert_eq!(
            RPC_METHOD_INFO.len(),
            FROZEN_READ_ONLY.len(),
            "frozen bit anchor must track the descriptor table"
        );
        for (entry, (name, read_only)) in RPC_METHOD_INFO.iter().zip(FROZEN_READ_ONLY.iter()) {
            assert_eq!(
                entry.name, *name,
                "frozen anchor name drift at {}",
                entry.name
            );
            assert_eq!(
                entry.read_only, *read_only,
                "{name}: read-only bit must match the frozen  value"
            );
        }
    }

    /// Kind-face governance: the QueryList/QueryStatus/Special three
    /// families equal the frozen lists by name (in table order); the
    /// four-kind partition is complete — every method falls into
    /// exactly one kind (the enum field guarantees exactly one; the
    /// whole-set equality guarantees none missed).
    #[test]
    fn method_kinds_match_frozen_classification() {
        let kind_names = |kind: RpcMethodKind| {
            RPC_METHOD_INFO
                .iter()
                .filter(|d| d.kind == kind)
                .map(|d| d.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            kind_names(RpcMethodKind::QueryList),
            FROZEN_QUERY_LIST.to_vec()
        );
        assert_eq!(
            kind_names(RpcMethodKind::QueryStatus),
            FROZEN_QUERY_STATUS.to_vec()
        );
        assert_eq!(kind_names(RpcMethodKind::Special), FROZEN_SPECIAL.to_vec());
        // Control = the whole-set complement (whole-set equality →
        // nothing unclassified).
        let classified = kind_names(RpcMethodKind::Control).len()
            + FROZEN_QUERY_LIST.len()
            + FROZEN_QUERY_STATUS.len()
            + FROZEN_SPECIAL.len();
        assert_eq!(
            classified,
            RPC_METHOD_INFO.len(),
            "every descriptor carries exactly one frozen-kind classification"
        );
    }
}
