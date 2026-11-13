//! RPC method-surface contract vocabulary (the promise table plus the
//! structured descriptor registry; literals frozen).
//!
//! Single source: this module is the only registry for the method surface
//! — taiji-core::session re-exports it to preserve existing public paths
//! (`taiji_core::session::RPC_METHODS` / `RPC_METHOD_INFO` / descriptor
//! types); the taiji-rpc dispatch/metrics faces and the core engine's
//! counting slots consume the same point; the table order and literals
//! never exist twice. Governance tests (registry <-> promise table exact
//! equality both ways plus a frozen category list) live in the
//! taiji-core::session::command test module and lock this table through
//! the re-export.
//!
//! Dependency discipline: pure consts / type literals, zero workspace and
//! third-party dependencies; must not depend on core/rpc/cli.

/// The method-surface promise table, literals frozen. `system.listMethods`
/// and the RPC differential tests consume this table directly.
/// `addMetalink` registers with the `metalink` feature: with the feature
/// off the method does not exist (the "No such method" face; the older
/// "permanently not_supported" promise is retired); execution happens at
/// the RPC consumption seam (parse + per-task addUri expansion), with no
/// SessionCommand variant.
pub const RPC_METHODS: &[&str] = &[
    "addUri",
    "addTorrent",
    "tellStatus",
    "getFiles",
    "getPeers",
    "getServers",
    "getUris",
    "pause",
    "forcePause",
    "unpause",
    // forceRecheck: on-disk recheck scheduling (taiji.forceRecheck /
    // aria2.forceRecheck dual naming — the bare name registers and the
    // prefix-alias normalization exposes both faces). Neither upstream
    // aria2 nor the fork has this name (aria2 1.37.0 has no recheck RPC)
    // — a taiji capability extension, not a reference name.
    "forceRecheck",
    "pauseAll",
    // forcePauseAll: force-pause all tasks (a registered reference name;
    // the force distinction follows the single-task pause/forcePause
    // equivalence, RpcMethodImpl.cc).
    "forcePauseAll",
    "unpauseAll",
    "remove",
    "forceRemove",
    "purgeDownloadResult",
    "removeDownloadResult",
    "changeUri",
    // changePosition: waiting-queue reordering (a registered reference
    // name).
    "changePosition",
    "changeOption",
    // getOption: per-task option read (a registered reference name; the
    // natural companion of changeOption — what can be changed can be
    // read).
    "getOption",
    "changeGlobalOption",
    "getGlobalOption",
    "getGlobalStat",
    "getVersion",
    "getSessionInfo",
    "tellActive",
    "tellWaiting",
    "tellStopped",
    "saveSession",
    "shutdown",
    "forceShutdown",
    "system.listMethods",
    "system.multicall",
    "system.listNotifications",
    // metalink feature gate: on = the RPC consumption seam executes
    // addMetalink (parse -> per-task addUri expansion); off = not
    // registered — canonical_method lands on the unknown-method face
    // ("No such method", the same shape as aria2 with ENABLE_METALINK
    // disabled).
    #[cfg(feature = "metalink")]
    "addMetalink",
    "taiji.moveStorage",
    "taiji.renameFile",
    // Client-identification bans + manual ban face (the taiji.*
    // extension namespace).
    "taiji.banAddr",
    "taiji.unbanAddr",
    "taiji.listBans",
    // Scheduler policy skeleton + runtime switching face (taiji.*
    // namespace; set = write face, get = read-only).
    "taiji.setSchedulerPolicy",
    "taiji.getSchedulerPolicy",
    // Multi-level file priority face (taiji.* namespace; a write face —
    // rejected by the write gate when --rpc-secret is unset).
    "taiji.setFilePriority",
    // Stream-while-downloading playhead face (taiji.* namespace; a write
    // face).
    "taiji.setStreamingPlayhead",
    // disk_tier RPC face (taiji.* namespace; get = query face, set =
    // write face). Naming follows the unified taiji.* camelCase (the six
    // older snake_case names were renamed, no aliases kept).
    "taiji.getTorrentMetadata",
    "taiji.confirmTorrentSelection",
    "taiji.getHttpOutput",
    "taiji.finalizeHttp",
    "taiji.getDiskTier",
    "taiji.setDiskTier",
    // Structured capability discovery face (taiji.* namespace; a
    // parameterless query face).
    "taiji.getCapabilities",
    // Tracker dynamic editing face (taiji.* namespace, camelCase; both
    // methods are write faces — not in the is_read_only exemption set,
    // rejected by the write gate when --rpc-secret is unset). No compat
    // projection (the fork lacks both methods; the canonical names are
    // the literals in both states).
    "taiji.addTracker",
    "taiji.removeTracker",
    // Per-task cookie pass-through face (taiji.* namespace, camelCase;
    // both methods are write faces — not in the is_read_only exemption
    // set, rejected by the write gate when --rpc-secret is unset). The
    // fork has same-named `aria2.*` methods (aria2 fork
    // RpcMethodFactory.cc) but they are served under the taiji.*
    // canonical names — no compat alias projection (a call to
    // `aria2.addUriWithCookies` always lands on "No such method").
    "taiji.addUriWithCookies",
    "taiji.setTaskCookies",
    // Torrent-creation face (taiji.* namespace; a write face — rejected
    // by the write gate when --rpc-secret is unset). Execution bypasses
    // SessionActor: creation has no session state and hashing is
    // long-running, so the single-threaded actor must not be blocked —
    // the RPC layer calls the `taiji_core::create` facade directly
    // (spawn_blocking core + 600s timeout).
    "taiji.createTorrent",
    // Media line: addMedia/probeMedia/
    // getMediaFormats/stopRecording. addMedia = a write face (task
    // addition); probeMedia = the probe **action face** (an
    // outbound request + the format-tree snapshot cache — no secret
    // means the same fail-closed posture as the write faces);
    // getMediaFormats = a pure gid query; stopRecording = a write face
    // (registration + dispatch; the LIVE executor lands in 0.4 —
    // a non-recording task answers an explicit error, never
    // a silent no-op).
    "taiji.addMedia",
    "taiji.probeMedia",
    "taiji.getMediaFormats",
    "taiji.stopRecording",
    // The download-archive destructive clear:
    // a whole-table delete of browsing-history-class
    // rows — deliberately a write face (read_only **false**; no
    // secret → fail-closed like every destructive face). The CLI
    // counterpart is `--media-archive-clear`.
    "taiji.clearMediaArchive",
];

/// RPC method dispatch categories (the single decision point of the
/// table-driven dispatch shape, consumed by taiji-rpc). The category axis
/// = the dispatch **shape** (unified loop vs explicit arms), orthogonal to
/// the read/write axis (the `read_only` bit) — a parameterless read is
/// still Control when not in a query family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethodKind {
    /// Query-list family (unified table-driven loop): keys/pagination plus
    /// a status-view list rendering skeleton (tellActive has no pagination
    /// parameters; tellWaiting/tellStopped paginate, negative offset
    /// reverses order).
    QueryList,
    /// Query-locate family (unified table-driven loop): locate a task or
    /// task sub-resource view by gid (+ keys) (tellStatus also carries
    /// keys filtering; getOption and tellStatus are both three-domain
    /// locate reads, rendering via the Options dict).
    QueryStatus,
    /// Regular command face (explicit decode arms): decode params ->
    /// SessionCommand -> encode_reply passthrough (including parameterless
    /// reads — getVersion/getGlobalOption etc.; their replies have no
    /// family-specific rendering).
    Control,
    /// Special methods (explicit arms, never in the table-driven loop):
    /// RPC-layer direct answers / direct calls / direct expansion, or
    /// bespoke decode semantics — the system.* introspection family
    /// (direct answer / aggregator, dedicated dispatch branches),
    /// shutdown/forceShutdown (shutdown pass-through), addMetalink (RPC
    /// consumption seam expansion), taiji.createTorrent (direct call to
    /// the core facade), changePosition (three-mode how value-range
    /// handling).
    Special,
}

/// Method descriptor (structured registry entry): the name + read-only
/// bit + dispatch category triple, single point. The read-only bit = the
/// single source of truth for the write-gate exemption set (taiji-rpc
/// `is_read_only` consumes it via re-export); the category = the routing
/// basis for taiji-rpc's query-family table-driven loops. Exactly equal
/// as a set to [`RPC_METHODS`] in both directions (governance test:
/// extra/missing/duplicate entries are all red); table order follows
/// method-surface registration order. Read-only semantics = the
/// query/enumeration class — no task add/remove, no option changes, no
/// shutdown side effects; per-method write/read rationale noted inline.
/// New methods default to the write face (false = fail-closed: passes
/// the gate when --rpc-secret is unset); set true only with a pure-read
/// argument.
///
/// Dispatch note: `system.list*`/`system.multicall` (Special) take
/// dedicated branches in the RPC dispatch layer (list* answers without
/// auth; multicall pushes the write gate down to sub-calls decided one by
/// one), so the three names never reach the exemption-set consumption
/// point — the read-only bit is registered per "the method itself has no
/// side effects" (a static direct answer / an aggregator with no direct
/// side effects) and does not carry dispatch-layer auth routing.
///
/// `addMetalink` registers conditionally with the `metalink` feature
/// (same shape and gate as [`RPC_METHODS`]): a write face — parse then
/// per-task addUri expansion.
#[derive(Debug, Clone, Copy)]
pub struct RpcMethodDescriptor {
    /// Frozen method name (= the [`RPC_METHODS`] entry literal).
    pub name: &'static str,
    /// Read-only bit (write-gate exemption decision; semantics as in the
    /// table notes; false = fail-closed through the gate).
    pub read_only: bool,
    /// Dispatch category ([`RpcMethodKind`]; the routing basis for
    /// taiji-rpc's table-driven loop).
    pub kind: RpcMethodKind,
}

pub const RPC_METHOD_INFO: &[RpcMethodDescriptor] = &[
    RpcMethodDescriptor {
        name: "addUri",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "addTorrent",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "tellStatus",
        read_only: true,
        kind: RpcMethodKind::QueryStatus,
    },
    RpcMethodDescriptor {
        name: "getFiles",
        read_only: true,
        kind: RpcMethodKind::QueryStatus,
    },
    RpcMethodDescriptor {
        name: "getPeers",
        read_only: true,
        kind: RpcMethodKind::QueryStatus,
    },
    RpcMethodDescriptor {
        name: "getServers",
        read_only: true,
        kind: RpcMethodKind::QueryStatus,
    },
    RpcMethodDescriptor {
        name: "getUris",
        read_only: true,
        kind: RpcMethodKind::QueryStatus,
    },
    RpcMethodDescriptor {
        name: "pause",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "forcePause",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "unpause",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // Recheck scheduling is a mutating face (shutdown finalize + requeue)
    // — a write face through the gate.
    RpcMethodDescriptor {
        name: "forceRecheck",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "pauseAll",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // Force-pause all — a mutating face through the gate.
    RpcMethodDescriptor {
        name: "forcePauseAll",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "unpauseAll",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "remove",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "forceRemove",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "purgeDownloadResult",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "removeDownloadResult",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "changeUri",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // Waiting-queue reordering — a queue-mutating face through the gate;
    // the three-mode how value range is handled in an explicit RPC-layer
    // arm (Special, not in the table-driven loop).
    RpcMethodDescriptor {
        name: "changePosition",
        read_only: false,
        kind: RpcMethodKind::Special,
    },
    RpcMethodDescriptor {
        name: "changeOption",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // Per-task option query face (GetOptionRpcMethod, pure read) —
    // exempt under the same rule as the tellStatus/getGlobalOption read
    // family; the write half (changeOption/changeGlobalOption) is not
    // exempt (through the gate). The gid-locate read joins the
    // query-locate family (table-driven).
    RpcMethodDescriptor {
        name: "getOption",
        read_only: true,
        kind: RpcMethodKind::QueryStatus,
    },
    RpcMethodDescriptor {
        name: "changeGlobalOption",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "getGlobalOption",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "getGlobalStat",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "getVersion",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "getSessionInfo",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "tellActive",
        read_only: true,
        kind: RpcMethodKind::QueryList,
    },
    RpcMethodDescriptor {
        name: "tellWaiting",
        read_only: true,
        kind: RpcMethodKind::QueryList,
    },
    RpcMethodDescriptor {
        name: "tellStopped",
        read_only: true,
        kind: RpcMethodKind::QueryList,
    },
    // Session state persisted — a persistence side effect, a write face.
    RpcMethodDescriptor {
        name: "saveSession",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "shutdown",
        read_only: false,
        kind: RpcMethodKind::Special,
    },
    RpcMethodDescriptor {
        name: "forceShutdown",
        read_only: false,
        kind: RpcMethodKind::Special,
    },
    // The system.* introspection/aggregation family: the methods
    // themselves have no side effects (same rule as the type-level
    // dispatch note; the consumption point sits after the dedicated
    // branches, the bit carries no auth routing). Direct answer /
    // aggregator = dedicated dispatch branches (Special, not in the
    // table-driven loop).
    RpcMethodDescriptor {
        name: "system.listMethods",
        read_only: true,
        kind: RpcMethodKind::Special,
    },
    RpcMethodDescriptor {
        name: "system.multicall",
        read_only: true,
        kind: RpcMethodKind::Special,
    },
    RpcMethodDescriptor {
        name: "system.listNotifications",
        read_only: true,
        kind: RpcMethodKind::Special,
    },
    // A write face: parse then per-task addUri expansion (task addition
    // goes through the gate). Executed directly at the consumption seam
    // (Special, not in the table-driven loop).
    #[cfg(feature = "metalink")]
    RpcMethodDescriptor {
        name: "addMetalink",
        read_only: false,
        kind: RpcMethodKind::Special,
    },
    RpcMethodDescriptor {
        name: "taiji.moveStorage",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.renameFile",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // banAddr/unbanAddr are write faces through the gate; listBans is an
    // exempt query face.
    RpcMethodDescriptor {
        name: "taiji.banAddr",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.unbanAddr",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.listBans",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    // Across the scheduler/file-priority/playhead/disk-tier families, set
    // is a write face through the gate, get is an exempt query face.
    RpcMethodDescriptor {
        name: "taiji.setSchedulerPolicy",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.getSchedulerPolicy",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.setFilePriority",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.setStreamingPlayhead",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.getTorrentMetadata",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.confirmTorrentSelection",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.getHttpOutput",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.finalizeHttp",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.getDiskTier",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.setDiskTier",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // A parameterless query face reachable anonymously (capability
    // discovery — the frontend probes engine capabilities).
    RpcMethodDescriptor {
        name: "taiji.getCapabilities",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    // Tracker dynamic editing: write faces through the gate.
    RpcMethodDescriptor {
        name: "taiji.addTracker",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.removeTracker",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // Per-task cookie pass-through, deliberately a write face — task
    // addition/modification and cookie-jar runtime overrides; fails
    // closed when --rpc-secret is unset (same gate as other mutating
    // faces).
    RpcMethodDescriptor {
        name: "taiji.addUriWithCookies",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.setTaskCookies",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // Deliberately a write face — writes arbitrary paths; fails closed
    // when --rpc-secret is unset (same gate as other mutating faces).
    // Direct call to the core facade (Special, not in the table-driven
    // loop).
    RpcMethodDescriptor {
        name: "taiji.createTorrent",
        read_only: false,
        kind: RpcMethodKind::Special,
    },
    // Media line (read-only adjudication):
    // addMedia false (task addition); probeMedia **false** — the probe
    // is an action face (an outbound request + the server-side
    // snapshot cache; with no secret it fails closed exactly like the
    // write faces); getMediaFormats **true** (a pure
    // format-tree query off the media_format row / the live snapshot);
    // stopRecording **false** (a task-mutating face — registration +
    // dispatch; the LIVE execution semantics land in 0.4).
    RpcMethodDescriptor {
        name: "taiji.addMedia",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.probeMedia",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.getMediaFormats",
        read_only: true,
        kind: RpcMethodKind::Control,
    },
    RpcMethodDescriptor {
        name: "taiji.stopRecording",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
    // Deliberately a write face — a destructive whole-table clear of
    // sensitivity-equivalent-to-browsing-history rows (the card's
    // read_only=false adjudication; fails closed with no secret, the
    // purge-family rule).
    RpcMethodDescriptor {
        name: "taiji.clearMediaArchive",
        read_only: false,
        kind: RpcMethodKind::Control,
    },
];
