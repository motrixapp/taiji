//! SessionActor: the session-level command entry + queue scheduling +
//! graceful-shutdown propagation root (SPEC §3.2, §7.2, §8.2).
//!
//! Module map:
//! - [`command`]: the frozen SessionCommand/CommandReply (typed
//!   payloads) + re-exports of the method face [`RPC_METHODS`] (the
//!   vocabulary single point lives in taiji-domain);
//! - [`view`]: task status views and DownloadResult table payloads;
//! - [`options`]: global/per-task option subsets (the getGlobalOption
//!   echo; rpc-secret never appears) + changeUri tracker transforms;
//! - [`limits`]: rate-limit execution face handles (shared global
//!   bucket + arc-swap snapshots + per-torrent chained-set assembly);
//! - [`queue`]: the queue/DownloadResult bookkeeping state machine
//!   (pure data, a direct translation of RequestGroupMan, table-driven
//!   tests);
//! - [`events`]: SessionEvent/EventKind six events + the broadcast(256)
//!   bus (the event face);
//! - [`persist`]: the persistence assembly face (torrent/torrent_file
//!   row construction, config_json, saveSession text export; pure
//!   functions);
//! - [`backend_contract`]: the explicit per-family task-backend
//!   contract (live-read/row/control surfaces + the first-class
//!   verification-position field; the new-family onboarding
//!   checklist);
//! - [`http`]: the HTTP task persistence face (recovery read path /
//!   snapshot pipeline / resume verdicts);
//! - [`actor`]: the SessionActor main loop (spawns engine/magnet/
//!   metadata fetch + lifecycle commands + the option face + the
//!   six-event publish points + bootstrap/persistence/saveSession).
//!
//! Concurrency discipline:
//! - SessionActor exclusively owns the GID allocator, the queue, and
//!   the task table (lock-free);
//! - command channel `mpsc::channel(64)` + internal event
//!   `mpsc::channel(64)`: a full channel backpressures the caller (the
//!   RPC layer awaits); unbounded is banned;
//! - replies go over oneshot (single-shot, bounded); shutdown
//!   propagates through the `CancellationToken` hierarchy;
//! - the main loop does zero disk IO: metainfo parsing / EngineConfig
//!   assembly run in `spawn_blocking`; persistence belongs to
//!   PersistWriter.

mod actor;
/// The explicit per-family task-backend contract: live-read / row-persistence / control
/// surfaces + the first-class verification-position field; the
/// stated face of the actor's private TaskBackend enum (four
/// variants, three families). Carries the new-family onboarding
/// checklist (substrate reuse / capabilities doorplate /
/// verification-position declaration).
mod backend_contract;
/// Manual ban bookkeeping (the `taiji.banAddr` face): target
/// resolution/normalization, source classification. The pure-function
/// half; orchestration lives on the actor command face.
pub mod bans;
mod command;
mod events;
/// pub: the HTTP task persistence face (the http_task recovery read
/// path, the pre-bitmap-snapshot fsync + 2s debounce pipeline, the
/// ResumeValidator verdict table — SPEC §6; task actors consume through
/// it after wiring; details in the module doc).
pub mod http;
mod limits;
/// pub: the media task pipeline: the
/// session's third task family — Resolving → Downloading →
/// Processing → Verifying → Done across the driver/pipeline faces, the
/// media_task/media_format row lifecycle, the probe action face, and
/// the phaseChanged emission sink. The actor glue lives in
/// `actor::media_task`; this module is the reusable pipeline (the
/// CLI's `taiji media` face drives it directly).
pub mod media;
/// pub: the metrics counter face (SPEC §12) — the rpc rendering face
/// consumes [`metrics::MetricsSnapshot`] via [`SessionHandle::metrics`];
/// the engine feeds injection points via `EngineConfig::stats`.
/// The implementation lives in the engine subtree (`engine::metrics`,
/// the engine feed points being the main producers); re-exported here —
/// the existing `session::metrics` public path is unchanged.
pub use crate::engine::metrics;
mod options;
/// pub: the migration importer assembly face (`persist::import`, SPEC
/// §10 `taiji import`) is called by the taiji CLI orchestration; the
/// row assembly face stays pub(crate).
pub mod persist;
mod queue;
/// Startup recheck (re-entering the checking state, SPEC §10/§5.4) —
/// consumed by bootstrap. The standalone CLI `--check-integrity` reuses
/// the same entry via the targeted export below (an on-disk rescan ->
/// the measured bitmap fed to `EngineConfig::preset_progress`); the
/// rest of the module stays crate-visible, not opening the whole
/// module.
pub(crate) mod recheck;
mod view;

pub use crate::engine::metrics::{
    BLOCK_STAGE_BUCKETS_SECONDS, DISK_FINALIZE_BUCKETS_SECONDS, DNS_RESOLVE_BUCKETS_SECONDS,
    DhtQueryKind, EngineGauges, HTTP_CONN_ESTABLISH_BUCKETS_SECONDS, HTTP_REQUEST_BUCKETS_SECONDS,
    HTTP_SLOWSTART_BUCKETS_SECONDS, HttpTaskGauges, MetricsSnapshot, PEER_INFLIGHT_BUCKETS,
    PERSIST_COMMIT_BUCKETS_SECONDS, RPC_DURATION_BUCKETS_SECONDS, RPC_METHOD_SLOT_UNKNOWN,
    RPC_METHOD_SLOTS, SessionMetrics, WrcacheEvent,
};
pub use actor::{SessionActor, SessionHandle};
pub use command::{
    CommandReply, OffsetMode, RPC_METHOD_INFO, RPC_METHODS, RpcMethodDescriptor, RpcMethodKind,
    SessionCommand, SessionEnvelope, SessionError, TaskCookieSpec,
};
pub use events::{
    EVENT_BUS_CAPACITY, EventKind, MEDIA_PHASE_EVENT_METHOD, MediaEvent, MediaWarning,
    RecoveryEvent, RecoveryEventKind, RecoveryNotice, SessionEvent, TASK_COOKIE_EVENT_METHOD,
    TaskCookieEvent,
};
pub use limits::{OverallLimits, SpeedLimits};
pub use options::{
    ARIA2_OPTION_NAMES, DECLARED_NON_ACCEPTED_OPTION_NAMES, DECLARED_OPTION_DIFFS,
    DECLARED_UNWIRED_OPTION_NAMES, DHT_MESSAGE_TIMEOUT_DEFAULT_SECS, DHT_MESSAGE_TIMEOUT_MAX_SECS,
    DHT_MESSAGE_TIMEOUT_MIN_SECS, GlobalOptions, SUMMARY_INTERVAL_DEFAULT, SUMMARY_INTERVAL_MAX,
    SessionOptions, crypto_level_str, merge_global_trackers, option_name_declared,
    option_name_has_declaration, parse_crypto_level, parse_peer_connection_type, parse_select_file,
    parse_size, peer_connection_type_str, split_bt_tracker, windows_unsafe_basename,
};
/// Targeted recheck export (the standalone `--check-integrity`
/// consumption face — the taiji CLI rescans the disk before spawn and
/// maps the outcome bitmap; `RecheckOutcome` is exported alongside for
/// mapping/test construction. The module body stays pub(crate)).
pub use recheck::{RecheckOutcome, recheck_on_disk_recovering_with_progress};
/// The per-host cap default, forwarded from a single source (a
/// taiji-http constant; the session-init backfill value when the CLI
/// face `--http-max-per-host` is unset — the taiji CLI reads the same
/// source without depending on taiji-http directly).
pub use taiji_http::perhost::DEFAULT_MAX_PER_HOST;
pub use view::{
    BanEntryView, BanSource, BittorrentView, DownloadResultEntry, EngineFailure, EngineFailureKind,
    FileEntryView, GidResolveError, GlobalStatView, HttpSourceView, HttpView, MediaTrackView,
    MediaView, PeerCryptoKind, PeerEntryView, PeerTransportKind, ServerEntryView, StatusKind,
    TorrentStatusView, UriEntryView, expand_unique, file_piece_bases, offset_completed_length,
    per_file_completed, torrent_top_attrs,
};

/// magnet URI -> dual torrent identity extraction (v1 btih / v2 btmh).
/// Session addUri's duplicate detection walks the same parser,
/// `taiji_bt::magnet::parse` — the addMetalink expansion seam's
/// per-btih dedup reuses this single point, so duplicate semantics do
/// not drift with a second parser. Parse failure = None (the caller
/// handles it on its own error face; this function neither swallows
/// errors nor logs).
pub fn magnet_identity(uri: &str) -> Option<crate::metainfo::TorrentIdentity> {
    taiji_bt::magnet::parse(uri)
        .ok()
        .map(|m| crate::metainfo::TorrentIdentity {
            v1: m.btih,
            v2: m.btmh,
        })
}

#[cfg(test)]
mod magnet_identity_tests {
    use super::magnet_identity;

    /// A 40-hex btih shape extracts the v1 identity (the addMetalink
    /// seam dedup input face).
    #[test]
    fn btih_magnet_yields_v1_identity() {
        let id = magnet_identity(
            "magnet:?xt=urn:btih:1111111111111111111111111111111111111111&dn=x&tr=http%3A%2F%2Ft%2Fann",
        )
        .unwrap_or_else(|| panic!("valid btih magnet must parse"));
        assert_eq!(id.v1, Some([0x11; 20]));
        assert_eq!(id.v2, None);
    }

    /// A btmh (BEP52 multihash `1220` + 64 hex) extracts the v2
    /// identity.
    #[test]
    fn btmh_magnet_yields_v2_identity() {
        let id = magnet_identity(
            "magnet:?xt=urn:btmh:1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&dn=x",
        )
        .unwrap_or_else(|| panic!("valid btmh magnet must parse"));
        assert_eq!(id.v1, None);
        assert_eq!(id.v2, Some([0xaa; 32]));
    }

    /// Non-magnet input = None (no panic; the caller decides the error
    /// face).
    #[test]
    fn non_magnet_input_is_none() {
        assert!(magnet_identity("http://a.test/f.bin").is_none());
        assert!(magnet_identity("magnet:?dn=only").is_none());
    }
}
