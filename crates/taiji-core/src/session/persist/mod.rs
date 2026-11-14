//! Session persistence assembly face (pure functions, no IO, no spawn —
//! shared by the actor call sites and table-driven tests): torrent /
//! torrent_file row construction, the `config_json` payload, and
//! saveSession text-export serialization.
//!
//! Module layout (directory split mirroring the store/src/persist
//! precedent):
//!
//! - [`import`]: migration importer assembly (read-only parse of the
//! legacy aria2-fork sqlite database and `.aria2` control files into
//! target-store rows);
//! - [`recovery`]: recovery-layer derived-row assembly and startup
//! back-fill injection (same admission semantics).
//!
//! saveSession shape: the primary store is `taiji.sqlite3` (atomic via
//! the single-writer transaction; WAL semantics in
//! `store::persist::PersistJob::Checkpoint`); the text export is the
//! aria2 input-file compatible format, emitted only when
//! `--save-session` is set. Torrent tasks held by metainfo (added as
//! raw bytes) have no URI to write and are skipped by the text export;
//! their session rebuild is carried by the sqlite rows.
//!
//! Upstream anchor mapping: docs/design/core.md

use taiji_bt::filetree::SwarmKind;
use taiji_store::persist::{TaskPhase, TorrentFileRow, TorrentRow};

use crate::metainfo::{MetaFile, Metainfo, TorrentMeta};

/// Metadata intent survives a crash/restart independently of download policy.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(crate) struct PersistedMagnetFlags {
    pub save: bool,
    pub only: bool,
    pub follow: bool,
    pub pause_after: bool,
    pub load_saved: bool,
}
impl Default for PersistedMagnetFlags {
    fn default() -> Self {
        Self {
            save: false,
            only: false,
            follow: true,
            pause_after: false,
            load_saved: false,
        }
    }
}
impl From<&crate::magnet::MagnetOptions> for PersistedMagnetFlags {
    fn from(options: &crate::magnet::MagnetOptions) -> Self {
        Self {
            save: options.bt_save_metadata,
            only: options.bt_metadata_only,
            follow: options.follow_torrent,
            pause_after: options.pause_metadata,
            load_saved: options.bt_load_saved_metadata,
        }
    }
}
impl PersistedMagnetFlags {
    pub fn options(
        &self,
        connection: taiji_bt::utp::PeerConnectionType,
        holepunch: bool,
    ) -> crate::magnet::MagnetOptions {
        crate::magnet::MagnetOptions {
            bt_save_metadata: self.save,
            bt_metadata_only: self.only,
            follow_torrent: self.follow,
            pause_metadata: self.pause_after,
            bt_load_saved_metadata: self.load_saved,
            bt_peer_connection_type: connection,
            holepunch,
        }
    }
}

/// `config_json` payload of a `torrent` row (the task payload input for
/// recovery; the store does not interpret JSON, so this struct is the
/// sole core<->row contract). `tiers` = the tracker table after
/// `changeUri` edits (edits survive restarts; same semantics as the
/// aria2 announce-list persistence).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedTaskConfig {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub selection_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magnet_flags: Option<PersistedMagnetFlags>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub output_paths: std::collections::BTreeMap<usize, std::path::PathBuf>,
    #[serde(default)]
    pub dir: String,
    /// seed_ratio domain = [0, inf) (write faces: the import parse arm
    /// and the RPC option arm already filter). Deserialization
    /// tolerance (`de_seed_ratio`): null -> 0.0 — null is a
    /// pre-existing poisoning shape that older write faces projected
    /// through serde_json for non-finite values; it must not fail the
    /// whole payload's deserialization (otherwise `from_json`'s
    /// `unwrap_or_default` silently drops dir/magnet_uri/tiers/limits
    /// together and the restore target drifts). Out-of-range numeric
    /// literals like `1e999` are a document-level serde_json parse
    /// error (NumberOutOfRange) and cannot be tolerated per-field; the
    /// whole payload still falls back to defaults — upstream domain
    /// checks filter those, only hand-edited rows can carry them.
    #[serde(default, deserialize_with = "de_seed_ratio")]
    pub seed_ratio: f64,
    #[serde(default)]
    pub seed_time_min: f64,
    #[serde(default)]
    pub max_download_limit: u64,
    #[serde(default)]
    pub max_upload_limit: u64,
    #[serde(default)]
    pub tiers: Vec<(usize, String)>,
    /// Original magnet URI of a magnet task (recovery face when
    /// metadata is missing: re-run ut_metadata).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magnet_uri: Option<String>,
    /// .torrent URL (metadata re-fetch face for addUri http(s) tasks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub torrent_url: Option<String>,
    /// BEP16 super-seeding switch (default off). Internal to
    /// `config_json` — aria2 has no matching option and no RPC/CLI
    /// option name is promised (see the `SeedPolicy::super_seeding`
    /// docs). Not serialized when false, so the JSON face matches the
    /// pre-write dedup digest (zero drift for existing payloads).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub super_seeding: bool,
    /// BEP53 selected-file indexes (**file indexes** — BEP53 is
    /// 0-based, not the 1-based aria2 FileEntry index). The producers
    /// are mutually exclusive (coexistence = explicit conflict
    /// rejection on the add / changeOption faces): magnet `so=` (URI
    /// parsing) and the RPC `select-file` option (its 1-based ->
    /// 0-based conversion lives in one place,
    /// `session::options::parse_select_file`). None = select all (no
    /// change for existing tasks). Recovery: at activation, projected
    /// into the engine's flat piece mask via `file_piece_bases`
    /// (SetFileSelection command face).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_files: Option<Vec<u32>>,
    /// Sparse (file index, level) priority pairs, the persisted mirror
    /// of the RPC `taiji.setFilePriority` (client file indexes are
    /// 0-based -> level). Value range: -1 skip / 0 normal / 1..7 high
    /// (own range declaration aligned with the libtorrent
    /// `file_priority` capability). **-1 and `selected_files` stay
    /// consistent** (the write faces sync them: setting -1 removes the
    /// file from the selection set, 0..7 adds it back). Unlisted files
    /// = 0 (normal). None = default face (no bytes written, zero drift
    /// for existing payloads). Load chain: dispatched as
    /// SetFilePriority after the engine spawns at activation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_priorities: Option<Vec<(u32, i8)>>,
    /// ut_holepunch switch (**enabled by default** — libtorrent
    /// negotiates it with the extension handshake and has no separate
    /// switch; the default true aligns with it). Internal to
    /// `config_json` — no RPC/CLI option name is promised. Serialized
    /// only when false (zero drift for existing payloads); load chain:
    /// dispatched as SetHolepunch(false) after the engine spawns at
    /// activation.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub holepunch: bool,
    /// Scheduling policy (default rarest_first). Internal to
    /// `config_json` — the RPC face is
    /// taiji.get/setSchedulerPolicy (`taiji.*` namespace). Serialized
    /// only when non-default (zero drift for existing payloads); load
    /// chain: dispatched as SetSchedulerPolicy after the engine spawns
    /// at activation. The serde shape is adjacently tagged
    /// `{"policy":"rarest_first","params":{}}` so future parameters
    /// can be added without a shape change (serde defaults apply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_policy: Option<crate::engine::SchedulerPolicy>,
    /// Disk protection tier override (three tiers: throughput |
    /// ssd-protect | hdd-sequential). Internal to `config_json` (no
    /// RPC/CLI option promise); None = the session default throughput
    /// tier (no behavior change) and no JSON bytes are written (zero
    /// drift for existing payloads). Load chain: resolved at recovery
    /// / activation via [`taiji_store::disk_policy::DiskPolicy::resolve`]
    /// into `EngineConfig.disk_policy`; an unknown name warns on the
    /// resolve side and falls back to the default tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_tier: Option<String>,
    /// `bt-disable-dht`: per-task DHT flag (**None = follow the
    /// session `enable-dht`** — the Option semantics preserve the
    /// distinction between "explicit override" and "follow" across
    /// restarts). The recovery chain passes `TorrentJob.bt_disable_dht`
    /// through unchanged; at activation it is merged with the session
    /// value into the engine `DhtWireConfig.enabled`. Serialized only
    /// when explicitly set (zero drift for existing payloads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_disable_dht: Option<bool>,
    /// `enable-http-seeding` (BEP19): web-seeding switch (**None =
    /// default true** — the metainfo url-list projection applies as
    /// usual; the Option semantics preserve the distinction between
    /// "explicitly off" and "default on" across restarts). The
    /// recovery chain passes `TorrentJob.enable_http_seeding` through
    /// unchanged; at activation, false -> `build_engine_config` clears
    /// the webseeds (same spot in the magnet upgrade chain). Serialized
    /// only when explicitly set (zero drift for existing payloads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_http_seeding: Option<bool>,
    /// `bt-stop-timeout` (seconds; 0 = never stop — same as the aria2
    /// default). `config_json` task-face mirror (per-download options
    /// persist across restarts as in aria2): write faces =
    /// `patch_config` (an explicit patch value wins, falls back to the
    /// session global) / `job_config` (mirrors
    /// `SeedPolicy::stop_timeout`); recovery chain = both lifecycle
    /// arms back-fill `SeedPolicy.stop_timeout` (engine
    /// BtStopTimeoutWatch). Serialized only when non-zero (zero drift
    /// for existing payloads — same discipline as super_seeding).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub bt_stop_timeout_secs: u64,
    /// `taiji.moveStorage` intent journal . Written into the
    /// row in the same upsert, strictly before any on-disk move action;
    /// cleared in the commit upsert (`dir = to_dir`). Not derived from
    /// the Job — read back from the row mirror (the single journal
    /// truth; every config_json rewrite preserves it). None writes no
    /// bytes (zero drift for existing payloads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub move_pending: Option<MovePending>,
}

fn default_true() -> bool {
    true
}

/// JSON skip shorthand for the bt-stop-timeout default 0 (zero drift
/// for existing payloads — same pattern as super_seeding's `is_true`).
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// seed_ratio deserialization tolerance arm: null -> 0.0 (treated as
/// discard). Domain checks are not repeated here — finite
/// out-of-domain values (e.g. -1) pass through and are warned about
/// and skipped by the recovery consumer (the lifecycle domain check);
/// this arm only absorbs the null poisoning shape produced by the
/// serialization side itself, so the whole payload is not dropped by
/// `unwrap_or_default` over a single field.
fn de_seed_ratio<'de, D>(d: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(Option::<f64>::deserialize(d)?.unwrap_or(0.0))
}

/// `taiji.moveStorage` intent journal (the rename_pending
/// discipline applied to dir migration): recorded in the task row's
/// `config_json` **in the same row upsert, strictly before any on-disk
/// action**. The source payload is never destroyed before the commit
/// (taiji-io fsmove), so recovery after a kill at any point = redo the
/// move idempotently (`from_dir` payload → `to_dir`), then rewrite the
/// row with `dir = to_dir` and the journal cleared. Shared by the
/// torrent face ([`PersistedTaskConfig`]) and the HTTP face
/// (`HttpPersistConfig`); dirs are stored as display strings exactly
/// like `PersistedTaskConfig::dir`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct MovePending {
    /// Absolute old download dir (the payload's current/resting place).
    pub from_dir: String,
    /// Absolute new download dir (the move target / committed face).
    pub to_dir: String,
}

fn is_true(v: &bool) -> bool {
    *v
}

impl Default for PersistedTaskConfig {
    fn default() -> PersistedTaskConfig {
        PersistedTaskConfig {
            selection_pending: false,
            magnet_flags: None,
            output_paths: Default::default(),
            dir: String::new(),
            seed_ratio: 0.0,
            seed_time_min: 0.0,
            max_download_limit: 0,
            max_upload_limit: 0,
            tiers: Vec::new(),
            magnet_uri: None,
            torrent_url: None,
            super_seeding: false,
            selected_files: None,
            file_priorities: None,
            // Manual Default (was derive): the holepunch default
            // matches the serde default (enabled), so corrupted-JSON
            // recovery degrades on the same terms. Policy default =
            // None (the read-back face's unwrap_or_default() =
            // rarest_first).
            holepunch: true,
            scheduler_policy: None,
            // Default None = throughput tier (no behavior change).
            disk_tier: None,
            // Default None = follow the session enable-dht flag.
            bt_disable_dht: None,
            // Default None = web seeding on (BEP19 url-list projection
            // applies as usual).
            enable_http_seeding: None,
            // Default 0 = no seeding-stall watchdog (aria2 default is
            // the same).
            bt_stop_timeout_secs: 0,
            // Default None = no storage move in flight.
            move_pending: None,
        }
    }
}

impl PersistedTaskConfig {
    pub(crate) fn to_json(&self) -> String {
        // Serializing our own struct has no failure branch; on failure
        // degrade to an empty object (recovery falls back to defaults).
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub(crate) fn from_json(json: &str) -> Self {
        serde_json::from_str(json).unwrap_or_default()
    }
}

/// `torrent.kind` text (kind set: v1|v2|hybrid).
pub(crate) fn kind_str(kind: SwarmKind) -> &'static str {
    match kind {
        SwarmKind::V1Only => "v1",
        SwarmKind::V2Only => "v2",
        SwarmKind::Hybrid => "hybrid",
    }
}

/// `torrent.name` derivation: first component of the first non-pad file
/// path (multi-file = the directory name); a single-component path =
/// the file name itself. TorrentMeta does not carry `info.name` (a
/// parsing fact), so the first file path approximates it — name is
/// only an RPC display value and a required row column, never an
/// identity input.
pub(crate) fn derive_name(meta: &TorrentMeta) -> String {
    meta.files
        .iter()
        .find(|f| !f.padding)
        .map(|f| {
            f.path
                .components()
                .next()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .unwrap_or_else(|| f.path.display().to_string())
        })
        .unwrap_or_default()
}

/// `torrent` parent-row base (identity / metadata / kind fields are
/// filled by the caller per task shape — torrent tasks carry the raw
/// bytes, magnet tasks have metadata = NULL). The state arrives as the
/// unified vocabulary's enum ([`TaskPhase`]) and serializes through its
/// canonical `as_v1_str` table — no raw row word enters the assembly
/// face.
pub(crate) fn torrent_row(
    gid_hex: &str,
    state: TaskPhase,
    queue_pos: i64,
    name: &str,
    cfg: &PersistedTaskConfig,
) -> TorrentRow {
    let now = now_epoch();
    TorrentRow {
        gid: gid_hex.to_string(),
        name: name.to_string(),
        state: state.as_v1_str().to_string(),
        queue_pos,
        dir: cfg.dir.clone(),
        config_json: cfg.to_json(),
        kind: String::new(),
        v1_infohash: None,
        v2_infohash: None,
        is_private: false,
        metadata: None,
        error_code: None,
        error_msg: None,
        created_at: now,
        // Observation column (overwritten on the writer side); on
        // mirror rewrites a row-level comparison decides whether it is
        // really written.
        updated_at: now,
    }
}

/// Metadata-field fill for torrent tasks (kind / both infohashes /
/// private / metadata BLOB = raw .torrent bytes — the raw info slice
/// is preserved) + name derivation.
pub(crate) fn fill_torrent_identity(row: &mut TorrentRow, info: &Metainfo, raw: Vec<u8>) {
    row.kind = kind_str(info.meta.kind).to_string();
    row.v1_infohash = info.meta.identity.v1.map(|v| v.to_vec());
    row.v2_infohash = info.meta.identity.v2.map(|v| v.to_vec());
    row.is_private = info.private;
    row.metadata = Some(raw);
    row.name = derive_name(&info.meta);
}

/// Now (epoch seconds) — base value for created_at/updated_at
/// (updated_at defers to the writer-side time).
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `torrent_file` row assembly (TorrentMeta.files -> rows; file_index =
/// the files index; BEP47 pad files get attr = "p"). Default projection
/// of the selection / priority faces (selected = true / priority = 0 —
/// used by migration import and tasks without faces; face-aware
/// projection goes through [`file_rows_with_face`]).
pub(crate) fn file_rows(gid_hex: &str, files: &[MetaFile]) -> Vec<TorrentFileRow> {
    file_rows_with_face(gid_hex, files, None, None)
}

/// Face-aware row projection: `selection`/`priorities` = the task
/// mirror faces (BEP53 0-based non-pad sequence); the `selected` column
/// projects the priority face (-1 <=> 0 — consistent with the
/// config_json single source of truth); falls back to the selection
/// mask when there is no priority face, and to select-all when neither
/// exists (zero drift from existing behavior).
pub(crate) fn file_rows_with_face(
    gid_hex: &str,
    files: &[MetaFile],
    selection: Option<&[u32]>,
    priorities: Option<&[(u32, i8)]>,
) -> Vec<TorrentFileRow> {
    // BEP53 client file-order cursor (increments over non-pad files;
    // pad files are always selected at level 0 — transfer placeholders,
    // not files, so they take no part in selection / priority faces).
    let mut client_idx = 0u32;
    let face = |padding: bool, client_idx: &mut u32| -> (bool, i8) {
        if padding {
            return (true, 0);
        }
        let idx = *client_idx;
        *client_idx += 1;
        let level = priorities
            .and_then(|p| p.iter().find(|(i, _)| *i == idx).map(|(_, q)| *q))
            .unwrap_or(0);
        match (selection, priorities) {
            // Priority face present = authoritative (-1 <=> unselected;
            // selected_files is its projection).
            (_, Some(_)) => (level != -1, level),
            // Selection face only: the BEP53 mask.
            (Some(sel), None) => (sel.contains(&idx), level),
            (None, None) => (true, level),
        }
    };
    files
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            let (selected, priority) = face(f.padding, &mut client_idx);
            TorrentFileRow {
                gid: gid_hex.to_string(),
                file_index: idx as i64,
                path: f.path.display().to_string(),
                length: f.length.min(i64::MAX as u64) as i64,
                attr: if f.padding {
                    Some("p".to_string())
                } else {
                    None
                },
                pieces_root: f.pieces_root.map(|r| r.to_vec()),
                piece_layer: f.piece_layer.as_ref().map(|l| l.to_vec()),
                v1_offset: f.v1_offset.map(|o| o.min(i64::MAX as u64) as i64),
                selected,
                priority: i64::from(priority),
            }
        })
        .collect()
}

/// saveSession text-export entry (collected on the actor side; the pure
/// serialization function is [`serialize_export`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionExportEntry {
    /// Reload URI: the magnet URI or the .torrent URL.
    pub uri: String,
    /// Metadata task shape (magnet) -> URI line without a tab
    /// (`SessionSerializer.cc`); URL task -> URI + tab (the writeUri
    /// shape).
    pub metadata_style: bool,
    pub gid_hex: String,
    pub dir: String,
    pub paused: bool,
}

/// saveSession text-export serialization (input-file compatible; line
/// format per `SessionSerializer.cc`: URI line (metadata URI without a
/// tab / URL + tab), ` gid=<hex>`, ` pause=true`, then regular option
/// lines — our subset emits only `dir`).
pub(crate) fn serialize_export(entries: &[SessionExportEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        if e.metadata_style {
            out.push_str(&e.uri);
            out.push('\n');
        } else {
            out.push_str(&e.uri);
            out.push('\t');
            out.push('\n');
        }
        out.push_str(" gid=");
        out.push_str(&e.gid_hex);
        out.push('\n');
        if e.paused {
            out.push_str(" pause=true\n");
        }
        out.push_str(" dir=");
        out.push_str(&e.dir);
        out.push('\n');
    }
    out
}

/// Migration importer assembly face (read-only migration import from
/// the legacy aria2 fork / `.aria2` control files; implementation and
/// full module docs in [`import`]).
pub mod import;

/// Migration importer, HTTP-side core (serialized-state parsing ->
/// mirrors_json/config_json, preflight checks, backup before the real
/// import, dedup and second-import path-conflict decisions;
/// implementation and full module docs in [`import_http`]).
pub mod import_http;

/// piece->block bitmap mapping (full-coverage rule; golden consumer of
/// the grid.rs semantics; implementation and full module docs in
/// [`import_bitmap`]).
pub mod import_bitmap;

/// Recovery-layer derived-row assembly and startup back-fill injection
/// (same admission semantics; implementation and full module docs in
/// [`recovery`]).
pub mod recovery;

// Public re-export of the writer handle (same pattern as the
// disk_policy re-export in engine/mod.rs — rpc/cli depend only on
// core): the return tuple of `open_session_writer*` and the persist
// parameter of `SessionActor::spawn_with_persist` share this type, and
// the shared CLI assembly function needs a nameable path (it was
// previously a private use inside the actor/import modules and could
// not be named across crates).
pub use taiji_store::persist::PersistHandle;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::TorrentIdentity;
    use std::path::PathBuf;

    fn meta(paths: &[&str]) -> TorrentMeta {
        TorrentMeta {
            identity: TorrentIdentity { v1: None, v2: None },
            kind: SwarmKind::V2Only,
            piece_length: 16384,
            files: paths
                .iter()
                .map(|p| MetaFile {
                    path: PathBuf::from(p),
                    length: 1,
                    padding: false,
                    pieces_root: None,
                    piece_layer: None,
                    v1_offset: None,
                })
                .collect(),
        }
    }

    /// seed_ratio non-finite values -> serde_json projects them as null
    /// (observed via `to_json`: NaN/inf are written as
    /// `"seed_ratio":null`) — the nan/inf collected by the older import
    /// arm poisons rows in exactly this shape. from_json must tolerate
    /// the shape: it must not fail the whole deserialization (otherwise
    /// unwrap_or_default drops dir/magnet_uri/tiers/limits together and
    /// the target drifts to PathBuf::from("")). null -> 0.0 (treated as
    /// discard), all other fields preserved losslessly.
    #[test]
    fn config_json_null_seed_ratio_tolerated() {
        let back = PersistedTaskConfig::from_json(
            r#"{"dir":"/dl/keep","seed_ratio":null,"seed_time_min":30.0,"tiers":[[0,"http://t/ann"]]}"#,
        );
        assert_eq!(
            back.dir, "/dl/keep",
            "a null seed_ratio must not drop the whole configuration"
        );
        assert_eq!(back.seed_ratio, 0.0);
        assert_eq!(back.seed_time_min, 30.0);
        assert_eq!(back.tiers, vec![(0, "http://t/ann".to_string())]);
        // Valid values round-trip unaffected by the tolerance arm
        // (regression anchor).
        let ok = PersistedTaskConfig::from_json(r#"{"dir":"/dl/a","seed_ratio":2.0}"#);
        assert_eq!(ok.dir, "/dl/a");
        assert_eq!(ok.seed_ratio, 2.0);
        // Pins the serialization projection fact (the poisoning source
        // that the upstream import/recovery domain checks filter).
        let poisoned = PersistedTaskConfig {
            magnet_flags: None,
            dir: "/dl/x".into(),
            seed_ratio: f64::INFINITY,
            ..PersistedTaskConfig::default()
        };
        assert!(
            poisoned.to_json().contains(r#""seed_ratio":null"#),
            "the serialization projection of a non-finite seed_ratio = null: {}",
            poisoned.to_json()
        );
    }

    #[test]
    fn config_json_roundtrip_is_lossless_and_tolerant() {
        let cfg = PersistedTaskConfig {
            selection_pending: false,
            magnet_flags: None,
            output_paths: Default::default(),
            dir: "/tmp/dl".into(),
            seed_ratio: 1.5,
            seed_time_min: 30.0,
            max_download_limit: 1024,
            max_upload_limit: 0,
            tiers: vec![(0, "http://a/announce".into())],
            magnet_uri: Some("magnet:?xt=urn:btih:aa".into()),
            torrent_url: None,
            // Mechanical field completions: each default writes no JSON
            // bytes (roundtrip semantics unchanged).
            super_seeding: false,
            selected_files: None,
            file_priorities: None,
            holepunch: true,
            scheduler_policy: None,
            disk_tier: None,
            bt_disable_dht: None,
            enable_http_seeding: None,
            bt_stop_timeout_secs: 0,
            move_pending: None,
        };
        let json = cfg.to_json();
        assert_eq!(PersistedTaskConfig::from_json(&json), cfg);
        // Corrupt/foreign JSON -> all defaults (recovery degrades, no
        // panic).
        assert_eq!(
            PersistedTaskConfig::from_json("not-json"),
            PersistedTaskConfig::default()
        );
    }

    /// scheduler_policy field: the default writes no bytes (zero drift
    /// for existing payloads); a non-default policy persists with the
    /// payload (forward compatible: this module's read-back chain is
    /// lossless); a corrupt payload -> all-defaults degradation (same
    /// from_json tolerance as above).
    #[test]
    fn scheduler_policy_field_roundtrip_and_zero_drift() {
        let cfg = PersistedTaskConfig::default();
        assert!(
            !cfg.to_json().contains("scheduler_policy"),
            "the default policy emits no JSON bytes: {}",
            cfg.to_json()
        );
        let with_policy = PersistedTaskConfig {
            magnet_flags: None,
            scheduler_policy: Some(crate::engine::SchedulerPolicy::sequential()),
            ..PersistedTaskConfig::default()
        };
        let json = with_policy.to_json();
        assert!(json.contains("\"policy\":\"sequential\""), "{json}");
        assert_eq!(PersistedTaskConfig::from_json(&json), with_policy);
        // Corrupt policy value -> parse failure -> all defaults (no
        // panic, no partial recovery).
        assert_eq!(
            PersistedTaskConfig::from_json("{\"dir\":\"/x\",\"scheduler_policy\":42}"),
            PersistedTaskConfig::default()
        );
    }

    /// move_pending field: default None writes no bytes (zero drift —
    /// the journal must not appear on every existing payload); a
    /// recorded intent roundtrips losslessly (the bootstrap close-out
    /// trusts it); a corrupt value degrades to the whole-payload
    /// default (no panic, no partial recovery).
    #[test]
    fn move_pending_field_roundtrip_and_zero_drift() {
        let cfg = PersistedTaskConfig::default();
        assert!(
            !cfg.to_json().contains("move_pending"),
            "the journalless default emits no JSON bytes: {}",
            cfg.to_json()
        );
        let with_move = PersistedTaskConfig {
            move_pending: Some(MovePending {
                from_dir: "/old".into(),
                to_dir: "/new".into(),
            }),
            ..PersistedTaskConfig::default()
        };
        let json = with_move.to_json();
        assert!(json.contains("\"from_dir\":\"/old\""), "{json}");
        assert_eq!(PersistedTaskConfig::from_json(&json), with_move);
        // Legacy payloads without the key take the serde default None.
        assert_eq!(
            PersistedTaskConfig::from_json("{\"dir\":\"/x\"}").move_pending,
            None
        );
        // Corrupt value (a string instead of the dict) -> whole-payload
        // default (unwrap_or_default), never a partial recovery.
        assert_eq!(
            PersistedTaskConfig::from_json("{\"dir\":\"/x\",\"move_pending\":\"oops\"}"),
            PersistedTaskConfig::default()
        );
    }

    /// bt-stop-timeout field: default 0 writes no bytes (zero drift for
    /// existing payloads, same discipline as
    /// super_seeding/scheduler_policy); a non-zero value persists with
    /// the payload (the recovery chain back-fills
    /// SeedPolicy.stop_timeout in both lifecycle arms); legacy payloads
    /// without the key take the serde default 0.
    #[test]
    fn bt_stop_timeout_field_roundtrip_and_zero_drift() {
        // Default 0: no JSON bytes.
        let plain = PersistedTaskConfig::default().to_json();
        assert!(
            !plain.contains("bt_stop_timeout_secs"),
            "the default 0 must not write bt_stop_timeout_secs: {plain}"
        );
        // Non-zero value round-trip.
        let cfg = PersistedTaskConfig {
            selection_pending: false,
            magnet_flags: None,
            output_paths: Default::default(),
            bt_stop_timeout_secs: 45,
            ..PersistedTaskConfig::default()
        };
        let json = cfg.to_json();
        assert!(json.contains("\"bt_stop_timeout_secs\":45"), "got {json}");
        assert_eq!(
            PersistedTaskConfig::from_json(&json).bt_stop_timeout_secs,
            45
        );
        // Legacy payload without the key -> serde default 0 (no
        // seeding-stall watchdog).
        let legacy = PersistedTaskConfig::from_json(r#"{"dir":"/dl/a"}"#);
        assert_eq!(legacy.bt_stop_timeout_secs, 0);
    }

    /// `disk_tier` internal face: None writes no JSON bytes (zero
    /// drift); Some round-trips losslessly; an invalid tier string is
    /// preserved verbatim (the resolve side handles degradation).
    #[test]
    fn disk_tier_json_face_zero_drift_and_roundtrip() {
        // Default payload carries no disk_tier bytes (zero drift).
        let plain = PersistedTaskConfig::default().to_json();
        assert!(
            !plain.contains("disk_tier"),
            "the default payload must not write disk_tier: {plain}"
        );
        // Tier override round-trip.
        let cfg = PersistedTaskConfig {
            selection_pending: false,
            magnet_flags: None,
            output_paths: Default::default(),
            disk_tier: Some("ssd-protect".into()),
            ..PersistedTaskConfig::default()
        };
        let json = cfg.to_json();
        assert!(json.contains("\"disk_tier\":\"ssd-protect\""), "got {json}");
        assert_eq!(
            PersistedTaskConfig::from_json(&json).disk_tier.as_deref(),
            Some("ssd-protect")
        );
        // Unknown tier name in a recovery payload -> the string is
        // passed through verbatim (degradation warns on the resolve
        // side).
        let bad = PersistedTaskConfig {
            magnet_flags: None,
            disk_tier: Some("turbo".into()),
            ..PersistedTaskConfig::default()
        };
        let back = PersistedTaskConfig::from_json(&bad.to_json());
        assert_eq!(back.disk_tier.as_deref(), Some("turbo"));
    }

    /// `bt_disable_dht` flag face: None (follow the session) writes no
    /// JSON bytes (zero drift for existing payloads); explicit
    /// true/false round-trips losslessly (the Option semantics
    /// distinguish "explicit override" from "follow" across restarts);
    /// a corrupt payload -> all-defaults degradation.
    #[test]
    fn bt_disable_dht_json_face_zero_drift_and_roundtrip() {
        // Default payload carries no flag bytes (zero drift).
        let plain = PersistedTaskConfig::default().to_json();
        assert!(
            !plain.contains("bt_disable_dht"),
            "the default payload must not write bt_disable_dht: {plain}"
        );
        // Both explicit-override arms round-trip.
        for v in [true, false] {
            let cfg = PersistedTaskConfig {
                selection_pending: false,
                magnet_flags: None,
                output_paths: Default::default(),
                bt_disable_dht: Some(v),
                ..PersistedTaskConfig::default()
            };
            let json = cfg.to_json();
            assert!(json.contains("\"bt_disable_dht\":"), "got {json}");
            assert_eq!(
                PersistedTaskConfig::from_json(&json).bt_disable_dht,
                Some(v)
            );
        }
        // Corrupt value -> parse failure -> all defaults (no panic, no
        // partial recovery).
        assert_eq!(
            PersistedTaskConfig::from_json("{\"bt_disable_dht\":\"yes\"}"),
            PersistedTaskConfig::default()
        );
    }

    /// `enable_http_seeding` switch face (BEP19): None (default on)
    /// writes no JSON bytes (zero drift for existing payloads);
    /// explicit true/false round-trips losslessly (the Option semantics
    /// distinguish "explicitly off" from "default on" across restarts);
    /// a corrupt payload -> all-defaults degradation. Same pattern as
    /// the `bt_disable_dht` flag face.
    #[test]
    fn enable_http_seeding_json_face_zero_drift_and_roundtrip() {
        // Default payload carries no switch bytes (zero drift).
        let plain = PersistedTaskConfig::default().to_json();
        assert!(
            !plain.contains("enable_http_seeding"),
            "the default payload must not write enable_http_seeding: {plain}"
        );
        // Both explicit arms round-trip (true = back to on — explicit
        // and default stay distinguishable).
        for v in [true, false] {
            let cfg = PersistedTaskConfig {
                selection_pending: false,
                magnet_flags: None,
                output_paths: Default::default(),
                enable_http_seeding: Some(v),
                ..PersistedTaskConfig::default()
            };
            let json = cfg.to_json();
            assert!(json.contains("\"enable_http_seeding\":"), "got {json}");
            assert_eq!(
                PersistedTaskConfig::from_json(&json).enable_http_seeding,
                Some(v)
            );
        }
        // Corrupt value -> parse failure -> all defaults (no panic, no
        // partial recovery).
        assert_eq!(
            PersistedTaskConfig::from_json("{\"enable_http_seeding\":\"yes\"}"),
            PersistedTaskConfig::default()
        );
    }

    #[test]
    fn kind_name_and_file_rows_match_meta() {
        assert_eq!(kind_str(SwarmKind::V1Only), "v1");
        assert_eq!(kind_str(SwarmKind::V2Only), "v2");
        assert_eq!(kind_str(SwarmKind::Hybrid), "hybrid");
        // Multi-file: name = first directory; file-row attrs/indexes
        // align.
        let m = meta(&["docs/readme.md", "docs/deep/a.bin"]);
        assert_eq!(derive_name(&m), "docs");
        let rows = file_rows("80000000000000ff", &m.files);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].file_index, 0);
        assert_eq!(rows[1].path, "docs/deep/a.bin");
        assert_eq!(rows[0].gid, "80000000000000ff");
        // Single file: name = the file name.
        let single = meta(&["v2.bin"]);
        assert_eq!(derive_name(&single), "v2.bin");
    }

    /// Text export = input-file compatible (metadata URI without a
    /// tab; URL line with a tab; gid/pause/dir line order per
    /// SessionSerializer.cc).
    #[test]
    fn export_serialization_matches_input_file_shape() {
        let entries = vec![
            SessionExportEntry {
                uri: "magnet:?xt=urn:btih:aa".into(),
                metadata_style: true,
                gid_hex: "8000000000000001".into(),
                dir: "/tmp/dl".into(),
                paused: false,
            },
            SessionExportEntry {
                uri: "http://x/t.torrent".into(),
                metadata_style: false,
                gid_hex: "8000000000000002".into(),
                dir: "/tmp/d2".into(),
                paused: true,
            },
        ];
        let text = serialize_export(&entries);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "magnet:?xt=urn:btih:aa");
        assert_eq!(lines[1], " gid=8000000000000001");
        assert_eq!(lines[2], " dir=/tmp/dl");
        // URL task: URI + tab (the writeUri shape); pause before dir.
        assert_eq!(lines[3], "http://x/t.torrent\t");
        assert_eq!(lines[4], " gid=8000000000000002");
        assert_eq!(lines[5], " pause=true");
        assert_eq!(lines[6], " dir=/tmp/d2");
    }
}
