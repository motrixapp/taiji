//! Business-row payload types (field-for-field per the persistence
//! tables): torrent/torrent_file/torrent_progress/tracker/peer_ban/
//! ipfilter/dht_state rows plus the recovery snapshot
//! [`TorrentSnapshot`] — a pure data face; skip-write comparison
//! semantics (digest dedup / row-level comparison) live in each row's
//! docs and in the `write_*` execution faces.

use serde::Serialize;

// ---- media rows (media write enablement; pre-release
// DDL discipline) ----

/// media_task row payload (the minimal parent face: the FK anchor for
/// track/segment rows + the staging/digest facts; the orchestration
/// state machine that drives `state` stays on the media mount).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaTaskRow {
    /// 16-hex GID (FK anchor).
    pub gid: String,
    /// `hls`|`dash` (DDL CHECK domain).
    pub kind: String,
    /// Manifest URL verbatim.
    pub manifest_url: String,
    /// queued|resolving|downloading|recording|processing|verifying|
    /// finalizing|paused|error|done (the full ten-state domain; no CHECK).
    pub state: String,
    /// Pause phase memory (the media mount's face; carried verbatim).
    pub phase_detail_json: Option<String>,
    /// Selection snapshot (carried verbatim).
    pub variant_json: Option<String>,
    /// Selector snapshot (the three-layer selector expression,
    /// verbatim — the Error->unpause / selector-change re-resolve input).
    pub selector_json: Option<String>,
    /// The template-expanded, **sanitized** product name (the
    /// sanitation red line: what landed on disk is what this column
    /// says — the expansion result passed the red line before
    /// persisting).
    pub output_name: Option<String>,
    /// Bridge metadata (the 0.5 yt-dlp slot; NULL in 0.3).
    pub bridge_json: Option<String>,
    /// Staging directory (absolute).
    pub staging_dir: String,
    /// Output path (absolute).
    pub output_path: String,
    /// Normalized manifest digest (bytes).
    pub manifest_norm_digest: Vec<u8>,
    /// Bytes landed (observational).
    pub total_done: i64,
    /// Config snapshot JSON.
    pub config_json: String,
    pub error_code: Option<String>,
    pub error_msg: Option<String>,
    /// Observational (excluded from the dedup comparison).
    pub created_at: i64,
    /// Observational (excluded from the dedup comparison).
    pub updated_at: i64,
}

/// media_track row payload (field-for-field per the media data-model
/// DDL; `seg_bitmap` = packed per-segment done prefix, LSB-first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaTrackRow {
    pub gid: String,
    pub track_idx: i64,
    /// video|audio|subtitle (DDL comment domain).
    pub kind: String,
    pub playlist_uri: String,
    /// Archive file name inside staging (soft-frozen synthesis-line
    /// consumer).
    pub local_name: String,
    /// JSON array of init-section file names.
    pub init_files_json: Option<String>,
    pub seg_bitmap: Option<Vec<u8>>,
    pub seg_count: Option<i64>,
}

/// media_segment row payload (segment identity = absolute media
/// sequence; `validator_digest` = the normalized-identity digest
/// written from day one — the 0.4 signature-refresh/structure-diff
/// consumption face).
///
/// `seg_len` semantics (the renovation): the **plaintext** length —
/// for encrypted tracks the archive holds decrypted bytes appended in
/// order (decrypt-as-consume), so the ledger length and the archive
/// length stay on one semantics (the recovery reconcile compares bitmap
/// bytes vs archive length; both count plaintext).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaSegmentRow {
    pub gid: String,
    pub track_idx: i64,
    pub seg_idx: i64,
    /// HLS absolute media sequence (IV/bitmap key); DASH NULL.
    pub media_sequence: Option<i64>,
    pub uri: String,
    /// `length@offset` when BYTERANGE applies.
    pub byte_range: Option<String>,
    /// media_key.id reference (the decrypt face; NULL = plaintext
    /// segment / the explicit METHOD=NONE reset).
    pub key_id: Option<i64>,
    /// Plaintext length on disk (see type docs).
    pub seg_len: i64,
    pub duration_ms: Option<i64>,
    pub validator_digest: Option<Vec<u8>>,
    /// Effective EXT-X-MAP ordinal (multi-MAP boundary bookkeeping;
    /// NULL = no init section).
    pub map_idx: Option<i64>,
}

/// media_key row payload (write enablement; rotation sequence —
/// one row per KEY-tag identity `(gid, key_id)`, `key_id` = the
/// media-side identity digest of (resolved URI, IV); the design
/// requirement is "multiple key_id rows + the IV-sequence semantics").
/// At-rest posture:
/// key values live only here — never in staging — plaintext under the
/// local-machine threat model (static encryption is a deferred open
/// question; the secure_delete discipline bounds the deleted-copy
/// surface).
/// Row ids are **stable across upserts** (no delete/reinsert —
/// `media_segment.key_id` references them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaKeyRow {
    /// Row id (media_segment.key_id's target). `None` on insert; the
    /// load face fills it.
    pub id: Option<i64>,
    pub gid: String,
    /// Identity text (UNIQUE(gid, key_id)).
    pub key_id: String,
    /// Resolved key URI.
    pub uri: String,
    /// Explicit IV; NULL ⇒ the media-side derives per segment (the
    /// segment's absolute sequence — or, for an init section, the
    /// first following segment's sequence; the living-draft chain).
    pub iv: Option<Vec<u8>>,
    /// Key material, exactly 16 bytes.
    pub key: Vec<u8>,
}

/// media_format row payload (write enablement): the resolved
/// format-tree snapshot — the persisted counterpart of the probe
/// token's server-side cache. `formats_json` is the
/// serialized [`taiji_media::FormatTree`] verbatim (the store does not
/// interpret the payload).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaFormatRow {
    pub gid: String,
    pub formats_json: String,
    /// Observational (excluded from the dedup comparison).
    pub created_at: i64,
    /// Observational (excluded from the dedup comparison).
    pub updated_at: i64,
}

/// media_archive row payload: the
/// download archive — sensitivity class "equivalent to browsing
/// history" (the DDL comment is the annotation of record). Written
/// at the Done close-out of a
/// `--media-archive` task; read by the two duplicate checkpoints
/// (url_digest = checkpoint 1, manifest_digest = checkpoint 2);
/// cleared whole-table by the destructive faces
/// (`taiji.clearMediaArchive` / `--media-archive-clear`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaArchiveRow {
    /// Normalized URL digest (checkpoint 1 identity; PK).
    pub url_digest: String,
    /// The fetched manifest's canonical digest (checkpoint 2).
    pub manifest_digest: String,
    /// `hls`|`dash`.
    pub kind: String,
    /// The manifest's declared title, when the manifest carried one.
    pub title: Option<String>,
    /// The sanitized output name (the read-back face).
    pub output_name: String,
    /// The archiving task's GID (provenance).
    pub gid: String,
    /// Observational.
    pub created_at: i64,
    /// Observational.
    pub updated_at: i64,
}

/// torrent_progress row payload (the `torrent_progress` table;
/// digest/updated_at are derived on the writer side: digest = SHA-256 of
/// the payload's deterministic serialization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TorrentProgressRow {
    /// 16-hex GID (the upper layer formats
    /// `taiji-core::gid::Gid` before passing it in).
    pub gid: String,
    pub piece_length: i64,
    /// v1/hybrid global piece bitfield (synthesized view).
    pub v1_bitfield: Option<Vec<u8>>,
    /// v2: encoding of `[(file_index, per-file piece bitfield)...]`
    /// (synthesized view).
    pub v2_file_bits: Option<Vec<u8>>,
    pub upload_at_startup: i64,
    pub downloaded_total: i64,
    pub uploaded_total: i64,
    pub active_time_s: i64,
    pub seed_time_s: i64,
}

/// tracker row payload (field-for-field per the `tracker`
/// table).
///
/// Primary key = `(gid, tier, url)`; skip-write semantics match the
/// [`TorrentProgressRow`] digest dedup (rewriting identical data = zero
/// disk writes). Difference: the baseline v1 DDL tracker table has **no
/// digest column** (schema frozen, in-place table changes barred), so
/// dedup is implemented as **row-level comparison** — the stored row is
/// read back and the write is skipped on full-field equality; the
/// externally visible behavior (`PersistOutcome`) matches the digest
/// semantics exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerRow {
    /// 16-hex GID (FK -> torrent(gid)).
    pub gid: String,
    pub tier: i64,
    pub url: String,
    /// Tracker dynamic-edit switch (the engine always writes
    /// true).
    pub enabled: bool,
    pub last_interval: Option<i64>,
    pub last_min_interval: Option<i64>,
    /// Epoch seconds of the next periodic announce (`now + interval`
    /// after a success).
    pub next_announce_at: Option<i64>,
    pub last_error: Option<String>,
    pub last_ok_at: Option<i64>,
    /// Scrape cache (batched same-host scrape results after
    /// an announce).
    pub seeds: Option<i64>,
    pub leechers: Option<i64>,
}

/// peer_ban row payload (the `peer_ban` table: ip primary key + reason +
/// until, in epoch seconds). No FK — bans are independent of the torrent
/// lifecycle (engine-level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBanRow {
    /// Dotted/hextet textual IP (the writer always stores the canonical
    /// `IpAddr::to_string()` form).
    pub ip: String,
    pub reason: String,
    /// Expiry instant (epoch seconds; the ban counts as active while
    /// `until > now`).
    pub until: i64,
}

/// ipfilter row payload (the `ipfilter` table: kind=cidr|p2p-blocklist +
/// rule text + enabled). Rule text formats are a producer convention:
/// p2p-blocklist = `deny/allow,from,to` (invertibly parsed by
/// bt::peer_policy), cidr = `addr/prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfilterRow {
    pub kind: String,
    pub rule: String,
    pub enabled: bool,
}

/// dht_state row payload (the `dht_state` table: family primary key +
/// node_id + routing_table self-describing BLOB + saved_at). No FK — DHT
/// state is independent of the torrent lifecycle (session-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtStateRow {
    /// Address family ("v4"/"v6"; the DDL CHECK domain, the textual form
    /// of bt::dht::DhtFamily).
    pub family: String,
    /// Local node ID (20 bytes).
    pub node_id: Vec<u8>,
    /// Routing-table BLOB (the product of
    /// bt::dht::persist::encode_table).
    pub routing_table: Vec<u8>,
    /// Save instant (epoch seconds; observational — excluded from the
    /// dedup comparison, so an unchanged-content skip keeps the stored
    /// value; saved_at means "instant of last content change").
    pub saved_at: i64,
}

/// The active set of `torrent.state` (the recovery semantics "read
/// torrents with state in the active set"):
/// `LoadTorrentsAtStartup` returns only these rows; `done`/`error` are
/// persisted DownloadResults (terminal states, not rebuilt).
pub const TORRENT_ACTIVE_STATES: &[&str] = &[
    "queued",
    "metadata",
    "checking",
    "allocating",
    "downloading",
    "seeding",
    "paused",
];

/// torrent row payload (field-for-field per the `torrent`
/// table). Primary key gid; the table has no digest column -> skip-write
/// via row-level comparison (the same precedent as [`TrackerRow`]).
/// `created_at`/`updated_at` are observational (excluded from
/// comparison; a skip keeps the old values; on an actual write
/// updated_at = writer-side now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentRow {
    /// 16-hex GID (anchor for child-table FK references).
    pub gid: String,
    pub name: String,
    /// The state set: queued|metadata|checking|allocating|
    /// downloading|seeding|paused|error|done (stored verbatim as text;
    /// the value domain is the writer-side caller's duty — the DDL has
    /// no CHECK).
    pub state: String,
    /// Queue order (stable ORDER BY key at recovery; a session-side
    /// increasing counter).
    pub queue_pos: i64,
    pub dir: String,
    /// Per-task option subset as JSON (the task payload input face at
    /// recovery: dir/seed/rate limits/tiers/magnet uri etc.; the schema
    /// is a producer convention, the store does not interpret it).
    pub config_json: String,
    /// v1|v2|hybrid (textual form of SwarmKind).
    pub kind: String,
    /// SHA-1 of the info slice (v1/hybrid); absent for v2-only.
    pub v1_infohash: Option<Vec<u8>>,
    /// SHA-256 of the info slice (v2/hybrid).
    pub v2_infohash: Option<Vec<u8>>,
    /// BEP-27 private flag.
    pub is_private: bool,
    /// Raw .torrent bytes (raw info slice + outer piece layers — the
    /// sole basis for recovery rebuild/recheck/re-export; NULL while a
    /// magnet is not yet resolved -> recovery lands in the metadata
    /// state).
    pub metadata: Option<Vec<u8>>,
    pub error_code: Option<i64>,
    pub error_msg: Option<String>,
    /// Creation instant (epoch seconds; observational).
    pub created_at: i64,
    /// Instant of last content change (epoch seconds; observational).
    pub updated_at: i64,
}

/// torrent_file row payload (field-for-field per
/// the `torrent_file` table). No independent dedup — it belongs to the
/// [`TorrentRow`] parent's comparison unit (the file set is compared row
/// by row across all fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentFileRow {
    /// FK -> torrent(gid) (ON DELETE CASCADE).
    pub gid: String,
    /// File index (subscript into TorrentMeta.files; primary key
    /// `(gid, file_index)`).
    pub file_index: i64,
    /// Sanitized relative path (textual form of MetaFile::path).
    pub path: String,
    pub length: i64,
    /// BEP-47 pad file = "p" (None otherwise).
    pub attr: Option<String>,
    /// Pieces root for non-empty v2 files (32 bytes).
    pub pieces_root: Option<Vec<u8>>,
    /// Piece layer carried by the metadata (None for files of at most
    /// one piece).
    pub piece_layer: Option<Vec<u8>>,
    /// v1/hybrid layout offset.
    pub v1_offset: Option<i64>,
    pub selected: bool,
    /// 0 normal / -1 skip / 1..7 high (the priority levels).
    pub priority: i64,
}

/// Recovery snapshot for `LoadTorrentsAtStartup`: the parent row + the
/// file row set (in file_index order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentSnapshot {
    pub row: TorrentRow,
    pub files: Vec<TorrentFileRow>,
}

/// recovered_layer row payload (derived table; key = `(gid, file_index)`,
/// value = layer bytes + the payload for re-verification at read-back).
/// Skip-write via row-level comparison (the same precedent as
/// [`TrackerRow`] — the v2 DDL has no digest column, schema frozen);
/// `updated_at` is observational (excluded from comparison).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredLayerRow {
    /// FK -> torrent(gid) (ON DELETE CASCADE — deleting the task clears
    /// its recovery layers).
    pub gid: String,
    /// File index (subscript into TorrentMeta.files; primary key
    /// `(gid, file_index)`).
    pub file_index: i64,
    /// Piece length (input to the layer criterion at read-back
    /// re-verification).
    pub piece_length: i64,
    /// File length (input to the count criterion at read-back
    /// re-verification).
    pub file_length: i64,
    /// The file's pieces root (32 bytes; from the info dictionary — the
    /// trust anchor and the convergence target for read-back
    /// recomputation).
    pub pieces_root: Vec<u8>,
    /// Recovered piece-layer hashes (32 bytes x
    /// ceil(file_length/piece_length)).
    pub layer: Vec<u8>,
}

/// The active set of http_task.state (recovery semantics:
/// [`super::PersistJob::LoadHttpTasksAtStartup`] returns only these
/// rows); `done`/`error` are terminal and not rebuilt (matching the
/// [`TORRENT_ACTIVE_STATES`] recovery policy).
pub const HTTP_TASK_ACTIVE_STATES: &[&str] = &["queued", "probing", "downloading", "paused"];

/// The terminal set of http_task.state (the complement of
/// [`HTTP_TASK_ACTIVE_STATES`]). Non-terminal overwrites of terminal
/// rows are rejected by the write face (see the downgrade-write guard in
/// [`super::write_http::upsert_http_task`]); the only exit from a
/// terminal state is the explicit reopen (the Error->unpause re-probe
/// migration arm).
pub const HTTP_TASK_TERMINAL_STATES: &[&str] = &["done", "error"];

/// http_task row payload (the media data-model increment; DDL frozen).
///
/// Primary key gid (a namespace pooled with BT; no cross-table
/// FK — HTTP task rows are independent of the torrent lifecycle). The
/// table has no digest column (DDL frozen) -> dedup via **row-level
/// comparison** skip-write (the same precedent as [`TrackerRow`];
/// externally identical to digest semantics); `created_at`/`updated_at`
/// are observational (excluded from comparison; a skip keeps the old
/// values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTaskRow {
    /// 16-hex GID (shared task namespace).
    pub gid: String,
    /// User-entered URI (persisted verbatim; outbound logging/redaction
    /// is the caller's duty).
    pub url: String,
    /// Final probed URL (redirect endpoint; validator input for resume).
    pub final_url: String,
    /// Multi-source expansion (source state/deranking JSON); None for
    /// single-source tasks. The store does not interpret the structure.
    pub mirrors_json: Option<String>,
    /// queued|probing|downloading|paused|error|done (no DDL CHECK; the
    /// value domain is the writer-side caller's duty).
    pub state: String,
    /// Queue order (stable ORDER BY key at recovery; a session-side
    /// increasing counter).
    pub queue_pos: i64,
    pub dir: String,
    /// Output file name (`--out`; the full path = dir/out, assembled
    /// engine-side).
    pub out: String,
    /// Per-task option subset as JSON (the task payload input face at
    /// recovery; the schema is a producer convention, the store does not
    /// interpret it; includes creation-time persisted items such as the
    /// incomplete suffix).
    pub config_json: String,
    /// Authoritative probe facts (canonical ValidatorFacts JSON —
    /// final_url_path/total length/ETag/Last-Modified/encoding decision;
    /// the decision payload behind the resume digest; **not** a
    /// multi-source aggregated probe transcript — the probe_json column
    /// name is a historical artifact of the frozen DDL). None before
    /// probing.
    pub probe_json: Option<String>,
    /// ResumeValidator payload digest (facts outside the validator
    /// decision table — the store only stores/returns bytes, validation
    /// semantics belong to upper layers; after a signed-URL change this
    /// decides resume eligibility).
    pub validator_digest: Option<Vec<u8>>,
    /// Block-grid granularity (a power of two, 256KiB..16MiB; immutable
    /// per task).
    pub block_size: i64,
    /// Block bitmap (the only persisted progress unit; block-completion
    /// accounting treats the bitmap as the single truth).
    pub block_bitmap: Option<Vec<u8>>,
    pub block_count: Option<i64>,
    /// Completed-bytes counter (progress display; recovery trusts the
    /// bitmap check, not this).
    pub total_done: i64,
    pub error_code: Option<String>,
    pub error_msg: Option<String>,
    /// Creation instant (epoch seconds; observational).
    pub created_at: i64,
    /// Instant of last content change (epoch seconds; observational).
    pub updated_at: i64,
}

/// task_cookie row payload (unified task cookie storage across
/// the http|media families; DDL field-for-field). Primary key =
/// `(gid, name, domain, path)` — the gid pool is shared across families
/// (globally unique gids), so one primary key spans both;
/// `task_kind` is a plain routing column (the GC/read faces route by
/// it, the PK does not). **No FK** (an explicit trade-off: a
/// unified table cannot FK to either parent family) — cleanup is the
/// single-writer paired-delete discipline (task-row delete paths clear
/// the gid's cookie rows in the same transaction) plus the startup GC
/// for crash orphans; cookies clear on the **full terminal set**
/// (done and error both). No independent row-level dedup — the write
/// face is a **whole-set replacement** ([`super::PersistJob::
/// UpsertTaskCookies`]: skip on an unchanged set, single-transaction
/// DELETE + batch INSERT, the same precedent as the [`IpfilterRow`]
/// whole-table replace). Domain/path/Secure/expiry semantics (RFC 6265
/// send constraints) belong to the upper cookie store; the store only
/// stores/returns bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCookieRow {
    /// Task gid (http or media family; shared gid pool).
    pub gid: String,
    /// `http`|`media` (the DDL CHECK domain; [`TASK_KIND_HTTP`] /
    /// [`TASK_KIND_MEDIA`]).
    pub task_kind: String,
    /// Cookie name (non-empty; injection checks belong to the upstream
    /// producer).
    pub name: String,
    /// Domain (canonical form: no leading `.`, lowercase).
    pub domain: String,
    /// Path (RFC 6265 §5.1.4 path-match input).
    pub path: String,
    /// Cookie value.
    pub value: String,
    /// Expiry instant (epoch seconds); `None` = session cookie (lives
    /// with the task).
    pub expires_utc: Option<i64>,
    /// HTTPS-only send (not sent on an https->http downgrade — an
    /// upper-layer send constraint).
    pub secure: bool,
    /// Host-only (exact-domain match only, no subdomains).
    pub host_only: bool,
    /// Creation instant (epoch seconds; RFC 6265 storage metadata).
    pub creation_utc: i64,
}

/// The http family's `task_kind` value.
pub const TASK_KIND_HTTP: &str = "http";

/// The media family's `task_kind` value.
pub const TASK_KIND_MEDIA: &str = "media";

/// Recovery snapshot for `LoadHttpTasksAtStartup`: the http_task row +
/// the task cookie set (the unified table replay; cookies in
/// name/domain/path order for deterministic replay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTaskSnapshot {
    pub row: HttpTaskRow,
    pub cookies: Vec<TaskCookieRow>,
}
