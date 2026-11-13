//! Task status views and the DownloadResult table payload (core
//! semantics; the RPC layer maps them onto aria2's string-valued JSON,
//! SPEC §8.2).
//!
//! Payloads stay core-layer: no JSON field names (forbidden in core) —
//! aria2 boolean strings ("true"/"false"), hex, and percent-encoding are
//! synthesized in taiji-rpc. Value-domain narrowings for the peer face
//! are hard invariants; see docs/design/core.md.
//!
//! Upstream anchor mapping: docs/design/core.md

use crate::gid::Gid;

/// Task status (a subset of the aria2 `status` value domain; `removed`
/// appears only in the DownloadResult table — the terminal state of a
/// removed task; RpcMethodImpl.cc tellStopped semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    /// Engine/metadata phase running (occupies a
    /// `--max-concurrent-downloads` slot).
    Active,
    /// Queued (not paused).
    Waiting,
    /// Queued and paused by the user (unpause re-enters at the queue
    /// front, SPEC §7.2).
    Paused,
    /// Terminal: failed (the GID keeps its result, SPEC §7.1).
    Error,
    /// Terminal: complete (covers post-seeding wrap-up and the
    /// bt-detach-seed-only wrap-up).
    Complete,
    /// Terminal: removed by the user.
    Removed,
    /// **Extended value** (the seed pool's one
    /// user-visible status-value change): parked in the seed-pool
    /// waiting FIFO (`seed_wait`) — the task's content is complete, it
    /// waits for a seed budget slot without occupying any running slot.
    /// Aligned with the persisted row state `'seeding'` (which covers
    /// seeding residence and seed_wait waiting alike — the `'checking'`
    /// pending+in-flight precedent). Since the unified projection
    /// finalization, **seeding residents** (engine running) project the
    /// same value (§5: the row state covers residence + seed_wait, the
    /// projection follows — tellActive/tellStatus read the live view
    /// face with this status; the interim of projecting
    /// residents as `active` is closed).
    Seeding,
    /// Parked in the check-pool waiting FIFO
    /// (`check_pending` — a recheck admitted but budget-gated). The
    /// tellWaiting check segment projects this value; **existing value
    /// domain, zero extension** — unlike the seed segment's 'seeding',
    /// `'checking'` has been the persisted row state for pending +
    /// in-flight verification since Phase A (`TORRENT_ACTIVE_STATES`),
    /// so no row-state value is added. In-flight rechecks still project
    /// `active` (the aria2 active-semantics face); the segment order
    /// and status-projection finalization landed (the fixed
    /// four-segment order lives in the queue's waiting snapshot).
    Checking,
}

impl StatusKind {
    /// The aria2 wire strings (RpcMethodImpl.cc VLB_* constants).
    pub fn as_str(self) -> &'static str {
        match self {
            StatusKind::Active => "active",
            StatusKind::Waiting => "waiting",
            StatusKind::Paused => "paused",
            StatusKind::Error => "error",
            StatusKind::Complete => "complete",
            StatusKind::Removed => "removed",
            StatusKind::Seeding => "seeding",
            StatusKind::Checking => "checking",
        }
    }
}

/// Ban source (the `listBans` source value domain): a peer_ban.reason
/// prefix classification (`session::bans::ban_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanSource {
    /// Automatic ban (hash failure streak / protocol violation,
    /// SPEC §13).
    Auto,
    /// Manual ban (`taiji.banAddr`, reason=manual).
    Manual,
    /// Client-identity ban (`client_ban_prefixes` hit,
    /// reason=client-ban:*).
    ClientBan,
}

impl BanSource {
    pub fn as_str(self) -> &'static str {
        match self {
            BanSource::Auto => "auto",
            BanSource::Manual => "manual",
            BanSource::ClientBan => "client-ban",
        }
    }
}

/// One `taiji.listBans` entry (core-semantics payload; an active ban =
/// peer_ban active rows ∪ session manual bookkeeping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntryView {
    /// Target text (a single IP or a normalized CIDR; the peer_ban.ip
    /// column value verbatim).
    pub target: String,
    /// Stored reason (manual / client-ban:* / automatic violation text).
    pub reason: String,
    /// Expiry instant (epoch seconds; `i64::MAX` = permanent).
    pub until: i64,
    /// Source classification.
    pub source: BanSource,
}

/// One getUris URI (createUriEntry, RpcMethodImpl.cc: status ∈
/// "used" | "waiting").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriEntryView {
    pub uri: String,
    /// "used" (consumed) | "waiting" (pending).
    pub status: &'static str,
}

/// One getFiles/tellStatus.files entry (createFileEntry in
/// RpcMethodImpl.cc + the SPEC §8.2 supplements
/// piecesRoot/pieceSize/padding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntryView {
    /// 1-based ordinal (aria2 index starts at 1).
    pub index: u64,
    /// Relative path (after metadata sanitization).
    pub path: String,
    /// aria2 `selected` = the truth of `FileEntry::isRequested()`
    /// (createFileEntry, RpcMethodImpl.cc): projected from the task
    /// selection face `selected_files` (None = all selected); the
    /// single projection source is [`file_selected`].
    pub selected: bool,
    /// Multi-level per-file priority echo (a `taiji.*` extension key;
    /// aria2 createFileEntry has no such key — aligned with the
    /// libtorrent `file_priority` capability). Domain: -1 skip /
    /// 0 normal / 1..7 high; default 0.
    pub priority: i8,
    pub length: u64,
    /// Folded from bitmap ranges ([`offset_completed_length`],
    /// BitfieldMan.cc direct translation); v2 synthetic bitmap
    /// coordinates = file ordinal × pieces per file.
    pub completed_length: u64,
    /// Always empty for BT tasks (aria2 FileEntry URIs are HTTP
    /// semantics).
    pub uris: Vec<UriEntryView>,
    /// v2 piece root for non-empty files (32B; SPEC §8.2
    /// `piecesRoot`, rendered hex at the RPC layer; v1 files are
    /// None → key omitted).
    pub pieces_root: Option<[u8; 32]>,
    /// Global uniform piece length (SPEC §8.2 `pieceSize`; the
    /// current BEP52 text).
    pub piece_size: u32,
    /// BEP47 padding file (never written to disk / requested).
    pub padding: bool,
    /// Hash-recovery projection (present only for files with a
    /// missing layer participating; None = key omitted). Value
    /// domain = `layer_missing` (layer missing, waiting for
    /// recovery) | `recovering` (hash fetch in progress) | `ready`
    /// (recovery upgrade completed). Sourced from the engine
    /// QueryStatus snapshot `recovery_files` (the live single
    /// source); waiting/terminal views have no engine snapshot →
    /// None (truthful: no recovery is in progress).
    pub recovery: Option<&'static str>,
}

/// The tellStatus.bittorrent sub-dict payload (the full
/// gatherBitTorrentMetadata set in RpcMethodImpl.cc + the SPEC §8.2
/// supplements metaVersion/v2InfoHash/private).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BittorrentView {
    /// info.comment (None/empty = key omitted; the aria2
    /// `!comment.empty()` rule).
    pub comment: Option<String>,
    /// info creation date (epoch seconds; 0 = omitted; the aria2
    /// `if (creationDate)` rule).
    pub creation_date: Option<i64>,
    /// "single" | "multi" (bittorrent_helper.cc getModeString;
    /// unknown during the metadata phase = None → key omitted).
    pub mode: Option<&'static str>,
    /// announce-list (tier → URL list; source = the session tracker
    /// table).
    pub announce_list: Vec<Vec<String>>,
    /// info.name (present only once metadata is ready; aria2 emits
    /// the info dict only when metadata is non-empty).
    pub name: Option<String>,
    /// SPEC supplement: the synthesized meta version (v1-only = 1;
    /// v2-only/hybrid = 2 — a hybrid info dict carries "meta
    /// version": 2; the metadata truth).
    pub meta_version: Option<u8>,
    /// SPEC supplement: the v2 identity (64 hex; v1-only None → key
    /// omitted, per the §2.6 v2-only value-domain narrowing).
    pub v2_info_hash: Option<[u8; 32]>,
    /// BEP27 private flag (knowable once metadata is ready; None
    /// during the magnet metadata phase → key omitted, never
    /// fabricated).
    pub private: Option<bool>,
}

/// One getPeers peer (gatherPeer in RpcMethodImpl.cc + the SPEC §8.2
/// transport/crypto extensions). Value-domain narrowings live in the
/// module header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntryView {
    /// Peer id (the raw 20-byte handshake value; the RPC layer
    /// applies torrentPercentEncode, util.cc direct translation).
    pub peer_id: Option<[u8; 20]>,
    pub ip: String,
    /// Inbound connections always report 0 (the aria2 isIncomingPeer
    /// branch).
    pub port: u16,
    /// The peer's possession bitmap (locally observed: bitfield/have
    /// event accumulation; rendered hex at the RPC layer).
    pub bitfield: Vec<u8>,
    /// Whether the local end chokes the peer (a mirror of the engine
    /// serving decision: not in the unchoke set = true; per BEP3 a
    /// connection starts choked).
    pub am_choking: bool,
    /// Whether the peer chokes the local end (value-domain narrowing:
    /// always false — see the module header).
    pub peer_choking: bool,
    pub download_speed: u64,
    pub upload_speed: u64,
    /// The peer is a seeder (holds every piece; the same criterion as
    /// aria2 isSeeder).
    pub seeder: bool,
    /// Transport face (live: a direct map of the engine
    /// connection-establishment snapshot).
    pub transport: PeerTransportKind,
    /// MSE encryption level (the real outcome of inbound sniffing /
    /// outbound negotiation).
    pub crypto: PeerCryptoKind,
}

/// Transport kinds (the SPEC §8.2 getPeers.transport value domain;
/// values surface live with the µTP data face).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransportKind {
    Tcp,
    Utp,
}

impl PeerTransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerTransportKind::Tcp => "tcp",
            PeerTransportKind::Utp => "utp",
        }
    }
}

/// MSE encryption levels (the SPEC §8.2 getPeers.crypto value domain;
/// source = the bt::mse negotiation result).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCryptoKind {
    Plain,
    Arc4,
}

impl PeerCryptoKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerCryptoKind::Plain => "plain",
            PeerCryptoKind::Arc4 => "arc4",
        }
    }
}

/// One getServers tracker (SPEC §8.2: the tracker view of
/// url/tier/state; the outer JSON keeps the aria2 `{index, servers}`
/// nesting at the RPC layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntryView {
    pub url: String,
    pub tier: i64,
    /// Synthesized state: "disabled" | "error" | "working" |
    /// "waiting" (enabled=false / last_error / last_ok_at /
    /// otherwise).
    pub status: &'static str,
    /// Scrape cache (unknown = None → key omitted).
    pub seeds: Option<i64>,
    pub leechers: Option<i64>,
    /// This server's current download rate (bytes/s; the source of
    /// the aria2 server dict's downloadSpeed key — a BT tracker
    /// snapshot has no live rate = 0; an HTTP source = the per-source
    /// measured reading, matching aria2 HTTP semantics).
    pub download_speed: u64,
}

/// Engine-side failure subdivision (the second dimension of the
/// numeric-code mapping table; the mapping's single source =
/// taiji-rpc, core only carries semantics — the same division of labor
/// as [`SessionError`]). Only subdivisions with a structured carrier
/// are structured (status codes / read-idle timeout); transport-chain
/// text subdivisions (DNS / connection refused / reset) and disk
/// payloads do not classify and are always
/// [`EngineFailureKind::Bare`], taking the mapping table's fallback
/// row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineFailureKind {
    /// No subdivision (a single-value code; Bare on a multi-value
    /// code = the mapping table's fallback row).
    Bare,
    /// `taiji.http.unexpected_response`: the raw HTTP status code
    /// (404 → 3 / 401 → 24 / 502..504 → 29 / otherwise → 22).
    Status(u16),
    /// `taiji.http.transport`: read-idle timeout (bounded by the
    /// task-level `--timeout`; the same slot as aria2 EX_TIME_OUT).
    TransportTimeout,
}

/// Engine-side structured failure (a canonical `taiji.*` code + a
/// subdivision dimension). Carried by HTTP error terminal states;
/// None = no structured code (merged into the numeric face in core).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFailure {
    /// The engine-side canonical code (a `taiji.*` string code;
    /// source = taiji-http `HttpError::code()` or the task-level
    /// bounding point).
    pub code: String,
    /// The subdivision dimension (the second dimension of multi-value
    /// codes).
    pub kind: EngineFailureKind,
}

impl EngineFailure {
    /// Construction without a subdivision (single-value code /
    /// fallback-row semantics).
    pub fn bare(code: impl Into<String>) -> Self {
        EngineFailure {
            code: code.into(),
            kind: EngineFailureKind::Bare,
        }
    }

    /// Construct from a taiji-http error: the canonical code + the
    /// subdivision decidable from existing structured carriers (the
    /// status-code family; other variant payloads are redacted text
    /// and do not classify).
    pub fn of_http_error(e: &taiji_http::error::HttpError) -> Self {
        let kind = match e {
            taiji_http::error::HttpError::UnexpectedResponse { status } => {
                EngineFailureKind::Status(*status)
            }
            _ => EngineFailureKind::Bare,
        };
        EngineFailure {
            code: e.code().to_string(),
            kind,
        }
    }
}

/// One tellStatus `http` sub-dictionary source entry
/// (sources[{url,rate,state}]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSourceView {
    /// Source URI (user submission order).
    pub url: String,
    /// This source's rate (bytes/s; measured attribution at the sink
    /// write point; no established reading = 0).
    pub rate: u64,
    /// Source state: active | waiting | demoted | removed | failed
    /// (active/waiting are driven by the worker's live state;
    /// demoted/removed are the coordinator source-ledger terminal
    /// projections; failed = dropped at probe failure or removed from
    /// the merge table — takes no part in this task's extent
    /// scheduling).
    pub state: String,
}

/// Closed-output lifecycle, independent of the compatibility task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpOutputPhase {
    Downloading,
    Ready,
    Publishing,
    Published,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpOutputView {
    pub phase: HttpOutputPhase,
    pub host_controlled: bool,
    pub paused: bool,
    pub source_path: Option<String>,
    pub final_path: Option<String>,
    pub length: Option<u64>,
    pub error: Option<String>,
}

/// The tellStatus `http` sub-dictionary payload (promised fields:
/// finalUrl/connections/extentsActive/blocksDone/blocksTotal/encoding/
/// renamePending/sources[]). Carried by HTTP tasks only (None = key
/// omitted for non-HTTP tasks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpView {
    /// The embedding host commits logical completion after native publication.
    pub host_controlled: bool,
    /// The final URL after probe-redirect convergence (unprobed = the
    /// user URI verbatim).
    pub final_url: String,
    /// Active connection count (in-flight worker extents).
    pub connections: u64,
    /// In-flight extent count (runtime state, never persisted).
    pub extents_active: u64,
    /// Completed block count (the bitmap truth).
    pub blocks_done: u64,
    /// Total blocks in the block grid (a degraded task = 0, no
    /// bitmap face).
    pub blocks_total: u64,
    /// Response encoding (a non-identity encoding as decided at
    /// probe; identity/default → None, key omitted at the RPC layer).
    pub encoding: Option<String>,
    /// Pending-rename flag (once Done the file is reachable only with
    /// the uncompleted suffix; the frozen-seam semantics live in the
    /// taiji-http finalize module).
    pub rename_pending: bool,
    /// Multi-source inventory (user submission order; one entry for
    /// single-source tasks).
    pub sources: Vec<HttpSourceView>,
}

/// The tellStatus `media` sub-dictionary payload (the media
/// presentation: kind/phase/phase_detail/track states/staging slots/
/// variant). Carried by media tasks only (None = key
/// omitted for non-media tasks, the bittorrent/http rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaView {
    /// `hls` (the media_task.kind domain).
    pub kind: String,
    /// The live/persisted phase (the media phase domain string).
    pub phase: String,
    /// Pause phase memory (`paused` + the remembered phase; None =
    /// key omitted).
    pub phase_detail: Option<String>,
    /// Per-track states (label/kind/state/segments done-total).
    pub tracks: Vec<MediaTrackView>,
    /// The task's staging directory (absolute).
    pub staging_dir: String,
    /// The sanitized output product name (§10 #1's persisted result).
    pub output_name: Option<String>,
    /// The resolved selector snapshot (verbatim expression).
    pub selector: Option<String>,
    /// The chosen variant's resolution (diagnostics; empty when
    /// unknown).
    pub variant: Option<String>,
    /// Manifest URL.
    pub manifest_url: String,
}

/// One track's state inside the media sub-dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaTrackView {
    /// Track label (`v`, `a`, `s0`).
    pub label: String,
    /// video|audio|subtitle.
    pub kind: String,
    /// active|degraded|failed|done.
    pub state: String,
    /// Segments done of total (`done/total` accounting basis: the
    /// persisted bitmap prefix).
    pub segments_done: usize,
    pub segments_total: usize,
}

/// The getGlobalStat payload (RpcMethodImpl.cc + the four-pool
/// extension keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalStatView {
    pub download_speed: u64,
    pub upload_speed: u64,
    /// Download-slot occupancy only (the four-pool caliber: seeding /
    /// checking / synthesis hold no download slot and are not counted;
    /// the formal migration, declared in the rpc-api-diff
    /// entry).
    pub num_active: u64,
    /// The four waiting segments merged (reserved + check_pending +
    /// seed_wait + proc_wait — the tellWaiting caliber, one source =
    /// the queue's waiting snapshot).
    pub num_waiting: u64,
    pub num_stopped: u64,
    pub num_stopped_total: u64,
    /// **Extension key** `numSeeding` (aria2 has no such key): seeding
    /// residents in flight (`seeding_len` — the seed budget
    /// denominator; the seed_wait FIFO is NOT included).
    pub num_seeding: u64,
    /// **Extension key** `numChecking`: rechecks in flight
    /// (`checking_len`; the check_pending FIFO is NOT included).
    pub num_checking: u64,
    /// **Extension key** `numSynthesizing`: media syntheses in flight
    /// (`processing_len`; the proc_wait FIFO is NOT included).
    pub num_synthesizing: u64,
}

/// One status view of tellActive/tellWaiting/tellStopped/tellStatus
/// (full; shared by both sources: a live engine snapshot / a
/// DownloadResult table entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentStatusView {
    pub gid: Gid,
    pub status: StatusKind,
    /// Known total (metainfo total length; 0 during the magnet/url
    /// metadata phase — the same caliber as aria2 magnet
    /// totalLengthIsUnknown, bittorrent_helper).
    pub total_length: u64,
    /// Verified completed bytes (synthesized caliber: Σ per-file
    /// verified + padding counted full; a terminal entry = the
    /// snapshot at wrap-up).
    pub completed_length: u64,
    /// Cumulative upload (includes the pre-session base; the aria2
    /// allTimeUploadLength caliber).
    pub upload_length: u64,
    /// Cumulative download (session counter; the stopped face does
    /// not get this key in aria2 — the local end keeps the semantic
    /// value, and the RPC layer omits the key per source).
    pub download_length: u64,
    /// 10s sliding-window speed (always 0 when stopped; the aria2
    /// VLB_ZERO rule).
    pub download_speed: u64,
    pub upload_speed: u64,
    /// Active connection count (always 0 when stopped).
    pub connections: u64,
    /// Synthesized bitfield (SPEC §4.4: a v1 real bitmap / a v2
    /// file-ordinal × pieces-per-file concat; trailing spare bits
    /// are 0. None = no bitmap face (metadata phase / zero-piece
    /// task) → key omitted at the RPC layer; the aria2
    /// `getBitfieldLength() > 0` rule).
    pub bitfield: Option<Vec<u8>>,
    /// Global uniform piece length (0 when unknown; the same value
    /// as aria2's magnet phase).
    pub piece_length: u32,
    /// Global piece count (the synthesized view's Σ of per-file
    /// pieces; 0 when unknown).
    pub num_pieces: u64,
    /// followedBy (the magnet in-place upgrade = a degenerate chain
    /// of the same GID → an empty table, key omitted).
    pub followed_by: Vec<Gid>,
    pub following: Option<Gid>,
    pub belongs_to: Option<Gid>,
    /// File list (a waiting active task = full metadata +
    /// completed 0).
    pub files: Vec<FileEntryView>,
    /// The full file count when `files` is truncated (None = not
    /// truncated).
    pub num_files_full: Option<u64>,
    pub dir: String,
    /// BT attachment face (None = a non-BT / metadata-not-ready task
    /// has no attrs face, per aria2).
    pub bittorrent: Option<BittorrentView>,
    /// 20B infohash: the raw v1 sha1; v2-only is always the
    /// truncated sha256 (the field caliber is documented). None =
    /// metadata not ready.
    pub info_hash: Option<[u8; 20]>,
    /// Seeder peer count (no peer face = 0; the aria2 !btObject →
    /// VLB_ZERO rule).
    pub num_seeders: u64,
    /// Whether the local end is a seeder (None = no bitmap face →
    /// key omitted; aria2 always emits true/false — a local
    /// value-domain narrowing premised on the bitmap face existing).
    pub seeder: Option<bool>,
    /// Terminal error code (stopped source only; aria2 ds->result:
    /// FINISHED=0/REMOVED=31/everything else merged to
    /// 1=UNKNOWN_ERROR).
    pub error_code: Option<u64>,
    /// Engine-side structured failure (canonical code + subdivision;
    /// HTTP task error terminal states only). The numeric-code
    /// mapping's single source is taiji-rpc: the RPC render face
    /// resolves per code + per subdivision directly (the status-code
    /// family and the read-idle timeout keep their kind — they do
    /// not collapse).
    pub error_engine: Option<EngineFailure>,
    /// Terminal error message (stopped source only; None → the RPC
    /// layer emits an empty string; aria2 always emits the key).
    pub error_message: Option<String>,
    /// HTTP task attachment face (the `http` sub-dictionary; None =
    /// key omitted for non-HTTP tasks — the bittorrent field, same
    /// rule).
    pub http: Option<HttpView>,
    /// Media task attachment face (the `media` sub-dictionary; None =
    /// key omitted for non-media tasks — the same rule as http).
    pub media: Option<MediaView>,
}

impl TorrentStatusView {
    /// Minimal constructor (existing-caller compatibility: the four
    /// length fields + zero values elsewhere).
    pub fn minimal(gid: Gid, status: StatusKind, total: u64, completed: u64) -> TorrentStatusView {
        TorrentStatusView {
            gid,
            status,
            total_length: total,
            completed_length: completed,
            upload_length: 0,
            download_length: 0,
            download_speed: 0,
            upload_speed: 0,
            connections: 0,
            bitfield: None,
            piece_length: 0,
            num_pieces: 0,
            followed_by: Vec::new(),
            following: None,
            belongs_to: None,
            files: Vec::new(),
            num_files_full: None,
            dir: String::new(),
            bittorrent: None,
            info_hash: None,
            num_seeders: 0,
            seeder: None,
            error_code: None,
            error_engine: None,
            error_message: None,
            http: None,
            media: None,
        }
    }
}

/// The per-file `selected` truth projection (the single projection
/// source of [`FileEntryView::selected`]: every emission site
/// converges here; views must not hardcode their own).
///
/// Reference cross-validation: aria2
/// `selected = FileEntry::isRequested()` (RpcMethodImpl.cc); the
/// libtorrent boolean equivalent = `file_priorities[i] > 0` (the
/// BEP53 protocol behavior face; no aria2 counterpart).
///
/// `selection` = the task selection face (`cfg.selected_files`). The
/// BEP53 index caliber = the client file-list order — 0-based over
/// **non-pad entries** (pad entries are BEP47 transport placeholders,
/// not files, and are not counted; the same anchor as the engine
/// `selection_mask` / `so=` parsing):
/// - `None` = select all (every file true, pad placeholder entries
///   included — the isRequested default face; zero behavior change
///   for tasks without a selection);
/// - `Some(set)` = only members true. `client_idx` = the file's
///   ordinal in the non-pad order; pad entries pass `None` (not in
///   the client list → always false).
pub fn file_selected(selection: Option<&[u32]>, client_idx: Option<u32>) -> bool {
    match (selection, client_idx) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(set), Some(i)) => set.contains(&i),
    }
}

/// A DownloadResult table entry (isomorphic to aria2 `DownloadResult`:
/// stopped groups stay in the table for tellStopped /
/// removeDownloadResult consumption; RequestGroupMan.cc
/// `addDownloadResult` — `numStoppedTotal` only grows, purge only
/// clears the table).
///
/// The terminal display snapshot (the files/piece face and the
/// bittorrent dict) is synthesized into the entry by the actor at
/// wrap-up from the task payload — the isomorphic face of aria2
/// DownloadResult keeping fileEntries/bitfield/attrs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadResultEntry {
    pub gid: Gid,
    pub status: StatusKind,
    pub total_length: u64,
    pub completed_length: u64,
    pub upload_length: u64,
    pub download_length: u64,
    /// The task download directory (the source of tellStopped's dir
    /// key; aria2 ds->dir).
    pub dir: String,
    /// The wrap-up explicit failure message (the error_message key
    /// source; None → the empty-string caliber).
    pub error_message: Option<String>,
    /// Engine-side structured failure (canonical code + subdivision;
    /// carried by HTTP task error terminal states; see
    /// [`TorrentStatusView::error_engine`] for the numeric-face
    /// chain).
    pub error_engine: Option<EngineFailure>,
    /// The synthesized bitfield's final value (complete = an all-1
    /// synthetic bitmap; other terminal states keep no partial
    /// bitmap → None → key omitted at the RPC layer; the aria2
    /// empty-bitmap default).
    pub bitfield: Option<Vec<u8>>,
    pub piece_length: u32,
    pub num_pieces: u64,
    /// 20B infohash (the raw v1 value / the v2-only truncated
    /// caliber; see [`TorrentStatusView::info_hash`]).
    pub info_hash: Option<[u8; 20]>,
    /// File snapshot (completed_length: complete = full, otherwise
    /// 0 — a partial bitmap is not kept).
    pub files: Vec<FileEntryView>,
    /// Full file count (the original total when `files` exceeds
    /// MAX_RESULT_FILES and is truncated; None = not truncated).
    pub num_files_full: Option<u64>,
    pub bittorrent: Option<BittorrentView>,
    /// The HTTP task's `http` sub-dictionary terminal snapshot (the
    /// live reading at retire; None = key omitted for non-HTTP
    /// tasks).
    pub http: Option<HttpView>,
    /// The media task's `media` sub-dictionary terminal snapshot
    /// (None = key omitted for non-media tasks).
    pub media: Option<MediaView>,
}

/// GID prefix resolution errors (aria2 str2Gid →
/// GroupId::expandUnique's three branches, GroupId.cc +
/// RpcMethodImpl.cc; the actor layer formats the message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GidResolveError {
    /// Non-hex / length 0 or >16 (aria2 ERR_INVALID → "Invalid GID
    /// %s").
    Invalid,
    /// Prefix with no hit (ERR_NOT_FOUND → "GID %s is not found").
    NotFound,
    /// Prefix with multiple hits (ERR_NOT_UNIQUE → "GID %s is not
    /// unique").
    NotUnique,
}

/// expandUnique prefix resolution (GroupId.cc direct translation):
/// the hex string left-aligns into a 64-bit prefix p
/// (`p <<= 64 - i*4`), then a hit of `(gid & mask) == p` is searched
/// across the known GID set — exactly one → expand; several →
/// NotUnique; zero → NotFound; non-hex / overlong / empty → Invalid.
pub fn expand_unique(hex: &str, known: &[Gid]) -> Result<Gid, GidResolveError> {
    let n = hex.len();
    if n == 0 || n > 16 {
        return Err(GidResolveError::Invalid);
    }
    let mut p: u64 = 0;
    for c in hex.chars() {
        let v = match c.to_digit(16) {
            Some(d) => u64::from(d),
            // The hexCharToUInt failure face (GroupId.cc).
            None => return Err(GidResolveError::Invalid),
        };
        p = (p << 4) | v;
    }
    let shift = 64 - n * 4;
    p <<= shift;
    let mask: u64 = u64::MAX - ((1u64 << shift) - 1);
    // The first element ≥ p via lower_bound (the set is ascending);
    // the prefix-hit verdict matches the reference.
    let first = known.iter().filter(|g| g.as_u64() >= p).min();
    match first {
        Some(g) if g.as_u64() & mask == p => {
            let uniq = !known
                .iter()
                .any(|o| o.as_u64() > g.as_u64() && o.as_u64() & mask == p);
            if uniq {
                Ok(*g)
            } else {
                Err(GidResolveError::NotUnique)
            }
        }
        _ => Err(GidResolveError::NotFound),
    }
}

/// Completed length folded from bitmap ranges (a BitfieldMan.cc
/// `getOffsetCompletedLength` direct translation; bitmap coordinates
/// = synthetic piece ordinals, block = the global uniform piece
/// length). `total_bits × piece_len` is the total synthetic-space
/// length. Files align to the v1 layout / the synthetic base; a last
/// piece's overflow is not folded into this file.
pub fn offset_completed_length(
    bitfield: &[u8],
    piece_len: u32,
    total_bits: u64,
    offset: u64,
    length: u64,
) -> u64 {
    let piece_len = u64::from(piece_len);
    if length == 0 || piece_len == 0 {
        return 0;
    }
    let total = total_bits.saturating_mul(piece_len);
    if total <= offset {
        return 0;
    }
    let length = length.min(total - offset);
    let bit = |i: u64| bitfield[(i / 8) as usize] & (0x80 >> (i % 8)) != 0;
    let start = offset / piece_len;
    let end = (offset + length - 1) / piece_len;
    if start == end {
        if bit(start) {
            return length;
        }
        return 0;
    }
    let mut res = 0;
    if bit(start) {
        res += (start + 1) * piece_len - offset;
    }
    for i in start + 1..end {
        if bit(i) {
            res += piece_len;
        }
    }
    if bit(end) {
        res += offset + length - end * piece_len;
    }
    res
}

/// Per-file completedLength (the aria2 createFileEntry caliber: folded
/// from bitmap ranges). `bases` = each file's starting piece ordinal
/// in the synthetic piece space — the same coordinate system as the
/// engine `ProgressModel`: v1/hybrid = the prefix sums of layout file
/// piece counts (equal when aligned to v1_offset/piece_len); v2 = the
/// prefix sums of file ordinals.
pub fn per_file_completed(
    bitfield: &[u8],
    piece_len: u32,
    file_bases: &[u64],
    file_lens: &[u64],
) -> Vec<u64> {
    file_bases
        .iter()
        .zip(file_lens)
        .map(|(&base, &len)| {
            let bits = if len == 0 {
                0
            } else {
                len.div_ceil(u64::from(piece_len))
            };
            // The range arguments = piece ordinal × piece_len (the
            // aria2 file->getOffset() byte semantics).
            offset_completed_length(
                bitfield,
                piece_len,
                base + bits,
                base * u64::from(piece_len),
                len,
            )
        })
        .collect()
}

/// Each file's starting piece ordinal in the synthetic piece space
/// (the `ProgressModel` coordinate system: Σ of the preceding files'
/// ceil(len/piece_len)).
pub fn file_piece_bases(file_lens: &[u64], piece_len: u32) -> Vec<u64> {
    let mut bases = Vec::with_capacity(file_lens.len());
    let mut acc = 0u64;
    for &len in file_lens {
        bases.push(acc);
        if len > 0 {
            acc += len.div_ceil(u64::from(piece_len));
        }
    }
    bases
}

/// Raw metainfo bytes → top-level display attributes (comment /
/// creation date / info.name). Lenient parsing: a missing field or a
/// type mismatch → None (the same defaults as aria2
/// gatherBitTorrentMetadata). Metainfo bytes are captured by the
/// session on the addTorrent / URL upgrade paths (metainfo.rs's parse
/// face is untouched — a frozen cross-module interface).
pub fn torrent_top_attrs(bytes: &[u8]) -> (Option<String>, Option<i64>, Option<String>) {
    use taiji_bt::bencode;
    let Ok(top) = bencode::decode(bytes) else {
        return (None, None, None);
    };
    let get_str = |dict: &bencode::Value, key: &[u8]| -> Option<String> {
        match dict.get(key) {
            Some(bencode::Value::Bytes(b)) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }
    };
    let comment = get_str(&top, b"comment").filter(|s| !s.is_empty());
    let creation = match top.get(b"creation date") {
        Some(bencode::Value::Int(i)) if *i > 0 => Some(*i),
        _ => None,
    };
    let name = top
        .get(b"info")
        .and_then(|info| get_str(info, b"name"))
        .filter(|s| !s.is_empty());
    (comment, creation, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(n: u64) -> Gid {
        Gid::from_u64(n)
    }

    /// The StatusKind value-domain anchor:
    /// exactly eight variants — the aria2 six (active/waiting/paused/
    /// error/complete/removed) plus the one extension
    /// ('seeding') and the row-state shared 'checking'
    /// (both existing row-state values, zero new row-state
    /// extension). A new variant or a drifted wire string turns this
    /// red.
    #[test]
    fn status_kind_variant_set_and_wire_strings_anchor() {
        let all: [(StatusKind, &str); 8] = [
            (StatusKind::Active, "active"),
            (StatusKind::Waiting, "waiting"),
            (StatusKind::Paused, "paused"),
            (StatusKind::Error, "error"),
            (StatusKind::Complete, "complete"),
            (StatusKind::Removed, "removed"),
            (StatusKind::Seeding, "seeding"),
            (StatusKind::Checking, "checking"),
        ];
        for (kind, wire) in all {
            assert_eq!(kind.as_str(), wire, "wire-string drift: {wire}");
        }
        // Distinctness (a copy-paste variant pair would silently
        // collapse the domain).
        let mut wire_strings: Vec<&str> = all.iter().map(|(_, w)| *w).collect();
        wire_strings.sort();
        let total = wire_strings.len();
        wire_strings.dedup();
        assert_eq!(
            wire_strings.len(),
            total,
            "the value domain has duplicate wire strings"
        );
    }

    // ---- expandUnique's three branches (GroupId.cc) ----
    // This engine's GIDs always set the top bit → prefix
    // strings match hex digits starting "8".."f" left-aligned.

    /// A unique prefix → expand; more digits disambiguate more
    /// strongly.
    #[test]
    fn expand_unique_prefix_resolves_single_match() {
        let known = vec![g(0x8000_0000_0000_1234), g(0x8000_0000_0000_5678)];
        // A 13-digit prefix: the top 52 bits of GID1 hit uniquely.
        assert_eq!(
            expand_unique("8000000000001", &known),
            Ok(g(0x8000_0000_0000_1234))
        );
        // A 14-digit prefix, same.
        assert_eq!(
            expand_unique("80000000000012", &known),
            Ok(g(0x8000_0000_0000_1234))
        );
        // The full 16 hex digits hit exactly.
        assert_eq!(
            expand_unique("8000000000001234", &known),
            Ok(g(0x8000_0000_0000_1234))
        );
        assert_eq!(
            expand_unique("8000000000005678", &known),
            Ok(g(0x8000_0000_0000_5678))
        );
    }

    /// A non-unique prefix → NotUnique (GroupId.cc's second-hit
    /// check).
    #[test]
    fn expand_unique_ambiguous_prefix_is_rejected() {
        let known = vec![g(0x8000_0000_0000_1234), g(0x8000_0000_0000_5678)];
        // The top 16 bits ("8000") and the top 48 bits
        // ("800000000000") share a prefix across both GIDs.
        for prefix in ["8000", "800000000000"] {
            assert_eq!(
                expand_unique(prefix, &known),
                Err(GidResolveError::NotUnique),
                "prefix {prefix}"
            );
        }
    }

    /// Missing / illegal → NotFound / Invalid (the str2Gid message
    /// branches).
    #[test]
    fn expand_unique_missing_and_invalid_shapes() {
        let known = vec![g(0x8000_0000_0000_0001)];
        // The prefix has no hit.
        assert_eq!(
            expand_unique("9999", &known),
            Err(GidResolveError::NotFound)
        );
        // Exact 16 hex but not in the set (= not found, aria2 same).
        assert_eq!(
            expand_unique("8000000000000002", &known),
            Err(GidResolveError::NotFound)
        );
        // Non-hex.
        assert_eq!(expand_unique("xyz", &known), Err(GidResolveError::Invalid));
        // Empty / overlong (>16).
        assert_eq!(expand_unique("", &known), Err(GidResolveError::Invalid));
        assert_eq!(
            expand_unique("8000000000000000f", &known),
            Err(GidResolveError::Invalid)
        );
        // An empty set → not found.
        assert_eq!(expand_unique("8", &[]), Err(GidResolveError::NotFound));
    }

    // ---- the selected truth projection (the aria2 isRequested
    // caliber) ----

    /// The file_selected truth table: None = select all (pad
    /// placeholder entries included); Some(set) = non-pad members
    /// true; non-members and pad entries false.
    #[test]
    fn file_selected_truth_table() {
        // The None face: select all (the isRequested default — zero
        // change without a selection).
        assert!(file_selected(None, Some(0)));
        assert!(file_selected(None, Some(41)));
        assert!(
            file_selected(None, None),
            "a pad placeholder entry is always true on the select-all face"
        );
        // The Some face: BEP53 non-pad 0-based membership.
        let sel: &[u32] = &[0, 2];
        assert!(file_selected(Some(sel), Some(0)));
        assert!(!file_selected(Some(sel), Some(1)));
        assert!(file_selected(Some(sel), Some(2)));
        assert!(!file_selected(Some(sel), Some(3)));
        // Pad entries are not in the client list (BEP47 transport
        // placeholders, not files) → never selected on a Some face.
        assert!(!file_selected(Some(sel), None));
        // An empty selection set = nothing selected (the projection
        // face; acceptance has its own explicit rejection).
        let empty: &[u32] = &[];
        assert!(!file_selected(Some(empty), Some(0)));
    }

    // ---- synthesized bitfield ↔ caliber cross-validation ----

    /// The synthesized bitmap (ProgressModel) expanded ↔
    /// per_file_completed agrees with the per-file truth. Fixture =
    /// v1-only three entries (the hybrid fixture gives the same
    /// numbers): a.bin 70000 (5 pieces) / pad 11920 (1 model piece) /
    /// b.bin 30000 (2 pieces); 16384 piece length; bases =
    /// [`file_piece_bases`] (0/5/6, the model coordinate system).
    #[test]
    fn synthesized_bitfield_drives_per_file_completed() {
        use crate::metainfo::{MetaFile, TorrentIdentity, TorrentMeta};
        use crate::progress::ProgressModel;
        use taiji_bt::filetree::SwarmKind;
        let pl = 16384u32;
        let mk = |path: &str, length: u64, padding: bool| MetaFile {
            path: path.into(),
            length,
            padding,
            pieces_root: None,
            piece_layer: None,
            v1_offset: None,
        };
        let meta = TorrentMeta {
            identity: TorrentIdentity { v1: None, v2: None },
            kind: SwarmKind::V1Only,
            piece_length: pl,
            files: vec![
                mk("a.bin", 70000, false),
                mk(".pad/11920", 11920, true),
                mk("b.bin", 30000, false),
            ],
        };
        let mut pm = ProgressModel::from_meta(&meta);
        // Set bits: all 5 pieces of a + piece 0 of b (the pad piece
        // stays unset — the engine's real bitmap caliber).
        for i in 0..5 {
            pm.set_piece_done(0, i);
        }
        pm.set_piece_done(2, 0);
        let (bits, total) = pm.synthesized_bitfield();
        assert_eq!(total, 8);

        // The synthesized bitmap bit by bit ↔ the per-file truth
        // (caliber cross-validation).
        let mut expect: Vec<bool> = Vec::new();
        for f in &pm.files {
            for i in 0..f.piece_count {
                expect.push(f.piece_done(i));
            }
        }
        for (k, done) in expect.iter().enumerate() {
            assert_eq!(bits[k / 8] & (0x80 >> (k % 8)) != 0, *done, "bit {k}");
        }

        // Base derivation (the session layer and ProgressModel share
        // the formula).
        let bases = file_piece_bases(&[70000, 11920, 30000], pl);
        assert_eq!(bases, vec![0, 5, 6]);
        let completed = per_file_completed(&bits, pl, &bases, &[70000, 11920, 30000]);
        // a.bin: all 5 pieces done → 70000 (the last piece's
        // remainder counts only in-file bytes by range folding).
        assert_eq!(completed[0], 70000);
        // The pad file: its model piece (synthetic bit 5) is unset →
        // 0 (the bitmap truth; the difference from completed_length's
        // "pad counts full" caliber is a SPEC §4.4 note).
        assert_eq!(completed[1], 0);
        // b.bin: piece 0 good (16384) + piece 1 not → 16384.
        assert_eq!(completed[2], 16384);
    }

    /// The offset_completed_length boundary table (a BitfieldMan.cc
    /// direct translation): single-piece cross-range, empty length,
    /// out of bounds, last-piece truncation.
    #[test]
    fn offset_completed_length_table() {
        let bf = [0b1100_0000u8]; // pieces 0 and 1 complete
        let pl = 100u32;
        assert_eq!(offset_completed_length(&bf, pl, 8, 0, 100), 100);
        assert_eq!(offset_completed_length(&bf, pl, 8, 100, 100), 100);
        assert_eq!(offset_completed_length(&bf, pl, 8, 200, 100), 0);
        // An incomplete piece.
        assert_eq!(offset_completed_length(&bf, pl, 8, 200, 100), 0);
        // Last-piece truncation: total_bits=3 → total 300; request
        // [200,300).
        assert_eq!(offset_completed_length(&bf, pl, 3, 0, 1000), 200);
        // Empty length.
        assert_eq!(offset_completed_length(&bf, pl, 8, 0, 0), 0);
    }

    /// torrent_top_attrs: comment/creation date/name extraction + the
    /// default face.
    #[test]
    fn torrent_top_attrs_parses_and_defaults() {
        use taiji_bt::bencode::{self, Value};
        let mk = |comment: Option<&[u8]>, date: Option<i64>, name: &str| {
            let mut top: Vec<(Vec<u8>, Value)> = Vec::new();
            if let Some(c) = comment {
                top.push((b"comment".to_vec(), Value::Bytes(c.to_vec())));
            }
            if let Some(d) = date {
                top.push((b"creation date".to_vec(), Value::Int(d)));
            }
            top.push((
                b"info".to_vec(),
                Value::Dict(
                    vec![(b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec()))]
                        .into_iter()
                        .collect(),
                ),
            ));
            bencode::encode(&Value::Dict(top.into_iter().collect()))
        };
        let (c, d, n) =
            torrent_top_attrs(&mk(Some(b"hello"), Some(1700000000), "t.bin").unwrap_or_default());
        assert_eq!(c.as_deref(), Some("hello"));
        assert_eq!(d, Some(1700000000));
        assert_eq!(n.as_deref(), Some("t.bin"));
        // Defaults: no comment/creation date → None; creation date=0
        // → None.
        let (c, d, n) = torrent_top_attrs(&mk(None, Some(0), "x").unwrap_or_default());
        assert_eq!(c, None);
        assert_eq!(d, None);
        assert_eq!(n.as_deref(), Some("x"));
        // Non-bencode bytes → all None.
        assert_eq!(torrent_top_attrs(b"garbage"), (None, None, None));
    }
}
