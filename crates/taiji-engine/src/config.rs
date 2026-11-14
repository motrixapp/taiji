//! Engine configuration surface (assembly-time data): `EngineConfig`/
//! `FaceConfig`/`FaceKind`/`DhtWireConfig`/`TrackerWireConfig`/
//! `WriterFactory`.
//!
//! Scope: config structures and defaults for swarm faces and the engine,
//! the storage-construction hook trait, and the metainfo -> EngineConfig
//! assembly function (`engine_config`, the single source for swarm-face
//! assembly; domain-side metainfo does not reference engine types).
//! Runtime state (faces), network wiring (transit/dht), and persistence
//! (tracker/progress) live elsewhere.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use taiji_bt::dht::DhtEngineConfig;
use taiji_bt::dht::engine::DHT_PEER_ANNOUNCE_INTERVAL;
use taiji_bt::filetree::SwarmKind;
use taiji_bt::info_hash::truncated_v2;
use taiji_bt::mse::CryptoPolicy;
use taiji_bt::peer_policy::IpGuardHandle;
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_bt::tracker::TrackerOptions;
use taiji_io::rate_limit::LimiterSet;
use taiji_store::disk::DiskWriter;
use taiji_store::error::StoreError;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::Layout;
use taiji_store::merkle;
use taiji_store::persist::PersistHandle;
use taiji_store::verified::CrossRule;

use taiji_domain::metainfo::{MetaFile, Metainfo, MetainfoError};
use taiji_domain::seed::SeedPolicy;

/// Piece-vector budget cap: expected/piece_goffs/piece_bytes (assembly)
/// and the ClaimedSet/progress bitmap pair (runtime) all allocate
/// linearly in piece count, ~49B per piece combined. 2^22 pieces =>
/// ~200MB allocation bound; the legitimate real-world domains of 16KiB
/// pieces (64GiB) and 4MiB pieces (16TiB) stay within bounds — exceeding
/// the cap means a metadata length-declaration attack (the v1 face
/// pre-intercepts via the 20B x piece-count consistency of the pieces
/// string; v2 has no equivalent, so this cap is the unified v1/v2 gate).
pub(crate) const MAX_TORRENT_PIECES: u64 = 1 << 22;

/// Piece-count budget check (rejects only above the cap — exactly at the
/// cap is the legal 16KiB-piece 64GiB domain).
pub(crate) fn ensure_piece_budget(pieces: u64) -> Result<(), MetainfoError> {
    if pieces > MAX_TORRENT_PIECES {
        return Err(MetainfoError::PieceBudgetExceeded {
            pieces,
            max: MAX_TORRENT_PIECES,
        });
    }
    Ok(())
}

/// Swarm-face kind (data-plane protocol format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceKind {
    /// v1 data plane: stream piece space (BEP 3), Flat addressing,
    /// whole-piece SHA-1 verification.
    V1,
    /// v2 data plane: per-file piece space (BEP 52), PerFile addressing,
    /// piece-root verification. Wire identity = truncated sha256.
    V2,
}

/// Engine configuration for one swarm face (assembled from metainfo).
#[derive(Debug)]
pub struct FaceConfig {
    pub kind: FaceKind,
    /// 20B transport identity: v1 = the sha1 as-is; v2 = the first 20B of
    /// the sha256.
    pub info_hash: [u8; 20],
    /// Reserved bits for outbound/inbound handshakes (fast + ext [+ v2
    /// capability bit]).
    pub reserved: Reserved,
    /// wire index <-> PieceId addressing (v1 = Flat; v2 = the PerFile base
    /// table).
    pub addressing: Addressing,
    /// Expected hashes (synthetic flat order): v1 = whole-piece SHA-1;
    /// v2 = the piece root per piece.
    pub expected: Vec<ExpectedPieceHash>,
    /// Flat piece order -> global disk offset (v1 = k*piece_len; v2 =
    /// v2_piece_offset).
    pub piece_goffs: Vec<u64>,
    /// Flat piece order -> that piece's byte count (final block truncation
    /// for requests; the v2 last piece follows the file remainder).
    pub piece_bytes: Vec<u64>,
    /// File-length table for the HashPool plan (v1 = [stream total]; v2 =
    /// the real file lengths).
    pub plan_file_lengths: Vec<u64>,
    /// File-length table for the progress model (v1 = [stream total]; v2
    /// = the real file lengths).
    pub progress_file_lens: Vec<u64>,
    /// Cross-verification table (hybrid's two faces; empty = single-format
    /// torrent).
    pub cross: Vec<Option<CrossRule>>,
    /// hash-request serving file surface (non-empty for a v2 face whose
    /// metadata has a v2 representation; `MetaFile::v1_offset` is
    /// backfilled with the real disk-layout offset).
    pub hash_files: Option<Vec<MetaFile>>,
}

impl FaceConfig {
    /// Flat piece count (the assembler guarantees
    /// expected/piece_goffs/piece_bytes have equal lengths).
    pub fn piece_count(&self) -> usize {
        self.expected.len()
    }

    /// The face's total size (the announce `left` basis; v1 includes pad
    /// placeholders, v2 = the real file sum).
    pub fn total(&self) -> u64 {
        self.piece_bytes.iter().sum()
    }
}
/// Preset progress bitmaps (the `--check-integrity` bare-run recheck
/// surface): field shapes align with the bitmap columns of
/// [`taiji_store::persist::TorrentProgressRow`] — the CLI measures the
/// target directory before spawning the engine
/// (`taiji_core::session::recheck`, the same entry point and expected-
/// hash surface as checking-state re-entry) and injects the measured
/// bitmaps via [`EngineConfig::preset_progress`]. The engine consumes it
/// in build_faces as the bitmap restore source (a persist row wins; this
/// field applies when there is no row — a bare run without a session
/// store always takes this arm), with restore semantics identical to row
/// restore (progress/written_progress/written_bits set + verified/
/// written_count counters). Hard line: this field does not participate
/// in the `resume_existing` decision (allocate=false skips allocation ->
/// missing files are not created -> the write path is Fatal); the preset
/// path uses allocate=true, adding the existing-file open semantics (no
/// truncate, no zero-fill — the recheck-measured bytes match the
/// declared bitmap). None = default (zero behavior difference).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresetProgress {
    /// v1/hybrid global piece bitmap (face 0 basis, MSB first; None for
    /// v2-only).
    pub v1_bitfield: Option<Vec<u8>>,
    /// v2-only per-file bitmaps (`[u32 fi][u32 count][bits]` concatenated,
    /// the torrent_progress.v2_file_bits format; None for v1/hybrid —
    /// both faces are backfilled from the v1 bitmap, BEP 52 alignment
    /// k<->k).
    pub v2_file_bits: Option<Vec<u8>>,
}

/// Engine configuration (CLI/tests assemble it from metainfo).
pub struct EngineConfig {
    /// Zero-based non-padding file indices, applied before storage and dispatch.
    pub initial_selection: Option<Vec<u32>>,
    pub peer_id: [u8; 20],
    pub announce: String,
    pub listen_port: u16,
    /// The single global piece length (shared by both faces; v2/hybrid =
    /// the BEP 52 constrained value, v1-only = the BEP 3 positive-integer
    /// domain — validated per face at parse time; the assembly side does
    /// not re-check).
    pub piece_len: u32,
    /// Disk layout (used by the seeding ReaderSource and the
    /// WriterFactory).
    pub layout: Layout,
    pub dest: PathBuf,
    /// Whether to stay resident as a seeder once all pieces complete
    /// (true = CLI semantics; false = return on completion).
    pub seed_after_complete: bool,
    /// Seeding-ops policy (default = the frozen defaults).
    pub seed: SeedPolicy,
    /// Storage construction hook (None = the standard TorrentWriter +
    /// truncate allocation).
    pub writer_factory: Option<Arc<dyn WriterFactory>>,
    /// Disk-protection tier policy (three tiers; default throughput =
    /// zero behavior change,
    /// [`taiji_store::disk_policy::DiskPolicy::default`]). Per-torrent
    /// override = the config_json `disk_tier` key (no RPC option
    /// promised): the session activation chain overwrites this field per
    /// task payload via `build_engine_config`; the store pipeline
    /// consumes it (allocation style / write coalescing / flush cadence /
    /// IO quota).
    pub disk_policy: taiji_store::disk_policy::DiskPolicy,
    /// Swarm faces (1 = v1-only/v2-only; 2 = hybrid's two faces).
    pub faces: Vec<FaceConfig>,
    /// MSE/crypto policy (`--bt-require-crypto`/`--bt-min-crypto-level`):
    /// shared by inbound sniffing triage, outbound initiation, and the
    /// announce parameter bit.
    pub crypto: CryptoPolicy,
    /// DHT wiring (`DhtWireConfig::default` = disabled, leaving existing
    /// test surfaces unchanged; CLI download mode injects via
    /// `--enable-dht` (default true) and idle mode via the session option
    /// `enable_dht`).
    pub dht: DhtWireConfig,
    /// BEP 27 private flag (metainfo `private`; true -> DHT
    /// announce/lookup and PORT send/receive are forbidden, enforced at
    /// the type level by [`taiji_bt::dht::DhtTarget`]).
    pub private: bool,
    /// BEP 19 webseed URL set (a projection of the metainfo top-level
    /// `url-list`; empty = no HTTP supplemental sources). http/https only
    /// (filtered at parse time); when CLI `--enable-http-seeding` / the
    /// per-task option key `enable-http-seeding` are off, the assembly/
    /// activation chain calls `clear()` (the url-list original stays in
    /// the metainfo, so toggling loses nothing).
    pub webseeds: Vec<String>,
    /// Peer-exchange gate (`--enable-peer-exchange` semantics, aria2
    /// default true, `OptionHandlerFactory.cc` PREF_ENABLE_PEER_EXCHANGE):
    /// combined with [`Self::private`] through `bt::pex::pex_offered` into
    /// the ut_pex advertise/consume gate — false or a private torrent ->
    /// connections neither advertise ut_pex nor consume inbound frames.
    /// Existing test-surface construction sites pass false explicitly
    /// (keeping wire behavior unchanged).
    pub peer_exchange: bool,
    /// ut_metadata serving surface: Some = every connection sends the ext
    /// handshake (advertising ut_metadata + metadata_size) and answers
    /// inbound requests with fragments; None = only an empty ext handshake
    /// (no serving surface). BEP 9 serving duty: an engine already holding
    /// the metadata answers as usual (the same surface as any aria2 BT
    /// download).
    pub metadata_serve: Option<Arc<dyn taiji_bt::peer::MetadataSource>>,
    /// Rate-limit topology: a global bucket and a per-torrent bucket in
    /// series. None = no rate limiting (the CLI bare-run shape; even when
    /// mounted there is a double short-circuit — unlimited/unmounted
    /// buckets pass through at zero cost). Every peer connection (outbound +
    /// inbound) wraps its post-handshake transport stream in
    /// `Throttled`: awaiting permits on the PeerTask read path pushes back
    /// on the TCP/uTP windows.
    pub limiter: Option<Arc<LimiterSet>>,
    /// Hook trigger surface (shares the runner instance with
    /// SessionActor). The engine consumes only the bt-complete trigger
    /// point (DefaultPieceStorage.cc: the moment a BT download completes,
    /// no option gate; the bt-enable-hook-after-hash-check gate belongs
    /// only to the verification-complete trigger point,
    /// BtCheckIntegrityEntry.cc, consumed by the recheck path). None = no
    /// hook commands (zero-cost pass-through).
    pub hook: Option<Arc<taiji_domain::hook::HookRunner>>,
    /// NAT consumption surface: Some = trigger Map once the listen port
    /// is determined (TCP+UDP, 60min renewals); external-port changes
    /// couple into DHT announce re-issue via the 2s tick (the tracker
    /// announce port stays a spawn-time constant seam — dynamic re-porting
    /// is out of scope, see the [`taiji_domain::nat`] module docs). None =
    /// no NAT surface (zero change for existing callers).
    pub nat: Option<taiji_domain::nat::NatEngine>,
    /// Metrics feed (session-level atomic counters). The engine feeds
    /// incrementally along the existing 1s tick / event attribution /
    /// store pipeline paths (atomics — lock-free, no new channels). None =
    /// no feeding (zero change for existing tests/bare runs).
    pub stats: Option<Arc<super::metrics::SessionMetrics>>,
    /// Preset progress bitmaps (`--check-integrity`): None = default, zero
    /// behavior difference; Some = the bitmap restore source when no
    /// persist row exists (see [`PresetProgress`] — does not participate
    /// in the resume_existing decision).
    pub preset_progress: Option<PresetProgress>,
    /// Tracker announce client options (wiring for
    /// `--bt-tracker-interval`/`--bt-tracker-timeout`/
    /// `--bt-tracker-connect-timeout`): default =
    /// [`TrackerOptions::default()`] (0 = interval not overridden + two
    /// 60s timeouts, the aria2 defaults) — the assembly default is a zero
    /// behavior difference. Consumed by each face's tracker actor via
    /// `TrackerActorConfig.options` in assemble. Scope note: the
    /// magnet metadata-phase announce (taiji-core magnet.rs) and the
    /// .torrent byte-fetch client do not use this field (they keep the
    /// existing `TrackerOptions::default()` shape — CLI flags stay
    /// default on those two carriers, a stated difference).
    pub tracker_options: TrackerOptions,
}

// Hand-written `Debug` (a derive is impossible: the writer/metadata hooks
// are `dyn` trait objects and the limiter/hook/nat fields are non-Debug
// cross-crate handles). Opaque handles print as presence flags only —
// the remaining payload fields are the debug surface.
impl std::fmt::Debug for EngineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineConfig")
            .field("peer_id", &self.peer_id)
            .field("announce", &self.announce)
            .field("listen_port", &self.listen_port)
            .field("piece_len", &self.piece_len)
            .field("layout", &self.layout)
            .field("dest", &self.dest)
            .field("seed_after_complete", &self.seed_after_complete)
            .field("seed", &self.seed)
            .field("writer_factory", &self.writer_factory.is_some())
            .field("disk_policy", &self.disk_policy)
            .field("faces", &self.faces)
            .field("crypto", &self.crypto)
            .field("dht", &self.dht)
            .field("private", &self.private)
            .field("webseeds", &self.webseeds)
            .field("peer_exchange", &self.peer_exchange)
            .field("metadata_serve", &self.metadata_serve.is_some())
            .field("limiter", &self.limiter.is_some())
            .field("hook", &self.hook.is_some())
            .field("nat", &self.nat.is_some())
            .field("stats", &self.stats)
            .field("preset_progress", &self.preset_progress)
            .field("tracker_options", &self.tracker_options)
            .finish()
    }
}

/// DHT engine wiring parameters.
#[derive(Clone, Debug)]
pub struct DhtWireConfig {
    /// DHT master switch (`--enable-dht` semantics; false = no engine
    /// spawn, no demux dht channel consumption, no DHT bit in handshakes,
    /// no PORT sent).
    pub enabled: bool,
    /// Bootstrap entries (`--dht-entry-point`, host:port text; empty = the
    /// v4 router fallback constants — an intentional enhancement, not
    /// aria2 behavior).
    pub entry_points_v4: Vec<String>,
    /// `--dht-entry-point-6` (empty = the v6 router fallback constants
    /// `DEFAULT_BOOTSTRAP_NODES_V6` (engine/dht.rs; AAAA vetting in its
    /// comment) — an intentional enhancement like v4, not aria2 behavior.
    /// Also: without local global v6 connectivity the whole bootstrap is
    /// skipped, see the probe gate in assemble).
    pub entry_points_v6: Vec<String>,
    /// Engine internal intervals (tests inject millisecond values driving
    /// the same table; production = the frozen bt::dht defaults).
    pub engine: DhtEngineConfig,
    /// Torrent announce re-issue cadence (the engine registry drops an
    /// entry after 30min without a re-issue command — PURGE; default =
    /// `DHT_PEER_ANNOUNCE_INTERVAL` 15min, `DHTConstants.h`).
    pub announce_interval: Duration,
}

impl Default for DhtWireConfig {
    fn default() -> Self {
        DhtWireConfig {
            enabled: false,
            entry_points_v4: Vec::new(),
            entry_points_v6: Vec::new(),
            engine: DhtEngineConfig::default(),
            announce_interval: DHT_PEER_ANNOUNCE_INTERVAL,
        }
    }
}
/// Storage construction hook (tests inject slow/gated writers; None = the
/// standard TorrentWriter). The returned writer's `create()` must trigger
/// file allocation (TorrentWriter semantics).
pub trait WriterFactory: Send + Sync {
    fn build(
        &self,
        layout: &Layout,
        dest: &std::path::Path,
    ) -> Result<Box<dyn DiskWriter>, StoreError>;
}
/// Engine-level tracker wiring parameters.
/// [`crate::DownloadEngine::spawn`] passes
/// [`TrackerWireConfig::default`], keeping the frozen call surface
/// intact; callers needing tier overrides or persistence use
/// [`crate::DownloadEngine::spawn_with`].
#[derive(Clone, Default)]
pub struct TrackerWireConfig {
    /// Tracker table (tier, url); empty = build a single tier 0 from
    /// `EngineConfig::announce`. BEP 52 hybrid: both faces' actors
    /// announce to the same table with their own info_hash ("join both
    /// swarms").
    pub tiers: Vec<(usize, String)>,
    /// Persistence injection: `(gid as 16 hex chars, PersistWriter
    /// handle)`; None = no row writes. Events still drive the mirror
    /// pointers; they just produce no row writes.
    ///
    /// The handle also drives the tracker rows and the torrent_progress
    /// counter rows (autosave 60s + the engine-shutdown final values; the
    /// `upload_at_startup` base is read back via `LoadTorrentProgress` at
    /// engine start).
    ///
    /// It also drives the peer_ban/ipfilter rows (written as bans take
    /// effect; at startup, active unexpired bans and ipfilter rules are
    /// read back to rebuild the snapshot).
    pub persist: Option<(String, PersistHandle)>,
    /// IpGuard shared snapshot handle (arc-swap hot updates). The
    /// accept/dial filter-point queries and ban/import/sweep hot updates
    /// all go through this handle. None = the engine builds its own
    /// internal snapshot (automatic ban filtering still works; there is
    /// no external import/hot-update entry).
    pub guard: Option<IpGuardHandle>,
}

// Hand-written `Debug` (a derive is impossible: `persist`/`guard` are
// non-Debug cross-crate channel handles). The handles print as presence
// flags only — the tiers table is the debug surface.
impl std::fmt::Debug for TrackerWireConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackerWireConfig")
            .field("tiers", &self.tiers)
            .field("persist", &self.persist.is_some())
            .field("guard", &self.guard.is_some())
            .finish()
    }
}

/// Assemble the download-engine config (swarm faces per kind; the
/// v2-only data plane is enabled here).
///
/// `completion`: [`CompletionMode::Seed`] = stay resident as a seeder
/// after all pieces complete (the CLI default);
/// [`CompletionMode::ReturnOnComplete`] = return on completion (the
/// integration-test semantics).
///
/// # Errors
///
/// - [`MetainfoError::Layout`] / [`MetainfoError::HybridMismatch`]: layout
///   planning failed for the wire or disk view
///   ([`taiji_domain::metainfo::TorrentMeta::layout`] /
///   [`Metainfo::disk_layout`]; a hybrid v1 offset table that disagrees
///   with the v2 file tree surfaces here).
/// - [`MetainfoError::PieceBudgetExceeded`]: a face declares more pieces
///   than `MAX_TORRENT_PIECES` (checked before any piece-level allocation).
/// - [`MetainfoError::NoV1Pieces`] / [`MetainfoError::NoV2Identity`]: the
///   swarm kind needs a face whose identity the metainfo does not carry.
/// - [`MetainfoError::PiecesCountMismatch`]: the v1 `pieces` hash count
///   differs from the layout's piece count.
/// - [`MetainfoError::MisalignedHybridLayout`]: a hybrid v1 piece maps into
///   a padding region (the BEP 52 piece-alignment premise is broken).
/// - [`MetainfoError::FileNotInLayout`]: a v2 file is absent from the
///   layout (metadata/layout inconsistent).
/// - [`MetainfoError::BadPieceLayer`]: a v2 file's piece layer is missing
///   or malformed for its piece count.
/// - [`MetainfoError::FacePieceCountMismatch`]: the hybrid v1/v2 face piece
///   counts differ (also raised early by the v2 face when the v1 hash list
///   is shorter than the v2 piece count).
///
/// Post-completion residency of an assembled engine (the
/// [`engine_config`] completion face): what the engine does when the
/// last piece completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionMode {
    /// Stay resident as a seeder after all pieces complete (the CLI
    /// default).
    Seed,
    /// Return (shut the engine down) on completion (the
    /// integration-test semantics).
    ReturnOnComplete,
}

pub fn engine_config(
    meta: &Metainfo,
    dest: PathBuf,
    listen_port: u16,
    peer_id: [u8; 20],
    completion: CompletionMode,
) -> Result<EngineConfig, MetainfoError> {
    // The wire-view layout for face assembly (paths shaped like MetaFile;
    // the hash-serving file surface's `Layout::find` offset backfill
    // depends on that shape); the disk-view layout is used for disk
    // delivery (multi-file layouts carry the name directory layer). Their
    // offsets/totals are always equal (the prefix only changes paths).
    let (layout, disk_layout) = crate::metainfo_admission::layouts(meta)?;
    let piece_len = meta.meta.piece_length;
    let seed_after_complete = completion == CompletionMode::Seed;
    let mut faces: Vec<FaceConfig> = Vec::new();
    match meta.meta.kind {
        SwarmKind::V1Only => faces.push(v1_face(meta, &layout)?),
        SwarmKind::V2Only => faces.push(v2_face(meta, &layout)?),
        SwarmKind::Hybrid => {
            let v1 = v1_face(meta, &layout)?;
            let v2 = v2_face(meta, &layout)?;
            // Shared piece space premise: the BEP 52 alignment mapping =>
            // both faces have equal piece counts (k <-> k).
            if v1.piece_count() != v2.piece_count() {
                return Err(MetainfoError::FacePieceCountMismatch {
                    v1: v1.piece_count(),
                    v2: v2.piece_count(),
                });
            }
            faces.push(v1);
            faces.push(v2);
        }
    }
    Ok(EngineConfig {
        initial_selection: None,
        peer_id,
        announce: meta.announce.clone(),
        listen_port,
        piece_len,
        layout: disk_layout,
        dest,
        seed_after_complete,
        seed: taiji_domain::seed::SeedPolicy::default(),
        writer_factory: None,
        // Assembly defaults to the throughput tier (zero behavior change);
        // per-torrent overrides flow through the session activation chain
        // (config_json `disk_tier`).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces,
        // Default face: optional crypto (the two options' defaults), DHT
        // off (rewrite cfg.dht when needed), private follows the
        // metainfo.
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: DhtWireConfig::default(),
        private: meta.private,
        // BEP 19 webseed set (a projection of the parsed `url-list`; the
        // --enable-http-seeding / per-task enable-http-seeding switches
        // clear it in the assembly/activation chain, so this always
        // projects the original value — switch round-trips are lossless).
        webseeds: meta.url_list.clone(),
        // Peer exchange: aria2 `--enable-peer-exchange` defaults true
        // (OptionHandlerFactory.cc); private torrents are gated again in
        // the engine via pex_offered (BEP 27 forbids PEX).
        peer_exchange: true,
        // ut_metadata serving surface: an engine holding the metadata
        // answers inbound requests as usual (every aria2 BT download
        // carries the attrs->metadata service, the
        // HandshakeExtensionMessage surface).
        metadata_serve: Some(std::sync::Arc::new(taiji_bt::peer::MetadataBytes(
            meta.info_bytes.clone(),
        ))),
        // Rate-limit topology: not mounted by default (the CLI direct-run
        // shape); the session/magnet chains inject per options before
        // spawn (`EngineConfig::limiter`).
        limiter: None,
        // Hook surface: not mounted by default (the CLI direct-run shape
        // has no hook injection point); the session/magnet chains inject
        // the shared runner before spawn.
        hook: None,
        // NAT surface: not mounted by default (the single-instance
        // NatActor is process-level assembly, injected via CLI/session
        // layers as `EngineConfig::nat`; None = zero change).
        nat: None,
        // Metrics feed: not mounted by default; the session injects the
        // shared counter surface when activating a task
        // (`EngineConfig::stats`).
        stats: None,
        // Preset progress bitmaps: always None at assembly (a bare-run
        // `--check-integrity` overwrites and injects after CLI assembly;
        // default is a zero behavior difference).
        preset_progress: None,
        // Tracker announce client options: the assembly default (0
        // interval override + two 60s timeouts, the aria2 defaults — zero
        // behavior difference); CLI/session chains overwrite per options
        // before spawn.
        tracker_options: TrackerOptions::default(),
    })
}

/// v1 face (v1-only / hybrid): stream piece space, Flat addressing,
/// whole-piece SHA-1. In hybrid, carries cross-verification (recompute
/// the v2 piece root from the content).
fn v1_face(meta: &Metainfo, layout: &Layout) -> Result<FaceConfig, MetainfoError> {
    let v1_hash = meta.meta.identity.v1.ok_or(MetainfoError::NoV1Pieces)?;
    let piece_len = meta.meta.piece_length;
    let total = layout.total();
    let count = total.div_ceil(u64::from(piece_len)) as usize;
    // v1 piece-count consistency: the pieces string must exactly cover the
    // v1 layout total (pad ranges included).
    if meta.v1_pieces.len() != count {
        return Err(MetainfoError::PiecesCountMismatch {
            got: meta.v1_pieces.len(),
            expected: count,
        });
    }
    let expected: Vec<ExpectedPieceHash> = meta
        .v1_pieces
        .iter()
        .map(|h| ExpectedPieceHash::V1(*h))
        .collect();
    let piece_goffs: Vec<u64> = (0..count as u64)
        .map(|k| k * u64::from(piece_len))
        .collect();
    let piece_bytes: Vec<u64> = (0..count as u64)
        .map(|k| (total - k * u64::from(piece_len)).min(u64::from(piece_len)))
        .collect();

    // hybrid cross-verification table: stream piece k's content = exactly
    // one real file's piece (the BEP 47 alignment guarantee); recompute
    // that piece's v2 piece root from the content.
    let cross = match meta.meta.kind {
        SwarmKind::Hybrid => {
            let files = &meta.meta.files;
            let mut cross: Vec<Option<CrossRule>> = vec![None; count];
            for k in 0..count as u64 {
                let s = k * u64::from(piece_len);
                let Some(f) = files.iter().find(|f| {
                    let off = f.v1_offset.unwrap_or(u64::MAX);
                    off <= s && s < off + f.length
                }) else {
                    return Err(MetainfoError::MisalignedHybridLayout { index: s });
                };
                // Pieces of a layer-missing file: the V2Root rule needs
                // the piece root from the layer — while the layer is
                // missing, cross-verification degrades to None (the v1
                // authoritative verification still runs and never triggers
                // CrossCheckFailed; hybrid's v1 face is unrestricted). The
                // v2 re-verification after the layer arrives belongs to
                // the recheck re-entry surface (reusing verify_face).
                if f.layer_missing(piece_len) {
                    continue;
                }
                let Some(off) = f.v1_offset else {
                    return Err(MetainfoError::MisalignedHybridLayout { index: s });
                };
                if off % u64::from(piece_len) != 0 {
                    return Err(MetainfoError::MisalignedHybridLayout { index: off });
                }
                let p = ((s - off) / u64::from(piece_len)) as usize;
                let content_bytes = (f.length - (s - off)).min(u64::from(piece_len));
                let ExpectedPieceHash::V2(root) = piece_hash(meta, f, p)? else {
                    return Err(MetainfoError::BadPieceLayer {
                        path: f.path.clone(),
                        pieces: f.length.div_ceil(u64::from(piece_len)) as usize,
                    });
                };
                cross[k as usize] = Some(CrossRule::V2Root {
                    content_bytes,
                    root,
                    blocks_per_piece: (piece_len / merkle::BLOCK_SIZE) as usize,
                    single_piece_file: f.length.div_ceil(u64::from(piece_len)) == 1,
                });
            }
            cross
        }
        _ => Vec::new(),
    };

    // reserved: fast + ext (aria2 default) + the v2 capability bit (set
    // when the torrent has a v2 representation — the BEP 52 upgrade path).
    let reserved = Reserved::aria2_default();
    let reserved = match meta.meta.kind {
        SwarmKind::V1Only => reserved,
        _ => reserved.with_v2(),
    };
    Ok(FaceConfig {
        kind: FaceKind::V1,
        info_hash: v1_hash,
        reserved,
        addressing: Addressing::Flat,
        expected,
        piece_goffs,
        piece_bytes,
        plan_file_lengths: vec![total],
        progress_file_lens: vec![total],
        cross,
        hash_files: None,
    })
}

/// v2 face (v2-only / hybrid): per-file piece space, PerFile addressing,
/// truncated sha256 identity, piece-root verification. In hybrid, carries
/// cross-verification (whole-piece SHA-1 over content + pad zero fill).
fn v2_face(meta: &Metainfo, layout: &Layout) -> Result<FaceConfig, MetainfoError> {
    let v2_hash = meta.meta.identity.v2.ok_or(MetainfoError::NoV2Identity)?;
    let piece_len = meta.meta.piece_length;
    let files = &meta.meta.files;
    let file_lens: Vec<u64> = files.iter().map(|f| f.length).collect();
    let addressing = Addressing::per_file(&file_lens, piece_len);

    // Flat plan: file order x per-file piece counts (the synthetic view).
    // Note: a hybrid layout contains pad placeholder entries, so layout
    // indices must map through layout.find (meta.files is DFS real-file
    // order, no pad).
    //
    // Layer-missing files: a v2 expected root can only come from the
    // piece layer (structurally necessary), so while the layer is missing
    // the piece's expectation is an ALL-ZERO ROOT — SHA-256 preimage
    // resistance guarantees no real content's piece root can converge to
    // the all-zero root, i.e. placeholder pieces STRUCTURALLY cannot pass
    // verification or hit disk (the same boundary as "no download while
    // the layer is missing"; no content may enter the anchor/lazy-fetch
    // domain before the whole file converges). Once the layer converges
    // file-by-file via hash recovery and is admitted, that file's runtime
    // representation upgrades to full (the store pipeline's live seam for
    // expected roots belongs to the pipeline surface).
    let mut expected = Vec::new();
    let mut piece_goffs = Vec::new();
    let mut piece_bytes = Vec::new();
    for f in files.iter() {
        let li = layout.find(&f.path).ok_or(MetainfoError::FileNotInLayout {
            path: f.path.clone(),
        })?;
        let pieces = f.length.div_ceil(u64::from(piece_len)) as usize;
        for p in 0..pieces {
            expected.push(if f.layer_missing(piece_len) {
                ExpectedPieceHash::V2([0u8; 32])
            } else {
                piece_hash(meta, f, p)?
            });
            let goff = layout.v2_piece_offset(li, p as u32)?;
            piece_goffs.push(goff);
            piece_bytes
                .push((f.length - p as u64 * u64::from(piece_len)).min(u64::from(piece_len)));
        }
    }

    // hybrid cross-verification: once a content piece completes, append
    // pad zeros and compute the whole-piece SHA-1 (the v1 hash covers the
    // full piece including pad zeros — BEP 47 "content of padding file is
    // all zeros"). Both faces share the piece space (k <-> k), so the v1
    // hash is taken directly by index.
    let cross = match meta.meta.kind {
        SwarmKind::Hybrid => {
            let stream_total = layout.total();
            let count = expected.len();
            // v1 pieces must cover the shared piece space: the rule below
            // reads the v1 hash by the v2 piece index (k <-> k), while
            // engine_config's face piece-count equality check runs only
            // after both faces assemble — a malformed hybrid (v2 piece
            // count > v1 pieces; the magnet/ut_metadata metadata surface
            // is remotely reachable) would index v1_pieces out of bounds
            // here. Reject with the same variant that check uses. The
            // guard also bounds the stream_total subtraction in the loop
            // body below: v1_face has already pinned v1_pieces.len() to
            // ceil(stream_total/piece_len), so count <= that count keeps
            // every k*piece_len strictly below stream_total.
            if meta.v1_pieces.len() < count {
                return Err(MetainfoError::FacePieceCountMismatch {
                    v1: meta.v1_pieces.len(),
                    v2: count,
                });
            }
            let mut cross: Vec<Option<CrossRule>> = Vec::with_capacity(count);
            for (k, content) in piece_bytes.iter().enumerate().take(count) {
                let full =
                    (stream_total - k as u64 * u64::from(piece_len)).min(u64::from(piece_len));
                let pad_zeros = full.saturating_sub(*content);
                cross.push(Some(CrossRule::V1Hash {
                    hash: meta.v1_pieces[k],
                    pad_zeros,
                }));
            }
            cross
        }
        _ => Vec::new(),
    };

    // hash-request serving file surface: backfill layout offsets (v2-only
    // has no v1_offset; MetaHashSource reads with the "layout offset"
    // semantics).
    let hash_files = files_with_layout_offsets(meta, layout);

    Ok(FaceConfig {
        kind: FaceKind::V2,
        info_hash: truncated_v2(&v2_hash),
        reserved: Reserved::aria2_default().with_v2(),
        addressing,
        expected,
        piece_goffs,
        piece_bytes,
        plan_file_lengths: file_lens.clone(),
        progress_file_lens: file_lens,
        cross,
        hash_files: Some(hash_files),
    })
}

/// Expected hash of file f's piece p: sliced from the metadata piece
/// layer (>1-piece files); a single-piece file uses the pieces root
/// (BEP 52: files with <= 1 piece have no piece-layers entry).
fn piece_hash(meta: &Metainfo, f: &MetaFile, p: usize) -> Result<ExpectedPieceHash, MetainfoError> {
    let piece_len = meta.meta.piece_length;
    let pieces = f.length.div_ceil(u64::from(piece_len)) as usize;
    if let Some(layer) = &f.piece_layer {
        if layer.len() != pieces * 32 {
            return Err(MetainfoError::BadPieceLayer {
                path: f.path.clone(),
                pieces,
            });
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&layer[p * 32..(p + 1) * 32]);
        Ok(ExpectedPieceHash::V2(h))
    } else if pieces == 1 {
        let root = f.pieces_root.ok_or_else(|| MetainfoError::BadPieceLayer {
            path: f.path.clone(),
            pieces,
        })?;
        Ok(ExpectedPieceHash::V2(root))
    } else {
        Err(MetainfoError::BadPieceLayer {
            path: f.path.clone(),
            pieces,
        })
    }
}

/// Backfill layout offsets into the MetaFile list (for hash serving; the
/// `v1_offset` field here means "the file's global offset in the disk
/// layout" — hybrid = the v1 layout offset, v2-only = the compact layout
/// offset).
fn files_with_layout_offsets(meta: &Metainfo, layout: &Layout) -> Vec<MetaFile> {
    meta.meta
        .files
        .iter()
        .map(|f| {
            let mut m = f.clone();
            m.v1_offset = layout
                .find(&f.path)
                .and_then(|i| layout.files().get(i))
                .map(|lf| lf.offset);
            m
        })
        .collect()
}
