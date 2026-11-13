//! The magnet chain: magnet URI -> MetadataPending task -> DHT/tracker/LSD
//! discovery (plus an optional HTTP web-mirror source) -> ut_metadata
//! fetch -> TorrentMeta rebuild + verification -> an in-place upgrade to
//! a real download task; the followedBy GID chain data face is ready (RPC
//! field exposure is a later milestone); the bt-save-metadata /
//! bt-metadata-only / follow-torrent / pause-metadata /
//! bt-load-saved-metadata options land here.
//!
//! Upstream anchor mapping: docs/design/core.md.
//!
//! Hard invariants: every identity a magnet carries is checked against
//! the raw info bytes (SHA-1 for btih, SHA-256 for btmh); a magnet with
//! no tracker, DHT, LSD, explicit peer or metadata source fails explicitly; v2/hybrid metadata without a verifiable
//! `piece layers` fails instead of upgrading; a metadata deadline, when
//! set, fails honestly rather than faking completion; all metadata-phase
//! connections are cancelled after metadata/layer retrieval. Their swarm
//! subscription is withdrawn immediately; session discovery stays warm.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use taiji_bt::bencode::{self, Value};
use taiji_bt::dht::{
    DhtEngineConfig, DhtEvent, DhtFamily, DhtHandle, DhtSwarmKind, DhtTarget, DhtTransport,
    EVENT_CHANNEL_CAPACITY, forward_outbound, spawn_dht_engine,
};
use taiji_bt::info_hash::truncated_v2;
use taiji_bt::lsd::{LsdEvent, LsdHandle};
use taiji_bt::magnet as magnet_parse;
use taiji_bt::peer::MetadataFetched;
use taiji_bt::peer::{
    ExpectedInfoHash, MetadataFetchSpec, PeerCommand, PeerConfig, PeerHandle as _, PeerTask,
    PeerTaskHandle,
};
use taiji_bt::peer_policy::IpGuardHandle;
use taiji_bt::peer_wire::Reserved;
use taiji_bt::tracker::TrackerOptions;
use taiji_bt::tracker::actor::{
    TrackerActorConfig, TrackerActorEvent, TrackerCommand, UDP_INBOUND_CAPACITY,
    UDP_OUTBOUND_CAPACITY, UdpTransport, spawn_tracker_actor,
};
use taiji_io::rate_limit::{LimiterSet, Throttled};
use taiji_io::udp_demux::DemuxConfig;
use taiji_store::merkle;
use taiji_store::persist::PersistHandle;

use crate::engine::{DownloadEngine, EngineEnd, TrackerWireConfig};
use crate::gid::Gid;
use crate::hash_fetch::HASH_FETCH_TIMEOUT;
use crate::metainfo::Metainfo;
use crate::seed::SeedPolicy;
// hex_lower's single implementation lives in session::persist::import
// (same name and logic as this file's former private copy; the two
// implementations merged into one).
use crate::session::persist::import::hex_lower;
use crate::torrent::{TorrentState, legal_transition};

/// Outbound connect timeout (the same rule as the engine dial; a local
/// policy value).
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshake exchange timeout (the same rule as the engine).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The min-peers gate (aria2 `BtRuntime.h` DEFAULT_MIN_PEERS): the
/// metadata-phase connection count stays below this -> tracker
/// numwant=50.
const MIN_PEERS: usize = 40;

/// magnet task options (names frozen; defaults cross-checked against
/// aria2 OptionHandlerFactory.cc: pause-metadata, bt-load-saved-metadata,
/// bt-metadata-only, bt-save-metadata, follow-torrent).
#[derive(Debug, Clone)]
pub struct MagnetOptions {
    /// `bt-save-metadata` (default false): once the metadata is ready,
    /// write `<dir>/<hex(infohash)>.torrent`
    /// (UTMetadataPostDownloadHandler.cc).
    pub bt_save_metadata: bool,
    /// `bt-metadata-only` (default false): the fetch is the end state; no
    /// real-download upgrade.
    pub bt_metadata_only: bool,
    /// `follow-torrent` (default true): false = do not follow (aria2 does
    /// not register the post-download handler, RequestGroup.cc).
    pub follow_torrent: bool,
    /// `pause-metadata` (default false): the upgraded artifact enters a
    /// paused state (the honest shape before session residency; see the
    /// divergence notes in docs/design/core.md).
    pub pause_metadata: bool,
    /// `bt-load-saved-metadata` (default false): prefer reading
    /// `<dir>/<hex(btih)>.torrent` (download_helper.cc).
    pub bt_load_saved_metadata: bool,
    /// `bt-peer-connection-type` (default prefer-tcp): the outbound
    /// transport plan of the upgraded engine (metadata-phase connections
    /// honor the same TCP/uTP policy as the payload engine;
    /// the gap is declared explicitly).
    pub bt_peer_connection_type: taiji_bt::utp::PeerConnectionType,
    /// Enable BEP55 metadata connections (independent of router mapping).
    pub holepunch: bool,
}

impl Default for MagnetOptions {
    fn default() -> Self {
        MagnetOptions {
            bt_save_metadata: false,
            bt_metadata_only: false,
            follow_torrent: true,
            pause_metadata: false,
            bt_load_saved_metadata: false,
            bt_peer_connection_type: taiji_bt::utp::PeerConnectionType::default(),
            holepunch: true,
        }
    }
}

/// Metadata-phase parameters (local policy values; see the divergence
/// notes in docs/design/core.md).
#[derive(Debug, Clone)]
pub struct MetadataPhaseConfig {
    /// The BT listen port shared by the metadata phase and the upgraded
    /// engine.
    pub listen_port: u16,
    /// Maximum concurrent metadata peer attempts. Closed and unresponsive
    /// peers release their slots so later discovery results can be tried.
    pub max_metadata_peers: usize,
    /// Budget for one connected peer to deliver verified metadata.
    pub peer_metadata_timeout: Duration,
    /// The rediscovery beat while there is no metadata (re-issue get_peers +
    /// dial new addresses; tracker/LSD retry inside their own actors and
    /// are not repeated here — tracker min-interval is respected).
    pub discovery_round: Duration,
    /// The total metadata-phase budget (None = wait honestly; tests
    /// inject small values).
    pub metadata_deadline: Option<Duration>,
    /// Budget for asynchronous DHT initialization. Tracker, direct-peer and
    /// LSD discovery continue while bootstrap DNS and receipts are pending.
    pub dht_bootstrap_budget: Duration,
}

impl Default for MetadataPhaseConfig {
    fn default() -> Self {
        MetadataPhaseConfig {
            listen_port: 0,
            max_metadata_peers: 24,
            peer_metadata_timeout: Duration::from_secs(30),
            discovery_round: Duration::from_secs(15),
            metadata_deadline: None,
            dht_bootstrap_budget: Duration::from_secs(10),
        }
    }
}

/// An injected DHT engine or scoped receiver for session-owned discovery.
/// The Network subscription owns registration lifetime; handles are borrowed.
pub struct DhtLease {
    pub handle: DhtHandle,
    pub extra_handles: Vec<DhtHandle>,
    pub events: mpsc::Receiver<DhtEvent>,
}

/// Standalone IPv4 DHT assembly for embedding callers and integration tests.
/// Production sessions reuse MagnetServices and its shared TCP/uTP/DHT socket.
/// Restore state is optional; cancelling the token closes this standalone demux.
pub async fn spawn_phase_dht(
    shutdown: tokio_util::sync::CancellationToken,
    restore: Option<taiji_bt::dht::DhtRestoreState>,
) -> Option<DhtLease> {
    const LOG_TARGET: &str = "taiji::core::magnet";
    let (channels, demux) = match taiji_io::udp_demux::spawn(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(target: LOG_TARGET, %e, "metadata-phase dht demux bind failed");
            return None;
        }
    };
    // The metadata-phase DHT face does not consume the tracker/uTP
    // channels (see the port-sharing note above).
    drop(channels.tracker);
    drop(channels.utp);
    spawn_phase_dht_on(channels.dht, demux, shutdown, restore).await
}

async fn spawn_phase_dht_on(
    inbound: mpsc::Receiver<taiji_io::udp_demux::InboundPacket>,
    demux: taiji_io::udp_demux::UdpDemuxHandle,
    shutdown: CancellationToken,
    restore: Option<taiji_bt::dht::DhtRestoreState>,
) -> Option<DhtLease> {
    const LOG_TARGET: &str = "taiji::core::magnet";
    let (out_tx, out_rx) = mpsc::channel(taiji_bt::dht::COMMAND_CHANNEL_CAPACITY);
    let (ev_tx, ev_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let dht_port = demux.bound_addr().port();
    let (handle, _join) = spawn_dht_engine(
        DhtFamily::V4,
        dht_port,
        DhtEngineConfig::default(),
        DhtTransport {
            inbound,
            outbound: out_tx,
        },
        restore,
        ev_tx,
    );
    forward_outbound(out_rx, demux.clone());
    // BEP42 external address (the probe sends no packets; on failure keep
    // the random id — see the security module docs).
    match taiji_bt::dht::security::probe_source_ip(false).await {
        Some(ip) => {
            if let Err(e) = handle.set_external_ip(ip).await {
                warn!(target: LOG_TARGET, %e, "phase dht set_external_ip failed");
            }
        }
        None => {
            debug!(target: LOG_TARGET,
                "external ip probe failed; phase dht keeps random node id")
        }
    }
    // Keepalive half (see the lifecycle notes above): hold a handle clone
    // until the token cancels.
    let keepalive = demux.clone();
    tokio::spawn(async move {
        let _keepalive = keepalive;
        shutdown.cancelled().await;
    });
    info!(target: LOG_TARGET, port = dht_port, "metadata-phase dht engine spawned");
    Some(DhtLease {
        extra_handles: Vec::new(),
        handle,
        events: ev_rx,
    })
}

/// LSD service lease (same semantics as [`DhtLease`]).
pub struct LsdLease {
    pub handle: LsdHandle,
    pub events: mpsc::Receiver<LsdEvent>,
}

/// magnet task configuration.
pub struct MagnetTaskConfig {
    pub services: Option<Arc<MagnetServices>>,
    pub dht_ipv6_enabled: bool,
    pub dht_entry_point_v6_override: Option<String>,
    pub dht_message_timeout: Duration,
    /// Listener mapping supplied by the session or embedding host.
    pub nat: Option<crate::nat::NatEngine>,
    /// Session tracker configuration, including updates while fetching metadata.
    pub tracker_updates: Option<tokio::sync::watch::Receiver<Vec<(usize, String)>>>,
    /// Task GID (allocated by the caller — session/tests — from
    /// [`crate::gid::GidAllocator`]). The in-place upgrade keeps this
    /// GID.
    pub gid: Gid,
    /// The magnet URI (kept verbatim into [`MetadataChain`],
    /// MetadataInfo::uri semantics).
    pub magnet_uri: String,
    /// Download directory (also the bt-save-metadata /
    /// bt-load-saved-metadata directory).
    pub dest: PathBuf,
    pub peer_id: [u8; 20],
    pub options: MagnetOptions,
    pub phase: MetadataPhaseConfig,
    /// Optional injected DHT lease. Otherwise services provide discovery when
    /// dht_enabled permits it; known private metadata never enters this phase.
    pub dht: Option<DhtLease>,
    /// DHT bootstrap entry points (empty = resolve the hardcoded
    /// routers; tests pass a loopback entry explicitly).
    pub dht_entry_points: Vec<std::net::SocketAddr>,
    /// Optional host:port override supplied by the session configuration.
    pub dht_entry_point_override: Option<String>,
    /// DHT switch of the upgraded engine (passes through
    /// [`EngineConfig::dht`]'s `DhtWireConfig::enabled` — the session
    /// `--enable-dht` global semantics). Without this passthrough the
    /// upgraded engine's DHT stays off (DhtWireConfig::default() =
    /// false) and the download phase is left with only tracker/PEX
    /// discovery — mismatched with the torrent activation path (tasks.rs
    /// build_engine_config injects at the same point).
    pub dht_enabled: bool,
    /// Webseeding switch of the upgraded engine (BEP19; false = clear the
    /// webseed set projected from url-list — the torrent activation path
    /// overwrites at the same point in tasks.rs build_engine_config, and
    /// this field is the upgrade chain's counterpart). The url-list
    /// values stay in the metainfo, so toggling is lossless.
    pub webseeding_enabled: bool,
    /// LSD lease (None = no LSD discovery; bt-lsd defaults false).
    pub lsd: Option<LsdLease>,
    /// Seeding policy of the upgraded engine (passes through
    /// [`EngineConfig`] semantics).
    pub seed: SeedPolicy,
    /// The upgraded engine returns on completion (false) or turns to
    /// resident seeding (true; CLI semantics).
    pub seed_after_complete: bool,
    /// Tracker-table persistence injection (passes through
    /// [`TrackerWireConfig::persist`]; the metadata phase stores no rows —
    /// rows belong to the upgraded engine's session).
    pub persist: Option<(String, PersistHandle)>,
    /// BEP53 selection second source: the RPC `select-file` option value
    /// (**0-based**, already converted at the single point
    /// [`crate::session::options::parse_select_file`]; range validation
    /// anchored like `so=` — against the non-pad file count, decided
    /// after the upgrade chain's metadata is ready). Mutually exclusive
    /// with the magnet `so=` at the add/changeOption face (both present =
    /// explicit conflict rejection, session/tasks.rs and commands.rs);
    /// None = no option source (`so=` still parses from the URI).
    pub select_file: Option<Vec<u32>>,
    /// Rate-limit topology (passes through [`EngineConfig::limiter`]
    /// semantics): metadata-phase connections and the upgraded engine
    /// share one chain (the global bucket spans phases; hot updates
    /// apply directly).
    pub limiter: Option<Arc<LimiterSet>>,
    /// Hook trigger face (shares the runner instance with SessionActor).
    /// The metadata-phase payload is an in-memory projection (numFiles=0/
    /// firstFilename="", the reference `inMemoryDownload` branch in
    /// util.cc); the in-place upgrade re-mounts the real file face via
    /// [`crate::hook::HookRunner::set_payload`] and passes the same
    /// runner to the upgraded engine (the bt-complete trigger point).
    /// None = no hook commands.
    pub hook: Option<Arc<crate::hook::HookRunner>>,
    /// HTTP metadata mirror set (None = unconfigured / no v1 identity;
    /// the fourth discovery source is off).
    pub web: Option<Arc<WebMirrors>>,
    /// Session metrics counter face (passes through
    /// [`EngineConfig::stats`] — the upgraded engine's tracker announce/
    /// DHT/connection/byte counters feed it. None = no feeding; without
    /// it /metrics reads all zeros with a 0/0 announce appearance).
    pub stats: Option<Arc<crate::session::metrics::SessionMetrics>>,
    /// Session-level IpGuard snapshot handle (an arc-swap hot-reload read
    /// face). A uniformly defined ban gate added to the spawn_dial
    /// defense chain — every candidate address from the tracker/DHT/LSD/
    /// x.pe discovery sources consults `blocks()` before connect; a hit =
    /// no dial, no bookkeeping or cap accounting (the ban gate leaves no
    /// bypass; the engine's transit dial filter is the same rule). None =
    /// no gate (existing tests/bare runs unchanged). Hot reload: the
    /// session re-pushes the snapshot at ban-config change points, and
    /// live metadata tasks read the latest snapshot on every dial.
    pub ip_guard: Option<IpGuardHandle>,
}

/// The followedBy/following GID chain data face (the basis for the RPC
/// `followedBy`/`following` fields; aria2 RequestGroup.h semantics plus
/// the RequestGroup.cc tellStatus projection points).
///
/// aria2 creates a NEW RequestGroup for the magnet group with mutual
/// references; this engine upgrades in place (same GID), so
/// `followed_by`/`following` are both this module's GID — the fields are
/// still provided, semantics unchanged: followedBy = the real-task view
/// this task upgraded into; following = the reverse chain (which metadata
/// task it came from).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataChain {
    /// The metadata (magnet cold-start) task GID.
    pub metadata_gid: Gid,
    /// The real download task GID produced by the upgrade (in-place
    /// upgrade => equal to metadata_gid).
    pub task_gid: Gid,
    /// MetadataInfo::uri semantics (the original magnet URI;
    /// download_helper.cc createMetadataInfo(gid, magnetLink)).
    pub metadata_uri: String,
    /// The pause-metadata flag (the data face of
    /// UTMetadataPostDownloadHandler.cc setPauseRequested).
    pub paused: bool,
}

impl MetadataChain {
    /// The RPC `followedBy` field (aria2 RequestGroup.cc).
    pub fn followed_by(&self) -> Vec<Gid> {
        vec![self.task_gid]
    }

    /// The RPC `following` field (aria2 RequestGroup.cc; the reverse
    /// chain).
    pub fn following(&self) -> Gid {
        self.metadata_gid
    }
}

// ---- the HTTP metadata mirror source (the fourth discovery source) ----
// Implementation and tests live in [`web_mirrors`] (split out of this
// file: an independent subsystem no longer buried in the engine file).
// Only the module declaration + re-export sit here — the session-side
// `crate::magnet::{WebMirrors, WebMirrorHealth, parse_web_mirror_templates}`
// and this file's call sites (spawn_web_mirrors) keep unchanged paths.
mod candidates;
mod services;
pub use services::MagnetServices;
mod network;
mod peers;
use peers::{
    handle_metadata_holepunch, retry_metadata_rendezvous, spawn_dial_with_network,
    spawn_incoming_peer,
};
mod web_mirrors;

use self::web_mirrors::spawn_web_mirrors;
pub use web_mirrors::{
    WEB_MIRROR_PLACEHOLDER, WebMirrorHealth, WebMirrors, parse_web_mirror_templates,
};

/// magnet task terminal states.
#[derive(Debug)]
pub enum MagnetEnd {
    /// bt-metadata-only: the metadata is fetched and verified (with an
    /// optional save), not upgraded.
    MetadataFetched {
        /// The raw info-dict bytes (verified against both magnet
        /// identities).
        metadata: Bytes,
        chain: MetadataChain,
    },
    /// follow-torrent=false: the metadata is ready but not followed (the
    /// equivalent terminal of aria2 RequestGroup.cc not registering the
    /// post-download handler).
    NotFollowed { chain: MetadataChain },
    /// The in-place upgrade completed; the upgraded engine's terminal
    /// passes through. The upgrade artifact is delivered too (`meta` =
    /// the parse model for file rows/identity assembly, `torrent` = the
    /// rebuilt/loaded .torrent bytes for the torrent row's metadata BLOB
    /// — the outer layer around the raw info section).
    Upgraded {
        end: EngineEnd,
        chain: MetadataChain,
        meta: std::sync::Arc<Metainfo>,
        torrent: Vec<u8>,
    },
    /// pause-metadata=true: upgraded but not started (session residency:
    /// the session turns the upgrade artifact into a paused torrent task;
    /// resume semantics like a normal torrent row).
    UpgradedPaused {
        chain: MetadataChain,
        meta: std::sync::Arc<Metainfo>,
        torrent: Vec<u8>,
    },
    /// An explicit failure (magnet parse failure / metadata timeout /
    /// infohash mismatch / corrupt metadata / rebuild parse failure). The
    /// GID keeps the result semantics.
    Failed(String),
}

/// Pool of live metadata connections (face index -> PeerTask handle).
#[derive(Clone)]
struct MetadataPeer {
    face: usize,
    id: u64,
    address: std::net::SocketAddr,
    handle: PeerTaskHandle,
    token: CancellationToken,
    transport: taiji_bt::utp::Transport,
    peer_id: [u8; 20],
    inbound: bool,
}
type LivePeers = Arc<std::sync::Mutex<Vec<MetadataPeer>>>;

struct PeerSignals {
    network: Arc<network::Dialer>,
    candidates: std::sync::Mutex<candidates::Candidates>,
    metadata: Vec<Arc<taiji_bt::ut_metadata::MetadataCoordinator>>,
    pex: mpsc::Sender<taiji_bt::peer::PexEvent>,
    holepunch: mpsc::Sender<taiji_bt::peer::HolepunchEvent>,
    reports: mpsc::Sender<PeerReport>,
    next_id: AtomicU64,
    introducers: AtomicUsize,
    max_introducers: usize,
    enabled: bool,
}

enum PeerReport {
    Connected {
        face: usize,
        address: std::net::SocketAddr,
        id: u64,
        source: &'static str,
    },
    Slow {
        face: usize,
        address: std::net::SocketAddr,
    },
    Failed {
        face: usize,
        address: std::net::SocketAddr,
    },
    Closed(u64),
}

/// The metadata-phase product: metadata bytes + the live connection pool
/// (for BEP52 piece-layer prefetch — magnet metadata lacks the top-level
/// `piece layers`, which lives outside the info dict per BEP52; it must
/// be fetched via hash exchange and verified to the pieces root before
/// the upgrade) + the phase token.
struct MetadataPhase {
    metadata: Bytes,
    _network: network::Network,
    /// Live metadata peers (face index, PeerTask handle); cancelled
    /// together at phase close-out.
    peers: LivePeers,
    token: CancellationToken,
    /// Verified piece layers carried from an HTTP mirror hit (Some = the
    /// HTTP path, finalize skips peer prefetch — the peer pool may be
    /// empty on an HTTP hit); the P2P path = None (uses
    /// prefetch_piece_layers).
    web_layers: Option<Vec<([u8; 32], Vec<u8>)>>,
}

/// The metadata-phase tracker actor's UDP carrier (one system UDP socket
/// per actor; the later engine main face already shares a socket through
/// the demux, and the metadata-phase task lifecycle is independent of the
/// engine — a private minimal carrier; UDP trackers need literal-IP URLs,
/// protocol contract in `tracker::actor::issue_announce`).
async fn udp_carrier(
    mut outbound_rx: mpsc::Receiver<(std::net::SocketAddr, Vec<u8>)>,
    inbound_tx: mpsc::Sender<(std::net::SocketAddr, Vec<u8>)>,
) {
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!(target: "taiji::core::magnet", %e, "udp tracker carrier bind failed");
            return;
        }
    };
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            out = outbound_rx.recv() => match out {
                None => break,
                Some((addr, frame)) => {
                    let _ = socket.send_to(&frame, addr).await;
                }
            },
            recv = socket.recv_from(&mut buf) => match recv {
                Ok((n, from)) => {
                    if inbound_tx.send((from, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!(target: "taiji::core::magnet", %e, "udp carrier recv");
                }
            },
        }
    }
}

/// One swarm face of the metadata phase (one per magnet identity).
#[derive(Clone)]
struct MetaFace {
    /// Face index (for connection-pool attribution).
    index: usize,
    /// The 20B handshake/announce identity (btih as-is / btmh truncated).
    info_hash: [u8; 20],
    reserved: Reserved,
    /// The ut_metadata assembly verification anchor.
    expected: ExpectedInfoHash,
    dht_kind: DhtSwarmKind,
}

/// Announce as an incomplete peer while payload size is unknown. A nonzero
/// sentinel follows libtorrent's bytes_left() fallback and avoids seed filtering.
/// This view is tracker-only; it does not fabricate task progress or file size.
struct MetaSwarmView {
    peers: Arc<AtomicUsize>,
}

impl taiji_bt::tracker::actor::SwarmView for MetaSwarmView {
    fn total_length(&self) -> u64 {
        16 * 1024
    }
    fn completed_length(&self) -> u64 {
        0
    }
    fn session_uploaded(&self) -> u64 {
        0
    }
    fn session_downloaded(&self) -> u64 {
        0
    }
    fn all_download_finished(&self) -> bool {
        false
    }
    fn less_than_min_peers(&self) -> bool {
        self.peers.load(Ordering::Relaxed) < MIN_PEERS
    }
}

/// The metadata2Torrent equivalent (a direct translation of
/// bittorrent_helper.cc): `d [13:announce-list <tiers>] 4:info <raw info
/// bytes> e` — one tier per tr (parseMagnet semantics), empty tiers
/// excluded (the if !empty branch). The info bytes are embedded
/// verbatim (decode->re-encode is forbidden).
fn metadata2torrent(
    metadata: &[u8],
    trs: &[String],
    piece_layers: &[([u8; 32], Vec<u8>)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(metadata.len() + 64);
    out.extend_from_slice(b"d");
    if !trs.is_empty() {
        out.extend_from_slice(b"13:announce-list");
        let tiers = Value::List(
            trs.iter()
                .map(|u| Value::List(vec![Value::Bytes(u.as_bytes().to_vec())]))
                .collect(),
        );
        // Encoding a List/Bytes shape has no failure branch; a failure
        // means an internal invariant is broken — degrade to an empty tier
        // and log it (the info section stays correct).
        match bencode::encode(&tiers) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(e) => warn!(target: "taiji::core::magnet", %e,
                "announce-list encode failed (internal invariant broken)"),
        }
    }
    out.extend_from_slice(b"4:info");
    out.extend_from_slice(metadata);
    // Top-level `piece layers` (BEP52: the key = the 32B merkle root
    // as-is, the value = that layer's hashes concatenated in order;
    // magnet metadata lacks this key — injected by prefetch). Key order:
    // announce-list < info < piece layers (ascending, as strict decoders
    // require).
    if !piece_layers.is_empty() {
        out.extend_from_slice(b"12:piece layers");
        let dict = Value::Dict(
            piece_layers
                .iter()
                .map(|(root, layer)| (root.to_vec(), Value::Bytes(layer.clone())))
                .collect(),
        );
        match bencode::encode(&dict) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(e) => warn!(target: "taiji::core::magnet", %e,
                "piece layers encode failed (internal invariant broken)"),
        }
    }
    out.extend_from_slice(b"e");
    out
}

/// Engine-side identity review: every identity a magnet carries must hold
/// against the raw info bytes (the fetcher already validated the winning
/// face; this gate checks the other identity — both sides of a hybrid
/// must agree). Mirrors aria2's bt-load-saved-metadata actualInfoHash
/// comparison (download_helper.cc).
fn check_identity(
    metadata: &[u8],
    btih: Option<[u8; 20]>,
    btmh: Option<[u8; 32]>,
) -> Result<(), String> {
    if let Some(btih) = btih {
        let got: [u8; 20] = Sha1::digest(metadata).into();
        if got != btih {
            return Err(format!(
                "metadata infohash mismatch: sha1(info) = {} != magnet btih {} \
                 (explicit rejection, AGENTS §2.1.7)",
                hex_lower(&got),
                hex_lower(&btih)
            ));
        }
    }
    if let Some(btmh) = btmh {
        let got: [u8; 32] = Sha256::digest(metadata).into();
        if got != btmh {
            return Err(format!(
                "metadata infohash mismatch: sha256(info) = {} != magnet btmh {} \
                 (explicit rejection, BEP52 multihash 1220)",
                hex_lower(&got),
                hex_lower(&btmh)
            ));
        }
    }
    Ok(())
}

/// The magnet download engine (metadata phase + the linearized upgrade).
pub struct MagnetEngine;

impl MagnetEngine {
    /// Spawn a magnet task (`MagnetEnd` is the terminal).
    pub fn spawn(
        cfg: MagnetTaskConfig,
        parent: &CancellationToken,
    ) -> tokio::task::JoinHandle<MagnetEnd> {
        let (join, _upgrade_rx) = Self::spawn_with_upgrade_notify(cfg, parent);
        join
    }

    /// Controlled spawn: additionally returns the upgrade-notification
    /// receiver — on an in-place upgrade (metadata verified -> the
    /// upgraded engine spawned) the upgraded engine's
    /// [`crate::engine::EngineHandle`] is delivered over a bounded(1)
    /// channel. The session needs the upgraded engine's handle for the
    /// followedBy/following chain synthesis and live readings; before
    /// that the session held engine=None for the whole magnet lifetime,
    /// so tellStatus read constant zeros and followedBy was always
    /// absent. Channel closed/full = lossy (a one-shot event; if the
    /// session does not take it, the existing honest zero readings
    /// remain and the download face is unaffected).
    pub fn spawn_with_upgrade_notify(
        cfg: MagnetTaskConfig,
        parent: &CancellationToken,
    ) -> (
        tokio::task::JoinHandle<MagnetEnd>,
        mpsc::Receiver<crate::engine::EngineHandle>,
    ) {
        let (upgrade_tx, upgrade_rx) = mpsc::channel(1);
        let token = parent.child_token();
        let join = tokio::spawn(async move { run(cfg, token, Some(upgrade_tx)).await });
        (join, upgrade_rx)
    }

    /// The bt-load-saved-metadata read face (a direct translation of
    /// download_helper.cc): read `<dir>/<hex(id)>.torrent` -> parse ->
    /// identity check; mismatch = warn and return None (continue the
    /// magnet path). The original file bytes are returned alongside (the
    /// session-side torrent row's metadata BLOB is the outer layer around
    /// the raw info section — the basis for resume rebuilds/re-export;
    /// re-encoding would break the raw slices).
    async fn load_saved(
        dest: &std::path::Path,
        id_bytes: &[u8],
        btih: Option<[u8; 20]>,
        btmh: Option<[u8; 32]>,
    ) -> Option<(Metainfo, Vec<u8>)> {
        let path = dest.join(format!("{}.torrent", hex_lower(id_bytes)));
        // The disk read + parse both go into spawn_blocking (metadata
        // <=8MiB).
        let read = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || std::fs::read(&path)).await
        };
        let bytes = match read {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => return None,
            Err(e) => {
                warn!(target: "taiji::core::magnet", %e, "saved metadata read join failed");
                return None;
            }
        };
        let parsed = {
            let raw = bytes.clone();
            tokio::task::spawn_blocking(move || Metainfo::parse(&raw)).await
        };
        let (parsed, raw) = match parsed {
            Ok(Ok(m)) => (m, bytes),
            Ok(Err(e)) => {
                warn!(target: "taiji::core::magnet", path = %path.display(), %e,
                    "saved metadata unparseable; continuing magnet path");
                return None;
            }
            Err(e) => {
                warn!(target: "taiji::core::magnet", %e, "saved metadata join failed");
                return None;
            }
        };
        match check_identity(parsed.info_bytes.as_ref(), btih, btmh) {
            Ok(()) => {
                info!(target: "taiji::core::magnet", path = %path.display(),
                    "BitTorrent metadata was loaded from saved file");
                Some((parsed, raw))
            }
            Err(reason) => {
                // Reference behavior: warn and continue as if no archive
                // existed.
                warn!(target: "taiji::core::magnet", path = %path.display(), %reason,
                    "saved metadata has unexpected infohash; continuing magnet path");
                None
            }
        }
    }
}

async fn run(
    mut cfg: MagnetTaskConfig,
    parent: CancellationToken,
    upgrade_tx: Option<mpsc::Sender<crate::engine::EngineHandle>>,
) -> MagnetEnd {
    // ---- state machine: Queued -> MetadataPending ----
    let mut state = TorrentState::Queued;
    transit(&mut state, TorrentState::MetadataPending, cfg.gid);

    // ---- magnet parse (frozen face) ----
    let magnet = match magnet_parse::parse(&cfg.magnet_uri) {
        Ok(m) => m,
        Err(e) => {
            transit(&mut state, TorrentState::Error, cfg.gid);
            return MagnetEnd::Failed(format!("magnet parse failed: {e}"));
        }
    };
    // tr -> tiers (parseMagnet semantics: one tier per tr; empty URLs
    // filtered; non-UTF-8 replaced lossily with U+FFFD — replaced rather
    // than filtered, because lossy always yields non-empty output for
    // non-empty input; no second empty filter, which would be a
    // always-true dead branch).
    let mut trs: Vec<String> = magnet
        .tr
        .iter()
        .filter(|u| !u.is_empty())
        .map(|u| String::from_utf8_lossy(u).into_owned())
        .collect();
    if let Some(updates) = &cfg.tracker_updates {
        trs = updates
            .borrow()
            .iter()
            .map(|(_, tracker)| tracker.clone())
            .collect();
    }
    let cached_metadata = cfg
        .services
        .as_ref()
        .and_then(|services| services.cached(magnet.btih, magnet.btmh));
    if trs.is_empty()
        && cached_metadata.is_none()
        && !cfg.options.bt_load_saved_metadata
        && !cfg.dht_enabled
        && cfg.lsd.is_none()
        && magnet.xpe.is_none()
        && magnet.metadata_sources.is_empty()
        && cfg.web.as_ref().is_none_or(|web| web.templates.is_empty())
    {
        // Trackerless metadata is valid. Reject only when the caller has
        // disabled every discovery source; DHT magnets remain pending until
        // peers supply metadata or the caller cancels them.
        transit(&mut state, TorrentState::Error, cfg.gid);
        return MagnetEnd::Failed(
            "magnet carries no tr tracker list and no enabled peer discovery source".into(),
        );
    }
    let mut tiers: Vec<(usize, String)> = trs
        .iter()
        .enumerate()
        .map(|(i, u)| (i, u.clone()))
        .collect();

    // ---- dual-identity discovery faces ----
    let mut faces: Vec<MetaFace> = Vec::new();
    if let Some(btih) = magnet.btih {
        faces.push(MetaFace {
            index: faces.len(),
            info_hash: btih,
            reserved: Reserved::aria2_default(),
            expected: ExpectedInfoHash::V1(btih),
            dht_kind: DhtSwarmKind::V1,
        });
    }
    if let Some(btmh) = magnet.btmh {
        faces.push(MetaFace {
            index: faces.len(),
            info_hash: truncated_v2(&btmh),
            reserved: Reserved::aria2_default().with_v2(),
            expected: ExpectedInfoHash::V2(btmh),
            dht_kind: DhtSwarmKind::V2,
        });
    }
    let face_by_hash = |h: &[u8; 20]| faces.iter().position(|f| &f.info_hash == h);

    // ---- bt-load-saved-metadata short circuit (download_helper.cc) ----
    // The parse model + the original file bytes kept as a pair (the
    // finalize metadata BLOB source).
    let mut metainfo: Option<(Metainfo, Vec<u8>)> = None;
    if cfg.options.bt_load_saved_metadata {
        let (id_bytes, btih, btmh) = match (magnet.btih, magnet.btmh) {
            (Some(btih), _) => (btih.to_vec(), Some(btih), None),
            (None, Some(btmh)) => (btmh.to_vec(), None, Some(btmh)),
            (None, None) => unreachable!("magnet parse guarantees at least one identity"),
        };
        metainfo = MagnetEngine::load_saved(&cfg.dest, &id_bytes, btih, btmh).await;
    }

    if metainfo.is_none() {
        if let Some(cached) = cached_metadata {
            let trackers = trs.clone();
            let btih = magnet.btih;
            let btmh = magnet.btmh;
            metainfo = tokio::task::spawn_blocking(move || {
                let (_, span) = taiji_bt::bencode::decode_with_info_span(&cached).ok()?;
                check_identity(&cached[span.clone()], btih, btmh).ok()?;
                let bytes =
                    metadata2torrent(&cached[span], &trackers, &services::cached_layers(&cached));
                let meta = Metainfo::parse(&bytes).ok()?;
                Some((meta, bytes))
            })
            .await
            .ok()
            .flatten();
            if metainfo.is_some() {
                info!(target:"taiji::core::magnet","verified session metadata cache hit");
            }
        }
    }

    if metainfo.is_none()
        && trs.is_empty()
        && !cfg.dht_enabled
        && cfg.lsd.is_none()
        && magnet.xpe_peers.is_empty()
        && magnet.metadata_sources.is_empty()
        && cfg.web.as_ref().is_none_or(|web| web.templates.is_empty())
    {
        return MagnetEnd::Failed("no verified cached metadata or enabled discovery source".into());
    }

    // ---- metadata phase (discovery + ut_metadata fetch) ----
    let phase: Option<MetadataPhase> = if metainfo.is_some() {
        None // bt-load-saved-metadata short circuit: no metadata phase
    } else {
        let md_token = parent.child_token();
        // Take the leases out (recv needs &mut; finalize no longer
        // consumes them — the DHT/LSD lifecycles belong to the owner,
        // closed out by the session later).
        let mut dht_lease = cfg.dht.take();
        let mut lsd_lease = cfg.lsd.take();
        let result = discover_and_fetch(
            &cfg,
            &mut dht_lease,
            &mut lsd_lease,
            &faces,
            &tiers,
            &magnet.xpe_peers,
            &md_token,
            &face_by_hash,
        )
        .await;
        match result {
            Ok(phase) => Some(phase),
            Err(reason) => {
                md_token.cancel();
                transit(&mut state, TorrentState::Error, cfg.gid);
                return MagnetEnd::Failed(reason);
            }
        }
    };
    let metadata: Bytes = match (&phase, metainfo.as_ref()) {
        (Some(p), _) => p.metadata.clone(),
        (None, Some((m, _))) => m.info_bytes.clone(),
        (None, None) => unreachable!("phase or saved metadata must exist"),
    };

    if let Some(updates) = &cfg.tracker_updates {
        tiers = updates.borrow().clone();
        trs = tiers.iter().map(|(_, url)| url.clone()).collect();
    }
    // ---- rebuild + verify + options + upgrade ----
    finalize(
        cfg, magnet, trs, tiers, metadata, metainfo, phase, faces, state, parent, upgrade_tx,
    )
    .await
}

/// The discovery + ut_metadata fetch loop (the metadata-phase body).
///
/// `xpe` = the magnet `x.pe` direct endpoint (None = the parameter is
/// absent, zero behavior change). The injection point is this
/// metadata-phase discovery face — bt-metadata-only and the upgrade flow
/// share the same phase (both task shapes go through
/// `discover_and_fetch` and benefit); the upgraded engine rebuilds its
/// connection face entirely (engine responsibility), and x.pe sits at
/// the same layer as the DHT/tracker/LSD/web sources as a metadata-phase
/// discovery input.
#[expect(
    clippy::too_many_arguments,
    reason = "discovery leases and swarm faces are passed explicitly; bundling is a later phase"
)]
async fn discover_and_fetch(
    cfg: &MagnetTaskConfig,
    dht: &mut Option<DhtLease>,
    lsd: &mut Option<LsdLease>,
    faces: &[MetaFace],
    tiers: &[(usize, String)],
    xpe: &[std::net::SocketAddr],
    md_token: &CancellationToken,
    face_by_hash: &(dyn Fn(&[u8; 20]) -> Option<usize> + Sync),
) -> Result<MetadataPhase, String> {
    let phase_started = std::time::Instant::now();
    let mut network = if let Some(services) = &cfg.services {
        let (network, lease) = services.open(cfg, faces, md_token).await?;
        if dht.is_none() {
            *dht = lease;
        }
        network
    } else {
        network::Network::bind(
            cfg.phase.listen_port,
            cfg.peer_id,
            faces
                .iter()
                .map(|face| (face.info_hash, face.reserved))
                .collect(),
            cfg.nat.clone(),
            md_token,
        )
        .await?
    };
    let actual_port = network.dialer.port;
    if dht.is_none() && cfg.dht_enabled {
        if let Some((inbound, demux)) = network.dht.take() {
            let restore = match cfg.persist.as_ref() {
                Some((_, handle)) => {
                    crate::engine::load_dht_restore_state(handle, DhtFamily::V4).await
                }
                None => None,
            };
            *dht = spawn_phase_dht_on(inbound, demux, md_token.clone(), restore).await;
        }
    }
    let phase_nat = network.dialer.nat.clone();
    let mut external_ports = phase_nat.as_ref().map(|nat| nat.subscribe_external_ports());
    // Split the leases: the handle (Clone semantics, for
    // announce/get_peers) and the event receiver (moved; recv needs
    // exclusivity).
    let mut extra_dht_handles = Vec::new();
    let (dht_handle, mut dht_events): (Option<DhtHandle>, Option<mpsc::Receiver<DhtEvent>>) =
        match dht.take() {
            Some(lease) => {
                extra_dht_handles = lease.extra_handles;
                (Some(lease.handle), Some(lease.events))
            }
            None => (None, None),
        };
    let (lsd_handle, mut lsd_events): (Option<LsdHandle>, Option<mpsc::Receiver<LsdEvent>>) =
        match lsd.take() {
            Some(l) => (Some(l.handle), Some(l.events)),
            None => (None, None),
        };
    let swarm_peers = Arc::new(AtomicUsize::new(0));
    // Fetch results (concurrent peers, first wins; capacity 16 = an order
    // above the face cap).
    let (md_tx, mut md_rx) = mpsc::channel::<MetadataFetched>(16);
    // Tracker actor event aggregation.
    let (agg_tx, mut agg_rx) =
        mpsc::channel::<(usize, TrackerActorEvent)>(EVENT_CHANNEL_CAPACITY * faces.len());

    let mut tracker_updates = cfg.tracker_updates.clone();

    // ---- one TrackerActor per face (announce self-driven; identical
    // wiring) ----
    // Actor command handles: held until phase close-out (dropping all of
    // them exits the actor) — the metadata phase does not drive the Stop
    // sequence (shutdown semantics belong to the task teardown; here the
    // handles drop to close out).
    // BEP7: the announce request's `ipv6=` payload = this host's global
    // IPv6 (probed once; failure / no global address = None = omitted;
    // probe implementation in bt::dht::security probe_source_ip — v6 = a
    // bounded TCP connect probe).
    // Route probing is supplementary. It must never delay a ready tracker,
    // explicit peer or DHT result; activate IPv6 tracker paths when ready.
    let ipv6_probe = async {
        taiji_bt::dht::security::probe_source_ip(true)
            .await
            .and_then(|ip| match ip {
                std::net::IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
    };
    tokio::pin!(ipv6_probe);
    let mut ipv6_probe_done = !cfg.dht_ipv6_enabled;
    let mut actor_cmds: Vec<mpsc::Sender<TrackerCommand>> = Vec::new();
    for (face_i, face) in faces.iter().enumerate() {
        let (face_ev_tx, mut face_ev_rx) =
            mpsc::channel::<TrackerActorEvent>(EVENT_CHANNEL_CAPACITY);
        let (actor_out_tx, carrier_out_rx) = mpsc::channel(UDP_OUTBOUND_CAPACITY);
        let (carrier_in_tx, actor_in_rx) = mpsc::channel(UDP_INBOUND_CAPACITY);
        tokio::spawn(udp_carrier(carrier_out_rx, carrier_in_tx));
        let actor_cmd = spawn_tracker_actor(
            TrackerActorConfig {
                info_hash: face.info_hash,
                peer_id: cfg.peer_id,
                // The tracker follows the actual bound port and any later
                // gateway grant through SetListenPort below.
                listen_port: phase_nat
                    .as_ref()
                    .map(|n| n.external_ports().effective(actual_port))
                    .unwrap_or(actual_port),
                options: TrackerOptions {
                    local_ipv6: None,
                    ..TrackerOptions::default()
                },
                // The pre-MSE-negotiation rule (same as the engine): the
                // announce carries no requirecrypto.
                require_crypto: false,
                // The BEP27 single-flight gate does not apply to the
                // metadata phase: the private bit lives inside the info
                // dict and is unknowable before the metadata is fetched
                // ("a magnet cannot be private -> BEP27 always allows",
                // same as the DHT face); the upgraded engine takes over
                // via EngineConfig.private.
                private: false,
                tiers: tiers.to_vec(),
                scrape_hashes: faces.iter().map(|f| f.info_hash).collect(),
            },
            Arc::new(MetaSwarmView {
                peers: swarm_peers.clone(),
            }),
            face_ev_tx,
            UdpTransport {
                outbound: actor_out_tx,
                inbound: actor_in_rx,
            },
        );
        match actor_cmd {
            Ok(cmd) => actor_cmds.push(cmd),
            Err(e) => warn!(target: "taiji::core::magnet", %e,
                "metadata-phase tracker actor spawn failed"),
        }
        let tag = agg_tx.clone();
        tokio::spawn(async move {
            while let Some(ev) = face_ev_rx.recv().await {
                if tag.send((face_i, ev)).await.is_err() {
                    break;
                }
            }
        });
    }

    // ---- DHT: bootstrap + announce (a magnet cannot be private -> BEP27
    // always allows) ----
    let bootstrap = async {
        if let Some(dht) = dht_handle.as_ref() {
            // The bootstrap wait is bounded by
            // [`MetadataPhaseConfig::dht_bootstrap_budget`] (entry DNS /
            // restricted networks can block indefinitely): the timeout only
            // gives up waiting; the engine-side bootstrap rounds keep running
            // in the background (receipt-driven node_lookup + refresh), and
            // periodic get_peers/announce naturally produce PeersFound once
            // the table fills.
            if cfg.services.is_none() {
                let boot = async {
                    let entry_points = if let Some(endpoint) = &cfg.dht_entry_point_override {
                        resolve_bootstrap_override(endpoint).await
                    } else {
                        resolve_entry_points(&cfg.dht_entry_points).await
                    };
                    dht.bootstrap(entry_points).await
                };
                match tokio::time::timeout(cfg.phase.dht_bootstrap_budget, boot).await {
                    Ok(Ok(n)) => {
                        info!(target: "taiji::core::magnet", reachable = n, "dht bootstrap done")
                    }
                    Ok(Err(e)) => warn!(target: "taiji::core::magnet", %e, "dht bootstrap failed"),
                    Err(_) => warn!(target: "taiji::core::magnet",
                budget = ?cfg.phase.dht_bootstrap_budget,
                "dht bootstrap wait budget exceeded; phase continues (engine-side bootstrap keeps running)"),
                }
            }
            for face in faces {
                match DhtTarget::new(face.info_hash, face.dht_kind, false) {
                    Ok(target) => {
                        if let Err(e) = dht
                            .announce(
                                target,
                                phase_nat
                                    .as_ref()
                                    .and_then(|nat| nat.external_ports().udp)
                                    .unwrap_or(actual_port),
                            )
                            .await
                        {
                            warn!(target: "taiji::core::magnet", %e, "dht announce rejected");
                        }
                    }
                    Err(e) => warn!(target: "taiji::core::magnet", %e, "dht target gate refused"),
                }
            }
        }
        for handle in &extra_dht_handles {
            for face in faces {
                if let Ok(target) = DhtTarget::new(face.info_hash, face.dht_kind, false) {
                    let _ = handle.announce(target, actual_port).await;
                }
            }
        }
    };
    tokio::pin!(bootstrap);
    let mut bootstrap_done = false;

    // ---- LSD: the BEP14 payload is a 20B infohash — only the btih face
    // is announced (truncated v2 has no interop story; honest, not faked)
    // ----
    // LAN discovery advertises the local listener, independent of NAT.
    if let Some(lsd) = lsd_handle.as_ref() {
        if let Some(btih_face) = faces
            .iter()
            .find(|f| matches!(f.expected, ExpectedInfoHash::V1(_)))
        {
            if let Err(e) = lsd.announce(btih_face.info_hash, actual_port).await {
                warn!(target: "taiji::core::magnet", %e, "lsd announce failed");
            }
        } else {
            debug!(target: "taiji::core::magnet",
                "btmh-only magnet: LSD skipped (no v1 identity to advertise)");
        }
    }

    // Dial bookkeeping: dedup + cap; a failed dial leaves the bookkeeping
    // (retryable at the next discovery round).
    let dialed = Arc::new(std::sync::Mutex::new(HashSet::<(
        usize,
        std::net::SocketAddr,
    )>::new()));
    let dialed_total = Arc::new(AtomicUsize::new(0));
    // Live connection pool (feeds the post-metadata piece-layer
    // prefetch).
    let live: LivePeers = Arc::new(std::sync::Mutex::new(Vec::new()));

    let (pex_tx, mut pex_rx) = mpsc::channel(128);
    let (hp_tx, mut hp_rx) = mpsc::channel(64);
    let (report_tx, mut report_rx) = mpsc::channel(128);
    let signals = Arc::new(PeerSignals {
        network: network.dialer.clone(),
        candidates: std::sync::Mutex::new(candidates::Candidates::new()),
        metadata: faces
            .iter()
            .map(|face| {
                Arc::new(taiji_bt::ut_metadata::MetadataCoordinator::new(
                    face.expected,
                ))
            })
            .collect(),
        pex: pex_tx,
        holepunch: hp_tx,
        reports: report_tx,
        next_id: AtomicU64::new(1),
        introducers: AtomicUsize::new(0),
        max_introducers: cfg.phase.max_metadata_peers.saturating_sub(1).min(4),
        enabled: cfg.options.holepunch
            && cfg.options.bt_peer_connection_type != taiji_bt::utp::PeerConnectionType::Tcp,
    });
    let mut hp_books: Vec<_> = faces
        .iter()
        .map(|_| taiji_bt::holepunch::HolepunchBook::new(512))
        .collect();
    let mut pending_rendezvous = Vec::new();
    let mut pending_peers = VecDeque::new();
    let mut peer_slots = tokio::time::interval(Duration::from_millis(100));
    peer_slots.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Periodic rediscovery (re-issue DHT get_peers; tracker/LSD
    // self-drive).
    let mut round = tokio::time::interval(cfg.phase.discovery_round);
    // ---- HTTP mirror race (the fourth source; no v1 face = the public
    // sites have no v2 index ecosystem, skipped honestly). Non-tripped
    // mirrors volley concurrently for one round, verify-first wins; all
    // invalid or failed = a silent fallback to the three P2P sources.
    // ----
    let mut web_rx = spawn_web_mirrors(cfg, faces, md_token);
    // deadline (None = never ready).
    let deadline = cfg
        .phase
        .metadata_deadline
        .map(tokio::time::sleep)
        .unwrap_or_else(|| tokio::time::sleep(Duration::from_secs(u64::MAX)));
    tokio::pin!(deadline);

    loop {
        while dialed_total.load(Ordering::Relaxed)
            < cfg.phase.max_metadata_peers
                + if pending_peers
                    .front()
                    .is_some_and(|(_, _, source)| matches!(*source, "holepunch" | "relay-utp"))
                {
                    4
                } else {
                    0
                }
        {
            let connected: Vec<_> = crate::lock(&live)
                .iter()
                .filter(|peer| !peer.token.is_cancelled())
                .map(|peer| peer.address)
                .collect();
            let candidate = crate::lock(&signals.candidates).pop(
                &mut pending_peers,
                &connected,
                std::time::Instant::now(),
            );
            let Some((face_i, addr, source)) = candidate else {
                break;
            };
            spawn_dial_with_network(
                cfg,
                faces,
                face_i,
                addr,
                source,
                &swarm_peers,
                &dialed,
                &dialed_total,
                &live,
                md_tx.clone(),
                md_token,
                Some(signals.clone()),
            );
        }
        tokio::select! {
            biased;
            _ = md_token.cancelled() => {
                return Err("metadata phase cancelled".into());
            }
            _ = peer_slots.tick() => {
                if signals.enabled { retry_metadata_rendezvous(&live, &mut hp_books, &mut pending_peers, &mut pending_rendezvous); }
            }
            incoming = network.incoming.recv() => {
                if let Some(incoming) = incoming {
                    spawn_incoming_peer(cfg, faces, incoming, &swarm_peers, &dialed_total, &live, md_tx.clone(), md_token, signals.clone());
                }
            }
            Some(event) = pex_rx.recv() => {
                let peer = crate::lock(&live).iter().find(|p| p.id == event.from && !p.token.is_cancelled()).cloned();
                if let Some(peer) = peer {
                    for address in event.fresh {
                        if let Some(address) = crate::engine::addr_hygiene::sanitize_discovered_addr(address) {
                            hp_books[peer.face].note_introduced(address, peer.id, std::time::Instant::now());
                            let capability = event.capabilities.iter().find(|p| p.addr == address);
                            let source = if capability.is_some_and(|p| p.supports_holepunch) { "pex-holepunch" } else if capability.is_some_and(|p| p.supports_utp) { "pex-utp" } else { "pex" };
                            queue_metadata_peer(&mut pending_peers, peer.face, address, source);
                        }
                    }
                }
                if signals.enabled { retry_metadata_rendezvous(&live, &mut hp_books, &mut pending_peers, &mut pending_rendezvous); }
            }
            Some(report) = report_rx.recv() => {
                match report {
                    PeerReport::Slow { face, address } | PeerReport::Failed { face, address } => hp_books[face].note_dial_failed(address, std::time::Instant::now()),
                    PeerReport::Closed(id) => { for book in &mut hp_books { book.remove_introducer(id); } },
                    PeerReport::Connected { face, address, id, source } => {
                        hp_books[face].note_dial_connected(&address);
                        if source == "relay-utp" {
                            for &(f, relay, target) in &pending_rendezvous {
                                if f == face && relay == address { hp_books[face].note_introduced(target, id, std::time::Instant::now()); }
                            }
                        }
                    }
                }
                if signals.enabled { retry_metadata_rendezvous(&live, &mut hp_books, &mut pending_peers, &mut pending_rendezvous); }
            }
            Some(event) = hp_rx.recv(), if signals.enabled => {
                handle_metadata_holepunch(event, &live, &mut pending_peers);
            }
            changed = async {
                match external_ports.as_mut() { Some(ports) => ports.changed().await.is_ok(), None => std::future::pending().await }
            } => {
                if !changed { external_ports = None; continue; }
                let ports = external_ports.as_ref().map(|ports| *ports.borrow()).unwrap_or_default();
                for actor in &actor_cmds { let _ = actor.send(TrackerCommand::SetListenPort { port: ports.effective(actual_port) }).await; }
                if let Some(dht) = &dht_handle {
                    for face in faces { if let Ok(target) = DhtTarget::new(face.info_hash, face.dht_kind, false) { let _ = dht.announce(target, ports.udp.unwrap_or(actual_port)).await; } }
                }
                for peer in crate::lock(&live).iter() {
                    let port = signals.network.advertised(peer.transport, peer.address);
                    let _ = peer.handle.command(PeerCommand::SetListenPort(port));
                }
            }
            address = &mut ipv6_probe, if !ipv6_probe_done => {
                ipv6_probe_done = true;
                if address.is_some() {for actor in &actor_cmds {let _=actor.send(TrackerCommand::SetIpv6 {address}).await;}}
            }
            _ = &mut bootstrap, if !bootstrap_done => { bootstrap_done = true; }
            changed = async {
                match tracker_updates.as_mut() {
                    Some(updates) => updates.changed().await.is_ok(),
                    None => std::future::pending().await,
                }
            } => {
                if !changed { tracker_updates = None; continue; }
                let tiers = tracker_updates.as_ref().map(|updates| updates.borrow().clone()).unwrap_or_default();
                for actor in &actor_cmds {
                    let (reply, _) = tokio::sync::oneshot::channel();
                    let _ = actor.send(TrackerCommand::SetTrackers { tiers: tiers.clone(), reply }).await;
                }
            }
            fetched = md_rx.recv() => match fetched {
                Some(MetadataFetched::Complete(bytes)) => {
                    info!(target: "taiji::core::magnet", len = bytes.len(), elapsed_ms = phase_started.elapsed().as_millis() as u64,
                        "metadata fetched: identity verified (ut_metadata)");
                    let peers = {
                        let pool = crate::lock(&live);
                        pool.clone()
                    };
                    network.release_registration();
                    return Ok(MetadataPhase {
                        metadata: bytes,
                        _network: network,
                        peers: Arc::new(std::sync::Mutex::new(peers)),
                        token: md_token.clone(),
                        web_layers: None,
                    });
                }
                Some(MetadataFetched::Failed(reason)) => {
                    debug!(target: "taiji::core::magnet", %reason,
                        "metadata fetch failed on one peer; waiting for others/discovery");
                }
                None => return Err("metadata result channel closed".into()),
            },
            ev = async {
                match web_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => match ev {
                Some(m) => {
                    info!(target: "taiji::core::magnet", len = m.info.len(),
                        layers = m.layers.len(),
                        "metadata fetched: identity verified (web mirror)");
                    let peers = {
                        let pool = crate::lock(&live);
                        pool.clone()
                    };
                    network.release_registration();
                    return Ok(MetadataPhase {
                        metadata: m.info,
                        _network: network,
                        peers: Arc::new(std::sync::Mutex::new(peers)),
                        token: md_token.clone(),
                        web_layers: Some(m.layers),
                    });
                }
                // All mirror tasks ended without a winner: close this arm
                // and fall back to P2P.
                None => {
                    web_rx=None;
                    if dht_handle.is_none() && lsd_handle.is_none() && tiers.is_empty() && xpe.is_empty() {
                        return Err("explicit metadata sources returned no verified torrent".into());
                    }
                },
            },
            ev = agg_rx.recv() => {
                // Announce/scrape events: the metadata phase stores no
                // rows, only dials Peers.
                let Some((face_i, TrackerActorEvent::Peers { peers, peers6, .. })) = ev else {
                    continue;
                };
                for p in peers.iter().map(|p| std::net::SocketAddr::from((p.ip, p.port)))
                    .chain(peers6.iter().map(|p| std::net::SocketAddr::from((p.ip, p.port))))
                {
                    queue_metadata_peer(&mut pending_peers, face_i, p, "tracker");
                }
            }
            ev = async {
                match dht_events.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if ev.is_none() { dht_events = None; continue; }
                let Some(DhtEvent::PeersFound { info_hash, peers, .. }) = ev else { continue };
                let Some(face_i) = face_by_hash(&info_hash) else { continue };
                for addr in peers {
                    queue_metadata_peer(&mut pending_peers, face_i, addr, "dht");
                }
            }
            ev = async {
                match lsd_events.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if ev.is_none() { lsd_events = None; continue; }
                let Some(LsdEvent::PeerFound { info_hash, peer }) = ev else { continue };
                let Some(face_i) = face_by_hash(&info_hash) else { continue };
                queue_metadata_peer(&mut pending_peers, face_i, peer, "lsd");
            }
            _ = round.tick() => {
                // Rediscovery beat: re-issue DHT get_peers (announce
                // re-sends automatically once registered; tracker/LSD are
                // driven by their own actors, respecting min-interval).
                if let Some(dht) = dht_handle.as_ref() {
                    for face in faces {
                        if let Ok(target) = DhtTarget::new(face.info_hash, face.dht_kind, false) {
                            let _ = dht.get_peers(target).await;
                        }
                    }
                }
                for handle in &extra_dht_handles {
                    for face in faces { if let Ok(target)=DhtTarget::new(face.info_hash,face.dht_kind,false) {let _=handle.get_peers(target).await;} }
                }
                // ---- `x.pe` direct-source re-issue (the interval's first
                // tick fires immediately = dial at phase start; the same
                // rediscovery beat as DHT get_peers) ----
                // The dial face reuses the full existing spawn_dial
                // defense chain, zero bypass: address hygiene -> IpGuard
                // ban gate -> self-connect check (the extended predicate)
                // -> dialed bookkeeping dedup -> the max_metadata_peers
                // cap -> post-handshake Throttled limiting.
                // A successful connection stays in bookkeeping (later
                // rounds skip it — connected dedup); a failure leaves it
                // and retries naturally next round (the static-address
                // rediscovery backstop).
                //
                // Explicit peers participate in each declared swarm face;
                // address hygiene, retry history and dial budgets still apply.
                for address in xpe {
                    for face in faces {queue_metadata_peer(&mut pending_peers,face.index,*address,"xpe");}
                }
            }
            _ = &mut deadline => {
                return Err(format!(
                    "metadata deadline exceeded ({:?}): no peer offered valid metadata \
                     (honest failure, AGENTS §2.6)",
                    cfg.phase.metadata_deadline
                ));
            }
        }
    }
}

fn queue_metadata_peer(
    queue: &mut VecDeque<(usize, std::net::SocketAddr, &'static str)>,
    face: usize,
    address: std::net::SocketAddr,
    source: &'static str,
) {
    if matches!(source, "holepunch" | "relay-utp") {
        queue.retain(|(f, a, _)| *f != face || *a != address);
        if queue.len() < 1024 {
            queue.push_front((face, address, source));
        }
    } else if queue.len() < 1024 && !queue.iter().any(|(f, a, _)| *f == face && *a == address) {
        queue.push_back((face, address, source));
    }
}

/// Resolve the DHT bootstrap entry points (explicit entries first;
/// otherwise the hardcoded routers). Production uses the shared resolver
/// service's process-default instance (injected via
/// [`resolve_entry_points_with`]).
async fn resolve_entry_points(explicit: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    resolve_entry_points_with(explicit, &taiji_io::dns::SharedDns::shared_default()).await
}

/// Injection face of [`resolve_entry_points`] (the test seam:
/// `SharedDns::with_resolver` builds an isolated stub — no real DNS).
/// DNS goes through the shared resolver (a TTL cache + a 30s timeout
/// backstop inside the resolver stack's TimeoutResolver — a hanging
/// resolution can no longer stall the startup chain indefinitely);
/// failed nodes are skipped with a debug log (semantics preserved).
async fn resolve_entry_points_with(
    explicit: &[std::net::SocketAddr],
    dns: &taiji_io::dns::SharedDns,
) -> Vec<std::net::SocketAddr> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    use futures::StreamExt as _;
    let mut pending = futures::stream::FuturesUnordered::new();
    for (host, port) in taiji_bt::dht::DEFAULT_BOOTSTRAP_NODES {
        pending.push(async move {
            match tokio::time::timeout(
                Duration::from_secs(3),
                dns.resolve_for_transport(host, *port),
            )
            .await
            {
                Ok(Ok(addresses)) => addresses
                    .into_iter()
                    .filter(std::net::SocketAddr::is_ipv4)
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            }
        });
    }
    let mut out = Vec::new();
    while let Some(addresses) = pending.next().await {
        for address in addresses {
            if !out.contains(&address) {
                out.push(address);
            }
        }
    }
    out
}

async fn resolve_bootstrap_override(endpoint: &str) -> Vec<std::net::SocketAddr> {
    if let Ok(address) = endpoint.parse::<std::net::SocketAddr>() {
        return if address.is_ipv4() {
            vec![address]
        } else {
            Vec::new()
        };
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Vec::new();
    };
    let Ok(port) = port.parse::<u16>() else {
        return Vec::new();
    };
    let dns = taiji_io::dns::SharedDns::shared_default();
    match tokio::time::timeout(
        Duration::from_secs(3),
        dns.resolve_for_transport(host, port),
    )
    .await
    {
        Ok(Ok(addresses)) => addresses
            .into_iter()
            .filter(std::net::SocketAddr::is_ipv4)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "test adapter preserves the explicit dial identity and lifecycle arguments"
)]
fn spawn_dial(
    cfg: &MagnetTaskConfig,
    faces: &[MetaFace],
    face: usize,
    address: std::net::SocketAddr,
    source: &'static str,
    peers: &Arc<AtomicUsize>,
    dialed: &Arc<std::sync::Mutex<HashSet<(usize, std::net::SocketAddr)>>>,
    total: &Arc<AtomicUsize>,
    live: &LivePeers,
    tx: mpsc::Sender<MetadataFetched>,
    token: &CancellationToken,
) {
    spawn_dial_with_network(
        cfg, faces, face, address, source, peers, dialed, total, live, tx, token, None,
    );
}

/// The post-metadata close-out: identity review -> rebuild -> verify ->
/// options -> upgrade. `metainfo` = (parse model, original bytes) —
/// carried by the bt-load-saved-metadata short circuit; the artifact
/// bytes are preserved end to end (the torrent row metadata BLOB
/// source).
#[expect(
    clippy::too_many_arguments,
    reason = "upgrade hand-off carries every phase artifact explicitly; bundling is a later phase"
)]
async fn finalize(
    cfg: MagnetTaskConfig,
    magnet: magnet_parse::Magnet,
    trs: Vec<String>,
    tiers: Vec<(usize, String)>,
    metadata: Bytes,
    metainfo: Option<(Metainfo, Vec<u8>)>,
    phase: Option<MetadataPhase>,
    faces: Vec<MetaFace>,
    mut state: TorrentState,
    parent: CancellationToken,
    upgrade_tx: Option<mpsc::Sender<crate::engine::EngineHandle>>,
) -> MagnetEnd {
    let chain = MetadataChain {
        metadata_gid: cfg.gid,
        task_gid: cfg.gid, // in-place upgrade keeps the same GID
        metadata_uri: cfg.magnet_uri.clone(),
        paused: cfg.options.pause_metadata,
    };

    // ---- engine-side identity review (the gate of the double defense;
    // the fetcher already validated the winning face) ----
    if let Err(reason) = check_identity(&metadata, magnet.btih, magnet.btmh) {
        transit(&mut state, TorrentState::Error, cfg.gid);
        return MagnetEnd::Failed(reason);
    }

    // ---- BEP52 piece-layer prefetch (before parsing) ----
    // `piece layers` sits outside the info dict (a BEP52 top-level key) —
    // magnet metadata does not carry it. Multi-piece files' v2
    // verification anchors (per-piece hashes) are therefore missing;
    // BEP52 hash exchange exists exactly for this: the base layer
    // (<=512 leaves, one request) is fetched from a peer and the whole
    // layer recomputes and verifies against the pieces root; once trusted
    // it is injected as the top-level `piece layers` (the parser's load
    // verification then passes).
    // Failure = an explicit Failed: v2/hybrid metadata without layers
    // cannot pass the parser load, and no fake upgrade is allowed. The
    // metadata-phase connections close after the prefetch.
    let piece_layers: Vec<([u8; 32], Vec<u8>)> = match &phase {
        Some(phase) => match &phase.web_layers {
            // HTTP mirror hit — the layers were already Merkle-verified to
            // the pieces root at fetch time (verify_web_torrent); inject
            // them directly (the peer pool may be empty, so the prefetch
            // cannot be relied on).
            Some(layers) => {
                phase.token.cancel();
                layers.clone()
            }
            None => match prefetch_piece_layers(&metadata, phase, &faces).await {
                Ok(layers) => {
                    phase.token.cancel();
                    layers
                }
                Err(reason) => {
                    phase.token.cancel();
                    transit(&mut state, TorrentState::Error, cfg.gid);
                    return MagnetEnd::Failed(reason);
                }
            },
        },
        None => Vec::new(), // bt-load-saved-metadata: the file carries its own piece layers
    };

    drop(phase);

    // ---- rebuild + parse verification (incl. v2 layer checks; parses
    // >1MiB go to spawn_blocking) ----
    // The artifact bytes are preserved end to end (the torrent row's
    // metadata BLOB = the outer layer around the raw info section, for
    // resume rebuilds/re-export; the bt-load-saved-metadata path = the
    // original file bytes).
    let (metainfo, torrent_bytes) = match metainfo {
        Some((m, bytes)) => (m, bytes), // bt-load-saved-metadata: the file is the rebuilt artifact
        None => {
            let torrent = metadata2torrent(&metadata, &trs, &piece_layers);
            let parsed = {
                let torrent = torrent.clone();
                tokio::task::spawn_blocking(move || Metainfo::parse(&torrent)).await
            };
            match parsed {
                Ok(Ok(m)) => (m, torrent),
                Ok(Err(e)) => {
                    // Corrupt metadata (structure/levels/views
                    // inconsistent) -> an explicit rejection.
                    transit(&mut state, TorrentState::Error, cfg.gid);
                    return MagnetEnd::Failed(format!(
                        "rebuilt metadata rejected by parser (corrupt or inconsistent): {e}"
                    ));
                }
                Err(e) => {
                    transit(&mut state, TorrentState::Error, cfg.gid);
                    return MagnetEnd::Failed(format!("metadata parse task join failed: {e}"));
                }
            }
        }
    };

    if let Some(services) = &cfg.services {
        services.remember(magnet.btih, magnet.btmh, &torrent_bytes);
    }

    // ---- bt-save-metadata (before the metadata-only branch, matching the
    // reference order) ----
    if cfg.options.bt_save_metadata {
        let id_bytes: Vec<u8> = match magnet.btih {
            // The aria2 file name = hex(attrs->infoHash) (btih).
            Some(btih) => btih.to_vec(),
            // aria2 has no btmh magnets; local naming uses the multihash
            // digest hex.
            None => magnet.btmh.map(|b| b.to_vec()).unwrap_or_default(),
        };
        let path = cfg.dest.join(format!("{}.torrent", hex_lower(&id_bytes)));
        let payload = torrent_bytes.clone();
        // The write goes through spawn_blocking (disk IO stays out of the
        // async context).
        let write = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, &payload)
            })
            .await
        };
        match write {
            Ok(Ok(())) => info!(target: "taiji::core::magnet", path = %path.display(),
                "metadata saved (bt-save-metadata)"),
            Ok(Err(e)) => return MagnetEnd::Failed(format!("metadata save failed: {e}")),
            Err(e) => return MagnetEnd::Failed(format!("metadata save task join failed: {e}")),
        }
    }

    // ---- option gates (the same order as the reference) ----
    if cfg.options.bt_metadata_only {
        return MagnetEnd::MetadataFetched { metadata, chain };
    }
    if !cfg.options.follow_torrent {
        return MagnetEnd::NotFollowed { chain };
    }

    // ---- BEP53: selection validation (the reuse point of the upgrade
    // chain) ----
    // Source merge: the RPC `select-file` option value (cfg.select_file,
    // 0-based already) wins; when absent, fall back to the magnet `so=`
    // (URI parse — taken from the magnet already parsed at the run()
    // entry; parse is a pure function, so parsing the same URI twice is
    // identical). The two sources are mutually exclusive at
    // add/changeOption (both present = an explicit rejection at the
    // session face) — the resume-chain backfill and the URI re-parse
    // agree by construction, so the merge is defensively sound. Index
    // anchor = the client file list (metainfo files order; BEP47 pad
    // entries not counted — v2-only/hybrid lists have no pads; v1-only
    // lists do, and the client does not list them). Out of range = an
    // explicit failure (illegal selections are never silently ignored);
    // applied right after the upgraded engine spawns (consumed before any
    // connection, the engine.rs command face).
    let selected_files = cfg.select_file.clone().or(magnet.so);
    if let Some(sel) = &selected_files {
        let file_count = metainfo.meta.files.iter().filter(|f| !f.padding).count();
        if let Some(bad) = sel.iter().find(|&&i| i as usize >= file_count) {
            transit(&mut state, TorrentState::Error, cfg.gid);
            return MagnetEnd::Failed(format!(
                "select-file/so= file index {bad} out of range ({file_count} files, BEP53)"
            ));
        }
    }

    // ---- in-place upgrade: the engine config fully re-mounted
    // (storage/progress/announce) ----
    transit(&mut state, TorrentState::Allocating, cfg.gid);
    let mut engine_cfg = match crate::engine::engine_config(
        &metainfo,
        cfg.dest.clone(),
        cfg.phase.listen_port,
        cfg.peer_id,
        if cfg.seed_after_complete {
            crate::engine::CompletionMode::Seed
        } else {
            crate::engine::CompletionMode::ReturnOnComplete
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            transit(&mut state, TorrentState::Error, cfg.gid);
            return MagnetEnd::Failed(format!("upgraded engine config rejected: {e}"));
        }
    };
    engine_cfg.seed = cfg.seed;
    // The rate-limit topology passes to the upgraded engine (the metadata
    // phase and the upgraded engine share one chain — the global bucket
    // is shared, session hot updates reach the upgraded connection
    // face).
    engine_cfg.limiter = cfg.limiter;
    // The DHT switch passes to the upgraded engine (the torrent
    // activation path injects at the same point in build_engine_config;
    // DhtWireConfig::default() = false — without the passthrough the
    // engine-side DHT stays off).
    engine_cfg.dht.enabled = cfg.dht_enabled;
    engine_cfg.dht.engine.message_timeout = cfg.dht_message_timeout;
    if let Some(entry) = cfg.dht_entry_point_override {
        engine_cfg.dht.entry_points_v4 = vec![entry];
    }
    if let Some(entry) = cfg.dht_entry_point_v6_override {
        engine_cfg.dht.entry_points_v6 = vec![entry];
    }
    // The webseeding switch passes to the upgraded engine (BEP19; the
    // torrent activation path overwrites at the same point in
    // build_engine_config — per-task `enable-http-seeding` off = clear
    // the webseed set, a BT-only shape).
    if !cfg.webseeding_enabled {
        engine_cfg.webseeds.clear();
    }
    // The session metrics pass to the upgraded engine (tracker announce
    // ok/fail, DHT nodes, connection and byte counters feed points —
    // without the passthrough /metrics reads all zeros with a 0/0
    // announce appearance).
    engine_cfg.stats = cfg.stats;
    // The hook face passes to the upgraded engine + the payload re-mount
    // (the executeHookByOptName data extraction translated from util.cc:
    // firstFilename = the first requested file path, numFiles = the
    // count of requested files — requested = non-pad real files; BEP47
    // pads are placeholder ranges, not file entries). The same runner
    // instance: later session-side stop/complete triggers automatically
    // carry the real file face.
    if let Some(runner) = &cfg.hook {
        let files = engine_cfg.layout.files();
        let num_files = files.iter().filter(|f| !f.padding).count();
        let first_filename = files
            .iter()
            .find(|f| !f.padding)
            .map(|f| cfg.dest.join(&f.path).to_string_lossy().into_owned())
            .unwrap_or_default();
        runner.set_payload(num_files, first_filename);
        engine_cfg.hook = Some(Arc::clone(runner));
    }
    // metadata_serve is mounted by engine_config from info_bytes (the
    // upgraded connections keep serving ut_metadata, a BEP9 obligation).

    if cfg.options.pause_metadata {
        // pause-metadata: upgraded but not started. Session residency: the
        // upgrade artifact (parse model + rebuilt bytes) goes to the
        // session to become a paused torrent task (resume semantics like
        // a normal torrent row).
        info!(target: "taiji::core::magnet", gid = %cfg.gid,
            "task upgraded but paused (bt-pause-metadata); session residency");
        return MagnetEnd::UpgradedPaused {
            chain,
            meta: std::sync::Arc::new(metainfo),
            torrent: torrent_bytes,
        };
    }

    // Controlled spawn — the upgrade notification face (the EngineHandle
    // goes to the session, bounded(1) lossy; see
    // spawn_with_upgrade_notify) + the upgraded engine's live readings.
    engine_cfg.nat = cfg.nat.clone();
    engine_cfg.initial_selection = selected_files.clone();
    let (upgraded_handle, engine_join) = DownloadEngine::spawn_controlled(
        engine_cfg,
        TrackerWireConfig {
            tiers,
            persist: cfg.persist,
            // IpGuard: None = the engine builds its own internal snapshot
            // (the magnet chain has no external blocklist injection
            // point; session-level wiring is a later milestone).
            guard: None,
        },
        &parent,
        // The outbound transport plan passes with the session options to
        // the upgraded engine (the metadata transport is selected independently —
        // the standalone dial loop has no uTP face; the gap is noted on
        // the option field).
        cfg.options.bt_peer_connection_type,
    );
    // BEP53: the selection is applied at activation (the engine consumes
    // it before announce-driven connects).
    // Err = the engine face rejects (out of range/empty — the validation
    // ran earlier; the defensive path fails explicitly too).
    if let Some(sel) = &selected_files {
        if let Err(e) = upgraded_handle
            .set_file_selection(Arc::from(sel.as_slice()))
            .await
        {
            transit(&mut state, TorrentState::Error, cfg.gid);
            return MagnetEnd::Failed(format!("file selection rejected: {e}"));
        }
    }
    // The upgraded engine entering Running registers Downloading — the
    // engine previously tore down straight to Done over an unregistered
    // edge (Allocating -> Done is not in the transition table), so every
    // magnet upgrade logged "illegal torrent state transition". Routed
    // through Downloading, all three teardown states
    // (Done/Stopping/Error) sit on registered edges.
    transit(&mut state, TorrentState::Downloading, cfg.gid);
    if let Some(tx) = upgrade_tx {
        // Deliver a clone; this module keeps the original handle until the
        // engine finishes — if every EngineHandle drops, the engine
        // command channel closes and its select command arm becomes
        // permanently ready (recv -> None returns immediately), spinning
        // the engine main loop (the observed root cause of the
        // magnet_chain tests deadlocking under concurrency).
        let _ = tx.send(upgraded_handle.clone()).await;
    }
    let end = match engine_join.await {
        Ok(end) => end,
        Err(e) => {
            transit(&mut state, TorrentState::Error, cfg.gid);
            return MagnetEnd::Failed(format!("upgraded engine task join failed: {e}"));
        }
    };
    // The teardown state registers by the engine's final value (all three
    // edges from Downloading are in the transition table); Cancelled ->
    // Stopping (the GID-keeps-result classification belongs to the
    // session side; the local state machine records "stopping"
    // accurately).
    transit(
        &mut state,
        match end {
            EngineEnd::Cancelled => TorrentState::Stopping,
            EngineEnd::Failed(_) => TorrentState::Error,
            EngineEnd::Completed | EngineEnd::SeedStopped | EngineEnd::Detached => {
                TorrentState::Done
            }
        },
        cfg.gid,
    );
    MagnetEnd::Upgraded {
        end,
        chain,
        meta: std::sync::Arc::new(metainfo),
        torrent: torrent_bytes,
    }
}

/// The single-request cap for a single-file piece layer (BEP52 SHOULD
/// be <=512; a file layer with >512 leaves cannot be verified to the
/// root within one request and is not prefetched).
const MAX_PREFETCH_LEAVES: u64 = 512;

/// Files waiting for prefetch: (pieces root, file length).
type LayersWanted = Vec<([u8; 32], u64)>;

/// Scan the raw info-dict bytes for files needing piece-layer prefetch
/// (multi-piece and <= [`MAX_PREFETCH_LEAVES`] pieces). v1-only metadata
/// (no `file tree`) returns an empty list — v1 verification does not rely
/// on piece layers.
fn scan_layers_needed(metadata: &[u8]) -> Result<(u32, LayersWanted), &'static str> {
    let value = bencode::decode_permissive(metadata).map_err(|_| "info dict not decodable")?;
    let Value::Dict(d) = &value else {
        return Err("info dict is not a dict");
    };
    let piece_len = match d
        .iter()
        .find(|(k, _)| k.as_slice() == b"piece length")
        .map(|(_, v)| v)
    {
        Some(Value::Int(i)) if *i > 0 => *i as u64,
        _ => return Err("info dict missing `piece length`"),
    };
    let Some(tree) = d
        .iter()
        .find(|(k, _)| k.as_slice() == b"file tree")
        .map(|(_, v)| v)
    else {
        return Ok((piece_len as u32, Vec::new())); // v1-only: no layers needed
    };
    let mut wanted = Vec::new();
    let mut oversized = false;
    fn walk(tree: &Value, piece_len: u64, wanted: &mut Vec<([u8; 32], u64)>, oversized: &mut bool) {
        let Value::Dict(d) = tree else {
            return;
        };
        let is_leaf = d.iter().any(|(k, _)| k.as_slice() == b"length");
        if is_leaf {
            let length = match d
                .iter()
                .find(|(k, _)| k.as_slice() == b"length")
                .map(|(_, v)| v)
            {
                Some(Value::Int(i)) if *i > 0 => *i as u64,
                _ => return, // empty files have no root, no layer
            };
            let root = match d
                .iter()
                .find(|(k, _)| k.as_slice() == b"pieces root")
                .map(|(_, v)| v)
            {
                Some(Value::Bytes(b)) => <[u8; 32]>::try_from(b.as_slice()).ok(),
                _ => None,
            };
            let Some(root) = root else {
                return;
            };
            let pieces = length.div_ceil(piece_len);
            if pieces > 1 {
                if pieces <= MAX_PREFETCH_LEAVES {
                    wanted.push((root, length));
                } else {
                    *oversized = true;
                }
            }
            return;
        }
        for (_, v) in d {
            walk(v, piece_len, wanted, oversized);
        }
    }
    walk(tree, piece_len, &mut wanted, &mut oversized);
    if oversized {
        return Err(
            "file exceeds 512 pieces: piece layer needs segmented hash fetch \
             with proofs (not in M2 scope)",
        );
    }
    Ok((piece_len as u32, wanted))
}

/// BEP52 piece-layer prefetch (completing the magnet chain).
///
/// Fact: `piece layers` is a .torrent TOP-LEVEL key outside the info
/// dict (BEP52 "Torrent File Structure") — metadata fetched by
/// ut_metadata does not contain it. Multi-piece files' v2 verification
/// anchors (per-piece hashes) are therefore missing; BEP52 hash exchange
/// is designed for exactly this: the base layer (<=512 leaves, one
/// request) is fetched from a peer and the whole layer recomputes and
/// verifies against the pieces root (`merkle::validate_piece_layer`, the
/// same function as the filetree load check); once trusted it is
/// injected as the top-level `piece layers` (the parser's load check
/// then passes).
///
/// Failure semantics (honesty): any file layer unobtainable -> `Err`
/// (an explicit Failed — v2/hybrid metadata without layers cannot pass
/// the parser load, and no fake upgrade is allowed).
async fn prefetch_piece_layers(
    metadata: &[u8],
    phase: &MetadataPhase,
    faces: &[MetaFace],
) -> Result<Vec<([u8; 32], Vec<u8>)>, String> {
    let (piece_len, wanted) = scan_layers_needed(metadata).map_err(|e| e.to_string())?;
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    // Candidate connections: v2-face peers first (hash exchange is a
    // BEP52 capability).
    let peers: Vec<PeerTaskHandle> = {
        let pool = crate::lock(&phase.peers);
        let mut v2: Vec<PeerTaskHandle> = Vec::new();
        let mut rest: Vec<PeerTaskHandle> = Vec::new();
        for peer in pool.iter() {
            let (fi, h, token) = (&peer.face, &peer.handle, &peer.token);
            if token.is_cancelled() {
                continue;
            }
            let is_v2 = faces
                .get(*fi)
                .map(|f| matches!(f.expected, ExpectedInfoHash::V2(_)))
                .unwrap_or(false);
            if is_v2 {
                v2.push(h.clone());
            } else {
                rest.push(h.clone());
            }
        }
        v2.extend(rest);
        v2
    };
    if peers.is_empty() {
        return Err("no metadata-phase peer left for hash exchange".into());
    }
    let mut out = Vec::with_capacity(wanted.len());
    for (root, length) in wanted {
        let pieces = length.div_ceil(u64::from(piece_len));
        // Single-request domain: length = a power of two covering the
        // whole leaf domain (BEP52 zero padding; the validate side is
        // isomorphic), MUST be >=2 and a power of two, index=0 a multiple
        // of length.
        let req_len = pieces.next_power_of_two().max(2) as u32;
        let mut got = None;
        for handle in &peers {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let sent = handle
                .command(PeerCommand::RequestHashes {
                    root,
                    base: 0,
                    index: 0,
                    length: req_len,
                    proof: 0,
                    reply: tx,
                })
                .is_ok();
            if !sent {
                continue;
            }
            // rx: oneshot<Result<HashFetch, HashRequestError>>; the outer
            // Result is the oneshot itself (timeout/connection closed).
            let Ok(Ok(Ok(taiji_bt::peer::HashFetch::Hashes(hashes)))) =
                tokio::time::timeout(HASH_FETCH_TIMEOUT, rx).await
            else {
                continue; // timeout/connection closed/hash rejected: try the next peer
            };
            if (hashes.len() as u64) < pieces {
                continue; // insufficient coverage
            }
            let mut layer = Vec::with_capacity(pieces as usize * 32);
            for h in &hashes[..pieces as usize] {
                layer.extend_from_slice(h);
            }
            if merkle::validate_piece_layer(&root, &layer, length, piece_len).is_ok() {
                got = Some(layer);
                break;
            }
            debug!(target: "taiji::core::magnet",
                "prefetched piece layer rejected by root check; trying next peer");
        }
        match got {
            Some(layer) => {
                debug!(target: "taiji::core::magnet", pieces,
                    "piece layer fetched + verified to pieces root");
                out.push((root, layer));
            }
            None => {
                return Err(
                    "piece layer fetch failed on all peers (reject/timeout/root \
                     mismatch); v2/hybrid metadata cannot be loaded without layers"
                        .to_string(),
                );
            }
        }
    }
    Ok(out)
}

/// State transition (a legality check + log; illegal transitions do not
/// panic — the actor boundary is the fault boundary, same as torrent.rs).
fn transit(state: &mut TorrentState, to: TorrentState, gid: Gid) {
    if !legal_transition(*state, to) {
        warn!(target: "taiji::core::magnet", gid = %gid, from = ?*state, to = ?to,
            "illegal torrent state transition");
    }
    debug!(target: "taiji::core::magnet", gid = %gid, from = ?*state, to = ?to,
        "magnet task state transition");
    *state = to;
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_bt::peer_wire::ExtHandshake;

    /// `pub(crate)`: shared with the web_mirrors.rs tests (shared test
    /// infrastructure after the split).
    pub(crate) fn gid() -> Gid {
        let mut alloc = crate::gid::GidAllocator::new();
        alloc.allocate()
    }

    /// A legal v1 single-file .torrent (the metadata2torrent rebuilt
    /// shape). `pub(crate)`: shared with the web_mirrors.rs tests (shared
    /// test infrastructure after the split).
    pub(crate) fn web_mirror_torrent() -> (Vec<u8>, [u8; 20], Vec<u8>) {
        let piece = b"hello";
        let pieces: Vec<u8> = Sha1::digest(piece).to_vec();
        let info = Value::Dict(
            vec![
                (b"length".to_vec(), Value::Int(5)),
                (b"name".to_vec(), Value::Bytes(b"web-mirror-test".to_vec())),
                (b"piece length".to_vec(), Value::Int(16384)),
                (b"pieces".to_vec(), Value::Bytes(pieces)),
            ]
            .into_iter()
            .collect(),
        );
        let info = bencode::encode(&info).unwrap_or_else(|e| panic!("{e}"));
        let btih: [u8; 20] = Sha1::digest(&info).into();
        let torrent = metadata2torrent(&info, &["http://127.0.0.1:1/ann".to_string()], &[]);
        (torrent, btih, info)
    }

    #[test]
    fn metadata2torrent_matches_reference_layout() {
        // bittorrent_helper.cc structure: d [announce-list] 4:info <raw> e.
        let info = b"d4:name3:abce"; // a legal info dict (keys must be byte strings)
        let trs = vec!["http://t1/ann".to_string(), "http://t2/ann".to_string()];
        let torrent = metadata2torrent(info, &trs, &[]);
        // Structural assertions (decode + the info span), not hand-built
        // expected strings.
        let (value, span) =
            bencode::decode_with_info_span(&torrent).unwrap_or_else(|e| panic!("{e}"));
        let tiers = value
            .get(b"announce-list")
            .unwrap_or_else(|| panic!("announce-list missing"));
        let Value::List(tiers) = tiers else {
            panic!("announce-list must be list");
        };
        assert_eq!(tiers.len(), 2);
        let Value::List(t0) = &tiers[0] else {
            panic!("tier must be list");
        };
        assert_eq!(t0[0].as_bytes(), Some(trs[0].as_bytes()));
        // The info section = the raw bytes embedded verbatim.
        assert_eq!(&torrent[span], info);
        assert!(
            value.get(b"info").is_some(),
            "info key must exist (dict; span validation already covered byte equality)"
        );
    }

    #[test]
    fn metadata2torrent_without_tr_has_no_announce_list() {
        let info = b"d4:name1:xi1ee";
        let torrent = metadata2torrent(info, &[], &[]);
        let expect: Vec<u8> = [b"d4:info".as_slice(), info, b"e"].concat();
        assert_eq!(torrent, expect);
    }

    #[test]
    fn options_defaults_match_aria2() {
        let o = MagnetOptions::default();
        assert!(!o.bt_save_metadata, "OptionHandlerFactory.cc");
        assert!(!o.bt_metadata_only, ":1572-1578");
        assert!(o.follow_torrent, ":1793-1801 A2_V_TRUE");
        assert!(!o.pause_metadata, ":612-618");
        assert!(!o.bt_load_saved_metadata, ":1538-1544");
    }

    #[test]
    fn identity_check_rejects_both_sides_of_hybrid_magnet() {
        let info = b"d4:name3:abci7ee";
        let sha1: [u8; 20] = Sha1::digest(info).into();
        let sha256: [u8; 32] = Sha256::digest(info).into();
        // Both identities correct -> Ok.
        assert!(check_identity(info, Some(sha1), Some(sha256)).is_ok());
        // The v1 side mismatches -> an explicit error.
        let other1: [u8; 20] = Sha1::digest(b"other").into();
        assert!(check_identity(info, Some(other1), Some(sha256)).is_err());
        // The v2 side mismatches -> an explicit error (the hybrid's
        // other-side gate).
        let other2: [u8; 32] = Sha256::digest(b"other").into();
        assert!(check_identity(info, Some(sha1), Some(other2)).is_err());
    }

    #[test]
    fn chain_synthesizes_aria2_gid_semantics_in_place() {
        let g = gid();
        let chain = MetadataChain {
            metadata_gid: g,
            task_gid: g,
            metadata_uri: "magnet:?xt=urn:btih:aa".into(),
            paused: false,
        };
        // In-place upgrade: followedBy (the magnet view) and following
        // (the upgraded-task view) both point at this GID (the aria2
        // RequestGroup.cc fields, provided as-is).
        assert_eq!(chain.followed_by(), vec![g]);
        assert_eq!(chain.following(), g);
    }

    /// Regression for the upgrade path: the finalize transition edges are
    /// checked one by one against the transition table. The engine
    /// previously tore down straight to Done over an unregistered edge
    /// (Allocating -> Done), and every magnet upgrade logged "illegal
    /// torrent state transition". The current path MetadataPending ->
    /// Allocating -> Downloading -> {Done | Stopping | Error} uses
    /// registered edges only.
    #[test]
    fn upgrade_state_path_uses_registered_edges_only() {
        use TorrentState::*;
        for (from, to) in [
            (Queued, MetadataPending),
            (MetadataPending, Allocating),
            (Allocating, Downloading),
            (Downloading, Done),
            (Downloading, Stopping),
            (Downloading, Error),
            // Early failure branches (engine config rejected / metadata
            // phase failed).
            (Allocating, Error),
            (MetadataPending, Error),
        ] {
            assert!(
                legal_transition(from, to),
                "{from:?} → {to:?} must be a registered edge (SPEC §7.1)"
            );
        }
    }

    #[tokio::test]
    async fn run_fails_fast_on_bad_magnet_uri() {
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: "http://not-a-magnet".into(),
            dest: PathBuf::from("/tmp/taiji-magnet-test"),
            peer_id: [0u8; 20],
            options: MagnetOptions::default(),
            phase: MetadataPhaseConfig::default(),
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Webseeding defaults on for tests (the BEP19 face is not
            // exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            // Existing cases have no ban face (None = no gate, zero
            // behavior change); ban-gate cases inject their own snapshot.
            ip_guard: None,
        };
        let root = CancellationToken::new();
        let end = MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(end, MagnetEnd::Failed(_)), "got {end:?}");
    }

    /// The metadata-phase DhtEngine assembly face — the engine is present
    /// (snapshot answers, the v4 family), the external address hand-down
    /// does not fail, and after the token cancels the engine exits with
    /// the demux close-out (the command channel Closed; the lifecycle
    /// contract in the spawn_phase_dht docs).
    #[tokio::test]
    async fn spawn_phase_dht_brings_up_engine_and_cleans_up() {
        let token = tokio_util::sync::CancellationToken::new();
        let lease = spawn_phase_dht(token.clone(), None)
            .await
            .unwrap_or_else(|| panic!("lease expected"));
        let snap = lease
            .handle
            .snapshot()
            .await
            .unwrap_or_else(|e| panic!("snapshot: {e}"));
        assert_eq!(
            snap.family,
            DhtFamily::V4,
            "metadata phase: v4 single-stack"
        );
        assert_ne!(
            snap.dht_port, 0,
            "demux binds a nonzero port (ephemeral face)"
        );
        // Close-out: token cancel -> the demux exits -> the engine inbound
        // closes -> a saving exit -> the command channel Closed.
        token.cancel();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match lease.handle.snapshot().await {
                Ok(_) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "engine did not exit after token cancel"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(taiji_bt::dht::DhtEngineError::Closed) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn run_fails_fast_when_no_tr_and_no_saved_metadata() {
        // A pure btmh magnet with every discovery source disabled fails
        // immediately instead of waiting without a path to metadata.
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
        dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: "magnet:?xt=urn:btmh:12203da388b8b84c2a5be2af96f9a2de039f258a9ed45bdf1a219b4fcfc9c8a5885f".into(),
            dest: PathBuf::from("/tmp/taiji-magnet-test"),
            peer_id: [0u8; 20],
            options: MagnetOptions::default(),
            phase: MetadataPhaseConfig::default(),
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Webseeding defaults on for tests (the BEP19 face is not
            // exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            // Existing cases have no ban face (None = no gate, zero
            // behavior change); ban-gate cases inject their own snapshot.
            ip_guard: None,
        };
        let root = CancellationToken::new();
        let end = MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let MagnetEnd::Failed(reason) = &end else {
            panic!("expected Failed, got {end:?}");
        };
        assert!(reason.contains("no tr tracker list"), "{reason}");
    }

    // ===== `x.pe` direct discovery source (duplex end to end + defense
    // regressions) =====

    /// A minimal metadata seeder (a duplex peer, all in-process):
    /// handshake (the btih-face identity) -> ext handshake (BEP10:
    /// advertise ut_metadata=2 + metadata_size) -> ut_metadata request
    /// service (`serve_request` answers directly; no piece/bitfield face —
    /// a pure metadata payload has zero pieces so no bitfield is sent,
    /// the same rule as the other seeders). Returns (listen address,
    /// accept count).
    async fn spawn_xpe_metadata_seeder(
        metadata: Arc<Vec<u8>>,
        btih: [u8; 20],
    ) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        spawn_metadata_peer(metadata, btih, true).await
    }

    async fn spawn_metadata_peer(
        metadata: Arc<Vec<u8>>,
        btih: [u8; 20],
        responsive: bool,
    ) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        use taiji_bt::ut_metadata::{ServeOutcome, UtMetadata, serve_request as ut_serve};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                let metadata = Arc::clone(&metadata);
                tokio::spawn(async move {
                    let mut hs = [0u8; 68];
                    if sock.read_exact(&mut hs).await.is_err() {
                        return;
                    }
                    let ih: [u8; 20] = hs[28..48].try_into().unwrap_or_else(|_| panic!("slice"));
                    if ih != btih {
                        return; // joined the wrong swarm
                    }
                    let mut resp = [0u8; 68];
                    resp[0] = 19;
                    resp[1..20].copy_from_slice(b"BitTorrent protocol");
                    resp[25] = 0x10; // extended（BEP10）
                    resp[27] = 0x04; // fast
                    resp[28..48].copy_from_slice(&ih);
                    resp[48..68].copy_from_slice(b"XPESEEDERXPESEEDER00");
                    if sock.write_all(&resp).await.is_err() {
                        return;
                    }
                    // ext handshake (advertise ut_metadata=2 +
                    // metadata_size).
                    let ext = ExtHandshake {
                        m_ut_metadata: Some(2),
                        metadata_size: Some(metadata.len() as u32),
                        ..ExtHandshake::default()
                    };
                    let payload = ext.encode().unwrap_or_else(|e| panic!("{e}"));
                    let mut frame = Vec::with_capacity(5 + payload.len());
                    frame.extend_from_slice(
                        ((1 + 1 + payload.len()) as u32).to_be_bytes().as_slice(),
                    );
                    frame.push(20u8);
                    frame.push(0u8);
                    frame.extend_from_slice(&payload);
                    if sock.write_all(&frame).await.is_err() {
                        return;
                    }
                    loop {
                        let mut len_buf = [0u8; 4];
                        if sock.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = u32::from_be_bytes(len_buf) as usize;
                        if len == 0 {
                            continue; // keep-alive
                        }
                        let mut body = vec![0u8; len];
                        if sock.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        // interested -> unchoke (the same as the other
                        // seeders; the fetch face does not send).
                        if body[0] == 2 {
                            let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                            continue;
                        }
                        // Extended: ext_id 0 = the peer's handshake
                        // (ignored); 2 = a ut_metadata request.
                        if body[0] != 20 || body.len() < 2 || body[1] != 2 {
                            continue;
                        }
                        if !responsive {
                            continue;
                        }
                        let Ok(UtMetadata::Request { index }) = UtMetadata::decode(&body[2..])
                        else {
                            continue;
                        };
                        let reply = match ut_serve(&metadata, index) {
                            Ok(ServeOutcome::Data {
                                index,
                                total_size,
                                data,
                            }) => UtMetadata::Data {
                                index,
                                total_size,
                                data,
                            },
                            Ok(ServeOutcome::Reject { index }) => UtMetadata::Reject { index },
                            Err(_) => return, // out of range -> drop the connection
                        };
                        let payload = reply.encode().unwrap_or_else(|e| panic!("{e}"));
                        let mut frame = Vec::with_capacity(5 + payload.len());
                        frame.extend_from_slice(
                            ((1 + 1 + payload.len()) as u32).to_be_bytes().as_slice(),
                        );
                        frame.push(20u8);
                        frame.push(2u8);
                        frame.extend_from_slice(&payload);
                        if sock.write_all(&frame).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, hits)
    }

    async fn metadata_tracker(peers: Vec<std::net::SocketAddr>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let mut compact = Vec::new();
        for peer in peers {
            let std::net::IpAddr::V4(ip) = peer.ip() else {
                panic!("v4 fixture")
            };
            compact.extend_from_slice(&ip.octets());
            compact.extend_from_slice(&peer.port().to_be_bytes());
        }
        let mut body = format!("d8:intervali3600e5:peers{}:", compact.len()).into_bytes();
        body.extend(compact);
        body.push(b'e');
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while request.len() < 8192
                        && !request.windows(4).any(|window| window == b"\r\n\r\n")
                    {
                        let Ok(n) = socket.read(&mut buffer).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..n]);
                    }
                    // A seed-filtering tracker does not return seeds to clients
                    // claiming to have completed the payload (left=0).
                    let path = String::from_utf8_lossy(&request)
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .to_string();
                    let incomplete = path.split_once('?').is_some_and(|(_, query)| {
                        query.split('&').any(|pair| {
                            pair.split_once('=').is_some_and(|(key, value)| {
                                key == "left" && value.parse::<u64>().is_ok_and(|left| left > 0)
                            })
                        })
                    });
                    let body = if incomplete {
                        body
                    } else {
                        b"d8:intervali3600e5:peers0:e".to_vec()
                    };
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                });
            }
        });
        format!("http://{address}/announce")
    }

    pub(super) fn metadata_fixture_config(btih: [u8; 20], directory: PathBuf) -> MagnetTaskConfig {
        MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: format!("magnet:?xt=urn:btih:{}", hex_lower(&btih)),
            dest: directory,
            peer_id: *b"-TJ0001-METADATAFIX1",
            options: MagnetOptions {
                bt_metadata_only: true,
                bt_save_metadata: true,
                ..Default::default()
            },
            phase: MetadataPhaseConfig {
                metadata_deadline: Some(Duration::from_secs(8)),
                ..Default::default()
            },
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            ip_guard: None,
        }
    }

    #[tokio::test]
    async fn tracker_updates_bypass_pending_dht_and_recreate_metadata_directory() {
        let (_torrent, btih, info) = web_mirror_torrent();
        let (peer, _) = spawn_xpe_metadata_seeder(Arc::new(info.to_vec()), btih).await;
        let tracker = metadata_tracker(vec![peer]).await;
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let directory =
            std::env::temp_dir().join(format!("taiji-metadata-{}", rand::random::<u64>()));
        let root = CancellationToken::new();
        let mut cfg = metadata_fixture_config(btih, directory.clone());
        let (updates, receiver) = tokio::sync::watch::channel(Vec::new());
        cfg.tracker_updates = Some(receiver);
        cfg.dht = spawn_phase_dht(root.child_token(), None).await;
        cfg.dht_entry_points = vec![
            blackhole
                .local_addr()
                .unwrap_or_else(|error| panic!("{error}")),
        ];
        cfg.dht_enabled = true;
        let started = std::time::Instant::now();
        let handle = tokio::spawn({
            let root = root.clone();
            async move { MagnetEngine::spawn(cfg, &root).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        updates.send_replace(vec![(0, tracker)]);
        let end = tokio::time::timeout(Duration::from_secs(8), handle)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(end, MagnetEnd::MetadataFetched { .. }), "{end:?}");
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "DHT must not delay tracker discovery"
        );
        let saved = std::fs::read(directory.join(format!("{}.torrent", hex_lower(&btih))))
            .unwrap_or_else(|error| panic!("{error}"));
        let parsed = Metainfo::parse(&saved).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(parsed.info_bytes.as_ref(), info.as_slice());
        root.cancel();
        std::fs::remove_dir_all(directory).unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn unresponsive_metadata_peer_releases_slot_for_queued_candidate() {
        let (_torrent, btih, info) = web_mirror_torrent();
        let (bad, bad_hits) = spawn_metadata_peer(Arc::new(info.to_vec()), btih, false).await;
        let (good, good_hits) = spawn_xpe_metadata_seeder(Arc::new(info.to_vec()), btih).await;
        let tracker = metadata_tracker(vec![bad, good]).await;
        let directory =
            std::env::temp_dir().join(format!("taiji-metadata-{}", rand::random::<u64>()));
        let mut cfg = metadata_fixture_config(btih, directory.clone());
        let (_updates, receiver) = tokio::sync::watch::channel(vec![(0, tracker)]);
        cfg.tracker_updates = Some(receiver);
        cfg.phase.max_metadata_peers = 1;
        cfg.phase.peer_metadata_timeout = Duration::from_millis(300);
        cfg.phase.discovery_round = Duration::from_secs(30);
        let root = CancellationToken::new();
        let end = MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(end, MagnetEnd::MetadataFetched { .. }), "{end:?}");
        assert_eq!(bad_hits.load(Ordering::Relaxed), 1);
        assert_eq!(good_hits.load(Ordering::Relaxed), 1);
        root.cancel();
        std::fs::remove_dir_all(directory).unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn metadata_save_failure_never_reports_metadata_complete() {
        let (_torrent, btih, info) = web_mirror_torrent();
        let (peer, _) = spawn_xpe_metadata_seeder(Arc::new(info.to_vec()), btih).await;
        let directory =
            std::env::temp_dir().join(format!("taiji-metadata-file-{}", rand::random::<u64>()));
        std::fs::write(&directory, b"not a directory").unwrap_or_else(|error| panic!("{error}"));
        let mut cfg = metadata_fixture_config(btih, directory.clone());
        cfg.magnet_uri.push_str(&format!("&x.pe={peer}"));
        let root = CancellationToken::new();
        let end = MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            matches!(end, MagnetEnd::Failed(ref message) if message.contains("metadata save failed")),
            "{end:?}"
        );
        root.cancel();
        std::fs::remove_file(directory).unwrap_or_else(|error| panic!("{error}"));
    }

    /// The common face: a magnet (tr = an unreachable tracker + an
    /// optional x.pe direct endpoint) runs MagnetEngine to the
    /// bt-metadata-only terminal; DHT/LSD/web all off — x.pe is the only
    /// usable discovery source, so a hit proves the direct injection
    /// works. `listen_port` selects the metadata listener's preferred port;
    /// the transport may bind another port when it is already occupied.
    async fn run_with_xpe(
        btih: [u8; 20],
        xpe: Option<std::net::SocketAddr>,
        listen_port: u16,
        deadline: Duration,
    ) -> MagnetEnd {
        let mut uri = format!(
            "magnet:?xt=urn:btih:{}&tr=http://127.0.0.1:1/ann",
            hex_lower(&btih)
        );
        if let Some(a) = xpe {
            uri.push_str(&format!("&x.pe={a}"));
        }
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: uri,
            dest: PathBuf::from("/tmp/taiji-magnet-xpe-test"),
            peer_id: [0u8; 20],
            options: MagnetOptions {
                bt_metadata_only: true,
                ..MagnetOptions::default()
            },
            phase: MetadataPhaseConfig {
                listen_port,
                discovery_round: Duration::from_millis(100),
                metadata_deadline: Some(deadline),
                ..MetadataPhaseConfig::default()
            },
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Webseeding defaults on for tests (the BEP19 face is not
            // exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            // Existing cases have no ban face (None = no gate, zero
            // behavior change); ban-gate cases inject their own snapshot.
            ip_guard: None,
        };
        let root = CancellationToken::new();
        MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// Duplex end to end: x.pe direct -> handshake -> ut_metadata fetch
    /// (x.pe is the only discovery source: tr unreachable, DHT/LSD/web
    /// off). A successful connection stays in dialed bookkeeping — under
    /// the 100ms rediscovery beat, the x.pe re-issue may produce only one
    /// connection (connected dedup).
    #[tokio::test]
    async fn xpe_direct_peer_fetches_metadata() {
        let (_torrent, btih, info) = web_mirror_torrent();
        let (addr, hits) = spawn_xpe_metadata_seeder(Arc::new(info.to_vec()), btih).await;
        let end = run_with_xpe(btih, Some(addr), 0, Duration::from_secs(15)).await;
        let MagnetEnd::MetadataFetched { metadata, .. } = end else {
            panic!("expected MetadataFetched via x.pe direct peer, got {end:?}")
        };
        assert_eq!(
            metadata.as_ref(),
            info.as_slice(),
            "info section byte-identical (ut_metadata via x.pe)"
        );
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "x.pe round re-issue must be deduped by dialed bookkeeping (single connection)"
        );
    }

    /// The self-connect guard uses the actual bound listener, including
    /// an ephemeral port. A different loopback listener remains a valid peer.
    #[tokio::test]
    async fn xpe_self_connect_is_not_dialed() {
        let (_torrent, btih, _info) = web_mirror_torrent();
        let token = CancellationToken::new();
        let cfg = metadata_fixture_config(btih, PathBuf::from("/tmp/taiji-self-test"));
        let network = network::Network::bind(0, cfg.peer_id, vec![], None, &token)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_ne!(network.dialer.port, 0);
        let faces = vec![MetaFace {
            index: 0,
            info_hash: btih,
            reserved: Reserved::aria2_default(),
            expected: ExpectedInfoHash::V1(btih),
            dht_kind: DhtSwarmKind::V1,
        }];
        let signals = Arc::new(PeerSignals {
            network: network.dialer.clone(),
            candidates: std::sync::Mutex::new(candidates::Candidates::new()),
            metadata: vec![Arc::new(taiji_bt::ut_metadata::MetadataCoordinator::new(
                ExpectedInfoHash::V1(btih),
            ))],
            pex: mpsc::channel(1).0,
            holepunch: mpsc::channel(1).0,
            reports: mpsc::channel(1).0,
            next_id: AtomicU64::new(1),
            introducers: AtomicUsize::new(0),
            max_introducers: 0,
            enabled: false,
        });
        let peers = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));
        let dialed = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let live: LivePeers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (tx, _rx) = mpsc::channel(1);
        let own_address = std::net::SocketAddr::from(([127, 0, 0, 1], network.dialer.port));
        spawn_dial_with_network(
            &cfg,
            &faces,
            0,
            own_address,
            "xpe",
            &peers,
            &dialed,
            &total,
            &live,
            tx.clone(),
            &token,
            Some(signals.clone()),
        );
        assert_eq!(
            total.load(Ordering::Relaxed),
            0,
            "self address must never acquire a dial slot"
        );
        assert!(crate::lock(&dialed).is_empty());

        let other = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let other_address = other.local_addr().unwrap_or_else(|error| panic!("{error}"));
        spawn_dial_with_network(
            &cfg,
            &faces,
            0,
            other_address,
            "xpe",
            &peers,
            &dialed,
            &total,
            &live,
            tx,
            &token,
            Some(signals),
        );
        assert_eq!(
            total.load(Ordering::Relaxed),
            1,
            "another local client remains reachable"
        );
        token.cancel();
    }

    /// Address-hygiene regression: malicious x.pe endpoint shapes (v4
    /// unspecified `0.0.0.0` — the observable form where the kernel loops
    /// the connection back to local; v6 loopback `::1`) — the spawn_dial
    /// hygiene predicate rejects: zero sentinel connections and the
    /// metadata phase fails honestly (no faked completion).
    #[tokio::test]
    async fn xpe_bogon_endpoint_is_not_dialed_p122() {
        let (_torrent, btih, _info) = web_mirror_torrent();
        for target in ["0.0.0.0", "[::1]"] {
            let bind = format!("{target}:0");
            let listener = tokio::net::TcpListener::bind(&bind)
                .await
                .unwrap_or_else(|e| panic!("{target} bind: {e}"));
            let port = listener
                .local_addr()
                .unwrap_or_else(|e| panic!("{e}"))
                .port();
            let hits = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&hits);
            tokio::spawn(async move {
                loop {
                    let Ok((_sock, _)) = listener.accept().await else {
                        break;
                    };
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            });
            let xpe: std::net::SocketAddr = format!("{target}:{port}")
                .parse()
                .unwrap_or_else(|e| panic!("{e}"));
            let end = run_with_xpe(btih, Some(xpe), 0, Duration::from_secs(2)).await;
            let MagnetEnd::Failed(reason) = &end else {
                panic!("{target}: expected honest failure, got {end:?}")
            };
            assert!(reason.contains("deadline"), "{target}: {reason}");
            assert_eq!(
                hits.load(Ordering::Relaxed),
                0,
                "{target} malicious endpoint must be rejected by the hygiene predicate (zero connections)"
            );
        }
    }

    /// Defense regression (unit level, synchronous bookkeeping
    /// assertions): spawn_dial's self-connect check and dialed dedup —
    /// the x.pe source shares the same pipeline and defense chain as the
    /// other sources (zero bypass).
    #[tokio::test]
    async fn spawn_dial_guards_self_connect_and_duplicates() {
        let btih: [u8; 20] = Sha1::digest(b"xpe-guard-test").into();
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: format!("magnet:?xt=urn:btih:{}", hex_lower(&btih)),
            dest: PathBuf::from("/tmp/taiji-magnet-xpe-guard"),
            peer_id: [0u8; 20],
            options: MagnetOptions::default(),
            phase: MetadataPhaseConfig {
                listen_port: 47771,
                ..MetadataPhaseConfig::default()
            },
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Webseeding defaults on for tests (the BEP19 face is not
            // exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            // Existing cases have no ban face (None = no gate, zero
            // behavior change); ban-gate cases inject their own snapshot.
            ip_guard: None,
        };
        let faces = vec![MetaFace {
            index: 0,
            info_hash: btih,
            reserved: Reserved::aria2_default(),
            expected: ExpectedInfoHash::V1(btih),
            dht_kind: DhtSwarmKind::V1,
        }];
        let swarm_peers = Arc::new(AtomicUsize::new(0));
        let dialed: Arc<std::sync::Mutex<HashSet<(usize, std::net::SocketAddr)>>> =
            Arc::new(std::sync::Mutex::new(HashSet::new()));
        let dialed_total = Arc::new(AtomicUsize::new(0));
        let live: LivePeers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (md_tx, _md_rx) = mpsc::channel(16);
        let token = CancellationToken::new();
        let peer: std::net::SocketAddr =
            "10.253.0.1:6881".parse().unwrap_or_else(|e| panic!("{e}"));
        let self_addr: std::net::SocketAddr =
            "127.0.0.1:47771".parse().unwrap_or_else(|e| panic!("{e}"));

        // Self-connect (loopback + the announce port) -> rejected; zero
        // bookkeeping, zero dispatch.
        spawn_dial(
            &cfg,
            &faces,
            0,
            self_addr,
            "xpe",
            &swarm_peers,
            &dialed,
            &dialed_total,
            &live,
            md_tx.clone(),
            &token,
        );
        assert!(
            dialed.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "self address must not enter bookkeeping"
        );
        assert_eq!(
            dialed_total.load(Ordering::Relaxed),
            0,
            "self address must not dispatch a dial"
        );

        // Normal dispatch: into bookkeeping + counted (no await in this
        // test, so the dial task is not polled and the assertions are
        // deterministic).
        spawn_dial(
            &cfg,
            &faces,
            0,
            peer,
            "xpe",
            &swarm_peers,
            &dialed,
            &dialed_total,
            &live,
            md_tx.clone(),
            &token,
        );
        assert!(
            dialed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(0, peer)),
            "dispatch enters bookkeeping"
        );
        assert_eq!(dialed_total.load(Ordering::Relaxed), 1);

        // Dialed dedup: the rediscovery beat's x.pe re-issue -> no second
        // dispatch.
        spawn_dial(
            &cfg,
            &faces,
            0,
            peer,
            "xpe",
            &swarm_peers,
            &dialed,
            &dialed_total,
            &live,
            md_tx.clone(),
            &token,
        );
        assert_eq!(
            dialed_total.load(Ordering::Relaxed),
            1,
            "duplicate address must be rejected by dialed dedup"
        );
        token.cancel();
    }

    // ===== the metadata-phase IpGuard unified gate (four discovery
    // sources = tracker/DHT/LSD/x.pe; the choke point = spawn_dial) =====

    /// Test face: manual ban-range snapshots (same-family v4 closed
    /// ranges; reason/until shaped like the session `banAddr` effect —
    /// the manual section of the assembled refresh output).
    fn manual_ban_guard(ranges: &[([u8; 4], [u8; 4])]) -> IpGuardHandle {
        use taiji_bt::peer_policy::{BanRecord, IpGuard};
        IpGuardHandle::new(
            IpGuard::default().with_manual_bans(ranges.iter().map(|(s, e)| {
                (
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(*s)),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(*e)),
                    BanRecord {
                        reason: "manual".into(),
                        until: i64::MAX,
                    },
                )
            })),
        )
    }

    /// The four-source IpGuard gate, table-driven: a banned address sees
    /// ZERO dials under the tracker/DHT/LSD/x.pe source labels — not into
    /// the dialed bookkeeping, no cap accounting, no connection task
    /// spawned (the unit face of the reverse assertion: metadata-phase
    /// dynamic bans take effect). The control group = an unbanned address
    /// passes the same pipeline (the gate targets dynamic bans, not a
    /// discovery source or an address class).
    #[tokio::test]
    async fn ip_guard_ban_blocks_all_four_discovery_sources() {
        let btih: [u8; 20] = Sha1::digest(b"p125-ban-gate").into();
        let banned: std::net::SocketAddr =
            "10.66.0.7:6881".parse().unwrap_or_else(|e| panic!("{e}"));
        // A two-defense-line separation assertion (hygiene = address
        // classification, the gate = dynamic bans; both must pass): a
        // banned address must first pass hygiene — rejection-class
        // addresses (TEST-NET etc.) never reach this gate; this case
        // proves the second line works independently.
        assert!(
            crate::engine::addr_hygiene::sanitize_discovered_addr(banned).is_some(),
            "banned address must pass hygiene (this case proves the IpGuard gate works independently)"
        );
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: format!("magnet:?xt=urn:btih:{}", hex_lower(&btih)),
            dest: PathBuf::from("/tmp/taiji-magnet-p125-gate"),
            peer_id: [0u8; 20],
            options: MagnetOptions::default(),
            phase: MetadataPhaseConfig {
                listen_port: 47779,
                ..MetadataPhaseConfig::default()
            },
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Webseeding defaults on for tests (the BEP19 face is not
            // exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            ip_guard: Some(manual_ban_guard(&[([10, 66, 0, 0], [10, 66, 0, 255])])),
        };
        let faces = vec![MetaFace {
            index: 0,
            info_hash: btih,
            reserved: Reserved::aria2_default(),
            expected: ExpectedInfoHash::V1(btih),
            dht_kind: DhtSwarmKind::V1,
        }];
        let swarm_peers = Arc::new(AtomicUsize::new(0));
        let dialed: Arc<std::sync::Mutex<HashSet<(usize, std::net::SocketAddr)>>> =
            Arc::new(std::sync::Mutex::new(HashSet::new()));
        let dialed_total = Arc::new(AtomicUsize::new(0));
        let live: LivePeers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (md_tx, _md_rx) = mpsc::channel(16);
        let token = CancellationToken::new();

        // Table-driven: feed the banned address through each of the four
        // discovery sources -> zero dials for each.
        for source in ["tracker", "dht", "lsd", "xpe"] {
            spawn_dial(
                &cfg,
                &faces,
                0,
                banned,
                source,
                &swarm_peers,
                &dialed,
                &dialed_total,
                &live,
                md_tx.clone(),
                &token,
            );
            assert!(
                dialed.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "{source}: ban-hit address must not enter bookkeeping (rejection takes no \
                 admission slot; hot unban recovers)"
            );
            assert_eq!(
                dialed_total.load(Ordering::Relaxed),
                0,
                "{source}: ban hit must not dispatch a dial / consume the max_metadata_peers cap"
            );
        }
        assert_eq!(
            swarm_peers.load(Ordering::Relaxed),
            0,
            "all four sources rejected: zero connections derived from the task"
        );

        // Control group: the unbanned address passes the same pipeline
        // (hygiene passes -> IpGuard passes -> dispatched into
        // bookkeeping).
        let clean: std::net::SocketAddr =
            "10.253.0.9:6881".parse().unwrap_or_else(|e| panic!("{e}"));
        spawn_dial(
            &cfg,
            &faces,
            0,
            clean,
            "tracker",
            &swarm_peers,
            &dialed,
            &dialed_total,
            &live,
            md_tx.clone(),
            &token,
        );
        assert_eq!(
            dialed_total.load(Ordering::Relaxed),
            1,
            "control group must pass (the gate targets dynamic bans, not a discovery source or address class)"
        );
        token.cancel();
    }

    /// Hot-ban effectiveness: after the session side re-stores the
    /// snapshot (an arc-swap swap), the live task's next dial decides on
    /// the new snapshot immediately — new addresses are rejected after
    /// the ban (no bookkeeping) and the same address recovers after an
    /// unban (the natural retry semantics of the rediscovery beat).
    #[tokio::test]
    async fn ip_guard_hot_ban_takes_effect_on_live_task() {
        use taiji_bt::peer_policy::{BanRecord, IpGuard};
        let btih: [u8; 20] = Sha1::digest(b"p125-hot-ban").into();
        let guard = IpGuardHandle::new(IpGuard::default());
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: format!("magnet:?xt=urn:btih:{}", hex_lower(&btih)),
            dest: PathBuf::from("/tmp/taiji-magnet-p125-hot"),
            peer_id: [0u8; 20],
            options: MagnetOptions::default(),
            phase: MetadataPhaseConfig {
                listen_port: 47789,
                ..MetadataPhaseConfig::default()
            },
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Webseeding defaults on for tests (the BEP19 face is not
            // exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            ip_guard: Some(guard.clone()),
        };
        let faces = vec![MetaFace {
            index: 0,
            info_hash: btih,
            reserved: Reserved::aria2_default(),
            expected: ExpectedInfoHash::V1(btih),
            dht_kind: DhtSwarmKind::V1,
        }];
        let swarm_peers = Arc::new(AtomicUsize::new(0));
        let dialed: Arc<std::sync::Mutex<HashSet<(usize, std::net::SocketAddr)>>> =
            Arc::new(std::sync::Mutex::new(HashSet::new()));
        let dialed_total = Arc::new(AtomicUsize::new(0));
        let live: LivePeers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (md_tx, _md_rx) = mpsc::channel(16);
        let token = CancellationToken::new();
        let first: std::net::SocketAddr =
            "10.253.0.1:6881".parse().unwrap_or_else(|e| panic!("{e}"));
        let second: std::net::SocketAddr =
            "10.253.0.2:6881".parse().unwrap_or_else(|e| panic!("{e}"));

        // Baseline: an empty snapshot passes (into bookkeeping + counted).
        spawn_dial(
            &cfg,
            &faces,
            0,
            first,
            "dht",
            &swarm_peers,
            &dialed,
            &dialed_total,
            &live,
            md_tx.clone(),
            &token,
        );
        assert_eq!(dialed_total.load(Ordering::Relaxed), 1);

        // Hot ban: a new snapshot covers 10.253.0.0/24 -> subsequent
        // dials rejected immediately.
        guard.store(IpGuard::default().with_manual_bans([(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 253, 0, 0)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 253, 0, 255)),
            BanRecord {
                reason: "manual".into(),
                until: i64::MAX,
            },
        )]));
        spawn_dial(
            &cfg,
            &faces,
            0,
            second,
            "dht",
            &swarm_peers,
            &dialed,
            &dialed_total,
            &live,
            md_tx.clone(),
            &token,
        );
        assert_eq!(
            dialed_total.load(Ordering::Relaxed),
            1,
            "new address must not dispatch after hot ban"
        );
        assert!(
            !dialed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(0, second)),
            "hot-ban rejection takes no bookkeeping"
        );

        // Hot unban: re-store an empty snapshot -> the same address may
        // dial again next round (the symmetric face of not occupying
        // bookkeeping).
        guard.store(IpGuard::default());
        spawn_dial(
            &cfg,
            &faces,
            0,
            second,
            "dht",
            &swarm_peers,
            &dialed,
            &dialed_total,
            &live,
            md_tx.clone(),
            &token,
        );
        assert_eq!(
            dialed_total.load(Ordering::Relaxed),
            2,
            "after hot unban the same address may dial again"
        );
        token.cancel();
    }

    /// A variant of the common face: the same-shaped cfg with a
    /// session-level IpGuard snapshot injected. run_with_xpe stays as-is
    /// (zero regression change); this variant serves only the ban-gate
    /// end-to-end cases.
    async fn run_with_xpe_guard(
        btih: [u8; 20],
        xpe: Option<std::net::SocketAddr>,
        listen_port: u16,
        deadline: Duration,
        guard: IpGuardHandle,
    ) -> MagnetEnd {
        let mut uri = format!(
            "magnet:?xt=urn:btih:{}&tr=http://127.0.0.1:1/ann",
            hex_lower(&btih)
        );
        if let Some(a) = xpe {
            uri.push_str(&format!("&x.pe={a}"));
        }
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: uri,
            dest: PathBuf::from("/tmp/taiji-magnet-p125-e2e"),
            peer_id: [0u8; 20],
            options: MagnetOptions {
                bt_metadata_only: true,
                ..MagnetOptions::default()
            },
            phase: MetadataPhaseConfig {
                listen_port,
                discovery_round: Duration::from_millis(100),
                metadata_deadline: Some(deadline),
                ..MetadataPhaseConfig::default()
            },
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Webseeding defaults on for tests (the BEP19 face is not
            // exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: None,
            stats: None,
            ip_guard: Some(guard),
        };
        let root = CancellationToken::new();
        MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// The reverse assertion, end to end: a banAddr-shaped snapshot
    /// covering the seeder address -> the x.pe direct injection is
    /// rejected — zero listener connections (before the fix the metadata
    /// phase connected immediately and the ban defense was entirely
    /// absent there), no metadata peers -> the deadline fails honestly
    /// (no faked completion).
    #[tokio::test]
    async fn xpe_banned_endpoint_is_not_dialed_p125() {
        let (_torrent, btih, _info) = web_mirror_torrent();
        let (addr, hits) = spawn_xpe_metadata_seeder(Arc::new(vec![0u8; 0]), btih).await;
        let guard = manual_ban_guard(&[([127, 0, 0, 0], [127, 0, 0, 255])]);
        let end = run_with_xpe_guard(btih, Some(addr), 0, Duration::from_secs(2), guard).await;
        let MagnetEnd::Failed(reason) = &end else {
            panic!("expected honest failure, got {end:?}")
        };
        assert!(reason.contains("deadline"), "{reason}");
        assert_eq!(
            hits.load(Ordering::Relaxed),
            0,
            "banned x.pe endpoint must be rejected by the IpGuard gate (zero connections)"
        );
    }

    /// Control group: the same injection chain with an empty snapshot (no
    /// addresses banned) -> the x.pe direct fetch works (the ban gate is
    /// an incremental precondition on dynamic bans; the four-source
    /// discovery logic is unchanged).
    #[tokio::test]
    async fn xpe_with_clean_guard_still_fetches_metadata() {
        let (_torrent, btih, info) = web_mirror_torrent();
        let (addr, _hits) = spawn_xpe_metadata_seeder(Arc::new(info.to_vec()), btih).await;
        let guard = IpGuardHandle::new(taiji_bt::peer_policy::IpGuard::default());
        let end = run_with_xpe_guard(btih, Some(addr), 0, Duration::from_secs(15), guard).await;
        let MagnetEnd::MetadataFetched { metadata, .. } = end else {
            panic!("expected MetadataFetched with clean guard, got {end:?}")
        };
        assert_eq!(
            metadata.as_ref(),
            info.as_slice(),
            "info section byte-identical (empty snapshot, zero behavior change)"
        );
    }

    /// Bootstrap entry-resolution timeout close-out (the shared-resolver
    /// semantics): a hanging node + normal nodes mixed — the hanging node
    /// is closed out by the injected short bound (the parameterized shape
    /// of the production 30s backstop) and skipped with a debug log;
    /// normal nodes still resolve (a partial failure does not block the
    /// startup chain — it can no longer hang). Stub injected, no real
    /// DNS.
    #[tokio::test]
    async fn bootstrap_entry_resolution_hang_is_bounded_and_partial() {
        use taiji_io::dns::{HostResolver, ResolverFuture, SharedDns, TimeoutResolver};

        /// Mixed stub: the first fallback node hangs, the rest resolve to
        /// a fixed v4.
        struct MixedStub;
        impl HostResolver for MixedStub {
            fn resolve(&self, host: String) -> ResolverFuture {
                if host == taiji_bt::dht::DEFAULT_BOOTSTRAP_NODES[0].0 {
                    return Box::pin(std::future::pending());
                }
                let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
                Box::pin(std::future::ready(Ok(ip)))
            }
        }
        let dns = SharedDns::with_resolver(std::sync::Arc::new(TimeoutResolver::with_timeout(
            std::sync::Arc::new(MixedStub),
            Duration::from_millis(50),
        )));
        let t0 = std::time::Instant::now();
        let out = resolve_entry_points_with(&[], &dns).await;
        let elapsed = t0.elapsed();
        // Normal nodes all resolve (ports synthesized from the entry
        // table); the hanging node is skipped (not blocking).
        assert_eq!(
            out,
            vec![std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                6881
            )],
            "healthy nodes are retained and duplicate addresses are deduplicated"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the hang is bounded by the short timeout (elapsed {elapsed:?})"
        );
    }

    /// Explicit entries skip resolution (the original semantics
    /// preserved): a non-empty explicit list is returned as-is and the
    /// stub count stays zero.
    #[tokio::test]
    async fn bootstrap_entry_explicit_bypasses_resolution() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use taiji_io::dns::{HostResolver, ResolverFuture, SharedDns};

        struct Counting(AtomicUsize);
        impl HostResolver for Counting {
            fn resolve(&self, _host: String) -> ResolverFuture {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::ready(Ok(std::net::IpAddr::V4(
                    std::net::Ipv4Addr::LOCALHOST,
                ))))
            }
        }
        let stub = std::sync::Arc::new(Counting(AtomicUsize::new(0)));
        let dns = SharedDns::with_resolver(stub.clone());
        let explicit = vec![std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            6881,
        )];
        let out = resolve_entry_points_with(&explicit, &dns).await;
        assert_eq!(out, explicit);
        assert_eq!(
            stub.0.load(Ordering::SeqCst),
            0,
            "explicit entries resolve zero times"
        );
    }
}
