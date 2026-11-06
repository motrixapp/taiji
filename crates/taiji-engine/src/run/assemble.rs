//! run assembly stage (extracted): wiring orchestration for the network,
//! storage, DHT, tracker, and ban surfaces, producing [`AssembledEngine`]
//! for the main loop to destructure. The code is a verbatim move of the
//! original run() assembly section (function-level extraction; zero
//! behavior change — channel capacities, spawn order, and log points are
//! all preserved).
//!
//! Covers: assembling and lifecycle-wiring the engine subsystems.
//! Not covered: main-loop event decisions (arms/tick/dial) and the teardown
//! sequence (tail).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use taiji_bt::peer_policy::IpGuardHandle;
use taiji_io::udp_demux::UdpDemuxHandle;
use taiji_store::persist::TorrentProgressRow;

use crate::metrics::{EngineGauges, SessionMetrics};
use taiji_domain::seed::{SeedPolicy, SeedStats};

use super::super::verify_pool::VerifyPoolConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use taiji_bt::choke::{LeecherChoke, SeederChoke};
use taiji_bt::dht::{DhtEvent, DhtFamily};
use taiji_bt::mse;
use taiji_bt::peer::{AvailEvent, HashSource, PieceSource};
use taiji_bt::peer_policy::{FilterRule, Violation};
use taiji_bt::piece_stat::PieceStatMan;
use taiji_bt::tracker::TrackerOptions;
use taiji_bt::tracker::actor::{
    EVENT_CHANNEL_CAPACITY, TrackerActorConfig, TrackerActorEvent, TrackerCommand,
    UDP_INBOUND_CAPACITY, UDP_OUTBOUND_CAPACITY, UdpTransport, spawn_tracker_actor,
};
use taiji_bt::utp::PeerConnectionType;

use taiji_io::udp_demux;
use taiji_io::utp::listener::spawn_utp;
use taiji_io::utp::{UtpConfig, UtpStream};

use taiji_store::layout::Layout;
use taiji_store::torrent_writer::TorrentReader;
use taiji_store::verified::BlockCheck;

use tokio::task::JoinSet;

use crate::ban::{BanBook, SmartBanLedger, VIOLATION_CHANNEL_CAPACITY, client_v_deny_check};
use crate::bitmap::PieceBitmap;
use crate::command::EngineCommand;
use crate::config::{
    DhtWireConfig, EngineConfig, FaceConfig, FaceKind, TrackerWireConfig, WriterFactory,
};
use crate::dht::{
    AttachDhtSlot, DhtColdWiring, DhtFamilyWiring, DhtRuntimeSeam, DialDedup, spawn_dht_announces,
    spawn_dht_family, spawn_dht_inbound_gate, spawn_udp_face,
};
use crate::dispatch::{
    HashFetchEvent, LedgerArrival, RECOVERY_DELIVER_CAPACITY, RecoveryBook, V2DataPlane,
    build_v2_data_plane,
};
use crate::faces::{FaceState, FaceView, PeerRegistration, PexCandidates, SwarmSnapshot, XorShift};
use crate::pipeline::{
    BLOCK_CHANNEL_CAPACITY, BlockMsg, DataFlushState, ExpectedRoots, StoreJob, store_pipeline,
};
use crate::progress::{EngineEnd, Progress, restore_progress_bits};
use crate::redial::RedialReport;
use crate::run::state::{DialCtx, EngineLoop};
use crate::run::{
    LEDGER_CHANNEL_CAPACITY, UTP_ACCEPT_MERGE_CAPACITY, UTP_DIAL_QUEUE_CAPACITY,
    bind_listen_with_fallback, spawn_tcp_accept_merge,
};
use crate::strategy::{RarestFirstStrategy, StreamGeo};
use crate::tracker::{TrackerMirror, TrackerPersistShared, epoch_secs, spawn_tracker_flusher};
use crate::transit::{AttachDht, UtpDial, UtpDialReq};
use crate::upload::PartialFaceSource;
use taiji_domain::hash_fetch::RecoveredPieceLayer;
use taiji_domain::peer_guard::{
    BanLedger, ipfilter_row_to_rule, refresh_guard, variable_bad_peer_timeout,
};
use taiji_domain::progress::ProgressModel;
use taiji_domain::redial::RedialPool;
use taiji_domain::seed::{BtStopTimeoutWatch, SeedCheck, SessionSpeedCalc};
/// [`SeedStats`] adapter over the ratio reading source and the session
/// upload counter (a former run-local struct lifted to module level —
/// private, visibility unchanged).
struct EngineSeedStats {
    completed: Arc<AtomicU64>,
    session_up: Arc<AtomicU64>,
    startup_uploaded: u64,
}
impl SeedStats for EngineSeedStats {
    fn completed_length(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }
    fn session_upload_length(&self) -> u64 {
        self.session_up.load(Ordering::Relaxed)
    }
    fn upload_length_at_startup(&self) -> u64 {
        self.startup_uploaded
    }
}

/// Store-pipeline wiring for face assembly (extracted; gathers the former
/// run assembly locals, passed to [`build_faces`] by shared reference).
struct StoreWiring<'a> {
    dest: &'a PathBuf,
    layout: &'a Layout,
    writer_factory: &'a Option<Arc<dyn WriterFactory>>,
    /// Disk-protection tier (passed straight from the EngineConfig payload;
    /// Copy avoids borrowing).
    disk_policy: taiji_store::disk_policy::DiskPolicy,
    /// Live disk-tier surface: receiver of the policy watch (the engine
    /// command arm sends -> pipelines re-gear live) plus the applied-value
    /// cell (pipelines write, QueryDiskPolicy reads).
    policy_rx: &'a tokio::sync::watch::Receiver<taiji_store::disk_policy::DiskPolicy>,
    live: &'a Arc<taiji_store::disk_policy::LivePolicyCell>,
    /// A non-empty stored bitfield = resume (the store pipeline skips
    /// truncating allocation).
    resume_existing: bool,
    token: &'a CancellationToken,
    metrics: Option<&'a Arc<SessionMetrics>>,
    progress_tx: &'a mpsc::Sender<(usize, Progress)>,
    fetch_tx: &'a mpsc::Sender<(usize, usize, HashFetchEvent)>,
    avail_all_tx: &'a mpsc::Sender<(usize, AvailEvent)>,
}

/// Bitfield restore sources (a build_faces parameter group — the clippy
/// too_many_arguments gate is satisfied by grouping instead of `#[allow]`,
/// the same shape as StoreWiring/TrackerWiring): the persist row (the
/// session surface's authority) wins; with no row (a bare run, no session
/// store) the code falls back to `EngineConfig.preset_progress`. Restore
/// semantics at the build_faces bitfield-restore point.
struct RestoreSource<'a> {
    startup: &'a Option<TorrentProgressRow>,
    preset: &'a Option<crate::config::PresetProgress>,
}

/// Tracker-actor wiring for face assembly (extracted; grouped like the
/// above).
struct TrackerWiring<'a> {
    persist_shared: &'a Option<TrackerPersistShared>,
    /// Flat iteration order = the actor's tier_groups order (tiers ascending
    /// stable, registration order within a tier).
    tracker_flat: &'a [(usize, String)],
    tiers: &'a [(usize, String)],
    /// Scrape batch = every identifier of this torrent (same-host batching).
    all_info_hashes: &'a [[u8; 20]],
    /// Announce report port = the NAT external-port snapshot (effective:
    /// TCP mapping preferred); with no mapping / NAT unpowered =
    /// actual_port (the standing convention, zero behavior change). The
    /// actor `listen_port` is a spawn-time constant (a frozen seam) —
    /// external port changes after spawn are not followed (dynamic
    /// re-porting needs a bt seam extension; the blocking note lives in the
    /// `taiji_domain::nat` module docs; libtorrent re-reads
    /// `tcp_external_port` per announce, `session_impl.cpp`).
    announce_port: u16,
    peer_id: [u8; 20],
    /// Announce crypto parameter bit (wired via `mse::announce_crypto_param`).
    require_crypto: bool,
    /// BEP7: the local global-scope v6 (the announce `ipv6=` payload;
    /// None = omit).
    local_ipv6: Option<std::net::Ipv6Addr>,
    /// BEP27 private flag (projected unchanged from EngineConfig.private):
    /// true -> the actor's announce scheduling falls back to serial
    /// single-flight (the third face of the DHT/PEX gates — a private
    /// torrent's whole discovery surface closes under BEP27).
    private: bool,
    /// Announce client options (`--bt-tracker-interval` /
    /// `--bt-tracker-timeout` / `--bt-tracker-connect-timeout` wiring;
    /// projected unchanged from `EngineConfig.tracker_options` —
    /// `local_ipv6` is still overridden per face). Defaults = aria2-
    /// identical values, zero behavior difference.
    tracker_options: TrackerOptions,
}

/// [`build_faces`] output: face states + per-surface aggregate senders +
/// tracker UDP carrier outbound/inbound channels (handed to the DHT/µTP
/// assembly stage and the router tasks) + actor command handles.
struct FaceBuildOut {
    faces: Vec<FaceState>,
    avail_tx_face: Vec<mpsc::Sender<AvailEvent>>,
    udp_carrier_out_rxs: Vec<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    actor_in_txs: Vec<mpsc::Sender<(SocketAddr, Vec<u8>)>>,
    actor_cmds: Vec<Option<mpsc::Sender<TrackerCommand>>>,
    /// Per-face recovery books (same order as faces; EngineLoop.recovery).
    recovery_books: Vec<RecoveryBook>,
    /// Per-face gated-upgrade carriers (same order as faces; None = v1 face
    /// / no base; EngineLoop.recovery_upgrade).
    recovery_upgrades: Vec<Option<super::recovery_admit::RecoveryUpgrade>>,
}

/// Engine assembly output: field names = the original run local names, so
/// after run() destructures it the main-loop code keeps the same names and
/// meanings as before the extraction (the structural carrier of zero
/// behavior change).
pub(super) struct AssembledEngine {
    /// TCP v4/v6 accept merge channel (None = degraded to outbound-only).
    pub(super) tcp_inbound: Option<mpsc::Receiver<(tokio::net::TcpStream, SocketAddr)>>,
    /// Unified announce/UDP port (OS-assigned when listen_port=0).
    pub(super) actual_port: u16,
    pub(super) cmd_rx: Option<mpsc::Receiver<EngineCommand>>,
    pub(super) progress_rx: mpsc::Receiver<(usize, Progress)>,
    /// Block-arrival event receiver (the main-loop arrival arm; an
    /// engine-level single channel).
    pub(super) ledger_rx: mpsc::Receiver<LedgerArrival>,
    pub(super) fetch_rx: mpsc::Receiver<(usize, usize, HashFetchEvent)>,
    pub(super) avail_rx: mpsc::Receiver<(usize, AvailEvent)>,
    pub(super) tracker_ev_rx: mpsc::Receiver<(usize, TrackerActorEvent)>,
    pub(super) violation_rx: mpsc::Receiver<Violation>,
    pub(super) dht_ev_rx: mpsc::Receiver<(DhtFamily, DhtEvent)>,
    pub(super) pex_rx: mpsc::Receiver<taiji_bt::peer::PexEvent>,
    /// ut_pex advertise/consume gate (!private AND peer_exchange).
    pub(super) pex_enabled: bool,
    /// ut_holepunch events (PeerTask -> main loop).
    pub(super) hp_rx: mpsc::Receiver<taiji_bt::peer::HolepunchEvent>,
    /// Dial-outcome reports (peer_connect -> main loop).
    pub(super) hp_report_rx: mpsc::Receiver<super::holepunch::HpDialReport>,
    /// µTP accept merge channel (an Option: with no UDP face the main-loop
    /// arm parks forever).
    pub(super) utp_inbound: Option<mpsc::Receiver<(SocketAddr, UtpStream)>>,
    pub(super) dht_port_rx: mpsc::Receiver<(u64, u16)>,
    pub(super) reg_rx: mpsc::Receiver<PeerRegistration>,
    pub(super) leave_rx: mpsc::Receiver<(usize, u64, crate::LeaveKind)>,
    pub(super) redial_rx: mpsc::Receiver<RedialReport>,
    /// Redial scan tick (2s).
    pub(super) redial_ticker: tokio::time::Interval,
    /// Discovery-candidate drain tick (250ms — `run::ecology::DRAIN_TICK`).
    pub(super) ecology_ticker: tokio::time::Interval,
    /// 2s main tick.
    pub(super) ticker: tokio::time::Interval,
    /// Seeding-operations tick (1s).
    pub(super) seed_ticker: tokio::time::Interval,
    /// Choke-round tick.
    pub(super) choke_ticker: tokio::time::Interval,
    /// Dispatch-debt settle tick (2ms; see
    /// `dispatch::DISPATCH_DEBT_INTERVAL`).
    pub(super) debt_ticker: tokio::time::Interval,
    /// Session up/down counters (torrent-level; injected per connection into
    /// PeerConfig).
    pub(super) session_up: Arc<AtomicU64>,
    pub(super) session_down: Arc<AtomicU64>,
    /// Metrics feed point (None = no feed).
    pub(super) session_metrics: Option<Arc<SessionMetrics>>,
    /// Engine gauge slot (dropped on engine exit -> the renderer-side totals
    /// fall back automatically).
    pub(super) gauge_slot: Option<Arc<EngineGauges>>,
    /// Hook trigger surface (the engine side only consumes the bt-complete
    /// trigger).
    pub(super) hook: Option<Arc<taiji_domain::hook::HookRunner>>,
    /// NAT consumer surface (None = none).
    pub(super) nat: Option<taiji_domain::nat::NatEngine>,
    /// Seeding-operations policy.
    pub(super) seed: SeedPolicy,
    pub(super) seed_after_complete: bool,
    pub(super) layout: Layout,
    pub(super) dest: PathBuf,
    pub(super) piece_len: u32,
    /// DHT announce re-send cadence (compared on the 2s tick; consolidation:
    /// the main loop consumes only this field).
    pub(super) dht_announce_interval: Duration,
    /// Wiring with one DhtEngine per family (the µTP stats sampling shares
    /// its source).
    pub(super) dht_wiring: Vec<DhtFamilyWiring>,
    /// Runtime DHT seam (cold wiring + channel spares + config; consumed by
    /// the `EngineCommand::SetDhtEnabled` arm).
    pub(super) dht_seam: DhtRuntimeSeam,
    /// Command handles, one TrackerActor per face (None = spawn failed).
    pub(super) actor_cmds: Vec<Option<mpsc::Sender<TrackerCommand>>>,
    pub(super) startup_uploaded: u64,
    pub(super) startup_downloaded: u64,
    pub(super) startup_active_s: u64,
    pub(super) startup_seed_s: u64,
    /// Shared wiring for new-connection spawns (see state::DialCtx).
    pub(super) dial: DialCtx,
    /// Cross-arm mutable main-loop state (see state::EngineLoop).
    pub(super) state: EngineLoop,
    /// Recovery delivery seam receiver (the main-loop event-channel
    /// convention: like progress_rx and the rest it is a run() local
    /// binding, borrowed by a dedicated select! arm; the consumer is
    /// recovery_admit::consume_recovered_layer).
    pub(super) recovery_deliver_rx: mpsc::Receiver<RecoveredPieceLayer>,
    /// BEP19 webseed set (passed through from EngineConfig; consumed before
    /// run() starts by `dial::attach_webseeds` — the pseudo-peer assembly
    /// surface).
    pub(super) webseeds: Vec<String>,
}

/// Engine assembly (extracted): a verbatim move of the original run
/// assembly section, ending by gathering the cross-stage shared locals into
/// [`AssembledEngine`]. Empty faces = assembly failure (the original
/// `return EngineEnd::Failed` semantics -> `Err`).
pub(super) async fn assemble_engine(
    cfg: EngineConfig,
    tracker: TrackerWireConfig,
    token: &CancellationToken,
    cmd_rx: Option<mpsc::Receiver<EngineCommand>>,
    conn_type: PeerConnectionType,
) -> Result<AssembledEngine, EngineEnd> {
    let EngineConfig {
        peer_id,
        announce,
        listen_port,
        piece_len,
        layout,
        dest,
        seed_after_complete,
        seed,
        writer_factory,
        disk_policy,
        mut faces,
        crypto,
        dht: dht_cfg,
        private,
        peer_exchange,
        metadata_serve,
        limiter,
        hook,
        nat,
        stats: session_metrics,
        // BEP19 webseed set: leaves with the assembly output
        // (AssembledEngine.webseeds) — pseudo-peers are wired via
        // `dial::attach_webseeds` before the run() main loop starts (the
        // engine surface; switch semantics are closed by clear() in the
        // assembly/activation chain, and the assembly-side fallback is
        // BH_WEBSEED).
        webseeds,
        // Preset progress bitfield (the --check-integrity bare-run recheck
        // surface): consumed at the build_faces bitfield-restore source (the
        // persist row first; applies when there is no row).
        preset_progress,
        // Tracker announce client options (interval + two timeouts):
        // consumed at build_faces' per-face TrackerActorConfig.options (the
        // EngineConfig defaults = aria2-identical values, zero behavior
        // difference; the CLI/session chain overwrites before spawn).
        tracker_options,
    } = cfg;
    // Engine gauge slot (connections / choke / DHT nodes / hash queue
    // depth); dropped on engine exit -> the renderer-side totals fall back
    // automatically.
    let gauge_slot: Option<Arc<EngineGauges>> =
        session_metrics.as_ref().map(|m| m.register_engine());
    if faces.is_empty() {
        return Err(EngineEnd::Failed("engine config has no swarm face".into()));
    }
    // BEP27: DHT is disabled engine-wide for private torrents (also
    // enforced at the DhtTarget type level).
    let dht_enabled = dht_cfg.enabled && !private;
    if dht_cfg.enabled && private {
        info!(target: "taiji::core::engine",
            "private torrent: DHT disabled (BEP27)");
    }
    // ut_pex gate (the port of aria2 `PeerInteractionCommand.cc`:
    // `(metadataGetMode || !privateTorrent) && enable-peer-exchange` — the
    // engine surface is never in metadata mode, so this is !private AND
    // peer_exchange). Private torrents neither advertise nor consume PEX
    // (BEP27 forbids it, preventing swarm leaks).
    let pex_context = if private {
        taiji_bt::pex::PexContext::Private
    } else if peer_exchange {
        taiji_bt::pex::PexContext::PublicEnabled
    } else {
        taiji_bt::pex::PexContext::PublicDisabled
    };
    let pex_enabled = taiji_bt::pex::pex_offered(taiji_bt::pex::GetMode::Torrent, pex_context);
    if private {
        info!(target: "taiji::core::engine",
            "private torrent: peer exchange disabled (BEP27)");
    }

    // ---- Network surface: TCP listen (both swarms share) + UDP demux
    // (both families) ----
    // TCP binds first -> actual_port is the unified announce/UDP port (when
    // listen_port=0 the OS assigns it and UDP binds the same port — the
    // announce `port` semantics = the BT connection port). Listen failure =
    // degrade to outbound-only (existing semantics, not a fatal exit).
    // Port-by-port attempts: when listen_port != 0 a failed bind is not an
    // immediate give-up; the retries ascend through the listen_port..=+118
    // window (119 ports = the width of aria2's default `--listen-port
    // 6881-6999` range; upstream: `BtSetup.cc` walks the range port by port
    // and `PeerListenCommand.cc` moves on to the next port after a failure —
    // aria2 tries randomly and shares one global listener, while this side
    // uses a per-task listener with deterministic ascending attempts; the
    // convergence rule matches: the first bindable port wins). 0 = a single
    // OS ephemeral port (the existing test surface semantics unchanged).
    let listener = bind_listen_with_fallback(listen_port, token).await;
    let actual_port = listener.as_ref().map(|(_, p)| *p).unwrap_or(listen_port);
    let udp_face = spawn_udp_face(actual_port, token).await;

    // ---- NAT surface (port mapping) ----
    // Once the listen port is known, trigger Map (TCP+UDP; the NatActor
    // renews every 60min and backs off on failure). A mapping failure does
    // not block downloading (external reachability degrades — the same tier
    // as a listen failure degrading to outbound-only); the actual external
    // port syncs the announce value via the watch (the main-loop 2s tick,
    // see last_nat_announced_port).
    if let Some(nat_engine) = &nat {
        if let Err(e) = nat_engine.map_listen_port(actual_port).await {
            warn!(target: "taiji::core::engine", %e,
                "nat map failed (announce keeps local port, actor keeps retrying)");
        }
    }

    // DHT bit (BEP5 reserved[7]&0x01): declared in outbound/inbound
    // handshakes when enabled (peers use it to decide whether to send us
    // PORT).
    if dht_enabled {
        for f in &mut faces {
            f.reserved = f.reserved.with_dht();
        }
    }

    // BEP7 `ipv6=`: probe the local global-scope IPv6 (the announce request
    // parameter payload). Carried only when a global v6 exists; the probe is
    // bt::dht::security::probe_source_ip (v4 = a UDP connect route-source
    // query, no packet sent; v6 = a TCP connect probe — under mixed ULA+GUA
    // addressing UDP source selection can pick the ULA while TCP matches the
    // real outbound path). Failure / no global address = None = omitted.
    let local_ipv6 = taiji_bt::dht::security::probe_source_ip(true)
        .await
        .and_then(|ip| match ip {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        });

    // BEP10 extension surface (+ ut_pex): send the ext handshake when
    // holding metadata or when peer exchange is enabled (the former attaches
    // the serving surface, the latter advertises ut_pex); with neither, no
    // empty ext handshake is sent (preserving existing wire behavior, not
    // disturbing existing peers). Peers discovered via inbound ut_pex return
    // to the main loop over a bounded channel feeding connection management
    // (capacity 16: ut_pex is low frequency, one frame per peer every
    // >=60s; the PeerTask side drops when full, and duplicate discoveries
    // are covered by dial dedup).
    let (pex_tx, pex_rx) = mpsc::channel::<taiji_bt::peer::PexEvent>(16);
    let pex_tx = if pex_enabled { Some(pex_tx) } else { None };
    let ext = taiji_bt::peer::ExtConfig {
        enabled: metadata_serve.is_some() || pex_tx.is_some(),
        metadata: metadata_serve,
        fetch: None,
        pex: pex_tx.map(|tx| taiji_bt::peer::PexExt {
            tx,
            interval: taiji_bt::pex::DEFAULT_INTERVAL,
        }),
    };

    // ---- Seeding-operations state ----
    // Session up/down counters (torrent-level, injected per connection into
    // PeerConfig; the piece-payload convention is documented at the bt::peer
    // counting points — cross-checked with BtPieceMessage.cc).
    let session_up = Arc::new(AtomicU64::new(0));
    let session_down = Arc::new(AtomicU64::new(0));
    // Cross-session base reading (at task registration; the port of
    // `DefaultBtProgressInfoFile.cc`: the control-file/progress-row
    // uploaded_total becomes this session's uploadLengthAtStartup). No row
    // (the first task) -> all zeros. Read via the LoadTorrentProgress job
    // (the single write connection is serialized; no second connection).
    let startup = match &tracker.persist {
        Some((gid, handle)) => handle.load_torrent_progress(gid).await,
        None => Ok(None),
    };
    let startup = match startup {
        Ok(row) => row,
        Err(e) => {
            warn!(target: "taiji::core::engine", %e, "progress base load failed (fresh start)");
            None
        }
    };
    let startup_uploaded = startup.as_ref().map(|r| r.uploaded_total).unwrap_or(0) as u64;
    let startup_downloaded = startup.as_ref().map(|r| r.downloaded_total).unwrap_or(0) as u64;
    let startup_active_s = startup.as_ref().map(|r| r.active_time_s).unwrap_or(0) as u64;
    let startup_seed_s = startup.as_ref().map(|r| r.seed_time_s).unwrap_or(0) as u64;
    if startup.is_some() {
        info!(target: "taiji::core::engine",
            uploaded_at_startup = startup_uploaded,
            downloaded_at_startup = startup_downloaded,
            active_time_s = startup_active_s, seed_time_s = startup_seed_s,
            "progress base restored from previous session");
    }
    // A non-empty stored bitfield = confirmed pieces already present ->
    // resume mode (the store pipeline skips truncating allocation so a
    // restore cannot wipe the disk; rationale in the StoreJob::allocate
    // docs).
    let resume_existing = startup.as_ref().is_some_and(|r| {
        r.v1_bitfield
            .as_ref()
            .is_some_and(|b| b.iter().any(|&x| x != 0))
            || r.v2_file_bits
                .as_ref()
                .is_some_and(|b| b.iter().any(|&x| x != 0))
    });
    // Ratio reading source: completed = face 0's synthesized length
    // (refreshed by tick; hybrid face 0 = the v1 layout view including pad,
    // matching aria2's v1 handling of hybrid torrents).
    let stats_completed = Arc::new(AtomicU64::new(0));
    let seed_stats = Arc::new(EngineSeedStats {
        completed: stats_completed.clone(),
        session_up: session_up.clone(),
        startup_uploaded,
    });
    // SeedCheck (assembly ported from `BtSetup.cc`): an empty Union = seed
    // forever.
    let seed_check = SeedCheck::build(seed.seed_time, seed.seed_ratio, seed_stats.clone());
    // bt-stop-timeout (`BtSetup.cc`: mounted only when > 0) + a 10s
    // sliding-window rate.
    let stop_watch = BtStopTimeoutWatch::new(seed.stop_timeout);
    let speed_calc = SessionSpeedCalc::default();
    let last_down_sample = 0u64;
    // Session time totals (active = engine online; seed = after download
    // completion; this port's convention).
    let active_secs: u64 = 0;
    let seed_secs: u64 = 0;

    // One store pipeline per face (shape-wise; the two hybrid faces write
    // the same bytes of the same files — each verifies and writes its own,
    // and TorrentWriter guarantees pads never reach disk).
    let (progress_tx, progress_rx) = mpsc::channel::<(usize, Progress)>(16 * faces.len());
    // Block-arrival events: the transit forwarding task -> the main-loop
    // arrival arm (bounded, an engine-level single channel; capacity = 4x
    // BLOCK_CHANNEL_CAPACITY — arrival events accompany block data from the
    // same source, and the 4x depth keeps a normal supply stream
    // degradation-free; when full, try_send drops the event = a graceful
    // degrade that keeps InFlight, never blocks the forwarding task, and the
    // main loop reconverges by re-dispatching as it does today).
    let (ledger_tx, ledger_rx) = mpsc::channel::<LedgerArrival>(LEDGER_CHANNEL_CAPACITY);
    // Lazy-fetch events: watcher -> main loop (bounded; full = backpressure
    // on the watcher).
    let (fetch_tx, fetch_rx) = mpsc::channel::<(usize, usize, HashFetchEvent)>(16 * faces.len());
    let mut stat_rng = XorShift(0x853C49E6748FEA9Bu64);
    // Shuffle source for choke rounds (the leecher optimistic slot; an
    // independent XorShift state).
    let choke_rng = XorShift(0x9E3779B97F4A7C15u64);
    // Availability events: a raw channel per face + an aggregating forward
    // task (a single main-loop receiver).
    let (avail_all_tx, avail_rx) = mpsc::channel::<(usize, AvailEvent)>(64 * faces.len());

    // Tracker wiring: one TrackerActor per swarm face.
    // tiers default = EngineConfig::announce as a single tier 0 (face); URL
    // dedup keeps first-seen — events carry no tier (a frozen protocol
    // surface) and the mirror locates rows by url, so duplicate URLs would
    // distort attribution (actor-side semantics equivalent: same URL, same
    // response).
    // An empty announce string = no tracker (pure-DHT tasks admitted through
    // the ingestion gate with DHT enabled) — no empty-URL tier is recorded
    // (a tracker actor with empty tiers idles with zero slots; DHT discovery
    // is unaffected).
    let mut tiers = tracker.tiers;
    if tiers.is_empty() && !announce.is_empty() {
        tiers.push((0, announce));
    }
    {
        let mut seen = std::collections::HashSet::new();
        tiers.retain(|(_, u)| seen.insert(u.clone()));
    }
    // Flat iteration order = the actor's tier_groups order (tiers ascending
    // stable, registration order within a tier).
    let tracker_flat: Vec<(usize, String)> = {
        let mut flat = tiers.clone();
        flat.sort_by_key(|(tier, _)| *tier);
        flat
    };
    let all_info_hashes: Vec<[u8; 20]> = faces.iter().map(|f| f.info_hash).collect();
    // Tracker announce report port = the NAT external-port snapshot
    // (effective: TCP mapping preferred); no mapping / NAT unpowered ->
    // actual_port (the standing behavior, zero change). Read timing: the NAT
    // mapping round was already awaited above (the assemble NAT stage), and
    // mapping events land via the watch pump at the await points in between
    // (the v6 probe / progress baseline read-back) — the initial announce
    // already carries the external port. Afterwards, following
    // gateway-reassigned port changes: DHT = the existing 2s tick linkage;
    // the tracker actor does not follow because listen_port is a constant
    // (a bt seam limitation, see the TrackerWiring::announce_port note).
    let announce_port = taiji_domain::nat::resolve_announce_port(
        nat.as_ref().map(|e| e.external_ports()),
        actual_port,
    );
    // Cross-check (no surface changes here): the tracker announce report
    // port is the actor's single `listen_port` constant (a frozen seam; the
    // bt/tracker surfaces are untouched by this module) — the single-value
    // form matches libtorrent (the tracker request port =
    // `m_ses.listen_port()`, one value, src/torrent.cpp, the same for v4/v6
    // carriers). Per-family ports live in the engine's own DHT announce
    // surface ([`super::super::dht::family_announce_port`]: a v6 face always
    // reports actual_port, only v4 consumes the external-port snapshot).
    // The v6 bind-V6ONLY point (io demux) and the v6 UDP tracker carrier
    // (bt::tracker) are untouched.
    // Actor event aggregation (a face-index tag, the same shape as
    // availability events; bounded 16 x face count).
    let (tracker_ev_tx, tracker_ev_rx) =
        mpsc::channel::<(usize, TrackerActorEvent)>(EVENT_CHANNEL_CAPACITY * faces.len());
    let persist_shared = tracker.persist.map(|(gid, handle)| TrackerPersistShared {
        gid,
        handle,
        dirty: Arc::new(Mutex::new(Vec::new())),
        notify: Arc::new(tokio::sync::Notify::new()),
    });
    let tracker_flusher = persist_shared.clone().map(spawn_tracker_flusher);

    // ---- Peer ban bookkeeping + IpGuard filtering ----
    // Shared IpGuard snapshot: injected externally (the session import /
    // hot-reload surface) or built by the engine (auto-ban filtering still
    // applies).
    let guard = tracker.guard.clone().unwrap_or_default();
    // Startup restore: active unexpired bans (the peer_ban table) + ipfilter
    // static rules rebuild the snapshot — bans and filtering are effective
    // immediately after a restart.
    let ban_book = build_ban_book(guard, persist_shared.as_ref(), session_metrics.as_ref()).await;
    // Violation event aggregation (Violation mpsc(64) -> core bookkeeping).
    let (violation_tx, violation_rx) = mpsc::channel::<Violation>(VIOLATION_CHANNEL_CAPACITY);

    // Live disk-tier surface: the disk-policy watch (a single-value bounded
    // channel — new values overwrite old; the engine command arm -> the
    // store pipelines) + the applied-value cell (written after the pipelines
    // re-gear; the QueryDiskPolicy reply source). Initial value = the
    // EngineConfig construction-time policy.
    let (disk_policy_tx, disk_policy_rx) =
        tokio::sync::watch::channel::<taiji_store::disk_policy::DiskPolicy>(disk_policy);
    let disk_live = Arc::new(taiji_store::disk_policy::LivePolicyCell::new(disk_policy));

    // Tracker UDP carrier migration surface: the actors' outbound packet
    // streams (face routers route by family to the demux shared socket) and
    // the inbound fan-out targets (the demux tracker-channel dispatcher).
    let built = build_faces(
        faces,
        piece_len,
        &RestoreSource {
            startup: &startup,
            preset: &preset_progress,
        },
        &StoreWiring {
            dest: &dest,
            layout: &layout,
            writer_factory: &writer_factory,
            disk_policy,
            // Live disk-tier surface: policy watch + applied reading (the
            // construction-time initial = the EngineConfig policy; re-geared
            // at runtime via SetDiskPolicy).
            policy_rx: &disk_policy_rx,
            live: &disk_live,
            resume_existing,
            token,
            metrics: session_metrics.as_ref(),
            progress_tx: &progress_tx,
            fetch_tx: &fetch_tx,
            avail_all_tx: &avail_all_tx,
        },
        &TrackerWiring {
            persist_shared: &persist_shared,
            tracker_flat: &tracker_flat,
            tiers: &tiers,
            all_info_hashes: &all_info_hashes,
            announce_port,
            peer_id,
            require_crypto: crypto.require_crypto,
            local_ipv6,
            // BEP27 single-flight gate wiring: private is projected through
            // the engine assembly onto each face's actor (serial
            // single-flight announces).
            private,
            // Announce client options projection (interval + two timeouts).
            tracker_options,
        },
        tracker_ev_tx.clone(),
        &mut stat_rng,
    )
    .await;
    let FaceBuildOut {
        faces,
        avail_tx_face,
        udp_carrier_out_rxs,
        actor_in_txs,
        actor_cmds,
        recovery_books,
        recovery_upgrades,
    } = built;
    drop(progress_tx);
    // Recovery delivery seam (bounded; the consumer is the admission
    // side, hooked up below).
    let (recovery_deliver, recovery_deliver_rx) =
        mpsc::channel::<RecoveredPieceLayer>(RECOVERY_DELIVER_CAPACITY);

    // The listener was already bound in the network stage (moved up so
    // actual_port can bind the UDP demux to the same port); here it is
    // unpacked and the v4/v6 accept merge tasks start (the same shape as the
    // µTP merge channel — a single main-loop arm consumes it).
    let tcp_inbound = listener.map(|(dual, _)| spawn_tcp_accept_merge(dual, token.clone()));

    // ---- Tracker UDP carrier migration: the demux shared socket replaces
    // udp_carrier ----
    // Outbound: one router task per face routes by destination address
    // family to the matching demux instance (the single-writer discipline is
    // enforced by the demux outbound channel). Inbound: one dispatcher per
    // family fans the demux tracker channel out to every actor (each actor's
    // transaction table self-filters by transaction_id — the reply shape
    // when several faces share one socket; a full channel = await
    // backpressure, and the actor's 256-capacity inbound absorbs bursts).
    for mut rx in udp_carrier_out_rxs {
        let v4 = udp_face
            .iter()
            .find(|(f, _, _)| *f == DhtFamily::V4)
            .map(|(_, _, h)| h.clone());
        let v6 = udp_face
            .iter()
            .find(|(f, _, _)| *f == DhtFamily::V6)
            .map(|(_, _, h)| h.clone());
        if v4.is_none() && v6.is_none() {
            break; // no UDP face: no task (the receiver closes with its channel
            // peers at teardown).
        }
        tokio::spawn(async move {
            while let Some((addr, frame)) = rx.recv().await {
                let handle = if addr.is_ipv4() {
                    v4.as_ref()
                } else {
                    v6.as_ref()
                };
                match handle {
                    Some(h) => {
                        let _ = h.send_packet(addr, frame.into()).await;
                    }
                    None => {
                        debug!(target: "taiji::core::engine", %addr,
                            "udp tracker packet dropped: family face unavailable")
                    }
                }
            }
        });
    }

    // ---- DHT assembly ----
    // One DhtEngine per family: inbound = the demux dht channel; outbound is
    // bridged back to the shared socket via forward_outbound (the demux
    // single-writer discipline). Restored state = the dht_state row (first
    // session / decode failure -> from zero, DHTSetup.cc).
    //
    // The µTP branch (topology completion) is wired in the same loop — the
    // demux utp channel -> the `io::utp` listener (stack: table dispatch +
    // accept-on-SYN), outbound packets pumped back to the demux single-write
    // entry by spawn_utp. The accept surface merges v4/v6 into one channel
    // for the main loop (the engine holds a sender clone: while the arm is
    // idle, recv stays Pending rather than None, preventing a spinning
    // select); the dial side dials through a per-family service task (the
    // handle is exclusive: accept consumption and the connection registry
    // share one listener instance whose &mut cannot be split). Tasks share
    // the demux/listener token lifetime; the µTP surface does not depend on
    // the DHT switch (the tracker UDP surface is likewise always present).
    let (utp_inbound_tx, utp_inbound_rx) =
        mpsc::channel::<(SocketAddr, UtpStream)>(UTP_ACCEPT_MERGE_CAPACITY);
    // Option form: with no UDP face (both demux family binds failed) the
    // main-loop accept arm parks forever (pending(), the same convention as
    // an absent TCP listener).
    let utp_inbound = Some(utp_inbound_rx);
    // DHT event aggregation (per-family event channels -> one main-loop
    // receiver; tag = family). When disabled, no sender exists: the
    // main-loop arm parks forever via pending().
    let (dht_ev_tx, dht_ev_rx) = mpsc::channel::<(DhtFamily, DhtEvent)>(EVENT_CHANNEL_CAPACITY * 2);
    let (dht_port_tx, dht_port_rx) = mpsc::channel::<(u64, u16)>(64);
    let (dht_wiring, utp_dial, dht_cold) = wire_dht_and_utp(
        udp_face,
        &actor_in_txs,
        dht_enabled,
        &dht_cfg,
        persist_shared.as_ref(),
        token,
        crypto,
        utp_inbound_tx,
        &dht_ev_tx,
    )
    .await;
    // Attach-stage DHT parameters: the PORT payload = the local DHT UDP
    // port (TCP/UDP share the port; inbound PORT returns to the main loop
    // via the same dht_port_tx).
    // Verification note (not this module's convention; recorded as-is):
    // libtorrent's DHT PORT message advertises the UDP external port
    // (`bt_peer_connection.cpp` via `external_udp_port`), a different
    // protocol surface from the tracker announce's TCP external port
    // (`session_impl.cpp` `tcp_external_port`). The effective convention
    // here is the TCP-first BT data port; copying it blindly would advertise
    // DHT a wrong port whenever the two protocol externals disagree. This
    // engine maps both TCP+UDP and typical gateways agree on all
    // three ports, so the local convention is the correct value; advertising
    // the UDP external port awaits a DHT-surface seam (the DHT PORT message
    // is outside this module — a separate decision).
    // The attach slot form (swapped at runtime enable/disable; prefilled in
    // the initial enabled shape).
    let attach_dht = {
        let slot = AttachDhtSlot::default();
        if let Some(w) = dht_wiring.first() {
            slot.set(Some(AttachDht {
                local_port: w.dht_port,
                port_tx: dht_port_tx.clone(),
            }));
        }
        slot
    };

    // First-round DHT announce registration (private torrents were already
    // excluded by the dht_enabled gate; immediate peer lookup + registry
    // re-announce — the re-send cadence is the 2s tick). Both families
    // report actual_port right now (the NAT external-port snapshot syncs on
    // the 2s tick and only the v4 face consumes the snapshot — the
    // family_announce_port convention).
    let last_dht_announce = Instant::now();
    let dht_dial_dedup = DialDedup::new();
    if !dht_wiring.is_empty() {
        spawn_dht_announces(&dht_wiring, &faces, actual_port, actual_port);
    }
    // NAT external-port sync base (compared on the main-loop 2s tick — a
    // change re-registers the DHT announces with the new port; the tracker
    // announce port seam limitation is in the taiji_domain::nat module
    // docs).
    let last_nat_announced_port = actual_port;

    // Result of the bt-detach-seed-only decision (set at completion; decides
    // the SeedStopped vs Detached return paths).
    let detached = false;
    let completed = false;
    // Upload-serving sources: initially each face's download-time partial
    // source (PartialFaceSource serves only flushed pieces, the tit-for-tat
    // reciprocal upload surface; unflushed pieces are rejected — the gate
    // checks the written bit, and hash-pass pieces have announced HAVE while
    // their bytes are still in the write cache / flush in flight); once
    // every face completes, attach_seeding_sources overwrites the slot with
    // the full seeding source (the same slot; behavior converges).
    let seeding_sources: Vec<Option<Arc<dyn PieceSource>>> =
        faces.iter().map(|f| f.download_source.clone()).collect();
    let seeding_hash_sources: Vec<Option<Arc<dyn HashSource>>> =
        faces.iter().map(|_| None).collect();
    let next_cuid: u64 = 1;
    // ---- Task-surface state (swap/task policy; loaded from config_json) ----
    // BEP53 select-file (None = select all): the session sends it right
    // after activation via SetFileSelection (the engine consumes it before
    // announce dials — bounded command-channel order precedes dispatch).
    let selected_mask: Option<Arc<[bool]>> = None;
    // Per-file priorities (None = the all-zero default): sent by the session
    // after activation via SetFilePriority (the same channel/timing as
    // SetFileSelection).
    let piece_priority: Option<Arc<[i8]>> = None;
    // Pieces required for completion per face (pieces inside the mask once
    // a mask applies; default = piece_count).
    let required: Vec<usize> = faces.iter().map(|f| f.piece_count).collect();
    // BEP21 upload_only (the seeding-state announcement): set and broadcast
    // when all faces complete (the state transition itself re-advertises);
    // PeerConfig of connections registered afterwards is caught up via
    // SetUploadOnly.
    let upload_only = false;
    // BEP16 super-seeding book: created on entering the seeding state (the
    // `seed.super_seeding` master switch; shared by Arc with the connection
    // serving gate and the engine assignment decision).
    let super_seed: Option<Arc<taiji_bt::superseed::SuperSeedBook>> = None;
    // Random source for bookkeeping (picks randomly among tied pieces; a
    // fixed constant seed — the engine has no external entropy surface, so
    // determinism means reproducible tests, in the same family as aria2
    // PieceStatMan's startup shuffle).
    let superseed_rng = XorShift(0x9E37_79B9_7F4A_7C15u64);
    // Streaming static geometry (the layout -> real-file-order projection;
    // built before the EngineLoop literal — layout is moved into
    // AssembledEngine right after).
    let stream_geo = Arc::new(StreamGeo::from_layout(&layout, piece_len));

    let (reg_tx, reg_rx) = mpsc::channel::<PeerRegistration>(16 * faces.len());
    // Leave event payloads carry the reason (a connection-retention
    // observation — the five LeaveKind kinds, projected in transit.rs).
    let (leave_tx, leave_rx) = mpsc::channel::<(usize, u64, crate::LeaveKind)>(16 * faces.len());
    // Peer redial pool (libtorrent min_reconnect_time semantics,
    // cross-checked in the redial module docs): low-frequency redialing of
    // outbound peers that previously handshook and are currently
    // disconnected, during announce gaps. The pool and the result channel
    // are main-loop exclusive; the result channel is bounded(64) — redial
    // results are low frequency (one event per dial), full = await
    // backpressure on the dial task.
    let redial_pool = RedialPool::new(taiji_domain::redial::REDIAL_POOL_CAP);
    let (redial_tx, redial_rx) = mpsc::channel::<RedialReport>(64);
    // Silent-endpoint failure ledger (cross-checked in the silent module
    // docs): escalating backoff / cooldown demotion for discovery-dead
    // endpoints. Parallel to the redial pool, main-loop exclusive (no shared
    // lock).
    let silent_book = taiji_domain::silent::SilentBook::new(taiji_domain::silent::SILENT_BOOK_CAP);
    // ut_holepunch surface (on by default — libtorrent negotiates it with
    // the extension surface and has no separate switch; flipped at runtime
    // via EngineCommand::SetHolepunch, with the config_json load chain
    // driven by the session). Event channel bounded(16): rendezvous/connect
    // are both rate-limited by the PeerTask-layer fixed window (4/60s), low
    // frequency; the PeerTask side awaits under backpressure. Outcome report
    // channel bounded(64): one event per outbound dial, full = await
    // backpressure on the dial task. Trigger/introducer bookkeeping bounded
    // (HOLEPUNCH_BOOK_CAP).
    let (hp_tx, hp_rx) = mpsc::channel::<taiji_bt::peer::HolepunchEvent>(16);
    let hp_enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let holepunch = Some(taiji_bt::peer::HolepunchExt { tx: hp_tx });
    let (hp_report_tx, hp_report_rx) = mpsc::channel::<super::holepunch::HpDialReport>(64);
    let hp_book = taiji_bt::holepunch::HolepunchBook::new(taiji_bt::holepunch::HOLEPUNCH_BOOK_CAP);
    // Redial scan tick (2s): pool dequeue is batch-capped (REDIAL_SWEEP_BATCH
    // per sweep); at the 60s base interval, 2s granularity is ample and not
    // a busy loop.
    let redial_ticker = tokio::time::interval(Duration::from_secs(2));
    // Discovery-candidate drain tick: 250ms — with the 30/s budget accruing
    // continuously, each tick dials at most 7-8, so the connection-setup
    // latency bound = the tick (the rationale is in
    // `run::ecology::DRAIN_TICK`). Skip: a main-loop pause longer than the
    // tick is not caught up (the same rule as debt_ticker).
    let mut ecology_ticker = tokio::time::interval(super::ecology::DRAIN_TICK);
    ecology_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // BEP-40 rank self-reference: the v4 route-source probe (a UDP connect
    // route lookup, zero packets, millisecond-scale; probe_source_ip(false)
    // shares its source with the DHT bootstrap's BEP42-derived probe — a
    // separate call, so the engine surface does not depend on DHT being
    // enabled). None = no route / failure -> a neutral rank sort key (the
    // `run::ecology` divergence note).
    let self_v4 = taiji_bt::dht::security::probe_source_ip(false).await;
    // Query surface: torrent-level 10s sliding-window rates (sampled after
    // the per-peer delta bridging; the SpeedCalc.cc convention) + the
    // bridging baselines.
    let speed_up = SessionSpeedCalc::default();
    let speed_down = SessionSpeedCalc::default();
    let last_up_total: u64 = 0;
    let last_down_total: u64 = 0;
    let last_down_tcp_total: u64 = 0;
    let last_down_utp_total: u64 = 0;
    let ticker = tokio::time::interval(Duration::from_secs(2));
    // Choke-round interval is mode-dependent (libtorrent 15s default /
    // aria2 fallback 10s, BH_CHOKE_ARIA2=1). FaceState's choke objects read
    // the same knob (parsed once per process; the semantic consistency is in
    // bt::choke::choke_mode_from_env).
    let choke_ticker = tokio::time::interval(taiji_bt::choke::round_interval(
        taiji_bt::choke::choke_mode_from_env(),
    ));
    // Dispatch-debt settle tick arm (the tick-driven dispatch surface):
    // event arms (each BlockSettled / each HAVE advertisement) only register
    // face numbers; this arm drives the settle check when the debt ages out
    // (DISPATCH_DEBT_MAX_AGE; the three-condition gate lives inside
    // flush_dispatch_debt — the quiet/batch conditions are checked at the
    // top of the loop, and this arm covers the parked-with-no-events shape)
    // — the in-round decision order is unchanged (rationale and constants
    // in the dispatch::DISPATCH_DEBT_MAX_AGE docs). Skip behavior: a
    // main-loop pause longer than the tick does not replay backlog ticks
    // (settling is idempotent, preventing a post-pause burst).
    let mut debt_ticker = tokio::time::interval(super::super::dispatch::DISPATCH_DEBT_MAX_AGE);
    debt_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // 1s tick (cross-checked with BtStopDownloadCommand.cc's
    // TimeBasedCommand 1_s; SeedCheck / stop-timeout / time totals /
    // autosave all share this cadence).
    let seed_ticker = tokio::time::interval(Duration::from_secs(1));

    let total_pieces: usize = faces.iter().map(|f| f.piece_count).sum();
    info!(target: "taiji::core::engine",
        faces = faces.len(),
        kinds = ?faces.iter().map(|f| f.kind).collect::<Vec<_>>(),
        pieces = total_pieces, seed_after_complete, "engine up");

    // Runtime DHT seam (hot switch): the announce cadence is taken first
    // (DhtWireConfig moves into the seam), then cold wiring + channel spares
    // are packaged — consumed by the SetDhtEnabled arm.
    let dht_announce_interval = dht_cfg.announce_interval;
    let dht_seam = DhtRuntimeSeam {
        cold: dht_cold,
        cfg: dht_cfg,
        ev_tx: dht_ev_tx,
        port_tx: dht_port_tx,
    };

    Ok(AssembledEngine {
        tcp_inbound,
        actual_port,
        cmd_rx,
        progress_rx,
        ledger_rx,
        fetch_rx,
        avail_rx,
        tracker_ev_rx,
        violation_rx,
        dht_ev_rx,
        pex_rx,
        pex_enabled,
        utp_inbound,
        dht_port_rx,
        reg_rx,
        leave_rx,
        redial_rx,
        hp_rx,
        hp_report_rx,
        redial_ticker,
        ecology_ticker,
        ticker,
        seed_ticker,
        choke_ticker,
        debt_ticker,
        session_up,
        session_down,
        session_metrics,
        gauge_slot,
        hook,
        nat,
        seed,
        seed_after_complete,
        layout,
        dest,
        piece_len,
        startup_uploaded,
        startup_downloaded,
        startup_active_s,
        startup_seed_s,
        dht_announce_interval,
        dht_wiring,
        dht_seam,
        actor_cmds,
        dial: DialCtx {
            peer_id,
            crypto,
            conn_type,
            ext,
            // EngineLoop holds another Arc of the same instance (the budget
            // source for budget-derived slots; the choke round reads the
            // hot-updated rate directly) — this clone keeps the state
            // literal below a move of owned values.
            limiter: limiter.clone(),
            attach_dht,
            utp_dial,
            reg_tx,
            leave_tx,
            violation_tx,
            redial_tx,
            holepunch,
            hp_enabled: Arc::clone(&hp_enabled),
            hp_report_tx,
            avail_tx_face,
            // Block-arrival event sender (injected by outbound DialJob /
            // inbound attach).
            ledger_tx,
            // ext handshake `v` identity re-check callback (shares the
            // IpGuard snapshot handle; list hot-reloads apply immediately).
            client_deny: Some(client_v_deny_check(&ban_book.guard)),
        },
        state: EngineLoop {
            faces,
            // BEP27 private bit (the SetDhtEnabled gate — runtime enable on
            // a private engine is always refused; torrent.cpp priv() cannot
            // be overridden).
            private,
            ban_book,
            persist_shared,
            tracker_flusher,
            redial_pool,
            silent_book,
            completed,
            detached,
            upload_only,
            super_seed,
            superseed_rng,
            seeding_sources,
            seeding_hash_sources,
            selected_mask,
            piece_priority,
            required,
            choke_rng,
            // Budget source for budget-derived unchoke slots (the same Arc
            // instance as DialCtx.limiter; None = a bare run without rate
            // limiting, budget mode falls back to static slots).
            limiter,
            next_cuid,
            tasks: JoinSet::new(),
            seed_check,
            stop_watch,
            speed_calc,
            last_down_sample,
            active_secs,
            seed_secs,
            stats_completed,
            speed_up,
            speed_down,
            last_up_total,
            last_down_total,
            last_down_tcp_total,
            last_down_utp_total,
            // Supply-byte totals (observation; always zero at session start
            // — traffic from a restored session belongs to the progress-row
            // baseline and does not enter this process's counters, the same
            // convention as bytes_down_total).
            supply_tcp_down: 0,
            supply_utp_down: 0,
            mix_log_prev: None,
            // In-flight/completed dial observation (the data source for the
            // 30s pool-curve line): always zero at session start; written by
            // the spawn wrapper arm, read by tick.
            dial_ifl: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            dial_done: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_dht_announce,
            dht_dial_dedup,
            last_nat_announced_port,
            hp_book,
            hp_enabled,
            // The strategy starts as rarest-first (the direct port, zero
            // behavior change; swapped atomically at runtime via
            // SetSchedulerPolicy).
            strategy: Box::new(RarestFirstStrategy),
            // Streaming static geometry (projected once from the layout);
            // the playhead starts as None — delivered at runtime by
            // SetStreamingPlayhead.
            stream_geo,
            playhead: None,
            // Live disk-tier surface (the construction-time policy initial;
            // re-geared by SetDiskPolicy).
            disk_policy_tx,
            disk_live,
            // Hash recovery (missing-layer file bookkeeping + the delivery
            // seam sender; the receiver leaves via AssembledEngine — the
            // main-loop event-channel convention).
            recovery: recovery_books,
            recovery_deliver,
            // Admission consumption counters (session totals, starting at zero).
            recovery_admission: super::recovery_admit::RecoveryAdmissionStats::default(),
            // Gated-upgrade carriers (live expected-roots copies + the pipeline
            // seam senders).
            recovery_upgrade: recovery_upgrades,
            // Recovery event tracking (initialized at the activation emit
            // point; only missing-layer tasks hold non-defaults).
            recovery_track: super::recovery_admit::RecoveryEventTrack::default(),
            // Dispatch debt (the tick-driven dispatch surface): starts
            // empty; event arms register via note_dispatch_debt, and the
            // loop-top age check plus the debt-ticker arm settle by debt
            // age.
            dispatch_debt: Default::default(),
            dispatch_debt_since: None,
            // Observation-family bridging baselines (always zero at session
            // start — the process-level atomics share that origin).
            two_phase_obs_prev: (0, 0, 0),
            dispatch_debt_settles: Default::default(),
            // Stall-detection valve: starts in the empty state — zero-delta
            // counters, stall hysteresis, and rotation observation
            // bookkeeping all zero; fed by the 1s seed tick (run::stall).
            stall_valve: super::stall::StallValve::default(),
            // Connection-ecology governance: the dial budget (starts full;
            // BH_CONNECT_SPEED overrides at construction — Some = pinned
            // rate) / the discovery candidate table (starts empty; capacity
            // from the BH_CONN_FILL_POOL knob read once at assembly via
            // from_env) / the BEP-40 self-reference / the turnover cadence
            // anchor / the dial-outcome observation window (starts empty).
            dial_budget: super::ecology::DialBudget::from_env(Instant::now()),
            dial_candidates: super::ecology::DialCandidates::from_env(),
            self_v4,
            // v6 candidate-preference surface: the global v6 probe reuses
            // the same `probe_source_ip(true)` call as BEP7 `ipv6=` (zero
            // extra probes; None = no global v6 -> v6 sort keys always
            // neutral).
            self_v6_global: local_ipv6.is_some(),
            last_turnover: None,
            // Slow-peer eviction bookkeeping: the cadence anchor starts None
            // / the eviction mark table starts empty (insertion at the
            // eviction point); peer registration times moved into the
            // FaceState.peer_state row (written as registered_at by the
            // register arm).
            last_slow_churn: None,
            slow_evict_marks: std::collections::HashMap::new(),
            dial_outcomes: super::ecology::DialOutcomeWindow::new(Instant::now()),
            // Dial decay ladder: starts unstepped with the
            // anchor at assembly — the earliest possible step is one
            // outcome window (30s) in. The gear starts at the base rate
            // (an override pins it from the first decision).
            dial_decay_steps: 0,
            dial_gear: super::ecology::CONNECTION_SPEED,
            dial_decay_anchor: Instant::now(),
            // Holepunch observation bridging baseline (always zero at
            // session start — the process-level atomics share that origin;
            // the 1s seed tick feeds deltas in tick.rs).
            hp_obs_prev: super::holepunch::HolepunchObs::default(),
            // Webseed pseudo-peer cuid book (starts empty; pre-registered at
            // assembly by dial::attach_webseeds before run() starts).
            webseed_cuids: std::collections::HashSet::new(),
        },
        // The delivery seam receiver leaves with the state (select! arms
        // borrow separately — like the other event channels it is a run()
        // local binding).
        recovery_deliver_rx,
        // BEP19 webseed set (consumed before run() starts).
        webseeds,
    })
}

/// Startup ban-book restoration (extracted; a verbatim move of the original
/// run assembly's ban_book block): active unexpired bans + ipfilter static
/// rules rebuild the IpGuard snapshot.
async fn build_ban_book(
    guard: IpGuardHandle,
    persist_shared: Option<&TrackerPersistShared>,
    metrics: Option<&Arc<SessionMetrics>>,
) -> BanBook {
    let mut ledger = BanLedger::new(Box::new(variable_bad_peer_timeout));
    let mut static_rules: Vec<FilterRule> = Vec::new();
    if let Some(p) = persist_shared {
        let handle = &p.handle;
        let now = epoch_secs();
        match handle.load_active_peer_bans(now).await {
            Ok(rows) => {
                for r in &rows {
                    match r.ip.parse::<IpAddr>() {
                        Ok(ip) => ledger.restore_ban(ip, r.reason.clone(), r.until, now),
                        Err(_) => warn!(target: "taiji::core::engine", ip = %r.ip,
                            "stored ban ip unparsable, skipped"),
                    }
                }
                if !rows.is_empty() {
                    info!(target: "taiji::core::engine", count = rows.len(),
                        "active peer bans restored from previous session");
                }
            }
            Err(e) => warn!(target: "taiji::core::engine", %e,
                "peer ban restore failed (fresh guard)"),
        }
        match handle.load_ipfilter().await {
            Ok(rows) => {
                for r in &rows {
                    if let Some(rule) = ipfilter_row_to_rule(r) {
                        static_rules.push(rule);
                    }
                }
                if !rows.is_empty() {
                    info!(target: "taiji::core::engine", count = rows.len(),
                        "ipfilter rules restored");
                }
            }
            Err(e) => warn!(target: "taiji::core::engine", %e,
                "ipfilter restore failed (no static rules)"),
        }
    }
    // Refresh the snapshot only when there really is a read-back surface
    // (persist injected): without persistence the injected snapshot was
    // assembled externally (session import / test presets) and must not be
    // overwritten by an empty read-back.
    if persist_shared.is_some() {
        refresh_guard(&guard, &static_rules, &ledger, epoch_secs());
    }
    BanBook {
        guard,
        static_rules,
        ledger,
        // Identity rules / manual bans are pushed wholesale by the session
        // after activation via SetBanConfig (the engine starts empty = it
        // bans no client).
        client_deny: Vec::new(),
        manual: Vec::new(),
        metrics: metrics.cloned(),
        // smart_ban ledger (the BH_SMART_BAN/BH_SMART_BAN_PAROLE knobs are
        // read at ledger construction) + the read-back budget gate (one
        // piece per torrent at a time).
        smart_ban: SmartBanLedger::from_env(),
        smart_ban_read_gate: Arc::new(tokio::sync::Semaphore::new(1)),
    }
}

/// Per-face assembly (extracted; a verbatim move of the original run
/// assembly's `faces.into_iter().enumerate()` loop): the store pipeline +
/// availability aggregation + bitfield restore + TrackerActor wiring +
/// FaceState construction.
async fn build_faces(
    faces_cfg: Vec<FaceConfig>,
    piece_len: u32,
    restore: &RestoreSource<'_>,
    store: &StoreWiring<'_>,
    tracker: &TrackerWiring<'_>,
    tracker_ev_tx: mpsc::Sender<(usize, TrackerActorEvent)>,
    stat_rng: &mut XorShift,
) -> FaceBuildOut {
    let mut avail_tx_face: Vec<mpsc::Sender<AvailEvent>> = Vec::new();
    let mut udp_carrier_out_rxs: Vec<mpsc::Receiver<(SocketAddr, Vec<u8>)>> = Vec::new();
    let mut actor_in_txs: Vec<mpsc::Sender<(SocketAddr, Vec<u8>)>> = Vec::new();
    let mut actor_cmds: Vec<Option<mpsc::Sender<TrackerCommand>>> = Vec::new();
    // Recovery bookkeeping sidecar (collected in face order).
    let mut recovery_books: Vec<RecoveryBook> = Vec::new();
    // Gated-upgrade carrier sidecar (collected in face order).
    let mut recovery_upgrades: Vec<Option<super::recovery_admit::RecoveryUpgrade>> = Vec::new();

    let faces: Vec<FaceState> = faces_cfg
        .into_iter()
        .enumerate()
        .map(|(fi, f)| {
            let (block_tx, block_rx) = mpsc::channel::<BlockMsg>(BLOCK_CHANNEL_CAPACITY);
            let (atx, arx) = mpsc::channel::<AvailEvent>(64);
            let goffs = Arc::new(f.piece_goffs.clone());
            let cross = Arc::new(f.cross.clone());
            // v2 face requester base: HashTreeCache (metadata piece layers
            // are the trusted anchors) + a flat piece coordinate table +
            // per-file lazy-fetch plans. For single-block files (<=16 KiB)
            // the leaf hash == the pieces root, so the load is anchored into
            // the store and the state goes straight to Done (an empty plan,
            // no network lazy fetch — see the hash_fetch module docs).
            // Multi-piece files with missing layers also register recovery
            // bookkeeping (the sidecar collects it).
            let V2DataPlane {
                trees,
                piece_leaves,
                coords: flat_coords,
                layers,
                recovery,
            } = build_v2_data_plane(f.hash_files.as_deref(), f.addressing.clone(), piece_len);
            recovery_books.push(recovery);
            // Gated-upgrade seam: with a v2 base present, attach the live
            // expected-roots channel (the initial snapshot = the
            // construction shape: missing layers hold zero-root placeholders;
            // after admission the activation chain fills in the real roots
            // and re-publishes the whole set). A v1 face (trees = None)
            // always has complete expectations, so the seam stays default.
            let (recovery_upgrade, recovery_expected_rx) = if trees.is_some() {
                let (tx, rx) = tokio::sync::watch::channel(Arc::new(ExpectedRoots {
                    expected: f.expected.clone(),
                    piece_leaves: Arc::clone(&piece_leaves),
                }));
                (
                    Some(super::recovery_admit::RecoveryUpgrade {
                        expected: f.expected.clone(),
                        piece_leaves: Arc::clone(&piece_leaves),
                        tx,
                    }),
                    Some(rx),
                )
            } else {
                (None, None)
            };
            recovery_upgrades.push(recovery_upgrade);
            let block_check = trees.clone().map(|trees| BlockCheck {
                piece_leaves: piece_leaves.clone(),
                trees,
            });
            // Endgame observation flag: written on dispatch edges, read by
            // the store pipeline (duplicate/buffered block split counts
            // during the triggered window) — built first, then cloned
            // twice.
            let endgame_live = Arc::new(std::sync::atomic::AtomicBool::new(false));
            // Face-level block pool (a shared lease source for wire decoding
            // and cache cells; BH_BLOCK_ARENA=0 -> None falls back to direct
            // allocation, zero behavior change).
            let block_arena = crate::pipeline::block_arena_for_face(piece_len);
            // Pre-registered counter (observation): incremented by direct-
            // sink block delivery, decremented by pipeline batch
            // confirmations — observation only, never a decision input (see
            // FaceState::block_inflight).
            let block_inflight = Arc::new(std::sync::atomic::AtomicU64::new(0));
            // Final data-flush barrier wiring: a trigger channel (engine
            // teardown -> the pipeline) + a watch barrier (the pipeline sets
            // the final value -> the engine's final_flush waits). The
            // ordering invariant "data fsync first, progress-row upsert
            // second" is documented in pipeline::DataFlushState and the
            // store_pipeline teardown section.
            let (final_flush_tx, final_flush_rx) = mpsc::channel::<()>(1);
            let (data_flush_gate, data_flush_rx) =
                tokio::sync::watch::channel(DataFlushState::Pending);
            // Snapshot write-barrier fsync surface: filled in by the
            // pipeline after building the write handle, consumed by the
            // regular autosave arm (run/tick.rs autosave_snapshot) — why
            // delivery takes the cell instead of the pipeline arm is in the
            // pipeline::SnapshotSyncCell docs.
            let snapshot_sync: crate::pipeline::SnapshotSyncCell =
                Arc::new(std::sync::OnceLock::new());
            tokio::spawn(store_pipeline(StoreJob {
                face: fi,
                expected: f.expected.clone(),
                piece_len,
                plan_file_lengths: f.plan_file_lengths.clone(),
                goffs: goffs.clone(),
                cross,
                block_check,
                dest: store.dest.clone(),
                writer_factory: store.writer_factory.clone(),
                layout: store.layout.clone(),
                allocate: !store.resume_existing,
                block_rx,
                progress_tx: store.progress_tx.clone(),
                token: store.token.clone(),
                metrics: store.metrics.cloned(),
                endgame_live: Arc::clone(&endgame_live),
                // Verify/write worker pool (default = min(cpu count, 4),
                // overridable via the BH_VERIFY_WORKERS env var; see
                // VerifyPoolConfig::auto).
                pool: VerifyPoolConfig::auto(),
                // Disk-protection tier (the throughput default = zero
                // behavior change; per-torrent override via
                // EngineConfig.disk_policy).
                disk_policy: store.disk_policy,
                // Live disk-tier surface: policy watch receiver + applied
                // reading.
                policy_rx: store.policy_rx.clone(),
                live: store.live.clone(),
                // Gated-upgrade seam receiver (v2 faces only; v1 = None).
                recovery_expected_rx,
                block_arena: block_arena.clone(),
                // Pre-registered counter (decremented by pipeline batch
                // confirmations) + the return-flow batching knob
                // (BH_BLOCK_BATCH_ACK, default follows BH_BLOCK_BYPASS; read
                // once at build_faces assembly).
                block_inflight: Arc::clone(&block_inflight),
                batch_ack: super::super::block_batch_ack_enabled(),
                final_flush_rx,
                data_flush_gate,
                snapshot_sync: snapshot_sync.clone(),
            }));
            // Availability event aggregation: the face tag is attached by
            // the forwarding task (lossy drops are fine — rarity is
            // heuristic, not correctness data; see the bt::peer::PeerConfig
            // docs).
            let tag_tx = store.avail_all_tx.clone();
            let fwd_token = store.token.clone();
            tokio::spawn(async move {
                let mut arx = arx;
                loop {
                    tokio::select! {
                        _ = fwd_token.cancelled() => break,
                        ev = arx.recv() => match ev {
                            None => break,
                            Some(ev) => {
                                if tag_tx.send((fi, ev)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            avail_tx_face.push(atx);
            let mut progress = ProgressModel::from_lengths(&f.progress_file_lens, piece_len);
            debug_assert_eq!(
                progress.global_piece_count() as usize,
                f.piece_count(),
                "face {fi} layout piece count matches the expected hash count"
            );
            // Bitfield restore (the crash-recovery fast-start path; the
            // cross-session counter base shares this source — the `startup`
            // row is the previous session's final values as read back by
            // LoadTorrentProgress). In-flight block bitmaps are not restored
            // (an intentional deviation; see the progress_row docs). The
            // bitfield-trust assumption = the default fast-start semantics
            // of --bt-hash-check-seed; its trust premise is backed by the
            // persistence write barrier: a stored row is committed only
            // after the corresponding data files are fsynced (regular rows:
            // the snapshot barrier — run/tick.rs autosave_snapshot, with the
            // dirty-face fsync first and a fail-closed row skip on failure;
            // final rows: the final-state barrier — run/tail.rs
            // final_flush). Therefore the piece bytes a row's bitfield
            // claims were on disk before the previous session lost power,
            // and setting the written/verified models directly cannot
            // mistake sparse zeros for verified data (the seeding read
            // surface and the hash-serving surface share this base). The
            // forced recheck entry (re-entering the checking state) is the
            // explicit escape hatch for this assumption.
            //
            // Restore-source fork: the persist row wins (the session
            // surface's authority); with no row (a bare --check-integrity)
            // the code falls back to cfg.preset_progress — a measured
            // on-disk bitfield taken before the CLI spawn (the same entry as
            // a session recheck), so the disk bytes match the bitfield's
            // claims by construction; the trust premise is as above. Hard
            // rule: preset does not participate in the resume_existing
            // decision (that value still looks only at the startup row — if
            // a preset flipped resume_existing, allocate=false would skip
            // allocation, missing on-disk files would never be created, and
            // the write path would hit Fatal; on the preset path
            // allocate=true keeps the open-existing-files semantics,
            // preserving existing bytes and creating missing files as
            // usual).
            let (restored, restored_from_preset): (usize, bool) =
                match (restore.startup.as_ref(), restore.preset.as_ref()) {
                    (Some(row), _) => {
                        let n = match f.kind {
                            FaceKind::V2 => restore_progress_bits(
                                &mut progress,
                                row.v1_bitfield.as_deref(),
                                row.v2_file_bits.as_deref(),
                            ),
                            FaceKind::V1 => restore_progress_bits(
                                &mut progress,
                                row.v1_bitfield.as_deref(),
                                None,
                            ),
                        };
                        (n, false)
                    }
                    (None, Some(p)) => {
                        let n = match f.kind {
                            FaceKind::V2 => restore_progress_bits(
                                &mut progress,
                                p.v1_bitfield.as_deref(),
                                p.v2_file_bits.as_deref(),
                            ),
                            FaceKind::V1 => {
                                restore_progress_bits(&mut progress, p.v1_bitfield.as_deref(), None)
                            }
                        };
                        (n, true)
                    }
                    (None, None) => (0, false),
                };
            if restored > 0 && !restored_from_preset {
                debug!(target: "taiji::core::engine", face = fi, restored = restored,
                    total = f.piece_count(), "bitfield restored from previous session");
            } else if restored > 0 {
                debug!(target: "taiji::core::engine", face = fi, restored = restored,
                    total = f.piece_count(),
                    "bitfield restored from preset progress (--check-integrity)");
            }
            let face_total: u64 = f.piece_bytes.iter().sum();
            let face_count = f.piece_count();
            // On-disk bitmap (the restore path sets bits before this point
            // — the restored bits come from the previous session's doubly-
            // confirmed pieces, a disk fact, so both models start aligned) +
            // the download-period upload serving source (serves only flushed
            // pieces — the tit-for-tat upload surface gated on written; on
            // completion attach_seeding_sources overwrites the
            // initial_source slot with the full source). The verified model
            // (progress) and the written model (written_progress) diverge
            // from here: the former advances with PieceVerified (hash-pass
            // advertisement/progress), the latter with PieceWritten (upload
            // gating / persistence / completion).
            let written_bits = Arc::new(PieceBitmap::new(face_count));
            for k in 0..face_count {
                if progress.piece_done_global(k as u64) {
                    written_bits.set(k);
                }
            }
            let written_progress = progress.clone();
            let download_source: Arc<dyn PieceSource> = Arc::new(PartialFaceSource {
                // Read-side handle pool: download-period upload serving also
                // stops opening/closing handles per segment (open cost
                // O(requests) -> O(active files)).
                reader: TorrentReader::with_handle_pool(
                    store.layout.clone(),
                    store.dest.to_path_buf(),
                    taiji_store::torrent_writer::READER_MAX_OPEN_HANDLES,
                ),
                goffs: goffs.clone(),
                written: written_bits.clone(),
            });
            // TrackerActor wiring: the SwarmView snapshot (refreshed by the
            // 2s tick) + actor spawn + the UDP carrier + event aggregation
            // forwarding.
            // The snapshot's initial value must reflect the restored
            // bitfield (it was previously hardcoded to 0/false — for a
            // seed-only task, at the first announce
            // `all_download_finished` had not flipped yet, so the event =
            // STARTED, then advanced to DOWNLOADING after success, and the
            // next round sent COMPLETED as completed-allowed -> sites
            // counted a phantom snatch. Upstream: aria2 adjusts to
            // STARTED_AFTER_COMPLETION via `allDownloadFinished()` before
            // the first announce (`DefaultBtAnnounce.cc`; its pieceStorage
            // is loaded from the control file before the announce command
            // starts). Here the restored bitfield's completion state is
            // moved before the actor's first read, so the corresponding
            // branch applies with aria2 semantics from the first announce.
            // No snapshot refresh happens before the first tick; afterwards
            // the two values remain tick-authoritative (the behavior surface
            // is unchanged).
            let restored_completed = progress.completed_length();
            let swarm = FaceView(Arc::new(Mutex::new(SwarmSnapshot {
                total: face_total,
                completed: restored_completed,
                all_finished: restored >= face_count,
                peers: 0,
                uploaded: 0,
                downloaded: 0,
            })));
            let mirror_rows_gid = tracker
                .persist_shared
                .as_ref()
                .map(|p| p.gid.clone())
                .unwrap_or_default();
            let mirror = TrackerMirror::new(tracker.tracker_flat, &mirror_rows_gid);
            // Row registration (enabled=1): the session-visible tracker
            // table exists before the first announce (the read
            // surface the session relies on).
            if let Some(p) = tracker.persist_shared.as_ref() {
                for row in mirror.rows.values() {
                    p.enqueue(row.clone());
                }
            }
            let (face_ev_tx, mut face_ev_rx) =
                mpsc::channel::<TrackerActorEvent>(EVENT_CHANNEL_CAPACITY);
            let (actor_out_tx, carrier_out_rx) =
                mpsc::channel::<(std::net::SocketAddr, Vec<u8>)>(UDP_OUTBOUND_CAPACITY);
            let (carrier_in_tx, actor_in_rx) =
                mpsc::channel::<(std::net::SocketAddr, Vec<u8>)>(UDP_INBOUND_CAPACITY);
            // The actor's UDP carrier moves to the demux — outbound goes
            // through carrier_out_rx to the face router task, which routes
            // by family to the shared socket; inbound is fanned out to
            // carrier_in_tx by the demux tracker-channel dispatcher (actor
            // channel semantics unchanged). With no UDP face (bind failure)
            // carrier_out_rx/actor_in_rx stall naturally as their channels
            // close (HTTP announce unaffected).
            udp_carrier_out_rxs.push(carrier_out_rx);
            actor_in_txs.push(carrier_in_tx);
            let actor_cmd = spawn_tracker_actor(
                TrackerActorConfig {
                    info_hash: f.info_hash,
                    peer_id: tracker.peer_id,
                    // Announce report port (the NAT external-port snapshot,
                    // falling back to actual_port without a mapping — see
                    // TrackerWiring::announce_port).
                    listen_port: tracker.announce_port,
                    options: {
                        // Announce client options (interval + two timeouts,
                        // projected unchanged from
                        // EngineConfig.tracker_options; the BEP7 v6 carrier
                        // is still overridden per face).
                        let mut o = tracker.tracker_options;
                        o.local_ipv6 = tracker.local_ipv6;
                        o
                    },
                    // Announce crypto parameter bit (wired; the boundary
                    // declaration is folded in): require ->
                    // `requirecrypto=1`, otherwise `supportcrypto=1`
                    // ([`mse::announce_crypto_param`], cross-checked with
                    // `DefaultBtAnnounce.cc`; URL construction dispatches on
                    // this bool inside the frozen bt::tracker surface).
                    require_crypto: tracker.require_crypto,
                    // BEP27 single-flight gate: private -> serial
                    // single-flight scheduling (parallel waves per host
                    // would violate "use only one tracker at a time" for a
                    // private torrent).
                    private: tracker.private,
                    tiers: tracker.tiers.to_vec(),
                    // Scrape batch = every identifier of this torrent (same-
                    // host batching; BEP52 hybrid scrapes both identifiers at
                    // once).
                    scrape_hashes: tracker.all_info_hashes.to_vec(),
                },
                Arc::new(swarm.clone()),
                face_ev_tx,
                UdpTransport {
                    outbound: actor_out_tx,
                    inbound: actor_in_rx,
                },
            );
            if let Err(e) = &actor_cmd {
                warn!(target: "taiji::core::engine", face = fi, %e,
                    "tracker actor spawn failed (face announces nothing)");
            }
            let tag_tx = tracker_ev_tx.clone();
            tokio::spawn(async move {
                while let Some(ev) = face_ev_rx.recv().await {
                    if tag_tx.send((fi, ev)).await.is_err() {
                        break;
                    }
                }
            });
            actor_cmds.push(actor_cmd.ok());
            FaceState {
                kind: f.kind,
                info_hash: f.info_hash,
                reserved: f.reserved,
                addressing: f.addressing,
                piece_bytes: std::sync::Arc::from(f.piece_bytes),
                piece_goffs: goffs,
                progress,
                piece_count: face_count,
                verified_count: restored,
                stat_man: PieceStatMan::new(face_count as u64, &mut |n| stat_rng.next(n)),
                peer_avail: std::collections::HashMap::new(),
                peer_seeds: std::collections::HashSet::new(),
                peers: Vec::new(),
                peer_cuids: Vec::new(),
                // Per-peer table consolidation (rows are built by the register
                // arm).
                peer_state: std::collections::HashMap::new(),
                block_senders: Arc::new(Mutex::new(HashMap::new())),
                pex_candidates: PexCandidates::default(),
                choke: SeederChoke::new(),
                leecher_choke: LeecherChoke::new(),
                regular_unchoked: std::collections::HashSet::new(),
                download_source: Some(download_source),
                written_bits,
                written_progress,
                written_count: restored,
                completed: false,
                hash_files: f.hash_files,
                swarm,
                mirror,
                block_cursor: 0,
                block_tx,
                trees,
                flat_coords,
                layers,
                fetch_tx: store.fetch_tx.clone(),
                refetch: Vec::new(),
                dispatch_replies: Vec::new(),
                // Endgame observation: the flag is shared with the store
                // pipeline (written on dispatch edges, read by the pipeline);
                // the duration fields are maintained by dispatch edges plus
                // tick/flush checkpoints, starting at zero. The tail-segment
                // observation (last-mile / the final-8-pieces window) starts
                // at zero too (registered on the entering edge as missing
                // pieces decline, during dispatch rounds).
                endgame_live,
                endgame_edge: None,
                endgame_cum: Duration::ZERO,
                last_mile_edge: None,
                last_mile_final: None,
                last8_edge: None,
                last8_final: None,
                endgame_deadline: std::collections::HashMap::new(),
                // Write-locality observation (observation only): the
                // face-level totals start at zero (checkpoint_endgame
                // bridges take-and-reset).
                write_adjacent: 0,
                write_isolated: 0,
                // Dispatch-round scratch pool (take-out/put-back reuse;
                // starts at zero capacity — the first round grows it to the
                // face's piece count).
                dispatch_scratch: Default::default(),
                blocks_sent: std::collections::HashMap::new(),
                // Face-level read pool: the serve-read service shared by all
                // of the face's connections (disk reads move out of the peer
                // event loop). build_faces runs inside a runtime context
                // (spawning the dispatcher task needs a tokio handle).
                read_pool: Some(taiji_bt::peer::ReadPool::new()),
                // Parole suspect set (starts empty; written by event arms, read
                // by the dispatch gate).
                parole_peers: std::collections::HashSet::new(),
                block_arena,
                // Pre-registered counter (observation; shared with the
                // pipeline).
                block_inflight,
                // Final data-flush barrier wiring: the trigger end and the
                // barrier read end ride with the face state for engine
                // teardown consumption.
                final_flush_tx,
                data_flush_gate: data_flush_rx,
                // The restored bitfield comes from a previous session's row
                // that already passed the barrier (the bytes were on disk
                // then) -> the dirty flag starts false; the fsync surface is
                // the cell note above.
                dirty_since_snapshot: false,
                snapshot_sync,
            }
        })
        .collect();
    FaceBuildOut {
        faces,
        avail_tx_face,
        udp_carrier_out_rxs,
        actor_in_txs,
        actor_cmds,
        recovery_books,
        recovery_upgrades,
    }
}

/// DHT/µTP wiring (extracted; a verbatim move of the original run
/// assembly's `for (family, channels, demux) in udp_face` loop): the
/// tracker-channel dispatcher, the µTP listener + accept merge and
/// delegated dial, and DHT engine spawn + bootstrap (per family).
#[expect(
    clippy::too_many_arguments,
    reason = "verbatim extraction of the run assembly loop; parameters mirror the captured locals"
)]
async fn wire_dht_and_utp(
    udp_face: Vec<(DhtFamily, udp_demux::DemuxChannels, UdpDemuxHandle)>,
    actor_in_txs: &[mpsc::Sender<(SocketAddr, Vec<u8>)>],
    dht_enabled: bool,
    dht_cfg: &DhtWireConfig,
    persist_shared: Option<&TrackerPersistShared>,
    token: &CancellationToken,
    crypto: taiji_bt::mse::CryptoPolicy,
    utp_inbound_tx: mpsc::Sender<(SocketAddr, UtpStream)>,
    dht_ev_tx: &mpsc::Sender<(DhtFamily, DhtEvent)>,
) -> (Vec<DhtFamilyWiring>, UtpDial, Vec<DhtColdWiring>) {
    let mut utp_dial = UtpDial::default();
    let mut dht_wiring: Vec<DhtFamilyWiring> = Vec::new();
    // Cold wiring: one per bound family (the gate pump task is always
    // built — the demux dht receiver stays resident in the gate, and runtime
    // enable/disable no longer consumes the receiver).
    let mut dht_cold: Vec<DhtColdWiring> = Vec::new();
    for (family, mut channels, demux) in udp_face {
        // Tracker-channel dispatcher (independent of the DHT switch — the
        // UDP tracker announce surface rides the demux in the default shape
        // too).
        let targets = actor_in_txs.to_vec();
        tokio::spawn(async move {
            while let Some(pkt) = channels.tracker.recv().await {
                let frame = (pkt.from, pkt.data.to_vec());
                for tx in &targets {
                    if tx.send(frame.clone()).await.is_err() {
                        break; // this actor is gone (engine teardown); the
                        // remaining targets will exit too.
                    }
                }
            }
        });
        // µTP listener (the protocol stack's consumer side; the UtpConfig
        // defaults are a frozen value surface).
        let (utp_handle, _utp_pump) = spawn_utp(
            channels.utp,
            demux.clone(),
            UtpConfig::default(),
            token.clone(),
        );
        let (req_tx, req_rx) = mpsc::channel::<UtpDialReq>(UTP_DIAL_QUEUE_CAPACITY);
        match family {
            DhtFamily::V4 => utp_dial.v4 = Some(req_tx.clone()),
            DhtFamily::V6 => utp_dial.v6 = Some(req_tx.clone()),
        }
        // Consumer decoupling: accept delivery and µTP delegated dialing are
        // split into two independent tasks (the original single-task select
        // shape had a stall mode — while the accept arm sat in
        // `accept_tx.send().await` backpressure (merge channel full / slow
        // main loop), the dial req arm was parked wholesale, leaving
        // dead-address µTP fallback requests stuck in the bounded(64) queue
        // with no upper bound; the consumer-exit window had the same
        // failure). `utp_handle.connect(&self)` only reads shared state, so
        // it is split via a cloned [`UtpConnectHalf`] (the io listener's
        // read half; the routing table / outbound pump / token share one
        // source — the "routing table is the connection registry"
        // uniqueness holds). The "synchronous connect + oneshot reply"
        // semantics are unchanged; only the task topology changed. The two
        // tasks share a lifecycle: the merge channel closing (the main loop
        // exits) -> the accept task exits + the UtpDial sender drops with
        // DialContext -> req_rx None -> the dial task exits; the listener
        // exiting (token cancelled) -> accept_from None converges both.
        let connect_half = utp_handle.connect_half();
        tokio::spawn(utp_accept_pump(utp_handle, utp_inbound_tx.clone()));
        tokio::spawn(utp_dial_pump(req_rx, req_tx, connect_half));
        // The demux bound port = the DHT port (TCP/UDP share the port; the
        // v6 face uses the same port as v4 — two family instances of one
        // listen-port).
        let dht_port = demux.bound_addr().port();
        // Inbound gate (the receiver stays resident; forward targets connect
        // or disconnect per the watch slot). The cold wiring is ALWAYS
        // built: the gate (the holder of the watch sender) must outlive this
        // loop — the enabled path's engine-inbound channel sender lives in
        // the watch slot, and an early gate death = pump exit = the engine's
        // inbound surface closes (the actor saves and exits); it also
        // preserves the reuse surface for runtime enable/disable.
        let gate = spawn_dht_inbound_gate(channels.dht, token.clone());
        dht_cold.push(DhtColdWiring {
            family,
            gate: std::sync::Arc::clone(&gate),
            demux: demux.clone(),
            dht_port,
        });
        if dht_enabled {
            // Warm up during assembly (the existing behavior path, zero
            // change — spawn_dht_family is a move of the original loop
            // body's engine assembly section).
            dht_wiring.push(
                spawn_dht_family(
                    family,
                    &gate,
                    demux,
                    dht_port,
                    dht_cfg,
                    persist_shared,
                    dht_ev_tx,
                )
                .await,
            );
        }
    }
    if !dht_wiring.is_empty() {
        info!(target: "taiji::core::engine",
            families = dht_wiring.len(),
            port = dht_wiring[0].dht_port,
            announce_param = mse::announce_crypto_param(crypto),
            "dht wired (announce param per DefaultBtAnnounce.cc)");
    } else if dht_enabled {
        warn!(target: "taiji::core::engine",
            "dht enabled but no udp face bound: DHT disabled for this engine");
    }
    (dht_wiring, utp_dial, dht_cold)
}

/// µTP accept delivery task (an independent task after the consumer split;
/// formerly one select with the dial pump — the semantics moved verbatim,
/// only the task topology changed). Listener exit (token cancelled / the
/// routing task winding down) -> accept_from None -> the loop ends
/// naturally; the merge channel closing (the engine main loop already
/// gone) -> send Err -> break.
async fn utp_accept_pump(
    mut utp_handle: taiji_io::utp::UtpListenerHandle,
    accept_tx: mpsc::Sender<(SocketAddr, UtpStream)>,
) {
    while let Some(pair) = utp_handle.accept_from().await {
        if accept_tx.send(pair).await.is_err() {
            // The merge channel closed = the engine main loop has exited
            // (teardown).
            break;
        }
    }
}

/// µTP delegated-dial consumer task (an independent task after the split —
/// accept backpressure no longer parks this queue, removing the stall
/// mode). The `req_tx` copy lives until the task ends: req_rx.recv()
/// returns None only after every sender is gone (engine teardown) — while
/// the main loop is alive it stays Pending, never spinning (the same
/// keepalive discipline as the old single task).
async fn utp_dial_pump(
    mut req_rx: mpsc::Receiver<UtpDialReq>,
    req_tx: mpsc::Sender<UtpDialReq>,
    connect_half: taiji_io::utp::UtpConnectHalf,
) {
    let _req_keepalive = req_tx;
    while let Some((addr, back)) = req_rx.recv().await {
        // The delegated dial returns the handle immediately (connection
        // success or failure surfaces through the handshake budget); a
        // dropped reply end = the dial task is gone (including a budget
        // timeout returning early) and the handle converges via drop.
        let _ = back.send(Some(connect_half.connect(addr)));
    }
}

/// Consumer-decoupling timing test: while the accept merge channel is under
/// backpressure (full with no consumer), µTP delegated-dial requests are
/// still served by the independent consumer task (the reply returns the
/// handle immediately) — under the old single-task select shape, the accept
/// arm parking in `send().await` froze the dial arm with it (a direct
/// demonstration of the old stall mode). Trade-off note: full engine
/// assembly (wire_dht_and_utp needs the demux/DHT/face chain) is too costly
/// here, so the test drives the production pump functions by name plus a
/// real io listener (the sink-injected form) — the task topology and
/// channel semantics are bit-identical to production.
#[cfg(test)]
mod utp_consumer_split_tests {
    use super::*;
    use taiji_io::utp::InboundPacket;
    use taiji_io::utp::listener::spawn_with_sink;
    use taiji_io::utp::packet::{Header, PacketType};
    use tokio::sync::oneshot;

    /// Test peer addresses (an arbitrary loopback segment — route keys
    /// only, no real packets).
    fn peer_a() -> SocketAddr {
        "127.0.0.1:40971".parse().unwrap_or_else(|e| panic!("{e}"))
    }
    fn peer_b() -> SocketAddr {
        "127.0.0.1:40972".parse().unwrap_or_else(|e| panic!("{e}"))
    }

    /// SYN packet construction (the same parameter shape as the io tests'
    /// `peer_header`).
    fn syn(from: SocketAddr, conn_id: u16) -> InboundPacket {
        let header = Header {
            packet_type: PacketType::Syn,
            extension: 0,
            connection_id: conn_id,
            timestamp_micros: 42,
            timestamp_diff_micros: 0,
            wnd_size: 64 * 1024,
            seq_nr: 1,
            ack_nr: 0,
        };
        InboundPacket {
            from,
            data: taiji_io::utp::packet::encode(&header, None, &[]).freeze(),
        }
    }

    #[tokio::test]
    async fn utp_dial_pump_serves_under_accept_backpressure() {
        // A real listener (sink-injected — routing/accept/outbound connect
        // all real).
        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, _out_rx) = mpsc::channel(64);
        let token = CancellationToken::new();
        let utp_handle = spawn_with_sink(UtpConfig::default(), in_rx, out_tx, token);
        let connect_half = utp_handle.connect_half();
        // Merge channel capacity 1 with the receiver held alive but not
        // consuming: the first send fills it, the second send parks in
        // backpressure (under the old single-task shape this is where the
        // dial arm froze).
        let (accept_tx, _accept_rx_alive) = mpsc::channel::<(SocketAddr, UtpStream)>(1);
        let (req_tx, req_rx) = mpsc::channel::<UtpDialReq>(UTP_DIAL_QUEUE_CAPACITY);
        // The two-task topology mirrors the production wiring (the same as
        // wire_dht_and_utp).
        tokio::spawn(utp_accept_pump(utp_handle, accept_tx.clone()));
        tokio::spawn(utp_dial_pump(req_rx, req_tx.clone(), connect_half));
        // Two inbound SYNs (different sources) -> the accept pump's first
        // send claims the slot, the second parks in backpressure.
        in_tx
            .send(syn(peer_a(), 90))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        in_tx
            .send(syn(peer_b(), 91))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Backpressure-ready check (poll up to 2s): the merge channel is
        // full.
        let deadline = Instant::now() + Duration::from_secs(2);
        while accept_tx.capacity() != 0 {
            assert!(
                Instant::now() < deadline,
                "accept backpressure not in place"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Once reached: the accept pump is parked on the second send. The
        // delegated-dial request must still be served now (the reply returns
        // the handle — Some, the outbound-connect-returns-immediately
        // semantics).
        let (back_tx, back_rx) = oneshot::channel();
        req_tx
            .send((peer_b(), back_tx))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let reply = tokio::time::timeout(Duration::from_secs(3), back_rx)
            .await
            .unwrap_or_else(|e| panic!("delegated-dial reply timeout (accept backpressure parked the delegated-dial arm): {e}"))
            .unwrap_or_else(|e| panic!("reply receiver gone: {e}"));
        assert!(
            reply.is_some(),
            "delegated dial returns the handle immediately (Some) — connect outcome surfaces via the handshake budget"
        );
    }
}
