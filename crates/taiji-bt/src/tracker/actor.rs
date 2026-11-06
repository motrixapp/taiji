//! TrackerActor: the per-torrent/face announce orchestrator (message
//! contract).
//!
//! The pure protocol surface lives in `bt::tracker`: command/event types,
//! DefaultBtAnnounce semantics orchestration, HTTP/UDP client driving; all
//! injected via bounded channels (core wiring = spawn
//! [`spawn_tracker_actor`] + forward events, no protocol-surface changes).
//! Announce scheduling follows libtorrent per-tracker parallel semantics
//! (per-tracker timer state, one wave draining all due trackers per tick,
//! an in-flight cap, strict interval/min_interval compliance); BEP27
//! private torrents collapse to serial single-flight (in-flight cap 1,
//! pinned last-success tracker, failure advances in table order). UDP
//! hosts resolve through the shared [`taiji_io::dns`] layer (literal IPs
//! pass through, per-family faces, the v6 face gated on a global-v6
//! probe). Domain URLs expand to v4+v6 faces; the tier event machine and
//! stopped/completed sequences keep the aria2/AnnounceList semantics.
//!
//! Upstream anchor mapping: docs/design/tracker.md

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

// rand 0.10: the random_range sampling surface lives in RngExt (the old
// Rng renamed); StdRng is built with make_rng
// (SeedableRng::from_os_rng was removed).
use rand::RngExt;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use std::time::Instant;

use super::announce_list::{AnnounceList, AnnounceTier, TierEvent};
use super::dns::{HostResolver, ResolveFamily, SharedDns};
use super::http::{HttpAnnounce, OwnedAnnounceParams, TrackerOptions, apply_interval_settings};
use super::scrape::{ScrapeCache, build_scrape_url, parse_scrape_response};
use super::udp::{UdpAction, UdpEvent, UdpReply, UdpRequest, UdpTrackerClient};
use super::{DEFAULT_NUMWANT, PeerAddr, PeerAddr6, ScrapeStats, TrackerError};

/// Command channel capacity (mpsc(16)).
pub const COMMAND_CHANNEL_CAPACITY: usize = 16;
/// Event channel capacity (mpsc(16)).
pub const EVENT_CHANNEL_CAPACITY: usize = 16;
/// UDP carrier outbound capacity (the demux outbound-channel magnitude).
pub const UDP_OUTBOUND_CAPACITY: usize = 64;
/// UDP carrier inbound capacity (the demux tracker_tx(256) magnitude).
pub const UDP_INBOUND_CAPACITY: usize = 256;
/// Cap on concurrent in-flight announces (the parallelism bound, against
/// self-flooding). Midpoint of an 8-16 selection range; libtorrent's
/// drain loop has no cap (src/torrent.cpp) — this cap is a taiji-local
/// scheduling addition.
pub const ANNOUNCE_MAX_IN_FLIGHT: usize = 12;
/// Internal HTTP/UDP result channel capacity (>= 2x the in-flight cap +
/// scrape headroom: backpressure on in-flight results must not block the
/// request tasks).
const RESULT_CHANNEL_CAPACITY: usize = ANNOUNCE_MAX_IN_FLIGHT * 2 + 8;
/// Polling granularity (an implementation detail, not a protocol
/// constant; tests drive with smaller values).
const TICK: Duration = Duration::from_secs(1);

/// Failure backoff cap = libtorrent `tracker_retry_delay_max`
/// (`src/announce_entry.cpp` `minutes32 constexpr tracker_retry_delay_max{60}`).
const FAILURE_BACKOFF_CAP: Duration = Duration::from_secs(60 * 60);

/// v6 availability probe cache TTL (the gate; the same magnitude as
/// [`super::dns::HOST_CACHE_TTL`] — local v6 connectivity changes
/// converge within one TTL). A gate-closed v6 face retries at this same
/// interval (not the tracker-failure backoff magnitude).
pub(crate) const V6_PROBE_TTL: Duration = Duration::from_secs(5 * 60);

/// Announce failure backoff (a port of libtorrent
/// `announce_infohash::failed`, `src/announce_entry.cpp`): delay =
/// min(60min, 5s + fails^2 * 5s * tracker_backoff/100); in seconds32
/// integer seconds this is 5 + 12*fails^2 (truncated), with
/// tracker_retry_delay_min = 5s and ratio = tracker_backoff default 250
/// (`src/settings_pack.cpp`). fails >= 1; saturating math prevents
/// overflow.
pub(crate) fn failure_backoff(fails: u32) -> Duration {
    let square = fails.saturating_mul(fails);
    let add = u64::from(square).saturating_mul(12);
    Duration::from_secs(5 + add).min(FAILURE_BACKOFF_CAP)
}

/// Issue-to-settle elapsed time (the `elapsed_ms` input of result
/// lines): a missing `attempt_at` means it settled without actually
/// being issued, recorded as 0. Shared by the three settle paths
/// (failure / HTTP ok / UDP ok).
fn attempt_elapsed_ms(attempt_at: Option<Instant>, now: Instant) -> u64 {
    attempt_at
        .map(|t| now.saturating_duration_since(t).as_millis() as u64)
        .unwrap_or(0)
}

/// Engine-side swarm statistics view (bt does not depend on core: the
/// caller injects an implementation; the readings correspond to aria2
/// `PieceStorage`/`NetStat`/`BtRuntime`).
pub trait SwarmView: Send + Sync {
    /// Total length (the denominator of `left = total - completed`).
    fn total_length(&self) -> u64;
    /// Verified completed length.
    fn completed_length(&self) -> u64;
    /// Uploaded this session.
    fn session_uploaded(&self) -> u64;
    /// Downloaded this session.
    fn session_downloaded(&self) -> u64;
    /// All downloads finished (`pieceStorage_->allDownloadFinished()`).
    fn all_download_finished(&self) -> bool;
    /// Fewer peers than the min-peers target (true -> numwant=50).
    fn less_than_min_peers(&self) -> bool;
}

/// Actor commands (TrackerCommand mpsc(16) + oneshot replies).
#[derive(Debug)]
pub enum TrackerCommand {
    /// Try one announce immediately (the event is decided by the internal
    /// state machine, aria2 adjustAnnounceList semantics).
    Announce {
        reply: oneshot::Sender<Result<(), TrackerError>>,
    },
    /// Reset timing and allow periodic announce immediately (aria2
    /// resetAnnounce semantics).
    Reannounce {
        reply: oneshot::Sender<Result<(), TrackerError>>,
    },
    /// Rebuild the tracker table (tier, url) — the engine-level
    /// SetTrackers command surface.
    SetTrackers {
        tiers: Vec<(usize, String)>,
        reply: oneshot::Sender<Result<(), TrackerError>>,
    },
    /// Stop: drive the stopped event sequence until noMoreAnnounce.
    Stop {
        reply: oneshot::Sender<Result<(), TrackerError>>,
    },
    /// Scrape the current successful host immediately (batched).
    Scrape {
        reply: oneshot::Sender<Result<(), TrackerError>>,
    },
}

/// Actor events (named `TrackerActorEvent` to avoid clashing with the
/// frozen surface's `tracker::TrackerEvent`, the announce event-name
/// enum).
#[derive(Debug, Clone)]
pub enum TrackerActorEvent {
    /// Peers discovered (HTTP `peers`/`peers6` or a UDP reply).
    Peers {
        info_hash: [u8; 20],
        peers: Vec<PeerAddr>,
        peers6: Vec<PeerAddr6>,
    },
    /// interval/min-interval updated (tracker table
    /// last_interval/last_min_interval).
    IntervalUpdated { interval: u64, min_interval: u64 },
    /// A single announce failure (tracker table last_error).
    AnnounceFailed { url: String, reason: String },
    /// Scrape result (tracker table seeds/leechers).
    ScrapeResult {
        info_hash: [u8; 20],
        seeds: u64,
        leechers: u64,
    },
    /// The stopped sequence completed (noMoreAnnounce).
    Halted,
}

/// Actor configuration.
#[derive(Debug, Clone)]
pub struct TrackerActorConfig {
    /// The info hash this actor serves (hybrid dual identifiers -> one
    /// actor per face, matching the engine FaceState model; BEP52 joins
    /// both swarms).
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub listen_port: u16,
    pub options: TrackerOptions,
    /// `bt-force-encryption || bt-require-crypto`.
    pub require_crypto: bool,
    /// BEP27 private flag (the engine projection of `info.private` = 1;
    /// BEP27: "private torrents SHOULD NOT be announced to DHT ... each
    /// peer MUST use only one tracker at a time"): true -> announce
    /// scheduling reverts to **serial single-flight** — at most one
    /// tracker of one tier in flight at a time, pinning the successful
    /// tracker until it fails and the table order advances (the
    /// table-order equivalent of aria2's single-flight order, see
    /// [`super::announce_list::AnnounceList`]); false -> libtorrent
    /// parallel waves (docs/design/tracker.md). Always false during the
    /// magnet metadata phase (the private bit lives inside the info dict
    /// and is unknowable before metadata is fetched).
    pub private: bool,
    /// Initial tracker table (tier, url); empty -> no announce.
    pub tiers: Vec<(usize, String)>,
    /// Scrape batch (a same-host batch: all identifiers of the torrent;
    /// defaults to [info_hash]).
    pub scrape_hashes: Vec<[u8; 20]>,
}

impl TrackerActorConfig {
    /// tier list -> groups (`AnnounceList::reconfigure` skips empty
    /// groups; tiers are non-negative, gaps are padded with empty groups
    /// to keep index semantics).
    pub fn tier_groups(tiers: &[(usize, String)]) -> Vec<Vec<String>> {
        let mut sorted = tiers.to_vec();
        sorted.sort_by_key(|(tier, _)| *tier);
        let mut groups: Vec<Vec<String>> = Vec::new();
        let mut prev_tier: Option<usize> = None;
        for (tier, url) in sorted {
            if prev_tier == Some(tier) {
                if let Some(g) = groups.last_mut() {
                    g.push(url);
                }
            } else {
                while groups.len() < tier {
                    groups.push(Vec::new());
                }
                groups.push(vec![url]);
                prev_tier = Some(tier);
            }
        }
        groups
    }
}

/// UDP carrier channels (the stand-in until UdpDemux lands; once ready
/// the demux tracker_tx/outbound channels provide isomorphic endpoints).
pub struct UdpTransport {
    /// Outbound packets (single-writer discipline: the actor only sends;
    /// the demux task is the single writer on the outbound side).
    pub outbound: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    /// Inbound packets (from the demux tracker channel).
    pub inbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
}

/// Internal announce/scrape outcomes.
enum AnnounceOutcome {
    Http {
        /// The slot identity token at issue time (results land by token —
        /// duplicate-URL slots and stale results after a table rebuild
        /// must not be routed by URL first-match).
        token: u64,
        url: String,
        result: Result<super::http::AnnounceResponse, TrackerError>,
    },
    ScrapeHttp {
        result: Result<Vec<([u8; 20], ScrapeStats)>, TrackerError>,
    },
    /// UDP domain pre-resolution returning to the actor (announce side).
    /// Results land by the slot identity token taken at issue time (the
    /// same path as HTTP results); `event` is the per-tier event decision
    /// fixed at issue time (request construction happens when resolution
    /// completes and the event is not recomputed — mirrors the HTTP
    /// owned-parameter move semantics). `family` = the issuing face's
    /// request family (results land in the cache and on the carrier by
    /// family, never across families).
    UdpAnnounceResolve {
        token: u64,
        event: TierEvent,
        url: String,
        host: String,
        port: u16,
        family: ResolveFamily,
        result: Result<IpAddr, String>,
    },
    /// UDP domain pre-resolution returning (scrape side; an attached
    /// surface with no slot ownership).
    UdpScrapeResolve {
        url: String,
        host: String,
        port: u16,
        hashes: Vec<[u8; 20]>,
        family: ResolveFamily,
        result: Result<IpAddr, String>,
    },
}

/// Per-tracker independent announce state (the libtorrent
/// `announce_infohash` shape: `next_announce`/`min_announce`/`fails`/
/// `updating` from `include/libtorrent/aux_/announce_entry.hpp` —
/// per-tracker independent timers are the precondition for in-flight
/// parallelism; see docs/design/tracker.md).
#[derive(Debug)]
struct TrackerSlot {
    url: String,
    /// The configured tier value (the attempt-log convention, the same as
    /// the tracker table row key).
    tier: usize,
    /// Index into the tier event table (for [`Self::tiers`] lookups;
    /// decoupled from the tier value).
    tier_idx: usize,
    /// Slot identity token (monotonically increasing inside the actor;
    /// HTTP results land by token — the alignment with UDP routing by
    /// remote addr. Earlier code matched by URL first, so two slots with
    /// the same URL sent both results to the first slot and the second
    /// stuck in `updating` forever).
    token: u64,
    /// When this slot may announce next (None = never attempted ->
    /// immediately eligible; the same meaning as libtorrent's
    /// `next_announce = min()` initial value, `src/announce_entry.cpp`).
    next_due: Option<Instant>,
    /// In flight (`updating` in `announce_entry.hpp`; the gate forbidding
    /// duplicate announces to one tracker, `can_announce`
    /// `src/announce_entry.cpp`).
    updating: bool,
    /// Consecutive failure count (`fails` in `announce_entry.hpp`; reset
    /// on success, `src/torrent.cpp`).
    fails: u32,
    /// This tracker's latest reply min_interval (seconds) — the
    /// re-announce compliance lower bound (aria2 `DefaultBtAnnounce.cc`,
    /// made per-tracker; protocol red line).
    min_interval: u64,
    /// This tracker's latest reply `interval` (seconds) — the
    /// re-announce period (libtorrent `src/torrent.cpp` `next_announce =
    /// now + interval`; min_interval is only the compliance lower bound —
    /// earlier code wrongly used min_interval as the period and
    /// re-announced more often than the tracker requires). Initial value
    /// = [`TrackerActor::default_interval`].
    interval: u64,
    /// trackerid backfill (per-entry: `src/torrent.cpp`
    /// `ae->trackerid`; the aria2 port had one global value, made
    /// per-tracker under parallel semantics).
    tracker_id: Option<String>,
    /// UDP remote (replies route by addr after issue; None = HTTP).
    udp_addr: Option<SocketAddr>,
    /// UDP carrier family: None = an HTTP slot (or an unparseable URL —
    /// it fails as invalid-url at issue time); Some = a UDP per-family
    /// face (domain URLs expand to v4+v6 faces, literal IPs are
    /// single-face — see [`slot_faces`]; mirrors libtorrent
    /// `announce_entry::endpoints` per-endpoint state,
    /// `include/libtorrent/aux_/announce_entry.hpp`).
    udp_family: Option<ResolveFamily>,
    /// Silent failure: a dual-stack URL's attached v6 face does not enter
    /// the [`TrackerActorEvent::AnnounceFailed`] event surface (a silent
    /// skip + independent backoff; debug logs kept). The v4 primary face
    /// and single-face slots (literal v4/v6 URLs) report as usual.
    silent_failure: bool,
    /// When this attempt was issued (the elapsed_ms log input).
    attempt_at: Option<Instant>,
    /// Already counted toward the terminal sequence's (stopped/completed)
    /// tier failure advance (once per slot — aria2's failure advance
    /// tries each URL once, then the tier end forces the terminal
    /// state).
    walk_counted: bool,
}

/// Tier event state (the AnnounceTier seven-state port, reusing
/// [`AnnounceTier::next_event`]/`next_event_if_after_started`; the URL
/// list is kept for tier-end detection — the halt-sequence equivalent of
/// aria2 `announceFailure`'s tier-end `nextEventIfAfterStarted`
/// (`AnnounceList.cc`)).
struct TierState {
    tier: AnnounceTier,
    /// URLs failed within the stopped sequence (once per slot: aria2's
    /// failure advance tries each URL once, then the tier end forces
    /// HALTED so the stop sequence can complete).
    failed_walk: usize,
}

impl TierState {
    fn event(&self) -> TierEvent {
        self.tier.event
    }
}

/// TrackerActor state machine (an actor-shaped port of
/// DefaultBtAnnounce + TrackerWatcherCommand; announce scheduling follows
/// libtorrent per-tracker parallel semantics — see
/// docs/design/tracker.md). [`Self::run`] exits once every command handle
/// is dropped.
pub struct TrackerActor {
    cfg: TrackerActorConfig,
    view: Arc<dyn SwarmView>,
    /// Tier event state table (tier order = the tier_groups sort order;
    /// empty groups skipped, same as `AnnounceList.cc`).
    tiers: Vec<TierState>,
    /// Per-tracker slot table (table order = tier order, then configured
    /// order within a tier: the wave issue order).
    slots: Vec<TrackerSlot>,
    /// `--bt-tracker-interval` (0 = no override; applied per tracker).
    user_interval: u64,
    halt: bool,
    halted_emitted: bool,
    udp: UdpTrackerClient,
    /// UDP domain resolution shared service (resolver + TTL cache;
    /// default = the process-wide default instance, tests swap in a
    /// separate one via [`Self::with_resolver`]). Cache reads are
    /// per-family projections inside the tick (short lock critical
    /// sections); resolution happens in spawned tasks through the service
    /// — **whole-list backfill happens only inside the service** (the
    /// actor has no cache write path).
    dns: Arc<SharedDns>,
    /// v6 carrier availability override (test seam; None = production:
    /// probe_source_ip(true) measurement).
    v6_probe_override: Option<bool>,
    /// v6 availability cache (available, probed at) (TTL
    /// [`V6_PROBE_TTL`]; None = not probed).
    v6_gate_cache: Option<(bool, Instant)>,
    rng: rand::rngs::StdRng,
    scrape_cache: ScrapeCache,
    http: HttpAnnounce,
    last_ok_url: Option<String>,
    /// Slot identity token counter (allocated by `build_tables`;
    /// monotonically increasing across SetTrackers rebuilds — a stale
    /// in-flight result's token never matches the new table).
    token_seq: u64,
    /// BEP27 private single-flight pinned slot (index; None = not
    /// pinned). The most recently successful tracker stays the only one
    /// in use until it fails (the table-order equivalent of aria2
    /// `announceSuccess` = URL back to the queue front + pointer back to
    /// the first tier, `AnnounceList.cc`; see
    /// [`super::announce_list::AnnounceList`]). Reset with the table on
    /// SetTrackers rebuilds (indices become invalid). Used only on the
    /// `cfg.private` path.
    private_active: Option<usize>,
    cmd_rx: mpsc::Receiver<TrackerCommand>,
    event_tx: mpsc::Sender<TrackerActorEvent>,
    transport: UdpTransport,
    result_tx: mpsc::Sender<AnnounceOutcome>,
    result_rx: mpsc::Receiver<AnnounceOutcome>,
}

/// tier groups -> (tier event state table, per-tracker slot table)
/// (shared by `new` and SetTrackers; empty groups skipped, the same as
/// `AnnounceList.cc` reconfigure; slot order = tier order, then
/// configured order within a tier).
///
/// Two semantics worth noting:
/// - **Duplicate announce URLs fold (first occurrence kept, exact string
/// match)**: a magnet with repeated `tr=` entries (`tasks.rs`
/// enumerates each) can produce two slots with the same URL —
/// libtorrent keeps exactly one `announce_entry` per URL (multiple
/// endpoints), so duplicate entries fold into a single slot. The fold
/// happens at this one sink (the slot-table build), covering the
/// magnet/SetTrackers/global-import entries; the tier event table
/// folds in step (the halt sequence's `failed_walk` count stays
/// consistent with the slots, so the sequence can complete). Exact
/// string match = the same convention as announce issue; no host/port
/// normalization (that is configuration-surface semantics, outside
/// this module).
/// - **Slot identity tokens**: allocated from a monotonically increasing
/// counter inside the actor; after a SetTrackers rebuild, in-flight
/// results from the old table find no landing by token and are dropped
/// (never mislabeled onto new-table slots).
///
/// The tier event table stays at **URL level** (one entry per URL,
/// matching the configuration/event-machine convention); the slot table
/// expands by family — a udp:// domain -> (v4, reporting) + (v6, silent)
/// dual faces (dual-stack announce separately), a literal IP -> a single
/// face, http(s) -> a single slot (no family). Note: the terminal
/// sequence's walk count still converges on the tier's URL count — if
/// one face of a dual-face pair fails first, the count reaches
/// urls.len() and forces the terminal state while the other in-flight
/// face still completes its own sequence with its issue-time event (the
/// next_event terminal transitions are idempotent), so the sequence
/// completes (convergence identical to the old single-face convention).
fn build_tables(
    tiers_cfg: &[(usize, String)],
    token_seq: &mut u64,
) -> (Vec<TierState>, Vec<TrackerSlot>) {
    let mut seen = std::collections::HashSet::new();
    let deduped: Vec<(usize, String)> = tiers_cfg
        .iter()
        .filter(|(_, url)| seen.insert(url.clone()))
        .cloned()
        .collect();
    let mut tiers = Vec::new();
    let mut slots = Vec::new();
    // tier_groups pads with empty groups (index = the configured tier
    // value, see its doc); empty groups are skipped (same as
    // AnnounceList.cc) and the tier event table takes dense indices.
    for (tier_value, urls) in TrackerActorConfig::tier_groups(&deduped)
        .into_iter()
        .enumerate()
    {
        if urls.is_empty() {
            continue;
        }
        let tier_idx = tiers.len();
        for url in &urls {
            for (family, silent) in slot_faces(url) {
                *token_seq += 1;
                slots.push(TrackerSlot {
                    url: url.clone(),
                    tier: tier_value,
                    tier_idx,
                    token: *token_seq,
                    next_due: None,
                    updating: false,
                    fails: 0,
                    min_interval: TrackerActor::default_interval(),
                    interval: TrackerActor::default_interval(),
                    tracker_id: None,
                    udp_addr: None,
                    udp_family: family,
                    silent_failure: silent,
                    attempt_at: None,
                    walk_counted: false,
                });
            }
        }
        tiers.push(TierState {
            tier: AnnounceTier::new(urls.into_iter().collect()),
            failed_walk: 0,
        });
    }
    (tiers, slots)
}

/// Announce URL -> the slot's face set (family + whether failures are
/// silent):
/// - http/https or an unparseable URL -> `[(None, false)]` (a single
/// slot, the existing convention — an unparseable URL fails as
/// invalid-url at issue time);
/// - a udp literal v4/v6 -> a single face (family = the literal family;
/// it is the URL's only carrier -> failures report as usual);
/// - a udp domain -> `[(V4, false), (V6, true)]` (dual-stack announce
/// separately; v6 is the attached face: no AAAA / resolution failure
/// silently skips with independent backoff and does not affect the v4
/// face — libtorrent endpoint failure isolation,
/// `udp_tracker_connection.cpp`).
fn slot_faces(url: &str) -> Vec<(Option<ResolveFamily>, bool)> {
    let Ok(parsed) = super::http::parse_announce_url(url) else {
        return vec![(None, false)];
    };
    match parsed.scheme {
        super::http::Scheme::Udp => match parsed.host.parse::<IpAddr>() {
            Ok(ip) => vec![(Some(ResolveFamily::of_ip(ip)), false)],
            Err(_) => vec![
                (Some(ResolveFamily::V4), false),
                (Some(ResolveFamily::V6), true),
            ],
        },
        super::http::Scheme::Http | super::http::Scheme::Https => vec![(None, false)],
    }
}

impl TrackerActor {
    /// Create ([`spawn_tracker_actor`] assembles and spawns; tests can
    /// drive [`Self::tick`] directly).
    pub fn new(
        cfg: TrackerActorConfig,
        view: Arc<dyn SwarmView>,
        cmd_rx: mpsc::Receiver<TrackerCommand>,
        event_tx: mpsc::Sender<TrackerActorEvent>,
        transport: UdpTransport,
    ) -> Result<Self, TrackerError> {
        let http = HttpAnnounce::new(&cfg.options)?;
        let scrape_hashes = if cfg.scrape_hashes.is_empty() {
            vec![cfg.info_hash]
        } else {
            cfg.scrape_hashes.clone()
        };
        let (result_tx, result_rx) = mpsc::channel(RESULT_CHANNEL_CAPACITY);
        let mut cfg = cfg;
        cfg.scrape_hashes = scrape_hashes;
        let mut token_seq = 0u64;
        let (tiers, slots) = build_tables(&cfg.tiers, &mut token_seq);
        Ok(TrackerActor {
            tiers,
            slots,
            user_interval: cfg.options.bt_tracker_interval,
            halt: false,
            halted_emitted: false,
            udp: UdpTrackerClient::new(),
            dns: SharedDns::shared_default(),
            v6_probe_override: None,
            v6_gate_cache: None,
            rng: rand::make_rng::<rand::rngs::StdRng>(),
            scrape_cache: ScrapeCache::new(Duration::from_secs(15 * 60)),
            last_ok_url: None,
            token_seq,
            private_active: None,
            cfg,
            view,
            cmd_rx,
            event_tx,
            transport,
            http,
            result_tx,
            result_rx,
        })
    }

    /// `DEFAULT_ANNOUNCE_INTERVAL = 2_min` (BtAnnounce.h).
    fn default_interval() -> u64 {
        120
    }

    /// Inject a custom resolver (test seam; default = the process-wide
    /// shared service). Injection builds an **independent** [`SharedDns`]
    /// instance (zero cache sharing with the process default — stub
    /// counts can be asserted both ways, zero cross-test pollution).
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.dns = Arc::new(SharedDns::with_resolver(resolver));
        self
    }

    /// Inject a v6 availability override (test seam): `Some(b)` forces
    /// the gate value (locking behavior on no-real-network,
    /// no-global-v6 environments); `None` (default) = a production
    /// `probe_source_ip(true)` measurement.
    pub fn with_v6_probe_override(mut self, forced: Option<bool>) -> Self {
        self.v6_probe_override = forced;
        self
    }

    /// v6 carrier availability (the gate; async — measures when the TTL
    /// expires). The production convention =
    /// `crate::dht::security::probe_source_ip(true)` (v6 = a time-limited
    /// TCP connect probe); no global v6 -> false — "no probe -> skip the
    /// v6 face". Called only on tokio-driven issue/command paths (the
    /// probe needs a runtime; tests bypass via
    /// [`Self::with_v6_probe_override`]).
    async fn v6_gate(&mut self, now: Instant) -> bool {
        if let Some(forced) = self.v6_probe_override {
            return forced;
        }
        if let Some((ok, at)) = self.v6_gate_cache
            && now.duration_since(at) < V6_PROBE_TTL
        {
            return ok;
        }
        let ok = crate::dht::security::probe_source_ip(true).await.is_some();
        self.v6_gate_cache = Some((ok, now));
        ok
    }

    /// Synchronous read of v6 availability (the latest probe/override
    /// value; not probed = false). For synchronous chains such as
    /// finish_success -> scrape — when an announce just succeeded on the
    /// v6 carrier this is the gate's fresh measurement (seconds old);
    /// the Scrape command entry refreshes via [`Self::v6_gate`] first.
    fn v6_gate_cached(&self) -> bool {
        match self.v6_probe_override {
            Some(forced) => forced,
            None => self.v6_gate_cache.is_some_and(|(ok, _)| ok),
        }
    }

    /// `left = total - completed`.
    fn left(&self) -> u64 {
        self.view
            .total_length()
            .saturating_sub(self.view.completed_length())
    }

    /// numwant decision (full swarm / halt -> 0, otherwise 50). The
    /// threshold semantics of the [`SwarmView::less_than_min_peers`] gate
    /// reading live on the implementation side (engine `FaceView`): the
    /// default is the outbound-target reading ("keep requesting peers
    /// until the outbound target is met", closer to libtorrent's
    /// always-request announce convention); the aria2 value 40 is
    /// reachable via `BH_TRACKER_MIN_PEERS=40` — see engine faces.rs
    /// `tracker_min_peers`. The decision structure itself (halt/full ->
    /// 0) is unchanged, per aria2.
    fn numwant(&self) -> u32 {
        if self.halt || !self.view.less_than_min_peers() {
            0
        } else {
            DEFAULT_NUMWANT
        }
    }

    /// Number of in-flight announces (the parallelism-cap criterion).
    fn in_flight(&self) -> usize {
        self.slots.iter().filter(|s| s.updating).count()
    }

    /// Number of stopped-allowed tiers (aria2 `countStoppedAllowedTier`,
    /// `AnnounceList.cc`; reuses the [`AnnounceList`] predicates).
    fn stopped_allowed_tiers(&self) -> usize {
        self.tiers
            .iter()
            .filter(|t| AnnounceList::stopped_allowed(t.event()))
            .count()
    }

    /// Slot readiness (two of libtorrent `can_announce`'s three gates:
    /// not `updating`, and `max(next_announce, min_announce)` reached
    /// (`src/announce_entry.cpp`; the fail_limit gate is subsumed by the
    /// failure backoff — taiji has no fail_limit option)). Two sequence
    /// events bypass the periodic gate (the interval compliance red line
    /// only constrains periodic re-announces; same as upstream):
    /// - the halt stopped sequence: aria2's halt branch has no timer gate
    /// (`DefaultBtAnnounce.cc`; a shutdown stopped must be delivered
    /// promptly);
    /// - the completed sequence: libtorrent's `need_send_complete`
    /// exception (`src/announce_entry.cpp`) + aria2's completed branch
    /// has no timer gate.
    ///
    /// The periodic/default `next_due` gate is kept as-is; the
    /// "ready-now" of Announce/Reannounce/Stop commands is implemented by
    /// [`Self::force_ready`] rewriting `next_due`. Termination (bounded):
    /// on the periodic path each issue either sets `updating` or pushes
    /// `next_due` past `now`; the sequence paths converge via tier state
    /// (success -> HALTED/SEEDING; failure -> tier-end
    /// nextEventIfAfterStarted, see `finish_failure`).
    fn slot_due(&self, slot: &TrackerSlot, now: Instant) -> bool {
        if slot.updating {
            return false;
        }
        let event = self.tiers[slot.tier_idx].event();
        if self.halt && AnnounceList::stopped_allowed(event) {
            return true;
        }
        if self.view.all_download_finished() && AnnounceList::completed_allowed(event) {
            return true;
        }
        match slot.next_due {
            None => true,
            Some(at) => now >= at,
        }
    }

    /// Ready-now for Announce/Reannounce/Stop commands (the per-tracker
    /// form of aria2 forceDue / resetAnnounce): every non-in-flight slot
    /// becomes immediately eligible next tick (failure backoff resets
    /// too — an explicit user command wins).
    fn force_ready(&mut self, now: Instant) {
        for slot in &mut self.slots {
            if !slot.updating {
                slot.next_due = Some(now);
            }
        }
    }

    /// Next eligible slot (table order = tier order, then configured
    /// order within a tier; the event decision is made per-tier at issue
    /// time — the per-tier counterpart of aria2 `adjustAnnounceList`'s
    /// three branches).
    ///
    /// BEP27 private single-flight gate: the pinned slot (last success,
    /// [`Self::private_active`]) is the **only** candidate — a healthy
    /// tracker's interval wait is no reason to switch trackers (aria2
    /// `announceSuccess` = URL back to the queue front + pointer back to
    /// the first tier, `AnnounceList.cc`; see [`super::announce_list::
    /// AnnounceList`]: after a success the same URL keeps being used
    /// until it fails). If the pinned slot is not in a candidate state
    /// (in flight / inside the periodic gate / terminal event) -> nothing
    /// is issued this round (None), **no fallback to table order** —
    /// falling back would announce to other trackers while pinned,
    /// exactly what BEP27's "use only one tracker at a time" forbids.
    /// Unpinned, table-order advance = aria2 `announceFailure`'s
    /// within-group rotation / across-group order.
    fn next_candidate(&self, now: Instant) -> Option<usize> {
        let finished = self.view.all_download_finished();
        if self.cfg.private
            && let Some(i) = self.private_active
        {
            return self
                .slot_candidate(&self.slots[i], now, finished)
                .then_some(i);
        }
        self.slots
            .iter()
            .position(|slot| self.slot_candidate(slot, now, finished))
    }

    /// Per-slot candidate predicate ([`Self::next_candidate`];
    /// `finished` = a snapshot of swarm completion, taken once and
    /// shared).
    fn slot_candidate(&self, slot: &TrackerSlot, now: Instant, finished: bool) -> bool {
        if !self.slot_due(slot, now) {
            return false;
        }
        let event = self.tiers[slot.tier_idx].event();
        if event == TierEvent::Halted {
            return false;
        }
        if self.halt {
            // The stopped sequence only sends to stopped-allowed tiers
            // (countStoppedAllowedTier + moveToStoppedAllowedTier).
            return AnnounceList::stopped_allowed(event);
        }
        if finished {
            // completed has priority; a STARTED tier (started not yet
            // sent) takes the default branch and becomes
            // STARTED_AFTER_COMPLETION; a SEEDING tier takes the periodic
            // path (earlier only completed-allowed/STARTED were admitted,
            // so a slot whose event had advanced to SEEDING after a
            // completed success was never selected again and seeding-time
            // periodic announces stopped. Reference: aria2
            // `isDefaultAnnounceReady` (DefaultBtAnnounce.cc) does not
            // exclude by event, and SEEDING's event_str = "" is the
            // default periodic event; libtorrent re-announces while
            // seeding (`can_announce` has no seed exclusion,
            // `src/announce_entry.cpp`). The periodic beat is governed by
            // [`Self::slot_due`]'s `next_due` gate).
            return AnnounceList::completed_allowed(event)
                || event == TierEvent::Started
                || event == TierEvent::Seeding;
        }
        true
    }

    /// UDP key = a random value in [0, INT32_MAX] (aria2
    /// `getRandomNumber(INT32_MAX)`).
    fn random_key(&mut self) -> u32 {
        self.rng.random_range(0..=i32::MAX as u32)
    }

    /// Issue slot i's announce (HTTP or UDP, by URL scheme). The event
    /// decision is fixed per-tier at issue time.
    async fn issue_announce(&mut self, i: usize, now: Instant) {
        // Event decision (the per-tier counterpart of aria2
        // adjustAnnounceList).
        let event = {
            let slot = &self.slots[i];
            let tier = &mut self.tiers[slot.tier_idx];
            if self.halt && AnnounceList::stopped_allowed(tier.event()) {
                tier.tier.event = TierEvent::Stopped; // stopped
            } else if self.view.all_download_finished() {
                if AnnounceList::completed_allowed(tier.event()) {
                    tier.tier.event = TierEvent::Completed; // completed
                } else if tier.event() == TierEvent::Started {
                    tier.tier.event = TierEvent::StartedAfterCompletion; // started -> after completion
                }
            }
            tier.event()
        };
        let url = self.slots[i].url.clone();
        {
            let slot = &mut self.slots[i];
            slot.updating = true;
            slot.attempt_at = Some(now);
            slot.udp_addr = None;
        }
        let parsed = match super::http::parse_announce_url(&url) {
            Ok(p) => p,
            Err(e) => {
                warn!(target: "taiji::bt::tracker",
                    url = %super::redact_url_for_log(&url), %e, "bad tracker url");
                self.finish_failure(i, "invalid-url", e.reason(), now);
                return;
            }
        };
        // attempt log: url/scheme/tier/event readable in one line (tier
        // = the configured number, the same as the tracker table row key;
        // multiple URLs sharing a tier value share the number).
        let scheme = match parsed.scheme {
            super::http::Scheme::Http => "http",
            super::http::Scheme::Https => "https",
            super::http::Scheme::Udp => "udp",
        };
        let tier = self.slots[i].tier.to_string();
        debug!(target: "taiji::bt::tracker",
            url = %super::redact_url_for_log(&url), scheme, %tier,
            event = event.event_str(), "announce attempt");
        match parsed.scheme {
            super::http::Scheme::Udp => {
                // Per-family face: literal IP pass-through (used only
                // when the family matches; the isNumericHost pass-through
                // shape of aria2 NameResolveCommand.cc) -> the per-family
                // cache (a hit issues no query) -> on a miss, spawn a
                // per-family resolve task that returns via the result
                // channel (a non-blocking tick; the same decoupling as
                // NameResolveCommand.cc's independent command that only
                // addRequests onSuccess). The slot keeps `updating` and
                // holds in-flight budget (resolve concurrency is bounded
                // by the same cap); results land by token, the same path
                // as HTTP.
                let Some(family) = self.slot_family_or_fail(i, now) else {
                    return;
                };
                // v6 carrier gate: no global v6 locally -> skip the v6
                // face (probe_source_ip(true); a blind v6 announce without
                // a probe is forbidden). Fails as "unavailable" — booked
                // through finish_failure (backoff + the terminal-sequence
                // walk count so the halt sequence can converge); the
                // attached v6 face is silent (silent_failure).
                if family == ResolveFamily::V6 && !self.v6_gate(now).await {
                    self.finish_failure(
                        i,
                        "unavailable",
                        "no global ipv6 (probe_source_ip); v6 carrier skipped".into(),
                        now,
                    );
                    return;
                }
                let literal = parsed
                    .host
                    .parse::<IpAddr>()
                    .ok()
                    .filter(|ip| ResolveFamily::of_ip(*ip) == family);
                let resolved =
                    literal.or_else(|| self.dns.cached_family(&parsed.host, family, now));
                match resolved {
                    Some(ip) => {
                        self.issue_udp_announce(i, ip, parsed.port, event, now);
                        self.drain_udp(now).await;
                    }
                    None => {
                        let dns = self.dns.clone();
                        let result_tx = self.result_tx.clone();
                        let host = parsed.host.clone();
                        let port = parsed.port;
                        let family_arg = family;
                        let token = self.slots[i].token;
                        let resolve_url = url.clone();
                        tokio::spawn(async move {
                            // Resolve through the shared service: a cache
                            // hit (including the whole list just
                            // backfilled by the other face) issues no
                            // query; a miss -> a whole-list query +
                            // whole-list backfill inside the service (the
                            // actor has no write path) -> the per-family
                            // projection.
                            let result = dns.resolve_family(host.clone(), family_arg).await;
                            let _ = result_tx
                                .send(AnnounceOutcome::UdpAnnounceResolve {
                                    token,
                                    event,
                                    url: resolve_url,
                                    host,
                                    port,
                                    family: family_arg,
                                    result,
                                })
                                .await;
                        });
                    }
                }
            }
            super::http::Scheme::Http | super::http::Scheme::Https => {
                let owned = OwnedAnnounceParams {
                    announce_url: url.clone(),
                    info_hash: self.cfg.info_hash,
                    peer_id: self.cfg.peer_id,
                    port: self.cfg.listen_port,
                    uploaded: self.view.session_uploaded(),
                    downloaded: self.view.session_downloaded(),
                    left: self.left(),
                    event,
                    numwant: self.numwant(),
                    tracker_id: self.slots[i].tracker_id.clone(),
                    require_crypto: self.cfg.require_crypto,
                };
                let http = self.http.clone();
                let result_tx = self.result_tx.clone();
                let token = self.slots[i].token;
                tokio::spawn(async move {
                    let result = http.announce_owned(&owned).await;
                    let _ = result_tx
                        .send(AnnounceOutcome::Http {
                            token,
                            url: owned.announce_url.clone(),
                            result,
                        })
                        .await;
                });
            }
        }
    }

    /// Read the slot's carrier family + defense against its absence (one
    /// merged form of the two identical branches in issue_announce /
    /// issue_udp_announce): slot_faces always assigns a family to a
    /// parseable udp URL — unreachable, defensively settled as the
    /// existing invalid-url convention. Returning None = already settled
    /// as failed; the caller returns immediately.
    fn slot_family_or_fail(&mut self, i: usize, now: Instant) -> Option<ResolveFamily> {
        match self.slots[i].udp_family {
            Some(family) => Some(family),
            None => {
                self.finish_failure(
                    i,
                    "invalid-url",
                    "udp tracker slot without carrier family".into(),
                    now,
                );
                None
            }
        }
    }

    /// Build and register the UDP announce request (remote already
    /// resolved; literal IPs and domain resolution results share this
    /// sink). v4/v6 carriers have equal standing (the BEP15 frame surface
    /// is family-agnostic — the former v6 rejection path is removed); a
    /// resolved family not matching the face's requested family = a
    /// resolution-layer fault, settled as the retryable class "dns". If
    /// the same UDP endpoint already has an announce in flight -> yield
    /// this round (no duplicate announce to one tracker; retry next
    /// tick).
    fn issue_udp_announce(
        &mut self,
        i: usize,
        ip: IpAddr,
        port: u16,
        event: TierEvent,
        now: Instant,
    ) {
        let Some(family) = self.slot_family_or_fail(i, now) else {
            return;
        };
        if ResolveFamily::of_ip(ip) != family {
            self.finish_failure(
                i,
                "dns",
                format!(
                    "udp tracker host resolution returned {} address for requested {} face",
                    ResolveFamily::of_ip(ip).as_str(),
                    family.as_str()
                ),
                now,
            );
            return;
        }
        let addr = SocketAddr::new(ip, port);
        if self
            .slots
            .iter()
            .any(|s| s.updating && s.udp_addr == Some(addr))
        {
            let slot = &mut self.slots[i];
            slot.updating = false;
            slot.attempt_at = None;
            slot.next_due = Some(now + TICK);
            return;
        }
        // Request construction per DefaultBtAnnounce.cc.
        let mut req = UdpRequest::announce(addr, self.cfg.info_hash, self.random_key());
        req.peer_id = self.cfg.peer_id;
        req.downloaded = self.view.session_downloaded();
        req.left = self.left();
        req.uploaded = self.view.session_uploaded();
        req.event = match event {
            TierEvent::Started | TierEvent::StartedAfterCompletion => UdpEvent::Started,
            TierEvent::Stopped => UdpEvent::Stopped,
            TierEvent::Completed => UdpEvent::Completed,
            TierEvent::Downloading | TierEvent::Seeding | TierEvent::Halted => UdpEvent::None,
        };
        req.numwant = self.numwant() as i32;
        req.port = self.cfg.listen_port;
        let slot = &mut self.slots[i];
        slot.udp_addr = Some(addr);
        self.udp.add_request(req);
    }

    /// Register a same-endpoint UDP scrape (remote already resolved;
    /// v4/v6 carriers have equal standing — family = the carrier's remote
    /// family, the BEP15 scrape frame is family-agnostic).
    fn add_udp_scrape(&mut self, ip: IpAddr, port: u16, hashes: Vec<[u8; 20]>) {
        self.udp
            .add_request(UdpRequest::scrape(SocketAddr::new(ip, port), hashes));
    }

    /// Announce failure settle (+ TrackerWatcherCommand.cc). The result
    /// line carries the class ([`TrackerError::class`] family) + elapsed
    /// time — a diagnosable "which step failed". Failure handling =
    /// libtorrent per-tracker backoff (`announce_entry.cpp` `failed()`:
    /// fails+1, updating=false, next_announce backs off); a stopped
    /// failure inside the halt sequence additionally advances the tier
    /// URL walk (the tier end forces HALTED, the `AnnounceList.cc`
    /// equivalent — the stop sequence can complete).
    ///
    /// The face field goes into the log (carrier family/HTTP); a
    /// dual-stack URL's attached v6 face (`silent_failure`) is booked but
    /// not reported as an event (silent skip + independent backoff); the
    /// v4 primary face and single-face slots report as usual — otherwise
    /// a v6-only tracker's failures would be invisible and the halt
    /// sequence could not converge.
    fn finish_failure(&mut self, i: usize, class: &'static str, reason: String, now: Instant) {
        let url = self.slots[i].url.clone();
        let face = self.slots[i]
            .udp_family
            .map_or("http", ResolveFamily::as_str);
        let elapsed_ms = attempt_elapsed_ms(self.slots[i].attempt_at, now);
        debug!(target: "taiji::bt::tracker",
            url = %super::redact_url_for_log(&url), face, class, reason, elapsed_ms,
            "announce failed");
        let slot = &mut self.slots[i];
        let silent = slot.silent_failure;
        slot.updating = false;
        slot.attempt_at = None;
        slot.fails = slot.fails.saturating_add(1);
        slot.next_due = Some(now + failure_backoff(slot.fails));
        // Terminal-sequence (stopped/completed) tier failure advance:
        // each slot counts its first failure once; once every URL in the
        // tier has failed once -> force the terminal state (aria2
        // announceFailure's tier-end nextEventIfAfterStarted,
        // AnnounceList.cc: STOPPED -> HALTED, COMPLETED -> SEEDING — the
        // sequence completes and backoff retries are bounded). The
        // periodic path does not count (per-tracker backoff retry,
        // libtorrent semantics).
        let event = self.tiers[slot.tier_idx].event();
        if event == TierEvent::Stopped || event == TierEvent::Completed {
            let tier = &mut self.tiers[slot.tier_idx];
            if !slot.walk_counted {
                slot.walk_counted = true;
                tier.failed_walk += 1;
            }
            if tier.failed_walk >= tier.tier.urls.len() {
                tier.tier.next_event_if_after_started();
            }
        }
        // BEP27 private single-flight unpin: the pinned slot's own
        // failure -> release the only in-use slot; the next candidate
        // advances by table order (aria2 `announceFailure`'s URL/tier
        // advance, AnnounceList.cc — within-group rotation / across-group
        // order).
        if self.cfg.private && self.private_active == Some(i) {
            self.private_active = None;
        }
        // The attached v6 face is silent — bookkeeping/backoff/walk
        // count proceed as usual, only the event surface is suppressed
        // (the log was already emitted by the debug! above).
        if !silent {
            let _ = self
                .event_tx
                .try_send(TrackerActorEvent::AnnounceFailed { url, reason });
        }
    }

    /// Announce success settle (the per-tracker equivalent of
    /// TrackerWatcherCommand.cc's announceSuccess() + resetAnnounce()) +
    /// a same-host scrape. interval booking (red line): libtorrent
    /// `src/torrent.cpp` (next_announce/min_announce/fails). The period:
    /// the user override > the tracker's `interval` (booked as
    /// `max(interval, min_interval)` — the same shape as libtorrent
    /// `can_announce`'s `max(next_announce, min_announce)` in
    /// `src/announce_entry.cpp`; min_interval is the compliance lower
    /// bound). Earlier code wrongly used min_interval as the period (in
    /// aria2's `DefaultBtAnnounce.cc`, minInterval_ is always <=
    /// interval; here it was mistaken for an independent period) and
    /// re-announced more often than the tracker requires; the user
    /// override semantics (aria2 userDefinedInterval) are kept
    /// verbatim.
    fn finish_success(&mut self, i: usize, now: Instant) {
        let url = self.slots[i].url.clone();
        let period = if self.user_interval > 0 {
            self.user_interval
        } else {
            self.slots[i].interval.max(self.slots[i].min_interval)
        };
        let slot = &mut self.slots[i];
        slot.updating = false;
        slot.attempt_at = None;
        slot.fails = 0;
        slot.next_due = Some(now + Duration::from_secs(period));
        let tier = &mut self.tiers[slot.tier_idx];
        tier.tier.next_event(); // announceSuccess event advance (AnnounceList.cc)
        tier.failed_walk = 0;
        self.last_ok_url = Some(url.clone());
        let family = slot.udp_family;
        // BEP27 private single-flight pin: the successful tracker stays
        // the only one in use until it fails (the table-order equivalent
        // of announceSuccess's "URL back to the queue front + pointer
        // back to the first tier"; see [`Self::private_active`]).
        if self.cfg.private {
            self.private_active = Some(i);
        }
        self.issue_scrape(url, family, now);
    }

    /// Batched same-host scrape (HTTP=BEP48 / UDP=BEP15). Under parallel
    /// semantics every successful announce triggers it for its host (the
    /// former single-flight semantics = the last successful host).
    /// `family` = the issuing face's carrier family (None = the HTTP
    /// surface or the Scrape command entry — a UDP domain tries both the
    /// v4 and v6 faces, each failing silently). A UDP domain host goes
    /// through the per-family resolver+cache (the same order as announce:
    /// literal IP pass-through -> a cache hit issues no query -> spawn a
    /// resolve task back to the channel); resolution failure is only a
    /// debug log (scrape is attached to announce and does not enter the
    /// backoff ledger — the same handling as existing scrape failures).
    fn issue_scrape(&mut self, url: String, family: Option<ResolveFamily>, now: Instant) {
        let hashes = self.cfg.scrape_hashes.clone();
        let Ok(parsed) = super::http::parse_announce_url(&url) else {
            return;
        };
        match parsed.scheme {
            super::http::Scheme::Udp => {
                // Literal IP: family = the literal family (a v6 literal
                // passes the gate too — when announce just succeeded on
                // that carrier the cache is necessarily open; the Scrape
                // command entry refreshes it).
                if let Ok(ip) = parsed.host.parse::<IpAddr>() {
                    if ResolveFamily::of_ip(ip) == ResolveFamily::V6 && !self.v6_gate_cached() {
                        return;
                    }
                    self.add_udp_scrape(ip, parsed.port, hashes);
                    return;
                }
                // None (the Scrape command entry, outside the HTTP
                // surface) = try both the v4/v6 faces (each fails
                // silently); Some(f) = the issuing face's family.
                let mut requested: Vec<ResolveFamily> = Vec::with_capacity(2);
                match family {
                    Some(f) => requested.push(f),
                    None => requested.extend([ResolveFamily::V4, ResolveFamily::V6]),
                }
                for f in requested {
                    if f == ResolveFamily::V6 && !self.v6_gate_cached() {
                        continue;
                    }
                    if let Some(ip) = self.dns.cached_family(&parsed.host, f, now) {
                        self.add_udp_scrape(ip, parsed.port, hashes.clone());
                        continue;
                    }
                    let dns = self.dns.clone();
                    let result_tx = self.result_tx.clone();
                    let host = parsed.host.clone();
                    let port = parsed.port;
                    let scrape_url = url.clone();
                    let hashes = hashes.clone();
                    tokio::spawn(async move {
                        let result = dns.resolve_family(host.clone(), f).await;
                        let _ = result_tx
                            .send(AnnounceOutcome::UdpScrapeResolve {
                                url: scrape_url,
                                host,
                                port,
                                hashes,
                                family: f,
                                result,
                            })
                            .await;
                    });
                }
            }
            super::http::Scheme::Http | super::http::Scheme::Https => {
                let Ok(scrape_url) = build_scrape_url(&url, &hashes) else {
                    return;
                };
                let http = self.http.clone();
                let result_tx = self.result_tx.clone();
                tokio::spawn(async move {
                    let result = async {
                        let body = http.get_body(&scrape_url).await?;
                        parse_scrape_response(&body)
                    }
                    .await;
                    let _ = result_tx.send(AnnounceOutcome::ScrapeHttp { result }).await;
                });
            }
        }
    }

    /// HTTP announce success handling (processAnnounceResponse
    /// semantics; interval booked per tracker: libtorrent
    /// `src/torrent.cpp`).
    fn on_http_response(&mut self, i: usize, resp: &super::http::AnnounceResponse, now: Instant) {
        if let Some(tid) = &resp.tracker_id {
            self.slots[i].tracker_id = Some(tid.clone()); // per-entry backfill (torrent.cpp)
        }
        let mut interval = self.slots[i].interval;
        let mut min_interval = self.slots[i].min_interval;
        apply_interval_settings(resp, &mut interval, &mut min_interval); // aria2 interval/min-interval rules
        let slot = &mut self.slots[i];
        slot.interval = interval;
        slot.min_interval = min_interval;
        let url = slot.url.clone();
        let _ = self.event_tx.try_send(TrackerActorEvent::IntervalUpdated {
            interval,
            min_interval,
        });
        if !resp.peers.is_empty() || !resp.peers6.is_empty() {
            let _ = self.event_tx.try_send(TrackerActorEvent::Peers {
                info_hash: self.cfg.info_hash,
                peers: resp.peers.clone(),
                peers6: resp.peers6.clone(),
            });
        }
        let elapsed_ms = attempt_elapsed_ms(slot.attempt_at, now);
        debug!(target: "taiji::bt::tracker",
            url = %super::redact_url_for_log(&url), interval,
            elapsed_ms, "announce ok");
        self.finish_success(i, now);
    }

    /// UDP announce success handling (`processUDPTrackerResponse`).
    fn on_udp_announce_reply(&mut self, i: usize, req: &UdpRequest, now: Instant) {
        let Some(reply) = req.announce_reply() else {
            return;
        };
        if reply.interval > 0 {
            // aria2: minInterval = interval; interval_ = minInterval.
            let v = reply.interval as u64;
            let slot = &mut self.slots[i];
            slot.min_interval = v;
            slot.interval = v;
            let _ = self.event_tx.try_send(TrackerActorEvent::IntervalUpdated {
                interval: v,
                min_interval: v,
            });
        }
        if !reply.peers.is_empty() || !reply.peers6.is_empty() {
            // Peers land in the event fields by carrier family (a v4
            // carrier -> peers, a v6 carrier -> peers6, the other side
            // empty — never mixed; the family surface is in
            // [`super::udp`]).
            let _ = self.event_tx.try_send(TrackerActorEvent::Peers {
                info_hash: self.cfg.info_hash,
                peers: reply.peers.clone(),
                peers6: reply.peers6.clone(),
            });
        }
        // UDP success logs the same result-line shape as HTTP
        // (previously silent).
        let url = self.slots[i].url.clone();
        let elapsed_ms = attempt_elapsed_ms(self.slots[i].attempt_at, now);
        debug!(target: "taiji::bt::tracker",
            url = %super::redact_url_for_log(&url), interval = reply.interval,
            elapsed_ms, "announce ok");
        self.finish_success(i, now);
    }

    /// The in-flight UDP announce slot (replies/timeouts route by
    /// remote).
    fn updating_udp_slot(&self, addr: SocketAddr) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.updating && s.udp_addr == Some(addr))
    }

    /// UDP maintenance: emit frames + retransmit/timeout checks (the
    /// [`super::udp`] port layer).
    async fn drain_udp(&mut self, now: Instant) {
        while let Some((addr, frame)) = self.udp.create_request(&mut self.rng, now) {
            if self.transport.outbound.send((addr, frame)).await.is_err() {
                break;
            }
            self.udp.request_sent(now);
        }
        for req in self.udp.handle_timeout(now) {
            if req.action == UdpAction::Announce
                && let Some(i) = self.updating_udp_slot(req.remote)
            {
                // A UDP timeout = that tracker's announce failed (the
                // TrackerWatcherCommand.cc success()=false path).
                self.finish_failure(i, "timeout", "udp announce timeout".into(), now);
            }
        }
    }

    /// Cache one scrape result and emit it as an event.
    fn record_scrape(&mut self, info_hash: [u8; 20], stats: ScrapeStats, now: Instant) {
        self.scrape_cache.insert(info_hash, stats, now);
        let _ = self.event_tx.try_send(TrackerActorEvent::ScrapeResult {
            info_hash,
            seeds: stats.complete,
            leechers: stats.incomplete,
        });
    }

    /// One step of the driver (called on each tick; tests may call it
    /// directly). Order: results settle (failure fast-forward — results
    /// are processed before the wave issues, so DNS/invalid-url failures
    /// free their slot immediately) -> UDP maintenance -> noMoreAnnounce
    /// -> the parallel wave issues (all due slots drain within the cap).
    pub async fn tick(&mut self, now: Instant) {
        // UDP inbound (replies route to in-flight slots by remote).
        while let Ok((from, data)) = self.transport.inbound.try_recv() {
            match self.udp.receive_reply(from, &data, now) {
                Ok(Some(UdpReply::Announce(req))) => {
                    if let Some(i) = self.updating_udp_slot(req.remote) {
                        self.on_udp_announce_reply(i, &req, now);
                    }
                }
                Ok(Some(UdpReply::Scrape(req))) => {
                    if let Some(entries) = req.scrape_reply() {
                        for e in entries {
                            self.record_scrape(
                                e.info_hash,
                                ScrapeStats {
                                    complete: e.seeders.max(0) as u64,
                                    downloaded: e.completed.max(0) as u64,
                                    incomplete: e.leechers.max(0) as u64,
                                },
                                now,
                            );
                        }
                    }
                }
                Ok(Some(UdpReply::Error { message })) => {
                    if let Some(i) = self.updating_udp_slot(from) {
                        self.finish_failure(
                            i,
                            "tracker-reason",
                            format!("udp tracker error: {message}"),
                            now,
                        );
                    }
                }
                Ok(Some(UdpReply::Connected)) | Ok(None) => {}
                Err(e) => {
                    debug!(target: "taiji::bt::tracker", %e, "bad udp tracker packet");
                }
            }
        }
        // HTTP announce/scrape results. Announces land by the **slot
        // identity token taken at issue time** (URL first-matching is
        // ambiguous under parallel waves for duplicate-URL slots — both
        // results would land on the first slot, the second would stick in
        // updating forever, in_flight would leak, and the wave could be
        // wedged by a repeated tr=; the UDP side already routes by remote
        // addr, HTTP now aligns). A token miss = a stale result from a
        // table rebuild, dropped rather than mislabeling a new-table
        // slot.
        while let Ok(outcome) = self.result_rx.try_recv() {
            match outcome {
                AnnounceOutcome::Http { token, url, result } => {
                    match self
                        .slots
                        .iter()
                        .position(|s| s.token == token && s.updating)
                    {
                        Some(i) => match result {
                            Ok(resp) => self.on_http_response(i, &resp, now),
                            Err(e) => {
                                let class = e.class();
                                self.finish_failure(i, class, e.reason(), now)
                            }
                        },
                        None => debug!(
                            target: "taiji::bt::tracker", %url, token,
                            "stale announce result dropped (no matching in-flight slot)"
                        ),
                    }
                }
                AnnounceOutcome::ScrapeHttp { result } => match result {
                    Ok(entries) => {
                        for (h, stats) in entries {
                            self.record_scrape(h, stats, now);
                        }
                    }
                    Err(e) => {
                        debug!(target: "taiji::bt::tracker", %e, "scrape failed");
                    }
                },
                // UDP domain pre-resolution returning (per family): the
                // announce side lands by slot token (the same path as
                // HTTP; a token miss = a stale post-rebuild result,
                // dropped not mislabeled); Ok issues the announce
                // directly (the cache was already backfilled whole-list
                // inside the shared service — the actor has no write
                // path), Err = the retryable class "dns" (the network
                // class of aria2 NameResolveCommand.cc), not invalid-url
                // (permanent); backoff goes through finish_failure,
                // freeing the slot immediately (an attached v6 face is
                // silent — see finish_failure).
                AnnounceOutcome::UdpAnnounceResolve {
                    token,
                    event,
                    url,
                    host,
                    port,
                    family,
                    result,
                } => match self
                    .slots
                    .iter()
                    .position(|s| s.token == token && s.updating)
                {
                    Some(i) => match result {
                        Ok(ip) => {
                            self.issue_udp_announce(i, ip, port, event, now);
                            self.drain_udp(now).await;
                        }
                        Err(e) => {
                            self.finish_failure(
                                i,
                                "dns",
                                format!("udp tracker host resolution failed: {e}"),
                                now,
                            );
                        }
                    },
                    None => debug!(
                        target: "taiji::bt::tracker", %url, %host, token, family = family.as_str(),
                        "stale udp resolve result dropped (no matching in-flight slot)"
                    ),
                },
                // Scrape side: no slot ownership; Ok issues the scrape
                // directly (cache backfill happens inside the shared
                // service), Err only debug logs.
                AnnounceOutcome::UdpScrapeResolve {
                    url,
                    host,
                    port,
                    hashes,
                    family,
                    result,
                } => match result {
                    Ok(ip) => {
                        self.add_udp_scrape(ip, port, hashes);
                    }
                    Err(e) => debug!(
                        target: "taiji::bt::tracker", %url, %host,
                        family = family.as_str(), class = "dns", reason = %e,
                        "udp scrape host resolution failed"
                    ),
                },
            }
        }
        // UDP maintenance (resend/timeout).
        self.drain_udp(now).await;
        // noMoreAnnounce -> the stopped sequence completes.
        if self.halt
            && self.in_flight() == 0
            && self.stopped_allowed_tiers() == 0
            && !self.halted_emitted
        {
            self.halted_emitted = true;
            let _ = self.event_tx.try_send(TrackerActorEvent::Halted);
            return;
        }
        // Parallel wave issue: within the in-flight cap, drain all due
        // slots in table order (tier order, then configured order) — the
        // libtorrent announce_with_tracker one-round drain,
        // src/torrent.cpp; cap = ANNOUNCE_MAX_IN_FLIGHT.
        // BEP27 private single-flight gate: the cap drops to 1 — at most
        // one tracker of one tier in flight at a time ("each peer MUST
        // use only one tracker at a time"); candidate selection narrows
        // in step (next_candidate prefers the pin), and this gate catches
        // every concurrency path outside the pin (e.g. a table-order
        // fallback while the pinned slot is in flight, or a UDP domain
        // resolve occupying a slot).
        // Termination: each issue path either sets updating or pushes
        // next_due past now (see the slot_due note), so a tick always
        // drains.
        let cap = if self.cfg.private {
            1
        } else {
            ANNOUNCE_MAX_IN_FLIGHT
        };
        while self.in_flight() < cap {
            let Some(i) = self.next_candidate(now) else {
                break;
            };
            self.issue_announce(i, now).await;
        }
    }

    /// Read-only snapshot of the scrape cache (the data source for the
    /// tracker-table persistence side).
    pub fn scrape_cache_len(&self) -> usize {
        self.scrape_cache.len()
    }

    /// Handle a command; returns false to stop running.
    async fn handle_command(&mut self, cmd: TrackerCommand, now: Instant) -> bool {
        match cmd {
            // The Announce/Reannounce branches are verbatim identical
            // (by design): an or-pattern shares one body; the enum
            // variant set is untouched — core sends TrackerCommand, and
            // deleting a variant would be a cross-crate contract
            // change.
            TrackerCommand::Announce { reply } | TrackerCommand::Reannounce { reply } => {
                // resetAnnounce, made per-tracker: every non-in-flight
                // slot becomes ready now (failure backoff resets too — an
                // explicit user retry command).
                self.force_ready(now);
                let _ = reply.send(Ok(()));
            }
            TrackerCommand::SetTrackers { tiers, reply } => {
                self.cfg.tiers = tiers;
                // Rebuild the tier event table + per-tracker slot table
                // (all never-attempted -> the next tick announces per the
                // new table, engine-level edit semantics; the token
                // counter stays monotonic across rebuilds — old-table
                // in-flight results that miss are dropped). The private
                // single-flight pin resets with the table (slot indices
                // are invalid; the new table restarts single-flight from
                // the first candidate in table order).
                self.private_active = None;
                let (t, s) = build_tables(&self.cfg.tiers, &mut self.token_seq);
                self.tiers = t;
                self.slots = s;
                let _ = reply.send(Ok(()));
            }
            TrackerCommand::Stop { reply } => {
                self.halt = true;
                self.force_ready(now); // drive the stopped sequence now
                self.halted_emitted = false; // allow the stopped sequence again
                let _ = reply.send(Ok(()));
            }
            TrackerCommand::Scrape { reply } => {
                if let Some(url) = self.last_ok_url.clone() {
                    // Refresh the UDP v6 face gate first (the
                    // synchronous read feeds issue_scrape).
                    self.v6_gate(Instant::now()).await;
                    self.issue_scrape(url, None, Instant::now());
                }
                let _ = reply.send(Ok(()));
            }
        }
        true
    }

    /// Main loop: exits when all command handles drop (the interval tick
    /// drives the periodic semantics).
    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = cmd else { return; };
                    if !self.handle_command(cmd, Instant::now()).await {
                        return;
                    }
                }
                _ = tick.tick() => {
                    self.tick(Instant::now()).await;
                }
            }
        }
    }
}

/// Assemble and spawn a TrackerActor (the engine wiring point; returns
/// the command sender).
pub fn spawn_tracker_actor(
    cfg: TrackerActorConfig,
    view: Arc<dyn SwarmView>,
    event_tx: mpsc::Sender<TrackerActorEvent>,
    transport: UdpTransport,
) -> Result<mpsc::Sender<TrackerCommand>, TrackerError> {
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let actor = TrackerActor::new(cfg, view, cmd_rx, event_tx, transport)?;
    tokio::spawn(actor.run());
    Ok(cmd_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// Static SwarmView (total 1000 / completed 0 / up 5, down 7).
    struct FixedView;

    impl SwarmView for FixedView {
        fn total_length(&self) -> u64 {
            1000
        }
        fn completed_length(&self) -> u64 {
            0
        }
        fn session_uploaded(&self) -> u64 {
            5
        }
        fn session_downloaded(&self) -> u64 {
            7
        }
        fn all_download_finished(&self) -> bool {
            false
        }
        fn less_than_min_peers(&self) -> bool {
            true
        }
    }

    /// Fake tracker: a local TCP mock dispatching (status, body) by path.
    struct MockTracker {
        addr: SocketAddr,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl MockTracker {
        async fn start(
            handler: impl Fn(&str) -> (String, Vec<u8>) + Send + Sync + 'static,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("bind: {e}"));
            let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
            let handler = Arc::new(handler);
            let tasks = vec![tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        // Read the request head (reqwest HTTP/1.1; once
                        // the head ends the request is complete).
                        let mut req = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            let Ok(n) = sock.read(&mut chunk).await else {
                                return;
                            };
                            if n == 0 {
                                break;
                            }
                            req.extend_from_slice(&chunk[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let text = String::from_utf8_lossy(&req).into_owned();
                        let request_line = text.lines().next().unwrap_or("").to_string();
                        let path = request_line.split(' ').nth(1).unwrap_or("").to_string();
                        let (status, body) = handler(&path);
                        let head = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&body).await;
                        let _ = sock.shutdown().await;
                    });
                }
            })];
            MockTracker { addr, tasks }
        }

        fn url(&self) -> String {
            format!("http://{}/announce", self.addr)
        }
    }

    fn config(tiers: Vec<(usize, String)>) -> TrackerActorConfig {
        TrackerActorConfig {
            info_hash: [0x11; 20],
            peer_id: *b"-TJ0001-AAAAAAAAAAAA",
            listen_port: 6881,
            options: TrackerOptions::default(),
            require_crypto: false,
            private: false,
            tiers,
            scrape_hashes: vec![[0x11; 20]],
        }
    }

    /// (transport, outbound rx, inbound tx) triple (test assembly).
    type TransportParts = (
        UdpTransport,
        mpsc::Receiver<(SocketAddr, Vec<u8>)>,
        mpsc::Sender<(SocketAddr, Vec<u8>)>,
    );

    fn mk_transport() -> TransportParts {
        let (out_tx, out_rx) = mpsc::channel(UDP_OUTBOUND_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(UDP_INBOUND_CAPACITY);
        (
            UdpTransport {
                outbound: out_tx,
                inbound: in_rx,
            },
            out_rx,
            in_tx,
        )
    }

    /// Pump: wait for the spawned HTTP tasks to land, then drive one tick.
    async fn pump(actor: &mut TrackerActor) {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        actor.tick(Instant::now()).await;
    }

    /// Pump (synthetic clock): HTTP tasks land via a real short sleep,
    /// the tick instant is injected by the caller (sleep-free driving
    /// for the interval-compliance tables).
    async fn pump_at(actor: &mut TrackerActor, now: Instant) {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        actor.tick(now).await;
    }

    /// Integration: dual-tier announce — tier0 fails and advances to
    /// tier1 which succeeds -> Peers/IntervalUpdated -> a same-host
    /// scrape -> Stop drives the stopped sequence -> Halted.
    #[tokio::test]
    async fn dual_tier_failover_then_stop_sequence() {
        // tier0: 404 rejection; tier1: an announce response (BEP3+BEP23
        // keys), /scrape answers a BEP48 files dict.
        let bad = MockTracker::start(move |_path| ("404 Not Found".into(), Vec::new())).await;
        let good = MockTracker::start(move |path| {
            if path.starts_with("/scrape") {
                // BEP48: a files dict, key = the raw 20B info_hash.
                let mut body = Vec::from(&b"d5:filesd20:"[..]);
                body.extend_from_slice(&[0x11; 20]);
                body.extend_from_slice(b"d8:completei42e10:downloadedi7e10:incompletei3eeee");
                ("200 OK".into(), body)
            } else {
                // bencode dict keys must ascend: complete < incomplete
                // < interval < min interval < peers < tracker id.
                let body = Vec::from(
                    &b"d8:completei9e10:incompletei3e8:intervali1800e\
                       12:min intervali900e5:peers6:\x7F\x00\x00\x01\x1A\xE1\
                       10:tracker id3:abce"[..],
                );
                ("200 OK".into(), body)
            }
        })
        .await;

        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, bad.url()), (1, good.url())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // tick1: the tier0 announce (started) -> a 404 failure; tier1
        // advances within the same tick.
        actor.tick(Instant::now()).await;
        pump(&mut actor).await; // tier0's failure lands + tier1's announce issues
        pump(&mut actor).await; // tier1 succeeds -> events + scrape issue
        pump(&mut actor).await; // the scrape result lands

        let mut saw_fail = false;
        let mut saw_interval = false;
        let mut saw_peers = false;
        let mut saw_scrape = false;
        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TrackerActorEvent::AnnounceFailed { url, reason } => {
                    assert_eq!(url, bad.url(), "the failure was tier0 (reason={reason})");
                    saw_fail = true;
                }
                TrackerActorEvent::IntervalUpdated {
                    interval,
                    min_interval,
                } => {
                    assert_eq!((interval, min_interval), (1800, 900), "min(900,1800)");
                    saw_interval = true;
                }
                TrackerActorEvent::Peers {
                    info_hash,
                    peers,
                    peers6,
                } => {
                    assert_eq!(info_hash, [0x11; 20]);
                    assert_eq!(peers.len(), 1);
                    assert_eq!(peers[0].ip.to_string(), "127.0.0.1");
                    assert!(peers6.is_empty());
                    saw_peers = true;
                }
                TrackerActorEvent::ScrapeResult {
                    info_hash,
                    seeds,
                    leechers,
                } => {
                    assert_eq!(info_hash, [0x11; 20]);
                    assert_eq!((seeds, leechers), (42, 3), "BEP48 complete/incomplete");
                    saw_scrape = true;
                }
                TrackerActorEvent::Halted => panic!("Halted must not arrive before Stop"),
            }
        }
        assert!(
            saw_fail && saw_interval && saw_peers && saw_scrape,
            "all four event kinds present"
        );

        // Stop -> the stopped sequence: the only stopped-allowed tier1
        // -> event=stopped -> HALTED after success -> noMoreAnnounce ->
        // the Halted event.
        let (stx, srx) = oneshot::channel();
        actor
            .handle_command(TrackerCommand::Stop { reply: stx }, Instant::now())
            .await;
        assert!(srx.await.is_ok());
        pump(&mut actor).await;
        pump(&mut actor).await;
        let halted = std::iter::from_fn(|| event_rx.try_recv().ok())
            .any(|ev| matches!(ev, TrackerActorEvent::Halted));
        assert!(
            halted,
            "a completed stopped sequence must emit Halted (noMoreAnnounce)"
        );
        for t in bad.tasks {
            t.abort();
        }
        for t in good.tasks {
            t.abort();
        }
    }

    /// The UDP carrier over a duplex channel: the full connect ->
    /// announce chain + event feedback.
    #[tokio::test]
    async fn udp_announce_over_duplex_channel() {
        let tracker: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1337));
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, format!("udp://{tracker}/announce"))]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // tick: the CONNECT frame goes out.
        actor.tick(Instant::now()).await;
        let (to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("connect frame"));
        assert_eq!(to, tracker);
        assert_eq!(&frame[8..12], &0i32.to_be_bytes());
        let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
        // The fake tracker answers CONNECT.
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_be_bytes());
        reply.extend_from_slice(&tid.to_be_bytes());
        reply.extend_from_slice(&0xdead_c0de_dead_c0deu64.to_be_bytes());
        in_tx
            .send((tracker, reply))
            .await
            .unwrap_or_else(|_| panic!("in"));
        // tick: CONNECT is booked -> the ANNOUNCE frame goes out.
        actor.tick(Instant::now()).await;
        let (to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("announce frame"));
        assert_eq!(to, tracker);
        assert_eq!(&frame[0..8], &0xdead_c0de_dead_c0deu64.to_be_bytes());
        assert_eq!(&frame[8..12], &1i32.to_be_bytes());
        let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
        // Frame-body assertions (DefaultBtAnnounce.cc semantics
        // injected).
        assert_eq!(&frame[16..36], &[0x11; 20], "info_hash");
        assert_eq!(&frame[36..56], b"-TJ0001-AAAAAAAAAAAA");
        assert_eq!(&frame[56..64], &7u64.to_be_bytes(), "downloaded");
        assert_eq!(&frame[64..72], &1000u64.to_be_bytes(), "left");
        assert_eq!(&frame[72..80], &5u64.to_be_bytes(), "uploaded");
        assert_eq!(&frame[80..84], &2i32.to_be_bytes(), "event=started");
        assert_eq!(&frame[92..96], &50i32.to_be_bytes(), "numwant=50");
        assert_eq!(&frame[96..98], &6881u16.to_be_bytes(), "port");
        // The fake tracker answers ANNOUNCE (interval 600 / leechers 2 /
        // seeders 3 + 1 peer).
        let mut reply = Vec::new();
        reply.extend_from_slice(&1i32.to_be_bytes());
        reply.extend_from_slice(&tid.to_be_bytes());
        reply.extend_from_slice(&600i32.to_be_bytes());
        reply.extend_from_slice(&2i32.to_be_bytes());
        reply.extend_from_slice(&3i32.to_be_bytes());
        reply.extend_from_slice(&[10, 0, 0, 9, 0x1a, 0xe1]);
        in_tx
            .send((tracker, reply))
            .await
            .unwrap_or_else(|_| panic!("in"));
        actor.tick(Instant::now()).await;

        let mut saw_interval = false;
        let mut saw_peers = false;
        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TrackerActorEvent::IntervalUpdated {
                    interval,
                    min_interval,
                } => {
                    // aria2: minInterval = interval; interval_ = minInterval.
                    assert_eq!((interval, min_interval), (600, 600));
                    saw_interval = true;
                }
                TrackerActorEvent::Peers { peers, .. } => {
                    assert_eq!(peers.len(), 1);
                    assert_eq!(peers[0].ip.to_string(), "10.0.0.9");
                    saw_peers = true;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(saw_interval && saw_peers);
    }

    /// SetTrackers command surface (engine level): after the rebuild the
    /// new URL announces; an empty table does not announce.
    #[tokio::test]
    async fn set_trackers_rebuilds_announce_list() {
        let good = MockTracker::start(move |_path| {
            let mut body = Vec::from(&b"d8:intervali60e5:peersle"[..]);
            body.push(b'e');
            ("200 OK".into(), body)
        })
        .await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        actor.tick(Instant::now()).await;
        assert!(
            actor.last_ok_url.is_none(),
            "an empty table does not announce"
        );
        actor
            .handle_command(
                TrackerCommand::SetTrackers {
                    tiers: vec![(0, good.url())],
                    reply: {
                        let (tx, _rx) = oneshot::channel();
                        tx
                    },
                },
                Instant::now(),
            )
            .await;
        actor.tick(Instant::now()).await;
        pump(&mut actor).await;
        assert_eq!(actor.last_ok_url.as_deref(), Some(good.url().as_str()));
        for t in good.tasks {
            t.abort();
        }
    }

    // ===== attempt/result observability (kept surface) =====

    /// An all-404 mock recording the request order by server index (for
    /// table-driven tests).
    async fn start_404_recorder(
        order: Arc<std::sync::Mutex<Vec<usize>>>,
        idx: usize,
    ) -> MockTracker {
        MockTracker::start(move |_path| {
            if let Ok(mut o) = order.lock() {
                o.push(idx);
            }
            ("404 Not Found".into(), Vec::new())
        })
        .await
    }

    // ===== discovery-surface parallelization (scheduling change + locks) =====

    /// Announce failure backoff table (libtorrent
    /// `announce_infohash::failed` values: `src/announce_entry.cpp`,
    /// min=5s, max=60min, ratio = tracker_backoff default 250
    /// (`src/settings_pack.cpp`); seconds32 integer seconds ->
    /// 5 + 12*fails^2, capped at 3600s).
    #[test]
    fn announce_failure_backoff_table() {
        let cases: [(u32, u64); 8] = [
            (1, 17),
            (2, 53),
            (3, 113),
            (4, 197),
            (10, 1205),
            (17, 3473),
            (18, 3600),       // 5 + 12*324 = 3893 -> capped at 3600
            (u32::MAX, 3600), // the saturating path must not overflow or panic
        ];
        for (fails, want_s) in cases {
            assert_eq!(
                failure_backoff(fails),
                Duration::from_secs(want_s),
                "fails={fails}"
            );
        }
        assert_eq!(failure_backoff(u32::MAX), FAILURE_BACKOFF_CAP);
    }

    /// Locks that the first round attempts every tracker in parallel
    /// (table-driven).
    ///
    /// # Semantics-upgrade note
    ///
    /// This test's predecessor locked aria2's single-flight serial order
    /// (expected = the strict request order [0,1,2]). Scheduling changed
    /// by design to libtorrent per-tracker parallelism
    /// (`announce_with_tracker` drains all due trackers in one round,
    /// `src/torrent.cpp`; under parallelism the arrival order is
    /// non-deterministic and a strict-order assertion no longer holds),
    /// upgraded to the stronger assertion: **within the first round (one
    /// tick's wave) every tracker is attempted exactly once** — the
    /// serial form needed N failure-advance cycles to achieve that, so
    /// this assertion was necessarily false under the old semantics;
    /// strictly stronger. The "no immediate resend after an all-failure
    /// backoff" property is kept (the per-tracker backoff gate,
    /// `can_announce`, `src/announce_entry.cpp`).
    #[tokio::test]
    async fn first_round_all_trackers_attempted_table() {
        /// Table cases: (tier, server index) inputs (contiguous tiers /
        /// wide tier gaps / unordered input / multiple URLs per tier).
        type TierCase = &'static [(usize, usize)];
        let cases: &[TierCase] = &[
            &[(0, 0), (1, 1), (2, 2)],
            &[(0, 0), (33, 1)],
            &[(33, 0), (0, 1)],
            &[(0, 0), (0, 1)],
        ];
        for tiers in cases {
            let order = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut servers = Vec::new();
            for (i, _) in tiers.iter().enumerate() {
                servers.push(start_404_recorder(order.clone(), i).await);
            }
            let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
            let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
            let (transport, _out_rx, _in_tx) = mk_transport();
            let mut actor = TrackerActor::new(
                config(tiers.iter().map(|(t, s)| (*t, servers[*s].url())).collect()),
                Arc::new(FixedView),
                cmd_rx,
                event_tx,
                transport,
            )
            .unwrap_or_else(|e| panic!("{e}"));

            // First round: a single tick's wave issues all of them (the
            // parallel cap >= the case size); repeated pumps settle the
            // 404 failures.
            actor.tick(Instant::now()).await;
            for _ in 0..=tiers.len() {
                pump(&mut actor).await;
            }
            let got = order.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let mut want: Vec<usize> = (0..tiers.len()).collect();
            want.sort_unstable();
            let mut got_sorted = got.clone();
            got_sorted.sort_unstable();
            assert_eq!(
                got_sorted, want,
                "the first round tries each tracker once: tiers={tiers:?} got={got:?}"
            );
            // Failure backoff (per-tracker next_due) -> no immediate
            // resend.
            pump(&mut actor).await;
            assert_eq!(
                order.lock().unwrap_or_else(|e| e.into_inner()).len(),
                want.len(),
                "no immediate resend after an all-fail backoff: tiers={tiers:?}"
            );
            for s in servers {
                for t in s.tasks {
                    t.abort();
                }
            }
        }
    }

    /// Holding mock: accepts the connection, reads the request head,
    /// then never responds (for measuring in-flight parallelism).
    /// Records arrival indices; `current`/`max` are the server-visible
    /// concurrent in-flight request counts.
    async fn start_holding_tracker(
        idx: usize,
        hits: Arc<std::sync::Mutex<Vec<usize>>>,
        current: Arc<std::sync::atomic::AtomicUsize>,
        max: Arc<std::sync::atomic::AtomicUsize>,
    ) -> MockTracker {
        use std::sync::atomic::Ordering;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let tasks = vec![tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let hits = hits.clone();
                let current = current.clone();
                let max = max.clone();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        let Ok(n) = sock.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            break;
                        }
                        req.extend_from_slice(&chunk[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    if let Ok(mut h) = hits.lock() {
                        h.push(idx);
                    }
                    let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                    max.fetch_max(now, Ordering::SeqCst);
                    // Hold without responding (the announce stays in
                    // flight; the test tears down with the runtime).
                    std::future::pending::<()>().await;
                });
            }
        })];
        MockTracker { addr, tasks }
    }

    /// Parallelism cap, table-driven: one tick's wave issues at most
    /// [`ANNOUNCE_MAX_IN_FLIGHT`] in flight (corroborated by the
    /// server-visible concurrency count); slots beyond the cap, in table
    /// order (tier order, then configured order), wait for a slot to
    /// free.
    #[tokio::test]
    async fn parallel_wave_bounded_by_in_flight_cap_table() {
        use std::sync::atomic::Ordering;
        type CapCase = (usize, usize); // (tracker count, expected first wave)
        let cases: &[CapCase] = &[
            (5, 5),
            (ANNOUNCE_MAX_IN_FLIGHT, ANNOUNCE_MAX_IN_FLIGHT),
            (ANNOUNCE_MAX_IN_FLIGHT + 8, ANNOUNCE_MAX_IN_FLIGHT),
        ];
        for (n, want_first_wave) in cases {
            let hits = Arc::new(std::sync::Mutex::new(Vec::new()));
            let current = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let max = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut servers = Vec::new();
            for i in 0..*n {
                servers.push(
                    start_holding_tracker(i, hits.clone(), current.clone(), max.clone()).await,
                );
            }
            let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
            let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
            let (transport, _out_rx, _in_tx) = mk_transport();
            let mut actor = TrackerActor::new(
                config((0..*n).map(|t| (0, servers[t].url())).collect()),
                Arc::new(FixedView),
                cmd_rx,
                event_tx,
                transport,
            )
            .unwrap_or_else(|e| panic!("{e}"));

            actor.tick(Instant::now()).await;
            // Wait for the whole first wave to arrive (the holding mock
            // never responds; an arrival counts as in flight).
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let arrived = hits.lock().unwrap_or_else(|e| e.into_inner()).len();
                if arrived >= *want_first_wave || Instant::now() > deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                actor.in_flight(),
                *want_first_wave,
                "first wave in-flight = min(n, CAP): n={n}"
            );
            let got = hits.lock().unwrap_or_else(|e| e.into_inner()).clone();
            assert_eq!(
                got.len(),
                *want_first_wave,
                "those beyond the cap never issue: n={n} got={got:?}"
            );
            // Table order: the first want_first_wave slots (tier order)
            // issue first.
            let mut seen = got.clone();
            seen.sort_unstable();
            assert_eq!(
                seen,
                Vec::from_iter(0..*want_first_wave),
                "issued in table order: n={n}"
            );
            assert!(
                max.load(Ordering::SeqCst) <= ANNOUNCE_MAX_IN_FLIGHT,
                "server-visible concurrency <= CAP"
            );
            for s in servers {
                for t in s.tasks {
                    t.abort();
                }
            }
        }
    }

    /// Failure fast-forward ("a DNS failure does not wait for the
    /// timeout"): the first wave = a cap's worth of instantly-failing
    /// trackers (closed local ports, connect refused fails immediately);
    /// once the results settle the same wave refills with the remainder
    /// (a good tracker) — no idle timeout wait inside the capped
    /// batch.
    #[tokio::test]
    async fn failure_fast_forward_refills_cap_wave() {
        // Create ANNOUNCE_MAX_IN_FLIGHT closed ports (bind then drop).
        let mut closed = Vec::new();
        for _ in 0..ANNOUNCE_MAX_IN_FLIGHT {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("bind: {e}"));
            closed.push(l.local_addr().unwrap_or_else(|e| panic!("{e}")));
        }
        let good = MockTracker::start(move |_path| {
            let mut body = Vec::from(&b"d8:intervali60e5:peersle"[..]);
            body.push(b'e');
            ("200 OK".into(), body)
        })
        .await;
        let mut tiers: Vec<(usize, String)> = closed
            .iter()
            .enumerate()
            .map(|(t, a)| (t, format!("http://{a}/announce")))
            .collect();
        tiers.push((ANNOUNCE_MAX_IN_FLIGHT, good.url()));

        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(tiers),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        actor.tick(Instant::now()).await; // first wave = a cap's worth of closed
        pump(&mut actor).await; // 12 failures land + the good tracker refills
        pump(&mut actor).await; // the good tracker succeeds

        let mut failed = 0;
        let mut ok = false;
        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TrackerActorEvent::AnnounceFailed { .. } => failed += 1,
                TrackerActorEvent::IntervalUpdated { .. } => ok = true,
                _ => {}
            }
        }
        assert_eq!(
            failed, ANNOUNCE_MAX_IN_FLIGHT,
            "the whole first wave fails instantly"
        );
        assert!(
            ok,
            "the good tracker succeeds once failures advance the wave"
        );
        assert_eq!(actor.last_ok_url.as_deref(), Some(good.url().as_str()));
        for t in good.tasks {
            t.abort();
        }
    }

    // ===== BEP27 private torrent single-flight gate =====

    /// Private-mode config: the public [`config`] + the private bit (the
    /// engine projection of BEP27 `info.private` = 1).
    fn private_config(tiers: Vec<(usize, String)>) -> TrackerActorConfig {
        let mut cfg = config(tiers);
        cfg.private = true;
        cfg
    }

    /// BEP27 "each peer MUST use only one tracker at a time": with
    /// private=true at most one announce is in flight at a time. With
    /// two holding trackers (they never respond after the request
    /// arrives, so in-flight never settles): the first wave hits only
    /// the first tracker in table order, and the second sees zero
    /// requests while the first is in flight; the public config under
    /// the same scenario double-fires in the first round (the parallel
    /// contrast locked by
    /// `parallel_wave_bounded_by_in_flight_cap_table`).
    #[tokio::test]
    async fn private_torrent_announces_one_tracker_at_a_time() {
        use std::sync::atomic::Ordering;
        let hits0 = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
        let current = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h0 = start_holding_tracker(0, hits0.clone(), current.clone(), max.clone()).await;
        let h1 = start_holding_tracker(1, hits0.clone(), current.clone(), max.clone()).await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            private_config(vec![(0, h0.url()), (1, h1.url())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        actor.tick(Instant::now()).await;
        assert_eq!(
            actor.in_flight(),
            1,
            "single-flight: exactly one in flight in the first wave"
        );
        // Wait for the first request to reach the server (holding mock:
        // an arrival means in flight, never settling).
        let deadline = Instant::now() + Duration::from_secs(2);
        while hits0.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Second tick: the first slot is still in flight -> the second
        // tracker must not be issued.
        actor.tick(Instant::now()).await;
        let got = hits0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            got,
            vec![0],
            "only the first tracker in table order is requested: {got:?}"
        );
        assert_eq!(
            actor.in_flight(),
            1,
            "always 1 in flight (no second tracker issued)"
        );
        assert_eq!(
            max.load(Ordering::SeqCst),
            1,
            "server-visible concurrency = 1"
        );
        for s in [h0, h1] {
            for t in s.tasks {
                t.abort();
            }
        }
    }

    /// Companion case: private success pins + failure advances — the
    /// table-order equivalent of aria2's single-flight order (see
    /// [`super::announce_list::AnnounceList`]: `announceSuccess` = URL
    /// back to the queue front + pointer back to the first tier
    /// (AnnounceList.cc) => the successful tracker keeps being used
    /// until it fails; `announceFailure` advances => within-group
    /// rotation / across-group order). tier0's first success
    /// (interval=5s) -> zero requests to the second tracker within the
    /// period; tier0 turning bad -> only after the failure advance does
    /// tier1 get its first hit.
    #[tokio::test]
    async fn private_torrent_pins_working_tracker_advances_on_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        // tier0: ok=true -> 200 (interval=5s); ok=false -> 404. Starts
        // true (the first send succeeds), flipped to false before t0+5s
        // (the due resend fails).
        let a_ok_phase = Arc::new(AtomicBool::new(true));
        let a_hits = Arc::new(std::sync::Mutex::new(0usize));
        let (a_ok_in, a_hits_in) = (a_ok_phase.clone(), a_hits.clone());
        let a = MockTracker::start(move |path| {
            if path.starts_with("/announce")
                && let Ok(mut h) = a_hits_in.lock()
            {
                *h += 1;
            }
            if a_ok_in.load(Ordering::SeqCst) {
                let mut body = Vec::from(&b"d8:intervali5e5:peersle"[..]);
                body.push(b'e');
                ("200 OK".into(), body)
            } else {
                ("404 Not Found".into(), Vec::new())
            }
        })
        .await;
        // tier1: a 404 recorder (it only proves "when it is first hit";
        // success/failure is irrelevant).
        let b_hits = Arc::new(std::sync::Mutex::new(0usize));
        let b_hits_in = b_hits.clone();
        let b = MockTracker::start(move |path| {
            if path.starts_with("/announce")
                && let Ok(mut h) = b_hits_in.lock()
            {
                *h += 1;
            }
            ("404 Not Found".into(), Vec::new())
        })
        .await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            private_config(vec![(0, a.url()), (1, b.url())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // t0: tier0's first send succeeds (interval=5s -> pinned).
        let t0 = Instant::now();
        actor.tick(t0).await;
        assert_eq!(actor.in_flight(), 1);
        pump_at(&mut actor, t0).await;
        assert_eq!(
            a_hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            1,
            "tier0's first send happens exactly once"
        );
        assert_eq!(
            actor.in_flight(),
            0,
            "back to zero after a successful settle"
        );

        // t0+2s (inside the interval gate): no new requests at all —
        // within the pinned tracker's period gate, no rotation to other
        // trackers (the aria2 announceSuccess queue-front semantics).
        actor.tick(t0 + Duration::from_secs(2)).await;
        pump_at(&mut actor, t0 + Duration::from_secs(2)).await;
        assert_eq!(
            a_hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            1,
            "tier0 does not resend while pinned (the min_interval/interval compliance gate)"
        );
        assert_eq!(
            b_hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            0,
            "tier1 gets zero requests while pinned (success does not rotate)"
        );

        // tier0 turns bad -> the t0+5s due resend fails -> the failure
        // advances; the next tick gives tier1 its first hit (table-order
        // advance: across-group order).
        a_ok_phase.store(false, Ordering::SeqCst);
        let t5 = t0 + Duration::from_secs(5);
        actor.tick(t5).await;
        assert_eq!(actor.in_flight(), 1, "still single-flight (tier0 only)");
        pump_at(&mut actor, t5).await; // tier0's failure lands
        assert_eq!(
            a_hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            2,
            "tier0's due resend happens exactly once"
        );
        actor.tick(t5 + Duration::from_secs(1)).await;
        assert_eq!(
            actor.in_flight(),
            1,
            "tier1 issued on the advance (single-flight)"
        );
        pump_at(&mut actor, t5 + Duration::from_secs(1)).await;
        assert_eq!(
            b_hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            1,
            "tier1 first hit only after tier0's failure"
        );
        assert_eq!(actor.in_flight(), 0, "both slots settled");
        for s in [a, b] {
            for t in s.tasks {
                t.abort();
            }
        }
    }

    /// Delayed-response mock (for the first-announce parallelism
    /// assertion): records request arrival times, answers announce ok
    /// (empty peers) after the delay.
    async fn start_delayed_ok(
        arrivals: Arc<std::sync::Mutex<Vec<(usize, std::time::Instant)>>>,
        idx: usize,
        delay: Duration,
    ) -> MockTracker {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let tasks = vec![tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let arrivals = arrivals.clone();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        let Ok(n) = sock.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            break;
                        }
                        req.extend_from_slice(&chunk[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    // Count only announce requests (the post-success
                    // same-host scrape is not an in-flight announce).
                    let text = String::from_utf8_lossy(&req);
                    let request_line = text.lines().next().unwrap_or("");
                    if !request_line.contains("/announce") {
                        return;
                    }
                    if let Ok(mut a) = arrivals.lock() {
                        a.push((idx, std::time::Instant::now()));
                    }
                    tokio::time::sleep(delay).await;
                    let mut body =
                        Vec::from(&b"d8:intervali1800e12:min intervali900e5:peersle"[..]);
                    body.push(b'e');
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        })];
        MockTracker { addr, tasks }
    }

    /// The first-announce time = the fastest tracker (the target
    /// property): the slow tracker (tier 0, 600ms) no longer blocks the
    /// fast one (tier 1, 100ms) — under the serial form the first
    /// announce takes >= 600ms (tier 0 sends and answers first); under
    /// the parallel form it is ~100ms and both requests issue in the
    /// same wave.
    #[tokio::test]
    async fn first_announce_latency_is_fastest_tracker() {
        let arrivals = Arc::new(std::sync::Mutex::new(Vec::new()));
        let slow = start_delayed_ok(arrivals.clone(), 0, Duration::from_millis(600)).await;
        let fast = start_delayed_ok(arrivals.clone(), 1, Duration::from_millis(100)).await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, slow.url()), (1, fast.url())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let started = std::time::Instant::now();
        actor.tick(started).await; // both trackers issue in one wave (the serial form only sends tier 0)

        // The first announce (the first IntervalUpdated) arrives within
        // the fast tracker's delay.
        let deadline = started + Duration::from_secs(3);
        let mut first_ok: Option<Duration> = None;
        let mut oks = 0;
        while std::time::Instant::now() < deadline && oks < 2 {
            pump(&mut actor).await;
            while let Ok(ev) = event_rx.try_recv() {
                if matches!(ev, TrackerActorEvent::IntervalUpdated { .. }) {
                    oks += 1;
                    if first_ok.is_none() {
                        first_ok = Some(started.elapsed());
                    }
                }
            }
        }
        let first_ok = first_ok.unwrap_or_else(|| panic!("the first announce never arrived"));
        assert!(
            first_ok < Duration::from_millis(400),
            "the first announce = the fastest tracker's latency scale: {first_ok:?} (the serial form is >= 600ms)"
        );
        assert_eq!(oks, 2, "both trackers succeed");

        // Same-wave parallel issue: the arrival gap is far smaller than
        // the slow tracker's delay (the serial form only sends tier 1
        // after tier 0 responds, gap >= 600ms).
        let got = arrivals.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(got.len(), 2, "both requests arrived: {got:?}");
        let (mut lo, mut hi) = (Duration::ZERO, Duration::ZERO);
        for (_, at) in &got {
            let e = at.saturating_duration_since(started);
            lo = lo.min(e);
            hi = hi.max(e);
        }
        assert!(
            hi - lo < Duration::from_millis(300),
            "issued in parallel within the same wave (arrival gap < 300ms): {got:?}"
        );
        for s in [slow, fast] {
            for t in s.tasks {
                t.abort();
            }
        }
    }

    /// interval/min_interval compliance regression table (protocol red
    /// line): after parallelization each tracker's re-announce period is
    /// still gated by its own min_interval lower bound (libtorrent
    /// `can_announce`, `src/announce_entry.cpp`).
    ///
    /// The period was originally booked as the tracker min_interval,
    /// which re-announced too early relative to interval; fixed to the
    /// tracker `interval` (libtorrent `src/torrent.cpp`; after aria2's
    /// min-interval clamp, min_interval is always <= interval and stays
    /// as the compliance lower bound via `max`). The mock reply's
    /// `interval` is a measurable value accordingly. Driven by a
    /// synthetic clock, no real sleeps. Table cases: (user_interval
    /// override, interval reply, min_interval reply, early re-announce
    /// instant, due re-announce instant).
    #[tokio::test]
    async fn interval_compliance_per_slot_table() {
        let cases: &[(u64, u64, u64, u64, u64)] = &[
            // (user_interval override, interval reply, min_interval
            // reply, early re-announce instant, due re-announce instant)
            // Default (no user override): period = tracker interval=5s
            // (no longer the min_interval=3s); nothing at +3s (the old
            // min period point), exactly one at +5s.
            (0, 5, 3, 3, 5),
            // min_interval clamped by interval (aria2 `minInterval_ =
            // min(minInterval_, interval_)`): the mock declares min=4 >
            // interval=2 -> booked min=2, period = 2s; nothing at +1s,
            // exactly one at +2s.
            (0, 2, 4, 1, 2),
            // User override (bt-tracker-interval=10): period = 10s (the
            // override beats the tracker interval; the aria2 userDefined
            // semantics kept); nothing at +3s, exactly one at +10s.
            (10, 1800, 3, 3, 10),
        ];
        for (user, interval, min_interval, early_s, due_s) in cases {
            let hits = Arc::new(std::sync::Mutex::new(0usize));
            let hits_in = hits.clone();
            let mock = MockTracker::start(move |path| {
                // Count only announce requests (the post-success
                // same-host scrape is not counted).
                if path.starts_with("/announce")
                    && let Ok(mut h) = hits_in.lock()
                {
                    *h += 1;
                }
                let mut body =
                    format!("d8:intervali{interval}e12:min intervali{min_interval}e5:peersle")
                        .into_bytes();
                body.push(b'e');
                ("200 OK".into(), body)
            })
            .await;
            let mut cfg = config(vec![(0, mock.url())]);
            cfg.options = TrackerOptions {
                bt_tracker_interval: *user,
                ..TrackerOptions::default()
            };
            let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
            let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
            let (transport, _out_rx, _in_tx) = mk_transport();
            let mut actor =
                TrackerActor::new(cfg, Arc::new(FixedView), cmd_rx, event_tx, transport)
                    .unwrap_or_else(|e| panic!("{e}"));

            let t0 = Instant::now();
            actor.tick(t0).await; // first round issues
            pump_at(&mut actor, t0).await; // success lands (interval/min_interval booked)
            assert!(
                matches!(
                    event_rx.try_recv(),
                    Ok(TrackerActorEvent::IntervalUpdated { .. })
                ),
                "IntervalUpdated arrived: user={user}"
            );
            while event_rx.try_recv().is_ok() {}
            assert_eq!(
                hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                1,
                "exactly once in the first round: user={user}"
            );

            actor.tick(t0 + Duration::from_secs(*early_s)).await;
            pump_at(&mut actor, t0 + Duration::from_secs(*early_s)).await;
            assert_eq!(
                hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                1,
                "no resend inside the min_interval gate (compliance red line): user={user} early={early_s}"
            );
            actor.tick(t0 + Duration::from_secs(*due_s)).await;
            pump_at(&mut actor, t0 + Duration::from_secs(*due_s)).await;
            assert_eq!(
                hits.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                2,
                "the due resend happens exactly once: user={user} due={due_s}"
            );
            for t in mock.tasks {
                t.abort();
            }
        }
    }

    /// Seeding view (the SwarmView fully-complete state: the seeding
    /// phase scenario).
    struct FinishedView;

    impl SwarmView for FinishedView {
        fn total_length(&self) -> u64 {
            1000
        }
        fn completed_length(&self) -> u64 {
            1000
        }
        fn session_uploaded(&self) -> u64 {
            8388608
        }
        fn session_downloaded(&self) -> u64 {
            0
        }
        fn all_download_finished(&self) -> bool {
            true
        }
        fn less_than_min_peers(&self) -> bool {
            true
        }
    }

    /// Seeding regression: after a completed success the tier event
    /// advances to SEEDING, and the seeding phase must keep periodic
    /// announces at the tracker interval (the event string "" = the
    /// default periodic event). The old `next_candidate` finished branch
    /// only admitted completed-allowed/STARTED, so a SEEDING slot was
    /// never selected again -> after the first started plus one
    /// completed, no more requests; fixed, SEEDING goes through the
    /// `next_due` periodic gate continuously (and never sends completed
    /// — no inflated snatch counts).
    #[tokio::test]
    async fn seeding_periodic_announce_continues_after_completed() {
        // interval=1s/min=1s: the periodic beat drives second by second
        // on the synthetic clock; records each announce's query string
        // (the event parameter is visible).
        let paths = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let paths_in = paths.clone();
        let mock = MockTracker::start(move |path| {
            if path.starts_with("/announce")
                && let Ok(mut p) = paths_in.lock()
            {
                p.push(path.to_string());
            }
            let mut body = Vec::from(&b"d8:intervali1e12:min intervali1e5:peersle"[..]);
            body.push(b'e');
            ("200 OK".into(), body)
        })
        .await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, mock.url())]),
            Arc::new(FinishedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // t0: the first round (finished -> STARTED_AFTER_COMPLETION,
        // wire "started").
        let t0 = Instant::now();
        actor.tick(t0).await;
        pump_at(&mut actor, t0).await; // success -> SEEDING, next_due = t0+1s
        // t0+1..t0+4: four periodic beats (the synthetic clock advances
        // second by second, no real waiting).
        for s in 1..=4u64 {
            let now = t0 + Duration::from_secs(s);
            actor.tick(now).await;
            pump_at(&mut actor, now).await; // success lands -> the next round's next_due
        }

        let got = paths.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            got.len() >= 5,
            "the seeding phase must keep announcing periodically (first round + >= 4 period rounds): {got:?}"
        );
        assert!(
            got[0].contains("event=started"),
            "the first round = started (STARTED_AFTER_COMPLETION): {:?}",
            got[0]
        );
        for p in &got[1..] {
            assert!(
                !p.contains("event="),
                "periodic announces use the default event (no event=), never completed: {p}"
            );
        }
        for t in mock.tasks {
            t.abort();
        }
    }

    /// Failure classification (the mock form of a probe tier-0
    /// scenario): tier 0 = a closed local port (connect refused, reqwest
    /// classifies "connect") -> the AnnounceFailed reason carries the
    /// "connect:" class prefix; tier 1 then advances and succeeds. The
    /// attempt/failed/ok log lines are asserted by the core-tests smoke;
    /// this locks the structured event surface.
    #[tokio::test]
    async fn announce_failure_classification_connect_refused() {
        // Create a closed port: bind then immediately drop.
        let closed = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("bind: {e}"));
            l.local_addr().unwrap_or_else(|e| panic!("{e}"))
        };
        let good = MockTracker::start(move |_path| {
            let mut body = Vec::from(&b"d8:intervali60e5:peersle"[..]);
            body.push(b'e');
            ("200 OK".into(), body)
        })
        .await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![
                (0, format!("http://{closed}/announce")),
                (1, good.url()),
            ]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        actor.tick(Instant::now()).await; // tier 0 (closed) issues
        pump(&mut actor).await; // tier 0's failure lands + tier 1 issues
        pump(&mut actor).await; // tier 1 succeeds

        let mut events = Vec::new();
        while let Ok(ev) = event_rx.try_recv() {
            events.push(ev);
        }
        let saw_closed_fail = events.iter().any(|ev| {
            matches!(
                ev,
                TrackerActorEvent::AnnounceFailed { url, reason }
                if *url == format!("http://{closed}/announce") && reason.starts_with("connect:")
            )
        });
        let saw_good_ok = events
            .iter()
            .any(|ev| matches!(ev, TrackerActorEvent::IntervalUpdated { .. }));
        let strays: Vec<String> = events
            .iter()
            .filter_map(|ev| match ev {
                TrackerActorEvent::AnnounceFailed { url, reason }
                    if *url != format!("http://{closed}/announce") =>
                {
                    Some(format!("AnnounceFailed({url}, {reason})"))
                }
                _ => None,
            })
            .collect();
        assert!(
            saw_closed_fail && saw_good_ok,
            "events={events:?} strays={strays:?}"
        );
        assert!(
            strays.is_empty(),
            "no other failure events expected: strays={strays:?}"
        );
        assert_eq!(actor.last_ok_url.as_deref(), Some(good.url().as_str()));
        for t in good.tasks {
            t.abort();
        }
    }

    // ===== duplicate-URL folding + slot-identity result routing =====

    fn ok_body() -> (String, Vec<u8>) {
        let mut body = Vec::from(&b"d8:intervali60e5:peersle"[..]);
        body.push(b'e');
        ("200 OK".into(), body)
    }

    /// Entry-fold regression (a duplicate announce-URL configuration —
    /// three tiers, the same URL — folds into one slot); the announce
    /// wave completes (`updating` resets on success, `in_flight` returns
    /// to zero), and Stop's shutdown stopped sequence reaches Halted
    /// within budget (the old defect: the second slot stuck in updating
    /// forever -> `slot_due` always false -> the halt sequence
    /// blocked).
    #[tokio::test]
    async fn duplicate_announce_urls_fold_and_settle_with_halt() {
        let good = MockTracker::start(move |_path| ok_body()).await;
        let url = good.url();
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, url.clone()), (1, url.clone()), (2, url)]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // Fold: three same-URL entries -> a single slot and a single
        // tier (the same semantics as libtorrent's one announce_entry
        // per URL; the halt sequence's failed_walk count stays
        // consistent with the slots).
        assert_eq!(
            actor.slots.len(),
            1,
            "same-URL entries fold into a single slot"
        );
        assert_eq!(actor.tiers.len(), 1, "the tier event table folds in sync");

        // The wave completes: issue -> success -> updating resets,
        // in_flight returns to zero.
        actor.tick(Instant::now()).await;
        assert_eq!(actor.in_flight(), 1, "a single slot issues once");
        pump(&mut actor).await;
        assert_eq!(
            actor.in_flight(),
            0,
            "in_flight back to zero after success (no leak)"
        );
        assert!(!actor.slots[0].updating, "the slot's updating resets");
        assert_eq!(actor.slots[0].fails, 0);

        // The shutdown sequence converges: Stop -> stopped -> success
        // -> noMoreAnnounce -> Halted.
        let (stx, srx) = oneshot::channel();
        actor
            .handle_command(TrackerCommand::Stop { reply: stx }, Instant::now())
            .await;
        assert!(srx.await.is_ok());
        pump(&mut actor).await;
        pump(&mut actor).await;
        let halted = std::iter::from_fn(|| event_rx.try_recv().ok())
            .any(|ev| matches!(ev, TrackerActorEvent::Halted));
        assert!(
            halted,
            "a completed stopped sequence must emit Halted (the halt is not blocked by the updating gate)"
        );
        for t in good.tasks {
            t.abort();
        }
    }

    /// Result-routing regression: two same-URL slots issue in the same
    /// wave (the slot table is constructed white-box, bypassing the
    /// entry fold — the reachable pre-fix shape); the two HTTP results
    /// must land each on its issuing slot identity (token) — both
    /// slots' `updating` reset, `in_flight` back to zero, and the
    /// subsequent shutdown wave completes. Pre-fix, routing matched by
    /// `slots.iter().position(|s| s.url == url)` first-match, both
    /// results landed on slot 0, and slot 1 stayed updating forever.
    #[tokio::test]
    async fn http_results_route_by_slot_identity_not_url() {
        let good = MockTracker::start(move |_path| ok_body()).await;
        let url = good.url();
        let other = MockTracker::start(move |_path| ok_body()).await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, url.clone()), (1, other.url())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // White-box: rewrite slot 1 to the same URL with its own token
        // (the two-slots-one-URL shape — the pre-fold table form, locking
        // the routing surface itself).
        actor.slots[1].url = url.clone();
        actor.token_seq += 1;
        actor.slots[1].token = actor.token_seq;
        assert_eq!(actor.slots[0].url, actor.slots[1].url);
        assert_ne!(actor.slots[0].token, actor.slots[1].token);

        // Same-wave double issue (the same URL, two independent HTTP
        // announces) -> both results return.
        actor.tick(Instant::now()).await;
        assert_eq!(
            actor.in_flight(),
            2,
            "both slots issue once in the same wave"
        );
        pump(&mut actor).await;
        pump(&mut actor).await;
        assert_eq!(
            actor.in_flight(),
            0,
            "in_flight back to zero once both results land on their slots (under URL first-match slot 1 would stick at 1 forever)"
        );
        assert!(
            actor.slots.iter().all(|s| !s.updating && s.fails == 0),
            "both slots' updating reset with no failure booked"
        );

        // The wave completes: the shutdown stopped sequence converges
        // both slots -> Halted.
        let (stx, srx) = oneshot::channel();
        actor
            .handle_command(TrackerCommand::Stop { reply: stx }, Instant::now())
            .await;
        assert!(srx.await.is_ok());
        pump(&mut actor).await;
        pump(&mut actor).await;
        let halted = std::iter::from_fn(|| event_rx.try_recv().ok())
            .any(|ev| matches!(ev, TrackerActorEvent::Halted));
        assert!(
            halted,
            "the halt sequence is not blocked by a stuck updating"
        );
        for t in [good, other] {
            for t in t.tasks {
                t.abort();
            }
        }
    }

    // ===== UDP tracker domain resolution carrier =====

    use std::collections::HashMap;

    use crate::tracker::dns::ResolverFuture;

    /// Stub resolver (test seam; real DNS forbidden by design): returns
    /// preset results per host from a table; counts queries (asserting
    /// cache hits issue none). A table miss -> Err (an assembly error
    /// surfaces in assertions as a dns failure instead of panicking
    /// inside a spawned task).
    #[derive(Clone)]
    struct StubResolver {
        table: Arc<HashMap<String, Result<IpAddr, String>>>,
        queries: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl StubResolver {
        fn new(entries: Vec<(&'static str, Result<IpAddr, String>)>) -> Self {
            StubResolver {
                table: Arc::new(
                    entries
                        .into_iter()
                        .map(|(h, r)| (h.to_string(), r))
                        .collect(),
                ),
                queries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn queries(&self) -> usize {
            self.queries.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl HostResolver for StubResolver {
        fn resolve(&self, host: String) -> ResolverFuture {
            self.queries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let result = self
                .table
                .get(&host)
                .cloned()
                .unwrap_or_else(|| Err(format!("stub resolver: unexpected host {host}")));
            Box::pin(std::future::ready(result))
        }
    }

    /// Per-family stub resolver (test seam): separate V4/V6 result
    /// tables + per-family query counts (real DNS forbidden by design).
    /// `resolve` is only a trait-compat implementation (the actor now
    /// goes through `resolve_family`; this stub overrides the per-family
    /// path).
    #[derive(Clone)]
    struct FamilyStub {
        v4: Arc<HashMap<String, Result<IpAddr, String>>>,
        v6: Arc<HashMap<String, Result<IpAddr, String>>>,
        v4_queries: Arc<std::sync::atomic::AtomicUsize>,
        v6_queries: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FamilyStub {
        fn new(
            v4: Vec<(&'static str, Result<IpAddr, String>)>,
            v6: Vec<(&'static str, Result<IpAddr, String>)>,
        ) -> Self {
            FamilyStub {
                v4: Arc::new(v4.into_iter().map(|(h, r)| (h.to_string(), r)).collect()),
                v6: Arc::new(v6.into_iter().map(|(h, r)| (h.to_string(), r)).collect()),
                v4_queries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                v6_queries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn v4_queries(&self) -> usize {
            self.v4_queries.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn v6_queries(&self) -> usize {
            self.v6_queries.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl HostResolver for FamilyStub {
        fn resolve(&self, host: String) -> ResolverFuture {
            // The stub's v4-first simplification: consult the V4 table
            // first, fall back to the V6 table.
            self.v4_queries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let result = match self.v4.get(&host) {
                Some(r) => r.clone(),
                None => self.v6.get(&host).cloned().unwrap_or_else(|| {
                    Err(format!("family stub resolver: unexpected host {host}"))
                }),
            };
            Box::pin(std::future::ready(result))
        }

        fn resolve_family(&self, host: String, family: ResolveFamily) -> ResolverFuture {
            let result = match family {
                ResolveFamily::V4 => {
                    self.v4_queries
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    self.v4.get(&host).cloned()
                }
                ResolveFamily::V6 => {
                    self.v6_queries
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    self.v6.get(&host).cloned()
                }
            }
            .unwrap_or_else(|| Err(format!("family stub resolver: no {family:?} entry {host}")));
            Box::pin(std::future::ready(result))
        }
    }

    /// Minimal event-capturing subscriber (implements
    /// [`tracing::Subscriber`] directly, no dev-dependency): collects an
    /// event's field line (message/class/reason) into strings — for
    /// "class visible in the log" assertions.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<std::sync::Mutex<Vec<String>>>);

    impl LogCapture {
        fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl tracing::Subscriber for LogCapture {
        fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _from: &tracing::span::Id, _to: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct V(String);
            impl tracing::field::Visit for V {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={:?}", field.name(), value);
                }
            }
            let mut v = V(String::new());
            event.record(&mut v);
            if let Ok(mut all) = self.0.lock() {
                all.push(v.0);
            }
        }
        fn enter(&self, _id: &tracing::span::Id) {}
        fn exit(&self, _id: &tracing::span::Id) {}
    }

    /// Domain-form udp:// tracker announce/scrape full flow: the stub
    /// resolves tracker.example to 127.0.0.1 -> the local mock (duplex
    /// channel wire mode) CONNECT->ANNOUNCE->success->a same-host scrape
    /// (a cache hit) -> the resend round hits the cache again — the
    /// resolver queries exactly once throughout.
    #[tokio::test]
    async fn udp_domain_announce_scrape_full_flow_via_stub_resolver() {
        let stub = StubResolver::new(vec![(
            "tracker.example",
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )]);
        let url = "udp://tracker.example:1337/announce";
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, url.to_string())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()));

        // tick: a domain -> spawns a resolve task (no frame out).
        let t0 = Instant::now();
        actor.tick(t0).await;
        assert!(
            out_rx.try_recv().is_err(),
            "no outbound frame before the resolve completes"
        );
        pump(&mut actor).await; // the resolve result returns -> announce request -> CONNECT frame
        let tracker: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1337);
        let (to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("connect frame"));
        assert_eq!(to, tracker, "sent to the resolved address (not the domain)");
        assert_eq!(&frame[8..12], &0i32.to_be_bytes());
        let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_be_bytes());
        reply.extend_from_slice(&tid.to_be_bytes());
        reply.extend_from_slice(&0xdead_c0de_dead_c0deu64.to_be_bytes());
        in_tx
            .send((tracker, reply))
            .await
            .unwrap_or_else(|_| panic!("in"));
        actor.tick(t0 + Duration::from_secs(1)).await; // CONNECT booked -> ANNOUNCE frame
        let (_to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("announce frame"));
        assert_eq!(&frame[8..12], &1i32.to_be_bytes());
        let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
        // ANNOUNCE reply: interval=60 (the re-announce period gate) +
        // 1 peer.
        let mut reply = Vec::new();
        reply.extend_from_slice(&1i32.to_be_bytes());
        reply.extend_from_slice(&tid.to_be_bytes());
        reply.extend_from_slice(&60i32.to_be_bytes());
        reply.extend_from_slice(&2i32.to_be_bytes());
        reply.extend_from_slice(&3i32.to_be_bytes());
        reply.extend_from_slice(&[10, 0, 0, 9, 0x1a, 0xe1]);
        in_tx
            .send((tracker, reply))
            .await
            .unwrap_or_else(|_| panic!("in"));
        pump(&mut actor).await; // announce succeeds -> same-host scrape (cache hit) -> SCRAPE frame
        let (to, sframe) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("scrape frame"));
        assert_eq!(to, tracker);
        assert_eq!(&sframe[8..12], &2i32.to_be_bytes(), "action=scrape");
        assert_eq!(
            stub.queries(),
            1,
            "announce resolves once; a scrape cache hit issues no query"
        );
        let stid = u32::from_be_bytes([sframe[12], sframe[13], sframe[14], sframe[15]]);
        let mut sreply = Vec::new();
        sreply.extend_from_slice(&2i32.to_be_bytes());
        sreply.extend_from_slice(&stid.to_be_bytes());
        sreply.extend_from_slice(&42i32.to_be_bytes());
        sreply.extend_from_slice(&7i32.to_be_bytes());
        sreply.extend_from_slice(&3i32.to_be_bytes());
        in_tx
            .send((tracker, sreply))
            .await
            .unwrap_or_else(|_| panic!("in"));
        pump(&mut actor).await; // the scrape reply -> the ScrapeResult event

        let mut saw_interval = false;
        let mut saw_peers = false;
        let mut saw_scrape = false;
        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TrackerActorEvent::IntervalUpdated { .. } => saw_interval = true,
                TrackerActorEvent::Peers { peers, .. } => {
                    assert_eq!(peers.len(), 1);
                    assert_eq!(peers[0].ip.to_string(), "10.0.0.9");
                    saw_peers = true;
                }
                TrackerActorEvent::ScrapeResult {
                    seeds, leechers, ..
                } => {
                    assert_eq!((seeds, leechers), (42, 3));
                    saw_scrape = true;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(saw_interval && saw_peers && saw_scrape);

        // Resend round (+122s > min_interval 60s + the connection id
        // lifetime 60s, < cache TTL 300s): a cache hit issues no query
        // -> the connection has expired -> a fresh CONNECT frame.
        pump_at(&mut actor, t0 + Duration::from_secs(122)).await;
        let (to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("second connect frame"));
        assert_eq!(to, tracker);
        assert_eq!(
            &frame[8..12],
            &0i32.to_be_bytes(),
            "a resend round re-CONNECTs"
        );
        assert_eq!(
            stub.queries(),
            1,
            "a resend inside the TTL hits the cache and issues no query"
        );
    }

    /// Resolution failure = the retryable class "dns": an Err
    /// resolution -> the AnnounceFailed reason carries the
    /// resolution-failure prefix; the failure log line carries
    /// class="dns" (structured capture); per-tracker backoff engages
    /// (fails/next_due); after the backoff expires the retry queries
    /// again — not the invalid-url (permanent class) behavior.
    #[tokio::test]
    async fn udp_domain_dns_failure_is_retryable_with_dns_class() {
        let stub = StubResolver::new(vec![("dead.example", Err("nxdomain".to_string()))]);
        let url = "udp://dead.example:1337/announce";
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, _out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, url.to_string())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()));

        actor.tick(Instant::now()).await; // spawns the resolve
        tokio::time::sleep(Duration::from_millis(30)).await; // the resolve task lands (Err into the result channel)
        // The failure-settle tick drives inside the capturing subscriber
        // (futures::executor, zero runtime dependency — this tick has no
        // spawn/timer path).
        let capture = LogCapture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            futures::executor::block_on(actor.tick(Instant::now()));
        });
        assert!(
            capture.lines().iter().any(|l| l.contains("announce failed")
                && l.contains(r#"class="dns""#)
                && l.contains("nxdomain")),
            "the failure log should carry class=dns and the cause: {:?}",
            capture.lines()
        );
        assert!(
            !capture
                .lines()
                .iter()
                .any(|l| l.contains(r#"class="invalid-url""#)),
            "a resolution failure must not be classified invalid-url (the permanent class)"
        );
        assert!(matches!(
            event_rx.try_recv(),
            Ok(TrackerActorEvent::AnnounceFailed { url: u, reason })
            if u == url && reason.starts_with("udp tracker host resolution failed")
        ));
        assert_eq!(actor.slots[0].fails, 1, "failure booked");
        assert!(
            actor.slots[0]
                .next_due
                .unwrap_or_else(|| panic!("a failure must set the next_due backoff gate"))
                > Instant::now(),
            "the backoff next_due lies in the future (a retryable gate, not permanent discard)"
        );
        assert!(
            !actor.slots[0].updating,
            "an instant failure releases the slot immediately"
        );

        // Backoff expiry (failure_backoff(1) = 17s) -> the retry queries
        // again (retryable).
        let due = actor.slots[0]
            .next_due
            .unwrap_or_else(|| panic!("a failure must set the next_due backoff gate"));
        actor.tick(due + Duration::from_secs(1)).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        actor.tick(Instant::now()).await;
        assert_eq!(
            stub.queries(),
            2,
            "after backoff expiry the retry resolves again (retryable-class behavior)"
        );
    }

    /// The Scrape command path's cache-miss resolution: no announce ran
    /// first (the cache is empty; the empty tiers table makes this test
    /// exercise only the scrape path) -> the Scrape command -> spawn
    /// resolve -> CONNECT -> the SCRAPE frame goes to the resolved
    /// address.
    #[tokio::test]
    async fn udp_domain_scrape_resolves_on_cache_miss() {
        let stub = StubResolver::new(vec![(
            "tracker.example",
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )]);
        let url = "udp://tracker.example:1337/announce";
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()));
        actor.last_ok_url = Some(url.to_string()); // white-box: simulate a previously successful host

        actor
            .handle_command(
                TrackerCommand::Scrape {
                    reply: {
                        let (tx, _rx) = oneshot::channel();
                        tx
                    },
                },
                Instant::now(),
            )
            .await;
        assert!(
            out_rx.try_recv().is_err(),
            "no outbound frame before the resolve completes"
        );
        pump(&mut actor).await; // the resolve result returns -> scrape enqueued (an unknown endpoint prepends CONNECT)
        let tracker: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1337);
        let (to, cframe) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("connect frame"));
        assert_eq!(to, tracker);
        assert_eq!(
            &cframe[8..12],
            &0i32.to_be_bytes(),
            "CONNECT first (cc:278-288)"
        );
        let tid = u32::from_be_bytes([cframe[12], cframe[13], cframe[14], cframe[15]]);
        let mut creply = Vec::new();
        creply.extend_from_slice(&0i32.to_be_bytes());
        creply.extend_from_slice(&tid.to_be_bytes());
        creply.extend_from_slice(&0xdead_c0de_dead_c0deu64.to_be_bytes());
        in_tx
            .send((tracker, creply))
            .await
            .unwrap_or_else(|_| panic!("in"));
        actor.tick(Instant::now()).await; // CONNECT booked -> SCRAPE frame
        let (to, sframe) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("scrape frame"));
        assert_eq!(to, tracker);
        assert_eq!(&sframe[8..12], &2i32.to_be_bytes(), "action=scrape");
        assert_eq!(stub.queries(), 1);
    }

    /// Semantics upgrade (the predecessor,
    /// `udp_domain_v6_only_resolution_rejected_via_existing_path`,
    /// asserted "v6-only -> rejected with no frame" — the exact opposite
    /// of the current supported-v6-carriers semantics, replaced when the
    /// v6 rejection path was removed): a v6-only domain -> the v6 face
    /// goes over the v6 carrier via AAAA (the CONNECT frame goes to the
    /// v6 address); a v4 face with no A record -> an independent failure
    /// (the retryable "dns" class, the primary face reports as usual).
    /// The rejection string "ipv6 udp tracker unsupported" must never
    /// appear again.
    #[tokio::test]
    async fn udp_domain_v6_only_announces_over_v6_carrier_v4_face_dns_fails() {
        let v6: IpAddr = "2001:db8::1".parse().unwrap_or_else(|e| panic!("{e}"));
        let stub = FamilyStub::new(
            vec![("v6.example", Err("no A record".to_string()))],
            vec![("v6.example", Ok(v6))],
        );
        let url = "udp://v6.example:1337/announce";
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, url.to_string())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()))
        .with_v6_probe_override(Some(true));

        // Dual-face slots: the v4 primary face (reporting) + the v6
        // attached face (domain expansion).
        assert_eq!(actor.slots.len(), 2);
        assert_eq!(actor.slots[0].udp_family, Some(ResolveFamily::V4));
        assert_eq!(actor.slots[1].udp_family, Some(ResolveFamily::V6));
        assert!(!actor.slots[0].silent_failure);
        assert!(actor.slots[1].silent_failure);

        actor.tick(Instant::now()).await; // both faces spawn per-family resolves
        tokio::time::sleep(Duration::from_millis(30)).await;
        actor.tick(Instant::now()).await; // results return -> the v6 carrier CONNECT frame
        let tracker: SocketAddr = SocketAddr::new(v6, 1337);
        let (to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("v6 carrier connect frame"));
        assert_eq!(
            to, tracker,
            "the CONNECT goes to the v6 carrier address (no longer rejected)"
        );
        assert_eq!(&frame[8..12], &0i32.to_be_bytes());

        // The v4 face fails independently: the dns class (retryable),
        // not a v6 rejection string. Whole-list cache contract: after
        // the list query succeeds (v6 is in the list), an empty v4
        // projection = the normalized
        // "no ipv4 address (A) resolved" (the same wording as the real
        // TokioHostResolver's per-family message) — the stub's
        // per-family entry text no longer passes through the
        // projection.
        let mut saw_fail = false;
        while let Ok(ev) = event_rx.try_recv() {
            if let TrackerActorEvent::AnnounceFailed { url: u, reason } = ev {
                assert_eq!(u, url);
                assert!(
                    reason.starts_with("udp tracker host resolution failed")
                        && reason.contains("no ipv4 address (A) resolved"),
                    "a v4 face with no A record = a dns-class failure: {reason}"
                );
                saw_fail = true;
            }
        }
        assert!(
            saw_fail,
            "the v4 primary face's failure is reported as usual"
        );
        assert_eq!(stub.v4_queries(), 1, "the v4 face resolves A exactly once");
    }

    /// The literal-IP path has zero resolution overhead: a literal-IP
    /// udp:// bypasses the resolver (the stub count stays 0), behavior
    /// unchanged (the full duplex wire chain works).
    #[tokio::test]
    async fn udp_literal_ip_bypasses_resolver() {
        let stub = StubResolver::new(vec![]);
        let tracker: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1337));
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, _event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, format!("udp://{tracker}/announce"))]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()));

        actor.tick(Instant::now()).await; // the literal IP passes through -> the CONNECT frame is out
        let (to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("connect frame"));
        assert_eq!(to, tracker);
        assert_eq!(&frame[8..12], &0i32.to_be_bytes());
        let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_be_bytes());
        reply.extend_from_slice(&tid.to_be_bytes());
        reply.extend_from_slice(&0xdead_c0de_dead_c0deu64.to_be_bytes());
        in_tx
            .send((tracker, reply))
            .await
            .unwrap_or_else(|_| panic!("in"));
        actor.tick(Instant::now()).await;
        let (_to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("announce frame"));
        assert_eq!(&frame[8..12], &1i32.to_be_bytes());
        assert_eq!(
            stub.queries(),
            0,
            "a literal IP has zero resolution overhead"
        );
    }

    // ===== IPv6 UDP carrier =====

    /// An 18B v6 compact peer (the BEP32 shape: 16B address + 2B port,
    /// big-endian).
    fn v6_peer_bytes(ip: std::net::Ipv6Addr, port: u16) -> Vec<u8> {
        let mut b = Vec::with_capacity(18);
        b.extend_from_slice(&ip.octets());
        b.extend_from_slice(&port.to_be_bytes());
        b
    }

    /// KRPC reply assembly (the family-agnostic frame surface): action +
    /// tid + body.
    fn krpc_reply(action: i32, tid: u32, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::with_capacity(8 + body.len());
        r.extend_from_slice(&action.to_be_bytes());
        r.extend_from_slice(&tid.to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    /// A ::1 local mock UDP tracker (a real loopback socket — the
    /// carrier byte surface is fully real, ::1 only, no real network):
    /// CONNECT(16B)/ANNOUNCE(+interval 60 + the 18B peer
    /// 2001:db8::1:6882)/SCRAPE(12B: 42/7/3); received frames are stored
    /// in `captured` for wire assertions.
    async fn start_udp6_mock_tracker() -> (
        SocketAddr,
        Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let sock = tokio::net::UdpSocket::bind("[::1]:0")
            .await
            .unwrap_or_else(|e| panic!("bind [::1]: {e}"));
        let addr = sock.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap = captured.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let frame = buf[..n].to_vec();
                if let Ok(mut c) = cap.lock() {
                    c.push(frame.clone());
                }
                if frame.len() < 16 {
                    continue;
                }
                let action = i32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
                let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
                let reply = match action {
                    0 => krpc_reply(0, tid, &0xdead_c0de_dead_c0deu64.to_be_bytes()),
                    1 => {
                        let mut body = Vec::new();
                        body.extend_from_slice(&60i32.to_be_bytes()); // interval
                        body.extend_from_slice(&2i32.to_be_bytes()); // leechers
                        body.extend_from_slice(&3i32.to_be_bytes()); // seeders
                        body.extend_from_slice(&v6_peer_bytes(
                            "2001:db8::1".parse().unwrap_or_else(|e| panic!("{e}")),
                            6882,
                        ));
                        krpc_reply(1, tid, &body)
                    }
                    2 => {
                        let mut body = Vec::new();
                        body.extend_from_slice(&42i32.to_be_bytes());
                        body.extend_from_slice(&7i32.to_be_bytes());
                        body.extend_from_slice(&3i32.to_be_bytes());
                        krpc_reply(2, tid, &body)
                    }
                    _ => continue,
                };
                let _ = sock.send_to(&reply, src).await;
            }
        });
        (addr, captured, handle)
    }

    /// Poll until the mock has received n frames (isolates the local
    /// loopback latency; 10ms steps).
    async fn wait_for_frames(captured: &Arc<std::sync::Mutex<Vec<Vec<u8>>>>, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while captured.lock().unwrap_or_else(|e| e.into_inner()).len() < n {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the mock's frame #{n}: {:?}",
                captured.lock().unwrap_or_else(|e| e.into_inner()).len()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The full announce/scrape flow against the mock v6 UDP tracker (a
    /// real ::1 loopback socket): a literal v6 URL -> v6 carrier
    /// CONNECT->ANNOUNCE (wire frame-body assertions) -> the reply's 18B
    /// peers parse -> the Peers event (peers6 populated, peers empty —
    /// never mixed by family) -> a same-host v6 carrier scrape ->
    /// ScrapeResult. The actor's transport boundary stays channels; the
    /// frames make a real ::1 UDP roundtrip.
    #[tokio::test]
    async fn v6_carrier_announce_scrape_full_flow_over_real_loopback() {
        let (tracker, captured, mock) = start_udp6_mock_tracker().await;
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, format!("udp://{tracker}/announce"))]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_v6_probe_override(Some(true));

        // A literal v6 -> a single v6-face slot.
        assert_eq!(actor.slots.len(), 1);
        assert_eq!(actor.slots[0].udp_family, Some(ResolveFamily::V6));
        assert!(
            !actor.slots[0].silent_failure,
            "a single-face slot's failure is reported as usual"
        );

        // The actor->mock relay pump: outbound frames -> a relay socket
        // sends them to the mock; mock replies -> the inbound channel (a
        // real ::1 UDP roundtrip).
        let relay = tokio::net::UdpSocket::bind("[::1]:0")
            .await
            .unwrap_or_else(|e| panic!("bind relay: {e}"));
        let pump = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                tokio::select! {
                    out = out_rx.recv() => match out {
                        Some((dst, frame)) => {
                            let _ = relay.send_to(&frame, dst).await;
                        }
                        None => break,
                    },
                    r = relay.recv_from(&mut buf) => match r {
                        Ok((n, src)) => {
                            let _ = in_tx.send((src, buf[..n].to_vec())).await;
                        }
                        Err(_) => break,
                    },
                }
            }
        });

        // tick1: the literal v6 passes through (the gate forced open)
        // -> the CONNECT frame.
        actor.tick(Instant::now()).await;
        wait_for_frames(&captured, 1).await;
        tokio::time::sleep(Duration::from_millis(60)).await; // the reply lands via the relay
        // tick2: CONNECT booked -> the ANNOUNCE frame.
        actor.tick(Instant::now()).await;
        wait_for_frames(&captured, 2).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        // tick3: the ANNOUNCE reply (interval 60 + an 18B peer) ->
        // success events + scrape.
        actor.tick(Instant::now()).await;
        wait_for_frames(&captured, 3).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        // tick4: the SCRAPE reply -> the ScrapeResult event.
        actor.tick(Instant::now()).await;
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Wire assertions: the ANNOUNCE frame body (DefaultBtAnnounce.cc
        // semantics injected; the family-agnostic frame surface).
        let frames = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            frames.len(),
            3,
            "one frame each for CONNECT/ANNOUNCE/SCRAPE"
        );
        let af = &frames[1];
        assert_eq!(&af[0..8], &0xdead_c0de_dead_c0deu64.to_be_bytes());
        assert_eq!(&af[8..12], &1i32.to_be_bytes());
        assert_eq!(&af[16..36], &[0x11; 20], "info_hash");
        assert_eq!(&af[36..56], b"-TJ0001-AAAAAAAAAAAA");
        assert_eq!(&af[56..64], &7u64.to_be_bytes(), "downloaded");
        assert_eq!(&af[64..72], &1000u64.to_be_bytes(), "left");
        assert_eq!(&af[72..80], &5u64.to_be_bytes(), "uploaded");
        assert_eq!(&af[80..84], &2i32.to_be_bytes(), "event=started");
        assert_eq!(
            &af[84..88],
            &[0; 4],
            "ip=0 (the v6 carrier same-value form; the tracker trusts the source address)"
        );
        assert_eq!(&af[92..96], &50i32.to_be_bytes(), "numwant=50");
        assert_eq!(&af[96..98], &6881u16.to_be_bytes(), "port");
        let sf = &frames[2];
        assert_eq!(&sf[8..12], &2i32.to_be_bytes(), "action=scrape");

        let mut saw_interval = false;
        let mut saw_peers6 = false;
        let mut saw_scrape = false;
        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TrackerActorEvent::IntervalUpdated {
                    interval,
                    min_interval,
                } => {
                    assert_eq!((interval, min_interval), (60, 60));
                    saw_interval = true;
                }
                TrackerActorEvent::Peers { peers, peers6, .. } => {
                    assert!(
                        peers.is_empty(),
                        "the v6 carrier produces no v4 peers (never mixed)"
                    );
                    assert_eq!(peers6.len(), 1);
                    assert_eq!(peers6[0].ip.to_string(), "2001:db8::1");
                    assert_eq!(peers6[0].port, 6882);
                    saw_peers6 = true;
                }
                TrackerActorEvent::ScrapeResult {
                    seeds, leechers, ..
                } => {
                    assert_eq!((seeds, leechers), (42, 3));
                    saw_scrape = true;
                }
                TrackerActorEvent::AnnounceFailed { url, reason } => {
                    panic!("the v6 carrier full flow must not fail: {url} {reason}")
                }
                TrackerActorEvent::Halted => panic!("Halted must not arrive without Stop"),
            }
        }
        assert!(saw_interval && saw_peers6 && saw_scrape);
        mock.abort();
        pump.abort();
    }

    /// A dual-stack domain -> both faces in parallel in the same wave
    /// (dual-stack announce separately): a v4 carrier reply's 6B peers
    /// -> the `peers` field, a v6 carrier reply's 18B peers -> the
    /// `peers6` field (never mixed by family); each face scrapes its own
    /// endpoint; per-family resolution happens exactly once each (the
    /// scrape hits the cache).
    #[tokio::test]
    async fn dual_stack_domain_both_faces_announce_peers_by_family() {
        let stub = FamilyStub::new(
            vec![(
                "dual.example",
                Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            )],
            vec![(
                "dual.example",
                Ok(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            )],
        );
        let url = "udp://dual.example:1337/announce";
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, url.to_string())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()))
        .with_v6_probe_override(Some(true));
        assert_eq!(
            actor.slots.len(),
            2,
            "a domain expands into dual v4+v6 faces"
        );

        let v4t: SocketAddr = "127.0.0.1:1337".parse().unwrap_or_else(|e| panic!("{e}"));
        let v6t: SocketAddr = "[::1]:1337".parse().unwrap_or_else(|e| panic!("{e}"));

        actor.tick(Instant::now()).await; // both faces spawn per-family resolves
        pump(&mut actor).await; // results return -> both CONNECT frames

        // Both CONNECT frames (bucketed by destination address, not
        // issue order).
        let mut connects = std::collections::HashMap::new();
        for _ in 0..2 {
            let (to, frame) = out_rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("connect frame"));
            assert_eq!(&frame[8..12], &0i32.to_be_bytes());
            connects.insert(to, frame);
        }
        assert_eq!(connects.len(), 2);
        for addr in [v4t, v6t] {
            let frame = &connects[&addr];
            let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
            in_tx
                .send((
                    addr,
                    krpc_reply(0, tid, &0xdead_c0de_dead_c0deu64.to_be_bytes()),
                ))
                .await
                .unwrap_or_else(|_| panic!("in"));
        }

        actor.tick(Instant::now()).await; // both CONNECTs booked -> both ANNOUNCE frames
        let mut announces = std::collections::HashMap::new();
        for _ in 0..2 {
            let (to, frame) = out_rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("announce frame"));
            assert_eq!(&frame[8..12], &1i32.to_be_bytes());
            announces.insert(to, frame);
        }
        assert_eq!(announces.len(), 2);
        for (addr, peers_body) in [
            (v4t, Vec::from(&[10, 0, 0, 9, 0x1a, 0xe1][..])),
            (
                v6t,
                v6_peer_bytes(
                    "2001:db8::9".parse().unwrap_or_else(|e| panic!("{e}")),
                    6881,
                ),
            ),
        ] {
            let frame = &announces[&addr];
            let tid = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
            let mut body = Vec::new();
            body.extend_from_slice(&60i32.to_be_bytes());
            body.extend_from_slice(&0i32.to_be_bytes());
            body.extend_from_slice(&0i32.to_be_bytes());
            body.extend_from_slice(&peers_body);
            in_tx
                .send((addr, krpc_reply(1, tid, &body)))
                .await
                .unwrap_or_else(|_| panic!("in"));
        }

        pump(&mut actor).await; // both announces succeed -> Peers/Interval + scrape enqueued
        pump(&mut actor).await; // the scrape frames go out (same-tick drain) -> both SCRAPEs received
        let mut scrape_tids = std::collections::HashMap::new();
        for _ in 0..2 {
            let (to, frame) = out_rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("scrape frame"));
            assert_eq!(&frame[8..12], &2i32.to_be_bytes());
            scrape_tids.insert(
                to,
                u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]),
            );
        }
        assert_eq!(
            scrape_tids
                .keys()
                .copied()
                .collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from([v4t, v6t])
        );
        for (addr, tid) in &scrape_tids {
            let mut body = Vec::new();
            body.extend_from_slice(&42i32.to_be_bytes());
            body.extend_from_slice(&7i32.to_be_bytes());
            body.extend_from_slice(&3i32.to_be_bytes());
            in_tx
                .send((*addr, krpc_reply(2, *tid, &body)))
                .await
                .unwrap_or_else(|_| panic!("in"));
        }
        pump(&mut actor).await; // both scrape replies -> ScrapeResult

        let mut saw_v4_peers = false;
        let mut saw_v6_peers = false;
        let mut scrape_count = 0;
        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TrackerActorEvent::Peers { peers, peers6, .. } => {
                    if !peers.is_empty() {
                        assert!(
                            peers6.is_empty(),
                            "a v4-carrier event must not mix in peers6"
                        );
                        assert_eq!(peers[0].ip.to_string(), "10.0.0.9");
                        saw_v4_peers = true;
                    }
                    if !peers6.is_empty() {
                        assert!(peers.is_empty(), "a v6-carrier event must not mix in peers");
                        assert_eq!(peers6[0].ip.to_string(), "2001:db8::9");
                        assert_eq!(peers6[0].port, 6881);
                        saw_v6_peers = true;
                    }
                }
                TrackerActorEvent::ScrapeResult { .. } => scrape_count += 1,
                TrackerActorEvent::AnnounceFailed { url, reason } => {
                    panic!("the dual-face full flow must not fail: {url} {reason}")
                }
                _ => {}
            }
        }
        assert!(
            saw_v4_peers && saw_v6_peers,
            "both faces raise their per-family peers"
        );
        assert_eq!(scrape_count, 2, "each face scrapes on its own");
        assert_eq!(
            stub.v4_queries(),
            1,
            "A resolved exactly once (the scrape hits the cache)"
        );
        assert_eq!(
            stub.v6_queries(),
            1,
            "AAAA resolved exactly once (the scrape hits the cache)"
        );
    }

    /// No AAAA -> the v6 face silently skips with independent backoff:
    /// no AnnounceFailed event (the attached face is silent), the v6
    /// face books independently (fails/backoff next_due); the v4 face is
    /// unaffected (frames issue as usual, zero failure bookkeeping); the
    /// post-backoff retry still fails (within the whole-list cache TTL,
    /// "no AAAA" is the authoritative answer, the empty projection fails
    /// without re-querying) — still silent.
    #[tokio::test]
    async fn no_aaaa_v6_face_silent_skip_with_independent_backoff() {
        let stub = FamilyStub::new(
            vec![(
                "v4only.example",
                Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            )],
            vec![],
        );
        let url = "udp://v4only.example:1337/announce";
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, url.to_string())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()))
        .with_v6_probe_override(Some(true));

        actor.tick(Instant::now()).await; // both faces spawn resolves
        pump(&mut actor).await; // v4: the CONNECT frame; v6: resolution fails -> a silent settle

        // The v4 face issues its frame as usual (the v6 failure does
        // not affect the v4 announce).
        let (to, frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("v4 connect frame"));
        assert_eq!(
            to,
            "127.0.0.1:1337".parse().unwrap_or_else(|e| panic!("{e}"))
        );
        assert_eq!(&frame[8..12], &0i32.to_be_bytes());
        assert!(
            out_rx.try_recv().is_err(),
            "the v6 face is silent: no outbound frame"
        );

        // Zero events (the v6 face is silent; the v4 face has neither
        // succeeded nor failed yet).
        assert!(
            event_rx.try_recv().is_err(),
            "an attached v6 face's failure stays out of the event face"
        );
        // Independent backoff bookkeeping: the v6 face has fails=1 with
        // next_due in the future; the v4 face has none.
        assert_eq!(actor.slots[0].udp_family, Some(ResolveFamily::V4));
        assert_eq!(actor.slots[0].fails, 0);
        assert!(
            actor.slots[0].updating,
            "the v4 face's in-flight is unaffected"
        );
        assert_eq!(actor.slots[1].udp_family, Some(ResolveFamily::V6));
        assert_eq!(
            actor.slots[1].fails, 1,
            "the v6 face books failures independently"
        );
        assert!(
            !actor.slots[1].updating,
            "an instant failure releases the slot"
        );
        let due = actor.slots[1]
            .next_due
            .unwrap_or_else(|| panic!("a failure must set the backoff gate"));

        // Backoff expiry -> retry the v6 face -> still a silent
        // failure. Whole-list cache contract (behavior notes in
        // taiji_io::dns): the first round's backfilled [v4] list is
        // authoritative within the TTL ("no AAAA" is not re-queried each
        // round — the retry fails from the cache's empty projection and
        // fails are booked as usual; the stub's v6 query count stays at
        // the first round's 1).
        pump_at(&mut actor, due + Duration::from_secs(1)).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        actor.tick(due + Duration::from_secs(1)).await;
        assert_eq!(
            stub.v6_queries(),
            1,
            "a retry inside the TTL hits the cached list (the empty projection fails without re-querying)"
        );
        assert_eq!(
            stub.v4_queries(),
            1,
            "the v4 face does not retry along with v6"
        );
        assert_eq!(actor.slots[1].fails, 2);
        assert!(
            event_rx.try_recv().is_err(),
            "the retry's failure is still silent"
        );
    }

    /// The v6 gate closed (probe_source_ip(true)=None) -> the v6 face
    /// skips: a dual-stack domain only sends the v4 face (the attached
    /// face is silent); a literal v6 URL (single face) fails as
    /// "unavailable" and **reports as usual** (it is that tracker's only
    /// carrier — the failure must be visible and the halt sequence must
    /// be able to converge on the failure bookkeeping).
    #[tokio::test]
    async fn v6_gate_closed_skips_v6_face() {
        let stub = FamilyStub::new(
            vec![(
                "dual.example",
                Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            )],
            vec![(
                "dual.example",
                Ok(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            )],
        );
        let (_cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport, mut out_rx, _in_tx) = mk_transport();
        let mut actor = TrackerActor::new(
            config(vec![(0, "udp://dual.example:1337/announce".to_string())]),
            Arc::new(FixedView),
            cmd_rx,
            event_tx,
            transport,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_resolver(Arc::new(stub.clone()))
        .with_v6_probe_override(Some(false));

        actor.tick(Instant::now()).await; // both faces spawn per-family resolves
        pump(&mut actor).await; // results return -> the v4 CONNECT frame; the v6 face gate skips
        let (to, _frame) = out_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("v4 connect frame"));
        assert_eq!(
            to,
            "127.0.0.1:1337".parse().unwrap_or_else(|e| panic!("{e}"))
        );
        assert!(
            out_rx.try_recv().is_err(),
            "the v6 face has no outbound frame"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "the attached v6 face skips silently"
        );
        assert_eq!(
            actor.slots[1].fails, 1,
            "unavailable is booked independently too"
        );
        assert!(!actor.slots[1].updating);

        // A literal v6 URL (single face): the gate is closed -> the
        // failure reports (not silent).
        let (_cmd_tx2, cmd_rx2) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx2, mut event_rx2) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (transport2, mut out_rx2, _in_tx2) = mk_transport();
        let mut actor2 = TrackerActor::new(
            config(vec![(0, "udp://[::1]:1337/announce".to_string())]),
            Arc::new(FixedView),
            cmd_rx2,
            event_tx2,
            transport2,
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .with_v6_probe_override(Some(false));
        actor2.tick(Instant::now()).await;
        assert!(out_rx2.try_recv().is_err(), "no global v6 -> no blind send");
        assert!(
            matches!(
                event_rx2.try_recv(),
                Ok(TrackerActorEvent::AnnounceFailed { reason, .. })
                if reason.contains("no global ipv6")
            ),
            "a single-face slot's failure is reported as usual (the halt sequence can converge)"
        );
    }
}
