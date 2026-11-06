//! Cross-arm shared state for the engine main loop: the former `run` locals
//! are grouped by lifetime into [`EngineLoop`] (mutable bookkeeping shared
//! across select! arms) and [`DialCtx`] (immutable wiring for new-connection
//! spawns), passed to the arm bodies by `&mut`/`&`. Fields map one-to-one
//! onto the original locals; initialization order lives in the assemble
//! stage (zero behavior change).
//!
//! Covers: the main-loop state containers and outbound dial task assembly.
//! Not covered: per-arm decision logic (arms/dial/tick modules).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use taiji_bt::mse::CryptoPolicy;
use taiji_bt::peer::AvailEvent;
use taiji_bt::peer::HashSource;
use taiji_bt::peer::PieceSource;
use taiji_bt::peer_policy::Violation;
use taiji_io::rate_limit::LimiterSet;

use taiji_domain::redial::RedialPool;
use taiji_domain::seed::{BtStopTimeoutWatch, SeedCheck, SessionSpeedCalc};

use taiji_bt::utp::PeerConnectionType;

use tracing::debug;

use crate::ban::BanBook;
use crate::dht::DialDedup;
use crate::dispatch::{LedgerArrival, RecoveryBook};
use crate::faces::{FaceState, PeerRegistration, XorShift};
use crate::progress::EngineEnd;
use crate::redial::RedialReport;
use crate::strategy::{PieceSelectionStrategy, Playhead, StreamGeo, StreamPlan};
use crate::tracker::TrackerPersistShared;
use crate::transit::{DialJob, UtpDial, peer_connect};
use taiji_domain::hash_fetch::RecoveredPieceLayer;
/// Mutable state shared across the main-loop arms (extracted; gathers the
/// former `run` locals). Field groups: swarm faces (plus ban and dispatch
/// bookkeeping), seeding/completion state, the connection task surface
/// (tasks + cuid issuance), seeding-operations gauges, session rate
/// bridging, and DHT/redial cadence anchors. Each select! arm body gets
/// `&mut self` exclusively — no concurrency between arms.
pub(super) struct EngineLoop {
    /// Swarm faces (one independent state each; see the faces module).
    pub(super) faces: Vec<FaceState>,
    /// BEP27 private bit (metainfo `private`; the hard gate behind
    /// `EngineCommand::SetDhtEnabled(true)` — runtime enable on a private
    /// engine is always refused, the same rule as libtorrent `torrent.cpp`
    /// `priv()`, which no flag can override).
    pub(super) private: bool,
    /// Peer ban bookkeeping (writes the IpGuard snapshot).
    pub(super) ban_book: BanBook,
    /// Shared tracker/progress/persistence wiring (None = nothing is persisted).
    pub(super) persist_shared: Option<TrackerPersistShared>,
    /// Tracker row flusher task handle (aborted at teardown).
    pub(super) tracker_flusher: Option<tokio::task::JoinHandle<()>>,
    /// Peer redial pool.
    pub(super) redial_pool: RedialPool,
    /// Silent-endpoint failure ledger (gates discovery dials; escalating
    /// backoff / cooldown demotion — see the silent module docs; runs beside
    /// the redial pool, neither reads the other).
    pub(super) silent_book: taiji_domain::silent::SilentBook,
    /// All faces fully downloaded (true while seeding; input to the stop/seed
    /// path return values).
    pub(super) completed: bool,
    /// Result of the bt-detach-seed-only decision (set at completion;
    /// decides SeedStopped vs Detached).
    pub(super) detached: bool,
    /// BEP21 upload_only seeding announcement (set and broadcast on entering
    /// the seeding state).
    pub(super) upload_only: bool,
    /// BEP16 super-seeding book (created when entering the seeding state).
    pub(super) super_seed: Option<Arc<taiji_bt::superseed::SuperSeedBook>>,
    /// Random source for bookkeeping (picks among tied super-seed pieces; a
    /// fixed constant seed, deterministic).
    pub(super) superseed_rng: XorShift,
    /// Upload-serving sources (initially each face's download-time partial
    /// source; replaced by the full seeding source on completion).
    pub(super) seeding_sources: Vec<Option<Arc<dyn PieceSource>>>,
    /// v2 hash-serving sources (mounted once all faces complete).
    pub(super) seeding_hash_sources: Vec<Option<Arc<dyn HashSource>>>,
    /// BEP53 select-file mask (None = select all).
    pub(super) selected_mask: Option<Arc<[bool]>>,
    /// Per-file priorities projected to a piece-level table (None = the
    /// all-zero default). The engine command `SetFilePriority` replaces it
    /// wholesale via [`crate::dispatch::priority_mask`]; it only affects
    /// piece selection order (priority desc is the primary key before
    /// rarity), not completion counts or dispatch gates (skipped files are
    /// still expressed by selected_mask -> done folding).
    pub(super) piece_priority: Option<Arc<[i8]>>,
    /// Pieces required for completion per face (pieces inside the mask once a
    /// mask applies; default = piece_count).
    pub(super) required: Vec<usize>,
    /// Shuffle source for choke rounds (leecher optimistic slot; independent
    /// XorShift state).
    pub(super) choke_rng: XorShift,
    /// Budget source for budget-derived unchoke slots: the session upload
    /// rate-limit topology (the same Arc instance as `DialCtx.limiter` —
    /// the per_torrent.up bucket is mutated atomically by `set_rate` on a
    /// hot changeOption `max-upload-limit`, and the 15s choke round reads
    /// the latest rate directly; `--max-upload-limit` attaches the bucket
    /// via SpeedLimits -> LimiterSet). Consumed by
    /// `choke::budget_derived_slots` (the choke assembly's two read
    /// points: the ticker round and the leave-triggered rerun). None = a
    /// bare CLI run with no rate limit (no budget surface to guess from —
    /// budget mode falls back to static slots).
    pub(super) limiter: Option<Arc<LimiterSet>>,
    /// Connection cuid issuer (globally unique; locates a peer across faces).
    pub(super) next_cuid: u64,
    /// Connection/handshake task set (abort_all at teardown).
    pub(super) tasks: JoinSet<()>,
    /// SeedCheck (assembly ported from aria2 `BtSetup.cc`; empty Union = None =
    /// seed forever).
    pub(super) seed_check: Option<SeedCheck>,
    /// bt-stop-timeout watch (mounted only when > 0).
    pub(super) stop_watch: Option<BtStopTimeoutWatch>,
    /// Download-rate sampling on the 1s tick (input to stop-timeout decisions).
    pub(super) speed_calc: SessionSpeedCalc,
    /// Previous sampling baseline of speed_calc.
    pub(super) last_down_sample: u64,
    /// Session time total (active = engine online; this port's convention).
    pub(super) active_secs: u64,
    /// Seeding time total after download completion.
    pub(super) seed_secs: u64,
    /// Ratio reading source (face 0's synthesized length, refreshed by tick).
    pub(super) stats_completed: Arc<AtomicU64>,
    /// Torrent-level 10s sliding-window upload rate (query surface).
    pub(super) speed_up: SessionSpeedCalc,
    /// Torrent-level 10s sliding-window download rate.
    pub(super) speed_down: SessionSpeedCalc,
    /// Upload bridging baseline (per-peer counters -> session total deltas).
    pub(super) last_up_total: u64,
    /// Download bridging baseline.
    pub(super) last_down_total: u64,
    /// TCP download bridging baseline (per-transport supply-byte metering;
    /// the leave arm subtracts this family's share — the same baseline
    /// semantics as `last_down_total`, per family).
    pub(super) last_down_tcp_total: u64,
    /// µTP-family download bridging baseline (same semantics).
    pub(super) last_down_utp_total: u64,
    /// Session-total TCP supply bytes (wire-receive convention, duplicate
    /// redundancy included; fed at the three counter-bridge points plus the
    /// leave arm's final flush). Observation surface: the data source for
    /// the 30s conn-mix log and the endgame edge log — emits real values
    /// even without SessionMetrics in bare CLI mode.
    pub(super) supply_tcp_down: u64,
    /// Session-total µTP supply bytes (same conventions).
    pub(super) supply_utp_down: u64,
    /// Rate-window base point of the 30s conn-mix log (the per-transport
    /// totals snapshot taken at the previous log line; None = never logged,
    /// the first line carries totals only, no rate). The fourth element
    /// adds dial-completion totals so the `dial_rate` delta shares the same
    /// window and base point.
    pub(super) mix_log_prev: Option<(std::time::Instant, u64, u64, u64)>,
    /// Time of the last DHT announce registration (re-announce cadence base).
    pub(super) last_dht_announce: Instant,
    /// DHT/PEX dial dedup table (source-agnostic; minimal-intervention
    /// connection management).
    pub(super) dht_dial_dedup: DialDedup,
    /// NAT external-port sync base (a change re-registers the DHT announces).
    pub(super) last_nat_announced_port: u16,
    /// ut_holepunch initiator/introducer book (main-loop exclusive, no shared
    /// lock).
    pub(super) hp_book: taiji_bt::holepunch::HolepunchBook,
    /// ut_holepunch runtime switch (on by default; EngineCommand::SetHolepunch
    /// flips it, affecting only new-connection assembly — existing
    /// connections keep their negotiated state for their lifetime).
    pub(super) hp_enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Piece-selection strategy object (default =
    /// [`crate::strategy::RarestFirstStrategy`], the direct port). Replaced
    /// atomically as a whole inside the single-writer loop via
    /// `EngineCommand::SetSchedulerPolicy` (lock-free — each select! arm
    /// holds `&mut` exclusively and the strategy is never shared across
    /// tasks); a swap affects only future selection decisions, while
    /// in-flight bookkeeping, refetch queues, and claim sets are
    /// strategy-agnostic.
    pub(super) strategy: Box<dyn PieceSelectionStrategy>,
    /// Static streaming geometry (built once from the layout in assemble;
    /// real file order, shared by all faces — the BEP52 alignment mapping
    /// makes the hybrid faces' flat piece spaces isomorphic).
    pub(super) stream_geo: Arc<StreamGeo>,
    /// Playback-head runtime state (maintained via
    /// `EngineCommand::SetStreamingPlayhead`; None = unset — the streaming
    /// strategy degrades to rarest-first, maximizing reciprocity). Affects
    /// selection only while the strategy is streaming; not persisted
    /// (advancing = calling again; the caller replays after a restart).
    pub(super) playhead: Option<Playhead>,
    /// Live disk-tier surface: the disk-policy send side (a watch
    /// single-value channel; the `EngineCommand::SetDiskPolicy` arm sends
    /// and every store pipeline receiver re-gears live — IoGate quota,
    /// flush cadence, write-merge window).
    pub(super) disk_policy_tx: tokio::sync::watch::Sender<taiji_store::disk_policy::DiskPolicy>,
    /// Live reading cell (written after the pipelines apply the tier; the
    /// `QueryDiskPolicy` reply source — the pipelines' effective value, not
    /// a config mirror).
    pub(super) disk_live: Arc<taiji_store::disk_policy::LivePolicyCell>,
    /// Hash-recovery book (one per face; entries = multi-piece files
    /// missing piece layers — the live production path since parsing
    /// started degrading to layer_missing). Single writer in the main loop
    /// (tick + reply arm + consumer arm).
    pub(super) recovery: Vec<RecoveryBook>,
    /// Recovery delivery seam (bounded by
    /// [`crate::dispatch::RECOVERY_DELIVER_CAPACITY`]; full = backpressure,
    /// the layer stays Received and retries next round). Consumer = whole-
    /// file layer admission (run::recovery_admit::consume_recovered_layer;
    /// the receiver leaves this struct and, like the other event channels,
    /// is a run() local binding — select! arms borrow separately).
    pub(super) recovery_deliver: mpsc::Sender<RecoveredPieceLayer>,
    /// Admission consumption counters (session totals of admitted /
    /// rejected; sole writer is the run::recovery_admit consumer arm — the
    /// observable face of the "failure -> drop count" decision).
    pub(super) recovery_admission: super::recovery_admit::RecoveryAdmissionStats,
    /// Gated-upgrade carriers (one per face; None = v1 face / no v2 base —
    /// expectations always complete). Holds a live copy of the expected
    /// roots plus the pipeline seam sender; after successful admission the
    /// consumer arm runs
    /// [`super::recovery_admit::activate_recovered_file`].
    pub(super) recovery_upgrade: Vec<Option<super::recovery_admit::RecoveryUpgrade>>,
    /// Recovery event tracking (the engine half of the session recovery-
    /// event surface): the activated missing-layer set plus the not-yet-
    /// promoted remainder. Single writer in the main loop (the activation
    /// emit point and the consumer arm's promotion registration —
    /// run::recovery_admit::emit_recovery_activation/note_promotions).
    pub(super) recovery_track: super::recovery_admit::RecoveryEventTrack,
    /// Dispatch debt (the tick-driven dispatch surface): event arms
    /// register face numbers pending dispatch; once the debt age reaches
    /// `dispatch::DISPATCH_DEBT_INTERVAL` the debt settles (two triggers:
    /// the loop-top age check in the main loop and the debt-ticker arm
    /// waking an idle loop). The BTreeSet dedups face numbers and settles
    /// in deterministic order; high-frequency events (each BlockSettled /
    /// each HAVE) coalesce into at most one round per face per tick window
    /// — the in-round decision order is identical to per-event dispatch;
    /// rationale and constants in the constant docs.
    pub(super) dispatch_debt: std::collections::BTreeSet<usize>,
    /// Time the debt was first noted (debt-age origin; None = no debt). Cleared
    /// on settle.
    pub(super) dispatch_debt_since: Option<Instant>,
    /// Dispatch-debt settle counts (face -> block/piece settle events since
    /// the last settle; input to the settle batch threshold). Incremented
    /// only by settle-type events (BlockSettled/PieceVerified) — HAVE
    /// advertisement storms do not count and fall to the debt-age fallback.
    pub(super) dispatch_debt_settles: std::collections::HashMap<usize, u32>,
    /// Delta-bridging baseline for the two-phase ledger observation family
    /// (the 1s seed tick reads process-level atomics and feeds increments
    /// to `SessionMetrics::note_two_phase_ledger`; the same pattern as the
    /// utp/DHT query-sample deltas). `(arrivals, degrades, guard_hits)`.
    pub(super) two_phase_obs_prev: (u64, u64, u64),
    /// Stall-detection valve (coupled state machine; `run::stall`): zero-
    /// delta download sample counts -> stall state -> urgent actions
    /// (reannounce / dispatch reset / rate-capped disconnect of starved
    /// seeders). Fed by the 1s seed tick.
    pub(super) stall_valve: super::stall::StallValve,
    /// Session dial budget (the connection_speed 30/s token bucket): every
    /// outbound dial takes one token in [`spawn_peer_dial`] (Punch exempt);
    /// single writer in the main loop with injected time (see the
    /// `run::ecology` module docs).
    pub(super) dial_budget: super::ecology::DialBudget,
    /// Discovery candidate table (tracker/DHT/PEX arms insert; the 250ms
    /// drain round dials the top N by sort key from an O(300) sample — see
    /// the `run::ecology` module docs).
    pub(super) dial_candidates: super::ecology::DialCandidates,
    /// Own v4 endpoint IP (the BEP-40 rank self-reference: probed once at
    /// assembly via `probe_source_ip(false)`, the same route-source probe
    /// the BEP42 derivation uses — see the `run::ecology` divergence note;
    /// None = probe failed -> neutral rank key 0).
    pub(super) self_v4: Option<std::net::IpAddr>,
    /// Global IPv6 availability (the probe input to v6 candidate
    /// preference): an assembly-time `probe_source_ip(true)` probe, the
    /// same call reused for the BEP7 `ipv6=` announce payload (no extra
    /// probe, no extra startup latency; false = no global v6 -> v6 sort
    /// keys always neutral). Read when drain-round rows are built
    /// (`run::ecology`).
    pub(super) self_v6_global: bool,
    /// Time of the last turnover rotation (90s cadence anchor; `run::ecology`).
    pub(super) last_turnover: Option<Instant>,
    /// Time of the last slow-peer eviction pass (30s cadence anchor;
    /// `run::ecology::slow_peer_churn_tick`).
    pub(super) last_slow_churn: Option<Instant>,
    /// Slow-peer eviction marks (addr -> mark time). Inserted where
    /// eviction lands (mark first, then shutdown); consumed by the leave
    /// arm's redial admission (a hit within TTL forces had_data false, i.e.
    /// the 60s base interval); TTL-expired entries are swept by a retain at
    /// the insertion point (inbound peers have no redial admission path, so
    /// unconsumed marks are reclaimed by TTL — bounded). Single writer in
    /// the main loop.
    pub(super) slow_evict_marks: std::collections::HashMap<SocketAddr, Instant>,
    /// (Peer registration times moved into the `registered_at` field of the
    /// `FaceState.peer_state` row when the per-peer tables were
    /// consolidated — written by the register arm, removed by the leave
    /// arm; bookkeeping unchanged.)
    /// Dial-outcome observation window (the decision input for the
    /// connect_speed environment-adaptive gating): written by the dial-
    /// outcome report arm for every completed dial (`run::holepunch::
    /// handle_hp_dial_report`), read by the drain-round gearing decision
    /// (250ms cadence; window size and denominator conventions in the
    /// `run::ecology::DialOutcomeWindow` docs). Single writer in the main
    /// loop.
    pub(super) dial_outcomes: super::ecology::DialOutcomeWindow,
    /// Dial decay ladder position (constants and the pure
    /// transition in `run::ecology`): one-per-window steps taken while
    /// the outcome window reads sustained >85% failure. 0 = no decay.
    /// Read/written by the 250ms drain round; `BH_DIAL_BACKOFF=0` pins
    /// it at 0.
    pub(super) dial_decay_steps: u32,
    /// Current connect_speed **gear** (base 30 / hostile 100 / override)
    /// tracked separately from the bucket's applied rate (the applied
    /// rate is `dial_decay_rate(gear, eff_steps)` — decay composes
    /// on top): the gear-hold branch of [`super::ecology::
    /// connect_speed_for`] holds this value on insufficient samples, so
    /// decay never compounds through the hold path and gear transitions
    /// log once, not per 250ms round.
    pub(super) dial_gear: u32,
    /// Anchor of the last ladder transition (step or recovery): a step
    /// down is admissible only after a full 30s outcome window since the
    /// anchor, so the 250ms round's repeated readings of one window
    /// count as one step (worst-case descent 4 x 30s = 2min).
    pub(super) dial_decay_anchor: Instant,
    /// Holepunch observation bridging baseline (the 1s seed tick reads
    /// process-level atomics and feeds increments to
    /// `SessionMetrics::note_holepunch`; the same pattern as the two-phase
    /// baseline, always zero at session start).
    pub(super) hp_obs_prev: super::holepunch::HolepunchObs,
    /// Webseed pseudo-peer cuid book (pre-registered at assembly by
    /// `attach_webseeds`; the lookup behind the [`Self::is_webseed`]
    /// exemption — turnover, slow-churn, and stall sweeps all skip these
    /// rows). Entries are not removed on leave (cuids are per-connection
    /// unique and a webseed never reappears; capacity bound = the assembly
    /// limit of 8).
    pub(super) webseed_cuids: std::collections::HashSet<u64>,
    /// In-flight dial count (data source for the 30s pool-curve `dial_ifl`
    /// line): incremented synchronously at spawn (counted even before the
    /// task is polled — the observation lower bound is the truth),
    /// decremented by the [`DialInflightGuard`] Drop endgame (both the
    /// peer_connect return and teardown abort_all paths converge). Shared
    /// by Arc with the dial tasks; the main loop only reads (tick).
    pub(super) dial_ifl: Arc<std::sync::atomic::AtomicI64>,
    /// Completed-dial total (delta source for the 30s-window `dial_rate`):
    /// incremented after `peer_connect` returns normally in the wrapper
    /// task (the abort/teardown path does not count as completion — the
    /// convention is dials that ran their full plan). Shared by Arc with
    /// the dial tasks; the main loop reads deltas.
    pub(super) dial_done: Arc<AtomicU64>,
}

impl EngineLoop {
    /// Notes dispatch debt for one face (called on the event-arm hot path;
    /// once per block/advertisement event, BTreeSet insert O(log faces) —
    /// faces are single-digit, the constant is negligible). The first note
    /// sets the debt-age origin (the settle-cadence timing anchor).
    pub(super) fn note_dispatch_debt(&mut self, fi: usize) {
        if self.dispatch_debt.insert(fi) && self.dispatch_debt_since.is_none() {
            self.dispatch_debt_since = Some(Instant::now());
        }
    }

    /// Notes dispatch debt and bumps the settle count (settle-type events
    /// only — BlockSettled/PieceVerified; input to the batch-threshold
    /// settle).
    pub(super) fn note_dispatch_settle(&mut self, fi: usize) {
        self.note_dispatch_debt(fi);
        *self.dispatch_debt_settles.entry(fi).or_default() += 1;
    }

    /// Webseed pseudo-peer predicate (the row-collection/sweep exemption):
    /// the cuid belongs to the webseed set pre-registered at assembly
    /// (`run::dial::attach_webseeds`). Exemption consumers: turnover row
    /// collection (ecology.rs), slow-churn row collection (ecology.rs
    /// `slow_churn_faces`), and the stall rotation scan (stall.rs) — CDNs
    /// have unlimited patience, slowness is transient (Range requests queue
    /// behind the concurrency gate), and the "evict for a faster candidate"
    /// rationale does not apply (a webseed has no candidate pool). Naturally
    /// exempt from utp_mute (a TCP gate); unaffected on the choke side
    /// (webseeds are never interested, so leecher choke sorting skips them
    /// — choke.rs regular/optimistic slots pick interested peers only).
    pub(super) fn is_webseed(&self, cuid: u64) -> bool {
        self.webseed_cuids.contains(&cuid)
    }
}

/// Shared wiring for new-connection spawns (extracted; gathers the
/// immutable `run` locals). The tracker/DHT/PEX/redial/inbound-accept arms
/// clone fields as needed (equivalent to the original per-use
/// `xxx.clone()` — same values, same clone counts).
pub(super) struct DialCtx {
    /// Local peer id (handshake payload).
    pub(super) peer_id: [u8; 20],
    /// MSE crypto policy (shared by inbound sniffing and outbound initiation).
    pub(super) crypto: CryptoPolicy,
    /// Outbound transport plan (`--bt-peer-connection-type`).
    pub(super) conn_type: PeerConnectionType,
    /// BEP10 extension config (ut_metadata serving + ut_pex advertisement).
    pub(super) ext: taiji_bt::peer::ExtConfig,
    /// Rate-limit topology (None = none attached).
    pub(super) limiter: Option<Arc<LimiterSet>>,
    /// DHT attach slot (swapped by runtime enable/disable; an empty slot =
    /// not enabled. Sends PORT after the handshake and forwards inbound
    /// PORT; read when a new dial is assembled).
    pub(super) attach_dht: super::super::dht::AttachDhtSlot,
    /// µTP outbound dial surface.
    pub(super) utp_dial: UtpDial,
    /// Sender for connection-registration events.
    pub(super) reg_tx: mpsc::Sender<PeerRegistration>,
    /// Sender for connection-leave events (the payload carries the leave
    /// reason, a connection-retention observation — the five
    /// [`crate::LeaveKind`] projections).
    pub(super) leave_tx: mpsc::Sender<(usize, u64, crate::LeaveKind)>,
    /// Sender for protocol-violation events.
    pub(super) violation_tx: mpsc::Sender<Violation>,
    /// Redial report sender (Some only on the redial path).
    pub(super) redial_tx: mpsc::Sender<RedialReport>,
    /// ut_holepunch event sender (PeerTask -> main loop; None = gate closed).
    pub(super) holepunch: Option<taiji_bt::peer::HolepunchExt>,
    /// ut_holepunch runtime switch (the same Arc as EngineLoop.hp_enabled).
    pub(super) hp_enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Dial-outcome report sender (carried by every outbound dial).
    pub(super) hp_report_tx: mpsc::Sender<super::holepunch::HpDialReport>,
    /// Per-face availability event senders (injected at dial; indexed by face).
    pub(super) avail_tx_face: Vec<mpsc::Sender<AvailEvent>>,
    /// Block-arrival event sender (engine-level single channel; injected by
    /// outbound DialJob and inbound attach — emitted at the successful
    /// block_tx.send point in the forwarding loop).
    pub(super) ledger_tx: mpsc::Sender<LedgerArrival>,
    /// ext handshake `v` field identity re-check callback (shared by
    /// inbound and outbound attach; None = no re-check — the test assembly
    /// form).
    pub(super) client_deny: Option<taiji_bt::peer::ClientDenyCheck>,
}

impl DialCtx {
    /// Holepunch wiring at attach time (channel present AND runtime switch on).
    pub(super) fn holepunch_attach(&self) -> Option<taiji_bt::peer::HolepunchExt> {
        self.holepunch
            .clone()
            .filter(|_| self.hp_enabled.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl EngineLoop {
    /// Return value for the token-cancel arm: a completed engine takes the
    /// seeding-end path (Detached wins), otherwise it is a user cancel.
    pub(super) fn end_on_cancel(&self) -> EngineEnd {
        if self.completed {
            if self.detached {
                EngineEnd::Detached
            } else {
                EngineEnd::SeedStopped
            }
        } else {
            EngineEnd::Cancelled
        }
    }

    /// Dispatch-round payload: combines the static geometry when a playhead
    /// is present (an Arc clone + Copy — no locks or overlapping borrows in
    /// dispatch parameter passing).
    pub(super) fn stream_plan(&self) -> Option<StreamPlan> {
        self.playhead.map(|playhead| StreamPlan {
            playhead,
            geo: Arc::clone(&self.stream_geo),
        })
    }

    /// Total registered peers across all faces (the admission gate's
    /// counter — the analog of aria2 `BtRuntime::getConnections()`. An
    /// O(faces) sum inside the single-writer loop; faces are single-digit).
    pub(super) fn registered_peers(&self) -> usize {
        self.faces.iter().map(|f| f.peer_cuids.len()).sum()
    }

    /// Connection admission decision: `hard_cap` selects the hard-cap form
    /// (inbound / seeding dials), false the outbound-target form (leecher
    /// discovery dials). Returns true = admit.
    ///
    /// Rules (aria2 semantics ported; upstream anchors in the constant
    /// docs):
    /// - count below the threshold -> admit (the same form as
    /// `BtRuntime.h`); the threshold is the hard cap when `hard_cap` or
    /// seeding, the target count for leecher outbound dials;
    /// - a leecher with download rate below [`PEER_REQUEST_SPEED_LIMIT`] ->
    /// admitted anyway (`PeerReceiveHandshakeCommand.cc` /
    /// `ActivePeerConnectionCommand.cc`: slow download means connection
    /// count yields to supply — the structural anti-starvation guard; the
    /// gate only tightens while the download is healthy);
    /// - the seeding state (`completed`) has no rescue arm (aria2's seeder
    /// branch has only the count gate,
    /// `ActivePeerConnectionCommand.cc`).
    pub(super) fn admission_open(&mut self, hard_cap: bool, now: Instant) -> bool {
        let speed = self.speed_calc.calculate(now);
        // Download-healthy = seeding (no supply demand; the gate counts
        // only) OR the leecher rate reaches the threshold (slow download =
        // supply shortage; the in-gate rescue arm admits). The threshold is
        // read through the CLI override seam (`--bt-request-peer-speed-
        // limit`: unset keeps the existing 50K default, zero behavior
        // change; explicit 0 = threshold 0 -> always healthy -> the rescue
        // arm off; aria2's NumberOptionHandler min 0 covers the same
        // domain).
        let download_healthy = self.completed
            || speed >= taiji_io::knobs::peer_request_speed_limit(PEER_REQUEST_SPEED_LIMIT);
        admission_verdict(
            self.registered_peers(),
            self.completed,
            download_healthy,
            hard_cap,
        )
    }
}

/// Connection admission decision; reads the effective limits through the
/// runtime override seams [`peer_connections_target`] /
/// [`peer_connections_max`] (the [`PEER_CONNECTIONS_TARGET`] /
/// [`PEER_CONNECTIONS_MAX`] defaults when the env knobs are unset).
/// Decision semantics and upstream anchors: see the constant and wrapper
/// docs; table-driven callers use [`admission_verdict_limits`].
pub(crate) fn admission_verdict(
    total: usize,
    completed: bool,
    download_healthy: bool,
    hard_cap: bool,
) -> bool {
    admission_verdict_limits(
        total,
        completed,
        download_healthy,
        hard_cap,
        peer_connections_target(),
        peer_connections_max(),
    )
}

/// Pure decision core for connection admission (explicit limit arguments —
/// the seam for decision-table tests and fallback-value locking; the body
/// of [`EngineLoop::admission_open`]; semantics and upstream anchors in
/// the constant and wrapper docs).
///
/// - Threshold: `hard_cap || completed` -> hard cap; otherwise (the
/// leecher outbound-target form) -> target count;
/// - Rescue: only for a leecher (`!completed`) with an unhealthy download,
/// tightened to relax at most up to the hard cap (`max`), never
/// unbounded — connection growth with no supply only burns CPU without
/// bringing bytes; aria2's slow-download top-up is likewise count-bounded
/// (`ActivePeerConnectionCommand.cc`: at most 5 connections per 10s,
/// still inside the `bt-max-peers` hard cap). The anti-starvation band
/// from target to hard cap (default 100-120; fallback 51-64) stays open
/// during stalls (including the redial previously-connected-first band);
/// the stall valve (`run::stall`) aims the top-up at supply.
pub(crate) fn admission_verdict_limits(
    total: usize,
    completed: bool,
    download_healthy: bool,
    hard_cap: bool,
    target: usize,
    max: usize,
) -> bool {
    let limit = if hard_cap || completed { max } else { target };
    if total < limit {
        return true;
    }
    if completed {
        return false;
    }
    // Slow-download rescue (tightened): during a stall the count may still
    // grow from target up to the hard cap, never beyond.
    !download_healthy && total < max
}

/// Connection admission hard cap (count of registered peers, inbound
/// included).
///
/// Upstream anchors: aria2-next 2.8.3 ships a per-torrent `bt-max-peers`
/// default of 100 (`options/BitTorrentOptions.cc` `PREF_BT_MAX_PEERS`) and
/// a global `connections_limit` default of 500 (`PREF_BT_MAX_CONNECTIONS`,
/// written into libtorrent `settings_pack::connections_limit` via
/// `BtSettings.cc`) — 2.5x libtorrent's own default of 200
/// (`settings_pack.cpp`); libtorrent caps the setting by process fd
/// capacity at construction, reserving 20% for files.
///
/// 120 here = the per-torrent figure (100) x 1.2: the gate counts
/// registered peers, so the headroom absorbs in-flight handshake overshoot
/// (the same headroom reasoning as the previous 64, one step above aria2's
/// default 55). Intentional divergence: 120 is not aria2's 100 itself —
/// the hard cap sits one step above the per-torrent limit to carry the
/// handshake window; the decision form is unchanged (`BtRuntime.h`
/// `maxPeers_ == 0 || connections_ < maxPeers_`).
///
/// # Memory (block arena x connections)
///
/// Per-peer block-pool in-flight is roughly checkout 4 pieces x 16 KiB:
/// 120 peers x 16 KiB x 4 pieces = about 7.5 MiB of pool-cap headroom (a
/// single source for the budget formulas — the pipeline's
/// `wr_cache_limit`, `block_arena_for_face`, and `spill_floor` all consume
/// [`peer_connections_max`] and size with this value; caches and pools are
/// caps, not preallocations, so steady-state RSS is unchanged). No CLI/RPC
/// option surface; the runtime override seam is
/// [`peer_connections_max`] (`BH_PEER_MAX`, the load-test/fallback seam
/// convention).
pub(crate) const PEER_CONNECTIONS_MAX: usize = 120;

/// Outbound dial target (the leecher-period discovery dial gate).
///
/// TARGET semantics: a steady-state target for hostile environments, not
/// an aspirational figure for good ones — in NAT/hostile dialing worlds
/// the loss rate on "reaching a peer" is high, and a gate converging on a
/// low target count leaves too few effective connections; in friendly
/// environments the count reaches TARGET naturally, and seeding beyond
/// TARGET is governed by separate gates (hard cap + turnover,
/// [`PEER_CONNECTIONS_MAX`]).
///
/// Anchors: aligned with aria2-next's per-torrent `bt-max-peers` = 100
/// (`options/BitTorrentOptions.cc`; the discovery top-up drive chain —
/// `TrackerWatcherCommand.cc` `while (lessThanMinPeers())` plus
/// `PeerInitiateConnectionCommand.cc`'s chained `lessThanEqMinPeers()`
/// gate — keeps its semantics). Intentional divergence: no longer
/// [`PEER_CONNECTIONS_MAX`] x 0.8 (the derivation behind aria2
/// `BtRuntime.cc`'s old `minPeers_ = maxPeers * 0.8` = 51) — under
/// aria2-next's own configuration that formula yields 80, still below its
/// per-torrent cap; this codebase targets 100 directly, keeping the
/// target < hard-cap ordering invariant (admission still caps at the hard
/// cap). Runtime override seam: [`peer_connections_target`]
/// (`BH_PEER_TARGET`).
pub(crate) const PEER_CONNECTIONS_TARGET: usize = 100;

/// Runtime override for the connection hard cap (the fallback seam): reads
/// `BH_PEER_MAX` lazily once per process (same shape as
/// `multi_piece_checkout_cap`, the dispatch.rs convention); parse failure
/// or zero falls back to [`PEER_CONNECTIONS_MAX`]. `BH_PEER_MAX=64`
/// restores the previous 64-era configuration bit-for-bit (the capacity
/// formulas shrink with the value). Parse and read-timing registration in
/// `taiji_io::knobs` (a process-level OnceLock, unchanged).
pub(crate) fn peer_connections_max() -> usize {
    taiji_io::knobs::peer_max(PEER_CONNECTIONS_MAX)
}

/// Runtime override for the outbound target (the fallback seam):
/// `BH_PEER_TARGET` in the same shape; parse failure or zero falls back
/// to [`PEER_CONNECTIONS_TARGET`]. Defensive clamp: target = min(target,
/// hard cap) — "target < hard cap" is an admission-ordering invariant the
/// rescue-band semantics rely on; a target above the cap is meaningless.
/// `BH_PEER_TARGET=51` restores the previous value.
pub(crate) fn peer_connections_target() -> usize {
    taiji_io::knobs::peer_target(PEER_CONNECTIONS_TARGET).min(peer_connections_max())
}

/// Supply-shortage rescue threshold (bytes/s; the anti-starvation valve of
/// the admission gate): while a leecher's download rate is below this, the
/// outbound dial gate and the inbound admission gate open fully —
/// connection count yields to supply. Upstream anchors: aria2
/// `--bt-request-peer-speed-limit` defaults to 50K
/// (`OptionHandlerFactory.cc`); the consumers mirror it — inbound
/// `PeerReceiveHandshakeCommand.cc`
/// `(!finished && downloadSpeed < threshold) || lessThanMaxPeers()`,
/// outbound `ActivePeerConnectionCommand.cc` leecher branch
/// `downloadSpeed < threshold || lessThanMinPeers()` (slow -> more
/// connections, fast -> converge on the count). The rate reading is the
/// session 10s sliding window `SessionSpeedCalc` (fed by the existing 1s
/// tick, `run::tick`).
pub(crate) const PEER_REQUEST_SPEED_LIMIT: u64 = 50 * 1024;

/// Outbound dial source (an input to the gate decisions; the
/// [`spawn_peer_dial`] parameter).
///
/// Standing of the three sources relative to the silent-endpoint ledger
/// (the silent module's "relations" section):
/// - `Discovery` (tracker/DHT/PEX): gated — skipped inside cooldown or
/// backoff windows;
/// - `Punch` (the ut_holepunch connect command): exempt — the introducer
/// asserts reachability, which is fresh external evidence (the same
/// spirit as libtorrent's tracker-reannounce count reduction,
/// `peer_list.cpp`), and holepunch peers are often NAT peers that are
/// silent to direct dials but alive via punch;
/// - `Redial` (the redial pool): exempt — the pool manages its own failure
/// policy (60s base backoff, drop after 3 failures, unchanged).
#[derive(Debug)]
pub(super) enum DialSource {
    /// Discovery surface (tracker Peers / DHT PeersFound / ut_pex).
    Discovery,
    /// Holepunch outbound dial (rendezvous connect).
    Punch,
    /// Redial-pool scan (carries the result report sender).
    Redial(mpsc::Sender<RedialReport>),
}

/// Assembles and spawns an outbound dial task (shared by the five sources:
/// tracker/DHT/PEX/holepunch/redial; the DialJob literal maps one-to-one
/// onto the original sites — cuid issuance order, discovery counting, and
/// the IpGuard handle clone points all stay in place, zero behavior
/// change). `initial_source`/`initial_hash_source` = a snapshot of the
/// face's current upload-serving source (the full source while seeding).
///
/// Discovery sources pass the silent-endpoint gate at this assembly point —
/// endpoints inside cooldown/backoff windows skip the dial (a debug log,
/// the same no-silence discipline as bans); other sources are exempt
/// ([`DialSource`]).
///
/// Returns whether a task was actually spawned: interception by any gate
/// (hygiene / redial admission / silent ledger / token bucket) = false.
/// Existing callers (the drain round, the redial scan, punch_dial) ignore
/// the return value — zero behavior change; the only consumer is the PEX
/// immediate-dial surface (`run::dial::handle_pex_event`: a candidate
/// leaves the table only on a successful spawn, otherwise it stays for the
/// drain-round fallback).
#[expect(
    clippy::too_many_arguments,
    reason = "the dial entry takes the per-dial inputs directly; a bundle struct would not help"
)]
pub(super) fn spawn_peer_dial(
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
    fi: usize,
    addr: SocketAddr,
    source: DialSource,
    initial_source: Option<Arc<dyn PieceSource>>,
    initial_hash_source: Option<Arc<dyn HashSource>>,
) -> bool {
    // Single choke point at the dial entry: the tracker/DHT/PEX arms
    // already ran hygiene checks on entry (refused addresses never enter
    // counters or bookkeeping); this catch-all covers sources that bypass
    // the arm bodies — redial pool entries (endpoints of existing
    // connections, defensively rechecked) and punch targets (untrusted
    // addresses reported by the introducer; the ut_holepunch connect
    // command is a potential local probe-injection surface). Reuses
    // [`crate::addr_hygiene`] as the single classifier; no
    // re-classification here.
    let Some(addr) = crate::addr_hygiene::sanitize_discovered_addr(addr) else {
        debug!(target: "taiji::core::engine", raw = %addr, ?source,
            "dial target rejected by address hygiene ");
        return false;
    };
    // Connection admission gate (aria2 bt-max-peers/minPeers semantics;
    // the decision form in [`EngineLoop::admission_open`]). Per-source
    // rules:
    // - Discovery: the gate sits at the arm side (tracker/DHT/PEX arms
    // check it before consuming the dedup window, `run::dial`) — an
    // address stopped by the gate does not burn its dedup window and is
    // retried on the next announce/PEX supply (the top-up chain stays
    // unbroken; consuming first and refusing after would leave a static
    // tracker list unable to top up for a whole announce window once
    // peers leave);
    // - Redial: the gate sits at this assembly point (hard-cap form) —
    // between target and cap, previously-connected peers may still
    // re-connect first (admission tiers: a peer with recent successful
    // interaction outranks a bare discovery address); when over the limit
    // with a healthy download, top-ups pause and entries self-heal via
    // due()'s optimistic deferral (never dropped);
    // - Punch: exempt (introducer-asserted reachability is fresh external
    // evidence, a standing rule; its outbound rate is already bounded by
    // the dedup window plus the 4/60s PeerTask rate limit).
    if let DialSource::Redial(_) = &source
        && !state.admission_open(true, std::time::Instant::now())
    {
        debug!(target: "taiji::core::engine", %addr, ?source,
            registered = state.registered_peers(),
            max = peer_connections_max(),
            "redial skipped by connection admission ");
        return false;
    }
    // Silent-endpoint gate (Discovery sources only; read/updated
    // synchronously in the main loop, lock-free).
    let redial = match &source {
        DialSource::Redial(tx) => Some(tx.clone()),
        DialSource::Punch => None,
        DialSource::Discovery => match state.silent_book.admit(&addr, std::time::Instant::now()) {
            taiji_domain::silent::SilentVerdict::Allowed => None,
            verdict @ (taiji_domain::silent::SilentVerdict::Backoff
            | taiji_domain::silent::SilentVerdict::Cooldown) => {
                debug!(target: "taiji::core::engine", %addr, ?verdict,
                        book = state.silent_book.len(),
                        "dial skipped by silent book ");
                return false;
            }
        },
    };
    let cuid = state.next_cuid;
    state.next_cuid += 1;
    // Session dial throttle (connection_speed 30/s: a port of libtorrent
    // try_connect_more_peers' per-tick quota with tracker/DHT boosts
    // deducted from it, session_impl.cpp snapshot — see the `run::ecology`
    // module docs). Placed after every other gate: addresses refused
    // elsewhere do not burn budget. Punch is exempt (introducer-asserted
    // reachability is fresh external evidence; the existing 4/60s PeerTask
    // self-limit stands). An exhausted quota skips this dial — Redial
    // entries self-heal via due()'s optimistic deferral, Discovery
    // candidates stay in the candidate table for the next drain round (the
    // same effect as upstream boosts carrying over across ticks).
    if !matches!(source, DialSource::Punch) && !state.dial_budget.take1(std::time::Instant::now()) {
        debug!(target: "taiji::core::engine", %addr, ?source,
            "dial skipped by connection budget (connection_speed)");
        return false;
    }
    let face = &state.faces[fi];
    let job = DialJob {
        addr,
        face: fi,
        info_hash: face.info_hash,
        peer_id: dial.peer_id,
        reserved: face.reserved,
        cuid,
        addressing: face.addressing.clone(),
        // Upper-bound predicate for unsolicited block coordinates (a
        // face-shared table, Arc clone).
        piece_bytes: face.piece_bytes.clone(),
        avail_tx: dial.avail_tx_face[fi].clone(),
        initial_source,
        initial_hash_source,
        ext: dial.ext.clone(),
        reg_tx: dial.reg_tx.clone(),
        leave_tx: dial.leave_tx.clone(),
        block_tx: face.block_tx.clone(),
        block_senders: face.block_senders.clone(),
        // Direct-write seam: knob on -> mint a face-level sink per
        // connection (read at DialJob assembly, never on the block hot
        // path); off -> None = the legacy path.
        block_sink: face.block_sink_for(cuid),
        ledger_tx: dial.ledger_tx.clone(),
        guard: state.ban_book.guard.clone(),
        violation_tx: dial.violation_tx.clone(),
        parent: token.clone(),
        crypto: dial.crypto,
        conn_type: dial.conn_type,
        utp: dial.utp_dial.clone(),
        // Attach slot value (swapped by runtime enable/disable; applies to new
        // dials immediately).
        dht: dial.attach_dht.get(),
        limits: dial.limiter.clone(),
        redial,
        holepunch: dial.holepunch_attach(),
        hp_report: Some(dial.hp_report_tx.clone()),
        client_deny: dial.client_deny.clone(),
        // Face-level read pool: the serve-read service shared by the face's
        // outbound connections.
        read_pool: face.read_pool.clone(),
        block_arena: face.block_arena.clone(),
        // Punch-source marker (a feed-point predicate): source = Punch,
        // independent of the mode switch; HpDialReport.punch rides along
        // (with the BH_HOLEPUNCH_MODE=0 fallback, punch dials take the
        // regular plan and punch_established is still fed — a pure
        // observation add-on).
        punch: matches!(source, DialSource::Punch),
        // Mode gate: punch AND BH_HOLEPUNCH_MODE (read at DialJob assembly
        // — env vars are never read inside the dial task, the same
        // discipline as BH_BLOCK_BYPASS). true = peer_connect's punch-
        // dedicated path (µTP stickiness + fast in-window retries); false =
        // the regular plan path, bit-identical to today.
        punch_mode: matches!(source, DialSource::Punch)
            && super::holepunch::holepunch_mode_enabled(),
        // Dead-address reading (an assembly-time snapshot, read-only): the
        // plan loop's µTP-arm trim input (fails >= 1 AND the knob on ->
        // skip; the punch path does not consume it). Read identically for
        // all three sources — the Redial/Punch exemption belongs to the
        // silent-endpoint gate (they may dial); trimming only removes the
        // µTP second try for dead addresses, never the dial itself.
        fails: state.silent_book.fails(&addr),
    };
    // In-flight dial observation (the 30s pool-curve dial_ifl line):
    // synchronous inc at spawn (the observation lower bound is the truth),
    // Drop-endgame dec in the wrapper task; the completion count gets +1
    // only after peer_connect returns normally (aborts excluded).
    // Observation only — dial semantics untouched.
    state
        .dial_ifl
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ifl = Arc::clone(&state.dial_ifl);
    let done = Arc::clone(&state.dial_done);
    state.tasks.spawn(async move {
        let _guard = DialInflightGuard { ifl };
        peer_connect(job).await;
        done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    true
}

/// In-flight dial guard (the Drop endgame): the count is incremented at
/// spawn and this guard owns the handle — both `peer_connect` returning
/// normally (the async move block ends) and engine teardown
/// `JoinSet::abort_all` (the future is dropped) trigger Drop -> dec, so
/// the count can never dangle.
struct DialInflightGuard {
    ifl: Arc<std::sync::atomic::AtomicI64>,
}

impl Drop for DialInflightGuard {
    fn drop(&mut self) {
        self.ifl.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}
