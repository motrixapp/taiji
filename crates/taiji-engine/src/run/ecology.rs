//! Connection ecology governance: session-level dial throttling (the
//! connection_speed token bucket) + the discovery-face candidate table
//! (synthesized sort keys + O(300) sampled top-N) + peer turnover.
//!
//! Mechanism summaries, upstream anchor mapping, and the intentional
//! divergences (sort-key omissions, turnover interval/count, µTP
//! zero-throughput governance, hostile-dial adaptation, slow-peer
//! eviction): docs/design/engine.md.
//!
//! Hard invariants: the candidate table is bounded
//! ([`DIAL_CANDIDATE_CAP`]; full rejects new entries; TTL sweep) and
//! every outbound dial takes 1 token at the spawn point
//! ([`super::state::spawn_peer_dial`]); budget / table / turnover
//! bookkeeping is main-loop exclusive (no shared locks); time is an
//! injected `Instant` and unit tests never sleep (the silent.rs /
//! redial.rs style).

use std::cmp::Ordering;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use taiji_bt::dht::is_exempt_ip;
use taiji_bt::peer::PeerHandle as _;
use taiji_bt::peer_policy::bep40_rank;
use taiji_bt::utp::Transport;

use super::state::{DialCtx, DialSource, EngineLoop, spawn_peer_dial};

use taiji_domain::silent::SilentVerdict;

use super::state::peer_connections_max;

use crate::bitmap::PieceBitmap;
use crate::faces::FaceState;

// ---------------------------------------------------------------------------
// Dial throttling (connection_speed token bucket)
// ---------------------------------------------------------------------------

/// Session-wide per-second dial budget, base rate (the libtorrent
/// `settings_pack.cpp` `SET(connection_speed, 30, ...)` default).
pub(crate) const CONNECTION_SPEED: u32 = 30;

/// Hostile-tier rate: the speed-up target when the dial failure rate
/// exceeds the threshold. A conservative 100, the lower bound of the
/// 100-200 range commonly raised when SYNs time out en masse;
/// reference upper-bound analogy: vendored 2.1.1 `session_impl.cpp`
/// clamps negative values to 200 (100 sits inside that band).
pub(crate) const CONNECTION_SPEED_HOSTILE: u32 = 100;

/// Hostile verdict threshold: observed-window failure rate > 50%
/// (strictly greater).
pub(crate) const DIAL_FAILURE_RATE_PCT: u64 = 50;

/// Minimum samples for the hostile verdict: at least 20 dial outcomes
/// in the window before a gear shift is allowed — a small-sample guard
/// (a single failure or transient jitter must not shift gears).
pub(crate) const DIAL_FAILURE_MIN_ATTEMPTS: u64 = 20;

/// Dial-outcome observation window: 30s, the same cadence family as the
/// 30s download rate window (down_windows, the turnover transfer-key
/// reading). An expired window rolls over (shift decisions look only at
/// the current window).
pub(crate) const DIAL_OUTCOME_WINDOW: Duration = Duration::from_secs(30);

/// Half-open concurrency guard cap: dial rate x the 10s TCP dial budget
/// (this codebase dials TCP with a 10s budget, a deliberate tightening
/// of libtorrent's 15s peer_connect_timeout) = the upper bound on
/// instantaneous half-open SYNs (100/s x 10s = 1000) — home-router NAT
/// tables hold roughly 1024-4096 entries, so the cap of 512 halves the
/// rate face's half-open footprint. Read at the drain-round budget
/// `min` (at the defaults it does not bind: hostile 100 < 512; it binds
/// when `BH_CONNECT_SPEED` is set to a large value).
pub(crate) const DIAL_HALFOPEN_CAP: usize = 512;

/// `BH_CONNECT_SPEED` explicit override: a value >= 1 pins the rate
/// (adaptive shifting disabled; `BH_CONNECT_SPEED=30` restores the
/// fixed default); unset/non-numeric/0 = no override (0 is illegal — a
/// zero rate permanently refuses dials — and is treated as unset).
/// Read once at assembly ([`DialBudget::from_env`]; a process-level
/// knob, not hot-reloaded). Parse registry: `taiji_io::knobs`
/// (construction-time read, no caching layer).
pub(crate) fn connect_speed_override() -> Option<u32> {
    taiji_io::knobs::connect_speed_override()
}

/// v6-candidate-preference switch: `BH_V6_PREF=0` -> the sort key is
/// constantly false (neutral, zero decision change); any other value
/// (incl. unset) -> v6 candidates are preferred when global v6 is
/// available. Read at the drain round (250ms cadence, not hot path).
/// Parse registry: `taiji_io::knobs` (read each round).
pub(crate) fn v6_pref_enabled() -> bool {
    taiji_io::knobs::v6_pref_enabled()
}

/// `BH_CONNECT_SPEED_HOLD` gear-hold switch: `=0` -> insufficient
/// samples fall back to the base rate and gear shifts do not re-anchor
/// (prior behaviour bit-for-bit); any other value (incl. unset) -> gear
/// hold on. Read at the drain round (250ms cadence, not hot path).
/// Parse registry: `taiji_io::knobs` (read each round).
pub(crate) fn connect_speed_hold_enabled() -> bool {
    taiji_io::knobs::connect_speed_hold_enabled()
}

/// Gear-shift decision (pure function, table-driven tests): an explicit
/// override wins (adaptive shifting disabled, floor 1) -> the hostile
/// tier when the window holds at least [`DIAL_FAILURE_MIN_ATTEMPTS`]
/// samples and the failure rate exceeds [`DIAL_FAILURE_RATE_PCT`]; the
/// base rate otherwise. Exactly 50% does not shift (strictly greater).
/// Insufficient samples = **hold `current`** (an empty window is not
/// evidence for a downshift); the fallback assembly
/// (`BH_CONNECT_SPEED_HOLD=0`) passes the base rate, restoring the
/// prior "insufficient samples = base rate" behaviour bit-for-bit.
pub(crate) fn connect_speed_for(
    override_speed: Option<u32>,
    attempts: u64,
    failures: u64,
    current: u32,
) -> u32 {
    if let Some(v) = override_speed {
        return v.max(1);
    }
    if attempts < DIAL_FAILURE_MIN_ATTEMPTS {
        return current.max(1);
    }
    if failures.saturating_mul(100) > attempts.saturating_mul(DIAL_FAILURE_RATE_PCT) {
        CONNECTION_SPEED_HOSTILE
    } else {
        CONNECTION_SPEED
    }
}

// ---------------------------------------------------------------------------
// Dial decay ladder (sustained-failure dial backoff)
// ---------------------------------------------------------------------------

/// Dial decay verdict threshold: sustained window failure rate > 85%
/// (strictly greater) is "hostile-and-hopeless" — distinct from the
/// hostile *gear* (>50%, which speeds dialing up for download recovery):
/// past 85% the marginal dial is almost surely another dead address, and
/// the effective rate steps down the decay ladder instead (bench runs
/// measured
/// 86-90% at 17-18 dials/s in the idle-seeding bench shape).
pub(crate) const DIAL_DECAY_PCT: u64 = 85;

/// Effective-rate floor (dials/s): low enough to halve the measured
/// 17-18/s churn, high enough that a live swarm's fresh-candidate supply
/// (never-tried addresses are unaffected by the ladder — the dead-address
/// window and the sort keys both rank them first) still lands ~1 useful
/// connect/s at the measured 10-14% success rate.
pub(crate) const DIAL_DECAY_FLOOR: u32 = 8;

/// Ladder cap: gear >> 4 bottoms out at the floor for both gears
/// (100 -> 6 -> floor 8; 30 -> 1 -> floor 8), so the cap only bounds
/// recovery time (<= 4 step windows = <= 2min from any state).
pub(crate) const DIAL_DECAY_MAX_STEPS: u32 = 4;

/// pool_known coupling threshold ("lower the dial frequency when pool_known
/// is high"):
/// once the known-address table holds >= 512 entries (half its cap; the
/// bench shape measured 742-812), the discovery frontier is largely
/// burned — retries hit known-dead territory — and one extra decay step
/// applies while the table stays that large.
pub(crate) const DIAL_POOL_KNOWN_HIGH: usize = 512;

/// `BH_DIAL_BACKOFF` dial-backoff master switch (=0 restores the legacy
/// shapes: no decay ladder, flat 10min dedup window). Default on. Parse
/// registry: `taiji_io::knobs` (read at the 250ms drain round and at
/// dial-outcome events; not cached).
pub(crate) fn dial_backoff_enabled() -> bool {
    taiji_io::knobs::dial_backoff_enabled()
}

// ---------------------------------------------------------------------------
// Completed-state passive DHT (opt-in behavior flag, default
// off — for the NS line to adjudicate)
// ---------------------------------------------------------------------------

/// `BH_SEED_PASSIVE_DHT` read (=1 on; anything else incl. unset = off,
/// the current always-active behavior).
pub(crate) fn seed_passive_dht_enabled() -> bool {
    taiji_io::knobs::seed_passive_dht_enabled()
}

/// Completed-state passive-DHT suppression decision (pure; table-tested):
/// with the switch on and every face complete, the engine stops
/// re-issuing DHT announce/get_peers registration rounds (the 2s-tick
/// re-issue and the NAT port-change re-register). The node itself stays a
/// full DHT citizen — inbound queries keep being answered, the routing
/// table and its bucket refresh keep running inside the bt DHT engine;
/// only *our* active crawl for download peers stops (the bt-side announce
/// registry entries lapse after their 30min purge window without a
/// re-issue, so the face winds down on its own cadence). Default off: a
/// behavior change, delivered opt-in per the card's freeze seam.
pub(crate) fn seed_passive_dht_suppressed(completed: bool, enabled: bool) -> bool {
    completed && enabled
}

/// Decay ladder rate shape (pure): `max(gear >> steps, FLOOR)` with a
/// defensive floor of 1 (a zero rate would permanently refuse dials).
/// steps=0 is the identity (the gear itself).
pub(crate) fn dial_decay_rate(gear: u32, steps: u32) -> u32 {
    if steps == 0 {
        return gear.max(1);
    }
    (gear >> steps.min(31)).max(DIAL_DECAY_FLOOR).max(1)
}

/// Decay ladder transition (pure, table-driven tests): one step down per
/// [`DIAL_OUTCOME_WINDOW`] while the window evidence is
/// "hostile-and-hopeless" (>85% failures, >= [`DIAL_FAILURE_MIN_ATTEMPTS`]
/// samples); an immediate full recovery on a good window (<=50% — the
/// hostile-gear band floor, so recovery and the gear shift agree); hold
/// in between (50-85% band) and on insufficient samples. `pinned`
/// (BH_CONNECT_SPEED override) and the master switch off both pin the
/// ladder at 0 (an explicitly pinned rate is not adapted; the same
/// discipline as the gear decision). The per-window step cadence is the
/// caller's `step_window_elapsed` anchor — the 250ms drain round reads
/// the same window many times, so without the anchor the ladder would
/// bottom out within a second of a bad reading; with it, worst-case
/// descent is 4 x 30s = 2min.
pub(crate) fn dial_decay_steps(
    backoff_on: bool,
    pinned: bool,
    attempts: u64,
    failures: u64,
    prev_steps: u32,
    step_window_elapsed: bool,
) -> u32 {
    if !backoff_on || pinned {
        return 0;
    }
    if attempts < DIAL_FAILURE_MIN_ATTEMPTS {
        return prev_steps;
    }
    let bad = failures.saturating_mul(100) > attempts.saturating_mul(DIAL_DECAY_PCT);
    if bad {
        if step_window_elapsed {
            prev_steps.saturating_add(1).min(DIAL_DECAY_MAX_STEPS)
        } else {
            prev_steps
        }
    } else if failures.saturating_mul(100) <= attempts.saturating_mul(DIAL_FAILURE_RATE_PCT) {
        0
    } else {
        prev_steps
    }
}

/// Effective decay steps (pure): the ladder state plus one extra step
/// while the known-address pool is large (>= [`DIAL_POOL_KNOWN_HIGH`]),
/// capped — the card's pool_known coupling; with the master switch off or
/// a pinned rate the whole face collapses to 0 steps.
pub(crate) fn effective_decay_steps(
    backoff_on: bool,
    pinned: bool,
    ladder_steps: u32,
    pool_known: usize,
) -> u32 {
    if !backoff_on || pinned {
        return 0;
    }
    ladder_steps
        .saturating_add(u32::from(pool_known >= DIAL_POOL_KNOWN_HIGH))
        .min(DIAL_DECAY_MAX_STEPS)
}

/// Dial-outcome observation window (main-loop single writer; time is
/// injected, a pure structure — written at the dial-outcome report arm,
/// read by the drain-round shift decision).
///
/// Denominator scope: receipts cover real outbound attempts only.
/// Endpoints turned away by IpGuard (the transit `peer_connect` entry)
/// or by identity rules after the handshake terminate without a receipt
/// and never enter the window — those are local policy rejections, not
/// network-hostility signals, so excluding them is deliberate. Punch /
/// Redial source receipts enter as usual (a single feed point, low
/// frequency; punch and redial failures are direct-dial hostility
/// evidence alike).
#[derive(Debug)]
pub(crate) struct DialOutcomeWindow {
    /// Window start.
    started: Instant,
    /// Dial outcomes in the window (receipt count).
    attempts: u64,
    /// Failed outcomes in the window (connected=false).
    failures: u64,
}

impl DialOutcomeWindow {
    /// Assemble at startup (the first window starts at assembly time).
    pub(crate) fn new(now: Instant) -> DialOutcomeWindow {
        DialOutcomeWindow {
            started: now,
            attempts: 0,
            failures: 0,
        }
    }

    /// Roll an expired window (advance the start, clear the counters;
    /// after expiry the reading is an empty window -> the
    /// insufficient-samples branch of [`connect_speed_for`] holds the
    /// current gear until the new window collects the minimum — the
    /// "falls back before it speeds up" one-way lag is carried by the
    /// sample guard).
    fn roll_if_expired(&mut self, now: Instant) {
        if now.duration_since(self.started) >= DIAL_OUTCOME_WINDOW {
            self.started = now;
            self.attempts = 0;
            self.failures = 0;
        }
    }

    /// Shift-point re-anchor (the gear-hold arm): only the window start
    /// moves forward, counters are kept — the evidence that triggered
    /// the shift stays visible inside the re-anchored window (the >=20
    /// guard still applies) and the rolling clear is deferred until a
    /// full window has passed after the re-anchor. Fallback
    /// (`BH_CONNECT_SPEED_HOLD=0`) never re-anchors.
    pub(crate) fn reanchor(&mut self, now: Instant) {
        self.started = now;
    }

    /// Feed point (one receipt per dial outcome).
    pub(crate) fn note(&mut self, connected: bool, now: Instant) {
        self.roll_if_expired(now);
        self.attempts = self.attempts.saturating_add(1);
        if !connected {
            self.failures = self.failures.saturating_add(1);
        }
    }

    /// Shift-decision reading (the current window's counters, after
    /// rolling).
    pub(crate) fn observation(&mut self, now: Instant) -> (u64, u64) {
        self.roll_if_expired(now);
        (self.attempts, self.failures)
    }
}

/// Drain-round budget reading cap (pure function, table-driven tests):
/// `min(available tokens, candidate backlog, [`DIAL_HALFOPEN_CAP`])`.
/// The backlog term = "no faster than candidates are supplied" (slow
/// down as the backlog shrinks; row sampling also bounds actual dials,
/// so this term converges the budget reading onto the real dial count);
/// the 512 term is the half-open concurrency guard.
pub(crate) fn drain_budget_cap(available: usize, backlog: usize) -> usize {
    available.min(backlog).min(DIAL_HALFOPEN_CAP)
}

/// Budget drain cadence (250ms): continuous accrual gives at most ~7-8
/// dials per tick at the 30/s base rate (<= 25 at the hostile 100/s);
/// connection-setup latency is bounded by the tick (the reference
/// `try_connect_more_peers` grants per tick — the same shape; 250ms
/// balances ramp-up latency against wake-up overhead). Skip behaviour:
/// a paused main loop does not re-issue missed budget (the debt
/// ticker's rule too).
pub(crate) const DRAIN_TICK: Duration = Duration::from_millis(250);

const MICRO: u64 = 1_000_000;

/// Session-wide dial token bucket (main-loop single writer; injected
/// time, pure arithmetic — the rate accrues continuously and the cap =
/// 1s of the current rate). u64 micro-token integer math (no floats).
/// The rate can shift at runtime (base 30 <-> hostile 100,
/// [`Self::set_rate`] driven by the drain round; a `BH_CONNECT_SPEED`
/// override pins the rate, no shifting).
#[derive(Debug)]
pub(crate) struct DialBudget {
    /// Accrued micro-tokens (1 token = [`MICRO`]).
    accrued_micro: u64,
    /// Last settlement instant.
    last: Instant,
    /// Current rate (token/s). The cap (burst) = 1s of quota, i.e. this
    /// value.
    rate: u32,
    /// `BH_CONNECT_SPEED` explicit override (Some = pinned; the shift
    /// decision passes straight through).
    override_speed: Option<u32>,
}

impl DialBudget {
    /// Start with a full bucket at the base rate (cold-start dials
    /// unrestricted — the reference grants the connection_speed quota
    /// from startup too). Production assembly goes through
    /// [`Self::from_env`]; this constructor is the deterministic test
    /// face (injected time).
    #[cfg(test)]
    pub(crate) fn new(now: Instant) -> DialBudget {
        DialBudget::with_speed(now, None)
    }

    /// Production assembly: read the `BH_CONNECT_SPEED` override once at
    /// assembly time (Some = pinned rate).
    pub(crate) fn from_env(now: Instant) -> DialBudget {
        DialBudget::with_speed(now, connect_speed_override())
    }

    fn with_speed(now: Instant, override_speed: Option<u32>) -> DialBudget {
        let rate = override_speed.unwrap_or(CONNECTION_SPEED).max(1);
        DialBudget {
            accrued_micro: u64::from(rate) * MICRO,
            last: now,
            rate,
            override_speed,
        }
    }

    /// Current-rate reading (the transition-comparison input of the
    /// shift decision).
    pub(crate) fn rate(&self) -> u32 {
        self.rate
    }

    /// Override reading (shift-decision input; None = adaptive).
    pub(crate) fn speed_override(&self) -> Option<u32> {
        self.override_speed
    }

    /// Shift gears (drain-round driven; defensive floor of 1). The burst
    /// cap follows the rate (1s of quota — the existing semantics,
    /// parameterized). A downshift clamps excess accrual immediately
    /// (a single point; readers/consumers unchanged); an upshift does
    /// not top up (accrual still settles on elapsed time only).
    pub(crate) fn set_rate(&mut self, rate: u32) {
        self.rate = rate.max(1);
        self.accrued_micro = self.accrued_micro.min(u64::from(self.rate) * MICRO);
    }

    /// Settle accrual (the rate = the current tier, continuous;
    /// saturating multiplication guards a long pause against overflow —
    /// the cap clamps immediately, semantics unchanged).
    fn refill(&mut self, now: Instant) {
        if now > self.last {
            let micros = now.duration_since(self.last).as_micros() as u64;
            self.accrued_micro = (u64::from(self.rate) * MICRO).min(
                self.accrued_micro
                    .saturating_add(micros.saturating_mul(u64::from(self.rate))),
            );
            self.last = now;
        }
    }

    /// Tokens currently available (settles without consuming — the
    /// drain round's count reading).
    pub(crate) fn available(&mut self, now: Instant) -> usize {
        self.refill(now);
        (self.accrued_micro / MICRO) as usize
    }

    /// Take 1 token at the dial spawn point; false when empty (the
    /// caller skips this dial).
    pub(crate) fn take1(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.accrued_micro >= MICRO {
            self.accrued_micro -= MICRO;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery-face candidate table (synthesized sort keys + O(300) sampled
// top-N)
// ---------------------------------------------------------------------------

/// Discovery-source rank plane (libtorrent `request_blocks.cpp`
/// `source_rank`: tracker=1<<5 > lsd=1<<4 > dht=1<<3 > pex=1<<2). The
/// value is the rank (higher wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialSourceRank {
    Tracker = 1 << 5,
    /// Plane completeness (the reference four-source table): the engine
    /// discovery face has no LSD source yet (bt::lsd is consumed only on
    /// the magnet path, `magnet.rs`); the plane value stays locked to
    /// request_blocks.cpp so an LSD source can slot in unchanged.
    /// (The expectation is cfg-gated: the candidate-table tests construct
    /// this rank, so the lint only fires in the non-test build.)
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "reserved rank: no LSD discovery source in the engine yet; tests use it"
        )
    )]
    Lsd = 1 << 4,
    Dht = 1 << 3,
    Pex = 1 << 2,
}

impl DialSourceRank {
    fn value(self) -> u8 {
        self as u8
    }
}

/// Candidate-table entry.
#[derive(Debug, Clone)]
pub(crate) struct DialCandidate {
    pub(crate) addr: SocketAddr,
    /// Owning face (still revalidated at dial time — faces can shrink
    /// at runtime; same rule as the redial scan).
    pub(crate) face: usize,
    pub(crate) source: DialSourceRank,
    /// Push time (TTL sweep key).
    pub(crate) pushed_at: Instant,
}

/// Discovery-face candidate table (main-loop exclusive; sits beside the
/// dedup window — discovery arms pass hygiene/dedup/admission gates
/// first, then the drain round dials by sort key). Bounded: capacity
/// [`Self::cap`], full -> reject new entries (queued diversity wins,
/// re-supply naturally refills); entries older than
/// [`DIAL_CANDIDATE_TTL`] are swept (aligned with the dedup window;
/// over-age candidates are rebuilt by announce/DHT re-supply).
#[derive(Debug)]
pub(crate) struct DialCandidates {
    entries: Vec<DialCandidate>,
    /// Round-robin sampling start (`peer_list.cpp` `m_round_robin`).
    cursor: usize,
    /// Full-reject counter (observability).
    rejected_full: u64,
    /// Capacity (bounded): fixed once at assembly ([`Self::from_env`] —
    /// the `BH_CONN_FILL_POOL` reading; test [`Self::default`] = the
    /// [`DIAL_CANDIDATE_CAP`] constant).
    cap: usize,
}

impl Default for DialCandidates {
    /// Test default = the aligned capacity ([`DIAL_CANDIDATE_CAP`]);
    /// production assembly goes through [`Self::from_env`].
    fn default() -> DialCandidates {
        DialCandidates::with_cap(DIAL_CANDIDATE_CAP)
    }
}

impl DialCandidates {
    /// Explicit capacity (bounded, floor 1; shared by tests and
    /// [`Self::from_env`]).
    pub(crate) fn with_cap(cap: usize) -> DialCandidates {
        DialCandidates {
            entries: Vec::new(),
            cursor: 0,
            rejected_full: 0,
            cap: cap.max(1),
        }
    }

    /// Production assembly: `BH_CONN_FILL_POOL=0` -> the legacy capacity
    /// [`DIAL_CANDIDATE_CAP_LEGACY`]; otherwise the aligned capacity
    /// [`DIAL_CANDIDATE_CAP`] (see [`conn_fill_pool_enabled`]).
    pub(crate) fn from_env() -> DialCandidates {
        DialCandidates::with_cap(if conn_fill_pool_enabled() {
            DIAL_CANDIDATE_CAP
        } else {
            DIAL_CANDIDATE_CAP_LEGACY
        })
    }
}

/// Candidate-table capacity (bounded): aligned with the libtorrent
/// `max_peerlist_size` default of 3000 (`src/settings_pack.cpp`
/// `SET(max_peerlist_size, 3000, nullptr)`) — under hostile dialing a
/// large table is the base on which failures sink and fresh candidates
/// keep entering. Previously 1024 (a quarter of the DhtDialDedup cap
/// 4096; the table only holds addresses that passed
/// hygiene/dedup/admission). Fallback: `BH_CONN_FILL_POOL=0` ->
/// [`DIAL_CANDIDATE_CAP_LEGACY`].
pub(crate) const DIAL_CANDIDATE_CAP: usize = 3000;

/// Legacy candidate-table capacity (`BH_CONN_FILL_POOL=0`; provenance
/// in the [`DIAL_CANDIDATE_CAP`] docs).
pub(crate) const DIAL_CANDIDATE_CAP_LEGACY: usize = 1024;

/// Candidate-pool expansion switch: `BH_CONN_FILL_POOL=0` -> the table
/// capacity reverts to the legacy 1024; any other value (incl. unset)
/// -> 3000. Read once at assembly ([`DialCandidates::from_env`];
/// process-level knob, not hot-reloaded; the `BH_FAST_RECONNECT`
/// construction-time read follows the same discipline). Parse registry:
/// `taiji_io::knobs` (construction-time read, no caching layer).
pub(crate) fn conn_fill_pool_enabled() -> bool {
    taiji_io::knobs::conn_fill_pool_enabled()
}

/// Failed-candidate re-push switch: `BH_CONN_FILL_RETRY=0` -> failed
/// endpoints do not return to the candidate table (legacy: only
/// discovery re-supply re-admits); any other value (incl. unset) ->
/// silent failures re-push and retry on the silent backoff window. Read
/// at the dial-outcome report arm (main loop,
/// `run::holepunch::handle_hp_dial_report`). Parse registry:
/// `taiji_io::knobs` (read per event, no caching layer).
pub(crate) fn conn_fill_retry_enabled() -> bool {
    taiji_io::knobs::conn_fill_retry_enabled()
}

/// DHT low-peer fast-tier switch: `BH_CONN_FILL_DHT=0` -> the DHT
/// announce re-send cadence reverts to legacy (only the
/// all-faces-zero-connections shape enters the 1/3 fast tier); any
/// other value (incl. unset) -> connections below
/// [`dht_ramp_min_peers`] also enter the fast tier. Read at the 2s slow
/// tick (tick.rs; same discipline as `BH_LEAN_TELEMETRY` — tick-level
/// env reads every 2s, not hot path). Parse registry: `taiji_io::knobs`
/// (read each round).
pub(crate) fn conn_fill_dht_enabled() -> bool {
    taiji_io::knobs::conn_fill_dht_enabled()
}

/// DHT announce supply gate (registered connections, all faces summed;
/// semantics = "ramp while below the outbound target"): default reads
/// [`super::state::peer_connections_target`] (100; fed by the same
/// source as the `BH_PEER_MAX` override seam); numeric override seam
/// `BH_DHT_RAMP_MIN_PEERS` (trim+usize parse, failure/0 falls back to
/// the default — the `BH_PEER_MAX` pattern).
///
/// # Why the gate is the target, not 50 (divergence note)
///
/// libtorrent pulls DHT announce forward for a downloading torrent
/// while `num_peers() < 50` (`src/torrent.cpp` `start_announcing` ->
/// `prioritize_dht`; session_impl.cpp re-arms the announce timer
/// immediately). 50 is the reference's "connections are sparse"
/// heuristic, not a supply criterion; a supply gate should read "below
/// the outbound target" (the same-source reading). With the verbatim 50
/// the gate converges mid-band and the ramp tier judges itself out
/// exactly when supply is scarcest. Fallback:
/// `BH_DHT_RAMP_MIN_PEERS=50` restores the libtorrent-verbatim
/// threshold.
///
/// Read at the 2s slow tick (tier decision [`dht_announce_cadence`]).
/// Parse registry: `taiji_io::knobs` (read each round).
pub(crate) fn dht_ramp_min_peers() -> usize {
    taiji_io::knobs::dht_ramp_min_peers(super::state::peer_connections_target())
}

/// DHT announce tier decision (pure core, extracted as an explicit
/// parameter face for table-driven tests; consumed by the tick.rs 2s
/// slow tick, same style as `admission_verdict` /
/// `admission_verdict_limits` in state.rs). Tiers (first match wins):
/// - ramp tier: `!completed && conn_thin` (conn_thin = fast-tier switch
///   on && registered < ramp_min) -> `ramp_interval` (`None` = env
///   value 0 fallback -> the 1/3 tier);
/// - 1/3 fast tier: peer vacuum (peers_idle, all faces zero
///   connections) or conn_thin -> `announce_interval / 3`;
/// - regular tier: `announce_interval` (default 15min).
pub(crate) fn dht_announce_cadence(
    registered: usize,
    completed: bool,
    peers_idle: bool,
    fast_enabled: bool,
    ramp_min: usize,
    ramp_interval: Option<Duration>,
    announce_interval: Duration,
) -> Duration {
    let conn_thin = fast_enabled && registered < ramp_min;
    if !completed && conn_thin {
        ramp_interval.unwrap_or(announce_interval / 3)
    } else if peers_idle || conn_thin {
        announce_interval / 3
    } else {
        announce_interval
    }
}

/// DHT lookup cadence during ramp-up: while the download is incomplete
/// and connections < [`dht_ramp_min_peers`], announce/get_peers
/// re-queries tighten to this value (default 30s, tightened from 60 —
/// composed with the widened candidate frontier (taiji-bt dht/task.rs
/// `BH_DHT_FRONTIER_K`, width x2) into roughly a 4x discovery-face
/// expansion per minute; `BH_DHT_RAMP_INTERVAL_SECS=0` restores the
/// legacy 1/3 tier).
///
/// Anchor: the libtorrent prioritize_dht immediate tier (torrent.cpp ->
/// session_impl.cpp — the announce timer re-arms at 0s and drains the
/// priority queue). The 2s-tick shape has no priority-queue semantics
/// (a divergence), hence a fixed ramp cadence as the compromise: one
/// idempotent registration per tier (entry overwrite + immediate
/// get_peers); 30s = ~20 re-supplies within a typical lookup TTL,
/// bounded by the independent per-source query limiter (taiji-bt
/// dht/engine/query_limit.rs token buckets).
pub(crate) fn dht_ramp_interval() -> Option<Duration> {
    // Parse registry: `taiji_io::knobs` (read each round).
    let secs = taiji_io::knobs::dht_ramp_interval_secs();
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Candidate TTL: aligned with the dedup window (10min) — over-age
/// candidates are dropped and addresses are rebuilt naturally by
/// announce/DHT/PEX re-supply (window expiry re-admits).
pub(crate) const DIAL_CANDIDATE_TTL: Duration = Duration::from_secs(10 * 60);

/// Per-round sampling cap (`peer_list.cpp`
/// `std::min(int(m_peers.size()), 300)`): at most 300 rows evaluated
/// per drain round, constant overhead.
pub(crate) const DIAL_SAMPLE_MAX: usize = 300;

impl DialCandidates {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Push (the address has already been consumed by the dedup table;
    /// duplicate pushes of the same address are ignored — the first
    /// entry wins; table lifetime is far shorter than the dedup window,
    /// so duplicates only appear in long-stall shapes). Full -> reject
    /// (capacity [`Self::cap`]; the failed-candidate re-push and
    /// discovery re-supply share this gate — when full, re-pushed
    /// entries are rejected too; fresh candidates first = "rotate new
    /// candidates while the pool is rich").
    pub(crate) fn push(
        &mut self,
        addr: SocketAddr,
        face: usize,
        source: DialSourceRank,
        now: Instant,
    ) {
        if self.entries.iter().any(|c| c.addr == addr) {
            return;
        }
        if self.entries.len() >= self.cap {
            self.rejected_full = self.rejected_full.wrapping_add(1);
            return;
        }
        self.entries.push(DialCandidate {
            addr,
            face,
            source,
            pushed_at: now,
        });
    }

    /// Remove by address (the drain round pops on selection; idempotent).
    pub(crate) fn remove(&mut self, addr: &SocketAddr) {
        self.entries.retain(|c| c.addr != *addr);
    }
}

/// Round-robin sampling order (`peer_list.cpp` round_robin): take
/// `min(len, 300)` indices starting at `cursor`; returns (index order,
/// new cursor). len=0 -> an empty round.
pub(crate) fn sample_order(len: usize, cursor: usize, max: usize) -> (Vec<usize>, usize) {
    if len == 0 {
        return (Vec::new(), 0);
    }
    let start = if cursor >= len { 0 } else { cursor };
    let n = len.min(max);
    let idx = (0..n).map(|i| (start + i) % len).collect::<Vec<_>>();
    (idx, (start + n) % len)
}

/// Candidate sort-key row (the input projection of
/// [`compare_candidate`]; table-driven tests, not through EngineLoop —
/// the `PeerStallRow` style of stall.rs).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CandidateRow {
    /// Consecutive silent failures (silent-ledger reading; the
    /// libtorrent failcount analogy, `peer_list.cpp` — lower wins).
    pub(crate) fails: u32,
    /// Local (LAN) address (the libtorrent `is_local` analogy =
    /// `dht::is_exempt_ip` — the RFC1918/loopback/link-local/CGNAT
    /// exempt set; security.rs documents alignment with
    /// ip_helpers.cpp).
    pub(crate) local: bool,
    /// v6 preference key: global v6 available locally (assembly-time
    /// `probe_source_ip(true)`, BEP7 `ipv6=` reuse) && the `BH_V6_PREF`
    /// switch on && the candidate address is IPv6. v6 peers often
    /// bypass NAT (BiglyBT's "prefer what connects" advice) — an
    /// intentional divergence: reference `compare_peer` in
    /// peer_list.cpp has no such key. Key position: after is_local
    /// (directly reachable local candidates stay first), before
    /// last_connected. Constantly false when v6 is unavailable or the
    /// switch is off = a neutral key.
    pub(crate) v6_preferred: bool,
    /// Last connection attempt (carried by the dedup table's admit
    /// time; None = never — `peer_list.cpp` earlier last_connected
    /// wins, never-tried first).
    pub(crate) last_connected: Option<Instant>,
    /// Discovery-source rank (higher wins, `peer_list.cpp`).
    pub(crate) source: DialSourceRank,
    /// BEP-40 symmetric rank (higher wins, `peer_list.cpp`).
    ///
    /// Omitted-key note (the `finished && maybe_upload_only` demotion
    /// key of the reference `compare_peer`, between last_connected and
    /// source_rank): discovery candidates are un-handshaken addresses —
    /// upload-only/maybe_upload_only is decidable only for connected
    /// peers (after the BEP21/ext handshake, maintained by the
    /// connection face). Connected-peer records exist
    /// (`PeerMeta::upload_only`), but the candidate key needs a
    /// cross-connection address-level projection (demote again when the
    /// peer disconnects and the candidate returns to the table); no
    /// such bookkeeping yet, so the key is omitted (slot documented in
    /// engine.md).
    pub(crate) rank: u32,
}

/// Candidate sort synthesis (the `compare_peer` key chain + the v6 key,
/// with the omission noted — the per-key correspondence with reference
/// `peer_list.cpp` is documented on the [`CandidateRow`] fields).
pub(crate) fn compare_candidate(l: &CandidateRow, r: &CandidateRow) -> Ordering {
    l.fails
        .cmp(&r.fails)
        .then_with(|| l.local.cmp(&r.local).reverse())
        // v6 preference key (intentional divergence, see
        // CandidateRow::v6_preferred — absent upstream; constantly
        // equal and neutral when v6 is unavailable).
        .then_with(|| l.v6_preferred.cmp(&r.v6_preferred).reverse())
        .then_with(|| l.last_connected.cmp(&r.last_connected))
        .then_with(|| l.source.value().cmp(&r.source.value()).reverse())
        .then_with(|| l.rank.cmp(&r.rank).reverse())
}

/// Discovery-candidate drain (250ms cadence arm; main-loop single
/// writer): TTL sweep -> O(300) sample -> synthesized-sort top-N
/// (N = budget headroom) -> dial row by row. With the admission gate
/// closed the whole round is skipped (candidates stay queued; the
/// reference `try_connect_more_peers` limit early-return analogy).
pub(super) fn drain_dial_candidates(
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
    actual_port: u16,
) {
    let now = Instant::now();
    // (0) Admission gate (the leecher target shape — the discovery
    // arms' per-batch gate is the same form, run::dial docs): closed =
    // skip the whole round, candidates wait in the table.
    if !state.admission_open(false, now) {
        return;
    }
    // (1) TTL sweep of over-age entries.
    state
        .dial_candidates
        .entries
        .retain(|c| now.duration_since(c.pushed_at) < DIAL_CANDIDATE_TTL);
    // (0') Rate-shift decision (gear hold): settle the dial-outcome
    // window -> override-first / hostile-tier check -> shift
    // (transitions log at info). A 250ms cadence read, not hot path.
    // Predicate and constants: [`connect_speed_for`]; window scope:
    // [`DialOutcomeWindow`]. 4th arg: hold mode passes the current
    // **gear** (insufficient samples = no evidence, no shift); fallback
    // mode (`BH_CONNECT_SPEED_HOLD=0`) passes the base rate = "zero
    // samples = base rate" bit-for-bit. The gear is tracked separately
    // from the bucket's applied rate because (0'') may apply decay on
    // top — comparing the gear against the applied rate would flap the
    // transition (and its log) on every 250ms round while decay is
    // active (observed 160+ INFO lines/round on the bench before the
    // split).
    let hold = connect_speed_hold_enabled();
    let (attempts, failures) = state.dial_outcomes.observation(now);
    let hold_current = if hold {
        state.dial_gear
    } else {
        CONNECTION_SPEED
    };
    let gear = connect_speed_for(
        state.dial_budget.speed_override(),
        attempts,
        failures,
        hold_current,
    );
    if gear != state.dial_gear {
        info!(target: "taiji::core::engine", from = state.dial_gear, to = gear,
            attempts, failures,
            "connect_speed adapted (dial failure rate)");
        state.dial_gear = gear;
        // A shift does not clear samples: re-anchor the window at the
        // shift point so the shift evidence stays visible inside the
        // re-anchored window; the fallback keeps the prior phase (no
        // re-anchor).
        if hold {
            state.dial_outcomes.reanchor(now);
        }
    }
    // (0'') Dial decay ladder: sustained >85% failure steps
    // the effective rate down (halving per step window, floor
    // [`DIAL_DECAY_FLOOR`]); a good window recovers fully; the
    // pool_known coupling adds one step while the known pool is large.
    // Composed **after** the gear decision so the two faces stay
    // independent: the gear answers "speed up for recovery?" (>50%),
    // the ladder answers "is even that wasted?" (>85% + large burned
    // pool). `BH_DIAL_BACKOFF=0` collapses the whole face to 0 steps.
    // The bucket's applied rate is `dial_decay_rate(gear, eff_steps)`
    // — a single set_rate per actual transition (no flapping), and the
    // hold input above is the undecayed gear, so an empty window holds
    // the ladder arithmetic exactly rather than compounding it.
    let backoff = dial_backoff_enabled();
    let pinned = state.dial_budget.speed_override().is_some();
    let next_steps = dial_decay_steps(
        backoff,
        pinned,
        attempts,
        failures,
        state.dial_decay_steps,
        now.duration_since(state.dial_decay_anchor) >= DIAL_OUTCOME_WINDOW,
    );
    if next_steps != state.dial_decay_steps {
        info!(target: "taiji::core::engine", from = state.dial_decay_steps,
            to = next_steps, attempts, failures,
            "dial decay ladder stepped (sustained dial failure)");
        state.dial_decay_steps = next_steps;
        state.dial_decay_anchor = now;
    }
    let eff_steps = effective_decay_steps(
        backoff,
        pinned,
        state.dial_decay_steps,
        state.dht_dial_dedup.len(),
    );
    let target_rate = dial_decay_rate(gear, eff_steps);
    if target_rate != state.dial_budget.rate() {
        state.dial_budget.set_rate(target_rate);
    }
    let budget = drain_budget_cap(
        state.dial_budget.available(now),
        state.dial_candidates.len(),
    );
    if budget == 0 || state.dial_candidates.is_empty() {
        return;
    }
    // (2) O(300) round-robin sampling.
    let len = state.dial_candidates.len();
    let (sampled, next_cursor) = sample_order(len, state.dial_candidates.cursor, DIAL_SAMPLE_MAX);
    state.dial_candidates.cursor = next_cursor;
    // (3) Per-row eligibility: cooldown endpoints are removed (failcount
    // >= max_failcount loses candidate standing, the `peer_list.cpp`
    // analogy — the silent cooldown face); backoff endpoints stay in
    // the table unpicked (waiting-room semantics: rechecked when the
    // defer expires); allowed endpoints build rows.
    let self_v4 = state.self_v4.map(|ip| SocketAddr::new(ip, actual_port));
    // v6 preference face: the assembly-time global probe (BEP7 `ipv6=`
    // reuse, zero new probes) && the `BH_V6_PREF` switch. false = a
    // neutral key (zero decision change).
    let v6_available = state.self_v6_global && v6_pref_enabled();
    let mut rows: Vec<(CandidateRow, SocketAddr, usize)> = Vec::with_capacity(sampled.len());
    let mut cooldown_dropped = 0usize;
    for i in sampled {
        // Copy the field values out first (Copy) — borrows do not
        // overlap the ledger read-modify.
        let Some((addr, face, source)) = state
            .dial_candidates
            .entries
            .get(i)
            .map(|c| (c.addr, c.face, c.source))
        else {
            continue;
        };
        match state.silent_book.admit(&addr, now) {
            SilentVerdict::Cooldown => {
                state.dial_candidates.remove(&addr);
                cooldown_dropped += 1;
                continue;
            }
            SilentVerdict::Backoff => continue,
            SilentVerdict::Allowed => {}
        }
        let fails = state.silent_book.fails(&addr);
        let local = is_exempt_ip(addr.ip());
        let v6_preferred = v6_available && addr.is_ipv6();
        let last_connected = state.dht_dial_dedup.last_admitted(&addr);
        let rank = self_v4.map_or(0, |s| bep40_rank(s, addr));
        rows.push((
            CandidateRow {
                fails,
                local,
                v6_preferred,
                last_connected,
                source,
                rank,
            },
            addr,
            face,
        ));
    }
    if cooldown_dropped > 0 {
        debug!(target: "taiji::core::engine", dropped = cooldown_dropped,
            "dial candidates: cooldown endpoints evicted from candidate table");
    }
    // (4) Sort and take top-N (N = budget headroom; the reference
    // candidate_count truncation analogy). Rows <= 300 so the full
    // sort is negligible; the reference itself inserts into an ordered
    // small heap (peer_list.cpp).
    rows.sort_by(|l, r| compare_candidate(&l.0, &r.0));
    let mut dialed = 0usize;
    for (_, addr, face) in rows {
        if dialed >= budget {
            break;
        }
        // Face still present (faces can shrink at runtime; redial scan
        // same rule).
        let Some(f) = state.faces.get(face) else {
            state.dial_candidates.remove(&addr);
            continue;
        };
        // Same IP already connected (a post-push window gap — rechecked
        // fresh at dial time).
        if f.peer_state.values().any(|ps| ps.ip == Some(addr.ip())) {
            state.dial_candidates.remove(&addr);
            continue;
        }
        // Pop + dial (the spawn re-checks the silent ledger and takes 1
        // token — Allowed here by construction; the gate is a redundant
        // defense line).
        state.dial_candidates.remove(&addr);
        spawn_peer_dial(
            state,
            dial,
            token,
            face,
            addr,
            DialSource::Discovery,
            state.seeding_sources[face].clone(),
            state.seeding_hash_sources[face].clone(),
        );
        dialed += 1;
    }
    if dialed > 0 {
        debug!(target: "taiji::core::engine", dialed, budget,
            table = state.dial_candidates.len(),
            "dial candidates drained by synthesized priority");
    }
}

// ---------------------------------------------------------------------------
// peer turnover
// ---------------------------------------------------------------------------

/// Turnover trigger threshold = hard cap x cutoff (90%), integer
/// division (the reference `num_connections() >= limit * cutoff / 100`
/// form; 120 x 90/100 = 108 at the 120 hard cap, 57 at the 64 cap —
/// consumers read the runtime-effective value).
pub(crate) const PEER_TURNOVER_CUTOFF_PCT: u64 = 90;

/// Per-round disconnect fraction = `peer_turnover` 4%
/// (`settings_pack.cpp`).
pub(crate) const PEER_TURNOVER_PCT: u64 = 4;

/// Turnover period 90s: the reference source comment pins "every 90
/// seconds" (session_impl.cpp) while the setting default is
/// `peer_turnover_interval = 300s` (settings_pack.cpp); this codebase
/// takes 90s (divergence noted in engine.md).
pub(crate) const PEER_TURNOVER_INTERVAL: Duration = Duration::from_secs(90);

/// Turnover disconnect row (the input projection of
/// [`compare_disconnect`]; table-driven tests).
#[derive(Debug, Clone, Copy)]
pub(crate) struct TurnoverRow {
    pub(crate) cuid: u64,
    /// We want supply from this peer (it holds pieces we lack; the
    /// libtorrent `is_interesting` analogy. Constantly false when
    /// seeding — all pieces held, nothing wanted).
    pub(crate) interesting: bool,
    /// The peer is a seed (seeds are the scarce side to keep; non-seeds
    /// disconnect first).
    pub(crate) seed: bool,
    /// 30s download-window rate (down_windows; this codebase's carrier
    /// for the libtorrent transfer key).
    pub(crate) down_rate: f64,
    /// The peer chokes us (the `PeerTaskHandle::is_choking_us` mirror,
    /// BEP3-frame driven; the libtorrent is_choked key analogy — a peer
    /// choking us sends no bytes, disconnect it first).
    pub(crate) choking_us: bool,
}

/// Disconnect priority (the `compare_disconnect_peer` key chain;
/// reference snapshot `src/torrent.cpp`, per-key status):
/// 1. `is_disconnecting` — omitted: a disconnect here is an immediate
///    shutdown, no "disconnecting" state projection (the key would be
///    constantly equal, no discrimination);
/// 2. `is_interesting` — kept ([`TurnoverRow::interesting`]);
/// 3. `is_seed` — kept ([`TurnoverRow::seed`]);
/// 4. `on_parole` — omitted: no corresponding face (smart_ban absent);
/// 5. transfer — carried: `total_payload_download / time_connected` is
///    carried by the 30s download-window rate (the same wire-received
///    bytes numerator; the observation window normalizes time);
/// 6. `is_choked` ("prefer to disconnect peers that chokes us") — kept
///    ([`TurnoverRow::choking_us`], data face =
///    `PeerTaskHandle::is_choking_us`);
/// 7. `last_received` — omitted: no per-peer last-activity timestamp
///    projection (`PeerMeta::down` is a cumulative counter, the
///    `PeerRate::last_*` fields are sampling baselines). The key is the
///    chain-tail tiebreak: with the first six keys equal the reference
///    disconnects the peer silent longest; here the stable order
///    converges (the deterministic equivalent).
pub(crate) fn compare_disconnect(l: &TurnoverRow, r: &TurnoverRow) -> Ordering {
    if l.interesting != r.interesting {
        // interesting = true is kept -> it sorts greater (later).
        return if l.interesting {
            Ordering::Greater
        } else {
            Ordering::Less
        };
    }
    if l.seed != r.seed {
        return if l.seed {
            Ordering::Greater
        } else {
            Ordering::Less
        };
    }
    l.down_rate
        .partial_cmp(&r.down_rate)
        .unwrap_or(Ordering::Equal)
        // Key 6: peers choking us disconnect first.
        .then_with(|| {
            if l.choking_us != r.choking_us {
                // choking_us = true (the peer chokes us) sorts first
                // (disconnected earlier).
                if l.choking_us {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            } else {
                Ordering::Equal
            }
        })
    // Key 7 last_received omitted — see the function docs
    // (stable-order convergence).
}

/// Turnover selection (the `disconnect_peers` shape: partially select
/// the `count` worst — the `torrent.cpp` partial_sort_copy analogy;
/// count <= connected rows, select_nth + a stabilized prefix, a
/// deterministic decision order). Returns the picked cuids in
/// worst-first order.
pub(crate) fn turnover_pick(rows: &mut [TurnoverRow], count: usize) -> Vec<u64> {
    let n = count.min(rows.len());
    if n == 0 {
        return Vec::new();
    }
    if n < rows.len() {
        rows.select_nth_unstable_by(n - 1, compare_disconnect);
    }
    let head = &mut rows[..n];
    head.sort_by(compare_disconnect);
    head.iter().map(|r| r.cuid).collect()
}

/// Turnover cadence (1s seed tick feed point): past 90% of the hard
/// cap, disconnect the worst max(n x 4%, 1) every 90s. Disconnect =
/// graceful shutdown (the stall.rs rotation shape) — outbound
/// connections naturally enter the redial pool on the leave arm (60s
/// base linear reconnect), inbound peers reconnect on their own
/// cadence. Division of labour with the stall valve: engine.md.
///
/// Disconnect-count divergence: the reference disconnects
/// `min(max(n x 4%, 1), num_connect_candidates())` (session_impl.cpp —
/// a conservative cap disconnecting less when candidates are few); here
/// `max(n x 4%, 1)` has no such cap — the session face has no
/// num_connect_candidates reading (no per-torrent candidate
/// bookkeeping) and 4% is itself a small rotation step; divergence
/// recorded, behaviour not added. The slow-churn predicate below adopts
/// the candidate cap.
pub(super) fn turnover_tick(state: &mut EngineLoop, now: Instant) {
    if let Some(t) = state.last_turnover
        && now.duration_since(t) < PEER_TURNOVER_INTERVAL
    {
        return;
    }
    let total = state.registered_peers();
    let threshold = (peer_connections_max() as u64 * PEER_TURNOVER_CUTOFF_PCT / 100) as usize;
    if total < threshold {
        return;
    }
    // (0) Collect rows across all faces (faces are the v1/v2 views of a
    // single torrent; under session-level cap semantics rows are
    // collected across faces — the reference picks the largest torrent
    // via max_element(num_peers); here all faces share one source, so
    // there is no largest-torrent selection). Webseed pseudo-peers are
    // exempt (CDNs are infinitely patient and slowness is transient —
    // Range fetches queue behind the concurrency gate;
    // `EngineLoop::is_webseed`).
    let mut rows: Vec<TurnoverRow> = Vec::with_capacity(total);
    for face in &state.faces {
        for (i, cuid) in face.peer_cuids.iter().copied().enumerate() {
            if state.is_webseed(cuid) {
                continue;
            }
            let avail = face.peer_avail.get(&cuid);
            let seed = avail.is_some_and(|bits| bits.is_full());
            let interesting = !face.completed
                && avail.is_some_and(|bits| {
                    bits.iter_ones()
                        .any(|g| !face.progress.piece_done_global(g as u64))
                });
            let down_rate = face
                .peer_state
                .get(&cuid)
                .and_then(|ps| ps.down_window.as_ref())
                .map(|w| w.rate())
                .unwrap_or(0.0);
            // Key 6 data face: the peer-choking-us mirror
            // (PeerTaskHandle, BEP3-frame driven). i aligns with peers
            // (kept in sync by the register/leave arms).
            let choking_us = face.peers.get(i).is_some_and(|p| p.is_choking_us());
            rows.push(TurnoverRow {
                cuid,
                interesting,
                seed,
                down_rate,
                choking_us,
            });
        }
    }
    let count = (total as u64 * PEER_TURNOVER_PCT / 100).max(1) as usize;
    let picked = turnover_pick(&mut rows, count);
    state.last_turnover = Some(now);
    let mut rotated = 0usize;
    for cuid in picked {
        // cuids are globally unique -> locate across faces (lookup and
        // disconnect in the same instant — the leave arm is the single
        // downstream consumer, no race).
        for (fi, face) in state.faces.iter_mut().enumerate() {
            if let Some(pos) = face.peer_cuids.iter().position(|c| *c == cuid) {
                debug!(target: "taiji::core::engine", face = fi, cuid,
                    "peer turnover: optimistic disconnect (redial will re-connect)");
                face.peers[pos].shutdown();
                rotated += 1;
                break;
            }
        }
    }
    if rotated > 0 {
        info!(target: "taiji::core::engine",
            rotated, total, threshold, count,
            "peer turnover: worst connections rotated (libtorrent optimistic_disconnect)");
    }
}

// ---------------------------------------------------------------------------
// µTP zero-throughput connection governance
// ---------------------------------------------------------------------------

/// µTP zero-throughput disconnect window = 120s: one full rollover of
/// the BEP29 base_delay two-minute sliding window (the
/// `taiji-io::utp::ledbat` module docs, "the last two minutes") — in a
/// zero-throughput state the base bucket rolling over is LEDBAT's only
/// self-recovery path, so still zero output past the window means no
/// recovery. No reference disconnect face corresponds (intentional
/// divergence, engine.md); the same order of magnitude as the 90s
/// turnover period ([`PEER_TURNOVER_INTERVAL`]).
pub(crate) const UTP_MUTE_AFTER: Duration = Duration::from_secs(120);

/// Fallback switch (read once per tick; the `conn_fill_dht_enabled`
/// shape): `BH_UTP_MUTE=0` disables governance (zero-throughput µTP
/// connections are no longer disconnected = prior behaviour
/// bit-for-bit), default on. Parse registry: `taiji_io::knobs` (read
/// each round, no caching layer).
pub(crate) fn utp_mute_enabled() -> bool {
    taiji_io::knobs::utp_mute_enabled()
}

/// Per-connection governance decision (pure function, table-driven).
/// Inputs: transport kind, 30s download-window rate, 10s upload
/// sliding-window rate, any existing zero-throughput record, current
/// time. Output: `(new record, disconnect)`.
///
/// - **Transport gate**: `Transport::Tcp` is always `(None, false)` —
///   TCP zero throughput is governed by turnover (cap approach) and the
///   stall valve (session stall); this face never touches TCP;
/// - **Output exemption**: any direction producing (>0 B/s) clears the
///   record and does not disconnect — upload output is a reciprocity
///   contribution (the tit-for-tat supply side), exempt symmetrically
///   with download;
/// - **Observe -> disconnect**: the first observation records (no
///   disconnect); it stays observing while under [`UTP_MUTE_AFTER`];
///   still zero in both directions past the window -> disconnect and
///   clear the record (the connection leave arm reclaims the remaining
///   bookkeeping).
pub(crate) fn utp_mute_step(
    transport: Transport,
    down_rate: f64,
    up_rate: f64,
    since: Option<Instant>,
    now: Instant,
) -> (Option<Instant>, bool) {
    if transport != Transport::Utp {
        return (None, false);
    }
    if down_rate > 0.0 || up_rate > 0.0 {
        return (None, false);
    }
    match since {
        None => (Some(now), false),
        Some(t) => {
            if now.duration_since(t) >= UTP_MUTE_AFTER {
                (None, true)
            } else {
                (Some(t), false)
            }
        }
    }
}

/// µTP zero-throughput governance cadence (1s seed tick feed point,
/// after turnover): switch off = zero scanning, zero bookkeeping (prior
/// behaviour); on = per-face [`utp_mute_face`] decisions, landing as a
/// graceful shutdown (the turnover shape — the leave arm is the single
/// downstream consumer; outbound connections naturally enter the redial
/// pool, whose `(f+1) x 60s` linear gradient carries the retry
/// throttling).
///
/// Livelock note: a µTP-only endpoint that is disconnected dials back
/// via the redial pool over µTP and, still zero-throughput, re-enters
/// the window — the linear redial gradient + the 120s window drive its
/// slot occupancy toward zero; the candidate-table sort key (the
/// discovery face) always prefers fresh TCP-reachable candidates.
pub(super) fn utp_mute_tick(state: &mut EngineLoop, now: Instant) {
    if !utp_mute_enabled() {
        return;
    }
    let mut muted = 0usize;
    for (fi, face) in state.faces.iter_mut().enumerate() {
        for (pos, cuid) in utp_mute_face(face, now) {
            debug!(target: "taiji::core::engine", face = fi, cuid,
                after_secs = UTP_MUTE_AFTER.as_secs(),
                "utp mute: zero-throughput µTP connection disconnected \
                 (prefer_tcp behaviour target; slot freed for TCP candidates)");
            face.peers[pos].shutdown();
            muted += 1;
        }
    }
    if muted > 0 {
        info!(target: "taiji::core::engine", muted,
            "utp mute: zero-throughput µTP connections rotated");
    }
}

/// Per-face governance scan (bookkeeping + decision; `pub(crate)` =
/// the engine::tests direct-drive assembly face, the dispatch.rs
/// style). Returns disconnect decisions `(peer position, cuid)` (the
/// caller executes them — shutdown removes the entries on the next
/// leave arm; this function does not touch the peers vector). Table
/// upkeep: output exemption clears / first observation records /
/// disconnect clears (the leave arm withdraws entries for departed
/// cuids in step).
pub(crate) fn utp_mute_face(face: &mut FaceState, now: Instant) -> Vec<(usize, u64)> {
    let mut fire = Vec::new();
    let cuids: Vec<u64> = face.peer_cuids.to_vec();
    for cuid in cuids {
        // meta / download window / upload sampling read together (one
        // row fetch).
        let Some(ps) = face.peer_state.get_mut(&cuid) else {
            continue;
        };
        let Some(meta) = ps.meta.as_ref() else {
            continue;
        };
        let transport = meta.transport;
        let down_rate = ps.down_window.as_ref().map(|w| w.rate()).unwrap_or(0.0);
        let up_rate = ps.rates.as_mut().map(|r| r.up.calculate(now)).unwrap_or(0) as f64;
        let since = ps.utp_mute_since;
        let (next, disconnect) = utp_mute_step(transport, down_rate, up_rate, since, now);
        let ps = face.peer_state_row(cuid);
        match next {
            Some(t) => {
                ps.utp_mute_since = Some(t);
            }
            None => {
                ps.utp_mute_since = None;
            }
        }
        if disconnect && let Some(pos) = face.peer_cuids.iter().position(|c| *c == cuid) {
            fire.push((pos, cuid));
        }
    }
    fire
}

// ---------------------------------------------------------------------------
// Slow-peer eviction
// ---------------------------------------------------------------------------

/// Slow-peer eviction cadence 30s: the same window period as the 30s
/// download rate window (down_windows, [`crate::upload::RateWindow`])
/// — one pass per window, the rate-distribution reading refreshes with
/// each roll; separate from the 90s turnover rhythm
/// ([`PEER_TURNOVER_INTERVAL`]).
pub(crate) const SLOW_CHURN_INTERVAL: Duration = Duration::from_secs(30);

/// Pool-floor gate: swarms with < 8 connected peers are left alone —
/// in small pools the median is noisy (one peer's rate swing flips the
/// eviction line) and a disconnect is a large fraction of the pool.
pub(crate) const SLOW_CHURN_MIN_POOL: usize = 8;

/// Eviction-mark consumption window 300s: the TTL of the mark consumed
/// by the leave arm's redial admission — past the window the mark
/// expires (the peer may have improved or changed networks) and redial
/// returns to the regular 5s fast path. Prevents inbound-peer mark
/// buildup: the insert point retain-clears expired entries.
pub(crate) const SLOW_CHURN_MARK_TTL: Duration = Duration::from_secs(300);

/// Fallback switch (tick-level env read; the `BH_UTP_MUTE` pattern):
/// `BH_SLOW_PEER_CHURN=0` -> the whole face off (zero scanning, zero
/// bookkeeping, zero disconnects); default on. Parse registry:
/// `taiji_io::knobs` (read each round, no caching layer).
pub(crate) fn slow_peer_churn_enabled() -> bool {
    taiji_io::knobs::slow_peer_churn_enabled()
}

/// Eviction-line scaling (parse failure/unset falls back to the
/// default): `BH_SLOW_PEER_FRAC`, default 100 — the line = pool median
/// rate x frac% (100 = everything below the median is eligible; 50 =
/// only the lower half of the median band). Parse registry:
/// `taiji_io::knobs` (read each round).
pub(crate) fn slow_churn_frac_pct() -> u64 {
    taiji_io::knobs::slow_peer_frac_pct()
}

/// Per-round eviction fraction (the same pattern): `BH_SLOW_PEER_K_PCT`,
/// default 10 — per round K = max(1, n x k%) (10% = roughly a tenth of
/// the pool rotated per 30s round, not re-seated within the 300s mark
/// window). Parse registry: `taiji_io::knobs` (read each round).
pub(crate) fn slow_churn_k_pct() -> u64 {
    taiji_io::knobs::slow_peer_k_pct()
}

/// New-peer observation period (the same pattern):
/// `BH_SLOW_PEER_MIN_AGE_SECS`, default 45 — peers registered under
/// 45s (a not-yet-full 30s rate window) are not judged slow (a low
/// reading on an unfilled window is sampling sparsity, not slowness;
/// fresh supply must not be evicted); 0 = the observation period is
/// explicitly off. Parse registry: `taiji_io::knobs` (read each round).
pub(crate) fn slow_churn_min_age() -> Duration {
    Duration::from_secs(taiji_io::knobs::slow_peer_min_age_secs())
}

/// Rarity exemption switch (opt-in): `BH_SLOW_CHURN_RARITY_EXEMPT=1` ->
/// eviction decisions exempt rows where the peer is the sole connected
/// holder of any unfinished piece (without this, slow eviction can
/// evict the last holder of a rare piece and, within the 300s mark
/// window, starve that piece's supply); anything else (incl. unset) =
/// off (decisions bit-for-bit prior). Read at the slow-churn tick
/// assembly (30s cadence, not hot path). Parse registry:
/// `taiji_io::knobs` (read each round, no caching layer).
pub(crate) fn slow_churn_rarity_exempt_enabled() -> bool {
    taiji_io::knobs::slow_churn_rarity_exempt_enabled()
}

/// Sole-connected-holder predicate (pure function, table-driven; env
/// does not enter): true when the peer's advertised bitmap holds a
/// piece that is unfinished locally && availability == 1 across the
/// swarm (this peer is that piece's only connected holder).
/// Availability source = `face.stat_man.count` (the merged counter
/// including seed contributions, piece_stat.rs `count()`) — an
/// existing reading, zero new bookkeeping.
fn slow_churn_sole_holder(
    avail: Option<&PieceBitmap>,
    piece_done: &dyn Fn(u64) -> bool,
    availability: &dyn Fn(u64) -> u32,
) -> bool {
    avail.is_some_and(|bits| {
        bits.iter_ones()
            .any(|g| !piece_done(g as u64) && availability(g as u64) == 1)
    })
}

/// Slow-eviction decision parameters (pure-function inputs; env reads
/// happen at tick assembly — table-driven tests pin these, env stays
/// out of the pure function).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SlowChurnParams {
    /// Master switch (`BH_SLOW_PEER_CHURN`; false = an empty decision).
    pub(crate) enabled: bool,
    /// Eviction-line scaling percent (default 100).
    pub(crate) frac_pct: u64,
    /// Per-round eviction fraction percent (default 10).
    pub(crate) k_pct: u64,
    /// New-peer observation period (default 45s).
    pub(crate) min_age: Duration,
    /// Rarity exemption switch (`BH_SLOW_CHURN_RARITY_EXEMPT`, wired at
    /// tick assembly; default off).
    pub(crate) rarity_exempt: bool,
    /// Discovery candidate-table size (`dial_candidates.len()`; 0 = no
    /// replacement, no disconnect).
    pub(crate) candidates: usize,
}

/// Slow-eviction decision row (the input projection of
/// `slow_churn_pick`; table-driven tests).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SlowChurnRow {
    pub(crate) cuid: u64,
    /// 30s download-window rate (down_windows; the turnover
    /// transfer-key reading).
    pub(crate) down_rate: f64,
    /// Connection age (now - registration; observation-period input).
    pub(crate) age: Duration,
    /// We want supply from this peer (holds pieces we lack; derived
    /// like turnover — interesting peers are picked later at equal
    /// slowness).
    pub(crate) interesting: bool,
    /// Sole connected holder (when `params.rarity_exempt` is on, exempt
    /// from eviction; when off, the flag is ignored = prior behaviour).
    pub(crate) sole_holder: bool,
}

/// Slow-eviction decision output (observation fields reused by tick
/// logs / dashboards).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SlowChurnDecision {
    /// Picked cuids (worst-first: down_rate ascending -> non-interesting
    /// first -> cuid ascending).
    pub(crate) picked: Vec<u64>,
    /// Pool lower-median rate (sorted down_rates, n/2).
    pub(crate) median: f64,
    /// Line = median x frac_pct / 100.
    pub(crate) threshold: f64,
    /// Evictable count (below the line && past observation; before the
    /// K cap).
    pub(crate) evictable: usize,
}

/// Slow-eviction worst-first order: down_rate ascending (worst first)
/// -> ties: non-interesting first (interesting peers are kept; the same
/// direction as the reference `compare_disconnect_peer` is_interesting
/// key, torrent.cpp) -> further ties: cuid ascending (determinism —
/// same input, same output).
fn compare_slow_churn(l: &SlowChurnRow, r: &SlowChurnRow) -> Ordering {
    l.down_rate
        .partial_cmp(&r.down_rate)
        .unwrap_or(Ordering::Equal)
        .then_with(|| l.interesting.cmp(&r.interesting))
        .then_with(|| l.cuid.cmp(&r.cuid))
}

/// Slow-eviction decision core (pure function, table-driven; env stays
/// out):
///
/// - pool floor `rows.len() < [`SLOW_CHURN_MIN_POOL`]` / switch off /
///   `candidates == 0` -> an empty decision (**candidates = 0 means no
///   replacement, no disconnect** — the candidate-cap shape of the
///   reference `min(max(n x 4%, 1), num_connect_candidates())`
///   (session_impl.cpp) adopted here, closing the turnover divergence
///   gap);
/// - median = the lower median of all down_rates (sorted, n/2; n=0 is
///   blocked by the pool floor first);
/// - threshold = median x frac_pct / 100; median == 0 -> threshold 0 ->
///   nobody evictable (`down_rate < 0` is unreachable) — an all-zero
///   pool is left to the stall valve / utp_mute; this predicate governs
///   only "online but slow" (positive-rate distributions);
/// - evictable = `down_rate < threshold && age >= min_age` (strictly
///   below; at the line = the median itself, not evicted); with the
///   rarity exemption on, sole-holder rows are additionally removed
///   (the evictable count includes this exemption);
/// - K = min(evictable, max(1, n x k_pct / 100), candidates).
pub(crate) fn slow_churn_pick(
    rows: &mut [SlowChurnRow],
    params: &SlowChurnParams,
) -> SlowChurnDecision {
    let n = rows.len();
    if n < SLOW_CHURN_MIN_POOL || !params.enabled || params.candidates == 0 {
        return SlowChurnDecision {
            picked: Vec::new(),
            median: 0.0,
            threshold: 0.0,
            evictable: 0,
        };
    }
    // Lower median (copy+sort; the median is one of the row values —
    // the float reading is echoed verbatim).
    let mut rates: Vec<f64> = rows.iter().map(|r| r.down_rate).collect();
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let median = rates[n / 2];
    let threshold = median * params.frac_pct as f64 / 100.0;
    // Evictable filter + worst-first order (rows are Copy; the caller's
    // row order is untouched so the picked-to-bookkeeping
    // correspondence stays stable). Rarity exemption (opt-in; off = all
    // rows pass = prior behaviour).
    let mut evictable: Vec<SlowChurnRow> = rows
        .iter()
        .copied()
        .filter(|r| r.down_rate < threshold && r.age >= params.min_age)
        .filter(|r| !(params.rarity_exempt && r.sole_holder))
        .collect();
    let evictable_n = evictable.len();
    evictable.sort_by(compare_slow_churn);
    // K cap (saturating multiply guards large env values).
    let k_by_pct = ((n as u64).saturating_mul(params.k_pct) / 100).max(1) as usize;
    let k = evictable_n.min(k_by_pct).min(params.candidates);
    let picked = evictable.into_iter().take(k).map(|r| r.cuid).collect();
    SlowChurnDecision {
        picked,
        median,
        threshold,
        evictable: evictable_n,
    }
}

/// Slow-eviction mark TTL decision (pure function; consumed at the
/// leave arm's redial admission): marked within
/// [`SLOW_CHURN_MARK_TTL`] -> true (the departure was a slow eviction,
/// had_data forced false).
///
/// Divergence note: the redial fast path (5s) targets "peers that had
/// delivered data and went missing" (session-restart churn; redial.rs
/// source ranks); slow-evicted peers are "online but slow", not missing
/// — forcing them back to the 60s base = the libtorrent
/// `min_reconnect_time` default (settings_pack.cpp; the gate
/// `(f+1) x 60` in peer_list.cpp), preventing a 5s re-seat into an idle
/// slot (30s eviction rounds + the 60s base = no re-seat within the
/// 300s mark TTL; fresh candidates fill first).
pub(crate) fn slow_evict_marked(marked_at: Option<Instant>, now: Instant) -> bool {
    marked_at.is_some_and(|t| now.duration_since(t) < SLOW_CHURN_MARK_TTL)
}

/// Slow-eviction round execution (direct-drive function; `pub(crate)` =
/// the engine::tests assembly face, the same shape as `utp_mute_face` —
/// the tick is only its assembly shell): collect rows (connected peers
/// of non-completed faces) -> decision core -> locate and disconnect
/// each picked cuid across faces (the turnover shape). Disconnect =
/// **record the mark first** (the SocketAddr built from the peer_state
/// row meta's ip/port — the same construction as the leave arm's redial
/// admission, so the mark keys match) then shutdown (the leave arm
/// reclaims naturally). Returns the decision (observation fields for
/// tick logs).
pub(crate) fn slow_churn_faces(
    faces: &mut [FaceState],
    params: &SlowChurnParams,
    marks: &mut std::collections::HashMap<SocketAddr, Instant>,
    webseed_cuids: &std::collections::HashSet<u64>,
    now: Instant,
) -> SlowChurnDecision {
    // Collect rows only while downloading (completed-face peers are the
    // reciprocal upload side, not judged by download rate; an
    // all-complete pass = zero rows -> an empty decision via the pool
    // floor).
    let mut rows: Vec<SlowChurnRow> = Vec::new();
    for face in faces.iter() {
        if face.completed {
            continue;
        }
        for cuid in face.peer_cuids.iter().copied() {
            // Webseed pseudo-peers exempt (the same rule as turnover
            // row collection — CDN infinitely patient, slowness
            // transient; the direct-drive equivalent of
            // EngineLoop::is_webseed).
            if webseed_cuids.contains(&cuid) {
                continue;
            }
            // interesting derivation (the turnover shape, the
            // peer_avail reading).
            let avail = face.peer_avail.get(&cuid);
            let interesting = avail.is_some_and(|bits| {
                bits.iter_ones()
                    .any(|g| !face.progress.piece_done_global(g as u64))
            });
            // down_rate reading (the turnover transfer key, same
            // shape); age = now - registration (missing bookkeeping
            // defends to age 0 = observation period unmet, no false
            // eviction).
            let row = face.peer_state.get(&cuid);
            let down_rate = row
                .and_then(|ps| ps.down_window.as_ref())
                .map(|w| w.rate())
                .unwrap_or(0.0);
            let age = now.duration_since(row.map(|ps| ps.registered_at).unwrap_or(now));
            // Rarity-exemption flag (not evaluated when the switch is
            // off — zero cost, prior behaviour; availability =
            // stat_man.count including seeds, unfinished =
            // progress.piece_done_global as in the interesting
            // derivation).
            let sole_holder = params.rarity_exempt
                && slow_churn_sole_holder(
                    face.peer_avail.get(&cuid),
                    &|g| face.progress.piece_done_global(g),
                    &|g| face.stat_man.count(g),
                );
            rows.push(SlowChurnRow {
                cuid,
                down_rate,
                age,
                interesting,
                sole_holder,
            });
        }
    }
    let decision = slow_churn_pick(&mut rows, params);
    for cuid in decision.picked.iter().copied() {
        // cuids are globally unique -> locate across faces (lookup and
        // disconnect in the same instant — the leave arm is the single
        // downstream consumer, no race; the turnover shape).
        for (fi, face) in faces.iter_mut().enumerate() {
            let Some(pos) = face.peer_cuids.iter().position(|c| *c == cuid) else {
                continue;
            };
            // Record the mark first (copy ip/port before touching
            // peers — borrows do not overlap the meta read); the insert
            // point retain-clears TTL-expired entries (inbound peers
            // have no redial-admission consumer path; the TTL reclaims
            // marks — bounded).
            if let Some(meta) = face.peer_state.get(&cuid).and_then(|ps| ps.meta.as_ref()) {
                marks.retain(|_, t| now.duration_since(*t) < SLOW_CHURN_MARK_TTL);
                marks.insert(SocketAddr::new(meta.ip, meta.port), now);
            }
            debug!(target: "taiji::core::engine", face = fi, cuid,
                "slow_churn: slow TCP peer evicted (rate-distribution driven; \
                 slot freed for faster candidates)");
            face.peers[pos].shutdown();
            break;
        }
    }
    decision
}

/// Slow-eviction cadence (1s seed tick feed point, after utp_mute):
/// switch off = zero scanning, zero bookkeeping (prior behaviour);
/// early exit inside the 30s interval gate; the cadence anchor is set
/// after every evaluation (empty rounds and seeding too — prevents 1s
/// busy scans). Assembly shell: env parameter reads + EngineLoop
/// bookkeeping -> [`slow_churn_faces`] direct drive. Division of labour
/// with turnover/utp_mute: engine.md.
pub(super) fn slow_peer_churn_tick(state: &mut EngineLoop, now: Instant) {
    if !slow_peer_churn_enabled() {
        return;
    }
    if let Some(t) = state.last_slow_churn
        && now.duration_since(t) < SLOW_CHURN_INTERVAL
    {
        return;
    }
    state.last_slow_churn = Some(now);
    let params = SlowChurnParams {
        // enabled already early-exited via the env gate above
        // (BH_SLOW_PEER_CHURN=0 = prior behaviour); the enabled=false
        // empty-decision face is asserted by engine::tests.
        enabled: true,
        frac_pct: slow_churn_frac_pct(),
        k_pct: slow_churn_k_pct(),
        min_age: slow_churn_min_age(),
        // Rarity exemption (opt-in, default off = prior decisions).
        rarity_exempt: slow_churn_rarity_exempt_enabled(),
        candidates: state.dial_candidates.len(),
    };
    let decision = slow_churn_faces(
        &mut state.faces,
        &params,
        &mut state.slow_evict_marks,
        &state.webseed_cuids,
        now,
    );
    let evicted = decision.picked.len();
    if evicted > 0 {
        info!(target: "taiji::core::engine", evicted,
            evictable = decision.evictable,
            n = state.registered_peers(),
            median = decision.median,
            thr = decision.threshold,
            cand = params.candidates,
            "slow_churn evicted (rate-distribution driven; rqbit dead-90% anchor)");
    } else {
        debug!(target: "taiji::core::engine",
            evictable = decision.evictable,
            n = state.registered_peers(),
            median = decision.median,
            thr = decision.threshold,
            cand = params.candidates,
            "slow_churn round: no eviction (below line or gated)");
    }
}

/// Discovery-arm push consolidation (shared by the tracker/DHT/PEX
/// arms; the hygiene/dedup/self-connect/admission gates run arm-side
/// first — run::dial docs. Pushed addresses wait for the drain round to
/// dial by sort key).
pub(super) fn push_candidate(
    state: &mut EngineLoop,
    addr: SocketAddr,
    face: usize,
    source: DialSourceRank,
    now: Instant,
) {
    state.dial_candidates.push(addr, face, source, now);
}

// ---------------------------------------------------------------------------
// Failed-candidate re-push (outcome-driven retry dynamics)
// ---------------------------------------------------------------------------

/// Failed-candidate re-push decision (pure function, table-driven).
///
/// Background: a dial popped by the drain round that fails used to have
/// a single re-entry path — discovery re-supply — which the
/// `DhtDialDedup` 10min window intercepts, masking the silent ledger's
/// escalating backoff (120/240s) and stretching the real retry period
/// to >= 10min; under hostile dialing (handshake-class failures), that
/// candidate-pool starvation is the main source of connection-table
/// bleed. This face re-pushes failed discovery candidates by outcome;
/// the retry cadence is carried by the silent backoff curve.
///
/// Decision: a discovery source (tracker/DHT/PEX candidate) && switch
/// on && after a silent failure in the Backoff state (escalating
/// window) -> re-push. Three exclusions:
/// - not Backoff (the 3rd failure reached
///   [`taiji_domain::silent::SILENT_MAX_FAILS`] and entered cooldown)
///   -> no re-push — cooldown semantics unchanged (the endpoint waits
///   for discovery re-supply, an ~1800s scale);
/// - a non-discovery source (the Redial pool manages its own cadence /
///   Punch is introducer-gated) -> no re-push;
/// - switch off -> no re-push (legacy: only discovery re-supply
///   re-admits).
///
/// Re-pushed entries retry when the silent backoff window expires and
/// the drain round admits them naturally (`admit` Backoff -> the
/// existing in-table waiting-room semantics). The sort key (fails
/// ascending + last_connected set) keeps fresh candidates first —
/// "rotate fresh candidates while the pool is rich, retry stale ones on
/// backoff when scarce" (libtorrent keeps failures in the table,
/// sinking to the bottom behind the reconnect gate, peer_list.cpp —
/// same spirit; carried here by the silent curve; the 120/240s vs the
/// reference (f+1) x 60s = 120/180s gap is the pre-existing
/// [`taiji_domain::silent::SILENT_BACKOFF_BASE`] divergence, not
/// reopened here).
pub(crate) fn repush_on_silent_failure(
    discovery: bool,
    enabled: bool,
    verdict: SilentVerdict,
) -> bool {
    discovery && enabled && matches!(verdict, SilentVerdict::Backoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn v4(oct: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(oct)), port)
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn row(
        fails: u32,
        local: bool,
        last_connected: Option<Instant>,
        source: DialSourceRank,
        rank: u32,
    ) -> CandidateRow {
        CandidateRow {
            fails,
            local,
            v6_preferred: false,
            last_connected,
            source,
            rank,
        }
    }

    fn row6(
        fails: u32,
        local: bool,
        v6_preferred: bool,
        last_connected: Option<Instant>,
        source: DialSourceRank,
        rank: u32,
    ) -> CandidateRow {
        CandidateRow {
            fails,
            local,
            v6_preferred,
            last_connected,
            source,
            rank,
        }
    }

    /// Slow-eviction row constructor (decision table; sole_holder
    /// defaults false — rarity rows are rewritten in-test).
    fn srow(cuid: u64, down_rate: f64, age_s: u64, interesting: bool) -> SlowChurnRow {
        SlowChurnRow {
            cuid,
            down_rate,
            age: secs(age_s),
            interesting,
            sole_holder: false,
        }
    }

    /// Slow-eviction parameter constructor (decision table; enabled
    /// always true, rarity_exempt always false — both rewritten
    /// in-test).
    fn sparams(frac_pct: u64, k_pct: u64, min_age_s: u64, candidates: usize) -> SlowChurnParams {
        SlowChurnParams {
            enabled: true,
            frac_pct,
            k_pct,
            min_age: secs(min_age_s),
            rarity_exempt: false,
            candidates,
        }
    }

    /// Token-bucket decision table: 30/s continuous accrual, cap 30
    /// (a 1s burst), take1 consumption, long-pause saturation (the u64
    /// overflow face).
    #[test]
    fn dial_budget_refill_take_table() {
        let t = t0();
        let mut b = DialBudget::new(t);
        // Starts full: 30 available.
        assert_eq!(b.available(t), 30);
        // Continuous consumption: 30 grants, the 31st refuses.
        for i in 0..30 {
            assert!(b.take1(t), "token {i} must be granted");
        }
        assert!(!b.take1(t), "exhausted bucket refuses");
        // 0.5s accrues 15; consumption still settles from `last`
        // (continuous accrual).
        assert_eq!(b.available(t + Duration::from_millis(500)), 15);
        assert!(b.take1(t + Duration::from_millis(500)));
        assert_eq!(b.available(t + Duration::from_millis(500)), 14);
        // 1s burst cap: after another 1s the reading clamps to 30 (the
        // saturating-multiply face).
        assert_eq!(b.available(t + secs(1) + Duration::from_millis(500)), 30);
    }

    /// Rate-shift surface: after set_rate the accrual/cap follow the
    /// new tier; a downshift clamps excess accrual immediately; an
    /// upshift does not top up; the floor is defended.
    #[test]
    fn dial_budget_rate_surface() {
        let t = t0();
        let mut b = DialBudget::new(t);
        assert_eq!(b.rate(), 30);
        assert_eq!(b.speed_override(), None);
        // Shift to the hostile tier: the cap follows the rate (1s of
        // quota).
        b.set_rate(100);
        assert_eq!(
            b.available(t),
            30,
            "gear changes do not refill instantly (accumulation still settles by elapsed time)"
        );
        assert_eq!(
            b.available(t + Duration::from_millis(700)),
            100,
            "0.7s refills 70 + the standing 30 = 100 (clamped to one 1s worth)"
        );
        // Drained, then continuous accrual at 100/s.
        for _ in 0..100 {
            assert!(b.take1(t + Duration::from_millis(700)));
        }
        assert!(!b.take1(t + Duration::from_millis(700)));
        assert_eq!(b.available(t + Duration::from_millis(700) + secs(1)), 100);
        // Downshift: excess accrual clamps to the new cap immediately
        // (the set_rate single point).
        b.set_rate(30);
        assert_eq!(b.available(t + Duration::from_millis(700) + secs(1)), 30);
        assert_eq!(
            b.available(t + Duration::from_millis(700) + secs(2)),
            30,
            "the 1s burst ceiling follows the new gear"
        );
        // The set_rate floor is defended.
        b.set_rate(0);
        assert_eq!(b.rate(), 1);
    }

    /// Gear-shift decision table (connect_speed_for; the 4th arg = gear
    /// hold): override first -> minimum-sample guard (insufficient =
    /// hold current) -> strictly >50% picks the hostile tier; the
    /// base-rate boundary and recovery. The fallback
    /// (`BH_CONNECT_SPEED_HOLD=0`) production assembly passes the base
    /// rate = "insufficient samples -> base rate" bit-for-bit (hold vs
    /// fallback are distinguished at the pure function only by the
    /// `current` argument — one predicate).
    #[test]
    fn connect_speed_adaptive_decision_table() {
        // Override first: the override passes through even in a hostile
        // window (the fallback form BH_CONNECT_SPEED=30).
        assert_eq!(connect_speed_for(Some(30), 20, 20, CONNECTION_SPEED), 30);
        assert_eq!(connect_speed_for(Some(200), 0, 0, CONNECTION_SPEED), 200);
        // Override floor 1 (an illegal 0 is filtered at assembly parse;
        // only the pure function is pinned here).
        assert_eq!(connect_speed_for(Some(0), 0, 0, CONNECTION_SPEED), 1);
        // No override: empty window / small samples = hold current
        // (gear hold). The fallback assembly passes the base rate ->
        // bit-for-bit "empty window = base rate".
        assert_eq!(connect_speed_for(None, 0, 0, CONNECTION_SPEED), 30);
        assert_eq!(
            connect_speed_for(
                None,
                DIAL_FAILURE_MIN_ATTEMPTS - 1,
                DIAL_FAILURE_MIN_ATTEMPTS - 1,
                CONNECTION_SPEED
            ),
            30,
            "minimum-sample guard (fallback state = bit for bit)"
        );
        // Hold mode: under the hostile tier, an empty window / small
        // samples keep the hostile tier (the false "zero samples =
        // normal" downshift is eliminated).
        assert_eq!(
            connect_speed_for(None, 0, 0, CONNECTION_SPEED_HOSTILE),
            100,
            "an empty window holds the current gear (not evidence for a downgrade)"
        );
        assert_eq!(
            connect_speed_for(
                None,
                DIAL_FAILURE_MIN_ATTEMPTS - 1,
                DIAL_FAILURE_MIN_ATTEMPTS - 1,
                CONNECTION_SPEED_HOSTILE
            ),
            100,
            "a small sample holds the current gear"
        );
        // Full samples: exactly 50% does not shift (strictly greater),
        // 51% shifts (recovery is unaffected in hold mode — a
        // sufficient low failure rate still drops to base).
        assert_eq!(
            connect_speed_for(None, 20, 10, CONNECTION_SPEED_HOSTILE),
            30
        );
        assert_eq!(connect_speed_for(None, 20, 11, CONNECTION_SPEED), 100);
        // Large-sample shapes: all failures / all successes / just over
        // half.
        assert_eq!(connect_speed_for(None, 1000, 1000, CONNECTION_SPEED), 100);
        assert_eq!(
            connect_speed_for(None, 1000, 0, CONNECTION_SPEED_HOSTILE),
            30
        );
        assert_eq!(connect_speed_for(None, 1000, 501, CONNECTION_SPEED), 100);
        assert_eq!(
            connect_speed_for(None, 1000, 500, CONNECTION_SPEED_HOSTILE),
            30
        );
        // Constant provenance pinned.
        assert_eq!(CONNECTION_SPEED, 30, "settings_pack.cpp direct translation");
        assert_eq!(
            CONNECTION_SPEED_HOSTILE, 100,
            "industry-survey accelerated-band lower bound"
        );
        assert_eq!(DIAL_FAILURE_RATE_PCT, 50, "the spec's >50% semantics");
    }

    /// Gear-shift oscillation elimination sequence table: a first
    /// window of 77 tries / 39 failures (50.6%, just over the line)
    /// shifts to the hostile tier -> shift re-anchor (counters kept) ->
    /// candidate drought, zero new samples: the old evidence keeps the
    /// hostile tier within the re-anchored window (without the hold the
    /// rate would fall back to base on the window roll) -> after the
    /// re-anchored window rolls, an empty window holds the current tier
    /// -> a recovery window (>=20 samples && a low failure rate) drops
    /// to base as usual. The no-hold behaviour (same inputs, no
    /// re-anchor + insufficient samples -> base) is covered by the
    /// fallback rows of the decision table above.
    #[test]
    fn connect_speed_hold_oscillation_elimination_table() {
        let t = t0();
        let mut w = DialOutcomeWindow::new(t);
        let mut rate = CONNECTION_SPEED;
        // First window: 77 tries, 39 failures = 50.6%, strictly >50%.
        for i in 0..77u64 {
            w.note(i % 2 == 1, t + Duration::from_millis(300 * (i + 1)));
        }
        let (a, f) = w.observation(t + secs(25));
        assert_eq!((a, f), (77, 39));
        let speed = connect_speed_for(None, a, f, rate);
        assert_eq!(
            speed, CONNECTION_SPEED_HOSTILE,
            "50.6% just crosses the line into the hostile gear"
        );
        rate = speed;
        w.reanchor(t + secs(25)); // Shift re-anchor (drain arm same shape: samples not cleared).
        // Hostile tier with a candidate drought: zero new samples in
        // the re-anchored window — the old evidence stays visible, the
        // hostile tier holds (the "next window 0 tries 0 failures =
        // recovery" flip point is eliminated).
        let (a2, f2) = w.observation(t + secs(25) + secs(20));
        assert_eq!(
            (a2, f2),
            (77, 39),
            "re-anchoring keeps the gear-change evidence"
        );
        assert_eq!(
            connect_speed_for(None, a2, f2, rate),
            rate,
            "within the re-anchor window the old evidence holds the hostile gear (the same point has already fallen back to the base gear)"
        );
        // The re-anchored window rolls: an empty window holds the
        // current tier ("zero samples != normal").
        let (a3, f3) = w.observation(t + secs(25) + DIAL_OUTCOME_WINDOW);
        assert_eq!(
            (a3, f3),
            (0, 0),
            "only a full window after re-anchoring rolls the counters to zero"
        );
        assert_eq!(
            connect_speed_for(None, a3, f3, rate),
            rate,
            "an empty window holds the current gear — both the up and down \
             directions need >= 20-sample evidence"
        );
        // Recovery: a new window with >=20 samples && zero failures ->
        // drop to base (the recovery path is untouched).
        for _ in 0..20u64 {
            w.note(true, t + secs(56));
        }
        let (a4, f4) = w.observation(t + secs(57));
        assert_eq!((a4, f4), (20, 0));
        assert_eq!(
            connect_speed_for(None, a4, f4, rate),
            CONNECTION_SPEED,
            "recovery judgment proceeds as usual (gear-holding does not pin the hostile gear)"
        );
    }

    /// Dial decay rate shape: `max(gear >> steps, FLOOR)`,
    /// identity at 0 steps, floor 8 for both gears, defensive floor 1 for
    /// degenerate zero gears.
    #[test]
    fn dial_decay_rate_table() {
        // Hostile gear 100: 100 -> 50 -> 25 -> 12 -> 8 -> 8.
        let hostile: [(u32, u32, u32); 6] = [
            (100, 0, 100),
            (100, 1, 50),
            (100, 2, 25),
            (100, 3, 12),
            (100, 4, 8),
            (100, 99, 8),
        ];
        // Base gear 30: 30 -> 15 -> 8 -> 8.
        let base: [(u32, u32, u32); 4] = [(30, 0, 30), (30, 1, 15), (30, 2, 8), (30, 3, 8)];
        for (gear, steps, want) in hostile.iter().chain(base.iter()) {
            assert_eq!(
                dial_decay_rate(*gear, *steps),
                *want,
                "gear={gear} steps={steps}"
            );
        }
        assert_eq!(dial_decay_rate(0, 0), 1, "zero-rate defense floor of 1");
        assert_eq!(dial_decay_rate(1, 3), 8, "the floor is never below 8/s");
        assert_eq!(DIAL_DECAY_FLOOR, 8, "half the measured 17-18/s magnitude");
        assert_eq!(
            DIAL_DECAY_PCT, 85,
            "no discount below the measured 86-90% failure band"
        );
        assert_eq!(
            DIAL_POOL_KNOWN_HIGH, 512,
            "half the 4096 cap (measured 742-812 hits)"
        );
    }

    /// Ladder transition table: master switch off / pinned
    /// override -> constant 0; insufficient samples -> hold; >85% + a
    /// fresh step window -> +1 capped at 4; >85% without an elapsed step
    /// window -> hold (the 250ms round re-reads one window up to 120x —
    /// only one step counts); 50-85% band -> hold; <=50% -> immediate
    /// full recovery.
    #[test]
    fn dial_decay_steps_table() {
        let bad = (100u64, 90u64); // 90% > 85%
        let band = (100u64, 70u64); // 70%: the 50-85% hold band
        let good = (100u64, 50u64); // 50%: <= the gear threshold -> recovery
        // Switch off / pinned: everything is 0 regardless of evidence.
        assert_eq!(dial_decay_steps(false, false, bad.0, bad.1, 2, true), 0);
        assert_eq!(dial_decay_steps(true, true, bad.0, bad.1, 2, true), 0);
        // Insufficient samples: hold.
        assert_eq!(dial_decay_steps(true, false, 19, 19, 2, true), 2);
        // Bad + elapsed: +1; cap at 4.
        assert_eq!(dial_decay_steps(true, false, bad.0, bad.1, 0, true), 1);
        assert_eq!(dial_decay_steps(true, false, bad.0, bad.1, 3, true), 4);
        assert_eq!(dial_decay_steps(true, false, bad.0, bad.1, 4, true), 4);
        // Bad + not elapsed: hold (one window = one step).
        assert_eq!(dial_decay_steps(true, false, bad.0, bad.1, 2, false), 2);
        // Band: hold either way.
        assert_eq!(dial_decay_steps(true, false, band.0, band.1, 2, true), 2);
        // Good: immediate full recovery.
        assert_eq!(dial_decay_steps(true, false, good.0, good.1, 4, false), 0);
    }

    /// pool_known coupling ("lower the dial frequency when pool_known
    /// is high"): a
    /// large known pool adds one effective step (capped); switch off /
    /// pinned collapses the face.
    #[test]
    fn effective_decay_steps_pool_coupling() {
        assert_eq!(effective_decay_steps(true, false, 0, 0), 0);
        assert_eq!(effective_decay_steps(true, false, 0, 511), 0);
        assert_eq!(effective_decay_steps(true, false, 0, 512), 1);
        assert_eq!(effective_decay_steps(true, false, 2, 742), 3);
        assert_eq!(
            effective_decay_steps(true, false, 4, 4096),
            4,
            "capped at 4"
        );
        assert_eq!(effective_decay_steps(false, false, 4, 4096), 0);
        assert_eq!(effective_decay_steps(true, true, 4, 4096), 0);
    }

    /// Completed-state passive-DHT decision: suppression
    /// requires BOTH faces complete and the opt-in switch on — the
    /// default (switch off) is never suppressed at any completion state
    /// (the freeze seam: behavior change delivered opt-in, default off).
    #[test]
    fn seed_passive_dht_suppression_table() {
        assert!(!seed_passive_dht_suppressed(false, false));
        assert!(!seed_passive_dht_suppressed(false, true));
        assert!(
            !seed_passive_dht_suppressed(true, false),
            "default off: the completed state still climbs actively"
        );
        assert!(
            seed_passive_dht_suppressed(true, true),
            "both opt-in conditions are required to stop"
        );
    }

    /// Seeding-steady-state descent walk (the bench-measured shape): hostile
    /// gear 100 + sustained 88% failure + pool_known 742 (the measured
    /// curve; the pool coupling adds one effective step throughout)
    /// descends 100 -> 25 -> 12 -> 8 over three step windows (>= 90s) and
    /// holds the floor, and a good window recovers the ladder immediately
    /// (the pool coupling keeps one step while the table stays large) —
    /// the download-ramp safety face (a fresh engine can take at most one
    /// step in its first 30s, so the A/B download window never sees a
    /// rate below its own achieved dial rate).
    #[test]
    fn dial_decay_descent_and_recovery_walk() {
        let mut steps = 0;
        // Three elapsed step windows at (attempts=510, failures=448) ≈ 88%.
        for expected in [25u32, 12, 8, 8] {
            steps = dial_decay_steps(true, false, 510, 448, steps, true);
            let eff = effective_decay_steps(true, false, steps, 742);
            assert_eq!(
                dial_decay_rate(CONNECTION_SPEED_HOSTILE, eff),
                expected,
                "steps={steps} eff={eff}"
            );
        }
        // A good window (<=50%): full ladder recovery; the pool coupling
        // keeps one effective step while the table stays large, and a
        // drained pool restores the gear rate outright.
        steps = dial_decay_steps(true, false, 510, 100, steps, false);
        assert_eq!(steps, 0);
        let eff = effective_decay_steps(true, false, steps, 742);
        assert_eq!(
            dial_decay_rate(CONNECTION_SPEED_HOSTILE, eff),
            50,
            "a large pool still folds one step"
        );
        let eff = effective_decay_steps(true, false, steps, 100);
        assert_eq!(dial_decay_rate(CONNECTION_SPEED_HOSTILE, eff), 100);
    }

    /// Re-anchor window phase table ([`DialOutcomeWindow::reanchor`]):
    /// only the start moves, counters are kept; a re-anchor defers the
    /// roll (a window near expiry gains a full window); interplay with
    /// the note-triggered roll.
    #[test]
    fn dial_outcome_window_reanchor_table() {
        let t = t0();
        let mut w = DialOutcomeWindow::new(t);
        w.note(false, t + secs(1));
        w.note(true, t + secs(2));
        // Re-anchor near expiry: the window would roll at t+29s; it
        // gains a full window.
        w.reanchor(t + secs(29));
        assert_eq!(
            w.observation(t + secs(29)),
            (2, 1),
            "re-anchoring does not clear the counts"
        );
        assert_eq!(
            w.observation(t + DIAL_OUTCOME_WINDOW),
            (2, 1),
            "the old window's phase is void — rolling counts from the re-anchor \
             point (t+29+30 not yet full)"
        );
        assert_eq!(
            w.observation(t + secs(29) + DIAL_OUTCOME_WINDOW),
            (0, 0),
            "a full window after re-anchoring rolls the counters to zero"
        );
    }

    /// Observation-window roll table (DialOutcomeWindow): in-window
    /// accumulation, receipt classification, roll-on-expiry (shift
    /// decisions see only the current window), saturation.
    #[test]
    fn dial_outcome_window_roll_table() {
        let t = t0();
        let mut w = DialOutcomeWindow::new(t);
        assert_eq!(w.observation(t), (0, 0), "empty window at the start");
        // In-window accumulation: 3 attempts, 2 failures.
        w.note(false, t + secs(1));
        w.note(true, t + secs(2));
        w.note(false, t + secs(3));
        assert_eq!(w.observation(t + secs(3)), (3, 2));
        // Just inside the window (< 30s): not cleared.
        assert_eq!(w.observation(t + secs(29)), (3, 2));
        // Past the window: rolled and cleared.
        assert_eq!(w.observation(t + DIAL_OUTCOME_WINDOW), (0, 0));
        assert_eq!(
            w.observation(t + DIAL_OUTCOME_WINDOW),
            (0, 0),
            "repeated readings do not advance the window"
        );
        // The new window re-accumulates.
        w.note(true, t + DIAL_OUTCOME_WINDOW + Duration::from_millis(500));
        assert_eq!(w.observation(t + DIAL_OUTCOME_WINDOW + secs(1)), (1, 0));
        // note also triggers the roll (a dial after long silence).
        w.note(false, t + DIAL_OUTCOME_WINDOW * 3);
        assert_eq!(w.observation(t + DIAL_OUTCOME_WINDOW * 3), (1, 1));
        // u64 saturation (a defensive shape).
        w.attempts = u64::MAX;
        w.failures = u64::MAX;
        w.note(false, t + DIAL_OUTCOME_WINDOW * 3);
        assert_eq!(w.attempts, u64::MAX, "saturation adds without overflowing");
        assert_eq!(w.failures, u64::MAX);
    }

    /// Drain-budget cap formula table (drain_budget_cap): the backlog
    /// term converges the budget and the backlog, the 512 half-open cap
    /// binds under large overrides, the defaults do not bind.
    #[test]
    fn drain_budget_cap_formula_table() {
        assert_eq!(
            DIAL_HALFOPEN_CAP, 512,
            "the spec cap formula's right-hand term"
        );
        // Base 30: with scarce candidates the budget converges to the
        // backlog (actual dials are bounded by row sampling anyway — a
        // zero-behaviour-change face).
        assert_eq!(drain_budget_cap(30, 5), 5);
        // Hostile 100: does not bind when candidates are plentiful.
        assert_eq!(drain_budget_cap(100, 3000), 100);
        // A large override (>512): the half-open cap binds.
        assert_eq!(drain_budget_cap(1000, 3000), 512);
        // Both small: takes the smaller.
        assert_eq!(drain_budget_cap(600, 400), 400);
    }

    /// Sampling order (round_robin): a window <= len walks forward and
    /// wraps, an out-of-range cursor resets, len=0 is an empty round.
    #[test]
    fn sample_order_round_robin() {
        let (idx, cur) = sample_order(5, 0, 300);
        assert_eq!(idx, vec![0, 1, 2, 3, 4]);
        assert_eq!(cur, 0);
        let (idx, cur) = sample_order(5, 3, 300);
        assert_eq!(idx, vec![3, 4, 0, 1, 2]);
        assert_eq!(
            cur, 3,
            "back to the start after a full round-robin sweep (round_robin synonym)"
        );
        // Window < len: the 300 cap applies when len>300.
        let (idx, cur) = sample_order(1024, 1020, 300);
        assert_eq!(idx.len(), 300);
        assert_eq!(idx[0], 1020);
        assert_eq!(idx[3], 1023);
        assert_eq!(idx[4], 0);
        assert_eq!(cur, (1020 + 300) % 1024);
        let (idx, cur) = sample_order(0, 7, 300);
        assert!(idx.is_empty());
        assert_eq!(cur, 0);
    }

    /// Sort-key synthesis decision table (the compare_peer key order +
    /// the v6 key): fails ascending -> local -> v6_preferred ->
    /// last_connected earlier/never -> source_rank descending -> bep40
    /// rank descending; per-key dominance plus the full chain.
    #[test]
    fn candidate_priority_synthesis_table() {
        let t = t0();
        // Key 1: lower failcount wins (all other keys equal).
        assert_eq!(
            compare_candidate(
                &row(0, false, None, DialSourceRank::Pex, 0),
                &row(1, true, Some(t), DialSourceRank::Tracker, u32::MAX),
            ),
            Ordering::Less,
            "failcount dominates the other keys"
        );
        // Key 2: local wins (over source/rank).
        assert_eq!(
            compare_candidate(
                &row(0, true, None, DialSourceRank::Pex, 0),
                &row(0, false, None, DialSourceRank::Tracker, u32::MAX),
            ),
            Ordering::Less
        );
        // Key 3: never-connected (None) precedes any tried time.
        assert_eq!(
            compare_candidate(
                &row(0, false, None, DialSourceRank::Pex, 0),
                &row(0, false, Some(t), DialSourceRank::Tracker, u32::MAX),
            ),
            Ordering::Less
        );
        assert_eq!(
            compare_candidate(
                &row(0, false, Some(t + secs(1)), DialSourceRank::Pex, 0),
                &row(0, false, Some(t + secs(2)), DialSourceRank::Pex, 0),
            ),
            Ordering::Less,
            "an earlier last_connected wins"
        );
        // Key 4: higher source_rank wins (tracker > lsd > dht > pex).
        assert_eq!(
            compare_candidate(
                &row(0, false, None, DialSourceRank::Tracker, 0),
                &row(0, false, None, DialSourceRank::Lsd, u32::MAX),
            ),
            Ordering::Less
        );
        assert_eq!(
            compare_candidate(
                &row(0, false, None, DialSourceRank::Dht, 0),
                &row(0, false, None, DialSourceRank::Pex, u32::MAX),
            ),
            Ordering::Less
        );
        // Key 5: higher bep40 rank wins.
        assert_eq!(
            compare_candidate(
                &row(0, false, None, DialSourceRank::Pex, 9),
                &row(0, false, None, DialSourceRank::Pex, 7),
            ),
            Ordering::Less
        );
        // All equal -> Equal.
        assert_eq!(
            compare_candidate(
                &row(1, true, Some(t), DialSourceRank::Dht, 5),
                &row(1, true, Some(t), DialSourceRank::Dht, 5)
            ),
            Ordering::Equal
        );
        // Key 3' (v6 preference, after local before last_connected): a
        // v6 candidate outranks last_connected/source/rank but not
        // fails/local; both false = a neutral key (v6 unavailable /
        // switch off — zero decision change).
        assert_eq!(
            compare_candidate(
                &row6(0, false, true, Some(t + secs(5)), DialSourceRank::Pex, 0),
                &row6(0, false, false, Some(t), DialSourceRank::Tracker, u32::MAX),
            ),
            Ordering::Less,
            "v6 candidates outrank any v4 (within the same key tier)"
        );
        assert_eq!(
            compare_candidate(
                &row6(1, false, true, None, DialSourceRank::Tracker, u32::MAX),
                &row6(0, false, false, None, DialSourceRank::Pex, 0),
            ),
            Ordering::Greater,
            "the fails key still dominates the v6 key"
        );
        assert_eq!(
            compare_candidate(
                &row6(0, false, true, None, DialSourceRank::Pex, 0),
                &row6(0, true, false, None, DialSourceRank::Pex, 0),
            ),
            Ordering::Greater,
            "the local key still dominates the v6 key (link-local direct connect is most preferred)"
        );
        assert_eq!(
            compare_candidate(
                &row6(0, false, false, None, DialSourceRank::Dht, 1),
                &row6(0, false, false, None, DialSourceRank::Dht, 1),
            ),
            Ordering::Equal,
            "the v6 key's neutral face (both false)"
        );
    }

    /// Candidate-table bounded face: full rejects new entries (counted),
    /// duplicate addresses ignored; TTL/remove are consumed by the
    /// drain (only the structure is verified here).
    #[test]
    fn candidate_table_bounded_and_dedup() {
        let t = t0();
        let mut tbl = DialCandidates::default();
        tbl.push(v4([203, 0, 113, 1], 6881), 0, DialSourceRank::Tracker, t);
        // A duplicate address push is ignored.
        tbl.push(v4([203, 0, 113, 1], 6881), 1, DialSourceRank::Dht, t);
        assert_eq!(tbl.len(), 1);
        // Full -> reject new entries.
        let mut full = DialCandidates::default();
        for i in 0..DIAL_CANDIDATE_CAP {
            full.push(
                v4([10, (i / 256) as u8, i as u8, 1], 6881),
                0,
                DialSourceRank::Dht,
                t,
            );
        }
        assert_eq!(full.len(), DIAL_CANDIDATE_CAP);
        full.push(v4([203, 0, 113, 9], 6881), 0, DialSourceRank::Dht, t);
        assert_eq!(
            full.len(),
            DIAL_CANDIDATE_CAP,
            "full table rejects new entries"
        );
        // remove is idempotent.
        full.remove(&v4([203, 0, 113, 9], 6881));
        assert_eq!(full.len(), DIAL_CANDIDATE_CAP);
        full.remove(&v4([10, 0, 0, 1], 6881));
        assert_eq!(full.len(), DIAL_CANDIDATE_CAP - 1);
    }

    /// Capacity face: the default = the aligned capacity
    /// (max_peerlist_size 3000, settings_pack.cpp); with_cap applies an
    /// explicit capacity (the switch fallback is an assembly-time
    /// from_env reading; env does not enter unit tests — the
    /// constructor face is pinned via with_cap, the
    /// `BH_FAST_RECONNECT` with_fast_reconnect pattern).
    #[test]
    fn candidate_table_cap_surface() {
        let t = t0();
        assert_eq!(DIAL_CANDIDATE_CAP, 3000, "aligned with max_peerlist_size");
        assert_eq!(
            DIAL_CANDIDATE_CAP_LEGACY, 1024,
            "the current fallback value"
        );
        let mut tbl = DialCandidates::with_cap(2);
        tbl.push(v4([203, 0, 113, 1], 1), 0, DialSourceRank::Dht, t);
        tbl.push(v4([203, 0, 113, 2], 1), 0, DialSourceRank::Dht, t);
        tbl.push(v4([203, 0, 113, 3], 1), 0, DialSourceRank::Dht, t);
        assert_eq!(
            tbl.len(),
            2,
            "with_cap sizes the table; full rejects new entries"
        );
        // Capacity floor 1 (the cap.max(1) degenerate shape).
        let mut one = DialCandidates::with_cap(0);
        one.push(v4([203, 0, 113, 4], 1), 0, DialSourceRank::Dht, t);
        one.push(v4([203, 0, 113, 5], 1), 0, DialSourceRank::Dht, t);
        assert_eq!(one.len(), 1);
    }

    /// Failed-candidate re-push decision table: discovery source &&
    /// switch on && the Backoff state re-pushes — cooldown (the 3rd
    /// failure), a non-discovery source (Redial/Punch self-managed),
    /// and the switch off are all excluded; live interplay with the
    /// silent ledger (note_silent -> admit verdict per failure) is
    /// embedded.
    #[test]
    fn repush_on_silent_failure_decision_table() {
        let t0 = Instant::now();
        let mut book = taiji_domain::silent::SilentBook::new(taiji_domain::silent::SILENT_BOOK_CAP);
        let a = v4([203, 0, 113, 20], 6881);
        // 1st failure: Backoff -> discovery + switch on = re-push.
        book.note_silent(a, t0);
        assert!(repush_on_silent_failure(true, true, book.admit(&a, t0)));
        // 2nd failure: Backoff -> re-push (a 240s window; the retry
        // cadence is carried by the in-table waiting room).
        book.note_silent(a, t0 + secs(120));
        assert!(repush_on_silent_failure(
            true,
            true,
            book.admit(&a, t0 + secs(120))
        ));
        // 3rd failure: SILENT_MAX_FAILS -> cooldown -> no re-push
        // (cooldown unchanged).
        book.note_silent(a, t0 + secs(360));
        assert_eq!(book.admit(&a, t0 + secs(360)), SilentVerdict::Cooldown);
        assert!(!repush_on_silent_failure(
            true,
            true,
            book.admit(&a, t0 + secs(360))
        ));
        // A non-discovery source (the Redial pool / Punch face
        // self-managed) -> no re-push.
        assert!(!repush_on_silent_failure(
            false,
            true,
            SilentVerdict::Backoff
        ));
        // Switch off -> no re-push (legacy behaviour).
        assert!(!repush_on_silent_failure(
            true,
            false,
            SilentVerdict::Backoff
        ));
    }

    /// Turnover disconnect-order decision table (the
    /// compare_disconnect_peer key chain): not interesting -> non-seed
    /// -> low rate -> choking us; the omitted
    /// is_disconnecting/on_parole/last_received keys are documented on
    /// compare_disconnect; turnover_pick truncation + stable order.
    #[test]
    fn turnover_pick_worst_first_table() {
        let mk = |cuid, interesting, seed, rate, choking| TurnoverRow {
            cuid,
            interesting,
            seed,
            down_rate: rate,
            choking_us: choking,
        };
        // Order: not interesting < non-seed < low rate < choking us
        // (further left disconnects first).
        let mut rows = vec![
            mk(1, true, true, 100.0, false), // best: interesting + seed + fast + unchoked
            mk(2, false, false, 0.0, false), // worst: uninteresting + non-seed + zero rate
            mk(3, false, true, 50.0, false), // uninteresting seed
            mk(4, true, false, 10.0, false), // interesting non-seed, slow
        ];
        assert_eq!(
            turnover_pick(&mut rows, 1),
            vec![2],
            "the sole worst performer is picked"
        );
        let picked = turnover_pick(&mut rows, 4);
        assert_eq!(
            picked,
            vec![2, 3, 4, 1],
            "the full set output in worst-first order"
        );
        // count > len: take all.
        assert_eq!(turnover_pick(&mut rows, 99).len(), 4);
        // Empty: empty result.
        assert!(turnover_pick(&mut [], 3).is_empty());
        // Key 6 (is_choked): with the earlier keys all equal
        // (uninteresting + non-seed + zero rate), the peer choking us
        // disconnects first (reference torrent.cpp).
        let mut rows = vec![
            mk(20, false, false, 0.0, false),
            mk(21, false, false, 0.0, true),
        ];
        assert_eq!(
            turnover_pick(&mut rows, 1),
            vec![21],
            "the peer choking us disconnects first"
        );
        // Key 6 sits after the rate key (no jumping): a choking but
        // fast peer sorts after an unchoked zero-rate peer.
        let mut rows = vec![
            mk(30, false, false, 50.0, true), // choking us + fast
            mk(31, false, false, 0.0, false), // unchoked + zero rate
        ];
        assert_eq!(
            turnover_pick(&mut rows, 2),
            vec![31, 30],
            "the rate key precedes the choke key"
        );
        // Partial truncation = the reference partial_sort_copy: the
        // first count picks equal the worst prefix of the full order.
        let mut rows = vec![
            mk(10, true, true, 9.0, false),
            mk(11, false, false, 1.0, false),
            mk(12, false, false, 2.0, false),
            mk(13, true, false, 8.0, false),
        ];
        let mut full_ref = rows.clone();
        let part = turnover_pick(&mut rows, 2);
        let whole = turnover_pick(&mut full_ref, 4);
        assert_eq!(
            part,
            whole[..2],
            "truncation = a prefix of the full-order sequence"
        );
    }

    /// µTP zero-throughput governance decision table (the utp_mute_step
    /// pure function): transport gate (TCP never touched) / output
    /// exemption (any output clears the record) / first observation
    /// records / the window holds / past-window disconnects (>=
    /// semantics; exactly 120s disconnects).
    #[test]
    fn utp_mute_step_decision_table() {
        let t0 = t0();
        let t1 = t0 + Duration::from_secs(1);
        let t120 = t0 + UTP_MUTE_AFTER;
        let t119 = t0 + UTP_MUTE_AFTER - Duration::from_secs(1);
        // Transport gate: any TCP input (even a past-window record)
        // never disconnects or records — TCP zero throughput belongs to
        // turnover / the stall valve.
        assert_eq!(
            utp_mute_step(Transport::Tcp, 0.0, 0.0, None, t0),
            (None, false)
        );
        assert_eq!(
            utp_mute_step(Transport::Tcp, 0.0, 0.0, Some(t0), t120),
            (None, false),
            "over the TCP window does not trigger either"
        );
        // Output exemption: any direction producing clears the record,
        // no disconnect (upload output = a reciprocity contribution,
        // exempt symmetrically with download).
        assert_eq!(
            utp_mute_step(Transport::Utp, 100.0, 0.0, Some(t0), t1),
            (None, false),
            "downloads have output"
        );
        assert_eq!(
            utp_mute_step(Transport::Utp, 0.0, 100.0, Some(t0), t1),
            (None, false),
            "uploads with output are exempt"
        );
        // First observation records (no disconnect).
        assert_eq!(
            utp_mute_step(Transport::Utp, 0.0, 0.0, None, t0),
            (Some(t0), false)
        );
        // Inside the window the original instant is kept (the timing
        // anchor = the first observation).
        assert_eq!(
            utp_mute_step(Transport::Utp, 0.0, 0.0, Some(t0), t1),
            (Some(t0), false)
        );
        assert_eq!(
            utp_mute_step(Transport::Utp, 0.0, 0.0, Some(t0), t119),
            (Some(t0), false),
            "still observed one second before the window fills"
        );
        // Past-window disconnect (>= semantics: exactly 120s
        // disconnects) + the record cleared.
        assert_eq!(
            utp_mute_step(Transport::Utp, 0.0, 0.0, Some(t0), t120),
            (None, true),
            "disconnected at exactly 120s (the BEP29 base two-minute full-window cycle)"
        );
    }

    /// Slow-eviction decision table (the slow_churn_pick pure
    /// function; the base pool = 10 rows with rates 10..100 (cuid
    /// 1..10), age 100s, defaults frac=100 -> median=60 -> line=60,
    /// k_pct=30, candidates=50 -> K=3): below-line evictable /
    /// above-line exempt / new-peer observation exempt / median=0 all
    /// exempt / candidates=0 all exempt / n<8 pool floor exempt /
    /// enabled=false all exempt / frac scaling / K capped by k_pct / K
    /// capped by candidates / ties pick non-interesting first /
    /// determinism (same input, same output).
    #[test]
    fn slow_churn_pick_decision_table() {
        // Base pool: cuid k -> rate k*10 (1..=10 -> 10..=100), age 100s
        // (>= the 45 observation period), all non-interesting.
        let base_pool = || -> Vec<SlowChurnRow> {
            (1..=10u64)
                .map(|cuid| srow(cuid, cuid as f64 * 10.0, 100, false))
                .collect()
        };
        // Base parameters: frac 100 / k_pct 30 / min_age 45 /
        // candidates 50.
        let base_params = || sparams(100, 30, 45, 50);
        // Row 1 (below-line evictable): median=60, line=60, evictable =
        // cuid 1..5 (rates 10..50 < 60), K = min(5, max(1,3), 50) = 3
        // -> worst-first [1,2,3]; the observation fields (median/thr)
        // echo with the decision.
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &base_params());
        assert_eq!(
            d.picked,
            vec![1, 2, 3],
            "below-the-line peers picked in worst-first order"
        );
        assert_eq!(d.evictable, 5);
        assert_eq!(d.median, 60.0, "the lower median (sorted, index n/2)");
        assert_eq!(d.threshold, 60.0, "the line = median x 100%");
        // Row 2 (above-line exempt): cuid 6..10 (rates 60..100 >= the
        // line) never enter the evictable set — even K opened to 10
        // (k_pct=100) yields only 5.
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &sparams(100, 100, 45, 50));
        assert_eq!(
            d.picked,
            vec![1, 2, 3, 4, 5],
            "exactly at the line (rate=median=60) and above it are all exempt (strictly <)"
        );
        // Row 3 (new-peer observation period): cuid 1 age=44 < 45 ->
        // out, the next in line fills in.
        let mut rows = base_pool();
        rows[0].age = secs(44);
        let d = slow_churn_pick(&mut rows, &base_params());
        assert_eq!(
            d.evictable, 4,
            "peers inside the observation period never enter the evictable set"
        );
        assert_eq!(
            d.picked,
            vec![2, 3, 4],
            "next in line fills in (the worst-first order unchanged)"
        );
        // Row 3' (age == min_age -> passes: the >= semantics).
        let mut rows = base_pool();
        rows[0].age = secs(45);
        let d = slow_churn_pick(&mut rows, &base_params());
        assert_eq!(
            d.picked,
            vec![1, 2, 3],
            "age == min_age just crosses the observation period"
        );
        // Row 4 (median=0 all exempt): an all-zero pool -> threshold 0
        // -> nobody evictable (an all-zero pool is left to stall /
        // utp_mute).
        let mut rows: Vec<SlowChurnRow> =
            (1..=10).map(|cuid| srow(cuid, 0.0, 100, false)).collect();
        let d = slow_churn_pick(&mut rows, &base_params());
        assert!(d.picked.is_empty());
        assert_eq!(d.evictable, 0);
        assert_eq!(d.threshold, 0.0);
        // Row 5 (candidates=0 all exempt): no replacement, no
        // disconnect (the reference session_impl.cpp candidate-cap
        // shape adopted).
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &sparams(100, 30, 45, 0));
        assert!(d.picked.is_empty());
        assert_eq!(
            d.evictable, 0,
            "an empty decision (no distribution evaluated)"
        );
        // Row 6 (n<8 pool floor): a 7-row pool is left alone.
        let mut rows: Vec<SlowChurnRow> = base_pool();
        rows.truncate(7);
        let d = slow_churn_pick(&mut rows, &base_params());
        assert!(d.picked.is_empty());
        // Row 7 (enabled=false all exempt): the BH_SLOW_PEER_CHURN=0
        // equivalent.
        let mut rows = base_pool();
        let mut p = base_params();
        p.enabled = false;
        let d = slow_churn_pick(&mut rows, &p);
        assert!(d.picked.is_empty());
        // Row 8 (frac scaling): the BH_SLOW_PEER_FRAC=50 shape — line =
        // 60 x 50% = 30 -> the below-median half (rates 10,20) narrows.
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &sparams(50, 30, 45, 50));
        assert_eq!(d.threshold, 30.0);
        assert_eq!(
            d.evictable, 2,
            "the line halved -> the evictable set narrows to below half the median"
        );
        assert_eq!(d.picked, vec![1, 2]);
        // Row 9 (K capped by k_pct): the default 10% x n=10 -> K=1.
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &sparams(100, 10, 45, 50));
        assert_eq!(d.picked, vec![1], "K = max(1, n x k%) clamped");
        // Row 9' (k_pct=0 floor 1): max(1, 0) = 1.
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &sparams(100, 0, 45, 50));
        assert_eq!(d.picked, vec![1], "the K floor of 1");
        // Row 10 (K capped by candidates): evictable 5, k 3, candidates
        // 2 -> 2.
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &sparams(100, 30, 45, 2));
        assert_eq!(d.picked, vec![1, 2], "K = min(evictable, k, candidates)");
        // Row 11 (ties pick non-interesting first): cuid 1/2 tie at
        // rate 10 (both below the line), cuid 1 interesting -> picked
        // later at equal slowness.
        let mut rows = base_pool();
        rows[0].interesting = true;
        rows[1].down_rate = 10.0; // ties cuid 1
        let d = slow_churn_pick(&mut rows, &sparams(100, 10, 45, 50));
        assert_eq!(
            d.picked,
            vec![2],
            "on a tie the non-interesting peer is picked first"
        );
        // A further tie -> cuid ascending (determinism).
        let mut rows = base_pool();
        rows[1].down_rate = 10.0; // cuid 1/2 tie, both interesting=false
        let d = slow_churn_pick(&mut rows, &sparams(100, 10, 45, 50));
        assert_eq!(d.picked, vec![1], "a further tie breaks by ascending cuid");
        // Row 12 (determinism): same input, same output (the whole sort
        // chain is stable).
        let mut a = base_pool();
        let mut b = base_pool();
        assert_eq!(
            slow_churn_pick(&mut a, &base_params()),
            slow_churn_pick(&mut b, &base_params())
        );
        // Constant provenance pinned.
        assert_eq!(SLOW_CHURN_MIN_POOL, 8, "the pool-floor gate");
        assert_eq!(
            SLOW_CHURN_INTERVAL,
            Duration::from_secs(30),
            "the evaluation cadence = the 30s window period"
        );
        assert_eq!(
            SLOW_CHURN_MARK_TTL,
            Duration::from_secs(300),
            "the mark consumption window"
        );
    }

    /// Rarity exemption decision table (slow_churn_pick direct drive —
    /// the base pool/parameters as in slow_churn_pick_decision_table:
    /// median=60, line=60, evictable cuid 1..5, K=3): sole connected
    /// holders not evicted (the next in line fills) / non-sole evicted
    /// as usual / the switch off (=0) ignores the flag, prior
    /// behaviour.
    #[test]
    fn slow_churn_rarity_exempt_table() {
        let base_pool = || -> Vec<SlowChurnRow> {
            (1..=10u64)
                .map(|cuid| srow(cuid, cuid as f64 * 10.0, 100, false))
                .collect()
        };
        let mut p = sparams(100, 30, 45, 50);
        p.rarity_exempt = true;
        // Row 1 (sole holder exempt): the worst row cuid 1 flagged sole
        // -> not evicted, [2,3,4] fills; evictable narrows (5 -> 4).
        let mut rows = base_pool();
        rows[0].sole_holder = true;
        let d = slow_churn_pick(&mut rows, &p);
        assert_eq!(
            d.picked,
            vec![2, 3, 4],
            "the sole holder exempted + next in line fills in"
        );
        assert_eq!(
            d.evictable, 4,
            "exempted rows never enter the evictable set"
        );
        // Row 2 (non-sole as usual): the switch on but no sole flag ->
        // the same verdict as before.
        let mut rows = base_pool();
        let d = slow_churn_pick(&mut rows, &p);
        assert_eq!(
            d.picked,
            vec![1, 2, 3],
            "non-unique rows are evicted as usual"
        );
        assert_eq!(d.evictable, 5);
        // Row 3 (=0 fallback): switch off + the sole flag present = the
        // flag ignored.
        let mut rows = base_pool();
        rows[0].sole_holder = true;
        let d = slow_churn_pick(&mut rows, &sparams(100, 30, 45, 50));
        assert_eq!(
            d.picked,
            vec![1, 2, 3],
            "switch off: marking ignored (bit-for-bit status quo)"
        );
        assert_eq!(d.evictable, 5);
    }

    /// Sole-holder predicate table (slow_churn_sole_holder with
    /// avail/completion/availability injected): advertised && unfinished
    /// && availability==1 -> true; a finished piece / majority held /
    /// the sole pieces all finished / a missing bitmap -> false.
    #[test]
    fn slow_churn_sole_holder_table() {
        // Bitmap: pieces 0/1 advertised, piece 2 not; piece 2 counts as
        // done (injected). (avail rows are bitmap-backed — literals
        // are written through the from_bools bridge.)
        let avail = crate::bitmap::PieceBitmap::from_bools(&[true, true, false]);
        let done = |g: u64| g == 2;
        // Piece 0 missing and uniquely held -> true.
        assert!(slow_churn_sole_holder(
            Some(&avail),
            &done,
            &|g| if g == 0 { 1 } else { 2 },
        ));
        // All missing pieces majority-held (availability 2) -> false.
        assert!(!slow_churn_sole_holder(Some(&avail), &done, &|_| 2));
        // The sole pieces are all finished -> false (finished pieces
        // give no exemption).
        assert!(!slow_churn_sole_holder(Some(&avail), &|_| true, &|_| 1));
        // A missing bitmap (a have-none peer) -> false.
        assert!(!slow_churn_sole_holder(None, &done, &|_| 1));
    }

    /// Slow-eviction mark TTL table (slow_evict_marked; the decision
    /// consumed at the leave arm's redial admission): no mark / a hit
    /// within the TTL / exactly a full window expires / a zero-age hit.
    #[test]
    fn slow_evict_marked_decision_table() {
        let t0 = t0();
        assert!(!slow_evict_marked(None, t0), "no mark = not a slow evict");
        assert!(slow_evict_marked(Some(t0), t0), "zero age hits");
        assert!(
            slow_evict_marked(Some(t0), t0 + SLOW_CHURN_MARK_TTL - secs(1)),
            "hit within the TTL (had_data forcing false falls to the 60s base gear)"
        );
        assert!(
            !slow_evict_marked(Some(t0), t0 + SLOW_CHURN_MARK_TTL),
            "expired at exactly 300s (strictly < TTL; an expired mark returns to the \
             regular redial path)"
        );
    }

    /// DHT announce tier decision table (dht_announce_cadence):
    /// registered in {49, 55, 65, 99, 100} x gate readings (the default
    /// = the outbound target 100 / the `BH_DHT_RAMP_MIN_PEERS=50`
    /// fallback) — the mid band must land in the ramp tier (30s); the
    /// fallback (=50) restores the libtorrent-verbatim behavior.
    #[test]
    fn dht_announce_cadence_decision_table() {
        let interval = secs(15 * 60);
        let ramp = Some(secs(30));
        // --- Default gate (= the peer_connections_target() reading
        // 100) ---
        for &registered in &[49usize, 55, 65, 99] {
            assert_eq!(
                dht_announce_cadence(registered, false, false, true, 100, ramp, interval),
                secs(30),
                "incomplete + registered={registered} < 100 -> the ramp-up tier 30s"
            );
        }
        // registered = 100 = the target met: not the ramp tier.
        assert_eq!(
            dht_announce_cadence(100, false, false, true, 100, ramp, interval),
            interval,
            "target met (registered = target) -> the regular 15min tier"
        );
        // Completed (seeding): conn_thin still enters the 1/3 tier
        // (supply refill), not the ramp tier (ramp = supply ramp-up for
        // unfinished downloads).
        assert_eq!(
            dht_announce_cadence(55, true, false, true, 100, ramp, interval),
            interval / 3,
            "completed + under target -> the 1/3 fast tier (not the ramp-up tier)"
        );
        // Peer vacuum (all faces zero connections) always enters the
        // 1/3 tier (an independent guard, gate-independent).
        assert_eq!(
            dht_announce_cadence(120, false, true, true, 100, ramp, interval),
            interval / 3,
            "a peer vacuum -> the 1/3 tier (an independent fallback gate)"
        );
        // Fast-tier switch off (BH_CONN_FILL_DHT=0): non-vacuum reverts
        // to the regular tier (conn_thin fails wholesale — the ramp
        // gate shares the same conn_thin face, the switch is not split).
        assert_eq!(
            dht_announce_cadence(55, false, false, false, 100, ramp, interval),
            interval,
            "the fast-tier switch off -> the regular tier"
        );
        // Ramp cadence env 0 fallback (BH_DHT_RAMP_INTERVAL_SECS=0 ->
        // None): the ramp tier degrades to the 1/3 tier (the existing
        // fallback kept).
        assert_eq!(
            dht_announce_cadence(55, false, false, true, 100, None, interval),
            interval / 3,
            "ramp=0 fallback -> the 1/3 tier"
        );
        // --- Fallback arm (BH_DHT_RAMP_MIN_PEERS=50, the
        // libtorrent-verbatim gate) ---
        for &registered in &[55usize, 65, 99] {
            assert_eq!(
                dht_announce_cadence(registered, false, false, true, 50, ramp, interval),
                interval,
                "fallback threshold 50: registered={registered} falls back to the regular tier (bit-for-bit old behavior)"
            );
        }
        // Under the fallback, 49 still enters the ramp tier (< 50, the
        // old rule holds).
        assert_eq!(
            dht_announce_cadence(49, false, false, true, 50, ramp, interval),
            secs(30),
            "fallback threshold 50: registered=49 -> the ramp-up tier (bit-for-bit old behavior)"
        );
    }
}
