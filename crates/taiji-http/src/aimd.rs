//! Per-source connection-count AIMD control — the connection-count decision
//! face for each task's sources.
//!
//! Growth/shrink rules (fully integer; the connection count is always
//! `u32`): start at the slow-start start
//! ([`AimdConfig::start_connections`]; spec baseline `min(2, cap)`, raised
//! to the user's explicit `--split` intent via [`AimdConfig::with_start`]).
//! An evaluation window (default [`EVAL_WINDOW`] 5s) aggregating gain >=
//! [`GAIN_THRESHOLD`] (10%) doubles the count (slow-start x2), capped at
//! the growth cap; gain < 10% stops growth (hold — no step-back; overshoot
//! is at most one doubling step). Congestion signals (connection reset /
//! server-side 429 throttling) trigger a multiplicative decrease with a
//! floor of 1, then a baseline reset — later windows rebuild the baseline
//! and growth can resume.
//!
//! Window protocol: window k runs on the connection count decided by
//! window k-1, so gain >= 10% means "the previous doubling was confirmed".
//! The first valid window has no baseline -> optimistic probe (establish a
//! baseline and double once); without probing there would never be gain
//! evidence to judge. Under per-connection bandwidth bounds, connections
//! converge on the gain-threshold point (= the cap) +/- 1.
//!
//! Input signals: bytes actually transferred inside a permit window (the
//! observation seam is `Permit::waited()`, flowing in via
//! `CoordinatorMsg::RateSample`). Rate-limiter-dominated windows (permit
//! wait share > 50%) and host-cap contention windows are excluded whole —
//! no gain evaluation, baseline preserved, never a decision. Only
//! server-side signatures ([`CongestionKind`]) trigger a decrease; local
//! limiter waits are never congestion.
//!
//! Recovery timing: baseline-absent windows — the cold-start first window
//! and the post-`Reset` rebuild — close at the short [`RECOVERY_WINDOW`]
//! (2s); a post-`Throttled` rebuild keeps the spec window (fast re-probing
//! of a throttling source is neither polite nor effective).
//!
//! SFTP seam: under the single-connection model AIMD tunes the pipeline
//! depth instead (domain 1..=[`SFTP_PIPELINE_DEPTH_MAX`]); the controller
//! is domain-agnostic — a future SftpTransport constructs
//! `AimdConfig { max_connections: SFTP_PIPELINE_DEPTH_MAX, .. }` to plug
//! in.
//!
//! The controller is owned exclusively by the ExtentCoordinator actor;
//! window closes are driven lazily by the RateSample stream and congestion
//! arrives via `CongestionSignal` messages. This module delivers the
//! decision and signal faces only, not the connection loop.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Evaluation window: the window-length floor — under lazy window closing
/// (observation-driven, same pattern as [`crate::rate`]) actual windows are >=
/// this value.
pub const EVAL_WINDOW: Duration = Duration::from_secs(5);

/// Gain threshold ("aggregate gain per window >= 10% -> x2").
pub const GAIN_THRESHOLD: f64 = 0.10;

/// Reset-level recovery window / cold-start establishment window: the
/// window-length floor for **baseline-absent windows**. Two cases share
/// this value:
///
/// - the baseline rebuild window after a [`CongestionKind::Reset`]
///   decrease (`in_recovery` set; a `Throttled` decrease always keeps the
///   spec window — fast re-probing of a throttling source is neither
///   polite nor effective);
/// - the **cold-start first window** (the startup establishment window is
///   isomorphic to the post-decrease rebuild window: baseline absent +
///   optimistic probe Grow, and the window length is the startup latency).
///   Under the 5s spec window the connection ramp spans several whole
///   windows on a real network before reaching the cap; a 2s establishment
///   window moves the first probe earlier.
///
/// Sample-size argument: 2s x starting connections x single-stream rate
/// still exceeds what judging the 10% gain threshold requires — this
/// window only rebuilds the baseline and probes, with no gain
/// re-judgment, so baseline quality is not hurt by the shorter window.
///
/// Once the establishment window closes (optimistic probe Grow, baseline
/// rebuilt), cadence falls back to the spec window [`EVAL_WINDOW`] — later
/// gain re-judgment windows keep their rhythm.
pub const RECOVERY_WINDOW: Duration = Duration::from_secs(2);

/// Whole-window exclusion threshold for permit-wait / cap-contention share
/// (share > 50% -> the window does not count toward gain evaluation).
const EXCLUDE_SHARE: f64 = 0.5;

/// SFTP pipeline depth domain cap (`--sftp-pipeline-depth` domain 1..32;
/// the SFTP seam constructs [`AimdConfig`] with it — see the module docs).
pub const SFTP_PIPELINE_DEPTH_MAX: u32 = 32;

/// Congestion signal kinds (the decrease triggers; **server-side
/// signatures only** — local rate-limiter waits are not congestion, go
/// through the whole-window exclusion of the observation seam, and must
/// never be reported here).
///
/// Graded decrease coefficients: `Reset` = a connection-level single death
/// (`floor(7n/8)`, lighter depth penalty + early recovery window);
/// `Throttled` = source-level throttling (the spec original `floor(3n/4)`,
/// spec recovery window). The decrease structure (multiplicative decrease +
/// floor 1 + baseline reset) is identical for both — only the parameters
/// differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionKind {
    /// Connection reset (peer RST / transport interruption). Wired in
    /// production: the transport error classifier
    /// ([`crate::error::HttpError::is_connection_reset`]) routes peer
    /// interruption signatures here via the coordinator's
    /// `report_congestion`. **Connect phase vs steady state**: zero-byte
    /// failures (connect-phase noise — first-wave connection races bursting
    /// the accept queue into RSTs) are not congestion; the verdict uses the
    /// failed extent's real written-byte watermark
    /// ([`crate::heartbeat::ExtentHeartbeat::written_bytes`]) so the
    /// decrease is not misfired by first-wave connection races.
    Reset,
    /// Server-side throttling signature (HTTP 429 and the like).
    Throttled,
}

impl CongestionKind {
    /// Denominator of the decrease coefficient (integer division):
    /// `Reset` = 8 (7n/8, a lighter penalty for a connection-level event);
    /// `Throttled` = 4 (3n/4, the spec original — a 429 is a source-level
    /// signal; depth is not reduced).
    fn decrease_divisor(self) -> u32 {
        match self {
            CongestionKind::Reset => 8,
            CongestionKind::Throttled => 4,
        }
    }

    /// Whether this kind enables the early recovery window
    /// ([`RECOVERY_WINDOW`]): only connection-level `Reset`; source-level
    /// `Throttled` keeps the spec-window re-probe rhythm.
    fn fast_recovery(self) -> bool {
        matches!(self, CongestionKind::Reset)
    }
}

/// One AIMD decision (a window close or a congestion event;
/// `from`/`to`/`n` are integer connection counts — for the SFTP face,
/// pipeline depths; the domain is agnostic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AimdDecision {
    /// Slow-start doubling confirmed (or first-window optimistic probe): `to = min(2*from, cap)`.
    Grow {
        /// Connection count before the decision.
        from: u32,
        /// Connection count after the decision (> from).
        to: u32,
    },
    /// Gain insufficient (< 10%) or already at cap: stop growing, hold.
    Hold {
        /// The held connection count.
        n: u32,
    },
    /// Congestion decrease: `to = max(1, floor(from*k))` with k per signal
    /// kind (graded: `Reset` = 7/8, `Throttled` = 3/4); the baseline resets
    /// (opening the recovery path).
    Decrease {
        /// Connection count before the decision.
        from: u32,
        /// Connection count after the decision (< from).
        to: u32,
    },
}

/// AIMD config (fixed once at task creation; `max_connections` domain
/// validation belongs to the option layer — `--max-connection-per-server`
/// 1..=16; the constructor only defends with a clamp >= 1, and the SFTP
/// seam constructs 32 legitimately).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AimdConfig {
    /// Growth cap: HTTP/FTP = `--max-connection-per-server`; SFTP (the
    /// seam) = the pipeline depth domain cap.
    pub max_connections: u32,
    /// Evaluation window (default [`EVAL_WINDOW`]; tests may shorten it).
    pub eval_window: Duration,
    /// Reset-level recovery window (default [`RECOVERY_WINDOW`], clamped <=
    /// `eval_window`): the window-length floor for the baseline rebuild
    /// window after a [`CongestionKind::Reset`] decrease — once that window
    /// closes, cadence falls back to `eval_window` (recovery timing, module
    /// docs).
    pub recovery_window: Duration,
    /// Slow-start starting point (initial connection count). Spec baseline
    /// = `min(2, cap)`; the user's explicit concurrency intent (`--split`)
    /// raises it via [`AimdConfig::with_start`] — the cross-validation
    /// reference (aria2) has no slow start and opens `min(split, ...)`
    /// connections immediately, so when the start sits below user intent
    /// the ramp amortization dominates short-task cost. Raising the start
    /// only changes where the ramp begins, not the adaptivity semantics of
    /// growth/decrease/convergence.
    pub start_connections: u32,
}

impl AimdConfig {
    /// Build from the growth cap (evaluation window defaults to
    /// [`EVAL_WINDOW`], recovery window to [`RECOVERY_WINDOW`]; defensive
    /// clamp of the cap >= 1 — a cap of 0 has nothing to tune, same
    /// convention as [`crate::perhost::HostCap::new`]; slow-start start =
    /// the spec baseline `min(2, cap)`).
    pub fn new(max_connections: u32) -> Self {
        let max = max_connections.max(1);
        AimdConfig {
            max_connections: max,
            eval_window: EVAL_WINDOW,
            recovery_window: RECOVERY_WINDOW.min(EVAL_WINDOW),
            start_connections: 2.min(max),
        }
    }

    /// Build from the growth cap + the user's explicit concurrency intent
    /// (`--split`): the slow-start start rises to
    /// `clamp(max(split, min(2, cap)), 1, cap)` — a split below the spec
    /// probe floor stays `min(2, cap)` (without probing there is never gain
    /// evidence to judge), a split above the cap clamps to the cap.
    pub fn with_start(max_connections: u32, split: u32) -> Self {
        let mut cfg = AimdConfig::new(max_connections);
        cfg.start_connections = split
            .max(cfg.start_connections)
            .min(cfg.max_connections)
            .max(1);
        cfg
    }
}

/// Single-source AIMD controller (pure decision logic; `Instant` is an
/// explicit parameter for testability — production passes
/// `Instant::now()`; owned by the coordinator actor, no shared locks).
#[derive(Debug)]
pub struct AimdController {
    max: u32,
    eval_window: Duration,
    recovery_window: Duration,
    /// Current connection count (the controlled variable; for the SFTP face, pipeline depth).
    n: u32,
    /// Whether slow start has reached steady state (read-only observation:
    /// set by the first `Hold` window-close decision — Hold means gain
    /// insufficient (< 10%, aggregate rate already ~90%+ of baseline) or at
    /// cap. Source of truth for the slow-start duration metric's endpoint;
    /// zero behavior change).
    settled: bool,
    /// Aggregate throughput baseline of the last **valid** window
    /// (bytes/s); `None` = pending establishment (first window or
    /// post-decrease rebuild).
    baseline_bps: Option<f64>,
    /// Open window start (`None` = the next observation opens one).
    window_open: Option<Instant>,
    /// Aggregated bytes of the open window.
    window_bytes: u64,
    /// Sum of permit waits in the open window (`Permit::waited()`).
    window_permit_waited: Duration,
    /// Sum of cap-contention waits in the open window (the per-host cap
    /// held by other tasks, observed by the connection driver side).
    window_cap_waited: Duration,
    /// Recovery mode: set after a `Reset` decrease — the baseline rebuild
    /// window closes at `recovery_window` (an early close = a faster
    /// recovery ramp); a rebuilt baseline (the `evaluate` establishment
    /// branch) clears it. A `Throttled` decrease always clears it (post-429
    /// re-probing keeps the spec-window rhythm; a Reset immediately
    /// followed by a 429 means the source-level signal takes over, also the
    /// spec window — last signal wins).
    in_recovery: bool,
    /// Whether a baseline has ever been established since task start (the
    /// flag behind the cold-start establishment window): `false` = first
    /// window (establishment window = `recovery_window`, isomorphic to the
    /// post-decrease rebuild window); once set, window-length selection
    /// returns to the existing semantics (`in_recovery` ->
    /// `recovery_window`, else `eval_window`). A post-decrease rebuild does
    /// **not** return to the cold-start bit — a `Throttled` rebuild keeps
    /// the spec window (politeness) and a `Reset` rebuild goes through
    /// `in_recovery` (recovery), each semantics unchanged.
    ever_established: bool,
}

impl AimdController {
    /// Build from config: initial connections = the slow-start start (spec
    /// baseline `min(2, cap)`; user intent raised via
    /// [`AimdConfig::with_start`]).
    pub fn new(config: AimdConfig) -> Self {
        let max = config.max_connections.max(1);
        AimdController {
            max,
            eval_window: config.eval_window,
            recovery_window: config.recovery_window.min(config.eval_window),
            n: config.start_connections.min(max).max(1),
            settled: false,
            baseline_bps: None,
            window_open: None,
            window_bytes: 0,
            window_permit_waited: Duration::ZERO,
            window_cap_waited: Duration::ZERO,
            in_recovery: false,
            ever_established: false,
        }
    }

    /// Current connection count (observation readout of the decision face).
    pub fn connections(&self) -> u32 {
        self.n
    }

    /// Whether slow start has reached steady state (true from the first
    /// `Hold` window-close decision; read-only — decision logic unchanged;
    /// the source of truth for the slow-start duration metric's endpoint).
    pub fn is_settled(&self) -> bool {
        self.settled
    }

    /// Record one write observation and close the window on schedule (lazy
    /// closing: observation-driven, actual window length >= the floor — the
    /// spec window [`AimdConfig::eval_window`], or the establishment window
    /// [`AimdConfig::recovery_window`] for baseline-absent windows (the
    /// cold-start first window / a Reset rebuild); the same pattern as
    /// [`crate::rate::SourceRateBook::observe_at`] — the rate face feeds
    /// the allocation formula, this face feeds gain evaluation, with
    /// independent window regimes).
    ///
    /// Returns the window-close decision; `None` = window not full / window
    /// excluded (the non-congestion factors) / first-window establishment
    /// (whose optimistic probe is expressed as [`AimdDecision::Grow`]).
    pub fn observe_at(
        &mut self,
        bytes: u64,
        permit_waited: Duration,
        cap_waited: Duration,
        now: Instant,
    ) -> Option<AimdDecision> {
        let Some(open) = self.window_open else {
            // The opening observation is a boundary marker: it physically
            // covers the **previous time span** (nothing transferred before
            // the stream / polluted windows already discarded) and does not
            // enter the new window — bytes and waits are zeroed together and
            // the new window starts from zero. Counting it into the new
            // window would inflate the window bps: the window length would
            // only cover the new span while bytes include residue from the
            // previous one (post-congestion pollution would raise the
            // rebuilt baseline).
            self.window_open = Some(now);
            self.window_bytes = 0;
            self.window_permit_waited = Duration::ZERO;
            self.window_cap_waited = Duration::ZERO;
            return None;
        };
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        self.window_permit_waited = self.window_permit_waited.saturating_add(permit_waited);
        self.window_cap_waited = self.window_cap_waited.saturating_add(cap_waited);
        let elapsed = now.saturating_duration_since(open);
        // Window-length floor (recovery timing + cold-start establishment):
        // baseline-absent windows close early at `recovery_window` — the
        // cold-start first window (`ever_established` false: startup
        // establishment and post-decrease rebuild are isomorphic, see the
        // constant docs) and recovery mode (`in_recovery`: a Reset rebuild;
        // Throttled clears it and stays on the spec window). With a baseline
        // present: the spec window (gain re-judgment rhythm identical to the
        // existing semantics).
        let threshold = if !self.ever_established || self.in_recovery {
            self.recovery_window
        } else {
            self.eval_window
        };
        if elapsed < threshold {
            return None;
        }
        // Close the window (excluded windows are consumed too — the window
        // is spent, just not evaluated).
        self.window_open = Some(now);
        let (win_bytes, win_permit, win_cap) = (
            self.window_bytes,
            self.window_permit_waited,
            self.window_cap_waited,
        );
        self.window_bytes = 0;
        self.window_permit_waited = Duration::ZERO;
        self.window_cap_waited = Duration::ZERO;
        self.evaluate(win_bytes, win_permit, win_cap, elapsed)
    }

    /// Congestion signal intake (the decrease trigger): multiplicative
    /// decrease immediately (the connections are already lost; waiting out
    /// the window is pointless), discard the in-flight window
    /// (congestion-polluted observations must not enter the baseline), and
    /// reset the baseline (later windows rebuild it -> gain re-judgment ->
    /// recovery).
    ///
    /// Recovery-path note: recovery = baseline reset (here) -> a recovery/
    /// spec-window close -> the `evaluate` establishment branch (baseline
    /// None) optimistically probing `min(2n, cap)` straight back to the cap
    /// — the loop is structurally sound. "No recovery" at cap 1 is the
    /// shadow of an empty probe space (1 -> 1 is always Hold), not a defect
    /// of this path.
    ///
    /// Graded parameters: the decrease coefficient is graded by signal kind
    /// — `Reset` (connection-level) `floor(7n/8)` + recovery mode set (an
    /// early rebuild window); `Throttled` (source-level 429) the spec
    /// original `floor(3n/4)` + spec window (recovery mode cleared — last
    /// signal wins: a Reset immediately followed by a 429 hands over to
    /// source-level throttling, no accelerated re-probe).
    pub fn note_congestion(&mut self, kind: CongestionKind, _now: Instant) -> AimdDecision {
        let from = self.n;
        // Integer floor(from*(d-1)/d): direct division avoids floats;
        // max(1, ..) is the floor. d = decrease_divisor(kind): Reset=8
        // (7n/8), Throttled=4 (3n/4).
        let d = kind.decrease_divisor();
        let to = (from * (d - 1) / d).max(1);
        self.n = to;
        self.baseline_bps = None;
        self.window_open = None;
        self.window_bytes = 0;
        self.window_permit_waited = Duration::ZERO;
        self.window_cap_waited = Duration::ZERO;
        self.in_recovery = kind.fast_recovery();
        AimdDecision::Decrease { from, to }
    }

    /// Window evaluation (the close path): the exclusion criteria run first
    /// (rate-limiter-dominated / cap-contention / zero-byte windows do not
    /// count); valid windows re-judge gain against the baseline. The
    /// baseline persists across excluded windows — "not counted" means not
    /// evaluated, not that the evaluation anchor is dropped.
    fn evaluate(
        &mut self,
        bytes: u64,
        permit_waited: Duration,
        cap_waited: Duration,
        elapsed: Duration,
    ) -> Option<AimdDecision> {
        let secs = elapsed.as_secs_f64();
        let conn_secs = secs * f64::from(self.n);
        let dominated = permit_waited.as_secs_f64() > EXCLUDE_SHARE * conn_secs
            || cap_waited.as_secs_f64() > EXCLUDE_SHARE * conn_secs;
        if dominated || bytes == 0 {
            return None;
        }
        let bps = bytes as f64 / secs;
        match self.baseline_bps {
            // First valid window: establish the baseline + optimistic probe
            // (window-protocol causality, see the module docs).
            // Establishment is also the end of recovery mode: the baseline
            // is rebuilt, so later windows return to the spec evaluation
            // window; the cold-start bit sets too (post-decrease rebuilds
            // now route via in_recovery; the cold-start short window serves
            // only the task's first window).
            None => {
                self.baseline_bps = Some(bps);
                self.in_recovery = false;
                self.ever_established = true;
                self.grow()
            }
            Some(base) => {
                let gain = bps / base - 1.0;
                if gain >= GAIN_THRESHOLD {
                    self.grow()
                } else {
                    Some(self.hold())
                }
            }
        }
    }

    /// Doubling probe: `min(2n, cap)`; no headroom at the cap -> Hold.
    ///
    /// Note on the gain criterion: it only has a verdict surface while the
    /// growth domain `[start, cap]` is non-empty — at cap 1,
    /// `candidate = min(2n, 1) = 1 = n` is always Hold and the criterion is
    /// never evaluated true. This function is unchanged; the "never
    /// satisfied" pathology lives in the cap clamping the verdict surface,
    /// not in the criterion.
    fn grow(&mut self) -> Option<AimdDecision> {
        let candidate = self.n.saturating_mul(2).min(self.max);
        if candidate > self.n {
            let from = self.n;
            self.n = candidate;
            Some(AimdDecision::Grow {
                from,
                to: candidate,
            })
        } else {
            Some(self.hold())
        }
    }

    fn hold(&mut self) -> AimdDecision {
        // Steady-state flag (the slow-start observation): Hold = gain
        // insufficient (< 10% — aggregate rate already ~90%+ of baseline)
        // or at cap. The decision itself is unchanged.
        self.settled = true;
        AimdDecision::Hold { n: self.n }
    }
}

/// Per-source AIMD ledger (owned by the coordinator actor; source
/// controllers are created lazily — the first observation/congestion
/// signal enrolls the source; config is shared from the same origin).
#[derive(Debug)]
pub struct AimdBook {
    config: AimdConfig,
    sources: BTreeMap<u32, AimdController>,
}

impl AimdBook {
    /// Build the ledger from the task-level AIMD config.
    pub fn new(config: AimdConfig) -> Self {
        AimdBook {
            config,
            sources: BTreeMap::new(),
        }
    }

    /// Current connections for the source (`None` = no AIMD state yet).
    /// Snapshot query face (the data source for metrics and the scale
    /// execution loop).
    pub fn connections(&self, source: u32) -> Option<u32> {
        self.sources.get(&source).map(AimdController::connections)
    }

    /// Snapshot of all sources (ascending source order).
    pub fn snapshot(&self) -> Vec<(u32, u32)> {
        self.sources
            .iter()
            .map(|(&s, c)| (s, c.connections()))
            .collect()
    }

    /// Whether any source has reached steady state (the endpoint test for
    /// the slow-start duration metric — true from the first `Hold`
    /// window-close decision; no sources / no AIMD state = false; an
    /// unsettled task is not sampled).
    pub fn settled_any(&self) -> bool {
        self.sources.values().any(AimdController::is_settled)
    }

    /// Record one source observation (passed through to the controller, lazy creation).
    pub fn observe_at(
        &mut self,
        source: u32,
        bytes: u64,
        permit_waited: Duration,
        cap_waited: Duration,
        now: Instant,
    ) -> Option<AimdDecision> {
        self.entry(source)
            .observe_at(bytes, permit_waited, cap_waited, now)
    }

    /// Source congestion signal (passed through, lazy creation — a
    /// connection that congests before any sample decreases from the
    /// slow-start start).
    pub fn note_congestion(
        &mut self,
        source: u32,
        kind: CongestionKind,
        now: Instant,
    ) -> AimdDecision {
        self.entry(source).note_congestion(kind, now)
    }

    fn entry(&mut self, source: u32) -> &mut AimdController {
        self.sources
            .entry(source)
            .or_insert_with(|| AimdController::new(self.config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic time base (same shape as rate.rs: explicit advancing, no real sleeps).
    struct Clock(Instant);
    impl Clock {
        fn new() -> Self {
            Clock(Instant::now())
        }
        fn tick(&mut self, d: Duration) -> Instant {
            self.0 += d;
            self.0
        }
    }

    const MIB: f64 = 1024.0 * 1024.0;

    /// Constant-rate source fixture: aggregate = min(n x per-connection,
    /// ceiling), scalable (the rate-limited low-throughput shape), plus
    /// in-window non-congestion wait injection points.
    #[derive(Clone)]
    struct Fixture {
        per_conn_bps: f64,
        ceiling_bps: f64,
        /// Aggregate override (`Some` = a fixed aggregate independent of n —
        /// exact byte control for gain-threshold boundary tests).
        fixed_agg: Option<f64>,
        /// Byte scale (rate/cap dominated windows: scarce permits -> collapsed throughput).
        byte_scale: f64,
        /// Permit wait carried per observation (rate-dominated window injection).
        permit_waited: Duration,
        /// Cap-contention wait carried per observation (cap-contention window injection).
        cap_waited: Duration,
    }

    impl Fixture {
        /// Healthy source: `per_conn_bps` per connection, server-side
        /// aggregate ceiling (non-congestive).
        fn healthy(per_conn_bps: f64, ceiling_bps: f64) -> Self {
            Fixture {
                per_conn_bps,
                ceiling_bps,
                fixed_agg: None,
                byte_scale: 1.0,
                permit_waited: Duration::ZERO,
                cap_waited: Duration::ZERO,
            }
        }

        /// Fixed-aggregate source (n-independent — exact throughput control for boundary tests).
        fn with_aggregate(agg_bps: f64) -> Self {
            Fixture {
                per_conn_bps: 0.0,
                ceiling_bps: f64::INFINITY,
                fixed_agg: Some(agg_bps),
                byte_scale: 1.0,
                permit_waited: Duration::ZERO,
                cap_waited: Duration::ZERO,
            }
        }

        /// Rate-dominated injection: the permit wait share set to 0.6 (> the
        /// 50% threshold), throughput scaled to 1/4 (scarce permits). The
        /// share spreads across connections via [`Fixture::waits_for`] — >
        /// 50% for any n.
        fn throttled(base: &Fixture, window: Duration) -> Self {
            Fixture {
                permit_waited: window.mul_f64(0.6),
                byte_scale: 0.25,
                ..base.clone()
            }
        }

        /// Cap-contention injection: the per-host cap held by other tasks
        /// (wait share injection 0.6).
        fn cap_contended(base: &Fixture, window: Duration) -> Self {
            Fixture {
                cap_waited: window.mul_f64(0.6),
                byte_scale: 0.25,
                ..base.clone()
            }
        }

        fn bytes_for(&self, n: u32, span: Duration) -> u64 {
            let agg = self
                .fixed_agg
                .unwrap_or_else(|| (f64::from(n) * self.per_conn_bps).min(self.ceiling_bps));
            (agg * self.byte_scale * span.as_secs_f64()) as u64
        }

        /// Waits carried per observation (spread over `n` connections):
        /// share = wait sum / (window x n) — with an even stream one
        /// observation closes exactly one window, so injection 0.6 means a
        /// window share of 0.6 (over the 50% threshold regardless of n).
        fn waits_for(&self, n: u32) -> (Duration, Duration) {
            (
                self.permit_waited.mul_f64(f64::from(n)),
                self.cap_waited.mul_f64(f64::from(n)),
            )
        }
    }

    /// Opening baseline observation (stream start / post-congestion-recovery
    /// boundary): carries zero bytes — the opening observation physically
    /// covers the previous time span (nothing before the stream / polluted
    /// windows discarded) and does not enter the new window (enforced by the
    /// opening arm of [`AimdController::observe_at`]: non-zero residue never
    /// enters either).
    fn prime(ctrl: &mut AimdController, clock: &mut Clock, window: Duration) {
        let t = clock.tick(window);
        ctrl.observe_at(0, Duration::ZERO, Duration::ZERO, t);
    }

    /// Feed one observation (advance one evaluation window): with an even
    /// stream the observation interval = the window length, and each
    /// observation closes exactly the previous window — observation bytes =
    /// A(n)xL cover the full window, so window bps = A exactly.
    fn feed(
        ctrl: &mut AimdController,
        clock: &mut Clock,
        fx: &Fixture,
        window: Duration,
    ) -> Option<AimdDecision> {
        let n = ctrl.connections();
        let t = clock.tick(window);
        let (pw, cw) = fx.waits_for(n);
        ctrl.observe_at(fx.bytes_for(n, window), pw, cw, t)
    }

    /// Run `windows` whole windows and collect close decisions (excluded
    /// windows do not appear in the vector — assert exclusion explicitly
    /// via [`feed`]'s return value).
    fn run_windows(
        ctrl: &mut AimdController,
        clock: &mut Clock,
        fx: &Fixture,
        window: Duration,
        windows: usize,
    ) -> Vec<AimdDecision> {
        (0..windows)
            .filter_map(|_| feed(ctrl, clock, fx, window))
            .collect()
    }

    // ---------------- Decision tables (initial / doubling / threshold / decrease) ----------------

    /// Initial connections = min(2, cap): cap 1 -> 1 (aria2's default
    /// single connection — the never-grows control shape); cap 2 -> 2;
    /// cap 8 -> 2.
    #[test]
    fn initial_connections_are_min_two_cap() {
        for (cap, want) in [(1u32, 1u32), (2, 2), (8, 2)] {
            let ctrl = AimdController::new(AimdConfig::new(cap));
            assert_eq!(ctrl.connections(), want, "cap={cap}");
        }
    }

    /// Start elevation (the user's explicit `--split` intent): cap 16 +
    /// split 16 -> start at cap (the no-slow-start alignment shape of the
    /// cross-validation reference); cap 16 + split 5 -> 5 (user intent
    /// beats the spec floor); cap 1 + split 16 -> 1 (cap clamp); cap 8 +
    /// split 1 -> 2 (the spec probe floor backstop — a single connection
    /// yields no gain evidence); a split over the cap clamps to the cap.
    #[test]
    fn with_start_raises_floor_to_user_split() {
        for (cap, split, want) in [
            (16u32, 16u32, 16u32),
            (16, 5, 5),
            (1, 16, 1),
            (8, 1, 2),
            (8, 99, 8),
        ] {
            let cfg = AimdConfig::with_start(cap, split);
            assert_eq!(cfg.start_connections, want, "cap={cap} split={split}");
            let ctrl = AimdController::new(cfg);
            assert_eq!(
                ctrl.connections(),
                want,
                "controller start cap={cap} split={split}"
            );
        }
        // new()'s baseline is unaffected by with_start (spec start min(2, cap)).
        assert_eq!(AimdConfig::new(16).start_connections, 2);
    }

    /// Doubling trajectory from an elevated start: start 8 (cap 16) -> the
    /// first valid window establishes + optimistic probe 8->16 -> Hold at
    /// cap — gain/convergence semantics are independent of the start (only
    /// the starting point changes).
    #[test]
    fn elevated_start_keeps_growth_semantics() {
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::with_start(16, 8));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let ds = run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 2);
        assert_eq!(
            ds,
            vec![
                AimdDecision::Grow { from: 8, to: 16 },
                AimdDecision::Hold { n: 16 },
            ]
        );
    }

    /// Slow-start doubling trajectory (1MiB/s per connection, non-binding
    /// ceiling): establishment-window optimistic probe 2->4 -> gain 100%
    /// confirms 4->8 -> Hold at cap; gain 0% holds from then on — zero
    /// connection drift in the tail (the decision face of the +/-1
    /// convergence criterion).
    #[test]
    fn slow_start_doubles_until_cap_then_holds() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, window);
        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 6);
        assert_eq!(
            ds,
            vec![
                AimdDecision::Grow { from: 2, to: 4 },
                AimdDecision::Grow { from: 4, to: 8 },
                AimdDecision::Hold { n: 8 },
                AimdDecision::Hold { n: 8 },
                AimdDecision::Hold { n: 8 },
                AimdDecision::Hold { n: 8 },
            ]
        );
        assert_eq!(ctrl.connections(), 8);
    }

    /// Slow-start settled observation flag: unset during the Grow phase;
    /// set by the first Hold window-close decision (at cap here; the
    /// gain-insufficient < 10% Hold has the same semantics). The AimdBook
    /// face judges identically (no sources / unsettled = false).
    #[test]
    fn settled_flag_flips_on_first_hold_decision() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        assert!(!ctrl.is_settled(), "start not settled (honest zero value)");
        assert!(
            !AimdBook::new(AimdConfig::new(8)).settled_any(),
            "empty ledger = false"
        );

        prime(&mut ctrl, &mut clock, window);
        // Establishment-window optimistic probe Grow: the settled flag is still false.
        assert_eq!(
            feed(&mut ctrl, &mut clock, &fx, window),
            Some(AimdDecision::Grow { from: 2, to: 4 })
        );
        assert!(!ctrl.is_settled(), "Grow decision does not set the flag");
        // A confirmed Grow (4->8) still does not set it; the Hold at cap
        // (8) is steady state — hold() is the single set point (the < 10%
        // Hold sets the same flag).
        assert_eq!(
            feed(&mut ctrl, &mut clock, &fx, window),
            Some(AimdDecision::Grow { from: 4, to: 8 })
        );
        assert!(!ctrl.is_settled(), "Grow decision does not set the flag");
        assert_eq!(
            feed(&mut ctrl, &mut clock, &fx, window),
            Some(AimdDecision::Hold { n: 8 })
        );
        assert!(
            ctrl.is_settled(),
            "the first Hold window-close decision is steady state"
        );
    }

    /// Deliberate one-shot latch: a decrease after the first Hold does not
    /// clear `settled`. The flag is the endpoint of the slow-start duration
    /// metric — task start to the first steady state, a one-time event
    /// (`http_task.rs` takes a single sample behind its `slowstart_done`
    /// guard). Pinned so a later "fix" does not turn it into a resettable
    /// state flag.
    #[test]
    fn settled_survives_decrease() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, window);
        // Grow(2->4) -> Grow(4->8) -> Hold(8) at cap: the first Hold settles.
        assert_eq!(
            run_windows(&mut ctrl, &mut clock, &fx, window, 3),
            vec![
                AimdDecision::Grow { from: 2, to: 4 },
                AimdDecision::Grow { from: 4, to: 8 },
                AimdDecision::Hold { n: 8 },
            ]
        );
        assert!(ctrl.is_settled());
        // Post-settle congestion (source-level 429): 8 -> floor(8*3/4) = 6.
        assert_eq!(
            ctrl.note_congestion(CongestionKind::Throttled, clock.tick(Duration::ZERO)),
            AimdDecision::Decrease { from: 8, to: 6 }
        );
        assert!(
            ctrl.is_settled(),
            "a decrease does not clear the one-shot settled latch"
        );
    }

    /// AimdBook settled face: a single source's first Hold makes
    /// settled_any true; false during the Grow phase (the ledger-level
    /// source of truth for the slowstart_settled snapshot field).
    #[test]
    fn book_settled_any_tracks_first_hold() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut book = AimdBook::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        // Source 0: open -> Grow(2->4) -> Grow(4->8) -> Hold(8) at cap.
        book.observe_at(0, 0, Duration::ZERO, Duration::ZERO, clock.tick(window));
        book.observe_at(
            0,
            fx.bytes_for(2, window),
            Duration::ZERO,
            Duration::ZERO,
            clock.tick(window),
        );
        assert!(!book.settled_any(), "not settled during the Grow phase");
        book.observe_at(
            0,
            fx.bytes_for(4, window),
            Duration::ZERO,
            Duration::ZERO,
            clock.tick(window),
        );
        assert!(
            !book.settled_any(),
            "confirmed-doubling Grow still not settled"
        );
        book.observe_at(
            0,
            fx.bytes_for(8, window),
            Duration::ZERO,
            Duration::ZERO,
            clock.tick(window),
        );
        assert!(
            book.settled_any(),
            "the first Hold window-close decision is steady state"
        );
    }

    /// Doubling cap clamp: at cap 3, 2->4 clamps to 2->3; cap 1 always
    /// Holds (the control baseline shape).
    #[test]
    fn doubling_clamps_at_cap() {
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(3));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let ds = run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 2);
        assert_eq!(
            ds,
            vec![
                AimdDecision::Grow { from: 2, to: 3 },
                AimdDecision::Hold { n: 3 },
            ]
        );

        let mut single = AimdController::new(AimdConfig::new(1));
        let mut clock = Clock::new();
        prime(&mut single, &mut clock, EVAL_WINDOW);
        let ds = run_windows(&mut single, &mut clock, &fx, EVAL_WINDOW, 2);
        assert_eq!(
            ds,
            vec![AimdDecision::Hold { n: 1 }, AimdDecision::Hold { n: 1 }]
        );
    }

    /// Gain threshold boundary: exactly 10% (>=) doubles; below 10% stops.
    /// The fixed-aggregate fixture provides exact byte control (baseline
    /// 2MiB/s; control windows +10% / +9%).
    #[test]
    fn gain_threshold_boundary() {
        let window = EVAL_WINDOW;
        let base_bps = 2.0 * MIB;
        let base = Fixture::with_aggregate(base_bps);
        let up10 = Fixture::with_aggregate(base_bps * 1.1);
        let up9 = Fixture::with_aggregate(base_bps * 1.09);

        // Establishment window -> optimistic Grow{2,4}; a +10% window
        // passes the threshold -> Grow{4,8}.
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, window);
        assert_eq!(
            run_windows(&mut ctrl, &mut clock, &base, window, 1),
            vec![AimdDecision::Grow { from: 2, to: 4 }]
        );
        assert_eq!(
            run_windows(&mut ctrl, &mut clock, &up10, window, 1),
            vec![AimdDecision::Grow { from: 4, to: 8 }],
            "exactly 10% gain passes the threshold (>=)"
        );

        // A +9% window misses the threshold -> Hold.
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, window);
        let _ = run_windows(&mut ctrl, &mut clock, &base, window, 1);
        assert_eq!(
            run_windows(&mut ctrl, &mut clock, &up9, window, 1),
            vec![AimdDecision::Hold { n: 4 }],
            "9% gain stops growth"
        );
    }

    // ---------------- Decrease triggers / recovery path ----------------

    /// Multiplicative decrease table, Throttled (source-level 429): keeps
    /// the spec original max(1, floor(n*3/4)) — 16->12, 12->9, 9->6, 6->4,
    /// 4->3, 3->2, 2->1, 1->1 (floor).
    #[test]
    fn multiplicative_decrease_decision_table_throttled() {
        let want = [
            (16u32, 12u32),
            (12, 9),
            (9, 6),
            (6, 4),
            (4, 3),
            (3, 2),
            (2, 1),
            (1, 1),
        ];
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let fx = Fixture::healthy(MIB, 1.0e9);
        assert_eq!(
            run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 3),
            vec![
                AimdDecision::Grow { from: 2, to: 4 },
                AimdDecision::Grow { from: 4, to: 8 },
                AimdDecision::Grow { from: 8, to: 16 },
            ],
            "slow start to cap"
        );
        for (from, to) in want {
            let d = ctrl.note_congestion(CongestionKind::Throttled, Instant::now());
            assert_eq!(d, AimdDecision::Decrease { from, to }, "throttled: {from}");
            assert_eq!(ctrl.connections(), to);
        }
    }

    /// Multiplicative decrease table, Reset (connection-level RST): the
    /// lighter coefficient max(1, floor(n*7/8)) — 16->14, 14->12, 12->10,
    /// 10->8, 8->7, 7->6, 6->5, 5->4, 4->3, 3->2, 2->1, 1->1 (floor).
    /// Rationale: one dead connection of 16 (-6% capacity) is not
    /// source-level congestion evidence, and 0.75 over-penalizes depth
    /// (amplified end-to-end under injected doses, see the module docs).
    #[test]
    fn multiplicative_decrease_decision_table_reset() {
        let want = [
            (16u32, 14u32),
            (14, 12),
            (12, 10),
            (10, 8),
            (8, 7),
            (7, 6),
            (6, 5),
            (5, 4),
            (4, 3),
            (3, 2),
            (2, 1),
            (1, 1),
        ];
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let fx = Fixture::healthy(MIB, 1.0e9);
        assert_eq!(
            run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 3),
            vec![
                AimdDecision::Grow { from: 2, to: 4 },
                AimdDecision::Grow { from: 4, to: 8 },
                AimdDecision::Grow { from: 8, to: 16 },
            ],
            "slow start to cap"
        );
        for (from, to) in want {
            let d = ctrl.note_congestion(CongestionKind::Reset, Instant::now());
            assert_eq!(d, AimdDecision::Decrease { from, to }, "reset: {from}");
            assert_eq!(ctrl.connections(), to);
        }
    }

    /// Decrease trigger + recovery path: converge at cap 8 -> congestion ->
    /// Decrease{8,7} (Reset 7/8) -> baseline reset -> an establishment-
    /// window optimistic probe Grow{7,8} -> gain confirms, Hold{8}
    /// stabilizes the tail — connections return to the pre-decrease level
    /// (the recovery loop). Note: this test feeds windows at the spec
    /// rhythm (5s); the short recovery-window close is pinned separately by
    /// [`reset_recovery_window_shortens_rebuild`].
    #[test]
    fn decrease_then_recovery_returns_to_converged_level() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();

        // Converge to 8 (same trajectory as slow_start).
        prime(&mut ctrl, &mut clock, window);
        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 3);
        assert_eq!(ds[0], AimdDecision::Grow { from: 2, to: 4 });
        assert_eq!(ds[1], AimdDecision::Grow { from: 4, to: 8 });
        assert_eq!(ctrl.connections(), 8);

        // Congestion (connection reset): decrease immediately, not at a window boundary.
        let d = ctrl.note_congestion(CongestionKind::Reset, clock.tick(Duration::ZERO));
        assert_eq!(d, AimdDecision::Decrease { from: 8, to: 7 });
        assert_eq!(ctrl.connections(), 7);

        // Recovery: the post-decrease window rebuilds the baseline (decision
        // = optimistic probe Grow{7,8}); gain then confirms -> Hold{8} at
        // cap stabilizes the tail.
        prime(&mut ctrl, &mut clock, window); // boundary observation after the polluted window is discarded
        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 4);
        assert_eq!(
            ds,
            vec![
                AimdDecision::Grow { from: 7, to: 8 },
                AimdDecision::Hold { n: 8 },
                AimdDecision::Hold { n: 8 },
                AimdDecision::Hold { n: 8 },
            ],
            "recovery path: baseline rebuild -> probe back to cap -> stable"
        );
        assert_eq!(ctrl.connections(), 8);
    }

    /// Congestion discards the in-flight window: observations from the
    /// first half of a congested window must not leak into the post-decrease
    /// baseline — the first post-decrease window runs "establishment"
    /// (optimistic Grow), not a gain re-judgment against a polluted
    /// baseline.
    #[test]
    fn congestion_discards_in_flight_window() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();

        // First window establishes + probes (n=4); then feed the first
        // observation of the next window (in flight, half a window, below
        // the boundary — no close).
        prime(&mut ctrl, &mut clock, window);
        let _ = run_windows(&mut ctrl, &mut clock, &fx, window, 1);
        assert_eq!(ctrl.connections(), 4);
        let n = ctrl.connections();
        let t = clock.tick(window / 2);
        let _ = ctrl.observe_at(
            fx.bytes_for(n, window / 2),
            Duration::ZERO,
            Duration::ZERO,
            t,
        );

        // Mid-window congestion: the in-flight window and the baseline are discarded together.
        let d = ctrl.note_congestion(CongestionKind::Throttled, clock.tick(Duration::ZERO));
        assert_eq!(d, AimdDecision::Decrease { from: 4, to: 3 });

        // First post-decrease window = establishment (a leaked polluted
        // observation would distort the baseline -> decision drift).
        prime(&mut ctrl, &mut clock, window); // boundary observation after the polluted window is discarded
        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 3);
        assert_eq!(
            ds,
            vec![
                AimdDecision::Grow { from: 3, to: 6 },
                AimdDecision::Grow { from: 6, to: 8 },
                AimdDecision::Hold { n: 8 },
            ],
            "baseline rebuild face: the first post-decrease window probes \
             optimistically, polluted observations never enter the ledger"
        );
    }

    // ---------------- Recovery timing ----------------

    /// The baseline rebuild window after a Reset decrease comes early: in
    /// recovery mode the window-length floor is [`RECOVERY_WINDOW`] (2s) —
    /// the first post-decrease window closes at 2s and yields the
    /// optimistic probe Grow (straight back to cap); recovery latency =
    /// window length. Once the baseline is rebuilt, cadence falls back to
    /// the spec window (2s beats no longer close; 5s beats do).
    #[test]
    fn reset_recovery_window_shortens_rebuild() {
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();

        // Converge at cap 16.
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let _ = run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 3);
        assert_eq!(ctrl.connections(), 16);

        // Reset decrease (7/8) -> recovery mode.
        let d = ctrl.note_congestion(CongestionKind::Reset, clock.tick(Duration::ZERO));
        assert_eq!(d, AimdDecision::Decrease { from: 16, to: 14 });

        // Post-decrease 2s beat: the window hit the recovery floor -> close
        // + an establishment-arm optimistic probe back to cap (under the
        // spec window this beat would not close — 2s < 5s; the earlier
        // recovery ramp is the point).
        prime(&mut ctrl, &mut clock, RECOVERY_WINDOW); // window-opening boundary observation
        let d = feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW);
        assert_eq!(
            d,
            Some(AimdDecision::Grow { from: 14, to: 16 }),
            "recovery window closes at 2s: optimistic probe straight back to cap \
             (no decision on this beat under the 5s window)"
        );

        // Baseline rebuilt -> recovery mode ends: 2s beats stop closing
        // (spec rhythm); the 5s beat closes -> Hold at cap.
        let d = feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW);
        assert_eq!(
            d, None,
            "after recovery mode ends a 2s beat does not close (spec window 5s)"
        );
        let d = feed(&mut ctrl, &mut clock, &fx, EVAL_WINDOW);
        assert_eq!(d, Some(AimdDecision::Hold { n: 16 }));
    }

    /// Throttled (source-level 429) does not come early: the post-decrease
    /// rebuild window keeps the spec evaluation window — a 2s beat does not
    /// close, a 5s beat does (no accelerated re-probe of a throttling
    /// source).
    #[test]
    fn throttled_keeps_full_eval_window_for_rebuild() {
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();

        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let _ = run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 3);
        assert_eq!(ctrl.connections(), 16);

        let d = ctrl.note_congestion(CongestionKind::Throttled, clock.tick(Duration::ZERO));
        assert_eq!(d, AimdDecision::Decrease { from: 16, to: 12 });

        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let d = feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW);
        assert_eq!(
            d, None,
            "Throttled rebuild window does not come early: no decision on the 2s beat"
        );
        // Complete to 5s (2s+3s since opening): close -> optimistic probe Grow{12,16}.
        let d = feed(&mut ctrl, &mut clock, &fx, EVAL_WINDOW - RECOVERY_WINDOW);
        assert_eq!(
            d,
            Some(AimdDecision::Grow { from: 12, to: 16 }),
            "after the spec-window close the probe returns to cap as usual"
        );
    }

    /// Mixed signals, last wins: a Reset immediately followed by a
    /// Throttled = source-level throttling takes over — recovery mode
    /// clears (rebuild on the spec window); a Throttled followed by a Reset
    /// sets it (the connection level takes over, rebuild comes early).
    /// Decrease coefficients are independent per signal (no residual state
    /// across consecutive decreases).
    #[test]
    fn mixed_signals_last_signal_wins_recovery_mode() {
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let _ = run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 3);
        assert_eq!(ctrl.connections(), 16);

        // Reset (16->14) -> Throttled (14->floor(14*3/4)=10): Throttled
        // clears recovery mode -> rebuild window = spec window (a 2s beat
        // does not close).
        let _ = ctrl.note_congestion(CongestionKind::Reset, clock.tick(Duration::ZERO));
        let d = ctrl.note_congestion(CongestionKind::Throttled, clock.tick(Duration::ZERO));
        assert_eq!(d, AimdDecision::Decrease { from: 14, to: 10 });
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        assert_eq!(
            feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW),
            None,
            "last signal Throttled: rebuild does not come early"
        );

        // Throttled (10->7) -> Reset (7->6): recovery mode set -> the 2s beat closes.
        let _ = ctrl.note_congestion(CongestionKind::Throttled, clock.tick(Duration::ZERO));
        let d = ctrl.note_congestion(CongestionKind::Reset, clock.tick(Duration::ZERO));
        assert_eq!(d, AimdDecision::Decrease { from: 7, to: 6 });
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        assert_eq!(
            feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW),
            Some(AimdDecision::Grow { from: 6, to: 12 }),
            "last signal Reset: rebuild window comes early, optimistic probe 6->12"
        );
    }

    /// No congestion = cold-start establishment window + spec-window
    /// rhythm: the baseline-absent first window closes at the establishment
    /// window ([`RECOVERY_WINDOW`] 2s) — startup establishment is
    /// isomorphic to the post-decrease rebuild (establish + optimistic
    /// probe; window length = startup latency); once a baseline exists, 2s
    /// beats never close — later gain re-judgments only appear on >= 5s
    /// beats (spec rhythm identical to the existing semantics).
    #[test]
    fn cold_start_window_then_spec_window_cadence() {
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);

        // Cold-start first window: the 2s beat closes -> an establishment-
        // arm optimistic probe (under the 5s spec window it would not — the
        // cold-start short window is the point).
        assert_eq!(
            feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW),
            Some(AimdDecision::Grow { from: 2, to: 4 }),
            "baseline-absent first window closes at 2s (establish + optimistic probe)"
        );
        // Baseline present: two 2s beats (4s < 5s), zero decisions — spec rhythm.
        assert_eq!(feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW), None);
        assert_eq!(feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW), None);
        // 6s since the last close (2+2+2): close -> gain re-judgment (doubling confirmed).
        assert_eq!(
            feed(&mut ctrl, &mut clock, &fx, RECOVERY_WINDOW),
            Some(AimdDecision::Grow { from: 4, to: 8 })
        );
    }

    /// Recovery window config: `recovery_window` clamps <= `eval_window`
    /// (configuration may only make recovery earlier, never later than the
    /// spec window — later would covertly prolong recovery, against the
    /// direction); explicit equality disables the early-recovery face (the
    /// fallback shape).
    #[test]
    fn recovery_window_clamps_to_eval_window() {
        let mut cfg = AimdConfig::new(16);
        cfg.recovery_window = EVAL_WINDOW * 2; // out of range (> eval_window)
        let ctrl = AimdController::new(cfg);
        assert_eq!(
            ctrl.recovery_window, EVAL_WINDOW,
            "clamped to the spec window"
        );
    }

    /// Rate-dominated windows are excluded whole: share > 50% -> no
    /// decision (`None` — counting them would yield a Hold), connections
    /// unmoved, and **no decrease** (limiter waits are not congestion); the
    /// baseline persists — the first valid window after an excluded one
    /// re-judges against the old baseline (Hold, not an establishment
    /// Grow).
    #[test]
    fn throttle_dominated_windows_are_excluded_without_penalty() {
        let window = EVAL_WINDOW;
        // Ceiling 2MiB/s: A(n>=2) is always 2MiB/s — valid-window gain is
        // always <= 0% (the decision face can distinguish Hold / None /
        // Grow).
        let fx = Fixture::healthy(MIB, 2.0 * MIB);
        let dom = Fixture::throttled(&fx, window);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();

        // W1 valid: establish + probe; W2 valid: gain 0% (the ceiling is
        // saturated by 2 connections) -> Hold{4}.
        prime(&mut ctrl, &mut clock, window);
        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 2);
        assert_eq!(ds[0], AimdDecision::Grow { from: 2, to: 4 });
        assert_eq!(ds[1], AimdDecision::Hold { n: 4 });

        // W3 rate-dominated (low throughput + high wait share): excluded
        // whole (None) — neither a Hold nor a decrease.
        let d = feed(&mut ctrl, &mut clock, &dom, window);
        assert_eq!(
            d, None,
            "excluded window yields no decision \
             (bytes=1/4 non-zero — exclusion via the wait-share branch)"
        );
        assert_eq!(
            ctrl.connections(),
            4,
            "excluded window does not move the connection count"
        );

        // W4 valid: the baseline persists (W2's 2MiB/s) -> gain 0% -> Hold
        // — if excluded windows dropped the baseline this would be an
        // optimistic establishment Grow{4,8}.
        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 1);
        assert_eq!(
            ds,
            vec![AimdDecision::Hold { n: 4 }],
            "the baseline persists across excluded windows"
        );
    }

    /// An excluded window must not establish the baseline: a rate-dominated
    /// first window -> None (no baseline); only a later valid window
    /// establishes and probes.
    #[test]
    fn dominated_first_window_does_not_establish_baseline() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 1.0e9);
        let dom = Fixture::throttled(&fx, window);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, window);

        let d = feed(&mut ctrl, &mut clock, &dom, window);
        assert_eq!(
            d, None,
            "a dominated window does not establish the baseline"
        );
        assert_eq!(ctrl.connections(), 2, "no establishment, no probe");

        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 1);
        assert_eq!(
            ds,
            vec![AimdDecision::Grow { from: 2, to: 4 }],
            "only the first valid window establishes"
        );
    }

    /// Cap-contention windows are excluded the same way: the per-host cap
    /// held by other tasks (wait share > 50%) -> no decision, connections
    /// unmoved.
    #[test]
    fn cap_contention_windows_are_excluded() {
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 2.0 * MIB);
        let contended = Fixture::cap_contended(&fx, window);
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, window);

        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 2);
        assert_eq!(ds[0], AimdDecision::Grow { from: 2, to: 4 });
        assert_eq!(ds[1], AimdDecision::Hold { n: 4 });

        let d = feed(&mut ctrl, &mut clock, &contended, window);
        assert_eq!(d, None, "cap-contention window excluded whole");
        assert_eq!(ctrl.connections(), 4);
    }

    /// Zero-byte windows neither establish nor evaluate (stalled
    /// observations belong to the stall face by division of labor).
    #[test]
    fn zero_byte_window_yields_no_decision() {
        let mut ctrl = AimdController::new(AimdConfig::new(8));
        let mut clock = Clock::new();
        let window = EVAL_WINDOW;
        let t = clock.tick(window);
        let d = ctrl.observe_at(0, Duration::ZERO, Duration::ZERO, t);
        assert!(d.is_none(), "window-open zero bytes");
        let t = clock.tick(window);
        let d = ctrl.observe_at(0, Duration::ZERO, Duration::ZERO, t);
        assert!(
            d.is_none(),
            "window-close zero bytes: no evaluation, no establishment"
        );
        assert_eq!(ctrl.connections(), 2);
    }

    /// Opening observations do not count into the new window (the boundary
    /// marker convention): residue from the previous span carried by the
    /// opening observation (the post-congestion-recovery shape) must not
    /// leak into the first evaluation window — if it did, the established
    /// baseline would be inflated by the residue and later valid windows'
    /// gain re-judgments would drift (a real 1MiB/s source inflated to a
    /// 2MiB/s baseline by 1MiB of residue turns a +10% gain window into a
    /// misjudged Hold).
    #[test]
    fn opening_observation_bytes_do_not_leak_into_first_window() {
        let window = EVAL_WINDOW;
        let mut ctrl = AimdController::new(AimdConfig::new(16));
        let mut clock = Clock::new();

        // The opening observation carries 1MiB of residue (physical
        // coverage of the pollution span, not this window's content).
        let t = clock.tick(window);
        let d = ctrl.observe_at(MIB as u64, Duration::ZERO, Duration::ZERO, t);
        assert!(
            d.is_none(),
            "the opening observation does not close a window"
        );

        // Establishment window exactly 1MiB (leaked residue -> a 2MiB/s
        // baseline) -> optimistic probe.
        let ds = run_windows(
            &mut ctrl,
            &mut clock,
            &Fixture::with_aggregate(MIB),
            window,
            1,
        );
        assert_eq!(ds, vec![AimdDecision::Grow { from: 2, to: 4 }]);

        // Gain re-judgment: a real +10% window -> doubling (with leaked
        // residue the baseline is 2MiB/s, so -45% here -> a misjudged
        // Hold).
        let ds = run_windows(
            &mut ctrl,
            &mut clock,
            &Fixture::with_aggregate(MIB * 1.1),
            window,
            1,
        );
        assert_eq!(
            ds,
            vec![AimdDecision::Grow { from: 4, to: 8 }],
            "opening-observation residue must not inflate the established baseline"
        );
    }

    // ---------------- Convergence + aggregate throughput comparison ----------------

    /// Convergence (1MiB/s per connection, non-binding server ceiling, cap
    /// 8): connections converge on the gain-threshold point (under
    /// per-connection rate caps gain stays >= 10% up to the cap -> the
    /// threshold point = cap) +/- 1 — the last 8 windows all read exactly 8
    /// (zero drift).
    #[test]
    fn convergence_to_gain_gate_within_one() {
        const CAP: u32 = 8;
        const TAIL: usize = 8;
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 100.0 * MIB); // non-binding ceiling
        let mut ctrl = AimdController::new(AimdConfig::new(CAP));
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, window);

        let ds = run_windows(&mut ctrl, &mut clock, &fx, window, 16);
        let tail: Vec<u32> = ds[ds.len() - TAIL..]
            .iter()
            .map(|d| match *d {
                AimdDecision::Grow { to: n, .. }
                | AimdDecision::Hold { n }
                | AimdDecision::Decrease { to: n, .. } => n,
            })
            .collect();
        let lo = tail.iter().min().unwrap_or_else(|| panic!("tail empty"));
        let hi = tail.iter().max().unwrap_or_else(|| panic!("tail empty"));
        assert_eq!(
            (lo, hi),
            (&CAP, &CAP),
            "the last {TAIL} windows converge on the gain-threshold point \
             +/- 1 (actual drift {lo}..{hi}): {ds:?}"
        );
        assert_eq!(ctrl.connections(), CAP);
    }

    /// Aggregate throughput comparison: under the same fixture, the window
    /// aggregate of AIMD's converged connection count n >= the
    /// single-connection baseline x n x 0.7; the control is cap 1 (aria2's
    /// default `--max-connection-per-server 1`, the single-connection
    /// shape). The multi-connection comparison: AIMD's aggregate is
    /// strictly above the single connection (coordination overhead within
    /// the 30% tolerance).
    #[test]
    fn aggregate_throughput_at_convergence_beats_single_connection_baseline() {
        const CAP: u32 = 8;
        let window = EVAL_WINDOW;
        let fx = Fixture::healthy(MIB, 100.0 * MIB);
        let mut clock = Clock::new();

        // Control: cap 1 (single connection).
        let mut single = AimdController::new(AimdConfig::new(1));
        prime(&mut single, &mut clock, window);
        let single_ds = run_windows(&mut single, &mut clock, &fx, window, 16);
        assert!(
            single_ds
                .iter()
                .all(|d| matches!(d, AimdDecision::Hold { n: 1 })),
            "single-connection control always Holds"
        );
        let single_window_bytes = fx.bytes_for(1, window);

        // AIMD: converges at cap 8.
        let mut aimd = AimdController::new(AimdConfig::new(CAP));
        prime(&mut aimd, &mut clock, window);
        let _ = run_windows(&mut aimd, &mut clock, &fx, window, 16);
        let n = aimd.connections();
        assert_eq!(n, CAP);
        let aimd_window_bytes = fx.bytes_for(n, window);

        // Aggregate >= single x n x 0.7 (no coordination overhead in this
        // fixture: n*R >= 0.7*n*R trivially).
        assert!(
            aimd_window_bytes as f64 >= single_window_bytes as f64 * f64::from(n) * 0.7,
            "aggregate {aimd_window_bytes} < single connection {single_window_bytes} x {n} x 0.7"
        );
        // Multi-connection comparison: AIMD's aggregate is strictly above
        // single (the direction face of adaptivity).
        assert!(
            aimd_window_bytes > single_window_bytes,
            "multi-connection aggregate must beat single connection: \
             {aimd_window_bytes} vs {single_window_bytes}"
        );
    }

    // ---------------- SFTP parameter slot (seam smoke) ----------------

    /// SFTP depth domain (the parameter slot of the SFTP special case): the
    /// same controller built with the `SFTP_PIPELINE_DEPTH_MAX` cap serves
    /// the depth domain — doubling to 32, decrease 32->28 (the seam proof
    /// of domain agnosticism; the SFTP transport itself is out of scope
    /// here).
    #[test]
    fn sftp_pipeline_depth_domain_seam() {
        let mut ctrl = AimdController::new(AimdConfig::new(SFTP_PIPELINE_DEPTH_MAX));
        assert_eq!(ctrl.connections(), 2, "min(2, 32)");
        let fx = Fixture::healthy(MIB, 1.0e9);
        let mut clock = Clock::new();
        prime(&mut ctrl, &mut clock, EVAL_WINDOW);
        let _ = run_windows(&mut ctrl, &mut clock, &fx, EVAL_WINDOW, 5);
        assert_eq!(ctrl.connections(), 32, "doubling chain 2->4->8->16->32");
        let d = ctrl.note_congestion(CongestionKind::Reset, Instant::now());
        assert_eq!(
            d,
            AimdDecision::Decrease { from: 32, to: 28 },
            "floor(32x7/8) (Reset-level coefficient)"
        );
    }

    // ---------------- AimdBook (per-source ledger) ----------------

    /// Ledger lazy creation and source isolation: independent
    /// growth/decrease never cross-talk; snapshots in ascending source
    /// order.
    #[test]
    fn book_per_source_isolation_and_snapshot() {
        let mut book = AimdBook::new(AimdConfig::new(8));
        assert_eq!(book.connections(0), None, "source with no state");
        assert!(book.snapshot().is_empty());

        let mut clock = Clock::new();
        let fx = Fixture::healthy(MIB, 1.0e9);
        // Source 7 enrolled first (out-of-order key), source 1 after: an
        // opening baseline + 4 windows (2->4->8->Hold tail).
        let open = clock.tick(EVAL_WINDOW);
        book.observe_at(7, 0, Duration::ZERO, Duration::ZERO, open);
        for _ in 0..4 {
            let n = book.connections(7).unwrap_or_else(|| panic!("src7"));
            let t = clock.tick(EVAL_WINDOW);
            book.observe_at(
                7,
                fx.bytes_for(n, EVAL_WINDOW),
                Duration::ZERO,
                Duration::ZERO,
                t,
            );
        }
        let d = book.note_congestion(1, CongestionKind::Reset, clock.tick(Duration::ZERO));
        assert_eq!(
            d,
            AimdDecision::Decrease { from: 2, to: 1 },
            "a sample-less source decreases from the slow-start start"
        );
        assert_eq!(
            book.snapshot(),
            vec![(1, 1), (7, 8)],
            "snapshot sources ascending; per-source ledger isolation \
             (7 doubled twice, 1 decreased independently)"
        );
    }
}
