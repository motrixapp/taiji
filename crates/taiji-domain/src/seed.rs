//! Seeding operating policy: the stop semantics of seed-ratio / seed-time
//! / bt-stop-timeout, plus the bt-detach-seed-only seed-only predicate.
//!
//! A faithful transcription of the aria2 criteria machinery:
//! [`SeedCriteria`] (evaluate/reset), the share-ratio and time criteria, a
//! union, the [`SeedCheck`] start gate (timing/evaluation begins at
//! download completion), the 1s-tick [`BtStopTimeoutWatch`], a minimal
//! 10s-window [`SessionSpeedCalc`], and the [`seed_only_detached`]
//! predicate. Upstream anchor mapping: docs/design/domain-policies.md.
//!
//! Boundary note: the seed-only concurrency accounting (seed-only does not
//! occupy a --max-concurrent-downloads slot) lands with the session queue
//! wiring; this module delivers the predicate and the engine return path
//! (Detached: exit on completion, no seeding residency).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Seeding stop criterion (aria2 `SeedCriteria.h`).
pub trait SeedCriteria: Send {
    /// Criterion satisfied (seeding may end).
    fn evaluate(&mut self) -> bool;
    /// Resets state (TimeSeed restarts its timer; ShareRatio is stateless
    /// — aria2's reset is empty, `ShareRatioSeedCriteria.cc`).
    fn reset(&mut self);
}

/// Ratio evaluation readout source (the minimal equivalent of aria2's
/// pieceStorage / netStat / btRuntime injection surface; the engine side
/// implements it with atomic counters, tests with synthetic injection).
pub trait SeedStats: Send + Sync {
    /// Completed length (`PieceStorage::getCompletedLength`, bytes).
    fn completed_length(&self) -> u64;
    /// Session upload length (`NetStat::getSessionUploadLength`;
    /// piece-payload accounting, counted at the `BtPieceMessage.cc`
    /// upload point).
    fn session_upload_length(&self) -> u64;
    /// Pre-session cumulative upload (`BtRuntime::getUploadLengthAtStartup`;
    /// the .aria2 control file's `uploadLength` <->
    /// `torrent_progress.upload_at_startup`, `DefaultBtProgressInfoFile.cc`).
    fn upload_length_at_startup(&self) -> u64;
}

/// seed-ratio seeding stop criterion (`ShareRatioSeedCriteria.cc`).
pub struct ShareRatioSeedCriteria {
    ratio: f64,
    stats: std::sync::Arc<dyn SeedStats>,
}

impl ShareRatioSeedCriteria {
    pub fn new(ratio: f64, stats: std::sync::Arc<dyn SeedStats>) -> ShareRatioSeedCriteria {
        ShareRatioSeedCriteria { ratio, stats }
    }
}

impl SeedCriteria for ShareRatioSeedCriteria {
    fn reset(&mut self) {
        // aria2's same-named method is empty (ShareRatioSeedCriteria.cc).
    }

    fn evaluate(&mut self) -> bool {
        let completed_length = self.stats.completed_length();
        // completed == 0 counts as satisfied (the divide-by-zero semantics
        // of ShareRatioSeedCriteria.cc; never relax — with no data to
        // serve, the seeding obligation is complete).
        if completed_length == 0 {
            return true;
        }
        let upload_length =
            self.stats.upload_length_at_startup() + self.stats.session_upload_length();
        // `ratio_ <= 1.0 * uploadLength / completedLength`
        // (ShareRatioSeedCriteria.cc; f64 division keeps the reference's
        // precision).
        self.ratio <= 1.0 * upload_length as f64 / completed_length as f64
    }
}

/// seed-time seeding stop criterion (`TimeSeedCriteria.cc`).
pub struct TimeSeedCriteria {
    duration: Duration,
    /// Timer anchor since `reset()` (`watch_`; Timer semantics).
    watch: Instant,
}

impl TimeSeedCriteria {
    pub fn new(duration: Duration) -> TimeSeedCriteria {
        TimeSeedCriteria {
            duration,
            watch: Instant::now(),
        }
    }

    /// Deterministic form of [`SeedCriteria::evaluate`] (injected clock,
    /// for tests; production goes through [`Self::evaluate`] =
    /// `evaluate_at(Instant::now())`).
    fn evaluate_at(&mut self, now: Instant) -> bool {
        // `watch_.difference(global::wallclock()) >= duration_`
        // (TimeSeedCriteria.cc).
        now.duration_since(self.watch) >= self.duration
    }
}

impl SeedCriteria for TimeSeedCriteria {
    fn reset(&mut self) {
        // `watch_ = global::wallclock()` (TimeSeedCriteria.cc).
        self.watch = Instant::now();
    }

    fn evaluate(&mut self) -> bool {
        self.evaluate_at(Instant::now())
    }
}

/// Union criterion: satisfied when any sub-criterion is satisfied
/// (`UnionSeedCriteria.cc`).
#[derive(Default)]
pub struct UnionSeedCriteria {
    criteria: Vec<Box<dyn SeedCriteria>>,
}

impl UnionSeedCriteria {
    pub fn new() -> UnionSeedCriteria {
        UnionSeedCriteria::default()
    }

    /// `addSeedCriteria` (`UnionSeedCriteria.cc`).
    pub fn push(&mut self, criteria: Box<dyn SeedCriteria>) {
        self.criteria.push(criteria);
    }

    pub fn is_empty(&self) -> bool {
        self.criteria.is_empty()
    }
}

impl SeedCriteria for UnionSeedCriteria {
    fn reset(&mut self) {
        // Cascading reset (UnionSeedCriteria.cc).
        for c in &mut self.criteria {
            c.reset();
        }
    }

    fn evaluate(&mut self) -> bool {
        // True when any sub-criterion is satisfied (UnionSeedCriteria.cc).
        self.criteria.iter_mut().any(|c| c.evaluate())
    }
}

/// SeedCheckCommand transcription: the start gate and evaluation for the
/// seeding stop check.
///
/// `checkStarted` gate semantics (`SeedCheckCommand.cc`): the first tick
/// where `downloadFinished` is true sets the latch and calls
/// `criteria.reset()` — timing/evaluation begins at the download-completion
/// moment (the reference basis for the seed-time reset boundary); when
/// satisfied -> halt (`MSG_SEEDING_END` + `setHalt(true)`).
pub struct SeedCheck {
    started: bool,
    criteria: Option<Box<dyn SeedCriteria>>,
}

impl SeedCheck {
    /// Assembly (`BtSetup.cc`): `seed_time > 0` attaches TimeSeedCriteria
    /// (the option-`defined` semantics on the engine face = non-zero;
    /// aria2's option face is minutes x 60, `BtSetup.cc`);
    /// `seed_ratio > 0.0` attaches ShareRatio. An empty Union -> None (no
    /// SeedCheck attached — no criteria means seed until externally
    /// stopped).
    pub fn build(
        seed_time: Duration,
        seed_ratio: f64,
        stats: std::sync::Arc<dyn SeedStats>,
    ) -> Option<SeedCheck> {
        let mut union = UnionSeedCriteria::new();
        if seed_time > Duration::ZERO {
            union.push(Box::new(TimeSeedCriteria::new(seed_time)));
        }
        if seed_ratio > 0.0 {
            union.push(Box::new(ShareRatioSeedCriteria::new(seed_ratio, stats)));
        }
        if union.is_empty() {
            return None;
        }
        Some(SeedCheck {
            started: false,
            criteria: Some(Box::new(union)),
        })
    }

    /// Per-tick advance (SeedCheckCommand::execute, `SeedCheckCommand.cc`):
    /// returns true = seeding should stop (halt). [`DownloadPhase::Running`]
    /// ticks only advance the gate check, no evaluation (matching the
    /// reference `checkStarted_` latch).
    pub fn tick(&mut self, phase: DownloadPhase) -> bool {
        let Some(criteria) = self.criteria.as_mut() else {
            return false;
        };
        if !self.started && phase == DownloadPhase::Finished {
            self.started = true;
            criteria.reset();
        }
        if self.started {
            return criteria.evaluate();
        }
        false
    }

    /// Latch started (true after downloadFinished; for logs/tests).
    pub fn started(&self) -> bool {
        self.started
    }
}

/// Download-phase fact fed to the seed observers (aria2
/// `downloadFinished`): gates the seeding-criteria latch of
/// [`SeedCheck::tick`] and the detach-seed-only predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadPhase {
    /// The download is still running: ticks only advance the gate check,
    /// no evaluation.
    Running,
    /// The download finished: the criteria latch starts (reset +
    /// evaluate).
    Finished,
}

/// The `--bt-detach-seed-only` option value (`RequestGroup.cc`
/// `enableSeedOnly()`'s option term).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachSeedOnly {
    /// Option off: completion never detaches the group.
    Off,
    /// Option on: a finished download detaches to seed-only.
    On,
}

/// The bt-detach-seed-only completion-to-seed-only predicate
/// (`RequestGroup.cc` `enableSeedOnly()`): option on && download finished
/// (sets `seedOnly_` if not already set; idempotent).
///
/// Wiring note (boundary): aria2 also calls
/// `requestGroupMan_->decreaseNumActive()` + `requestQueueCheck()` here
/// (seed-only does not occupy a --max-concurrent-downloads slot) — when
/// this engine's session queue wires up, SessionActor should account
/// `EngineEnd::Detached` as "this group released its concurrency slot" and
/// drive the queue.
pub fn seed_only_detached(option: DetachSeedOnly, phase: DownloadPhase) -> bool {
    option == DetachSeedOnly::On && phase == DownloadPhase::Finished
}

/// bt-stop-timeout observer (BtStopDownloadCommand).
///
/// - Mount condition: timeout > 0 (`BtSetup.cc`); `new` returning None =
///   not mounted.
/// - tick: download speed > 0 -> checkpoint reset (`BtStopDownloadCommand.cc`,
///   `calculateDownloadSpeed()` accounting = the SpeedCalc 10s window,
///   `SpeedCalc.cc`); checkpoint older than the timeout -> forced stop.
/// - No more ticks after download completion (enableExit — active only
///   during download).
pub struct BtStopTimeoutWatch {
    timeout: Duration,
    checkpoint: Instant,
    timed_out: bool,
}

impl BtStopTimeoutWatch {
    /// Mounted only when `btStopTimeout > 0` (`BtSetup.cc`); checkpoint
    /// initial value = command creation time (aria2's TimeBasedCommand
    /// sets the checkpoint at construction).
    pub fn new(timeout: Duration) -> Option<BtStopTimeoutWatch> {
        if timeout == Duration::ZERO {
            return None;
        }
        Some(BtStopTimeoutWatch {
            timeout,
            checkpoint: Instant::now(),
            timed_out: false,
        })
    }

    /// Per-tick advance (1s tick, `BtStopDownloadCommand.cc`):
    /// `download_speed` > 0 resets the checkpoint; returns true = a
    /// timed-out forced stop.
    pub fn tick(&mut self, download_speed: u64) -> bool {
        self.tick_at(Instant::now(), download_speed)
    }

    /// Deterministic form of [`Self::tick`] (injected clock, for tests).
    pub fn tick_at(&mut self, now: Instant, download_speed: u64) -> bool {
        if download_speed > 0 {
            self.checkpoint = now;
        }
        if now.duration_since(self.checkpoint) >= self.timeout {
            self.timed_out = true;
        }
        self.timed_out
    }

    /// Timeout already determined (sticky; the caller force-stops on
    /// this).
    pub fn timed_out(&self) -> bool {
        self.timed_out
    }
}

/// Session download rate (a minimal SpeedCalc transcription: 10s window,
/// `SpeedCalc.cc`).
///
/// Local sampling granularity = per-1s-tick byte deltas (aria2 updates per
/// message); window trimming and the mean formula match: drop stale slots
/// outside the window, empty window -> 0, else
/// `bytesWindow * 1000 / elapsed_ms` (computed from the first slot).
#[derive(Default)]
pub struct SessionSpeedCalc {
    slots: VecDeque<(Instant, u64)>,
    window_bytes: u64,
}

/// `SpeedCalc.cc constexpr auto WINDOW_TIME = 10_s`.
pub const SPEED_WINDOW: Duration = Duration::from_secs(10);

impl SessionSpeedCalc {
    /// Records the byte delta since the last sample (1s-tick accounting).
    pub fn add(&mut self, bytes: u64) {
        let now = Instant::now();
        self.add_at(now, bytes)
    }

    /// Deterministic form of [`Self::add`] (injected clock, for tests).
    pub fn add_at(&mut self, now: Instant, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.window_bytes += bytes;
        self.slots.push_back((now, bytes));
    }

    /// Current rate (bytes/sec; a `calculateSpeed` transcription).
    pub fn calculate(&mut self, now: Instant) -> u64 {
        // removeStaleTimeSlot (SpeedCalc.cc): drop the first slot while it
        // is older than the window.
        while let Some((t, b)) = self.slots.front() {
            if now.duration_since(*t) <= SPEED_WINDOW {
                break;
            }
            self.window_bytes -= b;
            self.slots.pop_front();
        }
        let Some((oldest, _)) = self.slots.front() else {
            return 0; // empty window -> 0 (SpeedCalc.cc)
        };
        let elapsed = now.duration_since(*oldest);
        if elapsed.is_zero() {
            return 0; // same-instant sample (injected clock): no time span, no rate extrapolation.
        }
        // bytesWindow * 1000 / elapsed_ms (SpeedCalc.cc). The reference
        // clamps elapsed <= 0 to 1ms (`if (elapsed <= 0) elapsed = 1`);
        // as_millis() truncates 1us..999us spans to 0 — the same clamp is
        // applied here, eliminating a zero-divisor panic (with 1s-tick
        // sample slots just enqueued, QueryStatus/getPeers snapshots can
        // call this within <1ms).
        let elapsed_ms = elapsed.as_millis() as u64;
        if elapsed_ms == 0 {
            // Sub-millisecond delta -> 1ms floor (defensively returns a
            // sane value without hiding errors: extrapolate over the
            // smallest resolvable window, matching the reference's
            // clamp).
            return self.window_bytes * 1000;
        }
        self.window_bytes * 1000 / elapsed_ms
    }
}

/// Seeding operating policy (`EngineConfig.seed`; option names and
/// defaults frozen: seed-ratio(1.0) / seed-time(0=undefined) /
/// bt-stop-timeout(0) / bt-detach-seed-only(false)).
#[derive(Debug, Clone, PartialEq)]
pub struct SeedPolicy {
    /// `--seed-ratio`: upload/completed ratio threshold; `<= 0` = no ratio
    /// criterion (`BtSetup.cc`).
    pub seed_ratio: f64,
    /// `--seed-time` (aria2's option face is minutes; the engine face is a
    /// Duration): 0 = undefined, no time criterion (`BtSetup.cc`
    /// option->defined semantics).
    pub seed_time: Duration,
    /// `--bt-stop-timeout`: 0 = not mounted (`BtSetup.cc`).
    pub stop_timeout: Duration,
    /// `--bt-detach-seed-only`: switch to seed-only on completion (occupies
    /// no concurrency slot).
    pub detach_seed_only: bool,
    /// BEP16 super-seeding: the seeding initial-distribution propagation
    /// mode — default **off** (BEP16: "only recommended for initial
    /// seeding servers"). true = the seeding state enters super-seeding:
    /// peer registration does not send the full bitfield (libtorrent
    /// `bt_peer_connection.cpp`); each peer is assigned pieces not yet
    /// propagated out and receives new pieces only after completing them
    /// (`torrent.cpp`; bookkeeping = `taiji_bt::superseed::SuperSeedBook`,
    /// engine scheduling = the `engine.rs` run main loop).
    ///
    /// # Option surface
    ///
    /// aria2 has no such option — **no RPC/CLI option naming commitment**;
    /// the switch loads via the config_json internal face
    /// (`PersistedTaskConfig::super_seeding`) and passes through the
    /// restore chain as-is (session/actor.rs rebuild_from_row -> this
    /// struct -> `EngineConfig.seed`).
    pub super_seeding: bool,
}

impl Default for SeedPolicy {
    fn default() -> SeedPolicy {
        SeedPolicy {
            seed_ratio: 1.0,
            seed_time: Duration::ZERO,
            stop_timeout: Duration::ZERO,
            detach_seed_only: false,
            super_seeding: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Synthetic readout source (synthetic upload injection for the
    /// tolerance assertions).
    struct Synth {
        completed: u64,
        session_up: AtomicU64,
        startup_up: u64,
    }

    impl Synth {
        fn new(completed: u64, startup_up: u64) -> Synth {
            Synth {
                completed,
                session_up: AtomicU64::new(0),
                startup_up,
            }
        }

        fn inject(&self, bytes: u64) {
            self.session_up.fetch_add(bytes, Ordering::SeqCst);
        }
    }

    impl SeedStats for Synth {
        fn completed_length(&self) -> u64 {
            self.completed
        }
        fn session_upload_length(&self) -> u64 {
            self.session_up.load(Ordering::SeqCst)
        }
        fn upload_length_at_startup(&self) -> u64 {
            self.startup_up
        }
    }

    fn stats(completed: u64, startup: u64) -> std::sync::Arc<Synth> {
        std::sync::Arc::new(Synth::new(completed, startup))
    }

    // ---- ShareRatioSeedCriteria (ShareRatioSeedCriteria.cc) ----

    /// completed == 0 -> true (the divide-by-zero semantics; even with
    /// zero upload).
    #[test]
    fn ratio_completed_zero_is_satisfied_even_with_zero_upload() {
        let s = stats(0, 0);
        let mut cri = ShareRatioSeedCriteria::new(1.0, s);
        assert!(
            cri.evaluate(),
            "completed==0 must satisfy (reference :55-57)"
        );
    }

    /// Zero upload + completed > 0 -> not satisfied (0 < 1.0 at ratio
    /// 1.0).
    #[test]
    fn ratio_zero_upload_not_satisfied() {
        let s = stats(1000, 0);
        let mut cri = ShareRatioSeedCriteria::new(1.0, s);
        assert!(!cri.evaluate());
    }

    /// Exactly at target (the equality side of ratio <= upload/completed)
    /// -> satisfied.
    #[test]
    fn ratio_exact_target_is_satisfied() {
        let s = stats(1000, 0);
        s.inject(2000);
        let mut cri = ShareRatioSeedCriteria::new(2.0, s);
        assert!(
            cri.evaluate(),
            "ratio 2.0 with upload==2*completed must hold"
        );
    }

    /// One byte short of target -> not satisfied (the <= boundary).
    #[test]
    fn ratio_just_below_target_not_satisfied() {
        let s = stats(1000, 0);
        s.inject(1999);
        let mut cri = ShareRatioSeedCriteria::new(2.0, s);
        assert!(!cri.evaluate());
    }

    /// upload_at_startup counts into the numerator — the math behind a
    /// lossless ratio base across restarts.
    #[test]
    fn ratio_counts_startup_base() {
        let s = stats(1000, 1500);
        s.inject(500);
        let mut cri = ShareRatioSeedCriteria::new(2.0, s);
        assert!(cri.evaluate(), "(1500+500)/1000 == 2.0");
        let s2 = stats(1000, 1500);
        s2.inject(499);
        let mut cri2 = ShareRatioSeedCriteria::new(2.0, s2);
        assert!(!cri2.evaluate());
    }

    /// Two-percent tolerance band: for target ratio R, injecting
    /// 0.98 x R x completed does not satisfy; injecting R x completed does
    /// (the control necessarily lands inside the band).
    #[test]
    fn ratio_within_two_percent_band_table() {
        for target in [1.0f64, 1.5, 2.0, 5.0] {
            let completed = 1_000_000u64;
            // Below the band: 0.98 * target (2% short) -> must not
            // satisfy.
            let lo = stats(completed, 0);
            lo.inject((0.98 * target * completed as f64) as u64);
            let mut cri_lo = ShareRatioSeedCriteria::new(target, lo);
            assert!(
                !cri_lo.evaluate(),
                "target {target}: 98% of target upload must NOT satisfy"
            );
            // At target: injecting target x completed -> must satisfy.
            let hit = stats(completed, 0);
            hit.inject((target * completed as f64) as u64);
            let mut cri_hit = ShareRatioSeedCriteria::new(target, hit);
            assert!(
                cri_hit.evaluate(),
                "target {target}: exact target upload must satisfy"
            );
        }
    }

    // ---- TimeSeedCriteria (TimeSeedCriteria.cc) ----

    /// Timer not elapsed -> false; elapsed -> true (the >= boundary).
    #[test]
    fn time_criteria_elapsed_boundary() {
        let mut cri = TimeSeedCriteria::new(Duration::from_secs(60));
        let t0 = cri.watch;
        assert!(!cri.evaluate_at(t0 + Duration::from_secs(59)));
        assert!(cri.evaluate_at(t0 + Duration::from_secs(60)), ">= boundary");
    }

    /// reset restarts the clock: after reset, timing starts over — the
    /// "begins at completion" transcription.
    #[test]
    fn time_criteria_reset_restarts_watch() {
        let mut cri = TimeSeedCriteria::new(Duration::from_secs(60));
        let t0 = cri.watch;
        // 59s elapsed before reset.
        assert!(!cri.evaluate_at(t0 + Duration::from_secs(59)));
        // reset (= the download-completion moment, SeedCheckCommand.cc) ->
        // timing restarts.
        cri.reset();
        let t1 = cri.watch;
        assert!(!cri.evaluate_at(t1 + Duration::from_secs(30)));
        assert!(cri.evaluate_at(t1 + Duration::from_secs(60)));
    }

    // ---- UnionSeedCriteria (UnionSeedCriteria.cc) ----

    /// Any satisfied -> satisfied; none satisfied -> false.
    #[test]
    fn union_any_satisfies() {
        let mut union = UnionSeedCriteria::new();
        union.push(Box::new(TimeSeedCriteria::new(Duration::from_secs(3600))));
        union.push(Box::new(ShareRatioSeedCriteria::new(1.0, stats(1000, 0))));
        assert!(!union.evaluate(), "time not elapsed + zero upload -> false");
        // ratio satisfied (completed==0 -> true) -> union satisfied.
        let mut union2 = UnionSeedCriteria::new();
        union2.push(Box::new(TimeSeedCriteria::new(Duration::from_secs(3600))));
        union2.push(Box::new(ShareRatioSeedCriteria::new(1.0, stats(0, 0))));
        assert!(union2.evaluate());
        // time satisfied is also sufficient.
        let mut union3 = UnionSeedCriteria::new();
        let mut t = TimeSeedCriteria::new(Duration::from_secs(60));
        t.watch -= Duration::from_secs(61);
        union3.push(Box::new(t));
        union3.push(Box::new(ShareRatioSeedCriteria::new(1.0, stats(1000, 0))));
        assert!(
            union3.evaluate(),
            "time elapsed alone satisfies (any semantics)"
        );
    }

    /// reset cascades.
    #[test]
    fn union_reset_cascades() {
        let mut union = UnionSeedCriteria::new();
        let mut t = TimeSeedCriteria::new(Duration::from_secs(60));
        t.watch -= Duration::from_secs(120); // already timed out
        union.push(Box::new(t));
        assert!(union.evaluate());
        union.reset();
        assert!(!union.evaluate(), "after reset the clock restarts");
    }

    // ---- SeedCheck::build (BtSetup.cc) ----

    /// Default policy (ratio 1.0 / time 0) -> ratio criterion only.
    #[test]
    fn build_default_policy_ratio_only() {
        let check = SeedCheck::build(Duration::ZERO, 1.0, stats(0, 0));
        assert!(
            check.is_some(),
            "default seed-ratio=1.0 must attach a SeedCheck"
        );
    }

    /// Both zero -> None (BtSetup.cc: an empty Union attaches no
    /// SeedCheck).
    #[test]
    fn build_empty_union_is_none() {
        assert!(SeedCheck::build(Duration::ZERO, 0.0, stats(0, 0)).is_none());
    }

    /// time-only / ratio-only / both are each reachable.
    #[test]
    fn build_combinations() {
        // ratio only (time undefined): ratio satisfied is enough to stop.
        let mut c = SeedCheck::build(Duration::ZERO, 1.0, stats(0, 0))
            .unwrap_or_else(|| panic!("ratio only"));
        assert!(
            !c.tick(DownloadPhase::Running),
            "downloadFinished=false: latch only, no evaluation"
        );
        assert!(
            c.tick(DownloadPhase::Finished),
            "completed==0 -> ratio satisfied"
        );
        // time only: completed is irrelevant.
        let mut t = SeedCheck::build(Duration::from_secs(60), 0.0, stats(0, 0))
            .unwrap_or_else(|| panic!("time only"));
        assert!(
            !t.tick(DownloadPhase::Finished),
            "reset base, not yet elapsed"
        );
        // Both criteria: Union (any).
        let mut both = SeedCheck::build(Duration::from_secs(60), 1.0, stats(0, 0))
            .unwrap_or_else(|| panic!("both"));
        assert!(
            both.tick(DownloadPhase::Finished),
            "ratio arm satisfied stops at once"
        );
    }

    // ---- SeedCheck gate (SeedCheckCommand.cc) ----

    /// Gate: no evaluation before downloadFinished (even if a criterion is
    /// already "satisfied") — SeedCheckCommand.cc's checkStarted_
    /// semantics; the latch set calls reset (the seed-time
    /// starts-at-completion boundary).
    #[test]
    fn seed_check_gate_starts_only_after_download_finished() {
        let mut check = SeedCheck::build(Duration::from_secs(60), 0.0, stats(0, 0))
            .unwrap_or_else(|| panic!("time check"));
        // Before completion: criteria never trigger (the checkStarted=false
        // branch).
        assert!(!check.tick(DownloadPhase::Running));
        assert!(!check.started());
        // At completion: latch set + reset (timing starts here).
        assert!(
            !check.tick(DownloadPhase::Finished),
            "must not satisfy immediately after reset"
        );
        assert!(check.started());
    }

    /// Latch stickiness, deliberate (`checkStarted_`,
    /// SeedCheckCommand.cc:71-82: set on the first downloadFinished tick,
    /// never cleared): a phase regression after completion (Finished ->
    /// Running) neither closes the gate nor re-arms `reset` on the next
    /// completion — Running ticks keep evaluating and seed-time stays
    /// anchored at the first completion. Clearing the latch would restart
    /// seed-time after every regress-and-complete cycle, diverging from
    /// aria2; pinned against such a "fix".
    #[test]
    fn seed_check_latch_is_sticky_across_phase_regression() {
        /// Probe criterion: counts `reset` calls and returns a steerable
        /// verdict (shared handles — once boxed into the SeedCheck it is
        /// read and steered from outside).
        struct Probe {
            resets: std::sync::Arc<AtomicU64>,
            satisfied: std::sync::Arc<AtomicBool>,
        }
        impl SeedCriteria for Probe {
            fn evaluate(&mut self) -> bool {
                self.satisfied.load(Ordering::SeqCst)
            }
            fn reset(&mut self) {
                self.resets.fetch_add(1, Ordering::SeqCst);
            }
        }
        let resets = std::sync::Arc::new(AtomicU64::new(0));
        let satisfied = std::sync::Arc::new(AtomicBool::new(false));
        let mut check = SeedCheck {
            started: false,
            criteria: Some(Box::new(Probe {
                resets: resets.clone(),
                satisfied: satisfied.clone(),
            })),
        };
        // Completion: latch set + the single reset (the timing anchor).
        assert!(!check.tick(DownloadPhase::Finished));
        assert!(check.started());
        assert_eq!(resets.load(Ordering::SeqCst), 1);
        // Phase regresses: the latch stays set ...
        assert!(!check.tick(DownloadPhase::Running));
        assert!(check.started(), "latch is sticky across a phase regression");
        // ... and Running ticks keep evaluating: satisfaction still halts.
        satisfied.store(true, Ordering::SeqCst);
        assert!(
            check.tick(DownloadPhase::Running),
            "criteria still evaluated after the phase regression"
        );
        // Re-completion re-arms nothing: seed-time keeps its first anchor.
        assert!(check.tick(DownloadPhase::Finished));
        assert_eq!(
            resets.load(Ordering::SeqCst),
            1,
            "re-completion must not reset the criteria again"
        );
    }

    /// Ratio control exact over a simulated 24h (two-percent tolerance):
    /// synthetic upload injected per tick, SeedCheck stops on the first
    /// tick crossing the threshold — overshoot <= one tick's injection
    /// (24h x 1s tick x rate), total ratio in [target, target + 2%).
    #[test]
    fn ratio_control_within_two_percent_over_simulated_24h() {
        // Scenario: 24h seeding, 100 KiB/s sustained upload, 1s ticks;
        // target ratio 2.0.
        const TOTAL: u64 = 8 * 1024 * 1024; // 8 MiB
        const TARGET: f64 = 2.0;
        const TICK_BYTES: u64 = 100 * 1024; // 100 KiB / tick
        let day_ticks: u64 = 24 * 3600; // tick budget for a simulated 24h
        let s = stats(TOTAL, 0);
        let mut check = SeedCheck::build(Duration::ZERO, TARGET, s.clone())
            .unwrap_or_else(|| panic!("ratio check"));
        assert!(
            !check.tick(DownloadPhase::Finished),
            "clock starts at completion (latch + reset)"
        );
        let mut ticks = 0u64;
        let stop_at = loop {
            ticks += 1;
            s.inject(TICK_BYTES);
            if check.tick(DownloadPhase::Finished) {
                break ticks;
            }
            assert!(
                ticks <= day_ticks,
                "must stop within 24h (target ratio {TARGET})"
            );
        };
        let uploaded = (stop_at * TICK_BYTES) as f64;
        let ratio = uploaded / TOTAL as f64;
        // Overshoot <= 1 tick = 100KiB/8MiB = 1.2% < 2% (the tolerance
        // band).
        assert!(
            (TARGET..TARGET * 1.02).contains(&ratio),
            "ratio {ratio} must be in [{TARGET}, {})",
            TARGET * 1.02
        );
    }

    // ---- BtStopTimeoutWatch (BtStopDownloadCommand.cc, table-driven) ----

    /// Table-driven: speed 0/non-zero x before/after timeout (checkpoint
    /// reset semantics).
    #[test]
    fn stop_timeout_table() {
        struct Row {
            name: &'static str,
            timeout: Duration,
            // (tick_offset, speed) sequence (from t0).
            ticks: Vec<(Duration, u64)>,
            expect_timeout: bool,
        }
        let rows = vec![
            Row {
                name: "speed stays 0, force stop after timeout",
                timeout: Duration::from_secs(30),
                ticks: vec![
                    (Duration::from_secs(1), 0),
                    (Duration::from_secs(15), 0),
                    (Duration::from_secs(29), 0),
                    (Duration::from_secs(30), 0),
                ],
                expect_timeout: true,
            },
            Row {
                name: "non-zero speed resets checkpoint, restarted clock does not time out",
                timeout: Duration::from_secs(30),
                ticks: vec![
                    (Duration::from_secs(10), 0),
                    (Duration::from_secs(20), 1024),
                    (Duration::from_secs(30), 0),
                    (Duration::from_secs(45), 0),
                    (Duration::from_secs(49), 0),
                ],
                expect_timeout: false,
            },
            Row {
                name: "speed 0 but before timeout -> no stop",
                timeout: Duration::from_secs(60),
                ticks: vec![(Duration::from_secs(1), 0), (Duration::from_secs(59), 0)],
                expect_timeout: false,
            },
            Row {
                name: "silence exceeds timeout after speed hits 0 -> stop (reset path)",
                timeout: Duration::from_secs(30),
                ticks: vec![
                    (Duration::from_secs(5), 2048),
                    (Duration::from_secs(10), 0),
                    (Duration::from_secs(39), 0),
                    (Duration::from_secs(40), 0),
                ],
                expect_timeout: true,
            },
        ];
        for row in rows {
            let mut watch = BtStopTimeoutWatch::new(row.timeout).unwrap_or_else(|| panic!("watch"));
            let t0 = watch.checkpoint;
            let mut hit = false;
            for (off, speed) in &row.ticks {
                hit = watch.tick_at(t0 + *off, *speed) || hit;
            }
            assert_eq!(hit, row.expect_timeout, "row: {}", row.name);
            assert_eq!(watch.timed_out(), row.expect_timeout);
        }
    }

    /// 0 = not mounted (`BtSetup.cc` `if btStopTimeout > 0`).
    #[test]
    fn stop_timeout_zero_is_disabled() {
        assert!(BtStopTimeoutWatch::new(Duration::ZERO).is_none());
        assert!(BtStopTimeoutWatch::new(Duration::from_secs(1)).is_some());
    }

    // ---- SessionSpeedCalc (SpeedCalc.cc) ----

    /// Window trimming + mean + empty-window zero.
    #[test]
    fn speed_calc_window_semantics() {
        let mut calc = SessionSpeedCalc::default();
        let t0 = Instant::now();
        calc.add_at(t0, 1000);
        // Same-instant calculation: elapsed millis is 0 -> 0 (divide-by-
        // zero defense; the reference's elapsed<=0 -> 1ms clamp is
        // equivalent to zero at millisecond granularity).
        assert_eq!(calc.calculate(t0), 0);
        // After 1s: 1000 B / 1000 ms = 1000 B/s.
        assert_eq!(calc.calculate(t0 + Duration::from_secs(1)), 1000);
        // Inject 2000 more (at 1s); at 2s: 3000 B / 2000 ms = 1500 B/s.
        calc.add_at(t0 + Duration::from_secs(1), 2000);
        assert_eq!(calc.calculate(t0 + Duration::from_secs(2)), 1500);
        // Outside the window (>10s): the first slot (t0) ages out; the
        // remaining 2000 B count from the second slot (t0+1s) -> elapsed =
        // 10s -> 2000*1000/10000 = 200 B/s (the reference mean spans from
        // the first slot to now, SpeedCalc.cc).
        assert_eq!(calc.calculate(t0 + Duration::from_secs(11)), 200);
        // All aged out -> empty window -> 0.
        assert_eq!(calc.calculate(t0 + Duration::from_secs(22)), 0);
    }

    /// Rate > 0 face (the bt-stop-timeout checkpoint reset criterion).
    #[test]
    fn speed_calc_positive_while_flowiing() {
        let mut calc = SessionSpeedCalc::default();
        let t0 = Instant::now();
        calc.add_at(t0, 16384);
        assert!(calc.calculate(t0 + Duration::from_millis(500)) > 0);
        calc.add_at(t0, 0);
        assert_eq!(calc.calculate(t0 + Duration::from_secs(1)), 16384);
    }

    /// Regression for the sub-millisecond case: calling calculate at
    /// 1us..999us deltas does not panic (zero-divisor defense).
    /// `as_millis()` truncates that band to 0 — the original code used it
    /// directly as a divisor (with 1s-tick sample slots just enqueued,
    /// QueryStatus/getPeers snapshots arrive within <1ms). Fix = the
    /// reference SpeedCalc.cc 1ms clamp: sub-millisecond deltas
    /// extrapolate as 1ms (100 B x 1000 / 1 = 100_000 B/s).
    #[test]
    fn speed_calc_sub_millisecond_elapsed_clamps_to_one_ms() {
        let mut calc = SessionSpeedCalc::default();
        let t0 = Instant::now();
        calc.add_at(t0, 100);
        // 999us: the original panic band where as_millis() == 0.
        assert_eq!(calc.calculate(t0 + Duration::from_micros(999)), 100_000);
        // 1us: lower bound of the same band (repeated queries do not
        // change the window).
        assert_eq!(calc.calculate(t0 + Duration::from_micros(1)), 100_000);
        // Back to normal millisecond-granularity mean:
        // 100 x 1000 / 500 = 200 B/s.
        assert_eq!(calc.calculate(t0 + Duration::from_millis(500)), 200);
    }

    // ---- seed_only_detached (RequestGroup.cc) ----

    /// Option on + finished -> seed-only; option off / unfinished -> not.
    #[test]
    fn detach_seed_only_judgement() {
        assert!(seed_only_detached(
            DetachSeedOnly::On,
            DownloadPhase::Finished
        ));
        assert!(!seed_only_detached(
            DetachSeedOnly::Off,
            DownloadPhase::Finished
        ));
        assert!(!seed_only_detached(
            DetachSeedOnly::On,
            DownloadPhase::Running
        ));
        assert!(!seed_only_detached(
            DetachSeedOnly::Off,
            DownloadPhase::Running
        ));
    }

    /// Default policy = the frozen values.
    #[test]
    fn default_policy_is_frozen() {
        let p = SeedPolicy::default();
        assert_eq!(p.seed_ratio, 1.0);
        assert_eq!(p.seed_time, Duration::ZERO);
        assert_eq!(p.stop_timeout, Duration::ZERO);
        assert!(!p.detach_seed_only);
    }
}
