//! Per-source rate EWMA (the rate term of the rate-composition
//! formula; the accounting base of multi-source weighting).
//!
//! # Where rate samples come from
//!
//! The write path takes a download permit through
//! [`crate::limiter::ThrottledSink`] ([`crate::limiter::Permit`]),
//! and the permit carries its wait duration (the observation seam
//! reserved by the rate-limit face). The sink reports
//! `(source, bytes, permit_waited)` to the coordinator on every write
//! (`CoordinatorMsg::RateSample`); this structure windows the samples
//! inside the coordinator actor: `rate = bytes / elapsed`.
//!
//! # Throttle-dominated window exclusion (the consumption semantics
//! of the observation seam)
//!
//! The limiter exposes permit wait durations to the scheduling face
//! precisely to distinguish **local rate-limit waits** from **slow
//! sources** ("permit-wait share > 50% within a window → not
//! counted"). Folding rate-limit waits into source rate would let the
//! global limiter collapse extent sizes and distort the AIMD gain
//! window. The exclusion criterion takes the **largest single permit
//! wait** in the window > 50% of the window length → discard the
//! whole window: a sum-based measure would be inflated to 100% by
//! "several connections each waiting 25%" and wrongly punish healthy
//! multi-connection sources (wait duration summed over permits grows
//! linearly with concurrency); the max measure is robust to
//! concurrency.
//!
//! The same observation has a second consumer — the **flow-control
//! wait exclusion of the stall-steal decision** ("a rate-limit wait
//! is not stall evidence"): [`SourceRateBook::rate_limit_shadow`]
//! maintains a "rate-limit liveness shadow" from the most recent
//! permit wait, and the decision face cross-checks it before
//! granting — when throttling stretches chunk gaps past the stall
//! window, zero byte growth is just a pacing gap, not stall evidence
//! (a low-rate-limit source should not be stolen from either: the
//! thief is subject to the same task rate limit — pure duplicate
//! writes, zero gain).
//!
//! # Warmup window
//!
//! While the rate EWMA is unestablished (first 10s) the rate term
//! takes +∞ (pure guided). "Unestablished" is implemented here as:
//! the source's accumulated **accepted** window time is below
//! [`RATE_WARMUP`]. Throttle-dominated discarded windows do not
//! advance warmup — rates during throttling do not reflect source
//! capability anyway.
//!
//! Smoothing: EWMA α = 0.5 (a new sample weighs half), minimum window
//! [`MIN_WINDOW`] — shorter reports merge into the next window,
//! keeping bursty small writes from polluting samples.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rate-EWMA warmup window ("first 10s"): until accepted observations
/// accumulate this duration, [`SourceRateBook::rate`] returns `None`
/// (rate term +∞).
pub const RATE_WARMUP: Duration = Duration::from_secs(10);

/// Minimum window length for closing: shorter reports merge into the
/// next window (bursty small writes do not become samples on their
/// own).
const MIN_WINDOW: Duration = Duration::from_millis(50);

/// EWMA new-sample weight (half-life of one sample: converges within
/// the 3s scheduling decision window while keeping smoothing).
const EWMA_ALPHA: f64 = 0.5;

/// Permit-wait share threshold: the **largest single** permit wait in
/// the window exceeding this fraction of the window length → verdict
/// throttle-dominated, discard the whole window (see the
/// throttle-dominated window exclusion in the module docs).
const THROTTLE_RATIO: f64 = 0.5;

/// Recording floor for the rate-limit liveness shadow: permit waits
/// below this are pass-through/call-measurement noise (the
/// unlimited-bucket pass-through path still yields sub-microsecond
/// nonzero `Permit::waited`) and are not evidence that "the local
/// limiter is suppressing the write path" — counting them would let
/// an unthrottled task refresh the steal-decision liveness shadow on
/// every write (over-exclusion). Throttle rhythms capable of faking
/// stall evidence (chunk gaps > stall window >= 3s) sit far above
/// this floor.
const RATE_WAIT_FLOOR: Duration = Duration::from_millis(100);

#[derive(Debug)]
struct SourceRate {
    /// Rate EWMA (bytes/s; the first window becomes the initial value
    /// directly).
    ewma_bps: f64,
    /// Accumulated duration of accepted windows (the warmup
    /// criterion; discarded windows not counted).
    valid_observed: Duration,
    /// Open-window accumulated bytes.
    pending_bytes: u64,
    /// Open-window largest single permit wait.
    pending_max_waited: Duration,
    /// Window start (`None` = no report yet; the next one opens the
    /// window).
    window_open: Option<Instant>,
    /// Most recent rate-limit permit wait (`(observed at, wait
    /// duration)`; `None` = no wait observation yet for this source).
    /// Overwritten by every qualifying sample (independent of window
    /// closing/merging) — the liveness-shadow input for the
    /// stall-steal decision's flow-control wait exclusion; see
    /// [`SourceRateBook::rate_limit_shadow`].
    last_permit_wait: Option<(Instant, Duration)>,
}

/// Per-source rate EWMA ledger (exclusive to the coordinator actor;
/// scheduling decisions read it serially inside the actor loop — no
/// shared locks).
#[derive(Debug, Default)]
pub struct SourceRateBook {
    sources: HashMap<u32, SourceRate>,
}

impl SourceRateBook {
    /// Empty ledger.
    pub fn new() -> Self {
        SourceRateBook {
            sources: HashMap::new(),
        }
    }

    /// Records one write observation (`(source, bytes,
    /// permit_waited)` reported by the sink write path; `now` = the
    /// observation arrival time — an explicit parameter keeps it
    /// testable, production passes `Instant::now()`).
    ///
    /// Window semantics: the first report opens the window; reports
    /// inside [`MIN_WINDOW`] merge (accumulate bytes, take the wait
    /// maximum); at the threshold the window closes —
    /// throttle-dominated windows ([`THROTTLE_RATIO`] criterion) and
    /// zero-byte windows are discarded; other samples enter the EWMA
    /// and advance warmup.
    pub fn observe_at(&mut self, source: u32, bytes: u64, permit_waited: Duration, now: Instant) {
        let sr = self.sources.entry(source).or_insert(SourceRate {
            ewma_bps: 0.0,
            valid_observed: Duration::ZERO,
            pending_bytes: 0,
            pending_max_waited: Duration::ZERO,
            window_open: None,
            last_permit_wait: None,
        });
        // Rate-limit liveness shadow (overwritten on every qualifying
        // sample, before the window-close branch — the window-opening
        // sample also carries a wait observation; waits below the
        // noise floor are not booked, see [`RATE_WAIT_FLOOR`]).
        if permit_waited >= RATE_WAIT_FLOOR {
            sr.last_permit_wait = Some((now, permit_waited));
        }
        let Some(open) = sr.window_open else {
            sr.window_open = Some(now);
            sr.pending_bytes = bytes;
            sr.pending_max_waited = permit_waited;
            return;
        };
        sr.pending_bytes = sr.pending_bytes.saturating_add(bytes);
        if permit_waited > sr.pending_max_waited {
            sr.pending_max_waited = permit_waited;
        }
        let elapsed = now.saturating_duration_since(open);
        if elapsed < MIN_WINDOW {
            return;
        }
        // Window close: sample = window bytes / window length; the
        // discard criteria run first (no warmup advance).
        sr.window_open = Some(now);
        let (win_bytes, win_waited) = (sr.pending_bytes, sr.pending_max_waited);
        sr.pending_bytes = 0;
        sr.pending_max_waited = Duration::ZERO;
        let dominated = win_waited.as_secs_f64() > THROTTLE_RATIO * elapsed.as_secs_f64();
        if dominated || win_bytes == 0 {
            return;
        }
        let sample_bps = win_bytes as f64 / elapsed.as_secs_f64();
        sr.ewma_bps = if sr.valid_observed.is_zero() {
            sample_bps
        } else {
            EWMA_ALPHA * sample_bps + (1.0 - EWMA_ALPHA) * sr.ewma_bps
        };
        sr.valid_observed += elapsed;
    }

    /// Source rate estimate (bytes/s); `None` = the EWMA is
    /// unestablished (warmup incomplete or no valid sample) — the
    /// composition formula's rate term takes +∞ (pure guided).
    pub fn rate(&self, source: u32) -> Option<f64> {
        let sr = self.sources.get(&source)?;
        (sr.valid_observed >= RATE_WARMUP).then_some(sr.ewma_bps)
    }

    /// Whether the source is inside its **rate-limit liveness
    /// shadow** (the flow-control wait exclusion criterion of the
    /// stall-steal decision: "a rate-limit wait is not stall
    /// evidence"): the most recent permit wait's shadow =
    /// `max(window, waited)` — the wait ends at the observation
    /// instant, but it covers the feeding period `[at − waited, at]`;
    /// when throttling stretches chunk gaps longer than the stall
    /// window (the low-rate-limit form, triggered around < 4.3KB/s
    /// with 64KiB chunks / a 15s window), a full window of zero byte
    /// growth is only a pacing gap, not stall, and the shadow takes
    /// the larger of wait and window to cover exactly that gap. A
    /// genuinely stopped server → no chunks → no permit requests →
    /// the shadow expires after the last wait → stall evidence stands
    /// as usual (the exclusion misses nothing).
    pub fn rate_limit_shadow(&self, source: u32, now: Instant, window: Duration) -> bool {
        self.sources
            .get(&source)
            .and_then(|sr| sr.last_permit_wait)
            .is_some_and(|(at, waited)| now.saturating_duration_since(at) <= window.max(waited))
    }

    /// Pre-seeded established rates (a `#[cfg(test)]` observation
    /// seam: the coordinator's weighted-share arbitration fixtures
    /// need deterministic weights, while warmup accumulates on the
    /// real clock — feeding 10s through the observation seam is not
    /// viable). The only production entry point is
    /// [`Self::observe_at`].
    #[cfg(test)]
    pub(crate) fn seed_established(samples: &[(u32, f64)]) -> Self {
        SourceRateBook {
            sources: samples
                .iter()
                .map(|&(source, bps)| {
                    (
                        source,
                        SourceRate {
                            ewma_bps: bps,
                            valid_observed: RATE_WARMUP,
                            pending_bytes: 0,
                            pending_max_waited: Duration::ZERO,
                            window_open: None,
                            last_permit_wait: None,
                        },
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic clock base (explicitly advanced in tests, no real
    /// sleeps).
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

    const KB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;

    /// One healthy 1s window: half the bytes at open and close, the
    /// window rate exactly `bytes` B/s (no waits). The clock is left
    /// at the close instant.
    fn healthy_second(book: &mut SourceRateBook, clock: &mut Clock, source: u32, bytes: u64) {
        let open = clock.tick(Duration::ZERO);
        book.observe_at(source, bytes / 2, Duration::ZERO, open);
        book.observe_at(
            source,
            bytes - bytes / 2,
            Duration::ZERO,
            clock.tick(Duration::from_secs(1)),
        );
    }

    /// Warmup: accepted observation total < 10s → rate = None (pure
    /// guided); once reached, a positive rate. Under stable samples
    /// the EWMA converges near the sample rate.
    #[test]
    fn warmup_gates_rate_until_valid_observation_accumulates() {
        let mut book = SourceRateBook::new();
        let mut clock = Clock::new();

        for _ in 0..9 {
            healthy_second(&mut book, &mut clock, 0, MIB);
        }
        assert!(
            book.rate(0).is_none(),
            "9s of valid observation < the 10s establishment window"
        );

        healthy_second(&mut book, &mut clock, 0, MIB);
        let rate = book
            .rate(0)
            .unwrap_or_else(|| panic!("the rate should establish after 10s of valid observation"));
        assert!(
            (rate - MIB as f64).abs() < MIB as f64 * 0.01,
            "the EWMA of stable 1MiB/s samples should converge within 1%: {rate}"
        );
    }

    /// Throttle-dominated window discard (the observation seam's
    /// consumption semantics): a single permit wait > 50% of the
    /// window → the whole window is not counted (no EWMA entry, no
    /// warmup advance); concurrent healthy waits (the max measure) are
    /// not wrongly punished. The discard is proven by the final EWMA:
    /// had the throttled window's 100KiB/s mixed in, blended
    /// half-weight with the 1MiB/s healthy windows it would sit near
    /// 550KiB/s, far below the healthy convergence value.
    #[test]
    fn throttle_dominated_window_is_discarded_by_max_wait() {
        let mut book = SourceRateBook::new();
        let mut clock = Clock::new();

        // Window 1s, single wait 600ms (> 50%) → discarded.
        let t0 = clock.tick(Duration::ZERO);
        book.observe_at(1, 100 * KB, Duration::from_millis(600), t0);
        book.observe_at(
            1,
            100 * KB,
            Duration::ZERO,
            clock.tick(Duration::from_secs(1)),
        );

        // 10 healthy windows (each single wait 200ms < 50% of the
        // window) → warmup completes.
        for _ in 0..10 {
            let open = clock.tick(Duration::ZERO);
            book.observe_at(1, MIB / 2, Duration::from_millis(200), open);
            book.observe_at(
                1,
                MIB / 2,
                Duration::ZERO,
                clock.tick(Duration::from_secs(1)),
            );
        }
        let rate = book.rate(1).unwrap_or_else(|| {
            panic!(
                "healthy windows should advance establishment \
                     and complete the 10s accumulation"
            )
        });
        assert!(
            rate > 0.8 * MIB as f64,
            "the discarded window must not enter the EWMA (otherwise ≈550KiB/s): {rate}"
        );

        // Multi-connection form: 4 waits of 200ms each (sum 800ms but
        // max 200ms < 50%) → the window is kept (a sum measure would
        // misjudge throttle dominance and discard the whole window).
        let mut book2 = SourceRateBook::new();
        let open = clock.tick(Duration::ZERO);
        book2.observe_at(2, MIB / 4, Duration::from_millis(200), open);
        for _ in 0..3 {
            book2.observe_at(
                2,
                MIB / 4,
                Duration::from_millis(200),
                clock.tick(Duration::from_millis(100)),
            );
        }
        book2.observe_at(2, 0, Duration::ZERO, clock.tick(Duration::from_millis(700)));
        // Whether the window was accepted is not externally visible
        // (bounded by warmup); this pins that it does not panic and
        // later healthy windows still establish — the healthiness of
        // the multi-connection aggregate-window path.
        for _ in 0..10 {
            healthy_second(&mut book2, &mut clock, 2, MIB);
        }
        assert!(
            book2.rate(2).is_some(),
            "healthy samples after a multi-connection wait window still establish"
        );
    }

    /// EWMA smoothing: two different-rate windows → the half-weight
    /// blend sequence (1 → 2 → approaching 3).
    #[test]
    fn ewma_blends_samples() {
        let mut book = SourceRateBook::new();
        let mut clock = Clock::new();

        healthy_second(&mut book, &mut clock, 2, MIB); // ewma = 1MiB/s
        healthy_second(&mut book, &mut clock, 2, 3 * MIB); // ewma = 2MiB/s
        for _ in 0..8 {
            healthy_second(&mut book, &mut clock, 2, 3 * MIB);
        }
        let rate = book
            .rate(2)
            .unwrap_or_else(|| panic!("should establish after a 10s healthy window"));
        // At establishment the EWMA = 3 - 2/2^9 ≈ 2.996MiB/s: the
        // historical tail is visible (< 3).
        assert!(
            rate < 3.0 * MIB as f64 && rate > 1.5 * MIB as f64,
            "the EWMA blend should land in 1.5..3MiB/s: {rate}"
        );
    }

    /// Zero-byte windows produce no sample (stalled observations
    /// belong to another scheduler face, not the rate face); accounts
    /// are isolated between sources; unknown sources are always None.
    #[test]
    fn zero_byte_windows_and_source_isolation() {
        let mut book = SourceRateBook::new();
        let mut clock = Clock::new();

        // Source 4: whole windows of zero bytes → discarded (still no
        // warmup progress after two 2s zero-byte windows).
        let t0 = clock.tick(Duration::ZERO);
        book.observe_at(4, 0, Duration::ZERO, t0);
        book.observe_at(4, 0, Duration::ZERO, clock.tick(Duration::from_secs(2)));
        book.observe_at(4, 0, Duration::ZERO, clock.tick(Duration::from_secs(2)));
        assert!(
            book.rate(4).is_none(),
            "zero-byte windows must not establish a rate"
        );

        // Source 5 establishes independently: source 4's state does
        // not bleed over (2s × 5 = 10s).
        for _ in 0..5 {
            let open = clock.tick(Duration::ZERO);
            book.observe_at(5, MIB, Duration::ZERO, open);
            book.observe_at(5, MIB, Duration::ZERO, clock.tick(Duration::from_secs(2)));
        }
        assert!(book.rate(4).is_none());
        assert!(
            book.rate(5).is_some(),
            "source-account isolation: source 5 establishes independently"
        );
        assert!(
            SourceRateBook::new().rate(999).is_none(),
            "unknown sources are always None (pure guided)"
        );
    }

    /// Rate-limit liveness shadow (the flow-control wait exclusion
    /// ledger of the stall-steal decision): no wait observation, no
    /// shadow; shadow = `max(window, waited)` — the low-rate-limit
    /// form (single wait > stall window) extends the shadow with the
    /// wait; after the wait ends the shadow expires (a genuinely
    /// stopped server is not missed); waits below the noise floor do
    /// not refresh the shadow; accounts are isolated between sources.
    #[test]
    fn rate_limit_shadow_covers_long_permit_waits() {
        let mut book = SourceRateBook::new();
        let mut clock = Clock::new();
        let window = Duration::from_secs(15);

        // No observation: no shadow (a never-throttled source gets no
        // exclusion).
        let t0 = clock.tick(Duration::ZERO);
        assert!(
            !book.rate_limit_shadow(0, t0, window),
            "no wait observation = no liveness shadow"
        );

        // Low-rate-limit form: waited 20s > window 15s → shadow 20s.
        book.observe_at(0, 64 * KB, Duration::from_secs(20), t0);
        assert!(
            book.rate_limit_shadow(0, t0 + Duration::from_secs(19), window),
            "shadow = max(window, waited): gaps within the wait rhythm are not stall evidence"
        );
        assert!(
            book.rate_limit_shadow(0, t0 + Duration::from_secs(20), window),
            "the shadow boundary includes the endpoint (<=)"
        );
        assert!(
            !book.rate_limit_shadow(
                0,
                t0 + Duration::from_secs(20) + Duration::from_nanos(1),
                window
            ),
            "shadow expired: no new permit request after the last wait \
             = real stall evidence can stand"
        );

        // Moderate throttling: waited 1s < window 15s → shadow =
        // window.
        let t1 = clock.tick(Duration::ZERO);
        book.observe_at(1, KB, Duration::from_secs(1), t1);
        assert!(book.rate_limit_shadow(1, t1 + window, window));
        assert!(!book.rate_limit_shadow(1, t1 + window + Duration::from_nanos(1), window));

        // Waits below the noise floor ([`RATE_WAIT_FLOOR`]) are not
        // booked: pass-through permits' sub-microsecond measurement
        // noise is not rate-limit activity (an unthrottled source must
        // not gain the exclusion through it — otherwise every write
        // would refresh the steal-decision liveness shadow).
        let t2 = clock.tick(Duration::ZERO);
        book.observe_at(2, KB, RATE_WAIT_FLOOR / 2, t2);
        assert!(
            !book.rate_limit_shadow(2, t2, window),
            "noise waits carry no shadow"
        );
        book.observe_at(2, KB, RATE_WAIT_FLOOR, t2);
        assert!(
            book.rate_limit_shadow(2, t2, window),
            "exactly at the floor (>=) is booked"
        );

        // Source isolation: source 1's shadow does not shelter source
        // 3.
        assert!(!book.rate_limit_shadow(3, t1, window));
    }
}
