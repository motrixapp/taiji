//! uTP congestion control: LEDBAT (BEP-29 "congestion control") plus RTT/
//! timeout estimation (BEP-29 "timeouts"). Pure logic, no IO, so numeric
//! vector tests are direct.
//!
//! Mechanism (full BEP-29/RFC quotes and rationale: docs/design/io.md):
//! - reply.micro = now - peer timestamp_microseconds, echoed back in
//! timestamp_difference_microseconds on every packet;
//! - base_delay = minute-bucketed sliding minimum over the last two minutes
//! ("Each socket keeps a sliding minimum of the lowest value for the last
//! two minutes."); our_delay = sample - base_delay;
//! - gain: delay_factor = off_target / CCONTROL_TARGET; window_factor =
//! outstanding_packet / max_window; scaled_gain =
//! MAX_CWND_INCREASE_PACKETS_PER_RTT * delay_factor * window_factor;
//! max_window += scaled_gain. CCONTROL_TARGET = 100 ms; off_target =
//! CCONTROL_TARGET - our_delay, so our_delay > target shrinks the window.
//! BEP-29's closing prose sentence reverses this sign (erratum); the
//! formula wins, matching libtorrent/libutp. MAX_CWND_INCREASE has no
//! BEP-29 value — a local tuning knob (see [`LedbatConfig`]). Floor:
//! "If max_window becomes less than 0, it is set to 0."
//! - slow start x2/RTT: RFC 6817 §2.2 defers to RFC 5681 §3.1 (cwnd += SMSS
//! per ACK => doubling per RTT); initial window 2xMSS (RFC 6817 §2.5:
//! "INIT_CWND and MIN_CWND SHOULD both be 2.");
//! - loss: max_window x0.5 ("When a packet is lost, the max_window is
//! multiplied by 0.5 to mimic TCP.");
//! - timeout: max_window and packet_size reset to the smallest packet size,
//! 150 bytes ([`MIN_PACKET_SIZE`]).
//!
//! Upstream anchor mapping: docs/design/io.md
//!
use std::time::Duration;

/// CCONTROL_TARGET = 100 ms (BEP-29 "congestion control": "the delay target
/// is set to 100 ms").
pub const CCONTROL_TARGET_US: i64 = 100_000;
/// Minimum packet size (BEP-29 "timeouts"/"packet sizes": "the smallest
/// packet size (150 bytes)" / "as small as 150 bytes per packet").
pub const MIN_PACKET_SIZE: u32 = 150;

/// LEDBAT parameters (implementation-local tuning unless attributed to BEP-29; not protocol facts).
#[derive(Debug, Clone)]
pub struct LedbatConfig {
    /// CCONTROL_TARGET (us). BEP-29 "congestion control": 100 ms. Defaults
    /// to [`CCONTROL_TARGET_US`]; tests may override (wire default unchanged).
    pub target_us: i64,
    /// `MAX_CWND_INCREASE_PACKETS_PER_RTT` from the BEP-29 gain formula
    /// (bytes/RTT). BEP-29 gives no value — local parameter: the largest
    /// per-RTT window growth at full gain.
    pub max_cwnd_increase_bytes_per_rtt: f64,
    /// max_window floor (bytes). BEP-29 allows down to 0; the implementation
    /// floors at [`MIN_PACKET_SIZE`] so one probe packet can still be sent
    /// after a timeout (BEP-29 "timeouts" restart-by-resend semantics).
    pub min_window_bytes: u32,
    /// max_window ceiling (bytes, local runaway-growth guard).
    pub max_window_bytes: u32,
    /// base_delay minute-bucket count. BEP-29: "the last two minutes" => 2.
    pub base_delay_buckets: usize,
}

impl Default for LedbatConfig {
    fn default() -> Self {
        Self {
            target_us: CCONTROL_TARGET_US,
            // Local: 2x1500 (two common-MTU packets; BEP-29 gives no value).
            max_cwnd_increase_bytes_per_rtt: 3000.0,
            min_window_bytes: MIN_PACKET_SIZE,
            max_window_bytes: 4 * 1024 * 1024,
            base_delay_buckets: 2,
        }
    }
}

/// base_delay: minute-bucketed sliding minimum (BEP-29 "congestion control":
/// "sliding minimum of the lowest value for the last two minutes"; bucket
/// structure matches RFC 6817 §3.1.1 update_base_delay, count = 2 per BEP-29).
#[derive(Debug)]
pub struct BaseDelay {
    /// Per-minute minimum sample; empty bucket = i64::MAX (RFC 6817 "+INFINITY" init).
    buckets: Vec<i64>,
    /// Minute number owning the current tail bucket (now_us / 60_000_000).
    current_minute: Option<u64>,
}

impl BaseDelay {
    pub fn new(buckets: usize) -> Self {
        Self {
            buckets: vec![i64::MAX; buckets.max(1)],
            current_minute: None,
        }
    }

    /// Feed one delay sample (us, may be negative — peer clock skew; BEP-29
    /// admits unsynchronized clocks: "The clocks in the machines are most
    /// likely not synchronized").
    pub fn update(&mut self, sample_us: i64, now_us: u64) {
        let minute = now_us / 60_000_000;
        match self.current_minute {
            Some(m) if m == minute => {
                let tail = self
                    .buckets
                    .last_mut()
                    .unwrap_or_else(|| unreachable_panic());
                *tail = (*tail).min(sample_us);
            }
            _ => {
                // Minute rollover: drop the oldest bucket, start a new minute
                // in the tail (RFC 6817 §3.1.1 update_base_delay roll semantics).
                self.buckets.rotate_left(1);
                if let Some(tail) = self.buckets.last_mut() {
                    *tail = sample_us;
                }
                self.current_minute = Some(minute);
            }
        }
    }

    /// Current base_delay = min over all buckets; `None` with no samples.
    pub fn get(&self) -> Option<i64> {
        let m = *self.buckets.iter().min()?;
        (m != i64::MAX).then_some(m)
    }
}

/// LEDBAT controller (one per connection).
#[derive(Debug)]
pub struct Ledbat {
    cfg: LedbatConfig,
    base: BaseDelay,
    /// max_window (bytes; f64 carries the gain formula's fractional
    /// accumulation — the BEP-29 formula is a continuous quantity).
    max_window: f64,
    /// Slow start active (RFC 6817 §2.2 + RFC 5681 §3.1; see module doc).
    slow_start: bool,
    /// Most recent our_delay (observability, us).
    last_our_delay_us: Option<i64>,
}

impl Ledbat {
    pub fn new(cfg: LedbatConfig, initial_window_bytes: u32) -> Self {
        Self {
            base: BaseDelay::new(cfg.base_delay_buckets),
            max_window: initial_window_bytes as f64,
            slow_start: true,
            last_our_delay_us: None,
            cfg,
        }
    }

    pub fn max_window(&self) -> f64 {
        self.max_window
    }

    pub fn in_slow_start(&self) -> bool {
        self.slow_start
    }

    pub fn last_our_delay_us(&self) -> Option<i64> {
        self.last_our_delay_us
    }

    /// ACK arrival: feed the delay sample and advance the window.
    ///
    /// `sample_us` = the peer-echoed timestamp_difference (us; 0 = the peer
    /// has no sample — BEP-29 "timestamp_difference_microseconds": "must be
    /// set to 0" — skipped). `bytes_newly_acked` drives slow-start stepping
    /// (RFC 5681 §3.1 equation (2)).
    pub fn on_ack(&mut self, sample_us: i64, bytes_newly_acked: u32, cur_window: u32, now_us: u64) {
        if sample_us == 0 {
            return;
        }
        self.base.update(sample_us, now_us);
        let Some(base) = self.base.get() else {
            return;
        };
        // our_delay = sample - base_delay (BEP-29 definition); clock skew can
        // make it negative, clamped to >= 0 (buffering delay is non-negative).
        let our_delay = (sample_us - base).max(0);
        self.last_our_delay_us = Some(our_delay);
        let target = self.cfg.target_us;

        if self.slow_start {
            // Delay crossing the target is the congestion signal: leave slow
            // start (RFC 6817 §2.2 applies slow start until congestion; the
            // BEP-29 target delay is the exit threshold).
            if our_delay >= target {
                self.slow_start = false;
            } else {
                // RFC 5681 §3.1: slow start adds <= SMSS per ACK => x2 per
                // RTT.
                self.max_window += bytes_newly_acked as f64;
                self.clamp();
                return;
            }
        }

        // BEP-29 "congestion control" gain formula (line-for-line, see module doc).
        let off_target = (target - our_delay) as f64;
        let delay_factor = off_target / target as f64;
        let window_factor = if self.max_window > 0.0 {
            (cur_window as f64) / self.max_window
        } else {
            0.0
        };
        let scaled_gain = self.cfg.max_cwnd_increase_bytes_per_rtt * delay_factor * window_factor;
        self.max_window += scaled_gain;
        self.clamp();
    }

    /// Loss: max_window x0.5 (BEP-29 "packet loss": "multiplied by 0.5") and
    /// leave slow start (congestion signal; the RFC 5681 §3.1 termination condition).
    pub fn on_loss(&mut self) {
        self.slow_start = false;
        self.max_window *= 0.5;
        self.clamp();
    }

    /// Timeout: squeeze max_window to the minimum packet size (BEP-29
    /// "timeouts": "set its packet_size and max_window to the smallest
    /// packet size (150 bytes)").
    pub fn on_timeout(&mut self) {
        self.slow_start = false;
        self.max_window = self.cfg.min_window_bytes as f64;
    }

    fn clamp(&mut self) {
        if self.max_window < self.cfg.min_window_bytes as f64 {
            self.max_window = self.cfg.min_window_bytes as f64;
        }
        if self.max_window > self.cfg.max_window_bytes as f64 {
            self.max_window = self.cfg.max_window_bytes as f64;
        }
    }
}

/// RTT / timeout estimation (BEP-29 "timeouts" formulas, in ms):
///
/// ```text
/// delta = rtt - packet_rtt
/// rtt_var += (abs(delta) - rtt_var) / 4;
/// rtt += (packet_rtt - rtt) / 8;
/// ```
///
/// Timeout (same section): "timeout = max(rtt + rtt_var * 4, 500)" (ms,
/// 1/2 s floor); "The initial timeout is set to 1000 milliseconds". Only
/// packets "that were sent only once" update the estimate (same section:
/// "The rtt and rtt_var is only updated for packets that were sent only
/// once.").
///
/// The same section's consecutive-timeout doubling ("For every packet
/// consecutive subsequent packet that times out, the timeout is doubled.")
/// applies to the driver's retransmit scan-round interval (see
/// conn::scan_round: with no inbound packets between rounds the interval
/// x2), not to this estimate — this value is only recomputed on rtt updates.
/// Folding doubling into this value would make it unrecoverable while
/// cumulative acks are blocked by a gap, stalling the connection for
/// minutes.
#[derive(Debug)]
pub struct Rtt {
    rtt_ms: f64,
    rtt_var_ms: f64,
}

impl Default for Rtt {
    fn default() -> Self {
        // Initial values give timeout = max(0 + 4x250, 500) = 1000 ms —
        // BEP-29 "timeouts": "The initial timeout is set to 1000 milliseconds".
        Self {
            rtt_ms: 0.0,
            rtt_var_ms: 250.0,
        }
    }
}

impl Rtt {
    /// Update on ACK when the packet was sent only once (BEP-29 "timeouts" formula, in ms).
    pub fn update(&mut self, packet_rtt_ms: f64) {
        let delta = self.rtt_ms - packet_rtt_ms;
        self.rtt_var_ms += (delta.abs() - self.rtt_var_ms) / 4.0;
        self.rtt_ms += (packet_rtt_ms - self.rtt_ms) / 8.0;
    }

    /// Effective timeout = max(rtt + rtt_var * 4, 500) (BEP-29, 1/2 s floor).
    pub fn timeout(&self) -> Duration {
        let ms = (self.rtt_ms + self.rtt_var_ms * 4.0).max(500.0);
        Duration::from_millis(ms.round() as u64)
    }

    pub fn rtt_ms(&self) -> f64 {
        self.rtt_ms
    }

    pub fn rtt_var_ms(&self) -> f64 {
        self.rtt_var_ms
    }
}

// unreachable_panic: explicit invariant failure point under the
// clippy::unwrap_used ban (the bucket vec is non-empty by construction,
// always length >= 1).
fn unreachable_panic() -> ! {
    panic!("BaseDelay buckets must be non-empty")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minute conversion helper (60_000_000 us per minute).
    const MINUTE: u64 = 60_000_000;

    /// BEP-29 "timeouts" RTT formula numeric vector (hand-computed per round).
    #[test]
    fn rtt_formula_vector() {
        let mut r = Rtt::default();
        assert_eq!(
            r.timeout(),
            Duration::from_millis(1000),
            "BEP29: initial 1000 ms"
        );
        r.update(100.0);
        // delta = 0-100 = -100; var += (100-250)/4 = -37.5 -> 212.5; rtt -> 12.5
        assert!((r.rtt_ms() - 12.5).abs() < 1e-9);
        assert!((r.rtt_var_ms() - 212.5).abs() < 1e-9);
        // timeout = max(12.5 + 212.5*4, 500) = 862.5 (floor not in effect).
        assert_eq!(r.timeout(), Duration::from_millis(863));
        r.update(200.0);
        // delta = 12.5-200 = -187.5; var += (187.5-212.5)/4 = -6.25 -> 206.25; rtt -> 35.9375
        assert!((r.rtt_var_ms() - 206.25).abs() < 1e-9);
        assert!((r.rtt_ms() - 35.9375).abs() < 1e-9);
        // timeout = max(35.9375 + 825, 500) = 860.9375.
        assert_eq!(r.timeout(), Duration::from_millis(861));
        r.update(1000.0);
        // rtt -> 35.9375 + (1000-35.9375)/8 = 156.4453125
        assert!((r.rtt_ms() - 156.4453125).abs() < 1e-9);
        assert!(
            r.timeout() >= Duration::from_millis(500),
            "floor 500 ms (BEP29)"
        );
    }

    /// Timeout floor and recovery (BEP-29 "timeouts": timeout =
    /// max(rtt+4*var, 500); consecutive-timeout doubling lives on the driver
    /// scan-round interval, see the conn::scan_round comments).
    #[test]
    fn timeout_floor_and_recovery() {
        let mut r = Rtt::default();
        assert_eq!(
            r.timeout(),
            Duration::from_millis(1000),
            "BEP29: initial 1000 ms"
        );
        r.update(50.0);
        // var -> 250+(50-250)/4 = 200; rtt -> 6.25; timeout = max(6.25+800,500) = 806.25
        assert_eq!(r.timeout(), Duration::from_millis(806));
        r.update(400.0);
        // rtt -> 6.25+(400-6.25)/8 = 55.46875; var -> 200+(393.75-200)/4 = 248.4375;
        // timeout = max(55.46875 + 993.75, 500) = 1049.21875.
        assert_eq!(r.timeout(), Duration::from_millis(1049));
    }

    /// LEDBAT gain formula numeric vector (BEP-29 "congestion control",
    ///
    /// line by line).
    ///
    /// Scenario: base_delay=1us, sample=target+1 => our_delay=target =>
    /// off_target=0 => window unchanged (the "This will make the window
    /// smaller if off_target ..." prose is a BEP-29 erratum; by the formula
    /// off_target=0 gives gain 0).
    ///
    /// The sample base is 1us, not 0: on the wire timestamp_difference=0
    /// means "the peer has no sample" (BEP-29
    /// "timestamp_difference_microseconds") and is skipped.
    #[test]
    fn gain_zero_at_target_delay() {
        let cfg = LedbatConfig::default();
        let mut l = Ledbat::new(cfg.clone(), 10_000);
        // Warm the two-minute buckets: sample 1us => base=1.
        l.on_ack(1, 0, 10_000, 0);
        l.on_ack(1, 0, 10_000, MINUTE);
        let before = l.max_window();
        // sample = target+1 => our_delay = target => off_target = 0.
        l.on_ack(cfg.target_us + 1, 0, 10_000, 2 * MINUTE);
        assert!(
            (l.max_window() - before).abs() < 1e-6,
            "off_target=0 implies gain 0"
        );
    }

    /// Congested direction: our_delay = 2xtarget => off_target=-target =>
    /// window shrinks (gain = K x (-1) x window_factor).
    #[test]
    fn gain_negative_over_target() {
        let cfg = LedbatConfig::default();
        let mut l = Ledbat::new(cfg.clone(), 100_000);
        // Warm-up: sample 1us => base=1, our=0 (no bytes acked in slow start, window unchanged).
        l.on_ack(1, 0, 50_000, 0);
        l.on_ack(1, 0, 50_000, MINUTE);
        let before = l.max_window();
        assert!(before > 0.0);
        // sample = 2xtarget+1: base=1 => our=2xtarget; slow start exits on
        // crossing the target, then by the formula delay_factor=-1 and
        // window_factor=0.5 => gain=-1500.
        l.on_ack(2 * cfg.target_us + 1, 0, 50_000, 2 * MINUTE);
        let expected = before - 1500.0;
        assert!(
            (l.max_window() - expected).abs() < 1e-6,
            "gain = K·delay_factor·window_factor"
        );
        assert!(l.max_window() < before);
    }

    /// Idle direction: our_delay=0 => off_target=+target => window grows (delay_factor=+1).
    #[test]
    fn gain_positive_under_target() {
        let cfg = LedbatConfig::default();
        let mut l = Ledbat::new(cfg.clone(), 100_000);
        // Warm up base=1 (two-minute buckets), our=0.
        l.on_ack(1, 0, 50_000, 0);
        l.on_ack(1, 0, 50_000, MINUTE);
        // sample=target+1: exits slow start (>= target), gain 0, window unchanged.
        l.on_ack(cfg.target_us + 1, 0, 50_000, 2 * MINUTE);
        let before = l.max_window();
        // sample=1 => our=0 => delay_factor=+1; window_factor=0.5 => gain=+1500.
        l.on_ack(1, 0, 50_000, 3 * MINUTE);
        assert!((l.max_window() - (before + 1500.0)).abs() < 1e-6);
    }

    /// Slow start: x2/RTT (RFC 6817 §2.2 + RFC 5681 §3.1); after exiting on
    /// crossing the target delay, the gain formula takes over.
    #[test]
    fn slow_start_doubles_per_rtt_then_exits() {
        let cfg = LedbatConfig::default();
        let mut l = Ledbat::new(cfg.clone(), 2 * 1500); // INIT_CWND=2xMSS (RFC 6817 §2.5)
        assert!(l.in_slow_start());
        // Ack 1500B (SMSS) per packet within one RTT; cwnd += SMSS/ACK => x2 per RTT.
        let now = 1u64;
        for _ in 0..4 {
            let before = l.max_window();
            l.on_ack(1, 1500, 3000, now);
            assert!(
                (l.max_window() - (before + 1500.0)).abs() < 1e-6,
                "slow start adds SMSS per ACK"
            );
        }
        // our_delay crosses target => leave slow start.
        l.on_ack(cfg.target_us * 3 + 1, 1500, 3000, now);
        assert!(
            !l.in_slow_start(),
            "crossing the 100ms delay target exits slow start"
        );
    }

    /// Loss halves the window by 0.5 (BEP-29 "packet loss"; Post-History 0.78 -> 0.5).
    #[test]
    fn loss_halves_window() {
        let mut l = Ledbat::new(LedbatConfig::default(), 40_000);
        l.on_loss();
        assert!((l.max_window() - 20_000.0).abs() < 1e-6);
        assert!(!l.in_slow_start());
    }

    /// Timeout squeezes the window to 150B (BEP-29 "timeouts") + floor clamping.
    #[test]
    fn timeout_floor_min_packet_size() {
        let mut l = Ledbat::new(LedbatConfig::default(), 40_000);
        l.on_timeout();
        assert_eq!(
            l.max_window(),
            150.0,
            "BEP29：smallest packet size (150 bytes)"
        );
        // The gain direction never dips below the floor either (clamped >= 150B).
        l.on_loss();
        assert!(l.max_window() >= 150.0);
    }

    /// base_delay: two-minute sliding minimum (BEP-29) + minute rollover.
    #[test]
    fn base_delay_two_minute_sliding_min() {
        let mut b = BaseDelay::new(2);
        assert_eq!(
            b.get(),
            None,
            "no sample = +INFINITY (RFC 6817 initialization)"
        );
        b.update(500, 0);
        assert_eq!(b.get(), Some(500));
        b.update(300, 0);
        assert_eq!(b.get(), Some(300), "same-minute minimum");
        b.update(100, MINUTE); // minute rollover: buckets roll, old bucket 300 retained
        assert_eq!(b.get(), Some(100));
        b.update(700, 2 * MINUTE); // rolls again: 300 out
        assert_eq!(b.get(), Some(100), "minimum within the two-minute window");
        b.update(900, 3 * MINUTE); // 100 rolls out too
        assert_eq!(
            b.get(),
            Some(700),
            "after stale buckets roll off, back to the new window's minimum"
        );
    }

    /// Negative samples (clock skew) do not panic; base may be negative
    /// (BEP-29 admits unsynchronized clocks).
    #[test]
    fn negative_samples_tolerated() {
        let mut b = BaseDelay::new(2);
        b.update(-5_000, 0);
        assert_eq!(b.get(), Some(-5_000));
        let cfg = LedbatConfig::default();
        let mut l = Ledbat::new(cfg.clone(), 10_000);
        l.on_ack(-5_000, 0, 5_000, 0);
        l.on_ack(-5_000, 0, 5_000, MINUTE);
        assert_eq!(
            l.last_our_delay_us(),
            Some(0),
            "sample=base implies our_delay=0 (negative clamped)"
        );
    }
}
