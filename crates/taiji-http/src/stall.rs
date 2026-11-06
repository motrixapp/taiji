//! Stall detection — the byte-level heartbeat consumer (the task-level
//! destination of `--timeout` read idle).
//!
//! Stall = BOTH liveness counters — cumulative bytes written and
//! flow-control wait events — show zero growth for a continuous
//! `window` (rate-agnostic: a slow connection that keeps writing is
//! never stalled). Permit waits count as liveness: they prove local
//! backoff (including the h2 flow-control waits it causes), not a
//! dead server. Sampling step = `window/4` (floor 10ms); detection
//! latency within [window, window + window/4].
//!
//! Upstream anchor mapping: docs/design/http.md

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Heartbeat source: task-level cumulative bytes written + flow-control
/// wait events (dual monotonic counters); concurrent writers use
/// `fetch_add`.
#[derive(Clone, Debug, Default)]
pub struct ByteHeartbeat {
    total: Arc<AtomicU64>,
    flow_waits: Arc<AtomicU64>,
}

impl ByteHeartbeat {
    pub fn new() -> Self {
        ByteHeartbeat {
            total: Arc::new(AtomicU64::new(0)),
            flow_waits: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Heartbeat injection: `n` bytes written (only >0 advances — a
    /// 0-byte event is not a heartbeat).
    pub fn note(&self, n: u64) {
        if n > 0 {
            self.total.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Flow-control wait event injection (the liveness side of the h2
    /// exclusion): any rate-limit permit wait counts once — weighted
    /// equally with the byte counter in the window check (either
    /// changing refreshes the stall baseline).
    pub fn note_flow_wait(&self) {
        self.flow_waits.fetch_add(1, Ordering::Relaxed);
    }

    /// Current cumulative bytes (snapshot).
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Current cumulative flow-control wait events (snapshot).
    pub fn flow_waits(&self) -> u64 {
        self.flow_waits.load(Ordering::Relaxed)
    }

    /// Wait for a stall: returns once BOTH bytes and flow-control wait
    /// events show zero growth for a continuous `window` (a slow
    /// connection that keeps writing — or whose write path is still
    /// awaiting permits, the flow-wait form — never returns).
    /// Cancellation via the caller's select/drop.
    pub async fn wait_stall(&self, window: Duration) {
        let step = poll_step(window);
        let mut last = (self.total(), self.flow_waits());
        let mut last_change = Instant::now();
        loop {
            tokio::time::sleep(step).await;
            let cur = (self.total(), self.flow_waits());
            if cur != last {
                last = cur;
                last_change = Instant::now();
                continue;
            }
            if last_change.elapsed() >= window {
                return;
            }
        }
    }
}

/// Pure-logic stall decision, reusable by synchronous consumers (the
/// driver tick).
#[derive(Debug)]
pub struct StallWatch {
    window: Duration,
    last_bytes: u64,
    last_change: Instant,
}

impl StallWatch {
    /// Start watching from the current counter baseline (`start` = the
    /// moment the watch is armed).
    pub fn new(window: Duration, baseline: u64, start: Instant) -> Self {
        StallWatch {
            window,
            last_bytes: baseline,
            last_change: start,
        }
    }

    /// Synchronous poll: `total` is the current cumulative snapshot;
    /// zero growth for a full `window` → true (polling may continue
    /// afterwards — sustained zero growth stays true).
    pub fn stalled(&mut self, total: u64, now: Instant) -> bool {
        if total != self.last_bytes {
            self.last_bytes = total;
            self.last_change = now;
            return false;
        }
        now.duration_since(self.last_change) >= self.window
    }
}

fn poll_step(window: Duration) -> Duration {
    let quarter = window / 4;
    // 10ms step floor: tiny windows (tests) must not produce busy-wait
    // granularity.
    if quarter < Duration::from_millis(10) {
        Duration::from_millis(10)
    } else {
        quarter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rate-agnostic semantics: sustained small growth (a slow
    /// connection) never judges stalled.
    #[tokio::test]
    async fn slow_growth_is_never_stalled() {
        let hb = ByteHeartbeat::new();
        let hb2 = hb.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                hb2.note(1); // a "slow connection" at 50 B/s.
            }
        });
        let window = Duration::from_millis(300);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            tokio::select! {
                _ = hb.wait_stall(window) => panic!("a slow connection must not judge stalled"),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        ticker.abort();
    }

    /// Zero growth for a full window returns (detection latency
    /// bounded: [window, window+step]).
    #[tokio::test]
    async fn zero_growth_fires_within_bounded_latency() {
        let hb = ByteHeartbeat::new();
        let window = Duration::from_millis(200);
        let t0 = Instant::now();
        hb.wait_stall(window).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= window,
            "must not fire earlier than the window: {elapsed:?}"
        );
        assert!(
            elapsed <= window + poll_step(window) + Duration::from_millis(150),
            "latency must be bounded: {elapsed:?}"
        );
    }

    /// Growth after a stall no longer returns (wait_stall fires once;
    /// re-arming is the caller's job — this test pins that note resets
    /// the decision baseline).
    #[tokio::test]
    async fn note_resets_stall_baseline() {
        let hb = ByteHeartbeat::new();
        hb.note(10);
        let mut watch = StallWatch::new(Duration::from_millis(100), hb.total(), Instant::now());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            watch.stalled(hb.total(), Instant::now()),
            "zero growth for a full window = stalled"
        );
        // New bytes refresh the baseline → reset.
        hb.note(5);
        assert!(!watch.stalled(hb.total(), Instant::now()));
    }

    /// StallWatch decision table: growth resets, sustained zero growth
    /// crosses the window, counter regression (defensive: an equal
    /// value still counts as zero growth).
    #[test]
    fn stall_watch_decision_table() {
        let t0 = Instant::now();
        let window = Duration::from_secs(1);
        let mut w = StallWatch::new(window, 0, t0);
        // Zero growth within the window, not yet full.
        assert!(!w.stalled(0, t0 + Duration::from_millis(999)));
        // Full window = stalled.
        assert!(w.stalled(0, t0 + window));
        // Growth resets.
        assert!(!w.stalled(100, t0 + window + window));
        // Sustained zero growth full window again → stalled (stays true).
        assert!(!w.stalled(100, t0 + 2 * window + window - Duration::from_millis(1)));
        assert!(w.stalled(100, t0 + 2 * window + window));
        assert!(w.stalled(100, t0 + 3 * window));
    }

    /// poll_step: window lower-bound protection (a 1ms window must not
    /// produce a 0-step loop).
    #[test]
    fn poll_step_has_floor() {
        assert_eq!(poll_step(Duration::from_secs(60)), Duration::from_secs(15));
        assert_eq!(
            poll_step(Duration::from_millis(4)),
            Duration::from_millis(10)
        );
        assert_eq!(poll_step(Duration::ZERO), Duration::from_millis(10));
    }

    // ---------------- h2 flow-control wait exclusion ----------------

    /// Zero byte growth + ongoing flow-control waits → not stalled:
    /// in the low-rate form (a single-chunk permit wait > window) the
    /// connection-level flow window is exhausted by read-side backoff
    /// and bytes stop, but permit-wait events continue — this is
    /// "waiting for a flow slot", not stall evidence.
    #[tokio::test]
    async fn flow_control_waits_exclude_stall_despite_zero_bytes() {
        let hb = ByteHeartbeat::new();
        let hb2 = hb.clone();
        // Simulate "a 16KiB block's permit takes 150ms (low rate
        // limit); no bytes hit disk until the permit clears": one wait
        // event per 50ms, bytes stay zero.
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                hb2.note_flow_wait();
            }
        });
        let window = Duration::from_millis(300);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            tokio::select! {
                _ = hb.wait_stall(window) => panic!(
                    "flow-control waits exclude stall: \
                     zero bytes + ongoing wait events must not judge stalled"
                ),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        ticker.abort();
        assert_eq!(hb.total(), 0, "scenario precondition: zero byte growth");
        assert!(
            hb.flow_waits() > 0,
            "scenario precondition: wait events keep coming"
        );
    }

    /// Flow-control waits stop + zero byte growth → stalled at full
    /// window (the exclusion does not miss: a truly stopped server
    /// sends no chunks and no permit requests, both counters
    /// zero-growth).
    #[tokio::test]
    async fn stall_still_fires_when_flow_waits_stop() {
        let hb = ByteHeartbeat::new();
        // Wait events early (the backoff form), then stopped — the
        // stall window counts from the last event.
        hb.note_flow_wait();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let window = Duration::from_millis(200);
        let t0 = Instant::now();
        hb.wait_stall(window).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= window,
            "only a zero-growth full window after the last event judges: {elapsed:?}"
        );
    }
}
