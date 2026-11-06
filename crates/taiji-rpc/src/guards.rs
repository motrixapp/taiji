//! RPC exposure guards: (1) a connection-concurrency ledger (total cap +
//! per-source-IP cap) and (2) exponential backoff on auth failures (the
//! token and Basic gates share one per-IP failure count).
//!
//! Threat-model rationale and lifecycle details:
//! Upstream anchor mapping: docs/design/rpc.md
//!
//! Hard invariants:
//! - Credential contents never enter metrics or logs; a backoff warn
//! carries only the IP and the window length.
//! - Backoff state expires by lazy sweeping (no timers); the rendering
//! path ([`AuthBackoff::active_windows`]) never mutates the table, so
//! periodic /metrics scrapes cannot reset failure accumulation. Over
//! the table capacity cap the whole table is cleared (fail-open).
//! - With neither the secret nor Basic credentials configured, neither
//! gate touches these ledgers (decided at the call sites).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::warn;

/// Default total concurrent connection cap (HTTP requests + WS sessions
/// combined; engine constant, not a CLI knob).
pub(crate) const DEFAULT_MAX_TOTAL_CONNS: usize = 256;
/// Default per-source-IP concurrent connection cap.
pub(crate) const DEFAULT_MAX_PER_IP_CONNS: usize = 32;
/// Auth-failure backoff threshold (consecutive failures; tests inject
/// smaller values).
pub(crate) const DEFAULT_AUTH_FAIL_THRESHOLD: u32 = 5;

/// First backoff window (applied when the threshold is reached).
const BACKOFF_FIRST_SECS: u64 = 1;
/// Backoff window cap.
const BACKOFF_CAP_SECS: u64 = 60;
/// Backoff table capacity cap: sweep inert entries first; if still full,
/// clear the whole table (fail-open).
const BACKOFF_TRACKED_CAP: usize = 4096;
/// Lazy-sweep trigger line: once the table reaches this length, the next
/// note_failure access point sweeps.
const BACKOFF_SWEEP_AT: usize = 256;

/// Guard parameters (test-injection surface; production always uses
/// [`Default`] = 256/32/5 — frozen seam, no CLI knobs; e2e injects small
/// values via serve_with_guards in [`crate::server`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RpcGuards {
    pub max_total_conns: usize,
    pub max_per_ip_conns: usize,
    pub auth_fail_threshold: u32,
}

impl Default for RpcGuards {
    fn default() -> Self {
        RpcGuards {
            max_total_conns: DEFAULT_MAX_TOTAL_CONNS,
            max_per_ip_conns: DEFAULT_MAX_PER_IP_CONNS,
            auth_fail_threshold: DEFAULT_AUTH_FAIL_THRESHOLD,
        }
    }
}

/// Connection-rejection dimension (value space of the metrics label
/// `scope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnScope {
    /// Total concurrency cap hit.
    Total,
    /// Per-IP concurrency cap hit.
    PerIp,
}

/// Connection concurrency ledger: a total count (atomic) plus per-IP
/// counts (one mutex-guarded table; the lock never spans an await —
/// acquire/release are purely synchronous critical sections).
pub(crate) struct ConnLedger {
    max_total: usize,
    max_per_ip: usize,
    total: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
}

impl ConnLedger {
    pub(crate) fn new(max_total: usize, max_per_ip: usize) -> Self {
        ConnLedger {
            max_total,
            max_per_ip,
            total: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
        }
    }

    /// Acquire a connection lease; on over-limit, return the dimension
    /// hit (total / per-IP). The total count claims a slot with an atomic
    /// RMW and rolls back on failure (linearized: concurrent acquires
    /// cannot overshoot); the per-IP decision happens under the lock.
    pub(crate) fn acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnLease, ConnScope> {
        // Claim a total slot: fetch_add returns the old value; roll back
        // if old + 1 > cap.
        let prev = self.total.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max_total {
            self.total.fetch_sub(1, Ordering::AcqRel);
            return Err(ConnScope::Total);
        }
        let mut per_ip = crate::lock(&self.per_ip);
        if per_ip.get(&ip).is_some_and(|c| *c >= self.max_per_ip) {
            drop(per_ip);
            self.total.fetch_sub(1, Ordering::AcqRel);
            return Err(ConnScope::PerIp);
        }
        *per_ip.entry(ip).or_insert(0) += 1;
        Ok(ConnLease {
            ledger: Arc::clone(self),
            ip,
        })
    }

    /// Lease release (the only call site is [`ConnLease::drop`]).
    fn release(&self, ip: IpAddr) {
        let prev = self.total.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "connection ledger underflow");
        let mut per_ip = crate::lock(&self.per_ip);
        if let Some(n) = per_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_ip.remove(&ip);
            }
        }
    }

    /// Ledger readout (test surface): (total concurrency, per-IP table
    /// length).
    #[cfg(test)]
    pub(crate) fn current(&self) -> (usize, usize) {
        let per_ip = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        (self.total.load(Ordering::Acquire), per_ip.len())
    }
}

/// Connection lease (RAII): dropping it releases the ledger entry. A WS
/// session takes over the handshake request's lease via
/// [`ConnLeaseSlot`] (released when the session exits); a plain HTTP
/// request is released by the middleware after the response is produced.
pub(crate) struct ConnLease {
    ledger: Arc<ConnLedger>,
    ip: IpAddr,
}

impl Drop for ConnLease {
    fn drop(&mut self) {
        self.ledger.release(self.ip);
    }
}

/// Handshake-request-to-WS-session lease transfer slot: the connection
/// gate middleware stores the lease (passed down in request extensions)
/// and `ws_upgrade` takes it when it decides to upgrade; if never taken
/// (plain HTTP / gate rejection), the middleware takes it back and
/// releases it after the response. A single slot guarantees exactly one
/// lease per connection (held continuously across handshake and session
/// — no double counting).
#[derive(Clone)]
pub(crate) struct ConnLeaseSlot(pub(crate) Arc<Mutex<Option<ConnLease>>>);

/// Per-IP auth failure state (one backoff ledger entry).
#[derive(Debug, Default, Clone, Copy)]
struct IpAuthState {
    /// Consecutive auth failures (reset on success).
    consecutive: u32,
    /// Deadline of the current backoff window (None = no window).
    window_until: Option<Instant>,
}

impl IpAuthState {
    /// Inert-entry test: no active window and below the threshold — the
    /// entry could never trigger backoff even if kept, so access points
    /// sweep it out (timer-free expiry).
    fn inert(&self, now: Instant, threshold: u32) -> bool {
        self.window_until.is_none_or(|u| u <= now) && self.consecutive < threshold
    }
}

/// Exponential backoff on auth failures (per-IP ledger shared by the
/// token and Basic gates).
pub(crate) struct AuthBackoff {
    threshold: u32,
    state: Mutex<HashMap<IpAddr, IpAuthState>>,
}

impl AuthBackoff {
    pub(crate) fn new(threshold: u32) -> Self {
        AuthBackoff {
            threshold,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// In-window wait: while the IP has an active backoff window, sleep
    /// until it expires before returning (correct credentials included —
    /// the call site does this BEFORE evaluating credentials). One sleep
    /// to the observed window deadline, no re-check loop: under sustained
    /// failure the window keeps being pushed out, and a loop would starve
    /// the IP's legitimate requests and hold the connection cap. Single
    /// sleep = "sleep to window end, then process". `None` = no peer
    /// (in-process test surface): no wait.
    pub(crate) async fn wait(&self, ip: Option<IpAddr>) {
        let Some(ip) = ip else { return };
        let until = {
            let state = crate::lock(&self.state);
            state.get(&ip).and_then(|s| s.window_until)
        };
        let now = Instant::now();
        if let Some(until) = until
            && until > now
        {
            tokio::time::sleep(until - now).await;
        }
    }

    /// Account an auth failure: increment the consecutive count; at the
    /// threshold, arm or extend the backoff window. Returns the window
    /// applied this time (None below the threshold). A `None` ip
    /// (in-process test surface) is not recorded. One critical section
    /// (std Mutex is not reentrant — no locking or logging while held).
    pub(crate) fn note_failure(&self, ip: Option<IpAddr>) -> Option<Duration> {
        let ip = ip?;
        let mut over_cap_dropped = 0usize;
        let window = {
            let mut state = crate::lock(&self.state);
            if state.len() >= BACKOFF_SWEEP_AT {
                // Lazy sweep: entries with no window and below the
                // threshold are swept here (no timers).
                let now = Instant::now();
                state.retain(|_, s| !s.inert(now, self.threshold));
            }
            if state.len() >= BACKOFF_TRACKED_CAP {
                // Capacity cap: still full (many window-armed sources) ->
                // clear the whole table, fail-open (availability over
                // rate-limit bookkeeping; the count is reported outside
                // the lock — IPs/credentials never enter logs).
                over_cap_dropped = state.len();
                state.clear();
            }
            let entry = state.entry(ip).or_default();
            entry.consecutive = entry.consecutive.saturating_add(1);
            let window = backoff_window(entry.consecutive, self.threshold);
            entry.window_until = window.map(|w| Instant::now() + w);
            window
        };
        if over_cap_dropped > 0 {
            warn!(
                target: "taiji::rpc::guards",
                dropped = over_cap_dropped,
                "auth backoff table over cap; cleared (fail-open)"
            );
        }
        window
    }

    /// Successful auth resets to zero (the entry is removed as a whole —
    /// consecutive count and window drop together).
    pub(crate) fn note_success(&self, ip: Option<IpAddr>) {
        let Some(ip) = ip else { return };
        crate::lock(&self.state).remove(&ip);
    }

    /// Number of source IPs currently inside an active backoff window
    /// (rendering readout for the gauge `taiji_rpc_auth_backoff_active`).
    /// Pure count, never mutates the table — rendering (a /metrics
    /// scrape) must not clean entries: periodic scrapes would otherwise
    /// keep resetting failure accumulation (backoff dismantled through
    /// the observability path). Lazy sweeping happens only at the
    /// [`Self::note_failure`] accounting access point.
    pub(crate) fn active_windows(&self) -> usize {
        let state = crate::lock(&self.state);
        let now = Instant::now();
        state
            .values()
            .filter(|s| s.window_until.is_some_and(|u| u > now))
            .count()
    }

    /// Ledger table length (test surface).
    #[cfg(test)]
    pub(crate) fn tracked_len(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Backoff window for `consecutive` consecutive failures at `threshold`:
/// None below the threshold; first window 1s, doubling per further
/// failure, capped at 60s. Pure function (state-machine unit-test
/// anchor). A lookup table replaces shifting (no shift overflow at large
/// counts).
pub(crate) fn backoff_window(consecutive: u32, threshold: u32) -> Option<Duration> {
    if consecutive < threshold {
        return None;
    }
    let exp = consecutive - threshold;
    let secs = match exp {
        0 => BACKOFF_FIRST_SECS,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        _ => BACKOFF_CAP_SECS,
    };
    Some(Duration::from_secs(secs))
}
/// Test surface: ledger table length (window-armed entries included;
/// distinct from the [`Self::active_windows`] rendering count — this
/// readout does not mutate the table).
#[cfg(test)]
impl AuthBackoff {
    pub(crate) fn backoff_record_len(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    // ---- connection ledger: paired acquire/release, both caps, per-IP aggregation ----

    /// Total cap: reject once full (scope=total), readmit after release;
    /// accounting pairs up (once all leases drop, the total count and the
    /// per-IP table drain to zero).
    #[test]
    fn ledger_enforces_total_cap_then_readmits_after_release() {
        let ledger = Arc::new(ConnLedger::new(2, 8));
        let a = ledger.acquire(v4(1)).unwrap_or_else(|_| panic!("first"));
        let b = ledger.acquire(v4(2)).unwrap_or_else(|_| panic!("second"));
        assert_eq!(
            ledger.acquire(v4(3)).err(),
            Some(ConnScope::Total),
            "third concurrent connection over total cap"
        );
        assert_eq!(ledger.current(), (2, 2));
        drop(a);
        let c = ledger.acquire(v4(3)).unwrap_or_else(|_| panic!("readmit"));
        assert_eq!(ledger.current(), (2, 2), "release/acquire must pair");
        drop(b);
        drop(c);
        assert_eq!(ledger.current(), (0, 0), "ledger drains to zero");
    }

    /// Per-IP cap: a third connection from one IP is rejected
    /// (scope=per_ip), other sources are unaffected, the same IP is
    /// readmitted after release; per-IP counts aggregate by source.
    #[test]
    fn ledger_enforces_per_ip_cap_and_aggregates_per_source() {
        let ledger = Arc::new(ConnLedger::new(8, 2));
        let a = ledger.acquire(v4(1)).unwrap_or_else(|_| panic!("ip1 #1"));
        let b = ledger.acquire(v4(1)).unwrap_or_else(|_| panic!("ip1 #2"));
        assert_eq!(
            ledger.acquire(v4(1)).err(),
            Some(ConnScope::PerIp),
            "third from one source over per-ip cap"
        );
        // Other sources unaffected (total concurrency 3 <= 8).
        let c = ledger.acquire(v4(2)).unwrap_or_else(|_| panic!("other ip"));
        assert_eq!(
            ledger.current(),
            (3, 2),
            "per-ip counts aggregate by source"
        );
        drop(b);
        let d = ledger
            .acquire(v4(1))
            .unwrap_or_else(|_| panic!("readmit same ip"));
        assert_eq!(ledger.current(), (3, 2));
        drop(a);
        drop(c);
        drop(d);
        assert_eq!(ledger.current(), (0, 0));
    }

    // ---- backoff state machine: failure sequence / success reset / cap / lazy sweep ----

    /// Window-sequence pure function: no window below the threshold,
    /// first window 1s, doubling per failure, capped at 60s; the
    /// threshold is injectable.
    #[test]
    fn backoff_window_sequence_arms_doubles_and_caps() {
        let s = Duration::from_secs;
        // Threshold 3.
        assert_eq!(backoff_window(2, 3), None, "below threshold: no window");
        assert_eq!(backoff_window(3, 3), Some(s(1)), "first window 1s");
        assert_eq!(backoff_window(4, 3), Some(s(2)));
        assert_eq!(backoff_window(5, 3), Some(s(4)));
        assert_eq!(backoff_window(6, 3), Some(s(8)));
        assert_eq!(backoff_window(7, 3), Some(s(16)));
        assert_eq!(backoff_window(8, 3), Some(s(32)));
        assert_eq!(backoff_window(9, 3), Some(s(60)), "64 caps to 60s");
        assert_eq!(backoff_window(1000, 3), Some(s(60)), "stays capped");
        // Threshold 5 (production default): first window at the 5th failure.
        assert_eq!(backoff_window(4, 5), None);
        assert_eq!(backoff_window(5, 5), Some(s(1)));
        // Threshold 1: every failure arms a window.
        assert_eq!(backoff_window(1, 1), Some(s(1)));
        assert_eq!(backoff_window(2, 1), Some(s(2)));
    }

    /// State machine (real clock, window length the constant 1s): a
    /// failure sequence arms a window -> an in-window wait really sleeps
    /// (tokio sleep, measured against a lower bound) -> once the window
    /// expires, active drops to zero (lazy sweep) -> success clears ->
    /// counting restarts from zero.
    #[tokio::test]
    async fn auth_state_machine_failure_sequence_success_reset() {
        let backoff = AuthBackoff::new(3);
        let ip = v4(1);
        // First two failures: no window, no wait (returns immediately).
        assert_eq!(backoff.note_failure(Some(ip)), None);
        assert_eq!(backoff.note_failure(Some(ip)), None);
        let t = std::time::Instant::now();
        backoff.wait(Some(ip)).await;
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "no window yet: {:?}",
            t.elapsed()
        );
        // Third failure: the 1s window arms.
        assert_eq!(
            backoff.note_failure(Some(ip)),
            Some(Duration::from_secs(1)),
            "threshold reached arms the first window"
        );
        assert_eq!(backoff.active_windows(), 1, "window active");
        // In-window auth attempt (the wait on the correct-credential
        // path): really sleeps until the window ends (0.5s lower bound
        // guards against scheduling flakes; upper bound against hangs).
        let t = std::time::Instant::now();
        backoff.wait(Some(ip)).await;
        assert!(
            t.elapsed() >= Duration::from_millis(500),
            "in-window wait must sleep ~1s: {:?}",
            t.elapsed()
        );
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "wait must stay bounded: {:?}",
            t.elapsed()
        );
        // Window expired: active back to zero (lazy sweep); the
        // consecutive count survives (a later failure escalates).
        assert_eq!(backoff.active_windows(), 0);
        assert_eq!(
            backoff.tracked_len(),
            1,
            "escalation record survives expiry"
        );
        // Fourth failure, after expiry: doubled, 2s.
        assert_eq!(
            backoff.note_failure(Some(ip)),
            Some(Duration::from_secs(2)),
            "post-window failure escalates"
        );
        // Successful auth clears: entry removed, a fresh failure does
        // not arm a window.
        backoff.note_success(Some(ip));
        assert_eq!(backoff.tracked_len(), 0, "success clears the record");
        assert_eq!(backoff.note_failure(Some(ip)), None);
        // No peer (in-process test surface): not recorded.
        assert_eq!(backoff.note_failure(None), None);
        backoff.note_success(None);
        assert_eq!(backoff.tracked_len(), 1);
    }

    /// Lazy sweep: inert entries (no window, below threshold) are swept
    /// at the next access point once the table hits the trigger length
    /// (256); window-armed entries (escalation records) survive the
    /// sweep.
    #[test]
    fn auth_backoff_sweeps_inert_entries_on_access() {
        let backoff = AuthBackoff::new(3);
        // 256 sources with one failure each (inert: no window, below the
        // threshold) — exactly at the line without crossing it (the
        // check runs before insertion; the sweep happens on the next
        // access after len reaches 256).
        for n in 1..=64u32 {
            for k in 1..=4u8 {
                let _ = backoff.note_failure(Some(IpAddr::V4(Ipv4Addr::new(192, 0, n as u8, k))));
            }
        }
        assert_eq!(backoff.tracked_len(), 256);
        // The first note_failure past the line sweeps inert entries,
        // keeping only the actor.
        let _ = backoff.note_failure(Some(v4(1)));
        assert_eq!(backoff.tracked_len(), 1, "inert junk swept, actor kept");
        // Escalation records (window armed) are not dropped by the
        // rendering path.
        let armed = AuthBackoff::new(1);
        let _ = armed.note_failure(Some(v4(9)));
        assert_eq!(armed.active_windows(), 1);
        assert_eq!(
            armed.backoff_record_len(),
            1,
            "armed entry survives rendering sweep"
        );
    }

    /// Capacity cap: over-cap table (many window-armed sources) -> whole
    /// table cleared, fail-open; accounting continues afterwards.
    #[test]
    fn auth_backoff_cap_clears_table_fail_open() {
        let backoff = AuthBackoff::new(1);
        for n in 1..=(BACKOFF_TRACKED_CAP as u32 + 8) {
            let _ = backoff.note_failure(Some(IpAddr::V4(Ipv4Addr::new(
                10,
                (n >> 16) as u8,
                (n >> 8) as u8,
                n as u8,
            ))));
        }
        assert!(
            backoff.tracked_len() < BACKOFF_TRACKED_CAP,
            "over-cap table must have been cleared"
        );
        // After the clear, accounting still arms a window.
        assert_eq!(
            backoff.note_failure(Some(v4(1))),
            Some(Duration::from_secs(1))
        );
    }
}
