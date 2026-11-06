//! Retry/backoff parameters (`--max-tries` 5 — semantics redefined as
//! per-extent, diverging from aria2's per-download reading;
//! `--retry-wait` 0s; exponential backoff ×2 capped at 30s).
//!
//! Retry driving belongs to the extent-level consumer (the
//! SegmentWorker fetch loop); this module only provides the parameter
//! face plus wait-sequence/retry helpers, avoiding double counting
//! between implicit client retries and scheduler-level retries.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::future::Future;
use std::time::Duration;

use crate::error::HttpError;

/// Retry policy (default values).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RetryPolicy {
    /// Maximum attempt count (`--max-tries`, default 5; semantics
    /// redefined as per-extent).
    pub max_tries: u32,
    /// Wait before the first retry (`--retry-wait`, default 0s).
    pub base_wait: Duration,
    /// Backoff ceiling (fixed 30s).
    pub max_wait: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_tries: 5,
            base_wait: Duration::ZERO,
            max_wait: Duration::from_secs(30),
        }
    }
}

impl RetryPolicy {
    /// Wait before retry attempt `attempt` (attempt >= 1):
    /// `base × 2^(attempt-1)` truncated to [`RetryPolicy::max_wait`];
    /// attempt 0 needs no wait.
    pub fn wait_before_retry(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        // Exponential ×2: saturating multiplication prevents a Duration
        // overflow panic (the ceiling is 30s anyway).
        let scaled = self
            .base_wait
            .saturating_mul(2u32.saturating_pow(attempt - 1));
        scaled.min(self.max_wait)
    }

    /// The full retry-wait sequence (length = `max_tries - 1`; zero
    /// retries = empty).
    pub fn waits(&self) -> impl Iterator<Item = Duration> + '_ {
        (1..self.max_tries.max(1)).map(|a| self.wait_before_retry(a))
    }
}

/// Parses the `Retry-After` header → suggested wait in seconds (the
/// two shapes of aria2 `parseUnavailableHeaders`). Both forms
/// (RFC 9110 §10.2.3):
/// - delta-seconds: `120`;
/// - HTTP date: `Wed, 21 Oct 2026 07:28:00 GMT` (difference from
/// `now`; a past moment → 0 — server clock skew / stale caches must
/// not produce a negative wait).
///
/// Parse failure → `None` (the caller falls back to its existing
/// backoff rhythm — the politeness face is best-effort; a malformed
/// header value is not a task failure).
pub fn parse_retry_after(value: &str, now: std::time::SystemTime) -> Option<u64> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    // Delta-seconds form (pure digits).
    if let Ok(secs) = v.parse::<u64>() {
        return Some(secs);
    }
    // HTTP-date form (the three canonical spellings, reusing the
    // hand-rolled remotetime parser — no new httpdate/chrono
    // dependency).
    let target = crate::remotetime::parse_http_date(v)?;
    let now_secs = i64::try_from(now.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs()).ok()?;
    Some(target.saturating_sub(now_secs).max(0) as u64)
}

/// Clamp floor for `Retry-After` (ms) = the existing failure-retry
/// rhythm (200ms). `Retry-After: 0` / a past date must not degrade
/// into machine-gun retries (the engine-magnitude counterpart of
/// aria2's 30s floor — the clamp domain takes this engine's backoff
/// magnitude, not aria2's 30s..24h).
pub const RETRY_AFTER_FLOOR_MS: u64 = 200;

/// `Retry-After` clamping (**server value wins, ceiling-clamped
/// against hangs**; the single semantic source):
/// `wait = clamp(after_secs → Duration, floor, max_wait)` —
/// - **server value wins**: respect the server's politeness signal —
/// wait the server-suggested value rather than the default rhythm /
/// exponential backoff (the user's explicit `--retry-wait`
/// configures the exponential-backoff base and does **not**
/// override the server value — the trade-off, written down: a
/// throttle wait is a protocol signal given by the server; user
/// config is a client-side backoff parameter; different domains,
/// and the server value wins within its domain);
/// - **ceiling = [`RetryPolicy::max_wait`]** (the 30s backoff
/// ceiling, same magnitude as `--retry-wait`) — a malicious/faulty
/// server's huge value must not hang the task (same shape as
/// aria2's `MAX_RETRY_AFTER` ceiling clamp);
/// - **floor = 200ms** ([`RETRY_AFTER_FLOOR_MS`]).
pub fn clamp_retry_after(after_secs: u64, policy: &RetryPolicy) -> Duration {
    Duration::from_secs(after_secs).clamp(
        Duration::from_millis(RETRY_AFTER_FLOOR_MS),
        policy
            .max_wait
            .max(Duration::from_millis(RETRY_AFTER_FLOOR_MS)),
    )
}

/// Magnitude of the retry-backoff random fuzz: additive jitter ceiling
/// = 25% of the base (0-25%). **Additive, never subtractive** —
/// existing lower-bound semantics (the clamped `Retry-After` value /
/// the 50ms RST short backoff) are unchanged (a wait is never shorter
/// than it would be without fuzz).
const FUZZ_MAX_PCT: u64 = 25;

/// Random fuzz of task-level retry backoff (aria2 `fuzzDelay` shape):
/// `wait × (1 + U[0, 25%])`, preventing a **synchronized retry
/// storm** when multiple tasks fail on the same source at the same
/// moment (N tasks hitting 429/disconnects on one source at once →
/// fixed backoff makes the N retries reconverge at the same instant,
/// a self-sustaining thundering herd; fuzz spreads the retry phases,
/// decoupling naturally after one or two backoffs).
///
/// Design face:
/// - **0-25% additive magnitude** ([`FUZZ_MAX_PCT`]): an engine-side
/// constant frozen as written (no CLI knob — the aria2 reference
/// behaves the same built-in way); the additive direction
/// guarantees [`clamp_retry_after`]'s 200ms floor and "server value
/// wins" are not breached (a wait is stretched by at most 25%; the
/// 30s clamp ceiling magnitude is undisturbed);
/// - **scope = the three task-level backoff computation points**
/// (grid worker failure arm / per-piece arm / batch-group arm;
/// single-sourced in this crate's retry helpers); **not the probe
/// face** (the probe's transient-failure retries have their own
/// 50ms-floor exponential rhythm and storm-window semantics), and
/// not the generic [`retry_with`] helper (its consumers include the
/// probe);
/// - **random source**: hand-rolled SplitMix64 (no new dependency);
/// seed = current nanoseconds mixed with a process-level monotonic
/// counter — sequences differ across tasks in-process and across
/// backoff points within a task (the key face against reset storms:
/// fuzz sampling is independent across tasks).
pub fn fuzz_delay(wait: Duration) -> Duration {
    let micros = u64::try_from(wait.as_micros()).unwrap_or(u64::MAX);
    // 25% additive ceiling (integer µs domain); a base of 0 (no
    // backoff face) or a ceiling rounding to 0 (pathological base
    // < 4µs) injects no delay.
    let span = micros.saturating_mul(FUZZ_MAX_PCT) / 100;
    if span == 0 {
        return wait;
    }
    let extra = fuzz_rand() % span;
    Duration::from_micros(micros.saturating_add(extra))
}

/// Fuzz random source (SplitMix64; seed = nanosecond clock ⊕
/// process-level counter mix).
fn fuzz_rand() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(0))
        .unwrap_or(0);
    splitmix64(nanos ^ splitmix64(n))
}

/// SplitMix64 finalizer mix (seed-sequence generator, no new
/// dependency).
fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Transport-class transient-failure retry criterion (**single
/// source** — the consumer face of URI-level probe retries):
/// `Transport` transients are retryable; **`DnsPermanent`
/// (NXDOMAIN-class resolution endgame) is not retried** — the aria2
/// reference fails directly on `NAME_RESOLVE_ERROR`
/// (`AbstractCommand.cc` DL_ABORT_EX2: a name-resolution failure is
/// terminal and never enters the retry loop); other variants
/// (deterministic protocol errors / out-of-table statuses) are not a
/// retry face.
pub fn transport_retryable(e: &HttpError) -> bool {
    match e {
        HttpError::Transport(_) => true,
        HttpError::DnsPermanent(_) => false,
        _ => false,
    }
}

/// Retries `op` under the given policy; `retryable` decides whether a
/// failure is worth retrying (non-idempotent faces / definite
/// protocol errors should return false). Waits use
/// `tokio::time::sleep` (with `base_wait = 0`, a single yield, no
/// real delay). Retry decision points feed
/// `taiji_http_retries_total` (process-default registry — the
/// production assembly convention; independent registries via
/// [`retry_with_counted`]).
pub async fn retry_with<T, E, F, Fut, R>(policy: &RetryPolicy, op: F, retryable: R) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    R: FnMut(&E) -> bool,
{
    retry_with_counted(
        taiji_io::metrics::registry_default().http(),
        policy,
        op,
        retryable,
    )
    .await
}

/// The metrics-injectable form of [`retry_with`] (tests assert retry
/// counter deltas against an independent registry, isolated from
/// parallel tests using the process default; semantics identical to
/// [`retry_with`]).
pub async fn retry_with_counted<T, E, F, Fut, R>(
    metrics: &taiji_io::metrics::HttpMetrics,
    policy: &RetryPolicy,
    mut op: F,
    mut retryable: R,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    R: FnMut(&E) -> bool,
{
    let mut attempt: u32 = 0;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                attempt += 1;
                if attempt >= policy.max_tries.max(1) || !retryable(&e) {
                    return Err(e);
                }
                metrics.note_retries(1);
                let wait = policy.wait_before_retry(attempt);
                tracing::debug!(
                    target: "taiji::http::retry",
                    attempt,
                    wait_ms = wait.as_millis() as u64,
                    "retrying after failure"
                );
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Wait sequence: base 2s → 2/4/8/16 (max_tries 5 = 4 retries).
    #[test]
    fn exponential_backoff_sequence() {
        let p = RetryPolicy {
            max_tries: 5,
            base_wait: Duration::from_secs(2),
            max_wait: Duration::from_secs(30),
        };
        let waits: Vec<_> = p.waits().collect();
        assert_eq!(
            waits,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
            ]
        );
    }

    /// Ceiling truncation: base 20s → 20/30/30…; base 0s (the default
    /// `--retry-wait`) → all zero.
    #[test]
    fn backoff_cap_and_zero_base() {
        let p = RetryPolicy {
            max_tries: 4,
            base_wait: Duration::from_secs(20),
            max_wait: Duration::from_secs(30),
        };
        let waits: Vec<_> = p.waits().collect();
        assert_eq!(
            waits,
            vec![
                Duration::from_secs(20),
                Duration::from_secs(30),
                Duration::from_secs(30),
            ]
        );

        let zero = RetryPolicy::default();
        assert!(zero.waits().all(|w| w.is_zero()));
    }

    /// Large attempt exponents do not overflow (saturating ×2 +
    /// ceiling truncation): attempt u32::MAX still converges safely to
    /// max_wait.
    #[test]
    fn backoff_no_overflow() {
        let p = RetryPolicy {
            base_wait: Duration::from_millis(10),
            ..RetryPolicy::default()
        };
        let w = p.wait_before_retry(u32::MAX);
        assert_eq!(w, Duration::from_secs(30));
        assert_eq!(p.wait_before_retry(0), Duration::ZERO);
        // Default zero base: any attempt waits exactly 0.
        let zero = RetryPolicy::default();
        assert!(zero.wait_before_retry(u32::MAX).is_zero());
    }

    /// retry_with: succeeds after two failures; counts and waits are
    /// right.
    #[tokio::test]
    async fn retries_until_success() {
        let p = RetryPolicy {
            max_tries: 3,
            base_wait: Duration::ZERO,
            max_wait: Duration::ZERO,
        };
        let calls = Cell::new(0u32);
        let res = retry_with(
            &p,
            || {
                let n = calls.replace(calls.get() + 1);
                async move { if n < 2 { Err("transient") } else { Ok(n) } }
            },
            |e| *e == "transient",
        )
        .await;
        assert_eq!(res, Ok(2));
        assert_eq!(calls.get(), 3);
    }

    /// Non-retryable errors surface immediately; exhausted retries
    /// return the last error.
    #[tokio::test]
    async fn gives_up_on_non_retryable_and_exhaustion() {
        let p = RetryPolicy {
            max_tries: 3,
            base_wait: Duration::ZERO,
            max_wait: Duration::ZERO,
        };
        // Non-retryable face: stops after one call.
        let calls = Cell::new(0u32);
        let res: Result<(), &str> = retry_with(
            &p,
            || {
                let _ = calls.replace(calls.get() + 1);
                async move { Err("fatal") }
            },
            |e| *e != "fatal",
        )
        .await;
        assert_eq!(res, Err("fatal"));
        assert_eq!(calls.get(), 1);

        // Retryable but exhausted: called exactly max_tries times.
        let calls = Cell::new(0u32);
        let res: Result<(), &str> = retry_with(
            &p,
            || {
                let _ = calls.replace(calls.get() + 1);
                async move { Err("transient") }
            },
            |e| *e == "transient",
        )
        .await;
        assert_eq!(res, Err("transient"));
        assert_eq!(calls.get(), 3);
    }

    /// `Retry-After` parse vectors for both forms + pathological
    /// values.
    #[test]
    fn retry_after_parses_both_forms() {
        let at = |unix: i64| {
            if unix >= 0 {
                std::time::UNIX_EPOCH + Duration::from_secs(unix as u64)
            } else {
                std::time::UNIX_EPOCH - Duration::from_secs(unix.unsigned_abs())
            }
        };
        // Delta-seconds form.
        assert_eq!(parse_retry_after("120", at(0)), Some(120));
        assert_eq!(parse_retry_after(" 0 ", at(0)), Some(0));
        assert_eq!(
            parse_retry_after(u64::MAX.to_string().as_str(), at(0)),
            Some(u64::MAX)
        );
        // HTTP-date form: target = now + 100s → 100 (the IMF-fixdate
        // canonical form).
        let target = crate::remotetime::parse_http_date("Wed, 21 Oct 2026 07:28:00 GMT")
            .unwrap_or_else(|| panic!("anchor"));
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", at(target - 100)),
            Some(100)
        );
        // RFC 850 / asctime same-instant equivalence.
        assert_eq!(
            parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", at(784111777 - 5)),
            Some(5)
        );
        assert_eq!(
            parse_retry_after("Sun Nov  6 08:49:37 1994", at(784111777)),
            Some(0)
        );
        // Past moment → 0 (clock skew never yields a negative wait).
        assert_eq!(
            parse_retry_after("Thu, 01 Jan 1970 00:00:00 GMT", at(1000)),
            Some(0)
        );
        // Pathological values → None (the caller falls back to its
        // existing rhythm).
        for bad in [
            "",
            "   ",
            "not a date",
            "Wed, 99 Xxx 2026 07:28:00 GMT",
            "-5",
        ] {
            assert_eq!(parse_retry_after(bad, at(0)), None, "{bad:?}");
        }
    }

    /// Clamp semantics — server value wins, 30s ceiling against
    /// hangs, 200ms floor against machine-gunning.
    #[test]
    fn retry_after_clamp_semantics() {
        let p = RetryPolicy::default(); // max_wait = 30s
        // Server value inside the domain → respected as-is (wins over
        // the default rhythm).
        assert_eq!(clamp_retry_after(1, &p), Duration::from_secs(1));
        assert_eq!(clamp_retry_after(2, &p), Duration::from_secs(2));
        // Huge value → clamped to 30s (a malicious server must not
        // hang the task).
        assert_eq!(clamp_retry_after(3600, &p), Duration::from_secs(30));
        assert_eq!(clamp_retry_after(u64::MAX, &p), Duration::from_secs(30));
        // 0 / past → 200ms floor (no machine-gun degradation).
        assert_eq!(
            clamp_retry_after(0, &p),
            Duration::from_millis(RETRY_AFTER_FLOOR_MS)
        );
    }

    /// Fuzz semantics: additive 0-25% — **additive only** (the base is
    /// the lower bound: the existing lower-bound semantics of clamped
    /// server values / 50ms RST short backoffs are not breached); the
    /// upper bound = base × 1.25; base 0 is always 0 (no backoff face,
    /// no delay injected).
    #[test]
    fn fuzz_delay_is_additive_within_quarter_band() {
        // Zero base: always zero (no backoff face).
        for _ in 0..64 {
            assert_eq!(fuzz_delay(Duration::ZERO), Duration::ZERO);
        }
        // Regular base band: sampled within the closed band [base,
        // base×1.25].
        for base_ms in [50u64, 200, 400, 3_200, 30_000] {
            let base = Duration::from_millis(base_ms);
            let ceiling = base + base / 4;
            for _ in 0..64 {
                let got = fuzz_delay(base);
                assert!(
                    got >= base && got <= ceiling,
                    "fuzz outside the band (base={base:?}, got={got:?}, ceiling={ceiling:?})"
                );
            }
        }
        // Liveness face: 64 samples are not all identical (the random
        // source really varies — the all-equal probability is pushed
        // to astronomically small by the sample count; this assertion
        // guards against degenerate "constant 0" or "constant ceiling"
        // implementations).
        let base = Duration::from_millis(200);
        let samples: std::collections::HashSet<_> = (0..64).map(|_| fuzz_delay(base)).collect();
        assert!(
            samples.len() > 1,
            "all 64 samples identical — degenerate random source: {samples:?}"
        );
    }

    /// Retry criterion table (the aria2 `NAME_RESOLVE_ERROR` direct
    /// failure, `AbstractCommand.cc` DL_ABORT_EX2): transport
    /// transients retryable; **DnsPermanent (NXDOMAIN-class resolution
    /// endgame) not retried**; deterministic protocol errors / status
    /// codes are not a retry face.
    #[test]
    fn transport_retryable_permanent_dns_is_fatal() {
        use crate::error::HttpError;
        // Transient face: Transport retryable.
        assert!(transport_retryable(&HttpError::Transport("reset".into())));
        // Permanent DNS: not retried (the reference semantics — a
        // name-resolution failure is terminal).
        assert!(!transport_retryable(&HttpError::DnsPermanent(
            "nxdomain".into()
        )));
        // Deterministic face: stops after one call.
        assert!(!transport_retryable(&HttpError::BadRange));
        assert!(!transport_retryable(&HttpError::UnexpectedResponse {
            status: 404
        }));
        assert!(!transport_retryable(&HttpError::CoordinatorStopped));
    }

    /// Retry-decision-point counting (independent registry injection —
    /// the mechanism behind banning bare globals):
    /// `retry_with_counted` increments only on a real retry decision
    /// (exhaustion / non-retryable do not count).
    #[tokio::test]
    async fn retry_counter_counts_retry_decisions_only() {
        use std::sync::Arc;
        use taiji_io::metrics::MetricsRegistry;
        let registry = Arc::new(MetricsRegistry::new());
        let p = RetryPolicy {
            max_tries: 3,
            base_wait: Duration::ZERO,
            max_wait: Duration::ZERO,
        };
        // Two failures then success: 2 retry decisions.
        let calls = Cell::new(0u32);
        let res: Result<u32, &str> = retry_with_counted(
            registry.http(),
            &p,
            || {
                let n = calls.replace(calls.get() + 1);
                async move { if n < 2 { Err("transient") } else { Ok(n) } }
            },
            |e| *e == "transient",
        )
        .await;
        assert_eq!(res, Ok(2));
        // Non-retryable error: stops after one call, zero retry
        // decisions.
        let calls = Cell::new(0u32);
        let res: Result<(), &str> = retry_with_counted(
            registry.http(),
            &p,
            || {
                let _ = calls.replace(calls.get() + 1);
                async move { Err("fatal") }
            },
            |e| *e != "fatal",
        )
        .await;
        assert_eq!(res, Err("fatal"));
        // Exhausted: 3 attempts = 2 retry decisions (the 3rd failure
        // returns immediately, no further decision).
        let calls = Cell::new(0u32);
        let res: Result<(), &str> = retry_with_counted(
            registry.http(),
            &p,
            || {
                let _ = calls.replace(calls.get() + 1);
                async move { Err("transient") }
            },
            |e| *e == "transient",
        )
        .await;
        assert_eq!(res, Err("transient"));
        let s = registry.snapshot().http;
        assert_eq!(s.retries_total, 4, "2 + 0 + 2 = 4 retry decisions");
    }
}
