//! Rate-limit integration: HTTP download traffic enters the existing
//! global + per-task dual token buckets ([`taiji_io::rate_limit`]);
//! the per-task bucket is the task-level pair of [`LimiterSet`].
//! `0 = unlimited` keeps the io-layer semantics (bucket-level
//! zero-cost short-circuit). Disk writes are gated at the
//! [`SegmentSink`] seam by [`ThrottledSink`]: take a permit for the
//! byte count, then let the inner write through — permit waits push
//! back the read window. `complete_block` (accounting) is not
//! rate-limited. [`Permit::waited`] feeds the dynamic scheduler's
//! rate-sample observation seam (see docs/design/http.md).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::future::BoxFuture;
use taiji_io::rate_limit::LimiterSet;

use crate::error::Result;
use crate::traits::{SegId, SegmentSink};

/// HTTP task rate limiter: `None` = no buckets (bare CLI/unconfigured
/// pass-through).
///
/// The global + task-level dual-bucket series topology is carried by
/// [`LimiterSet`] (session-side assembly: the global pair is Arc-shared,
/// the task pair is created per task — hot-updating the global pair
/// takes effect on running tasks immediately).
#[derive(Clone, Default)]
pub struct HttpLimiter {
    limits: Option<Arc<LimiterSet>>,
}

/// One download permit: carries its wait duration (the
/// dynamic-scheduling observation seam; see [`RateSampleReporter`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct Permit {
    waited: std::time::Duration,
}

impl Permit {
    /// This permit's wait duration (pass-through/unlimited ≈ 0).
    pub fn waited(&self) -> std::time::Duration {
        self.waited
    }
}

impl HttpLimiter {
    /// Attach the dual-bucket series topology (`None` = pass-through).
    pub fn new(limits: Option<Arc<LimiterSet>>) -> Self {
        HttpLimiter { limits }
    }

    /// Download-direction permit: global first, then task-level (the
    /// series order is fixed by [`LimiterSet`]); no buckets/unlimited
    /// buckets is a near-zero-cost pass-through.
    pub async fn acquire_down(&self, n: u64) -> Permit {
        let started = Instant::now();
        if let Some(limits) = &self.limits {
            limits.acquire_down(n).await;
        }
        Permit {
            waited: started.elapsed(),
        }
    }
}

/// Write-path rate observation reporter (consumer side of the
/// observation seam).
///
/// Implementors = the coordinator handle (message-based reporting).
/// Sync contract: the implementation must NOT block — samples are
/// dropped when the channel is full (sampled-telemetry semantics: the
/// EWMA is robust to lost samples; the write path is never
/// backpressured by the observation face).
pub trait RateSampleReporter: Send + Sync {
    /// Report one write observation: `source` (accounting domain),
    /// `bytes` (permit-released bytes), `permit_waited`
    /// ([`Permit::waited`], this permit's wait).
    fn report(&self, source: u32, bytes: u64, permit_waited: Duration);
}

/// Rate-limited sink wrapper: disk writes go through the frozen
/// [`SegmentSink`] seam; rate limiting wraps outside the seam (the
/// inner sink is the core-injected store implementation, unaware of
/// rate limiting).
///
/// - `write_at`: take a permit for `bytes.len()` → let the inner write
///   through (the disk handle is not touched while waiting; accounting
///   is never double-charged — the permit only gates disk-bound
///   bytes);
/// - `complete_block`: accounting passes straight through (bitmap
///   accounting is not rate-limited; its serialization lives in the
///   coordinator);
/// - optional [`RateSampleReporter`]: once attached, every write
///   reports a permit-wait observation (instances built with
///   [`ThrottledSink::new`] do not report — the observation face is
///   off by default).
pub struct ThrottledSink {
    inner: Arc<dyn SegmentSink>,
    limiter: HttpLimiter,
    reporter: Option<Arc<dyn RateSampleReporter>>,
}

impl ThrottledSink {
    /// Wrap the core-injected sink and the task limiter (no observation
    /// reporting).
    pub fn new(inner: Arc<dyn SegmentSink>, limiter: HttpLimiter) -> Self {
        ThrottledSink {
            inner,
            limiter,
            reporter: None,
        }
    }

    /// Like [`ThrottledSink::new`], plus a rate observation reporter
    /// (observation-seam consumer; see the type docs and
    /// [`RateSampleReporter`]).
    pub fn with_rate_reporter(
        inner: Arc<dyn SegmentSink>,
        limiter: HttpLimiter,
        reporter: Arc<dyn RateSampleReporter>,
    ) -> Self {
        ThrottledSink {
            inner,
            limiter,
            reporter: Some(reporter),
        }
    }
}

impl SegmentSink for ThrottledSink {
    fn write_at(&self, seg: SegId, off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>> {
        let inner = Arc::clone(&self.inner);
        let limiter = self.limiter.clone();
        let reporter = self.reporter.clone();
        let n = bytes.len() as u64;
        Box::pin(async move {
            let permit = limiter.acquire_down(n).await;
            let out = inner.write_at(seg, off, bytes).await;
            if let Some(reporter) = &reporter {
                reporter.report(seg.source, n, permit.waited());
            }
            out
        })
    }

    fn complete_block(&self, block: u64) -> BoxFuture<'_, Result<()>> {
        self.inner.complete_block(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Extent, SegmentTransport};
    use std::time::Duration;
    use taiji_io::rate_limit::LimiterPair;

    /// Recording sink: accumulates released bytes and completed blocks.
    #[derive(Default)]
    struct RecordingSink {
        bytes: std::sync::atomic::AtomicU64,
        blocks: std::sync::atomic::AtomicU64,
    }

    impl SegmentSink for RecordingSink {
        fn write_at(&self, _seg: SegId, _off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>> {
            self.bytes
                .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(())))
        }

        fn complete_block(&self, _block: u64) -> BoxFuture<'_, Result<()>> {
            self.blocks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    /// In-memory body transport: streams the body to the sink in 4KiB
    /// chunks (the rate gate applies per chunk).
    struct ChunkTransport(Arc<Vec<u8>>);

    impl SegmentTransport for ChunkTransport {
        fn fetch<'a>(
            &'a self,
            seg: &'a Extent,
            _ctx: &'a crate::traits::RequestCtx,
            sink: &'a dyn SegmentSink,
        ) -> futures::future::BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                let body = self.0.as_slice();
                if seg.end() > body.len() as u64 {
                    return Err(crate::error::HttpError::BadRange);
                }
                let seg_id = SegId {
                    source: 0,
                    extent: 0,
                };
                let mut off = seg.start;
                while off < seg.end() {
                    let n = 4096usize.min((seg.end() - off) as usize);
                    let chunk = Bytes::copy_from_slice(&body[off as usize..off as usize + n]);
                    sink.write_at(seg_id, off, chunk).await?;
                    off += n as u64;
                }
                Ok(())
            })
        }
    }

    /// Unlimited/pass-through: permits are near-instant (waited ≈ 0),
    /// all bytes released, complete_block not rate-limited.
    #[tokio::test]
    async fn unlimited_limiter_is_passthrough() {
        let inner = Arc::new(RecordingSink::default());
        // None = no buckets (pass-through form).
        let limiter = HttpLimiter::new(None);
        let sink = ThrottledSink::new(Arc::clone(&inner) as Arc<dyn SegmentSink>, limiter.clone());

        let permit = limiter.acquire_down(1 << 20).await;
        assert!(
            permit.waited() < Duration::from_millis(5),
            "pass-through permits must not wait: {:?}",
            permit.waited()
        );

        let body = Arc::new(vec![7u8; 8192]);
        let transport = ChunkTransport(Arc::clone(&body));
        let ext = Extent {
            start: 0,
            len: 8192,
        };
        transport
            .fetch(&ext, &crate::traits::RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        assert_eq!(inner.bytes.load(std::sync::atomic::Ordering::Relaxed), 8192);

        // Accounting passes through: never suspended by the rate face.
        let started = Instant::now();
        sink.complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        assert!(
            started.elapsed() < Duration::from_millis(5),
            "complete_block is not rate-limited"
        );
        assert_eq!(inner.blocks.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// Rate-limited face: the per-task bucket throttles throughput —
    /// transfer time >= theoretical value × tolerance floor; permit
    /// wait durations are recorded by the observation seam (total wait >=
    /// the floor); the dual-bucket series topology takes effect
    /// (with the task bucket the bottleneck, the effective rate =
    /// task-bucket rate).
    #[tokio::test]
    async fn rate_limited_write_throttles_and_records_wait() {
        const RATE: u64 = 32 * 1024; // 32KiB/s
        const TOTAL: usize = 48 * 1024; // 48KiB @32KiB/s ≈ 1.5s

        let inner = Arc::new(RecordingSink::default());
        let limits = Arc::new(LimiterSet {
            // Global unlimited, task-level 32KiB/s: in series the
            // bottleneck = the task bucket (per-task semantics).
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(RATE, 0),
        });
        let limiter = HttpLimiter::new(Some(Arc::clone(&limits)));
        let sink = ThrottledSink::new(Arc::clone(&inner) as Arc<dyn SegmentSink>, limiter.clone());

        let body = Arc::new(vec![9u8; TOTAL]);
        let transport = ChunkTransport(Arc::clone(&body));
        let ext = Extent {
            start: 0,
            len: TOTAL as u64,
        };

        let started = Instant::now();
        transport
            .fetch(&ext, &crate::traits::RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        let elapsed = started.elapsed();

        let theoretical = TOTAL as f64 / RATE as f64;
        assert!(
            elapsed.as_secs_f64() >= theoretical * 0.8,
            "throughput exceeded the limit: {elapsed:?} < {theoretical}s x 0.8"
        );
        assert_eq!(
            inner.bytes.load(std::sync::atomic::Ordering::Relaxed),
            TOTAL as u64,
            "throttling must not drop bytes"
        );

        // Observation seam: a single permit wait is measurable (after
        // continuous draining the bucket ≈ 0; a full bucket ≈ 1s).
        let permit = limiter.acquire_down(RATE).await;
        assert!(
            permit.waited() >= Duration::from_millis(750),
            "permit wait should approach 1s (full-bucket deficit after continuous draining): {:?}",
            permit.waited()
        );

        // Task buckets are independent: a second task at the same limit
        // shares no tokens (its own cold-start deficit).
        let other = HttpLimiter::new(Some(Arc::new(LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(RATE, 0),
        })));
        let p2 = other.acquire_down(RATE).await;
        assert!(
            p2.waited() >= Duration::from_millis(500),
            "an independent task bucket should have its own deficit: {:?}",
            p2.waited()
        );
    }

    /// Rate-limit smoke for the other path: when the global bucket is
    /// the bottleneck (global < task level) the effective rate = the
    /// global bucket (series order global-then-task; io-layer topology
    /// reused).
    #[tokio::test]
    async fn global_bucket_is_the_bottleneck_when_smaller() {
        const GLOBAL: u64 = 16 * 1024;
        const TASK: u64 = 1024 * 1024;
        let inner = Arc::new(RecordingSink::default());
        let limiter = HttpLimiter::new(Some(Arc::new(LimiterSet {
            global: LimiterPair::new(GLOBAL, 0),
            per_torrent: LimiterPair::new(TASK, 0),
        })));
        let sink = ThrottledSink::new(Arc::clone(&inner) as Arc<dyn SegmentSink>, limiter);

        const TOTAL: usize = 32 * 1024; // 32KiB @16KiB/s ≈ 2s
        let body = Arc::new(vec![1u8; TOTAL]);
        let transport = ChunkTransport(Arc::clone(&body));
        let ext = Extent {
            start: 0,
            len: TOTAL as u64,
        };
        let started = Instant::now();
        transport
            .fetch(&ext, &crate::traits::RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        let theoretical = TOTAL as f64 / GLOBAL as f64;
        assert!(
            started.elapsed().as_secs_f64() >= theoretical * 0.8,
            "global bucket is the bottleneck: {:?} < {theoretical}s x 0.8",
            started.elapsed()
        );
    }

    /// Observation-seam consumption (the RateSampleReporter face): with
    /// a reporter attached, every write reports a
    /// `(source, bytes, permit_waited)` triple — source from SegId,
    /// bytes = permit-released amount, wait non-zero when the rate face
    /// is active; without a reporter (`new`) nothing is reported. The
    /// `Permit::waited` observation seam flows into the coordinator
    /// from here.
    #[tokio::test]
    async fn throttled_sink_reports_rate_samples() {
        use std::sync::Mutex;

        #[derive(Default)]
        struct RecordingReporter {
            samples: Mutex<Vec<(u32, u64, Duration)>>,
        }
        impl RateSampleReporter for RecordingReporter {
            fn report(&self, source: u32, bytes: u64, permit_waited: Duration) {
                self.samples
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((source, bytes, permit_waited));
            }
        }

        let inner = Arc::new(RecordingSink::default());
        let reporter = Arc::new(RecordingReporter::default());
        // Task bucket 32KiB/s: the wait face is observable (non-zero
        // waited).
        let limiter = HttpLimiter::new(Some(Arc::new(LimiterSet {
            global: LimiterPair::new(0, 0),
            per_torrent: LimiterPair::new(32 * 1024, 0),
        })));
        let sink = ThrottledSink::with_rate_reporter(
            Arc::clone(&inner) as Arc<dyn SegmentSink>,
            limiter,
            Arc::clone(&reporter) as Arc<dyn RateSampleReporter>,
        );

        let body = Arc::new(vec![5u8; 8192]);
        let transport = ChunkTransport(Arc::clone(&body));
        let ext = Extent {
            start: 0,
            len: 8192,
        };
        transport
            .fetch(&ext, &crate::traits::RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));

        let samples = reporter
            .samples
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert!(
            !samples.is_empty(),
            "every write should produce an observation sample"
        );
        let total: u64 = samples.iter().map(|(_, b, _)| b).sum();
        assert_eq!(total, 8192, "sample bytes are conserved");
        assert!(
            samples.iter().all(|(s, _, _)| *s == 0),
            "source comes from the SegId accounting domain"
        );
        assert!(
            samples.iter().any(|(_, _, w)| *w > Duration::ZERO),
            "wait durations should be observable under the rate face (Permit::waited non-zero)"
        );

        // No observation face (`new` constructor): the write path is
        // unchanged (no reporter, no reporting path).
        let plain = ThrottledSink::new(
            Arc::clone(&inner) as Arc<dyn SegmentSink>,
            HttpLimiter::new(None),
        );
        transport
            .fetch(&ext, &crate::traits::RequestCtx::default(), &plain)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        assert_eq!(
            inner.bytes.load(std::sync::atomic::Ordering::Relaxed),
            8192 * 2,
            "both constructors behave identically on the write face"
        );
    }
}
