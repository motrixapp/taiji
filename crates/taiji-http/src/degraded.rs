//! Single-connection degraded path: no grid, no bitmap, no offset
//! resume — recovery always starts from zero (same boundary as the
//! [`crate::scheduler`] module docs). Taken when extent scheduling
//! cannot serve the task: all sources are 200 with no authoritative
//! total length ([`DegradedReason::NoTotalLength`]), or the encoding
//! is not identity so Range semantics are unknown
//! ([`DegradedReason::NonIdentityEncoding`]), plus the FTP no-REST
//! and single-connection-cap forms. Pipeline in [`DegradedJob::run`]:
//! plan_output -> PartFile::open (Restart) -> SegmentTransport::fetch
//! into the sink chain -> sync_all -> close -> Finalizer::finalize.
//! A stale `.part` is always truncated regardless of length
//! ([`crate::naming::decide_part_reuse`]).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::info;

use crate::error::HttpError;
use crate::finalize::{FinalizeOutcome, Finalizer, RenameIntent};
use crate::limiter::{HttpLimiter, ThrottledSink};
use crate::naming::{
    CreationPolicy, IncompleteSuffix, PartReuse, decide_part_reuse, part_path_for, plan_output,
};
use crate::partfile::{FileAllocation, FileSink, HandlesClosed, PartFile, PartOpenPolicy};
use crate::traits::{RequestCtx, ResumeValidator, SegmentSink, SegmentTransport};

/// Degraded reason (probe/validation decision output; `None` = Range-domain task, grid scheduling).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradedReason {
    /// No authoritative total length (no-range: all sources are 200).
    NoTotalLength,
    /// Response encoding is not identity: Range semantics unknown, bitmap disabled.
    NonIdentityEncoding,
    /// FTP server rejected `REST 0` (decided by `crate::ftp::FtpProbe`):
    /// single-stream degraded with no bitmap (resume from zero); no new
    /// persistence form.
    FtpNoResume,
}

/// Degraded decision (input from probe/validation): the negation of
/// grid eligibility.
///
/// The REST decision for FTP happens in the transport probe
/// ([`crate::ftp::FtpProbe::resume_supported`]); this function only
/// consumes the HTTP-side fields of ResumeValidator. `FtpNoResume` is
/// routed by the scheduler and does not pass through this decision.
pub fn degraded_reason(validator: &ResumeValidator) -> Option<DegradedReason> {
    if validator.total_len.is_none() {
        Some(DegradedReason::NoTotalLength)
    } else if !validator.encoding_ok {
        Some(DegradedReason::NonIdentityEncoding)
    } else {
        None
    }
}

/// Degraded download job parameters (the [`DegradedJob`] payload;
/// assembled once after creation-time resolution, then immutable for
/// the task's lifetime).
pub struct DegradedJob {
    /// 16-hex GID.
    pub gid: String,
    /// Target path after creation-time resolution (the [`plan_output`] product).
    pub final_path: PathBuf,
    /// Incomplete suffix for the task (value persisted at creation).
    pub suffix: IncompleteSuffix,
    /// Authoritative payload length of this connection
    /// (`Content-Length`; the EOF-streamed no-length form is an HTTP
    /// transport adaptation and lands on disk through the same sink).
    pub total_len: u64,
    /// `--file-allocation` placement.
    pub allocation: FileAllocation,
    /// Task rate limit (write-path gate): the sink is wrapped in
    /// [`ThrottledSink`] — degraded/EOF flows follow the same rate
    /// discipline as the grid path (a bare [`FileSink`] bypassing the
    /// limiter was a review defect). `None` bucket = pass-through
    /// (bare CLI runs).
    pub limiter: HttpLimiter,
    /// `--checksum` streaming digest feed seam (finalization
    /// pipelining): when set, the write path feeds disk-bound bytes to
    /// the callback in order via [`crate::checksum::TeeSink`] (a
    /// single-connection sequential stream's write order is the byte
    /// order — zero coordination; the hasher itself and the final
    /// comparison belong to core). `None` = disabled; the sink chain
    /// stays byte-identical to the existing one.
    pub checksum_feed: Option<crate::checksum::ByteFeed>,
}

impl DegradedJob {
    /// Run the full pipeline synchronously (execution order in [`download_degraded`]).
    pub async fn run(
        &self,
        transport: &dyn SegmentTransport,
        ctx: &RequestCtx,
        finalizer: &Finalizer,
    ) -> Result<FinalizeOutcome, HttpError> {
        download_degraded(self, transport, ctx, finalizer).await
    }

    /// Run in the background (for task-line assembly; join to
    /// completion, no dangling tasks).
    pub fn spawn(
        self: Arc<Self>,
        transport: Arc<dyn SegmentTransport>,
        ctx: RequestCtx,
        finalizer: Arc<Finalizer>,
    ) -> JoinHandle<Result<FinalizeOutcome, HttpError>> {
        tokio::spawn(async move {
            download_degraded(&self, transport.as_ref(), &ctx, finalizer.as_ref()).await
        })
    }
}

/// Degraded download full pipeline (single connection, no bitmap,
/// resume always from zero; the function body is the execution order).
///
/// - Precondition: the caller has run the creation-time checks
///   ([`plan_output`]) — this function re-runs the `.part` reuse
///   decision to pin "resume from zero" (degraded always maps to
///   `Restart`; a non-degraded input decides by length);
/// - `job.total_len`: see [`DegradedJob::total_len`].
///
/// Returns the rename finalization outcome; `Err` = a task-level
/// failure in disk or journal writes.
async fn download_degraded(
    job: &DegradedJob,
    transport: &dyn SegmentTransport,
    ctx: &RequestCtx,
    finalizer: &Finalizer,
) -> Result<FinalizeOutcome, HttpError> {
    let DegradedJob {
        gid,
        final_path,
        suffix,
        total_len,
        allocation,
        limiter,
        checksum_feed,
    } = job;
    let part_path = part_path_for(final_path, suffix);

    // Resume from zero (degraded is always Restart; the decision's
    // unit tests live in naming — this is where it executes).
    let reuse = decide_part_reuse(&part_path, Some(*total_len), true)?;
    debug_assert_eq!(
        reuse,
        PartReuse::Restart,
        "degraded-task resume always restarts from zero"
    );
    let _ = reuse;

    let part = PartFile::open(
        part_path,
        Some(*total_len),
        PartOpenPolicy::Restart,
        *allocation,
    )
    .await?;
    // Rate gate: the write path must go through ThrottledSink (permit
    // first, inner write second) — the degraded path must not bypass
    // rate limiting just because it has no bitmap. Checksum
    // pipelining: with `--checksum` set the inner sink becomes a
    // TeeSink (bytes between the rate permit and the disk write feed
    // the digest callback in order — a sequential stream's write order
    // is the byte order, zero coordination; the final digest value is
    // compared by the core-side callback holder).
    let sink: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::new(
        Arc::new(crate::checksum::TeeSink::new(
            Arc::new(FileSink::new(part.clone())) as Arc<dyn SegmentSink>,
            checksum_feed.clone(),
        )) as Arc<dyn SegmentSink>,
        limiter.clone(),
    ));

    // Single connection: one extent covers the whole file (no grid,
    // no pieces, no offset resume).
    let extent = crate::traits::Extent {
        start: 0,
        len: *total_len,
    };
    transport.fetch(&extent, ctx, sink.as_ref()).await?;

    // Data lands before the completion intent (in the bitmap-less
    // degraded form, fsync is the on-disk equivalent of the
    // "fsync before snapshot" ordering invariant).
    part.sync_all().await?;
    // Close the handle before rename (Windows/SMB handle-sharing and
    // oplock constraints).
    let closed: HandlesClosed = part.close();

    let intent = RenameIntent {
        gid: gid.clone(),
        part_path: part_path_for(final_path, suffix),
        final_path: final_path.clone(),
        expected_len: *total_len,
    };
    info!(target: "taiji::http::degraded", gid = %gid,
        path = %intent.final_path.display(), len = total_len,
        "degraded download complete; finalizing rename");
    finalizer.finalize(&intent, closed).await
}

/// Creation-time output resolution (entry point for degraded jobs:
/// conflict check + auto-file-renaming + configured suffix; a
/// re-export wrapper around [`plan_output`] pinning the call order —
/// once at creation, results consumed by [`download_degraded`].
/// `holder` = task gid: the placeholder key for the final path,
/// released at finalize completion/task removal).
pub fn resolve_output(
    final_path: PathBuf,
    suffix: &IncompleteSuffix,
    policy: CreationPolicy,
    holder: &str,
) -> Result<(PathBuf, PathBuf), HttpError> {
    let plan = plan_output(final_path, suffix, policy, holder)?;
    Ok((plan.final_path, plan.part_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalize::{ExponentialBackoff, FsOps, MemoryJournal, PathOps, RenameJournal};
    use bytes::Bytes;
    use futures::future::BoxFuture;
    use std::time::Instant;
    use taiji_io::rate_limit::{LimiterPair, LimiterSet};

    /// Fixture: single-connection transport streaming an in-memory
    /// body to the sink in 7-byte chunks (same fixture idea as
    /// `tests/probe_mock.rs`; no network in-process).
    struct BodyTransport {
        body: Arc<Vec<u8>>,
        fetches: AtomicCount,
    }

    type AtomicCount = std::sync::atomic::AtomicU32;

    impl SegmentTransport for BodyTransport {
        fn fetch<'a>(
            &'a self,
            seg: &'a crate::traits::Extent,
            _ctx: &'a RequestCtx,
            sink: &'a dyn crate::traits::SegmentSink,
        ) -> BoxFuture<'a, Result<(), HttpError>> {
            Box::pin(async move {
                self.fetches
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = self.body.as_slice();
                if seg.start != 0 || seg.end() > body.len() as u64 {
                    return Err(HttpError::BadRange);
                }
                let seg_id = crate::traits::SegId {
                    source: 0,
                    extent: 0,
                };
                let mut off = seg.start;
                while off < seg.end() {
                    let n = 7usize.min((seg.end() - off) as usize);
                    sink.write_at(
                        seg_id,
                        off,
                        Bytes::copy_from_slice(&body[off as usize..off as usize + n]),
                    )
                    .await?;
                    off += n as u64;
                }
                Ok(())
            })
        }
    }

    fn tempdir(tag: &str) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("taiji-http-deg-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
        path
    }

    /// Degraded decision: no total length / non-identity encoding →
    /// degraded; complete → grid eligible.
    #[test]
    fn degraded_reason_matrix() {
        let base = ResumeValidator {
            final_url_path: "/f".into(),
            total_len: Some(64),
            encoding_ok: true,
            ..ResumeValidator::default()
        };
        assert_eq!(
            degraded_reason(&base),
            None,
            "Range domain -> grid eligible"
        );
        assert_eq!(
            degraded_reason(&ResumeValidator {
                total_len: None,
                ..base.clone()
            }),
            Some(DegradedReason::NoTotalLength)
        );
        assert_eq!(
            degraded_reason(&ResumeValidator {
                encoding_ok: false,
                ..base
            }),
            Some(DegradedReason::NonIdentityEncoding)
        );
    }

    /// Degraded-path fixture: a stale `.part` whose length happens to
    /// match → truncate and restart from zero → correct bytes on disk
    /// → handles closed → intent before action → rename lands, target
    /// content == authoritative body, `.part` gone, journal empty.
    /// Single-connection is pinned by fetch count == 1.
    #[tokio::test]
    async fn degraded_fixture_restarts_from_zero_and_finalizes() {
        let dir = tempdir("fixture");
        let suffix = IncompleteSuffix::default();
        let body: Vec<u8> = (0u8..=100).collect(); // 101B: tail not chunk-aligned
        let final_path = dir.join("clip.bin");

        // Adversarial shape: stale .part whose length happens to match
        // (degraded still must not resume).
        let stale = part_path_for(&final_path, &suffix);
        std::fs::write(&stale, vec![0xFF; body.len()]).unwrap_or_else(|e| panic!("seed: {e}"));

        let journal = Arc::new(MemoryJournal::default());
        let fin = Finalizer::with_injection(
            Arc::clone(&journal) as Arc<dyn RenameJournal>,
            Arc::new(FsOps) as Arc<dyn PathOps>,
            Arc::new(ExponentialBackoff {
                base: std::time::Duration::ZERO,
            }),
        );

        let transport = BodyTransport {
            body: Arc::new(body.clone()),
            fetches: AtomicCount::new(0),
        };
        let job = DegradedJob {
            gid: "8000000000000007".into(),
            final_path: final_path.clone(),
            suffix,
            total_len: body.len() as u64,
            allocation: FileAllocation::Prealloc,
            limiter: HttpLimiter::new(None),
            checksum_feed: None,
        };
        let outcome = job
            .run(&transport, &RequestCtx::default(), &fin)
            .await
            .unwrap_or_else(|e| panic!("degraded download: {e}"));

        assert!(matches!(outcome, FinalizeOutcome::Completed { .. }));
        assert_eq!(
            std::fs::read(&final_path).unwrap_or_else(|e| panic!("read: {e}")),
            body,
            "on-disk content == authoritative body (stale bytes truncated and re-downloaded)"
        );
        assert!(!stale.exists(), "`.part` gone via rename");
        assert!(
            journal.load_pending().await.unwrap_or_default().is_empty(),
            "journal closes once the rename lands"
        );
        assert_eq!(
            transport.fetches.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "single connection: exactly one fetch"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Background execution: spawn joins to completion, no dangling
    /// tasks; result matches the direct call.
    #[tokio::test]
    async fn spawn_face_joins_to_completion() {
        let dir = tempdir("spawn");
        let suffix = IncompleteSuffix::parse(".dl").unwrap_or_else(|e| panic!("sfx: {e}"));
        let body = b"spawn degraded body".to_vec();
        let final_path = dir.join("sp.bin");

        let journal = Arc::new(MemoryJournal::default());
        let fin = Arc::new(Finalizer::with_injection(
            Arc::clone(&journal) as Arc<dyn RenameJournal>,
            Arc::new(FsOps) as Arc<dyn PathOps>,
            Arc::new(ExponentialBackoff {
                base: std::time::Duration::ZERO,
            }),
        ));
        let handle = Arc::new(DegradedJob {
            gid: "8000000000000008".into(),
            final_path: final_path.clone(),
            suffix,
            total_len: body.len() as u64,
            allocation: FileAllocation::None,
            limiter: HttpLimiter::new(None),
            checksum_feed: None,
        })
        .spawn(
            Arc::new(BodyTransport {
                body: Arc::new(body.clone()),
                fetches: AtomicCount::new(0),
            }),
            RequestCtx::default(),
            fin,
        );
        let outcome = handle
            .await
            .unwrap_or_else(|e| panic!("join: {e}"))
            .unwrap_or_else(|e| panic!("download: {e}"));
        assert!(matches!(outcome, FinalizeOutcome::Completed { .. }));
        assert_eq!(
            std::fs::read(&final_path).unwrap_or_else(|e| panic!("read: {e}")),
            body
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Checksum pipelining (degraded path): with `checksum_feed` set,
    /// every byte the download stream writes reaches the callback in
    /// disk-write order (a sequential stream = coordination-free tee);
    /// the concatenated callback bytes == the authoritative body —
    /// the core-side hasher can fix the final value at fetch
    /// completion, so finalization never re-reads the file. The
    /// disabled case (`None`) is pinned by the existing tests (zero
    /// behavior change).
    #[tokio::test]
    async fn degraded_checksum_feed_sees_all_bytes_in_order() {
        use sha2::Digest as _;
        let dir = tempdir("csfeed");
        let suffix = IncompleteSuffix::default();
        let body: Vec<u8> = (0..40_000u32).map(|i| (i % 249) as u8).collect();
        let final_path = dir.join("cs.bin");

        let journal = Arc::new(MemoryJournal::default());
        let fin = Finalizer::with_injection(
            Arc::clone(&journal) as Arc<dyn RenameJournal>,
            Arc::new(FsOps) as Arc<dyn PathOps>,
            Arc::new(ExponentialBackoff {
                base: std::time::Duration::ZERO,
            }),
        );
        // Hasher + callback (same shape as the core assembly: Mutex
        // holder, fed from the write path).
        let digest = Arc::new(std::sync::Mutex::new(sha2::Sha256::new()));
        let digest_t = Arc::clone(&digest);
        let feed: crate::checksum::ByteFeed = Arc::new(move |b: &[u8]| {
            use sha2::Digest as _;
            digest_t.lock().unwrap_or_else(|e| e.into_inner()).update(b);
        });
        let transport = BodyTransport {
            body: Arc::new(body.clone()),
            fetches: AtomicCount::new(0),
        };
        let job = DegradedJob {
            gid: "8000000000000009".into(),
            final_path: final_path.clone(),
            suffix,
            total_len: body.len() as u64,
            allocation: FileAllocation::None,
            limiter: HttpLimiter::new(None),
            checksum_feed: Some(feed),
        };
        let outcome = job
            .run(&transport, &RequestCtx::default(), &fin)
            .await
            .unwrap_or_else(|e| panic!("degraded download: {e}"));
        assert!(matches!(outcome, FinalizeOutcome::Completed { .. }));
        // Fixed at fetch completion: the callback-accumulated digest ==
        // one whole-body hash (no file re-read).
        fn to_hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let got = to_hex(
            &digest
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .finalize(),
        );
        assert_eq!(got, to_hex(&sha2::Sha256::digest(&body)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Degraded-path rate gate: the degraded stream must not bypass
    /// rate limiting — the sink is wrapped in [`ThrottledSink`] (a
    /// bare [`FileSink`] let degraded/EOF flows escape `--limit-rate`).
    /// The task bucket throttles throughput: transfer time >= the
    /// theoretical value × tolerance floor (same criterion as the
    /// limiter module).
    #[tokio::test]
    async fn degraded_download_respects_rate_limit() {
        const RATE: u64 = 64 * 1024; // 64KiB/s
        let dir = tempdir("throttle");
        let suffix = IncompleteSuffix::default();
        let body: Vec<u8> = vec![7u8; 48 * 1024]; // 48KiB @64KiB/s ≈ 0.75s
        let final_path = dir.join("t.bin");

        let journal = Arc::new(MemoryJournal::default());
        let fin = Finalizer::with_injection(
            Arc::clone(&journal) as Arc<dyn RenameJournal>,
            Arc::new(FsOps) as Arc<dyn PathOps>,
            Arc::new(ExponentialBackoff {
                base: std::time::Duration::ZERO,
            }),
        );
        let transport = BodyTransport {
            body: Arc::new(body.clone()),
            fetches: AtomicCount::new(0),
        };
        let job = DegradedJob {
            gid: "8000000000000009".into(),
            final_path: final_path.clone(),
            suffix,
            total_len: body.len() as u64,
            allocation: FileAllocation::None,
            checksum_feed: None,
            limiter: HttpLimiter::new(Some(Arc::new(LimiterSet {
                global: LimiterPair::new(0, 0),
                per_torrent: LimiterPair::new(RATE, 0),
            }))),
        };

        let started = Instant::now();
        let outcome = job
            .run(&transport, &RequestCtx::default(), &fin)
            .await
            .unwrap_or_else(|e| panic!("degraded download: {e}"));
        let elapsed = started.elapsed();
        assert!(matches!(outcome, FinalizeOutcome::Completed { .. }));
        let theoretical = body.len() as f64 / RATE as f64;
        assert!(
            elapsed.as_secs_f64() >= theoretical * 0.8,
            "degraded path bypassed rate limiting: {elapsed:?} < {theoretical}s x 0.8"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Creation-time resolution entry: the clean path passes the
    /// (final, part) pair through.
    #[test]
    fn resolve_output_clean_path() {
        let dir = tempdir("resolve");
        let suffix = IncompleteSuffix::default();
        let (final_path, part_path) = resolve_output(
            dir.join("r.bin"),
            &suffix,
            CreationPolicy::default(),
            "8000000000000008",
        )
        .unwrap_or_else(|e| panic!("resolve: {e}"));
        assert_eq!(final_path, dir.join("r.bin"));
        assert_eq!(part_path, dir.join("r.bin.part"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
