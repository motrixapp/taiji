//! The three segmentation traits and supporting types — the
//! foundation crate's contract with the media layer (the core
//! abstraction, frozen; signature and supporting-type field changes
//! require an ADR).
//!
//! # async signature desugaring trade-off
//!
//! `fetch`/`write_at`/`complete_block` are conceptually `async fn`,
//! but `SegmentTransport::fetch`'s verbatim signature contains
//! `&dyn SegmentSink` — the trait must stay object-safe, and native
//! async fn in trait (RPITIT) is not dyn-compatible; `async-trait` is
//! not in this crate's dependency whitelist. Hence the explicit
//! [`futures::future::BoxFuture`] desugaring
//! (`Pin<Box<dyn Future + Send>>`): a Send future semantically
//! equivalent to async fn, awaitable across actor boundaries;
//! implementors just `Box::pin(async move { .. })` — no macro, no
//! lifetime black hole.
//!
//! # Scheduler-agnostic principle
//!
//! The scheduler is agnostic to both transport and source: dynamic
//! segmentation, adaptive concurrency, and retries apply equally to
//! media segments — the three traits are the frozen face of that
//! decoupling.
//!
//! Upstream anchor mapping: docs/design/http.md
//!
//! Crate positioning (the verbatim lift): this module moved
//! byte-identical from `taiji-http/src/traits.rs` into the vocabulary
//! crate (sibling engines must not depend on the HTTP crate for the
//! segment vocabulary); `taiji-http` re-exports it as its
//! path-stable transition face. The HTTP-only free function
//! `same_origin` (reqwest-coupled) stayed behind in taiji-http.

use bytes::Bytes;
use futures::future::BoxFuture;

use crate::cookies::CookieStore;
use crate::error::Result;

/// Runtime byte range: a block-aligned extent (the runtime layer).
///
/// Extents vanish on completion and are never persisted; the only
/// persistent progress unit is the block grid (held on the
/// core/store side, not modeled in this crate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Extent {
    /// Start (in-file byte offset; block-aligned).
    pub start: u64,
    /// Length (bytes; block-aligned, sub-block extents forbidden —
    /// config domain).
    pub len: u64,
}

impl Extent {
    /// End (exclusive). u64 overflow saturates to [`u64::MAX`] (an
    /// out-of-range extent's `end()` is used only for bound
    /// comparisons; the saturated value keeps verdicts conservative
    /// and never wraps into a false interval).
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    /// Empty-range verdict.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The identity of one segment write (`write_at(seg: SegId, ..)`).
///
/// Its composition was open; this implementation takes the minimal
/// pair (frozen assumption: the field set is final as defined here;
/// changes require an ADR):
/// - `source`: the per-task source ordinal — the accounting domain of
///   multi-source weighting/demotion/removal;
/// - `extent`: the extent ordinal allocated by the ExtentCoordinator
///   (kept through a steal), for sink write-range instrumentation and
///   single-decision-point diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SegId {
    /// Per-task source ordinal (0-based; the weighted-rotation
    /// accounting key).
    pub source: u32,
    /// Per-task extent ordinal (0-based; runtime identity, never
    /// persisted).
    pub extent: u64,
}

/// Per-source request context: headers/UA/referer/cookies/
/// proxy/auth/task cookie store.
///
/// Deliberately transport-agnostic (no reqwest types bound) — the
/// FTP/SFTP adapters build their own protocol faces from the same
/// context.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestCtx {
    /// Explicit UA overriding the default `taiji/<semver>` (honest
    /// identification; spoofing is user-explicit).
    pub user_agent: Option<String>,
    /// Referer header.
    pub referer: Option<String>,
    /// Additional headers (order-preserving pass-through; outbound
    /// strings go through unified redaction).
    pub headers: Vec<(String, String)>,
    /// This source's cookie face (the jar's domain-resolved composite
    /// value; the jar itself is held by the client layer, and
    /// cross-host stripping semantics are enforced at the transport
    /// layer).
    pub cookies: Vec<(String, String)>,
    /// Task cookie store (the task cookie face: per-task isolation;
    /// Set-Cookie captured during download enters this store and is
    /// replayed per RFC 6265 domain/path/Secure; layered under the
    /// explicit cookie pairs — explicit pairs are subject to
    /// cross-host credential stripping, store cookies are naturally
    /// constrained by domain matching). `None` = no store attached
    /// (stateless probe faces etc.).
    pub task_cookies: Option<CookieStore>,
    /// Per-task proxy override (URL userinfo carries proxy auth).
    pub proxy: Option<String>,
    /// Challenge auth face (Basic/Digest).
    pub auth: Option<AuthScheme>,
}

/// Auth scheme (Basic/Digest challenge response).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthScheme {
    /// HTTP Basic.
    Basic { user: String, passwd: String },
    /// HTTP Digest.
    Digest { user: String, passwd: String },
}

/// Resume validator ("signature-stream friendly": the fields are the
/// probe record).
///
/// Semantics: strong ETag or Last-Modified match with equal length →
/// resume; neither present but path+length equal → weak resume (the
/// `weak` marker); mismatch → from zero. With `--checksum` supplied,
/// the checksum is the strongest validator (completion-time final
/// say). The final URL is converged by the manual redirect chain
/// (20-hop cap) into `final_url_path`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResumeValidator {
    /// Final-URL normalized path (path only, query stripped).
    pub final_url_path: String,
    /// Authoritative total length (probe 206 +
    /// `Content-Range: bytes 0-0/TOTAL` TOTAL; `None` for the
    /// no-total form).
    pub total_len: Option<u64>,
    /// Strong ETag only; `W/` weak tags count as missing.
    pub etag: Option<String>,
    /// Last-Modified verbatim.
    pub last_modified: Option<String>,
    /// Response encoding confirmed identity (`Content-Encoding !=
    /// identity` → Range semantics unknowable, bitmap not enabled).
    pub encoding_ok: bool,
}

/// Single-source plan item within the Range domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSource {
    /// Source URI (the redirect-converged final face is booked in the
    /// ResumeValidator).
    pub uri: String,
    /// Transport family (selects the SegmentTransport implementation).
    pub kind: TransportKind,
}

/// Transport family (HttpTransport / FtpTransport / SftpTransport).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// HTTP/HTTPS (plain and mirror alike — they differ in source
    /// count, not transport family).
    Http,
    /// FTP/FTPS.
    Ftp,
    /// SFTP (single-connection model; AIMD acts on pipeline depth).
    Sftp,
}

/// Where segments come from (`SegmentSource::plan`): the Range
/// domain (plain/mirror/FTP/SFTP) or a URI sequence (media).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegmentPlan {
    /// Range-domain multi-source: the source set participating in
    /// segmentation after probe merging.
    Range(Vec<PlanSource>),
    /// Ordered URI sequence: the media form taking segments in order.
    UriSequence(Vec<String>),
}

/// Where segmentation comes from.
///
/// Deliberately not annotated `Send + Sync`, preserving the verbatim
/// signature; when a consumer must hold an implementation across
/// threads, express it as `dyn SegmentSource + Send + Sync` — more
/// evolvable than adding supertraits after the fact (adding
/// supertraits inside a frozen seam is a breaking change).
pub trait SegmentSource {
    /// Returns the source plan: the Range domain
    /// (plain/mirror/FTP/SFTP) or a URI sequence.
    fn plan(&self) -> SegmentPlan;

    /// Returns the probe record's resume-validation face.
    fn validator(&self) -> ResumeValidator;
}

/// How segments are fetched: HttpTransport / FtpTransport /
/// SftpTransport.
///
/// SegmentWorker runs straight-line async: claim extent → `fetch` →
/// streamed sink writes → progress heartbeat (block-level and
/// byte-level). Failures go to the scheduler for retry/demotion/
/// removal (3 consecutive failures demote, 5 remove).
pub trait SegmentTransport: Send + Sync {
    /// Fetches the range named by `seg` and streams it into `sink`
    /// (the write point advances by block boundaries; same-block
    /// double writes are legal — accounting defers to
    /// `complete_block`'s single decision point).
    fn fetch<'a>(
        &'a self,
        seg: &'a Extent,
        ctx: &'a RequestCtx,
        sink: &'a dyn SegmentSink,
    ) -> BoxFuture<'a, Result<()>>;
}

/// Where segments go: core supplies the store implementation (this
/// crate does not depend on taiji-store — disk writes are injected
/// through this trait).
pub trait SegmentSink: Send + Sync {
    /// Positional write of segment bytes (`off` = in-file absolute
    /// byte offset).
    ///
    /// Same-block double writes under steal races are allowed: worst
    /// case wasted bandwidth, never interleaved corruption;
    /// accounting defers to `complete_block`'s first-report-wins
    /// below. Implementations should support a concurrent call face
    /// consistent with disk writes (blocking IO belongs to the
    /// implementation's spawn_blocking side).
    fn write_at(&self, seg: SegId, off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>>;

    /// Block-completion accounting (block-grid index) — the only
    /// entry point to the persisted bitmap; adjudicated serially at
    /// the ExtentCoordinator's single decision point: first report
    /// wins, late reports dropped (stealing is banned in endgame by
    /// the scheduler side).
    fn complete_block(&self, block: u64) -> BoxFuture<'_, Result<()>>;
}

/// Test/example sink: discards byte content, counts only written
/// bytes and completed blocks — for this crate's unit tests and as a
/// reference implementation for downstream mocks (not a production
/// write path).
#[derive(Debug, Default)]
pub struct NoopSink {
    written: std::sync::atomic::AtomicU64,
    blocks: std::sync::atomic::AtomicU64,
}

impl NoopSink {
    /// Total bytes written (and discarded).
    pub fn written_bytes(&self) -> u64 {
        self.written.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Number of blocks recorded complete.
    pub fn completed_blocks(&self) -> u64 {
        self.blocks.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl SegmentSink for NoopSink {
    fn write_at(&self, _seg: SegId, _off: u64, bytes: Bytes) -> BoxFuture<'_, Result<()>> {
        use std::sync::atomic::Ordering;
        self.written
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Box::pin(std::future::ready(Ok(())))
    }

    fn complete_block(&self, _block: u64) -> BoxFuture<'_, Result<()>> {
        use std::sync::atomic::Ordering;
        self.blocks.fetch_add(1, Ordering::Relaxed);
        Box::pin(std::future::ready(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HttpError;
    use std::sync::Arc;

    /// Test source: fixed plan + fixed validator.
    struct FixedSource(SegmentPlan, ResumeValidator);

    impl SegmentSource for FixedSource {
        fn plan(&self) -> SegmentPlan {
            self.0.clone()
        }
        fn validator(&self) -> ResumeValidator {
            self.1.clone()
        }
    }

    /// Test transport: streams the in-memory body to the sink in
    /// small chunks by extent range, then records each covered grid
    /// block (test grid = 4 bytes/block).
    struct SliceTransport(Arc<Vec<u8>>);

    impl SegmentTransport for SliceTransport {
        fn fetch<'a>(
            &'a self,
            seg: &'a Extent,
            _ctx: &'a RequestCtx,
            sink: &'a dyn SegmentSink,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                let body = self.0.as_slice();
                let end = seg.end();
                if seg.end() > body.len() as u64 {
                    return Err(HttpError::BadRange);
                }
                let seg_id = SegId {
                    source: 0,
                    extent: 0,
                };
                let mut off = seg.start;
                while off < end {
                    let n = 4usize.min((end - off) as usize);
                    let bytes = Bytes::copy_from_slice(&body[off as usize..off as usize + n]);
                    sink.write_at(seg_id, off, bytes).await?;
                    off += n as u64;
                }
                // Test grid fixed at 4 bytes/block: fully covers 2
                // blocks (no half-block tail simulated).
                sink.complete_block(0).await?;
                sink.complete_block(1).await?;
                Ok(())
            })
        }
    }

    #[test]
    fn noop_sink_round_trip_via_dyn_sink() {
        let body: Vec<u8> = (0u8..=8).collect(); // 9 bytes → 9B extent → 2 blocks + 1B tail
        let transport = SliceTransport(Arc::new(body));
        let source = FixedSource(
            SegmentPlan::Range(vec![PlanSource {
                uri: "http://example.test/a".into(),
                kind: TransportKind::Http,
            }]),
            ResumeValidator {
                final_url_path: "/a".into(),
                total_len: Some(9),
                encoding_ok: true,
                ..ResumeValidator::default()
            },
        );

        // Frozen face: the source side is synchronously queryable.
        assert_eq!(
            source.plan(),
            SegmentPlan::Range(vec![PlanSource {
                uri: "http://example.test/a".into(),
                kind: TransportKind::Http,
            }])
        );
        assert_eq!(source.validator().total_len, Some(9));

        // dyn compatibility is an explicit requirement of the frozen
        // seam: fetch's verbatim signature takes &dyn SegmentSink.
        let sink = NoopSink::default();
        let dyn_sink: &dyn SegmentSink = &sink;
        let extent = Extent { start: 0, len: 9 };
        let res =
            futures::executor::block_on(transport.fetch(&extent, &RequestCtx::default(), dyn_sink));
        assert!(res.is_ok(), "fetch failed: {res:?}");
        assert_eq!(sink.written_bytes(), 9);
        assert_eq!(sink.completed_blocks(), 2);
    }

    #[test]
    fn extent_arithmetics_and_bad_range_propagation() {
        let e = Extent {
            start: 4 * 1024 * 1024,
            len: 4 * 1024 * 1024,
        };
        assert_eq!(e.end(), 8 * 1024 * 1024);
        assert!(!e.is_empty());
        assert!(Extent { start: 0, len: 0 }.is_empty());

        // u64 overflow protection: start + len beyond range saturates
        // to u64::MAX, never wraps.
        let max = Extent {
            start: u64::MAX,
            len: 1,
        };
        assert_eq!(max.end(), u64::MAX);
        let wrap = Extent {
            start: u64::MAX - 3,
            len: 10,
        };
        assert_eq!(wrap.end(), u64::MAX);

        // Extent beyond the authoritative body length →
        // taiji.http.bad_range.
        let transport = SliceTransport(Arc::new(vec![0u8; 8]));
        let sink = NoopSink::default();
        let big = Extent { start: 0, len: 16 };
        let res = futures::executor::block_on(transport.fetch(&big, &RequestCtx::default(), &sink));
        assert_eq!(res, Err(HttpError::BadRange));
        assert_eq!(sink.written_bytes(), 0);
    }

    #[test]
    fn uri_sequence_plan_and_request_ctx_defaults() {
        let source = FixedSource(
            SegmentPlan::UriSequence(vec!["http://example.test/seg0.ts".into()]),
            ResumeValidator::default(),
        );
        assert!(matches!(source.plan(), SegmentPlan::UriSequence(_)));
        assert_eq!(source.validator(), ResumeValidator::default());

        let ctx = RequestCtx {
            auth: Some(AuthScheme::Basic {
                user: "u".into(),
                passwd: "p".into(),
            }),
            ..RequestCtx::default()
        };
        assert!(ctx.proxy.is_none());
        assert!(ctx.headers.is_empty());
    }
}
