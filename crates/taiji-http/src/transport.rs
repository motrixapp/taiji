//! HTTP implementation of [`SegmentTransport`]: Range-domain extent
//! fetches plus the degraded single-connection GET — the protocol
//! implementation face of the foundation crate.
//!
//! Assembly contract (invariants):
//! - one instance per worker (bound to its URI/source ordinal — the
//!   per-source accounting key propagates for real; EWMA-weighted
//!   share arbitration belongs to the coordinator);
//! - after claiming an extent and before `fetch`, the worker
//!   registers the allocated extent ordinal via
//!   [`HttpRangeTransport::arm`] (the frozen trait signature carries
//!   no `SegId`; this method is the `SegId` carrier seam);
//! - disk writes go through the injected [`SegmentSink`] (this crate
//!   does not depend on taiji-store; the DB/bitmap pipeline belongs
//!   to the core-side sink implementation).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::future::BoxFuture;
use tracing::warn;

use crate::client::HttpClient;
use crate::error::{HttpError, Result, note_http_error};
use crate::retry::parse_retry_after;
use crate::traits::{Extent, RequestCtx, SegId, SegmentSink, SegmentTransport, same_origin};
use taiji_io::metrics::MetricsRegistry;

/// HTTP 206 Partial Content (RFC 9110 §15.3.7).
pub const HTTP_PARTIAL_CONTENT: u16 = 206;

/// HTTP 200 OK (a download-phase Range request answered with 200 =
/// capability drift, explicit failure via [`HttpError::RangeIgnored`]).
pub const HTTP_OK: u16 = 200;

/// HTTP 429 Too Many Requests (server throttling signature — AIMD
/// multiplicative-decrease trigger).
pub const HTTP_TOO_MANY_REQUESTS: u16 = 429;

/// HTTP 503 Service Unavailable (reads `Retry-After` — throttling or
/// temporary unavailability, like 429).
pub const HTTP_SERVICE_UNAVAILABLE: u16 = 503;

/// HTTP 412 Precondition Failed (If-Match conditional resume against
/// changed content).
pub const HTTP_PRECONDITION_FAILED: u16 = 412;

/// Absolute cap for unknown-length EOF streams (1 TiB).
///
/// Rationale: a sanity bound for unknown-length downloads (no
/// Content-Length; an encoded entity length is not authoritative).
/// Identity streams have no amplification — real large files can
/// declare a Content-Length (bounded form, not subject to this cap)
/// or support Range and go through the grid; encoded amplification
/// (gzip decompression bombs >1000:1) is cut off here. Uncapped, a
/// malicious endless stream never trips the read-idle timeout (the
/// 60s timer only advances without progress) and writes and
/// decompression would continue to ENOSPC. Cross-validation: aria2
/// has no corresponding cap (its single-connection face is equally
/// unguarded); this cap is a deliberate tightening.
pub const MAX_UNBOUNDED_STREAM_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// Single-connection read-loop step decision (pure function — the
/// unit-testable overrun/over-cap verdict face).
///
/// Inputs: `off` = the landing point (the next write position after
/// this chunk, i.e. current write point + `chunk.len()`); `end` =
/// exclusive extent end; `cap` = the absolute cap
/// ([`MAX_UNBOUNDED_STREAM_BYTES`] for the unknown-length form,
/// `u64::MAX` for the bounded form — real large files can declare a
/// Content-Length; the cap only cuts off amplification of the
/// unknown-length form). Effective bound = `end.min(cap)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyStreamStep {
    /// Within the bound (including exactly at the bound — being full
    /// is not itself an error; the bytes **after** full are: exact
    /// full + EOF = clean close).
    Within,
    /// Beyond: bounded form = server over-send (declared N at probe,
    /// sent more at download — drift evidence, task failure);
    /// unknown-length form = past the absolute cap.
    Beyond,
}

/// Whether the decision landing point exceeds the effective bound
/// (bound semantics in [`BodyStreamStep`]).
pub fn body_stream_step(off: u64, end: u64, cap: u64) -> BodyStreamStep {
    if off <= end.min(cap) {
        BodyStreamStep::Within
    } else {
        BodyStreamStep::Beyond
    }
}

/// Absolute-cap selection for an extent: the bounded form (declared
/// length within the engine's declared-length domain
/// [`crate::grid::MAX_TOTAL_LEN`]) is uncapped; the unknown-length
/// form (length beyond that domain — a declared length over the
/// domain is already rejected task-level at the probe face, so only
/// the EOF-delimited sentinel `u64::MAX-1` can exceed it) takes
/// [`MAX_UNBOUNDED_STREAM_BYTES`].
pub fn stream_cap(seg: &Extent) -> u64 {
    if seg.len > crate::grid::MAX_TOTAL_LEN {
        MAX_UNBOUNDED_STREAM_BYTES
    } else {
        u64::MAX
    }
}

/// Outbound URI redaction (strips query/fragment): the local minimal
/// face of unified redaction — outbound strings in logs/error text
/// pass through here; shared crate-wide (same face in the worker
/// ring's FTP build-failure arm).
pub(crate) fn redact_uri(uri: &str) -> String {
    uri.split(['?', '#']).next().unwrap_or(uri).to_string()
}

/// Range-domain transport (grid path): GET `Range: bytes=start-end`
/// → 206 validation → streamed chunks written to the sink (absolute
/// offset advance).
pub struct HttpRangeTransport {
    client: HttpClient,
    /// Source-entry URI (accounting key / fallback face — the
    /// starting point when re-walking the original redirect chain
    /// after a `request_uri` hop failure).
    uri: String,
    /// Data-plane request start URL: the redirect-final URL converged
    /// at probe time (`ProbeResult::final_url`). Extent requests jump
    /// straight from the final URL instead of re-walking the redirect
    /// chain per request — saving a source round trip per block and a
    /// per-worker keep-alive/TLS connection to the origin. Mirrors
    /// aria2 `Request`'s redirected-URI cache semantics (final URL
    /// pinned; re-resolve on invalidation). `None` = disabled (for
    /// multi-source tasks the convergence holds only for the
    /// authoritative source; the source-entry URI conservatively
    /// re-walks the chain). A start-hop transport error falls back to
    /// `uri` and re-walks the chain once; success self-heals the start
    /// (mirror rotation/invalidation re-resolve).
    request_uri: Option<StdMutex<String>>,
    /// Per-task source ordinal (worker-bound source — the real
    /// accounting key for static source splitting; `SegId` carries
    /// real values, never a fabricated `SegId{0,0}`).
    source: u32,
    /// Ordinal of the extent currently in flight (written before every
    /// fetch with the coordinator's `Allocation.seg.extent` value —
    /// the runtime identity travels with the allocation).
    extent: AtomicU64,
    /// Metrics registry (extent-level feed seam for
    /// `request_seconds{phase=total}`; injected at assembly — tests
    /// use an independent instance, production the process default).
    metrics: Arc<MetricsRegistry>,
}

impl HttpRangeTransport {
    /// Assembly (constructor args are the whole protocol face:
    /// client / source-entry URI / optional start URL / source
    /// ordinal / metrics registry; the in-flight extent ordinal starts
    /// at 0 and travels via `arm`). `request_uri` is injected for
    /// single-source tasks only — the authoritative probe face is this
    /// source; for multi-source tasks the convergence holds only for
    /// the authoritative source, so pass `None` to re-walk the chain
    /// conservatively.
    pub fn new(
        client: HttpClient,
        uri: String,
        request_uri: Option<String>,
        source: u32,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            client,
            uri,
            request_uri: request_uri.map(StdMutex::new),
            source,
            extent: AtomicU64::new(0),
            metrics,
        }
    }

    /// Registers the coordinator-allocated extent ordinal before
    /// fetch (the `SegId` carrier seam — the frozen trait signature
    /// carries no `SegId`; the allocation lands here before fetch).
    pub fn arm(&self, seg: SegId) {
        self.extent.store(seg.extent, Ordering::Relaxed);
    }

    /// The identity currently written (real source ordinal + in-flight
    /// extent ordinal).
    fn seg_id(&self) -> SegId {
        SegId {
            source: self.source,
            extent: self.extent.load(Ordering::Relaxed),
        }
    }

    /// Data-plane start URL and request context (when `request_uri`
    /// and `uri` differ in origin, challenge credentials are stripped
    /// — the manual redirect loop's keep_credentials cross-endpoint
    /// stripping semantics: a 302 across hosts carries no
    /// Authorization anyway, and the start hop follows the same rule;
    /// same-origin keeps ctx as-is, 401 challenge-response unchanged).
    fn start_ctx(&self, ctx: &RequestCtx) -> (String, Option<RequestCtx>) {
        let Some(lock) = &self.request_uri else {
            return (self.uri.clone(), None);
        };
        let cur = crate::lock(lock).clone();
        if same_origin(&cur, &self.uri) {
            return (cur, None);
        }
        (
            cur,
            Some(RequestCtx {
                auth: None,
                ..ctx.clone()
            }),
        )
    }

    /// Start-URL self-heal: after a successful fallback through the
    /// original chain, update the start to the final URL (mirror
    /// rotation re-resolve; on failure the old value stays and the
    /// next extent retry tries again).
    fn note_final(&self, final_url: &str) {
        if let Some(lock) = &self.request_uri
            && let Ok(mut cur) = lock.lock()
        {
            *cur = final_url.to_string();
        }
    }

    /// Fetch body (the face wrapped by phase timing — all exits
    /// converge on the feed point of
    /// [`SegmentTransport for HttpRangeTransport`]).
    async fn fetch_body(
        &self,
        seg: &Extent,
        ctx: &RequestCtx,
        sink: &dyn SegmentSink,
    ) -> Result<()> {
        let end_incl = seg.end().saturating_sub(1);
        // Start URL (see the `request_uri` field doc): dial the
        // probe-converged final URL directly; strip challenge
        // credentials across origins. On a start-hop transport error
        // with start != source-entry URI, fall back and re-walk the
        // original chain once (the redirect chain is the only
        // authoritative mirror-discovery face — mirror
        // invalidation/rotation re-resolves here; success self-heals
        // the start via [`Self::note_final`]).
        let (start_url, stripped) = self.start_ctx(ctx);
        let ctx_ref: &RequestCtx = stripped.as_ref().unwrap_or(ctx);
        let followed = match self
            .client
            .get_range(&start_url, ctx_ref, seg.start, end_incl)
            .await
        {
            Ok(f) => f,
            Err(e) if start_url != self.uri => {
                warn!(target: "taiji::http::transport", source = self.source,
                        uri = %redact_uri(&start_url), error = %e,
                        "final-url hop failed; re-resolving via original redirect chain");
                let f = self
                    .client
                    .get_range(&self.uri, ctx, seg.start, end_incl)
                    .await?;
                self.note_final(f.final_url.as_str());
                f
            }
            Err(e) => return Err(e),
        };
        let status = followed.response.status();
        if status.as_u16() != HTTP_PARTIAL_CONTENT {
            // Same shape as aria2 `executeDownload` "Expected partial,
            // but received OK" → STATUS_CANNOT_RESUME: a **download**
            // Range request answered 200 after the probe confirmed
            // segmentation = capability drift / misreport — explicit
            // failure ([`HttpError::RangeIgnored`], the consumer goes
            // fatal once): no extent-retry burn (deterministic shape,
            // retry is worthless) and no silent restart from zero
            // (misaligned-overwrite risk). Same status as the
            // probe-time 200 (source-capability verdict →
            // single-connection degradation) but a different decision;
            // the full rationale lives in docs/design/http.md.
            if status.as_u16() == HTTP_OK {
                return Err(HttpError::RangeIgnored);
            }
            // 412 = the If-Match conditional-resume precondition was
            // rejected (server content changed; same deterministic
            // family as the probe-time 416 + `bytes */N` → BadRange —
            // retry is worthless). Mapped to
            // [`HttpError::PreconditionFailed`]: the consumer goes
            // fatal once, ending this attempt, and the task clears the
            // bitmap and re-downloads from zero — misaligned bytes are
            // rejected server-side and never reach disk, without
            // waiting for the checksum to adjudicate. A request
            // without If-Match can in theory also get 412 (odd server)
            // — same mapping (restart from zero is the safe
            // direction).
            if status.as_u16() == HTTP_PRECONDITION_FAILED {
                return Err(HttpError::PreconditionFailed);
            }
            // Same shape as aria2 `parseUnavailableHeaders`: 429/503
            // throttling carrying `Retry-After` → the error carries
            // the server-suggested wait explicitly (the consumer
            // clamps it into its backoff — server value wins, 30s
            // ceiling guards against hangs). Missing/malformed header
            // → plain UnexpectedResponse (existing semantics; the
            // politeness face is best-effort, a malformed header is
            // not a failure).
            if matches!(
                status.as_u16(),
                HTTP_TOO_MANY_REQUESTS | HTTP_SERVICE_UNAVAILABLE
            ) && let Some(after_secs) = followed
                .response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parse_retry_after(v, std::time::SystemTime::now()))
            {
                let e = HttpError::RetryAfter {
                    status: status.as_u16(),
                    after_secs,
                };
                note_http_error(&e);
                return Err(e);
            }
            let e = HttpError::UnexpectedResponse {
                status: status.as_u16(),
            };
            note_http_error(&e);
            return Err(e);
        }
        let seg_id = self.seg_id();
        let mut off = seg.start;
        let mut resp = followed.response;
        // 206 start matches + length-dimension deviations tolerated by
        // the read loop — the validation face
        // ([`crate::client::validate_range_echo`]) anchors only the
        // start; body-vs-requested-length deviations close out here:
        // - over-send (body longer than requested): stop reading once
        // the requested amount is complete; dropping the Response
        // closes the connection early (an unread body keeps hyper
        // from pooling — surplus bytes are discarded, and this fetch
        // books success for the requested amount);
        // - under-send (EOF before the request end): bytes already
        // read are booked at the write point (partial progress);
        // the trailing short-read error takes the existing failure
        // arm — the extent returns to the pool at the watermark via
        // abandon and the unsatisfied remainder is retried.
        // The exact-full ending (body == requested) is unaffected: the
        // last poll sees EOF, the stream closes cleanly, and the
        // connection returns to the pool for reuse (no pool-economics
        // regression).
        loop {
            let Some(chunk) = resp
                .chunk()
                .await
                // Full error-chain expansion (not a flat to_string):
                // the payload includes kernel errno sources — the
                // payload domain of the Reset signature test.
                .map_err(crate::client::transport_error)?
            else {
                // EOF: exact full = clean close (connection pooled);
                // early = under-send, decided by the post-loop
                // short-read check.
                break;
            };
            if off >= seg.end() {
                // Over-send evidence: body bytes remain after the
                // requested amount is complete — stop reading, discard
                // the surplus, close the connection early (the old
                // `body overruns extent` rejection is retired here in
                // favor of tolerate-and-close).
                break;
            }
            let n = chunk.len() as u64;
            if off.saturating_add(n) > seg.end() {
                // Chunk straddling the end: write the in-bounds prefix
                // (full amount), drop the tail with the early close
                // (the common over-send shape when chunk boundaries do
                // not align with the extent end).
                let mut prefix = chunk;
                prefix.truncate((seg.end() - off) as usize);
                sink.write_at(seg_id, off, prefix).await?;
                off = seg.end();
                break;
            }
            sink.write_at(seg_id, off, chunk).await?;
            off += n;
        }
        if off != seg.end() {
            return Err(HttpError::Transport(format!(
                "body short read: got {off}, want {}",
                seg.end()
            )));
        }
        Ok(())
    }
}

impl SegmentTransport for HttpRangeTransport {
    fn fetch<'a>(
        &'a self,
        seg: &'a Extent,
        ctx: &'a RequestCtx,
        sink: &'a dyn SegmentSink,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Request-latency phase feed (`request_seconds{phase=total}`
            // at extent level — request issue to stream completion;
            // success and failure sampled alike).
            let t0 = std::time::Instant::now();
            let outcome = self.fetch_body(seg, ctx, sink).await;
            self.metrics
                .http()
                .observe_request(taiji_io::metrics::RequestPhase::Total, t0.elapsed());
            outcome
        })
    }
}

/// Degraded single-connection transport: full GET (no Range header) →
/// streamed writes to the sink (the degraded form has no grid;
/// `complete_block` is always Ok — FileSink semantics). `SegId` is
/// honest: for a single stream, source 0 / extent 0 is the real
/// identity (no coordinator allocation face).
pub struct HttpBodyTransport {
    client: HttpClient,
    uri: String,
    /// Metrics registry (`request_seconds{phase=total}` feed seam —
    /// full request+stream duration of the degraded single stream;
    /// injected by the driver assembly).
    metrics: Arc<MetricsRegistry>,
}

impl HttpBodyTransport {
    /// Assembly (constructor args: client / source URI / metrics
    /// registry).
    pub fn new(client: HttpClient, uri: String, metrics: Arc<MetricsRegistry>) -> Self {
        Self {
            client,
            uri,
            metrics,
        }
    }
}

impl SegmentTransport for HttpBodyTransport {
    fn fetch<'a>(
        &'a self,
        seg: &'a Extent,
        ctx: &'a RequestCtx,
        sink: &'a dyn SegmentSink,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Phase-timing feed point (degraded single stream = request
            // issue to stream completion; success and failure sampled
            // alike).
            let t0 = std::time::Instant::now();
            let outcome = async {
                let followed = self.client.get(&self.uri, ctx).await?;
                let status = followed.response.status();
                if !status.is_success() {
                    let e = HttpError::UnexpectedResponse {
                        status: status.as_u16(),
                    };
                    note_http_error(&e);
                    return Err(e);
                }
                let seg_id = SegId {
                    source: 0,
                    extent: 0,
                };
                let mut off = seg.start;
                let mut resp = followed.response;
                // Read-loop bound face (cf. [`HttpRangeTransport`]'s
                // extent-cap / over-send stop-reading discipline — the
                // single-connection form previously had none): the
                // effective bound = min(extent end, absolute cap)
                // (pure-function verdict [`body_stream_step`], cap
                // selection [`stream_cap`]).
                // - Bounded form (Content-Length declared at probe):
                // the bound is the declared length — bytes beyond it
                // = server over-send (drift evidence: declared
                // identity+CL at probe, switched to a gzip stream at
                // download; reqwest data-plane auto-decompression
                // lets the decompressed bytes enter this loop) →
                // task failure;
                // - unknown-length form (EOF-delimited sentinel): the
                // bound is the absolute cap
                // [`MAX_UNBOUNDED_STREAM_BYTES`] — a gzip all-zeros
                // streaming amplification is cut off here (an
                // endless stream never trips the read-idle timeout;
                // uncapped it would write to ENOSPC).
                // Error shape aligned with the existing over-send error
                // (`body overruns extent`, [`HttpError::Transport`]
                // payload — the same-family rejection the Range
                // transport retired; a single connection has no Range
                // echo anchor, so any overrun contradicts the probe
                // declaration and is not tolerated).
                let cap = stream_cap(seg);
                while let Some(chunk) =
                    resp.chunk().await.map_err(crate::client::transport_error)?
                {
                    let n = chunk.len() as u64;
                    let landing = off.saturating_add(n);
                    if body_stream_step(landing, seg.end(), cap) == BodyStreamStep::Beyond {
                        // Chunk straddling the bound (bytes after the
                        // in-bounds prefix) or bytes past full —
                        // out-of-bounds bytes never reach disk; task
                        // failure.
                        return Err(HttpError::Transport(format!(
                            "body overruns extent {}..{} (got at least {landing})",
                            seg.start,
                            seg.end().min(cap)
                        )));
                    }
                    sink.write_at(seg_id, off, chunk).await?;
                    off = landing;
                }
                Ok(())
            }
            .await;
            self.metrics
                .http()
                .observe_request(taiji_io::metrics::RequestPhase::Total, t0.elapsed());
            outcome
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verdict table for the pure function [`body_stream_step`]
    /// (inputs off/end/cap): off at the end boundary, 1-byte over-send,
    /// an EOF stream's off approaching the cap, within-cap
    /// pass-through, bounded large files (declared CL ≤ 16 TiB) not
    /// capped.
    #[test]
    fn body_stream_step_boundary_table() {
        use BodyStreamStep::{Beyond, Within};
        let cap = MAX_UNBOUNDED_STREAM_BYTES;
        // Bounded form (declared N=1000, uncapped): exact full (the
        // landing point = end, i.e. this chunk lands on the bound)
        // passes — only bytes after full trip.
        assert_eq!(body_stream_step(0, 1000, u64::MAX), Within);
        assert_eq!(body_stream_step(999, 1000, u64::MAX), Within);
        assert_eq!(
            body_stream_step(1000, 1000, u64::MAX),
            Within,
            "off=end boundary passes"
        );
        // 1-byte over-send: landing past the declared length → trip
        // (cross-boundary chunk / bytes after full).
        assert_eq!(
            body_stream_step(1001, 1000, u64::MAX),
            Beyond,
            "1-byte over-send trips"
        );
        // EOF unknown-length form (sentinel end = u64::MAX-1):
        // approaching / exactly at the cap passes (exact + EOF = clean
        // close); 1 byte over the cap trips.
        let sentinel = u64::MAX - 1;
        assert_eq!(body_stream_step(1, sentinel, cap), Within);
        assert_eq!(
            body_stream_step(cap - 1, sentinel, cap),
            Within,
            "approaching the cap passes"
        );
        assert_eq!(
            body_stream_step(cap, sentinel, cap),
            Within,
            "exactly at the cap passes"
        );
        assert_eq!(
            body_stream_step(cap + 1, sentinel, cap),
            Beyond,
            "over the cap trips"
        );
        // Bounded large file (declared CL = 2 TiB > cap, still within
        // the engine's 16 TiB declared domain): cap selection passes
        // u64::MAX, so it is not hit by the 1 TiB cap (real large
        // files can declare a CL).
        let big = 2 * 1024 * 1024 * 1024 * 1024u64;
        assert_eq!(
            body_stream_step(big, big, u64::MAX),
            Within,
            "a large file within the declared domain passes at the full bound"
        );
        assert_eq!(
            body_stream_step(big + 1, big, u64::MAX),
            Beyond,
            "a large file within the declared domain still trips on over-send"
        );
    }

    /// Cap-selection table ([`stream_cap`]): the EOF-delimited
    /// sentinel and any length beyond the bounded declared domain take
    /// the absolute cap; within the declared domain (including exactly
    /// the 16 TiB ceiling) no cap.
    #[test]
    fn stream_cap_selects_unbounded_form_only() {
        // Bounded form: declared CL within the engine's declared
        // domain (16 TiB inclusive) → uncapped.
        assert_eq!(
            stream_cap(&Extent {
                start: 0,
                len: 1000
            }),
            u64::MAX
        );
        assert_eq!(
            stream_cap(&Extent {
                start: 0,
                len: crate::grid::MAX_TOTAL_LEN
            }),
            u64::MAX,
            "exactly the 16TiB ceiling still belongs to the declared domain"
        );
        // Unknown-length form: EOF-delimited sentinel (u64::MAX-1) →
        // absolute cap.
        assert_eq!(
            stream_cap(&Extent {
                start: 0,
                len: u64::MAX - 1
            }),
            MAX_UNBOUNDED_STREAM_BYTES
        );
        // Any length beyond the declared domain can only be the
        // sentinel form → absolute cap.
        assert_eq!(
            stream_cap(&Extent {
                start: 0,
                len: crate::grid::MAX_TOTAL_LEN + 1
            }),
            MAX_UNBOUNDED_STREAM_BYTES
        );
    }
}
