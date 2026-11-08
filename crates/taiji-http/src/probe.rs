//! URI probing — the full 7-row classification table plus the
//! multi-source merge table.
//!
//! Hard rule: HEAD is never a probing mechanism. HEAD semantics are not
//! enforced across HTTP implementations (servers may omit
//! Content-Length/entity headers, or lie for HEAD), so its result can
//! never back a segmentation decision — the only probe is a single
//! `GET` with `Range: bytes=0-0` and `Accept-Encoding: identity`,
//! reading the response headers and dropping the stream immediately
//! (the body is never read; `Response` drop closes it — cost bounded
//! by the 1-byte probe body). No probe path in this crate may
//! introduce HEAD.
//!
//! Classification table:
//!
//! - 206 + `Content-Range: bytes 0-0/TOTAL` → segmentable; TOTAL is
//!   the authoritative length ([`ProbeVerdict::RangeWithLength`]).
//! - 206 + `Content-Range: bytes 0-0/*` → Range supported, no total →
//!   single-connection degrade, no bitmap (weak)
//!   ([`ProbeVerdict::RangeNoLength`]).
//! - 200 + Content-Length → Range ignored → single-connection degrade
//!   ([`ProbeVerdict::NoRangeWithLength`]).
//! - 200 + chunked/no length → single-connection degrade, no bitmap
//!   (weak) ([`ProbeVerdict::NoRangeNoLength`]).
//! - 416 + `Content-Range: bytes */0` → empty file: create a 0-byte
//!   output, done ([`ProbeVerdict::EmptyFile`]).
//! - 416 + `Content-Range: bytes */N` (N>0) → length changed →
//!   `taiji.http.bad_range` ([`HttpError::BadRange`]).
//! - Content-Encoding != identity → Range semantics unknowable →
//!   single-connection degrade + self-decompression; bitmap off
//!   ([`ProbeVerdict::Encoded`]).
//!
//! The Content-Encoding rule outranks status-shape classification
//! inside the 200/206 arms: even a 206+TOTAL answer cannot map bytes
//! onto the grid under a non-identity encoding (TOTAL describes the
//! encoded entity), so the source always degrades. The rule is gated
//! to success statuses — it applies only inside the 200/206 arms:
//! gzip on 4xx/5xx error pages is routine, and such a page must not
//! be accepted as a usable source through the rule, swallowing the
//! real status.
//!
//! The authoritative total length carries an engine cap
//! ([`crate::grid::MAX_TOTAL_LEN`], 16 TiB): a TOTAL (206 arm) or
//! Content-Length (200 arm) beyond it rejects the whole task with
//! `taiji.http.total_length_exceeded` — giant bitmap allocations are
//! unreachable through the classification layer.
//!
//! Multi-source merge ([`merge_probes`]): per-source lengths must
//! agree (any disagreement → `taiji.http.mirror_mismatch`; with
//! `--checksum` the checksum-verifiable group wins and the rest are
//! dropped); Content-Type differences only warn (aria2 does not
//! compare types); only 206+TOTAL sources segment, the rest are
//! dropped (warned); all no-range → degrade to the first source
//! single-connection, the rest dropped; every source removed →
//! `taiji.http.no_source`.
//!
//! Upstream anchor mapping: docs/design/http.md

use reqwest::header::{
    ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    LAST_MODIFIED,
};
use reqwest::{StatusCode, Url};

use crate::client::{Followed, HttpClient};
use crate::error::HttpError;
use crate::grid;
use crate::traits::{PlanSource, RequestCtx, ResumeValidator, TransportKind};

/// Range shape of the probe request (single GET + `bytes=0-0`).
pub const PROBE_RANGE: (u64, u64) = (0, 0);

/// Single-source probe record (the classification table's record face:
/// Accept-Ranges/ETag/Last-Modified/final URL, plus the merge table's
/// Content-Type warning face).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// Final URL after redirects converge (feeds the ResumeValidator).
    pub final_url: String,
    /// Authoritative total: TOTAL (206 arm), Content-Length (200 arm),
    /// or 0 (empty file). Other shapes are semantically unknowable or
    /// absent → None.
    pub total_len: Option<u64>,
    /// ETag text (a weak `W/` marker counts as missing in
    /// [`ProbeResult::resume_validator`]).
    pub etag: Option<String>,
    /// Last-Modified text.
    pub last_modified: Option<String>,
    /// `Accept-Ranges: bytes` (a 206 in the Range arms itself proves
    /// Range support, always true there).
    pub accept_ranges: bool,
    /// The response encoding from the Content-Encoding rule (e.g.
    /// `gzip`); identity/absent → None.
    pub encoding: Option<String>,
    /// Content-Type (the merge table's "type difference warns only"
    /// reconciliation face).
    pub content_type: Option<String>,
}

impl ProbeResult {
    /// Extract the record face from response headers (total_len is
    /// filled in per classification arm).
    fn from_headers(final_url: &Url, headers: &reqwest::header::HeaderMap) -> Self {
        let text = |name| header_text(headers, name);
        Self {
            final_url: final_url.to_string(),
            total_len: None,
            etag: text(ETAG.as_str()),
            last_modified: text(LAST_MODIFIED.as_str()),
            accept_ranges: headers
                .get(ACCEPT_RANGES)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("bytes")),
            encoding: None,
            content_type: text(CONTENT_TYPE.as_str()),
        }
    }

    /// Resume-validation face (the fields are the probe record).
    ///
    /// Only strong ETags (a `W/` weak tag counts as missing);
    /// `encoding_ok` = the response encoding confirmed identity (the
    /// Content-Encoding rule → false, bitmap off).
    pub fn resume_validator(&self) -> ResumeValidator {
        ResumeValidator {
            final_url_path: Url::parse(&self.final_url)
                .map(|u| u.path().to_string())
                .unwrap_or_default(),
            total_len: self.total_len,
            etag: self.etag.as_ref().filter(|t| !t.starts_with("W/")).cloned(),
            last_modified: self.last_modified.clone(),
            encoding_ok: self.encoding.is_none(),
        }
    }
}

/// Probe classification verdict — the classification table as Rust
/// (the length-changed 416 shape is an error, not a variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// 206 + `bytes 0-0/TOTAL` → segmentable, TOTAL authoritative
    /// length.
    RangeWithLength(ProbeResult),
    /// 206 + `bytes 0-0/*` → Range supported without a total →
    /// single-connection degrade, no bitmap (weak).
    RangeNoLength(ProbeResult),
    /// 200 + Content-Length → Range ignored → single-connection
    /// degrade.
    NoRangeWithLength(ProbeResult),
    /// 200 + chunked/no length → single-connection degrade, no bitmap
    /// (weak).
    NoRangeNoLength(ProbeResult),
    /// 416 + `bytes */0` → empty file: create a 0-byte output, done.
    EmptyFile(ProbeResult),
    /// Content-Encoding != identity → Range semantics unknowable →
    /// single-connection degrade + self-decompression; bitmap off. The
    /// download face reads decompressed bytes via reqwest auto
    /// decompression (the checksum applies to the decompressed bytes).
    Encoded(ProbeResult),
}

impl ProbeVerdict {
    /// The probe record.
    pub fn result(&self) -> &ProbeResult {
        match self {
            Self::RangeWithLength(r)
            | Self::RangeNoLength(r)
            | Self::NoRangeWithLength(r)
            | Self::NoRangeNoLength(r)
            | Self::EmptyFile(r)
            | Self::Encoded(r) => r,
        }
    }

    /// May join block-grid segmentation (only the 206+TOTAL shape; the
    /// merge additionally drops no-total sources — no bitmap face).
    pub fn is_segmentable(&self) -> bool {
        matches!(self, Self::RangeWithLength(_))
    }

    /// Single-connection degrade (no bitmap face): the weak /
    /// no-range / encoded shapes.
    pub fn is_degraded_single(&self) -> bool {
        !matches!(self, Self::RangeWithLength(_) | Self::EmptyFile(_))
    }

    /// Merge-table length accounting: TOTAL (206+total), CL
    /// (200+length), 0 (empty file); semantically unknowable shapes →
    /// None (excluded from cross-source length comparison).
    pub fn known_len(&self) -> Option<u64> {
        match self {
            Self::RangeWithLength(r) | Self::NoRangeWithLength(r) => r.total_len,
            Self::EmptyFile(_) => Some(0),
            _ => None,
        }
    }
}

/// Single-source probe input: source URI + transport family + probe
/// verdict (a probe failure is a legal input — the source is removed
/// in the merge; only if all fail does `no_source` fire).
#[derive(Clone, Debug)]
pub struct ProbedSource {
    /// Source URI (user order = priority order, aria2 URI priority).
    pub uri: String,
    /// Transport family (the PlanSource output face).
    pub kind: TransportKind,
    /// Per-source probe verdict.
    pub outcome: Result<ProbeVerdict, HttpError>,
}

/// Multi-source merge parameters.
#[derive(Clone, Debug, Default)]
pub struct MergeInput {
    /// Per-source probe results (user URI order).
    pub sources: Vec<ProbedSource>,
    /// `--checksum=<type>=<digest>`. When provided, a length mismatch
    /// does not hard-fail: "the checksum-verifiable group wins, the
    /// rest are dropped" — probing cannot tell up front which length
    /// will pass the checksum, so the first source's length group is
    /// authoritative (aria2 URI priority) and the completion-time
    /// checksum has the final say.
    pub checksum: Option<(String, String)>,
}

/// Merge warnings (warn-only decisions, consumed by RPC/logging).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeWarning {
    /// Content-Type difference (aria2 does not compare types).
    ContentTypeMismatch {
        /// URI of the first source with that type.
        uri_a: String,
        /// First source's type.
        type_a: String,
        /// URI of the different-typed source.
        uri_b: String,
        /// The different type.
        type_b: String,
    },
    /// Probe-failed source dropped (transport error / out-of-table
    /// response).
    ProbeFailedDropped {
        /// Source URI.
        uri: String,
        /// Engine-side error code (`taiji.http.*`).
        code: &'static str,
    },
    /// Incapable source dropped (no-range / no total / encoded degrade
    /// — only 206+TOTAL sources segment).
    NonSegmentableDropped {
        /// Source URI.
        uri: String,
    },
    /// Length group dropped (the non-authoritative group under
    /// mirror_mismatch with `--checksum` provided).
    LengthGroupDropped {
        /// Source URI.
        uri: String,
    },
}

/// Multi-source merge product (feeds segmentation / resume planning).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergedPlan {
    /// ≥1 206+TOTAL source → block-grid segmentation.
    Segmented {
        /// Authoritative total (consistent among segmentable sources —
        /// disagreement takes the mirror_mismatch path).
        total_len: u64,
        /// Segmenting sources (user URI order).
        sources: Vec<PlanSource>,
        /// The authoritative source's (first segmentable) probe record
        /// (ResumeValidator derivation face).
        authoritative: ProbeResult,
        /// Merge warnings.
        warnings: Vec<MergeWarning>,
    },
    /// No source segmentable → degrade to the first source
    /// single-connection, the rest dropped (no bitmap).
    SingleConnection {
        /// The degraded download source (first source).
        source: PlanSource,
        /// First source's probe record.
        authoritative: ProbeResult,
        /// Content-Encoding rule: the download face must handle
        /// decompression (reqwest auto decompression already covers
        /// the data path; this flag serves the "self-decompression"
        /// semantics reconciliation and diagnostics).
        self_decompress: bool,
        /// Merge warnings.
        warnings: Vec<MergeWarning>,
    },
    /// All sources 416 + `bytes */0` (or the first source is an empty
    /// file with no length contradiction) → create a 0-byte output,
    /// done.
    EmptyFile {
        /// Merge warnings (same payload discipline as
        /// [`MergedPlan::Segmented`]/[`MergedPlan::SingleConnection`]
        /// — the non-first-source drop records).
        warnings: Vec<MergeWarning>,
    },
}

/// Probe one URI: GET + `Range: bytes=0-0` +
/// `Accept-Encoding: identity` (identity is the default through
/// `ClientConfig::identity_encoding` — a single source of truth),
/// reading the response headers and closing the stream. HEAD is never
/// a probing mechanism (module rule).
///
/// Transport goes through [`HttpClient::get_range_raw`] (the probe
/// instance with auto decompression off): the Content-Encoding rule
/// must read the raw, unstripped `Content-Encoding`.
///
/// URI-level retry (matching aria2's URI-level max-tries): only
/// transport-class transient failures retry ([`retry_with`],
/// parameters = `ClientConfig::retry`); 4xx / out-of-table / Range
/// conflicts (`UnexpectedResponse`/`BadRange`/...) are deterministic
/// failures that stop after one attempt — 4xx never travels the
/// transport channel and is naturally exempt. Retry parameters are
/// shared with the extent-level consumer (`RetryPolicy`); the client
/// itself does no implicit retry, so nothing double-counts.
///
/// Transient-failure backoff floor: with `--retry-wait` defaulting to
/// 0s, zero-gap retries fire entirely inside the transient window
/// (server RSTs from a same-moment connect burst, origin jitter) —
/// and probing is a task's first hop, so failing it ends a
/// single-source task in `no_source`. A 50ms floor is added to the
/// retry interval (exponential x2, the
/// [`RetryPolicy::wait_before_retry`] formula): 5 attempts span
/// 50/100/200/400ms, necessarily crossing a burst window of tens of
/// ms — the same exponential-backoff philosophy as the aria2 URI-level
/// max-tries anchor (backoff absorbs connect-phase RST noise).
pub async fn probe_uri(
    client: &HttpClient,
    uri: &str,
    ctx: &RequestCtx,
) -> Result<ProbeVerdict, HttpError> {
    let mut policy = client.retry_policy().clone();
    policy.base_wait = policy.base_wait.max(std::time::Duration::from_millis(
        PROBE_RETRY_BACKOFF_FLOOR_MS,
    ));
    let followed = crate::retry::retry_with(
        &policy,
        || client.get_range_raw(uri, ctx, PROBE_RANGE.0, PROBE_RANGE.1),
        crate::retry::transport_retryable,
    )
    .await?;
    // Read the response headers and close the stream: classify takes
    // only the headers, the Response drops with it, the body is never
    // read.
    classify(followed)
}

/// Probe transient-failure backoff floor (milliseconds). Only raises
/// the `base_wait` floor; attempt count/cap unchanged — an explicit
/// `--retry-wait` > 50ms keeps its value.
const PROBE_RETRY_BACKOFF_FLOOR_MS: u64 = 50;

/// The classification table (all rows).
///
/// The Content-Encoding rule is gated by status: it applies only
/// inside the 200/206 arms — it describes "encoding semantics
/// unknowable" for success shapes; non-2xx error pages (gzip on
/// 4xx/5xx is routine) must not be judged usable sources through it,
/// swallowing the real status code.
pub fn classify(followed: Followed) -> Result<ProbeVerdict, HttpError> {
    let Followed {
        response,
        final_url,
        ..
    } = followed;
    let status = response.status();
    let headers = response.headers();

    // Content-Encoding rule (checked first): != identity → Range
    // semantics unknowable and status-shape classification loses
    // meaning (total_len not filled — an encoded entity's length is
    // never authoritative).
    let raw_encoding = headers.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok());
    let encoded = raw_encoding.is_some_and(|enc| !enc.eq_ignore_ascii_case("identity"));

    let mut result = ProbeResult::from_headers(&final_url, headers);
    match status {
        StatusCode::PARTIAL_CONTENT => {
            if let Some(enc) = raw_encoding.filter(|_| encoded) {
                return Ok(encoded_verdict(result, enc));
            }
            let content_range = headers
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_range);
            match content_range {
                // `bytes 0-0/TOTAL` — TOTAL is the authoritative
                // length.
                Some(ContentRange::Partial {
                    start: 0,
                    end: 0,
                    total: Some(total),
                }) => {
                    // total > end guard (`bytes 0-0/0` pathological
                    // echo — an empty file arrives via the 416 arm):
                    // letting it through would produce an
                    // instantly-complete fake grid; aria2
                    // isRangeSatisfied fails → CANNOT_RESUME.
                    if total == 0 {
                        return Err(HttpError::BadRange);
                    }
                    // Authoritative-total cap (rationale in the
                    // [`grid::MAX_TOTAL_LEN`] comment): beyond it the
                    // task is rejected.
                    if total > grid::MAX_TOTAL_LEN {
                        return Err(HttpError::TotalLengthExceeded {
                            total,
                            max: grid::MAX_TOTAL_LEN,
                        });
                    }
                    result.total_len = Some(total);
                    result.accept_ranges = true;
                    Ok(ProbeVerdict::RangeWithLength(result))
                }
                // `bytes 0-0/*` — Range supported without a total
                // (weak).
                Some(ContentRange::Partial {
                    start: 0,
                    end: 0,
                    total: None,
                }) => {
                    result.accept_ranges = true;
                    Ok(ProbeVerdict::RangeNoLength(result))
                }
                // An echo mismatching the probe's `bytes=0-0`: aria2
                // HttpResponse.cc (isRangeSatisfied failure →
                // CANNOT_RESUME) — length-face conflicts map to
                // bad_range.
                Some(ContentRange::Partial { .. }) => Err(HttpError::BadRange),
                // A 416 unsatisfied shape inside 206 / unparseable:
                // out-of-table shape.
                _ => {
                    let e = HttpError::UnexpectedResponse {
                        status: status.as_u16(),
                    };
                    crate::error::note_http_error(&e);
                    Err(e)
                }
            }
        }
        StatusCode::OK => {
            if let Some(enc) = raw_encoding.filter(|_| encoded) {
                return Ok(encoded_verdict(result, enc));
            }
            // Range ignored + Content-Length → single-connection
            // degrade (total known).
            let content_length = headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                // Same authoritative-total cap (the degrade path
                // preallocs giant files too).
                .map(|len| {
                    if len > grid::MAX_TOTAL_LEN {
                        return Err(HttpError::TotalLengthExceeded {
                            total: len,
                            max: grid::MAX_TOTAL_LEN,
                        });
                    }
                    Ok(len)
                })
                .transpose()?;
            result.total_len = content_length;
            Ok(match content_length {
                Some(_) => ProbeVerdict::NoRangeWithLength(result),
                // chunked/no length → single-connection degrade, no
                // bitmap (weak).
                None => ProbeVerdict::NoRangeNoLength(result),
            })
        }
        StatusCode::RANGE_NOT_SATISFIABLE => {
            let content_range = headers
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_range);
            match content_range {
                // `bytes */0` → empty file: create a 0-byte output,
                // done.
                Some(ContentRange::Unsatisfied { total: 0 }) => {
                    result.total_len = Some(0);
                    Ok(ProbeVerdict::EmptyFile(result))
                }
                // `bytes */N` (N>0) → the length changed → bad_range.
                Some(ContentRange::Unsatisfied { total: _ }) => Err(HttpError::BadRange),
                _ => {
                    let e = HttpError::UnexpectedResponse {
                        status: status.as_u16(),
                    };
                    crate::error::note_http_error(&e);
                    Err(e)
                }
            }
        }
        _ => {
            let e = HttpError::UnexpectedResponse {
                status: status.as_u16(),
            };
            crate::error::note_http_error(&e);
            Err(e)
        }
    }
}

/// Constructor for the encoded verdict (total_len not filled — an
/// encoded entity's length is never authoritative).
fn encoded_verdict(mut r: ProbeResult, enc: &str) -> ProbeVerdict {
    tracing::debug!(
        target: "taiji::http::probe",
        encoding = %redact_str(enc),
        "probe: content-encoding is not identity; degrade to single connection"
    );
    r.encoding = Some(enc.to_owned());
    ProbeVerdict::Encoded(r)
}

/// `Content-Range` parse face (the two RFC 7233 shapes). Shared
/// in-crate (the client data face's echo validation uses the same
/// parser — no drift from a second implementation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentRange {
    /// `bytes <start>-<end>/<total|*>`.
    Partial {
        /// Echo start.
        start: u64,
        /// Echo end (inclusive).
        end: u64,
        /// Entity total (`*` = no total).
        total: Option<u64>,
    },
    /// `bytes */<total>` (416 unsatisfied).
    Unsatisfied {
        /// Entity total.
        total: u64,
    },
}

/// Parse a Content-Range header value; `bytes */*` and any unparseable
/// shape → None (outside the classification table).
pub(crate) fn parse_content_range(value: &str) -> Option<ContentRange> {
    let rest = value.trim();
    let unit_end = rest.find(char::is_whitespace)?;
    if !rest[..unit_end].eq_ignore_ascii_case("bytes") {
        return None;
    }
    let rest = rest[unit_end..].trim_start();

    if let Some(rest) = rest.strip_prefix('*') {
        let total_part = rest.trim_start().strip_prefix('/')?.trim();
        // `bytes */*`: total unknowable, outside the table.
        if total_part == "*" {
            return None;
        }
        return Some(ContentRange::Unsatisfied {
            total: total_part.parse().ok()?,
        });
    }

    let (range_part, total_part) = rest.split_once('/')?;
    let (start_s, end_s) = range_part.trim().split_once('-')?;
    let total = match total_part.trim() {
        "*" => None,
        t => Some(t.parse().ok()?),
    };
    Some(ContentRange::Partial {
        start: start_s.trim().parse().ok()?,
        end: end_s.trim().parse().ok()?,
        total,
    })
}

/// Multi-source probe merge.
///
/// Decision order: drop probe-failed sources → length consistency
/// (mirror_mismatch path) → type-difference warnings → only 206+TOTAL
/// sources segment → all non-segmentable degrades to the first source
/// → all removed fires `no_source`. Empty files take the first
/// source's shape: a first source that is an empty file with no length
/// contradiction → EmptyFile.
pub fn merge_probes(input: MergeInput) -> Result<MergedPlan, HttpError> {
    let mut warnings = Vec::new();
    let mut alive: Vec<(String, TransportKind, ProbeVerdict)> = Vec::new();
    // Authoritative-total cap (rationale in grid::MAX_TOTAL_LEN): any
    // source beyond it rejects the task — not a source-level drop; a
    // malicious total is not "incapable" (a failed-drop + no_source
    // combination would leave a path to a mixed-source giant bitmap
    // allocation).
    for src in &input.sources {
        if let Err(e @ HttpError::TotalLengthExceeded { .. }) = &src.outcome {
            return Err(e.clone());
        }
    }
    for src in input.sources {
        match src.outcome {
            Ok(verdict) => {
                if let Some(len) = verdict.known_len()
                    && len > grid::MAX_TOTAL_LEN
                {
                    tracing::warn!(
                        target: "taiji::http::probe",
                        uri = %redact_str(&src.uri),
                        len,
                        cap = grid::MAX_TOTAL_LEN,
                        "probed total length exceeds engine cap; task rejected"
                    );
                    return Err(HttpError::TotalLengthExceeded {
                        total: len,
                        max: grid::MAX_TOTAL_LEN,
                    });
                }
                alive.push((src.uri, src.kind, verdict));
            }
            Err(e) => {
                tracing::warn!(
                    target: "taiji::http::probe",
                    uri = %redact_str(&src.uri),
                    code = e.code(),
                    "probe failed; source dropped"
                );
                warnings.push(MergeWarning::ProbeFailedDropped {
                    uri: src.uri,
                    code: e.code(),
                });
            }
        }
    }
    // All sources removed → no_source.
    if alive.is_empty() {
        return Err(HttpError::NoSource);
    }

    // Length mismatch (any two sources with known lengths) →
    // mirror_mismatch; with `--checksum` the verifiable group wins
    // (the first source's length group is authoritative, the
    // completion-time checksum has final say) and other length groups
    // are dropped.
    let mut known_lens: Vec<u64> = alive.iter().filter_map(|(_, _, v)| v.known_len()).collect();
    known_lens.sort_unstable();
    known_lens.dedup();
    if known_lens.len() > 1 {
        let Some(checksum) = &input.checksum else {
            return Err(HttpError::MirrorMismatch);
        };
        let keep = alive
            .iter()
            .find_map(|(_, _, v)| v.known_len())
            .unwrap_or_default();
        let evicted: Vec<String> = alive
            .iter()
            .filter(|(_, _, v)| v.known_len().is_some_and(|l| l != keep))
            .map(|(uri, _, _)| uri.clone())
            .collect();
        alive.retain(|(_, _, v)| v.known_len().is_none_or(|l| l == keep));
        for uri in evicted {
            tracing::warn!(
                target: "taiji::http::probe",
                uri = %redact_str(&uri),
                checksum_type = %checksum.0,
                keep_len = keep,
                "mirror length mismatch with checksum; length group dropped"
            );
            warnings.push(MergeWarning::LengthGroupDropped { uri });
        }
    }

    // Content-Type differences warn only (aria2 does not compare
    // types).
    let mut types = alive.iter().filter_map(|(uri, _, v)| {
        v.result()
            .content_type
            .clone()
            .filter(|t| !t.is_empty())
            .map(|t| (uri.clone(), t))
    });
    if let Some((uri_a, type_a)) = types.next() {
        for (uri_b, type_b) in types {
            if type_b != type_a {
                tracing::warn!(
                    target: "taiji::http::probe",
                    "mirror content-type differs (warn only)"
                );
                warnings.push(MergeWarning::ContentTypeMismatch {
                    uri_a: uri_a.clone(),
                    type_a: type_a.clone(),
                    uri_b,
                    type_b,
                });
            }
        }
    }

    // Only 206+TOTAL sources segment; the rest are dropped (warned).
    if let Some(first_seg) = alive.iter().position(|(_, _, v)| v.is_segmentable()) {
        // The mirror_mismatch path already guaranteed segmenting
        // sources agree on length; the first 206+TOTAL source is
        // authoritative.
        let total_len = alive[first_seg].2.known_len().unwrap_or_default();
        let authoritative = alive[first_seg].2.result().clone();
        let mut sources = Vec::new();
        alive.retain(|(uri, kind, verdict)| {
            if verdict.is_segmentable() {
                sources.push(PlanSource {
                    uri: uri.clone(),
                    kind: *kind,
                });
                true
            } else {
                warnings.push(MergeWarning::NonSegmentableDropped { uri: uri.clone() });
                false
            }
        });
        return Ok(MergedPlan::Segmented {
            total_len,
            sources,
            authoritative,
            warnings,
        });
    }

    // All no-range/weak → degrade to the first source
    // single-connection, the rest dropped; a first source that is an
    // empty file (no length contradiction — that took the
    // mirror_mismatch path) → 0-byte output done (non-first-source
    // drops still land in the warnings).
    let (first_uri, first_kind, first_verdict) = &alive[0];
    if matches!(first_verdict, ProbeVerdict::EmptyFile(_)) {
        for (uri, ..) in alive.iter().skip(1) {
            warnings.push(MergeWarning::NonSegmentableDropped { uri: uri.clone() });
        }
        return Ok(MergedPlan::EmptyFile { warnings });
    }
    for (uri, ..) in alive.iter().skip(1) {
        warnings.push(MergeWarning::NonSegmentableDropped { uri: uri.clone() });
    }
    Ok(MergedPlan::SingleConnection {
        source: PlanSource {
            uri: first_uri.clone(),
            kind: *first_kind,
        },
        authoritative: first_verdict.result().clone(),
        self_decompress: matches!(first_verdict, ProbeVerdict::Encoded(_)),
        warnings,
    })
}

/// Header text (non-UTF-8 → None; tolerance for
/// ETag/Last-Modified/Content-Type — non-UTF-8 header values never
/// decide classification).
fn header_text(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Log-face URI redaction: strip query/fragment (unified redaction
/// discipline).
fn redact_str(uri: &str) -> impl std::fmt::Display + '_ {
    uri.split(['?', '#']).next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grid;

    fn source(
        uri: &str,
        kind: TransportKind,
        outcome: Result<ProbeVerdict, HttpError>,
    ) -> ProbedSource {
        ProbedSource {
            uri: uri.to_string(),
            kind,
            outcome,
        }
    }

    /// 206 + TOTAL verdict constructor.
    fn ranged(total: u64) -> ProbeVerdict {
        ProbeVerdict::RangeWithLength(ProbeResult {
            final_url: "http://example.test/f".into(),
            total_len: Some(total),
            etag: Some("\"e\"".into()),
            last_modified: None,
            accept_ranges: true,
            encoding: None,
            content_type: Some("application/octet-stream".into()),
        })
    }

    /// 200 + CL verdict constructor.
    fn no_range(total: u64) -> ProbeVerdict {
        ProbeVerdict::NoRangeWithLength(ProbeResult {
            final_url: "http://example.test/f".into(),
            total_len: Some(total),
            etag: None,
            last_modified: None,
            accept_ranges: false,
            encoding: None,
            content_type: Some("application/octet-stream".into()),
        })
    }

    /// 206 + `*` verdict constructor (weak).
    fn ranged_weak() -> ProbeVerdict {
        ProbeVerdict::RangeNoLength(ProbeResult {
            final_url: "http://example.test/f".into(),
            total_len: None,
            etag: None,
            last_modified: None,
            accept_ranges: true,
            encoding: None,
            content_type: None,
        })
    }

    /// 416 + `*/0` verdict constructor.
    fn empty_file() -> ProbeVerdict {
        ProbeVerdict::EmptyFile(ProbeResult {
            final_url: "http://example.test/f".into(),
            total_len: Some(0),
            etag: None,
            last_modified: None,
            accept_ranges: false,
            encoding: None,
            content_type: None,
        })
    }

    /// Content-Encoding != identity verdict constructor.
    fn encoded() -> ProbeVerdict {
        ProbeVerdict::Encoded(ProbeResult {
            final_url: "http://example.test/f".into(),
            total_len: None,
            etag: None,
            last_modified: None,
            accept_ranges: false,
            encoding: Some("gzip".into()),
            content_type: None,
        })
    }

    // ---------- Classification-table helpers ----------

    #[test]
    fn verdict_capability_and_length_accounting() {
        // 206+TOTAL segments, the empty file is not degraded, the
        // weak/no-range/encoded shapes degrade.
        assert!(ranged(10).is_segmentable());
        assert!(!ranged(10).is_degraded_single());
        assert!(ranged_weak().is_degraded_single());
        assert!(!ranged_weak().is_segmentable());
        assert!(no_range(10).is_degraded_single());
        assert!(encoded().is_degraded_single());
        assert!(!empty_file().is_degraded_single());

        // Length accounting: TOTAL, CL, 0, and None respectively.
        assert_eq!(ranged(10).known_len(), Some(10));
        assert_eq!(no_range(7).known_len(), Some(7));
        assert_eq!(empty_file().known_len(), Some(0));
        assert_eq!(ranged_weak().known_len(), None);
        assert_eq!(encoded().known_len(), None);
    }

    #[test]
    fn resume_validator_strong_etag_and_encoding_gate() {
        let mut r = ranged(100).result().clone();
        r.final_url = "https://cdn.example/dir/f.bin?token=secret".into();
        let v = r.resume_validator();
        assert_eq!(v.final_url_path, "/dir/f.bin"); // query stripped
        assert_eq!(v.total_len, Some(100));
        assert_eq!(v.etag, Some("\"e\"".into()));
        assert!(v.encoding_ok);

        // A weak ETag counts as missing (traits.rs contract).
        r.etag = Some("W/\"weak\"".into());
        assert_eq!(r.resume_validator().etag, None);

        // Encoded: != identity → encoding_ok = false (bitmap off).
        assert!(!encoded().result().resume_validator().encoding_ok);
    }

    // ---------- Content-Range parsing ----------

    #[test]
    fn content_range_parse_table_shapes() {
        assert_eq!(
            parse_content_range("bytes 0-0/123456"),
            Some(ContentRange::Partial {
                start: 0,
                end: 0,
                total: Some(123456)
            })
        );
        assert_eq!(
            parse_content_range("bytes 0-0/*"),
            Some(ContentRange::Partial {
                start: 0,
                end: 0,
                total: None
            })
        );
        assert_eq!(
            parse_content_range("bytes */0"),
            Some(ContentRange::Unsatisfied { total: 0 })
        );
        assert_eq!(
            parse_content_range("bytes */777"),
            Some(ContentRange::Unsatisfied { total: 777 })
        );
        // An echo not 0-0 (mismatches the probe request).
        assert_eq!(
            parse_content_range("bytes 5-5/100"),
            Some(ContentRange::Partial {
                start: 5,
                end: 5,
                total: Some(100)
            })
        );
    }

    #[test]
    fn content_range_parse_rejects_out_of_table() {
        for junk in [
            "",
            "application/json",
            "bytes",
            "bytes 0-0",
            "bytes 0-0/",
            "bytes 0-0/x",
            "bytes -1-0/5",
            "bytes */*",
            "bytes 0-0",
            "items 0-0/5",
        ] {
            assert_eq!(parse_content_range(junk), None, "{junk}");
        }
    }

    // ---------- Multi-source merge table ----------

    // ---------- Synthetic-response classification tests ----------

    /// Build a classification input (no wire dependency: a reqwest
    /// Response can be synthesized from an http::Response — the
    /// dev-dep axum http re-export).
    fn followed(status: u16, headers: &[(&str, &str)]) -> crate::client::Followed {
        let mut builder = axum::http::Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = builder
            .body(String::new())
            .unwrap_or_else(|e| panic!("response build: {e}"));
        crate::client::Followed {
            response: reqwest::Response::from(response),
            final_url: Url::parse("http://example.test/f").unwrap_or_else(|e| panic!("url: {e}")),
            hops: 0,
        }
    }

    /// The Content-Encoding status gate: a non-2xx error page carrying
    /// `Content-Encoding: gzip` must not be judged a usable source,
    /// swallowing the real status — the rule applies only inside the
    /// 200/206 arms.
    #[test]
    fn row7_gate_requires_success_status() {
        // 404/503 + gzip error pages → the out-of-table status
        // surfaces as-is (never swallowed).
        assert_eq!(
            classify(followed(404, &[("content-encoding", "gzip")]))
                .err()
                .unwrap_or_else(|| panic!("404 must not classify")),
            HttpError::UnexpectedResponse { status: 404 }
        );
        assert_eq!(
            classify(followed(
                503,
                &[("content-encoding", "gzip"), ("content-type", "text/html")]
            ))
            .err()
            .unwrap_or_else(|| panic!("503 must not classify")),
            HttpError::UnexpectedResponse { status: 503 }
        );

        // Control: 200/206 + gzip still take the encoded rule.
        assert!(matches!(
            classify(followed(200, &[("content-encoding", "gzip")]))
                .unwrap_or_else(|e| panic!("200+gzip: {e}")),
            ProbeVerdict::Encoded(_)
        ));
        assert!(matches!(
            classify(followed(
                206,
                &[
                    ("content-encoding", "gzip"),
                    ("content-range", "bytes 0-0/100")
                ]
            ))
            .unwrap_or_else(|e| panic!("206+gzip: {e}")),
            ProbeVerdict::Encoded(_)
        ));

        // 416 + gzip: the rule does not apply → the 416 arms /
        // out-of-table as usual (no Content-Range → out of table).
        assert_eq!(
            classify(followed(416, &[("content-encoding", "gzip")]))
                .err()
                .unwrap_or_else(|| panic!("416 must not classify")),
            HttpError::UnexpectedResponse { status: 416 }
        );
    }

    /// The 206 `bytes 0-0/0` guard: total > end (end = 0 → total ≥ 1).
    /// A 206 with total=0 is a pathological echo (an empty file
    /// arrives via the 416 arm); letting it through would produce an
    /// instantly-complete fake grid — aria2 isRangeSatisfied →
    /// CANNOT_RESUME.
    #[test]
    fn row1_total_zero_is_bad_range() {
        let err = classify(followed(206, &[("content-range", "bytes 0-0/0")]))
            .err()
            .unwrap_or_else(|| panic!("`bytes 0-0/0` must be rejected"));
        assert_eq!(err, HttpError::BadRange);
    }

    /// Authoritative-total cap injection: a 2^63-scale malicious
    /// total → task-level rejection at the classification layer
    /// (`taiji.http.total_length_exceeded`), never an Ok verdict —
    /// giant bitmap allocations stay unreachable before downstream
    /// construction (cap rationale in the `grid::MAX_TOTAL_LEN`
    /// comment).
    #[test]
    fn authoritative_total_beyond_cap_is_task_rejection() {
        const HUGE: u64 = 1u64 << 63; // 2^63: the magnitude of a malicious Content-Range total
        // 206 arm: `bytes 0-0/HUGE`.
        assert_eq!(
            classify(followed(
                206,
                &[("content-range", &format!("bytes 0-0/{HUGE}"))]
            ))
            .err()
            .unwrap_or_else(|| panic!("2^63 total must be rejected at probe")),
            HttpError::TotalLengthExceeded {
                total: HUGE,
                max: grid::MAX_TOTAL_LEN
            }
        );
        // 200 arm: `Content-Length: HUGE` (the degrade path rejects
        // giant files the same way).
        assert_eq!(
            classify(followed(200, &[("content-length", &HUGE.to_string())]))
                .err()
                .unwrap_or_else(|| panic!("2^63 content-length must be rejected")),
            HttpError::TotalLengthExceeded {
                total: HUGE,
                max: grid::MAX_TOTAL_LEN
            }
        );

        // Merge side: a constructed over-cap verdict → task-level
        // rejection (a healthy mixed set must not slip through).
        let input = MergeInput {
            sources: vec![
                source("http://good/f", TransportKind::Http, Ok(ranged(100))),
                source("http://evil/f", TransportKind::Http, Ok(ranged(HUGE))),
            ],
            checksum: None,
        };
        assert_eq!(
            merge_probes(input),
            Err(HttpError::TotalLengthExceeded {
                total: HUGE,
                max: grid::MAX_TOTAL_LEN
            })
        );
    }

    #[test]
    fn merge_length_mismatch_is_error_without_checksum() {
        let input = MergeInput {
            sources: vec![
                source("http://a/f", TransportKind::Http, Ok(ranged(100))),
                source("http://b/f", TransportKind::Http, Ok(ranged(200))),
            ],
            checksum: None,
        };
        assert_eq!(merge_probes(input), Err(HttpError::MirrorMismatch));
    }

    #[test]
    fn merge_mismatch_with_checksum_keeps_first_length_group() {
        // With `--checksum`, the verifiable group wins (the first
        // source's length group) and other length groups are dropped —
        // no hard failure.
        let input = MergeInput {
            sources: vec![
                source("http://a/f", TransportKind::Http, Ok(ranged(100))),
                source("http://b/f", TransportKind::Http, Ok(ranged(200))),
                source("http://c/f", TransportKind::Http, Ok(no_range(200))),
            ],
            checksum: Some(("sha-256".into(), "abc".into())),
        };
        match merge_probes(input) {
            Ok(MergedPlan::Segmented {
                total_len,
                sources,
                warnings,
                ..
            }) => {
                assert_eq!(total_len, 100);
                assert_eq!(sources.len(), 1);
                assert_eq!(sources[0].uri, "http://a/f");
                assert_eq!(
                    warnings,
                    vec![
                        MergeWarning::LengthGroupDropped {
                            uri: "http://b/f".into()
                        },
                        // The CL=200 no-range source belongs to the
                        // non-authoritative length group.
                        MergeWarning::LengthGroupDropped {
                            uri: "http://c/f".into()
                        },
                    ]
                );
            }
            other => panic!("expected segmented, got {other:?}"),
        }
    }

    #[test]
    fn merge_all_probe_failed_is_no_source() {
        let input = MergeInput {
            sources: vec![
                source(
                    "http://a/f",
                    TransportKind::Http,
                    Err(HttpError::Transport("refused".into())),
                ),
                source(
                    "http://b/f",
                    TransportKind::Http,
                    Err(HttpError::UnexpectedResponse { status: 404 }),
                ),
            ],
            checksum: None,
        };
        assert_eq!(merge_probes(input), Err(HttpError::NoSource));

        let empty = MergeInput {
            sources: vec![],
            checksum: None,
        };
        assert_eq!(merge_probes(empty), Err(HttpError::NoSource));
    }

    #[test]
    fn merge_content_type_difference_warns_only() {
        // Type differences do not fail: merge succeeds + warning
        // recorded (aria2 does not compare types).
        let mut b = ranged(100).result().clone();
        b.content_type = Some("video/mp4".into());
        let input = MergeInput {
            sources: vec![
                source("http://a/f", TransportKind::Http, Ok(ranged(100))),
                source(
                    "http://b/f",
                    TransportKind::Http,
                    Ok(ProbeVerdict::RangeWithLength(b)),
                ),
            ],
            checksum: None,
        };
        match merge_probes(input) {
            Ok(MergedPlan::Segmented {
                total_len,
                sources,
                warnings,
                ..
            }) => {
                assert_eq!(total_len, 100);
                assert_eq!(sources.len(), 2);
                assert_eq!(
                    warnings,
                    vec![MergeWarning::ContentTypeMismatch {
                        uri_a: "http://a/f".into(),
                        type_a: "application/octet-stream".into(),
                        uri_b: "http://b/f".into(),
                        type_b: "video/mp4".into(),
                    }]
                );
            }
            other => panic!("expected segmented, got {other:?}"),
        }
    }

    #[test]
    fn merge_mixed_capability_only_206_sources_segment() {
        // Mixed capability: only 206+TOTAL sources segment; no-range
        // sources dropped (warned); probe-failed sources dropped too.
        let input = MergeInput {
            sources: vec![
                source(
                    "http://dead/f",
                    TransportKind::Http,
                    Err(HttpError::Transport("timeout".into())),
                ),
                source("http://ok/f", TransportKind::Http, Ok(ranged(500))),
                source("http://norange/f", TransportKind::Http, Ok(no_range(500))),
                source("http://weak/f", TransportKind::Http, Ok(ranged_weak())),
            ],
            checksum: None,
        };
        match merge_probes(input) {
            Ok(MergedPlan::Segmented {
                total_len,
                sources,
                warnings,
                ..
            }) => {
                assert_eq!(total_len, 500);
                assert_eq!(sources.len(), 1);
                assert_eq!(sources[0].uri, "http://ok/f");
                assert_eq!(
                    warnings,
                    vec![
                        MergeWarning::ProbeFailedDropped {
                            uri: "http://dead/f".into(),
                            code: "taiji.http.transport",
                        },
                        MergeWarning::NonSegmentableDropped {
                            uri: "http://norange/f".into()
                        },
                        MergeWarning::NonSegmentableDropped {
                            uri: "http://weak/f".into()
                        },
                    ]
                );
            }
            other => panic!("expected segmented, got {other:?}"),
        }
    }

    #[test]
    fn merge_all_no_range_degrades_to_first_source() {
        // All no-range → degrade to the first source
        // single-connection, the rest dropped.
        let input = MergeInput {
            sources: vec![
                source("http://first/f", TransportKind::Http, Ok(no_range(42))),
                source("http://second/f", TransportKind::Http, Ok(no_range(42))),
                source("http://weak/f", TransportKind::Http, Ok(ranged_weak())),
            ],
            checksum: None,
        };
        match merge_probes(input) {
            Ok(MergedPlan::SingleConnection {
                source,
                self_decompress,
                warnings,
                ..
            }) => {
                assert_eq!(source.uri, "http://first/f");
                assert!(!self_decompress);
                assert_eq!(
                    warnings,
                    vec![
                        MergeWarning::NonSegmentableDropped {
                            uri: "http://second/f".into()
                        },
                        MergeWarning::NonSegmentableDropped {
                            uri: "http://weak/f".into()
                        },
                    ]
                );
            }
            other => panic!("expected single connection, got {other:?}"),
        }
    }

    #[test]
    fn merge_encoded_first_source_flags_self_decompress() {
        // Encoded first source → single-connection degrade +
        // self-decompress flag.
        let input = MergeInput {
            sources: vec![source("http://gz/f", TransportKind::Http, Ok(encoded()))],
            checksum: None,
        };
        match merge_probes(input) {
            Ok(MergedPlan::SingleConnection {
                self_decompress,
                authoritative,
                ..
            }) => {
                assert!(self_decompress);
                assert_eq!(authoritative.encoding, Some("gzip".into()));
            }
            other => panic!("expected single connection, got {other:?}"),
        }
    }

    #[test]
    fn merge_empty_file_first_source_is_done() {
        // All sources 416+`*/0` → empty-file done; non-first sources
        // (also non-segmentable shapes) dropped into the warnings; a
        // first empty file + weak source (no length contradiction) is
        // done too.
        let all_empty = MergeInput {
            sources: vec![
                source("http://a/f", TransportKind::Http, Ok(empty_file())),
                source("http://b/f", TransportKind::Http, Ok(empty_file())),
            ],
            checksum: None,
        };
        assert_eq!(
            merge_probes(all_empty),
            Ok(MergedPlan::EmptyFile {
                warnings: vec![MergeWarning::NonSegmentableDropped {
                    uri: "http://b/f".into()
                }]
            })
        );

        let first_empty = MergeInput {
            sources: vec![
                source("http://a/f", TransportKind::Http, Ok(empty_file())),
                source("http://weak/f", TransportKind::Http, Ok(ranged_weak())),
            ],
            checksum: None,
        };
        assert_eq!(
            merge_probes(first_empty),
            Ok(MergedPlan::EmptyFile {
                warnings: vec![MergeWarning::NonSegmentableDropped {
                    uri: "http://weak/f".into()
                }]
            })
        );

        // An empty file contradicting a healthy source's length (0 vs
        // 100) → the mirror_mismatch path.
        let conflicting = MergeInput {
            sources: vec![
                source("http://a/f", TransportKind::Http, Ok(empty_file())),
                source("http://b/f", TransportKind::Http, Ok(ranged(100))),
            ],
            checksum: None,
        };
        assert_eq!(merge_probes(conflicting), Err(HttpError::MirrorMismatch));
    }
}
