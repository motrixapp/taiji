//! HTTP engine error skeleton (thiserror per crate; cross-crate
//! normalization lives in core).
//!
//! Error codes are canonical `taiji.*` strings. This enum carries the
//! engine-side variants for the transport/redirect/cookie surfaces plus
//! the classification-table codes (`bad_range`, `path_conflict`,
//! `mirror_mismatch`, `no_source`), the unified authentication code
//! `taiji.auth.failed`, and the `--checksum` final verdict
//! `taiji.http.checksum_mismatch` (numeric face 32).
//! `taiji.option.invalid` and the metalink family extend the same enum
//! as their tasks land. The RPC-side error mapping has its single
//! source in taiji-rpc — new variants here only name engine-side
//! diagnostics and never pre-allocate RPC numeric codes.
//!
//! Crate positioning: the trait-signature
//! closure came along in the verbatim lift — the three segmentation
//! traits return `Result` (`Result<T, E = HttpError>`), so the error
//! face moved with them; `taiji-http` re-exports this module as its
//! path-stable transition face, and the `taiji.http.*` code strings
//! plus the taiji-rpc numeric mapping are untouched by the move.

/// HTTP engine error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// Range request conflicts with the authoritative length (probe
    /// 416 + `Content-Range: bytes */N` with N>0 → the length
    /// changed).
    #[error("taiji.http.bad_range: range conflicts with authoritative length")]
    BadRange,

    /// `.part`/output path conflict (engine-side check at task
    /// creation).
    #[error("taiji.http.path_conflict: output path conflicts with an existing file")]
    PathConflict,

    /// Multi-source probe lengths disagree (any two TOTALs differ;
    /// with `--checksum` the verifiable group wins, the rest are
    /// dropped).
    #[error("taiji.http.mirror_mismatch: mirror total lengths disagree")]
    MirrorMismatch,

    /// Every source removed: nothing usable remains after drops and
    /// downgrades.
    #[error("taiji.http.no_source: no usable source remains")]
    NoSource,

    /// Probe/response shape outside the classification table (an
    /// out-of-table status, or a missing/unparseable `Content-Range`
    /// in a 206/416). A 206 whose echo mismatches the probe's
    /// `bytes=0-0` goes to [`HttpError::BadRange`] (aria2
    /// `HttpResponse.cc` isRangeSatisfied → CANNOT_RESUME). The RPC
    /// numeric mapping draft lives in the taiji-rpc error mapping
    /// table (default HTTP_PROTOCOL_ERROR=22, with 404/401/502-504
    /// exceptions).
    #[error(
        "taiji.http.unexpected_response: probe response outside the classification table (HTTP {status})"
    )]
    UnexpectedResponse {
        /// Raw response status code.
        status: u16,
    },

    /// A 429/503 throttle response carrying `Retry-After` (same
    /// semantics as aria2's `parseUnavailableHeaders`): `after_secs`
    /// is the server-suggested wait in seconds (parsed from a
    /// delta-seconds or HTTP-date form,
    /// taiji_http::retry::parse_retry_after). Consumers (the
    /// extent-level failure arm) clamp it via
    /// taiji_http::retry::clamp_retry_after before backing off — the
    /// server value wins, clamped to a 30s ceiling. The canonical code
    /// stays in the `taiji.http.unexpected_response` family (no new
    /// external code face; the diagnostic split lives in the Display
    /// payload).
    #[error(
        "taiji.http.unexpected_response: HTTP {status} throttled, Retry-After: {after_secs}s (server hint honored, clamped)"
    )]
    RetryAfter {
        /// Throttle status code (429/503).
        status: u16,
        /// Server-suggested wait in seconds (parsed raw; clamping
        /// belongs to the consumer).
        after_secs: u64,
    },

    /// Redirect hop limit exceeded (default 20; aria2 `--max-redirect`
    /// default 20). `max` = the configured limit.
    #[error("taiji.http.redirect_limit: redirect hop limit exceeded (max {max})")]
    RedirectLimit {
        /// Configured maximum hops (`ClientConfig::max_redirects`).
        max: u32,
    },

    /// Redirect cycle: the visited set hit an already-visited URL.
    #[error("taiji.http.redirect_loop: redirect cycle detected (visited set hit)")]
    RedirectLoop,

    /// https→http downgrade redirects refused by default (explicitly
    /// allowed via `ClientConfig::allow_insecure_downgrade`).
    #[error("taiji.http.insecure_redirect: https to http downgrade redirect refused")]
    InsecureRedirect,

    /// Redirect-target IP hygiene rejection: the task's initial URL
    /// was unrestricted (public) but a redirect hop resolves to a
    /// restricted address (loopback/RFC1918/link-local/ULA/
    /// v4-mapped/NAT64-embedded v4/unspecified/multicast) — the SSRF
    /// face of a malicious or hijacked source (cloud metadata
    /// 169.254.169.254, internal host/port probing). Payload = the
    /// target host (diagnostics only, no credentials/paths). An
    /// initially restricted task (localhost/LAN) never produces this
    /// error (all hops allowed, per the initial policy). A
    /// deterministic protocol refusal; retrying is worthless
    /// (taiji_http::retry::transport_retryable is always false).
    #[error(
        "taiji.http.redirect_to_restricted_ip: redirect target in restricted address space refused: {host}"
    )]
    RedirectToRestrictedIp {
        /// The rejected redirect target host (URL host face, no
        /// credentials).
        host: String,
    },

    /// A `--load-cookies` file beyond the 1MiB cap.
    #[error("taiji.http.cookie_file_too_large: cookie file exceeds {max_bytes} bytes")]
    CookieFileTooLarge {
        /// The cap in bytes (currently 1MiB).
        max_bytes: u64,
    },

    /// Cookie file read/thread failure (the parser tolerantly skips
    /// bad lines; that never produces this error).
    #[error("taiji.http.cookie_file: cookie file failure: {0}")]
    CookieFile(String),

    /// Network transport failure (reqwest face). Payload is the
    /// error-chain text (URL stripped, per the unified redaction
    /// discipline).
    #[error("taiji.http.transport: transport failure: {0}")]
    Transport(String),

    /// Permanent DNS failure (NXDOMAIN-class resolution endgame — the
    /// name does not exist / has no address; retrying is worthless).
    /// The typed carrier for a decision made at the classification
    /// seam in taiji_http::client (before the reqwest error chain is
    /// flattened): retry semantics match aria2's `NAME_RESOLVE_ERROR`
    /// hard failure (`AbstractCommand.cc` DL_ABORT_EX2 — a
    /// name-resolution failure is final, no retry loop). The code face
    /// is unchanged: the string code is the same
    /// `taiji.http.transport` face as [`HttpError::Transport`] (RPC
    /// numeric code 6 resolves through the taiji-rpc mapping table's
    /// single source; no new code face or split dimension — the
    /// DNS-specific split of code 19 is unreachable in the production
    /// rendering chain, so the existing fallback to 6 stays).
    #[error("taiji.http.transport: dns permanent failure: {0}")]
    DnsPermanent(String),

    /// Authentication challenges exhausted/unanswerable (one code for
    /// HTTP/FTP/SFTP; the numeric face maps to 24 HTTP_AUTH_FAILED).
    /// Payload is diagnostics only (no credentials). A 401 without
    /// credentials goes to [`HttpError::UnexpectedResponse`]
    /// (pass-through semantics unchanged).
    #[error("taiji.auth.failed: authentication failed: {0}")]
    AuthFailed(String),

    /// `--checksum` completion-time verification mismatch (failure =
    /// task error, never an automatic re-download). The string code is
    /// named with the verification face; the numeric face = 32
    /// CHECKSUM_ERROR (aria2 `ChecksumCheckIntegrityEntry.cc`; the
    /// taiji-rpc mapping table maps the same point).
    #[error("taiji.http.checksum_mismatch: checksum mismatch (expected {expected}, got {got})")]
    ChecksumMismatch {
        /// Expected digest (lowercase hex).
        expected: String,
        /// Computed digest (lowercase hex).
        got: String,
    },

    /// An option value outside its configuration domain (domain
    /// validation and out-of-domain rejection; changeOption
    /// out-of-domain values are always rejected, never truncated).
    /// Produced by the scheduler's block-grid and scheduling-parameter
    /// validation.
    #[error("taiji.option.invalid: option {option} value out of domain: {value}")]
    OptionInvalid {
        /// Option name (e.g. `--http-block-size` / `--http-scheduler`).
        option: &'static str,
        /// The rejected original value text (diagnostics).
        value: String,
    },

    /// The scheduling actor stopped (the task close-out state after a
    /// block-completion accounting fault; the original error surfaces
    /// via the actor JoinHandle — this variant only marks "no longer
    /// accepting messages").
    #[error("taiji.http.coordinator_stopped: extent coordinator is no longer running")]
    CoordinatorStopped,

    /// FTP/FTPS transfer failure (control-channel protocol error /
    /// data-channel IO / DNS). Payload is diagnostics only: the status
    /// code digits and IO error text, never paths/credentials/server
    /// banner echoes (unified redaction). The RPC numeric mapping is
    /// maintained with the divergence declaration.
    #[error("taiji.http.ftp: ftp failure: {0}")]
    Ftp(String),

    /// FTP/FTPS control-connection DNS resolution failure (the
    /// taiji_http::ftp resolve face runs through the shared
    /// `taiji_io::dns` resolver and carries the typed
    /// [`taiji_io::dns::ResolveError`] as-is — no stringification, the
    /// source chain stays downcastable). The code face is unchanged:
    /// the same `taiji.http.ftp` string code as [`HttpError::Ftp`]
    /// (RPC numeric code 21 resolves through the string code via the
    /// taiji-rpc mapping table's single source; no new code face or
    /// split dimension).
    #[error("taiji.http.ftp: ftp failure: {0}")]
    FtpDns(taiji_io::dns::ResolveError),

    /// The server refused REST (the segmentation-resume prerequisite):
    /// an offset-carrying segment hitting a REST-less server fails
    /// loudly; the probe face (taiji_http::ftp::FtpProbe) should
    /// already have routed it into single-stream degrade (no bitmap,
    /// resume from zero).
    #[error("taiji.http.ftp_resume_unsupported: server does not support REST (resume)")]
    FtpResumeUnsupported,

    /// Local disk failure (`.part` open / positioned write / fsync /
    /// path probe; the payload carries gid + path context, per the
    /// disk write path's logging discipline). The recoverable-rename
    /// terminal state does not use this variant
    /// (taiji_http::finalize::FinalizeOutcome::RenamePending).
    #[error("taiji.http.disk: local disk failure: {0}")]
    Disk(String),

    /// A download-phase Range request received 200 OK after probing
    /// confirmed segmentability (206 + Content-Range) — same semantics
    /// as aria2 `executeDownload`'s "Expected partial, but received
    /// OK" → `STATUS_CANNOT_RESUME`: server capability drift or
    /// lying. Explicit failure semantics: never keep assuming 206 on
    /// the probe's word, never burn extent retries (a deterministic
    /// shape; retrying is worthless), never silently restart from zero
    /// (misaligned-overwrite risk). Same code slot as a probing-phase
    /// 200 (classification rows: the source honestly does not support
    /// Range → single-connection degrade) but a different meaning — a
    /// download-phase 200 contradicts confirmed capability. The RPC
    /// numeric mapping is maintained with the divergence declaration.
    #[error(
        "taiji.http.range_ignored: expected partial (206) after probe confirmed range support, but received 200 OK"
    )]
    RangeIgnored,

    /// A download-phase Range request received 412 Precondition Failed
    /// (the If-Match conditional-resume server gate): after the probe
    /// confirmed a strong ETag, fetch requests carry `If-Match:
    /// <etag>` — a mid-download server content change answers 412.
    /// Same family as the probe's 416 + `Content-Range: bytes */N`
    /// (length changed): a deterministic protocol fact (resource
    /// identity drifted), retrying is worthless — the consumer (grid /
    /// per-item / batch-worker failure arms) goes fatal once, ending
    /// the attempt, and the task clears its bitmap to re-download from
    /// zero (the running analog of an ETag mismatch → Restart: the
    /// server rejects misaligned resumes up front instead of waiting
    /// for the checksum to catch it after the bitmap is fully
    /// written). The canonical code stays in the
    /// `taiji.http.bad_range` family (the 416/BadRange path — no new
    /// external code face; the diagnostic split lives in the Display).
    #[error(
        "taiji.http.bad_range: 412 precondition failed (if-match): server content changed mid-download"
    )]
    PreconditionFailed,

    /// The authoritative total length exceeds the engine cap
    /// (taiji_http::grid::MAX_TOTAL_LEN). A malicious/broken source
    /// reporting a 2^63-scale `Content-Range` total /
    /// `Content-Length` would drag the whole process down through the
    /// block-grid bitmap allocation — beyond the cap is always a
    /// task-level rejection (never a source-level drop: mixed-source
    /// merging must leave no path to a giant bitmap allocation).
    #[error(
        "taiji.http.total_length_exceeded: authoritative total length {total} exceeds engine cap {max}"
    )]
    TotalLengthExceeded {
        /// The rejected total length (bytes).
        total: u64,
        /// The engine cap (bytes, taiji_http::grid::MAX_TOTAL_LEN).
        max: u64,
    },
}

impl HttpError {
    /// Connection-reset/interruption criterion (the classification
    /// face wired to taiji_http::aimd::CongestionKind::Reset's
    /// multiply-decrease trigger): peer RST / connection-interruption
    /// signatures inside transport-failure payloads. Ordinary request
    /// failures must never be classified as congestion (the
    /// pending-items gate requires it — otherwise failure noise would
    /// trigger decreases): out-of-table statuses
    /// ([`HttpError::UnexpectedResponse`]), DNS / timeout /
    /// connection-refused and other non-interruption transport
    /// failures, and protocol short-read / over-read are all
    /// constantly false.
    pub fn is_connection_reset(&self) -> bool {
        match self {
            HttpError::Transport(msg) | HttpError::Ftp(msg) => is_reset_signature(msg),
            _ => false,
        }
    }

    /// Engine-side error classification (the FTP/status-code feed
    /// point of `taiji_http_errors_total{class}`; the HTTP transport
    /// class is counted at the client's classification seam BEFORE
    /// flattening, so `Transport` payloads are always None here —
    /// preventing a double count of one failure). Returns None = not
    /// counted (protocol contradictions / local disk / configuration
    /// failures have no transport attribution — no metric without a
    /// feed point).
    pub fn error_class(&self) -> Option<taiji_io::metrics::HttpErrorClass> {
        use taiji_io::dns::{classify_error_chain, dns_persistence_of};
        use taiji_io::metrics::{HttpErrorClass, http_error_class_of};
        match self {
            // Typed DNS payload (the FTP control-connection resolve
            // face through the shared resolver, type preserved) —
            // persistence read directly.
            HttpError::FtpDns(re) => Some(HttpErrorClass::Dns(dns_persistence_of(re))),
            // FTP string payload: the diagnostic text is attributed
            // through the classification single source's text path.
            HttpError::Ftp(msg) => http_error_class_of(classify_error_chain(
                taiji_io::dns::TransportHints::default(),
                &ChainText(msg.clone()),
            )),
            // Status-code failure face (probe classification /
            // download-phase non-206 arms / throttling).
            HttpError::UnexpectedResponse { status } => status_class(*status),
            HttpError::RetryAfter { status, .. } => status_class(*status),
            // The transport class is already counted at the client's
            // classification seam (before flattening) — None here
            // prevents a double count.
            HttpError::Transport(_) | HttpError::DnsPermanent(_) => None,
            // Other variants have no transport attribution, not
            // counted.
            _ => None,
        }
    }

    /// The canonical `taiji.*` error code (the engine-side single
    /// source; the HTTP-failure → aria2 numeric-error-code mapping is
    /// a separate table in taiji-rpc).
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRange => "taiji.http.bad_range",
            Self::PathConflict => "taiji.http.path_conflict",
            Self::MirrorMismatch => "taiji.http.mirror_mismatch",
            Self::NoSource => "taiji.http.no_source",
            Self::UnexpectedResponse { .. } => "taiji.http.unexpected_response",
            Self::RetryAfter { .. } => "taiji.http.unexpected_response",
            Self::RangeIgnored => "taiji.http.range_ignored",
            Self::PreconditionFailed => "taiji.http.bad_range",
            Self::RedirectLimit { .. } => "taiji.http.redirect_limit",
            Self::RedirectLoop => "taiji.http.redirect_loop",
            Self::InsecureRedirect => "taiji.http.insecure_redirect",
            Self::RedirectToRestrictedIp { .. } => "taiji.http.redirect_to_restricted_ip",
            Self::CookieFileTooLarge { .. } => "taiji.http.cookie_file_too_large",
            Self::CookieFile(_) => "taiji.http.cookie_file",
            Self::Transport(_) | Self::DnsPermanent(_) => "taiji.http.transport",
            Self::AuthFailed(_) => "taiji.auth.failed",
            Self::ChecksumMismatch { .. } => "taiji.http.checksum_mismatch",
            Self::OptionInvalid { .. } => "taiji.option.invalid",
            Self::CoordinatorStopped => "taiji.http.coordinator_stopped",
            Self::Ftp(_) | Self::FtpDns(_) => "taiji.http.ftp",
            Self::FtpResumeUnsupported => "taiji.http.ftp_resume_unsupported",
            Self::Disk(_) => "taiji.http.disk",
            Self::TotalLengthExceeded { .. } => "taiji.http.total_length_exceeded",
        }
    }
}

/// Crate result alias: the `Result<>` in trait signatures expands
/// through this.
pub type Result<T, E = HttpError> = std::result::Result<T, E>;

/// An `Error`-shaped wrapper for diagnostic text (the classification
/// single source's input adapter — the FTP string payload has no
/// source chain; the wrapper only satisfies the
/// `&(dyn Error + 'static)` traversal contract, no behavior; it owns
/// its string — error paths are not hot, no lifetime escape
/// concerns).
#[derive(Debug)]
struct ChainText(String);

impl std::fmt::Display for ChainText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ChainText {}

/// Status code → error class (the 4xx/5xx slots; out-of-table statuses
/// are not counted).
fn status_class(status: u16) -> Option<taiji_io::metrics::HttpErrorClass> {
    match status {
        400..=499 => Some(taiji_io::metrics::HttpErrorClass::Http4xx),
        500..=599 => Some(taiji_io::metrics::HttpErrorClass::Http5xx),
        _ => None,
    }
}

/// Engine-side error-classification counter feed point (the process
/// default registry — the production assembly precedent; `None`
/// classes are not counted). The FTP face ([`HttpError::Ftp`] /
/// [`HttpError::FtpDns`]) and status-code failures are counted here
/// into `taiji_http_errors_total`; the unit is per failed request
/// (retries / source switches amplify by N).
pub fn note_http_error(err: &HttpError) {
    if let Some(class) = err.error_class() {
        taiji_io::metrics::registry_default()
            .http()
            .note_error(class);
    }
}

/// RST/interruption signatures (inside the transport-failure payload
/// text, case-insensitive substrings):
/// - the ECONNRESET family: "connection reset (by peer)" — kernel
///   errno text (macOS 54 / Linux 104) matching the ErrorKind text;
/// - EPIPE: "broken pipe" — the interrupted shape of writing on after
///   the peer stopped;
/// - hyper's mid-stream close signature: "connection closed before
///   message completed" — the response body cut short (the transport
///   face of a peer interruption/drop).
///
/// The signature set is deliberately conservative: only
/// peer-interruption signatures, never failures attributable to local
/// configuration or protocol semantics (wrong status, DNS, timeouts,
/// short reads, over reads).
fn is_reset_signature(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("connection closed before message completed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_canonical_namespace() {
        let cases = [
            (HttpError::BadRange, "taiji.http.bad_range"),
            (HttpError::PathConflict, "taiji.http.path_conflict"),
            (HttpError::MirrorMismatch, "taiji.http.mirror_mismatch"),
            (HttpError::NoSource, "taiji.http.no_source"),
            (
                HttpError::UnexpectedResponse { status: 404 },
                "taiji.http.unexpected_response",
            ),
            (
                HttpError::RedirectLimit { max: 20 },
                "taiji.http.redirect_limit",
            ),
            (HttpError::RedirectLoop, "taiji.http.redirect_loop"),
            (HttpError::InsecureRedirect, "taiji.http.insecure_redirect"),
            // Redirect IP hygiene: a new error shape (engine-side
            // diagnostic naming, no pre-allocated RPC numeric — the
            // taiji-rpc mapping table resolves by string code as its
            // single source; out-of-table codes fall to the UNKNOWN
            // fallback row).
            (
                HttpError::RedirectToRestrictedIp {
                    host: "169.254.169.254".into(),
                },
                "taiji.http.redirect_to_restricted_ip",
            ),
            (
                HttpError::CookieFileTooLarge {
                    max_bytes: 1024 * 1024,
                },
                "taiji.http.cookie_file_too_large",
            ),
            (HttpError::CookieFile("io".into()), "taiji.http.cookie_file"),
            (HttpError::Transport("dns".into()), "taiji.http.transport"),
            // DNS permanent-failure variant, same code face (stability
            // pinned by dns_permanent_error_code_face_is_stable).
            (
                HttpError::DnsPermanent("nxdomain".into()),
                "taiji.http.transport",
            ),
            (
                HttpError::AuthFailed("digest challenge".into()),
                "taiji.auth.failed",
            ),
            (
                HttpError::ChecksumMismatch {
                    expected: "ab".into(),
                    got: "cd".into(),
                },
                "taiji.http.checksum_mismatch",
            ),
            (
                HttpError::OptionInvalid {
                    option: "--http-block-size",
                    value: "3MiB".into(),
                },
                "taiji.option.invalid",
            ),
            (
                HttpError::CoordinatorStopped,
                "taiji.http.coordinator_stopped",
            ),
            (HttpError::Ftp("control channel".into()), "taiji.http.ftp"),
            // FTP DNS typed payload, same code face (stability pinned
            // by ftp_dns_error_code_face_is_stable).
            (
                HttpError::FtpDns(taiji_io::dns::ResolveError::Failed("nxdomain".into())),
                "taiji.http.ftp",
            ),
            (
                HttpError::FtpResumeUnsupported,
                "taiji.http.ftp_resume_unsupported",
            ),
            (HttpError::Disk("open .part".into()), "taiji.http.disk"),
            (
                HttpError::TotalLengthExceeded {
                    total: u64::MAX,
                    max: 1,
                },
                "taiji.http.total_length_exceeded",
            ),
            (HttpError::RangeIgnored, "taiji.http.range_ignored"),
            // The 412 variant reuses the bad_range family code (the
            // 416/BadRange path).
            (HttpError::PreconditionFailed, "taiji.http.bad_range"),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code);
            // Display starts with the canonical code, easing log/audit
            // reconciliation.
            assert!(err.to_string().starts_with(code), "{err}");
        }
    }

    /// The unified redaction discipline's code-side backstop:
    /// transport-failure payloads have the URL stripped by `client` at
    /// construction; this test pins the enum's Clone/Eq face
    /// regardless of payload.
    #[test]
    fn transport_payload_is_value_semantics() {
        let a = HttpError::Transport("connect refused".into());
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(b.code(), "taiji.http.transport");
    }

    /// Code-face stability of the DNS permanent-failure variant (the
    /// retry semantics changed, the code face did not): the string
    /// code matches [`HttpError::Transport`] (RPC numeric code 6
    /// unchanged), the Display prefix is unchanged, it is not a peer
    /// interruption (the decrease criterion constantly false), and the
    /// classification seam reads persistence directly.
    #[test]
    fn dns_permanent_error_code_face_is_stable() {
        let e = HttpError::DnsPermanent("nxdomain".into());
        assert_eq!(e.code(), "taiji.http.transport");
        assert!(e.to_string().starts_with("taiji.http.transport:"));
        assert!(
            !e.is_connection_reset(),
            "DNS failure is not a peer interruption"
        );
        // Classification-seam path: the variant itself is never
        // reclassified (Transport-family constantly None — counted
        // before flattening, no double count); the persistence fact is
        // carried by the variant name.
        assert_eq!(e.error_class(), None);
    }

    /// The engine-side error classification table (`error_class` —
    /// the FTP/status feed-point attribution): FtpDns persistence read
    /// directly, Ftp text attribution, status 4xx/5xx slots, and
    /// non-transport variants plus the Transport family not counted.
    #[test]
    fn engine_error_class_table() {
        use taiji_io::dns::{DnsPersistence, ResolveError};
        use taiji_io::metrics::HttpErrorClass;
        // FtpDns: typed payload, persistence read directly.
        assert_eq!(
            HttpError::FtpDns(ResolveError::Failed("nxdomain".into())).error_class(),
            Some(HttpErrorClass::Dns(DnsPersistence::Permanent))
        );
        assert_eq!(
            HttpError::FtpDns(ResolveError::Timeout(std::time::Duration::from_secs(30)))
                .error_class(),
            Some(HttpErrorClass::Dns(DnsPersistence::Transient))
        );
        // Ftp text: connection refused/reset/TLS attribution (the
        // suppaftp payload shape).
        assert_eq!(
            HttpError::Ftp("connection: Connection refused (os error 61)".into()).error_class(),
            Some(HttpErrorClass::Refused)
        );
        assert_eq!(
            HttpError::Ftp("connection: Connection reset by peer (os error 54)".into())
                .error_class(),
            Some(HttpErrorClass::Reset)
        );
        assert_eq!(
            HttpError::Ftp("tls: invalid peer certificate".into()).error_class(),
            Some(HttpErrorClass::Tls)
        );
        // Unmarked Ftp text (protocol receipts etc.) is not counted.
        assert_eq!(
            HttpError::Ftp("unexpected server reply (550)".into()).error_class(),
            None,
            "FTP protocol error with no transport attribution is not counted"
        );
        // Status-code slots.
        assert_eq!(
            HttpError::UnexpectedResponse { status: 404 }.error_class(),
            Some(HttpErrorClass::Http4xx)
        );
        assert_eq!(
            HttpError::RetryAfter {
                status: 503,
                after_secs: 30
            }
            .error_class(),
            Some(HttpErrorClass::Http5xx)
        );
        assert_eq!(
            HttpError::UnexpectedResponse { status: 302 }.error_class(),
            None,
            "out-of-table non-4xx/5xx status is not counted"
        );
        // The Transport family (counted before flattening) and other
        // variants are not counted.
        assert_eq!(HttpError::Transport("x".into()).error_class(), None);
        assert_eq!(HttpError::BadRange.error_class(), None);
        assert_eq!(HttpError::Disk("open".into()).error_class(), None);
    }

    /// Code-face stability of FTP DNS failures (the typed rewrite does
    /// not change the RPC projection): [`HttpError::FtpDns`]'s typed
    /// payload and [`HttpError::Ftp`]'s string payload share the
    /// strict `taiji.http.ftp` string code and the same Display
    /// prefix/shape — RPC numeric code 21 resolves through the
    /// taiji-rpc mapping table by string code as its single source
    /// (`"taiji.http.ftp" => 21`, locked by the taiji-rpc mapping
    /// test), and this assertion pins the typed variant to the same
    /// mapping row; the HTTP transport face (DNS text rides the chain
    /// into [`HttpError::Transport`] → Bare → 6) is likewise locked by
    /// the existing rpc rows, and here we pin the engine-side
    /// string-code prefix against this rewrite.
    #[test]
    fn ftp_dns_error_code_face_is_stable() {
        let dns_timeout = HttpError::FtpDns(taiji_io::dns::ResolveError::Timeout(
            std::time::Duration::from_secs(30),
        ));
        let dns_failed = HttpError::FtpDns(taiji_io::dns::ResolveError::Failed("nxdomain".into()));
        let string_form = HttpError::Ftp("read idle timeout".into());
        // Same string-code face for both payloads (one code face, no
        // split dimension).
        assert_eq!(dns_timeout.code(), "taiji.http.ftp");
        assert_eq!(dns_failed.code(), string_form.code());
        // Display shape: canonical code prefix + "ftp failure:", the
        // same shape as Ftp (the log/audit reconciliation face stays
        // unbroken).
        assert_eq!(
            dns_timeout.to_string(),
            "taiji.http.ftp: ftp failure: dns resolution timed out after 30s"
        );
        assert_eq!(
            dns_failed.to_string(),
            "taiji.http.ftp: ftp failure: dns resolution failed: nxdomain"
        );
        // DNS failures are not peer interruptions (the decrease
        // criterion constantly false — same verdict as the string
        // form).
        assert!(!dns_timeout.is_connection_reset());
        assert!(!dns_failed.is_connection_reset());
    }

    /// The reset/interruption signature criterion, positive and
    /// negative table: peer-interruption signatures always test true
    /// (including real error-chain-expanded shapes — reqwest top-level
    /// text + kernel errno source); ordinary request failures (status
    /// codes / DNS / timeouts / connection refused / protocol short
    /// reads / local configuration) always test false — decreases must
    /// never be triggered by failure noise (the aimd.rs pending-items
    /// gate).
    #[test]
    fn connection_reset_signature_table() {
        // Positives: real error-chain-expanded text (the client-side
        // error_chain payload).
        let positives = [
            "error sending request for url (redacted): client error (Connect): \
             tcp connect error: Connection reset by peer (os error 54)",
            "error decoding response body: connection error: \
             Connection reset by peer (os error 54)",
            "error decoding response body: connection error: \
             Connection reset by peer (os error 104)",
            "error decoding response body: connection error: connection reset",
            "connection closed before message completed",
            "error reading a body from connection: broken pipe",
            // Ftp-face payloads (status digits + IO error text) use
            // the same criterion.
            "ftp failure: 150 opening data connection: Connection reset by peer (os error 54)",
        ];
        for p in positives {
            assert!(
                HttpError::Transport(p.into()).is_connection_reset(),
                "positive must classify true: {p}"
            );
        }
        assert!(
            HttpError::Ftp("data connection: broken pipe".into()).is_connection_reset(),
            "Ftp variant payload under the same criterion"
        );

        // Negatives: ordinary request failures must never be
        // classified as congestion.
        let negatives = [
            // Status-code face (out-of-table statuses / throttling —
            // throttling takes its own seam).
            "taiji.http.unexpected_response",
            // DNS / connection refused / timeout (established or
            // peer-interruption evidence absent).
            "error sending request for url (redacted): client error (Connect): \
             dns error: failed to lookup address information",
            "error sending request for url (redacted): connection refused (os error 61)",
            "error sending request for url (redacted): operation timed out",
            // Protocol face (local decisions, not peer interruptions).
            "body short read: got 128, want 262144",
            "bad location header: invalid utf-8",
            "invalid url: relative URL without a base",
            "proxy: tunnel unavailable",
            // Empty-payload defense.
            "",
        ];
        for n in negatives {
            assert!(
                !HttpError::Transport(n.into()).is_connection_reset(),
                "negative must classify false: {n}"
            );
        }

        // Non-transport variants constantly false (UnexpectedResponse
        // included — 429 takes its own seam, this criterion is not
        // involved).
        assert!(!HttpError::UnexpectedResponse { status: 500 }.is_connection_reset());
        assert!(!HttpError::UnexpectedResponse { status: 429 }.is_connection_reset());
        assert!(!HttpError::CoordinatorStopped.is_connection_reset());
        assert!(!HttpError::BadRange.is_connection_reset());
    }
}
