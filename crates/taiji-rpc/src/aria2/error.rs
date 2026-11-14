//! RPC error mapping table — the repo-wide single source (the adapter
//! layer's home: `crate::aria2::error`; migrated whole from the former
//! `src/error.rs`, byte-frozen behavior).
//!
//! The aria2 numeric error codes and the `taiji.*` string codes get
//! their names, values, and HTTP mappings here; other crates (core/cli)
//! must not define their own mappings. core only supplies semantics
//! ([`SessionError`]); StoreError is normalized by taiji-core and
//! enters through the SessionCommand face (new branches extend
//! [`map_session_error`] here — the single source stays in this file).
//! Every frozen wire message (parameter templates, cookie validation
//! texts, metalink seams, the unknown-method wording, the caps
//! receipts) is named here as a constant or a constructor — call sites
//! never spell a wire message inline.
//!
//! Error-code stability invariants:
//!
//! - numeric code 1 = the generic method-execution error (aria2
//!   `RpcMethod.cc` `createErrorResponse`; unknown methods and auth
//!   failures land there too, see dispatch.rs);
//!
//! - JSON-RPC protocol errors -32700/-32600/-32602 (`rpc_helper.cc`,
//!   `HttpServerBodyCommand.cc`);
//!
//! - `-32601` is never produced: unknown methods use [`CODE_GENERIC`];
//!   the constant exists only to keep the HTTP mapping aligned with the
//!   reference switch;
//!
//! - the HTTP failure -> aria2 numeric-code mapping table is frozen; it
//!   grows only in reviewed increments, and the executable mirror
//!   [`try_http_numeric_code`] plus the `http_failure_*` tests must
//!   change at the same point as any table row.
//!
//! The full engine-failure-to-numeric-code table and the declared
//! differences vs aria2: docs/design/rpc.md.
//!
//! Upstream anchor mapping: docs/design/rpc.md

use axum::http::StatusCode;
use taiji_core::session::SessionError;

/// aria2 generic execution error code: any method-execution failure is 1
/// (reference: `RpcMethod.cc` `createErrorResponse` -> `Integer::g(1)`;
/// unknown methods and auth failures also land here — see dispatch.rs).
pub const CODE_GENERIC: i64 = 1;

/// JSON-RPC 2.0 protocol error codes (reference: HttpServerBodyCommand.cc).
pub const CODE_PARSE_ERROR: i64 = -32700;
pub const CODE_INVALID_REQUEST: i64 = -32600;
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// -32601 exists in aria2 only in the HTTP mapping branch
/// (HttpServerBodyCommand.cc -> 404); the error face itself is never
/// produced: unknown methods use [`CODE_GENERIC`] (via
/// NoSuchMethodRpcMethod, `RpcMethodFactory.cc` + `RpcMethodImpl.cc`).
/// The constant is kept to keep the mapping table aligned with the
/// reference switch item by item.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;

/// `taiji.*` string codes (the extension namespace, separate from the
/// aria2 numeric codes). Wire form: an error.message prefix (the error
/// structure is frozen as `{code,message}`, `RpcMethod.cc`, no new
/// fields).
pub const STR_NOT_SUPPORTED: &str = "taiji.method.not_supported";
pub const STR_SESSION_CLOSED: &str = "taiji.session.closed";
pub const STR_REQUEST_TOO_LARGE: &str = "taiji.request.too_large";
pub const STR_TOO_MANY_ITEMS: &str = "taiji.request.too_many_items";

/// Torrent-creation error codes (the taiji.* namespace). failed = a
/// creation-execution failure (input stat / path derivation / creator
/// validation / disk write); timeout = the 600s synchronous budget
/// exhausted (hashing large files is blocking — an explicit backstop
/// for the ban on synchronous RPCs without a timeout cap).
pub const STR_CREATE_TORRENT_FAILED: &str = "taiji.create_torrent.failed";
pub const STR_CREATE_TORRENT_TIMEOUT: &str = "taiji.create_torrent.timeout";

/// metalink parse error codes (the taiji.* namespace; the string codes
/// are owned by this table — taiji-metalink only supplies stable
/// variants). parse_failed = structural/format/limit hard errors;
/// unsupported_version = an explicit downgrade for v3/unknown versions
/// (a declared difference); timeout = the 600s parse budget exhausted
/// (the `taiji.createTorrent` backstop — no synchronous RPC without a
/// timeout cap).
pub const STR_METALINK_PARSE_FAILED: &str = "taiji.metalink.parse_failed";
pub const STR_METALINK_UNSUPPORTED_VERSION: &str = "taiji.metalink.unsupported_version";
pub const STR_METALINK_TIMEOUT: &str = "taiji.metalink.timeout";

/// Security fix: the rejection message for write operations when
/// `--rpc-secret` is unset. The message itself is the security semantic
/// (not `taiji.*`-prefixed — the wording is frozen by the
/// security-audit fix and is externally visible as the RPC
/// compatibility face).
pub const STR_UNAUTH_WRITE: &str = "unauthenticated write requires --rpc-secret";

/// The option-value rejection string code (the message-face prefix of
/// `taiji.option.invalid` rejections raised adapter-side; core raises
/// the same code through SessionError texts).
pub const STR_OPTION_INVALID: &str = "taiji.option.invalid";

// ---- frozen wire message texts (named constants; the single source) ----
// Every externally visible message is named here (or built by a named
// constructor below) — call sites never spell a wire message inline.
// Byte-frozen: changing a value is a wire change, not a refactor.

/// Parameter templates (the checkRequiredParam/checkParam face,
/// RpcMethodImpl.h). The two texts' upstream provenance is unverified
/// against the aria2 1.37.0 tree (2026-11-14 measurement gap); the
/// bytes are frozen as observed regardless.
pub(crate) const MSG_PARAM_REQUIRED_MISSING: &str =
    "The parameter at {index} is required but missing.";
pub(crate) const MSG_PARAM_WRONG_TYPE: &str = "The parameter at {index} has wrong type.";
/// checkRequiredInteger(req, 1, IntegerGE(0))'s inner text
/// (RpcMethodImpl.h).
pub(crate) const MSG_PARAM_INTEGER_NOT_GE_ZERO: &str = concat!(
    "The integer parameter at {index} has invalid value: ",
    "the value must be greater than or equal to 0."
);

/// system.multicall shape texts (RpcMethodImpl.cc; the recursion guard
/// wording is cross-validated live against the reference).
pub(crate) const MSG_RECURSIVE_MULTICALL: &str = "Recursive system.multicall forbidden.";
pub(crate) const MSG_MULTICALL_EXPECTED_STRUCT: &str = "system.multicall expected struct.";
pub(crate) const MSG_MULTICALL_MISSING_METHOD_NAME: &str = "Missing methodName.";

/// Task-cookie validation texts (RpcCookie.cc parseRpcCookies,
/// verbatim; module-doc anchor `rpc_cookies`).
pub(crate) const MSG_COOKIE_TOO_MANY: &str = "Too many task cookies.";
pub(crate) const MSG_COOKIE_NOT_OBJECT: &str = "Task cookie must be an object.";
pub(crate) const MSG_COOKIE_UNKNOWN_FIELD: &str = "Unknown task cookie field.";
pub(crate) const MSG_COOKIE_SYNTAX: &str = "Invalid task cookie syntax.";
pub(crate) const MSG_COOKIE_DOMAIN: &str = "Invalid task cookie domain.";
pub(crate) const MSG_COOKIE_EXPIRY: &str =
    "Task cookie expiry must be nonnegative Unix milliseconds.";
pub(crate) const MSG_COOKIE_STRING_FIELD: &str = "Invalid task cookie string field.";
pub(crate) const MSG_COOKIE_BOOL_FIELD: &str = "Invalid task cookie boolean field.";

/// addUri/addTorrent/addTracker/addMedia empty-set and shape texts
/// (RpcMethodImpl.cc wording family).
pub(crate) const MSG_URI_NOT_PROVIDED: &str = "URI is not provided.";
pub(crate) const MSG_URL_NOT_PROVIDED: &str = "URL is not provided.";
pub(crate) const MSG_TORRENT_NOT_BASE64: &str = "torrent data is not valid base64.";
pub(crate) const MSG_FILE_PATHS_NOT_PROVIDED: &str = "file paths are not provided.";
pub(crate) const MSG_TRACKER_URLS_NOT_PROVIDED: &str = "tracker URLs are not provided.";
/// changePosition's closed `how` domain text (RpcMethodImpl.cc).
pub(crate) const MSG_ILLEGAL_ARGUMENT: &str = "Illegal argument.";
/// changeUri's fileIndex bound text (RpcMethodImpl.cc
/// checkRequiredInteger(req, 1, IntegerGE(1))).
pub(crate) const MSG_INTEGER_GE_ONE: &str = "Integer value must be greater than or equal to 1.";

/// The metalink seam's own texts (the declared-difference family; the
/// string-code prefixes go through `RpcError::option_invalid` /
/// [`STR_METALINK_TIMEOUT`], never hand-spliced). Gated: the seam's
/// only consumer is the metalink feature.
#[cfg(feature = "metalink")]
pub(crate) const MSG_METALINK_NOT_BASE64: &str = "metalink data is not valid base64.";

/// RPC error (a mapping-table product; encoded into the JSON-RPC error object in [`jsonrpc`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    /// true = an unauthorized response: the HTTP layer delays 1s before
    /// sending (the reference DelayedCommand semantics,
    /// `HttpServerBodyCommand.cc`).
    pub unauthorized: bool,
}

impl RpcError {
    pub fn generic(message: impl Into<String>) -> Self {
        RpcError {
            code: CODE_GENERIC,
            message: message.into(),
            unauthorized: false,
        }
    }

    /// "Unauthorized" (reference: `RpcMethod.cc`
    /// `throw DL_ABORT_EX("Unauthorized")` -> caught by execute -> code 1 +
    /// the not_authorized bit).
    pub fn unauthorized() -> Self {
        RpcError {
            code: CODE_GENERIC,
            message: "Unauthorized".to_string(),
            unauthorized: true,
        }
    }

    /// The standard error face for promised-but-not-implemented /
    /// permanently unsupported methods (the `system.*` introspection
    /// placeholders, the taiji.moveStorage/renameFile capability face).
    pub fn not_supported(method: &str) -> Self {
        RpcError {
            code: CODE_GENERIC,
            message: format!("{STR_NOT_SUPPORTED}: {method}"),
            unauthorized: false,
        }
    }

    /// "No such method: <name>" (NoSuchMethodRpcMethod /
    /// RpcMethodImpl.cc — the raw caller spelling is echoed verbatim).
    pub(crate) fn no_such_method(raw_method: &str) -> Self {
        RpcError::generic(format!("No such method: {raw_method}"))
    }

    /// The missing-required-parameter text (checkRequiredParam,
    /// RpcMethodImpl.h) at position `index`.
    pub(crate) fn param_missing(index: usize) -> Self {
        RpcError::generic(MSG_PARAM_REQUIRED_MISSING.replace("{index}", &index.to_string()))
    }

    /// The wrong-parameter-type text (checkParam, RpcMethodImpl.h) at
    /// position `index`.
    pub(crate) fn param_wrong_type(index: usize) -> Self {
        RpcError::generic(MSG_PARAM_WRONG_TYPE.replace("{index}", &index.to_string()))
    }

    /// The IntegerGE(0) rejection text at position `index`
    /// (checkRequiredInteger, RpcMethodImpl.h).
    pub(crate) fn integer_param_not_ge_zero(index: usize) -> Self {
        RpcError::generic(MSG_PARAM_INTEGER_NOT_GE_ZERO.replace("{index}", &index.to_string()))
    }

    /// An adapter-side option-value rejection: code 1 + the
    /// `taiji.option.invalid` string-code prefix + the detail (the
    /// same face as the core-side changeOption rejections). Gated:
    /// the only raiser is the metalink seam.
    #[cfg(feature = "metalink")]
    pub(crate) fn option_invalid(detail: impl std::fmt::Display) -> Self {
        RpcError::generic(format!("{STR_OPTION_INVALID}: {detail}"))
    }

    /// The over-limit request error (HTTP 413 face): code 1 + the
    /// `taiji.request.too_large` string code + the knob pointer.
    pub(crate) fn request_too_large() -> Self {
        RpcError::generic(format!(
            "{STR_REQUEST_TOO_LARGE}: see --rpc-max-request-size"
        ))
    }

    /// The batch/multicall item-cap receipt.
    pub(crate) fn too_many_items(cap: usize) -> Self {
        RpcError::generic(format!(
            "{STR_TOO_MANY_ITEMS}: batch/multicall capped at {cap} calls"
        ))
    }

    /// The request-level subcall-budget receipt.
    pub(crate) fn subcall_budget_exceeded(total: usize, max: usize) -> Self {
        RpcError::generic(format!(
            "{STR_TOO_MANY_ITEMS}: batch subcall budget exceeded ({total} > {max})"
        ))
    }

    /// The defensive unexpected-reply face (a reply variant this method
    /// face does not encode — a broken structural invariant, never a
    /// faked payload). `method` is the canonical method name.
    pub(crate) fn unexpected_reply(method: &str, other: &dyn std::fmt::Debug) -> Self {
        RpcError::generic(format!("unexpected {method} reply: {other:?}"))
    }

    /// `taiji.createTorrent`'s closed format-domain rejection (the
    /// taiji.* namespace; no reference wording).
    pub(crate) fn unknown_torrent_format(shown: &str) -> Self {
        RpcError::generic(format!(
            "unknown torrent format: {shown} (expected one of v1|v2|hybrid)"
        ))
    }

    /// `taiji.setSchedulerPolicy`'s unknown-name rejection.
    pub(crate) fn unknown_scheduler_policy(shown: &str) -> Self {
        RpcError::generic(format!("unknown scheduler policy: {shown}"))
    }

    /// `taiji.setStreamingPlayhead`'s zero-rate rejection (position 3;
    /// the default rate is carried by omitting the parameter).
    pub(crate) fn playhead_bps_zero() -> Self {
        RpcError::generic(
            "The integer parameter at 3 has invalid value: bytes_per_sec must be greater than 0 \
             (omit the parameter for the default rate)"
                .to_string(),
        )
    }

    /// `taiji.setFilePriority`'s empty-pairs rejection (position 1).
    pub(crate) fn file_priority_pairs_empty() -> Self {
        RpcError::generic("The parameter at 1 has invalid value: pairs must not be empty.")
    }

    /// `taiji.setFilePriority`'s non-object entry rejection (entry `n`).
    pub(crate) fn file_priority_entry_not_object(n: usize) -> Self {
        RpcError::generic(format!(
            "The parameter at 1 has invalid value: entry {n} is not an object."
        ))
    }

    /// `taiji.setFilePriority`'s missing-index rejection (entry `n`).
    pub(crate) fn file_priority_entry_misses_index(n: usize) -> Self {
        RpcError::generic(format!(
            "The parameter at 1 has invalid value: entry {n} misses index."
        ))
    }

    /// `taiji.setFilePriority`'s out-of-domain priority rejection
    /// (entry `n`; the -1..=7 domain).
    pub(crate) fn file_priority_entry_bad_priority(n: usize) -> Self {
        RpcError::generic(format!(
            "The parameter at 1 has invalid value: entry {n} priority must be \
             an integer in -1..=7."
        ))
    }

    /// `taiji.setDiskTier`'s unknown-name rejection (the tier value
    /// domain echoes `DiskTier::NAMES`).
    pub(crate) fn unknown_disk_tier(name: &str, names: &[&str]) -> Self {
        RpcError::generic(format!(
            "unknown disk tier: {name} (expected one of {names:?})"
        ))
    }
}

/// system.multicall inline error slot (shape = createErrorResponse's
/// error object, `RpcMethod.cc`): the raw `{code,message}` JSON value
/// the multicall array embeds in place of a wrapped result.
pub(crate) fn multicall_inline_error(message: &str) -> serde_json::Value {
    serde_json::json!({ "code": CODE_GENERIC, "message": message })
}

/// SessionError -> RPC error (the single mapping point; core only supplies semantics).
pub fn map_session_error(err: &SessionError) -> RpcError {
    match err {
        SessionError::NotSupported { method } => RpcError::not_supported(method),
        SessionError::SessionClosed => RpcError {
            code: CODE_GENERIC,
            message: STR_SESSION_CLOSED.to_string(),
            unauthorized: false,
        },
        // Task-level explicit failure (parse / duplicate / gid not found
        // / not pausable etc.): numeric code 1 + the original message
        // (the aria2 DL_ABORT_EX -> createErrorResponse shape,
        // `RpcMethod.cc`).
        SessionError::Failed { message } => RpcError::generic(message.clone()),
    }
}

/// Torrent-creation errors (core semantics [`CreateTorrentError`]) ->
/// RPC error. An execution failure = code 1 + a
/// `taiji.create_torrent.failed:` prefix + the original message; a
/// timeout = code 1 + a `taiji.create_torrent.timeout:` prefix (the
/// string codes are owned by this file).
pub fn map_create_torrent_error(err: &taiji_core::create::CreateTorrentError) -> RpcError {
    if matches!(err, taiji_core::create::CreateTorrentError::Timeout { .. }) {
        return RpcError {
            code: CODE_GENERIC,
            message: format!("{STR_CREATE_TORRENT_TIMEOUT}: {err}"),
            unauthorized: false,
        };
    }
    RpcError {
        code: CODE_GENERIC,
        message: format!("{STR_CREATE_TORRENT_FAILED}: {err}"),
        unauthorized: false,
    }
}

/// metalink parse errors (taiji-metalink stable variants) -> RPC error.
/// The numeric code is always 1 (a method-execution failure — the aria2
/// METALINK_PARSE_ERROR -> DL_ABORT_EX -> createErrorResponse shape,
/// `RpcMethod.cc`); the string code dispatches on the variant
/// (unsupported_version / parse_failed). DocumentTooLarge/TooManyFiles/
/// TooManyUrls are limit hard errors = the parse_failed row (aria2's
/// limit trips are parse failures too).
#[cfg(feature = "metalink")]
pub fn map_metalink_error(err: &taiji_metalink::MetalinkError) -> RpcError {
    let code = match err {
        taiji_metalink::MetalinkError::UnsupportedVersion { .. } => {
            STR_METALINK_UNSUPPORTED_VERSION
        }
        _ => STR_METALINK_PARSE_FAILED,
    };
    RpcError {
        code: CODE_GENERIC,
        message: format!("{code}: {err}"),
        unauthorized: false,
    }
}

// ---- HTTP failure -> aria2 numeric error code (the executable form of
// the mapping table) ----
// The single source = the doc table above; this function is the
// executable mirror, pinned row by row by tests (including the 403->22
// correction). Adding/removing a row requires changing this function
// and the `http_failure_*` tests at the same point.

/// aria2 numeric error codes (read-only reference: `error_code.h`
/// `error_code::Value`). 19/15/16 (NAME_RESOLVE/FILE_OPEN/FILE_CREATE)
/// have no production-reachable table row and are not named (see the
/// "transport/disk fine-grained boundaries" difference note). The
/// `taiji.*` string codes and the numeric codes live in separate
/// namespaces — numeric codes appear only in the task-terminal
/// `errorCode` / diff comparisons, never in JSON-RPC error.code.
pub const NUM_UNKNOWN_ERROR: i64 = 1;
pub const NUM_TIME_OUT: i64 = 2;
pub const NUM_RESOURCE_NOT_FOUND: i64 = 3;
pub const NUM_NETWORK_PROBLEM: i64 = 6;
pub const NUM_CANNOT_RESUME: i64 = 8;
pub const NUM_FILE_ALREADY_EXISTS: i64 = 13;
pub const NUM_FILE_IO_ERROR: i64 = 17;
pub const NUM_FTP_PROTOCOL_ERROR: i64 = 21;
pub const NUM_HTTP_PROTOCOL_ERROR: i64 = 22;
pub const NUM_HTTP_TOO_MANY_REDIRECTS: i64 = 23;
pub const NUM_HTTP_AUTH_FAILED: i64 = 24;
pub const NUM_OPTION_ERROR: i64 = 28;
pub const NUM_HTTP_SERVICE_UNAVAILABLE: i64 = 29;
pub const NUM_CHECKSUM_ERROR: i64 = 32;

/// HTTP failure sub-kind (the second dimension of multi-value codes;
/// single-value codes pass [`HttpFailureKind::Bare`]). The value domain
/// maps one-to-one onto the core `EngineFailureKind` (the
/// production-render-chain reachable face): transport-chain text
/// (DNS/connect refused/reset/TLS) and disk payloads are always Bare —
/// the table, the function arms, and the difference notes share the
/// rule; no unreachable fine-grained arms (unreachable rows once made
/// the doc table declare 19/15/16 while production always fell to
/// 6/17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpFailureKind {
    /// No sub-kind (a single-value code; the Bare semantics of
    /// multi-value codes = the "other/fallback" table rows).
    Bare,
    /// `taiji.http.unexpected_response`: the original HTTP status code.
    Status(u16),
    /// `taiji.http.transport`: the read idle timeout (constructed
    /// directly at the task-level stall closure, `--timeout` zero byte
    /// growth).
    TransportTimeout,
}

/// HTTP failure -> aria2 numeric error code (the executable mirror of
/// the doc table; off-table codes = None, and [`http_numeric_code`]
/// falls back to 1). The `taiji.http.unexpected_response` 403 arm is
/// cross-validated: the reference status switch has no 403-specific arm
/// — EX_BAD_STATUS -> HTTP_PROTOCOL_ERROR(22); only 401 is
/// HTTP_AUTH_FAILED(24) (`HttpSkipResponseCommand.cc`).
pub fn try_http_numeric_code(engine_code: &str, kind: HttpFailureKind) -> Option<i64> {
    match engine_code {
        // bad_range same slot: the isRangeSatisfied failure family is
        // always CANNOT_RESUME — a mismatching 206 echo / a 416 probe
        // (bad_range) and an expected-206-got-200 (range_ignored) share
        // the wire code; the taiji-side behavioral difference (explicit
        // failure vs restart-from-zero) is in the doc table row.
        "taiji.http.bad_range" | "taiji.http.range_ignored" => Some(NUM_CANNOT_RESUME),
        "taiji.http.unexpected_response" => match kind {
            HttpFailureKind::Status(404) => Some(NUM_RESOURCE_NOT_FOUND),
            HttpFailureKind::Status(401) => Some(NUM_HTTP_AUTH_FAILED),
            HttpFailureKind::Status(502..=504) => Some(NUM_HTTP_SERVICE_UNAVAILABLE),
            // 403 and the other off-table statuses: the EX_BAD_STATUS fallback arm.
            HttpFailureKind::Status(_) | HttpFailureKind::Bare => Some(NUM_HTTP_PROTOCOL_ERROR),
            _ => None,
        },
        "taiji.http.transport" => match kind {
            // The read idle timeout = the task-level stall-closure
            // sub-kind (the transport face's only direct row).
            HttpFailureKind::TransportTimeout => Some(NUM_TIME_OUT),
            // DNS/connect refused/reset/TLS stay in the error-chain text,
            // always Bare -> the 6 fallback row (aria2's DNS-specific 19
            // is unreachable on the numeric face — declared difference).
            HttpFailureKind::Bare => Some(NUM_NETWORK_PROBLEM),
            _ => None,
        },
        "taiji.http.redirect_limit" | "taiji.http.redirect_loop" => {
            Some(NUM_HTTP_TOO_MANY_REDIRECTS)
        }
        "taiji.http.insecure_redirect" => Some(NUM_HTTP_PROTOCOL_ERROR),
        "taiji.http.mirror_mismatch"
        | "taiji.http.no_source"
        | "taiji.http.total_length_exceeded"
        | "taiji.http.coordinator_stopped"
        | "taiji.http.cookie_file_too_large"
        | "taiji.http.cookie_file" => Some(NUM_UNKNOWN_ERROR),
        "taiji.http.path_conflict" => Some(NUM_FILE_ALREADY_EXISTS),
        // Disk family single row (cross-validated against
        // AbstractDiskWriter.cc FILE_IO_ERROR): open/create/read-write
        // payloads are always Bare -> the 17 fallback row; aria2's finer
        // 15/16 are unreachable on the numeric face.
        "taiji.http.disk" => match kind {
            HttpFailureKind::Bare => Some(NUM_FILE_IO_ERROR),
            _ => None,
        },
        "taiji.option.invalid" => Some(NUM_OPTION_ERROR),
        "taiji.auth.failed" => Some(NUM_HTTP_AUTH_FAILED),
        // FTP family: the numeric code is 21 FTP_PROTOCOL_ERROR — the
        // reference's whole FTP control path shares it
        // (FtpNegotiationCommand.cc / FtpConnection.cc).
        "taiji.http.ftp" | "taiji.http.ftp_resume_unsupported" => Some(NUM_FTP_PROTOCOL_ERROR),
        "taiji.http.checksum_mismatch" => Some(NUM_CHECKSUM_ERROR),
        _ => None,
    }
}

/// The fallback form of [`try_http_numeric_code`]: off-table codes = 1
/// (UNKNOWN_ERROR, the aria2 RequestGroup fallback rule).
pub fn http_numeric_code(engine_code: &str, kind: HttpFailureKind) -> i64 {
    try_http_numeric_code(engine_code, kind).unwrap_or(NUM_UNKNOWN_ERROR)
}

/// Media error code -> aria2 numeric code (the media
/// error-code rows threaded through the numeric mapping — the media
/// codes have **no** aria2 counterparts, so every row is the
/// UNKNOWN_ERROR(1) family except the shared `taiji.option.invalid`
/// (28, the one row the two families share). Row list = the full
/// media error-code line (including the `staging` and
/// `ssrf_blocked`/`key_invalid` annotations and the first
/// `template_unsafe`/`probe_expired`/`not_media` wirings).
pub fn media_numeric_code(engine_code: &str) -> i64 {
    match engine_code {
        "taiji.option.invalid" => NUM_OPTION_ERROR,
        // The whole taiji.media.* family: no aria2 counterpart row —
        // the generic execution-error face (1), the error message
        // carries the canonical string code verbatim.
        "taiji.media.ffmpeg_missing"
        | "taiji.media.not_media"
        | "taiji.media.manifest_too_large"
        | "taiji.media.live_unsupported"
        | "taiji.media.sample_aes_unsupported"
        | "taiji.media.session_key_unsupported"
        | "taiji.media.iframes_unsupported"
        | "taiji.media.manifest_parse"
        | "taiji.media.variant_policy"
        | "taiji.media.cross_volume"
        | "taiji.media.staging_quota_exceeded"
        | "taiji.media.segment_decrypt_failed"
        | "taiji.media.ssrf_blocked"
        | "taiji.media.key_invalid"
        | "taiji.media.staging"
        | "taiji.media.remux_verify_failed"
        | "taiji.media.template_unsafe"
        | "taiji.media.probe_expired" => NUM_UNKNOWN_ERROR,
        _ => NUM_UNKNOWN_ERROR,
    }
}

/// Numeric code -> HTTP status. Cross-validated against the
/// `HttpServerBodyCommand.cc` switch: 0->200; 1->400; -32600->400;
/// -32601->404; default->500 (including -32700/-32602 — upstream is
/// like this, replicated faithfully). Batch responses are always 200
/// (sendJsonRpcBatchResponse does not pick a status code,
/// `HttpServerBodyCommand.cc`).
pub fn http_status(code: i64) -> StatusCode {
    match code {
        0 => StatusCode::OK,
        CODE_GENERIC => StatusCode::BAD_REQUEST,
        CODE_INVALID_REQUEST => StatusCode::BAD_REQUEST,
        CODE_METHOD_NOT_FOUND => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The consolidated constructors are byte-frozen (each reproduces
    /// the exact wire text that used to be spelled inline at the call
    /// sites — Phase C's collection step must not drift a byte).
    #[test]
    fn consolidated_constructors_are_byte_frozen() {
        assert_eq!(
            RpcError::no_such_method("aria2.getX").message,
            "No such method: aria2.getX"
        );
        assert_eq!(
            RpcError::param_missing(2).message,
            "The parameter at 2 is required but missing."
        );
        assert_eq!(
            RpcError::param_wrong_type(0).message,
            "The parameter at 0 has wrong type."
        );
        assert_eq!(
            RpcError::integer_param_not_ge_zero(1).message,
            "The integer parameter at 1 has invalid value: the value must be greater than or \
             equal to 0."
        );
        assert_eq!(
            RpcError::request_too_large().message,
            "taiji.request.too_large: see --rpc-max-request-size"
        );
        assert_eq!(
            RpcError::too_many_items(1000).message,
            "taiji.request.too_many_items: batch/multicall capped at 1000 calls"
        );
        assert_eq!(
            RpcError::subcall_budget_exceeded(10001, 10_000).message,
            "taiji.request.too_many_items: batch subcall budget exceeded (10001 > 10000)"
        );
        #[cfg(feature = "metalink")]
        assert_eq!(
            RpcError::option_invalid("bad value").message,
            "taiji.option.invalid: bad value"
        );
        assert_eq!(
            multicall_inline_error("Missing methodName."),
            serde_json::json!({"code": 1, "message": "Missing methodName."})
        );
    }

    #[test]
    fn http_status_mirrors_reference_switch() {
        // Item-by-item cross-validation of HttpServerBodyCommand.cc (including default -> 500).
        assert_eq!(http_status(0), StatusCode::OK);
        assert_eq!(http_status(1), StatusCode::BAD_REQUEST);
        assert_eq!(http_status(-32600), StatusCode::BAD_REQUEST);
        assert_eq!(http_status(-32601), StatusCode::NOT_FOUND);
        assert_eq!(http_status(-32700), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(http_status(-32602), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn session_error_mapping_uses_frozen_string_codes() {
        let ns = SessionError::NotSupported { method: "addUri" };
        let mapped = map_session_error(&ns);
        assert_eq!(mapped.code, CODE_GENERIC);
        assert_eq!(mapped.message, "taiji.method.not_supported: addUri");
        assert!(!mapped.unauthorized);

        let closed = map_session_error(&SessionError::SessionClosed);
        assert_eq!(closed.message, "taiji.session.closed");
        assert!(!closed.unauthorized);
    }

    #[test]
    fn unauthorized_error_carries_delay_flag() {
        let e = RpcError::unauthorized();
        assert_eq!(e.code, 1);
        assert_eq!(e.message, "Unauthorized");
        assert!(e.unauthorized);
    }

    // ---- HTTP failure -> aria2 numeric codes: mapping-table
    // cross-validation (read-only reference) ----

    /// 403 correction pin: the reference status switch
    /// (HttpSkipResponseCommand.cc) has dedicated arms only for
    /// 401/404/502/503/504; 403 falls to the EX_BAD_STATUS fallback ->
    /// HTTP_PROTOCOL_ERROR(22); only 401 is HTTP_AUTH_FAILED(24). An
    /// early draft merged 403 into the ->24 row, contradicting this.
    #[test]
    fn http_failure_403_is_protocol_error_not_auth_failed() {
        let f = |s: u16| {
            http_numeric_code("taiji.http.unexpected_response", HttpFailureKind::Status(s))
        };
        assert_eq!(
            f(403),
            NUM_HTTP_PROTOCOL_ERROR,
            "403 -> 22 (the reference's fallback arm)"
        );
        assert_eq!(
            f(401),
            NUM_HTTP_AUTH_FAILED,
            "401 -> 24 (its dedicated arm)"
        );
    }

    /// Status-code family, arm by arm, cross-validated against HttpSkipResponseCommand.cc.
    #[test]
    fn http_failure_status_rows_match_reference_switch() {
        let f = |s: u16| {
            http_numeric_code("taiji.http.unexpected_response", HttpFailureKind::Status(s))
        };
        assert_eq!(f(404), NUM_RESOURCE_NOT_FOUND);
        assert_eq!(f(502), NUM_HTTP_SERVICE_UNAVAILABLE);
        assert_eq!(f(503), NUM_HTTP_SERVICE_UNAVAILABLE);
        assert_eq!(f(504), NUM_HTTP_SERVICE_UNAVAILABLE);
        // Off-table statuses (500/410/429 sampled beyond 403) also hit the fallback arm.
        assert_eq!(f(500), NUM_HTTP_PROTOCOL_ERROR);
        assert_eq!(f(410), NUM_HTTP_PROTOCOL_ERROR);
        assert_eq!(f(429), NUM_HTTP_PROTOCOL_ERROR);
        // Bare (no status payload) = the fallback-row semantics.
        assert_eq!(
            http_numeric_code("taiji.http.unexpected_response", HttpFailureKind::Bare),
            NUM_HTTP_PROTOCOL_ERROR
        );
    }

    /// Single-value/fine-grained codes, row by row (the doc table's
    /// executable mirror; row changes must change this test at the same
    /// point).
    #[test]
    fn http_failure_rows_match_mapping_table() {
        let f = |c: &str, k: HttpFailureKind| http_numeric_code(c, k);
        assert_eq!(
            f("taiji.http.bad_range", HttpFailureKind::Bare),
            NUM_CANNOT_RESUME
        );
        // range_ignored row (slot 8): the same slot as bad_range — the
        // aria2 isRangeSatisfied failure family; previously the
        // off-table fallback 1, corrected to CANNOT_RESUME.
        assert_eq!(
            f("taiji.http.range_ignored", HttpFailureKind::Bare),
            NUM_CANNOT_RESUME
        );
        assert_eq!(
            f("taiji.http.transport", HttpFailureKind::TransportTimeout),
            NUM_TIME_OUT
        );
        // DNS/connect refused/reset/TLS payloads are always Bare -> the
        // 6 fallback row (aria2's DNS-specific 19 is unreachable —
        // declared difference).
        assert_eq!(
            f("taiji.http.transport", HttpFailureKind::Bare),
            NUM_NETWORK_PROBLEM
        );
        // Wire-code stability: the `DnsPermanent` variant (the typed
        // carrier of NXDOMAIN-like resolution dead-ends) shares the
        // string code and the numeric code 6 with `Transport` (no new
        // code face / sub-kind); the FTP face `taiji.http.ftp` stays at
        // 21 (the `FtpDns` typed payload shares the face — locked by
        // taiji-http `ftp_dns_error_code_face_is_stable`).
        {
            use taiji_http::error::HttpError;
            let dns_permanent = HttpError::DnsPermanent("nxdomain".into());
            let transport = HttpError::Transport("reset".into());
            let ftp_dns = HttpError::Ftp("resolver refused".into());
            assert_eq!(dns_permanent.code(), transport.code());
            assert_eq!(
                http_numeric_code(dns_permanent.code(), HttpFailureKind::Bare),
                NUM_NETWORK_PROBLEM,
                "the DNS permanent-failure variant lands on the existing row 6 (the code face unchanged)"
            );
            assert_eq!(
                http_numeric_code(ftp_dns.code(), HttpFailureKind::Bare),
                f("taiji.http.ftp", HttpFailureKind::Bare),
                "the FTP face shares the same string code and numeric code (the FtpDns typed payload \
                 shares the face, locked by taiji-http's ftp_dns_error_code_face_is_stable)"
            );
        }
        assert_eq!(
            f("taiji.http.redirect_limit", HttpFailureKind::Bare),
            NUM_HTTP_TOO_MANY_REDIRECTS
        );
        assert_eq!(
            f("taiji.http.redirect_loop", HttpFailureKind::Bare),
            NUM_HTTP_TOO_MANY_REDIRECTS
        );
        assert_eq!(
            f("taiji.http.insecure_redirect", HttpFailureKind::Bare),
            NUM_HTTP_PROTOCOL_ERROR
        );
        assert_eq!(
            f("taiji.http.mirror_mismatch", HttpFailureKind::Bare),
            NUM_UNKNOWN_ERROR
        );
        assert_eq!(
            f("taiji.http.no_source", HttpFailureKind::Bare),
            NUM_UNKNOWN_ERROR
        );
        assert_eq!(
            f("taiji.http.path_conflict", HttpFailureKind::Bare),
            NUM_FILE_ALREADY_EXISTS
        );
        assert_eq!(
            f("taiji.http.cookie_file_too_large", HttpFailureKind::Bare),
            NUM_UNKNOWN_ERROR
        );
        assert_eq!(
            f("taiji.http.cookie_file", HttpFailureKind::Bare),
            NUM_UNKNOWN_ERROR
        );
        // Disk family single row (cross-validated against
        // AbstractDiskWriter.cc FILE_IO_ERROR): payloads are always Bare
        // -> 17; aria2's finer 15/16 are unreachable on the numeric
        // face.
        assert_eq!(
            f("taiji.http.disk", HttpFailureKind::Bare),
            NUM_FILE_IO_ERROR
        );
        // taiji enhancement face (no aria2 counterpart -> the
        // UNKNOWN_ERROR rows listed in the differences).
        assert_eq!(
            f("taiji.http.total_length_exceeded", HttpFailureKind::Bare),
            NUM_UNKNOWN_ERROR
        );
        assert_eq!(
            f("taiji.http.coordinator_stopped", HttpFailureKind::Bare),
            NUM_UNKNOWN_ERROR
        );
        // Extension-namespace rows.
        assert_eq!(
            f("taiji.option.invalid", HttpFailureKind::Bare),
            NUM_OPTION_ERROR
        );
        assert_eq!(
            f("taiji.auth.failed", HttpFailureKind::Bare),
            NUM_HTTP_AUTH_FAILED
        );
        // FTP family rows (numeric code 21 FTP_PROTOCOL_ERROR; the
        // explicit REST-refusal failure is in the same family).
        assert_eq!(
            f("taiji.http.ftp", HttpFailureKind::Bare),
            NUM_FTP_PROTOCOL_ERROR
        );
        assert_eq!(
            f("taiji.http.ftp_resume_unsupported", HttpFailureKind::Bare),
            NUM_FTP_PROTOCOL_ERROR
        );
        // The --checksum mismatch row (numeric code 32).
        assert_eq!(
            f("taiji.http.checksum_mismatch", HttpFailureKind::Bare),
            NUM_CHECKSUM_ERROR
        );
    }

    /// Fine-grained dimension final pin: with the kind carried through
    /// the render chain, multi-value codes reach directly via the second
    /// dimension (read idle timeout -> 2 TIME_OUT; the disk family's
    /// Bare rows stay at 17 — the always-Bare payload decision).
    #[test]
    fn http_failure_kind_rows_match_mapping_table() {
        // Read idle timeout (task-level --timeout closure) -> TIME_OUT.
        assert_eq!(
            http_numeric_code("taiji.http.transport", HttpFailureKind::TransportTimeout),
            NUM_TIME_OUT
        );
        // The status family's final render path (404/401/502..504 reach
        // directly via the Status sub-kind instead of collapsing to 22).
        let f = |s: u16| {
            http_numeric_code("taiji.http.unexpected_response", HttpFailureKind::Status(s))
        };
        assert_eq!(f(404), NUM_RESOURCE_NOT_FOUND);
        assert_eq!(f(503), NUM_HTTP_SERVICE_UNAVAILABLE);
    }

    /// Media rows: the media family threads to 1 (no aria2
    /// counterparts — the canonical string code rides the message);
    /// the shared option-invalid row keeps its 28. The row list is
    /// pinned per code (a new media code missing here surfaces at the
    /// e2e numeric face).
    #[test]
    fn media_failure_rows_match_the_spec_media_14_line() {
        for code in [
            "taiji.media.ffmpeg_missing",
            "taiji.media.not_media",
            "taiji.media.manifest_too_large",
            "taiji.media.live_unsupported",
            "taiji.media.sample_aes_unsupported",
            "taiji.media.session_key_unsupported",
            "taiji.media.iframes_unsupported",
            // The DASH milestone line: the two judgment-table
            // codes it lands — a frozen-test extension, the
            // "initial freeze, increments by PR" mechanism's
            // non-silent form.
            "taiji.media.drm_unsupported",
            "taiji.media.sidx_unsupported",
            "taiji.media.manifest_parse",
            "taiji.media.variant_policy",
            "taiji.media.cross_volume",
            "taiji.media.staging_quota_exceeded",
            "taiji.media.segment_decrypt_failed",
            // The staging/SSRF/key annotation rows (annotated 2026-10-28).
            "taiji.media.staging",
            "taiji.media.ssrf_blocked",
            "taiji.media.key_invalid",
            // The first wirings (the existing error-code faces).
            "taiji.media.template_unsafe",
            "taiji.media.probe_expired",
            // The verify-failure inherited code.
            "taiji.media.remux_verify_failed",
        ] {
            assert_eq!(media_numeric_code(code), NUM_UNKNOWN_ERROR, "{code}");
        }
        assert_eq!(media_numeric_code("taiji.option.invalid"), NUM_OPTION_ERROR);
        // Off-table media-shaped codes fall back to 1 (same rule as
        // the http face).
        assert_eq!(
            media_numeric_code("taiji.media.not_a_code"),
            NUM_UNKNOWN_ERROR
        );
    }

    /// Off-table fallback = 1 (UNKNOWN_ERROR): `try_*` returns None and
    /// `http_numeric_code` falls back to the same value (the aria2
    /// RequestGroup rule).
    #[test]
    fn unknown_engine_code_falls_back_to_unknown_error() {
        assert_eq!(
            try_http_numeric_code("taiji.http.not_a_code", HttpFailureKind::Bare),
            None
        );
        assert_eq!(
            http_numeric_code("taiji.http.not_a_code", HttpFailureKind::Bare),
            NUM_UNKNOWN_ERROR
        );
    }

    /// Full variant sweep (production pairing): every taiji-http variant,
    /// paired through `EngineFailure::of_http_error` (the single
    /// core-side conversion), must have a mapping-table row — this
    /// removes fake coverage from hand-paired kinds (unreachable
    /// fine-grained arms were removed with the table/arm alignment;
    /// transport-chain text and disk payloads are always Bare). The
    /// per-code value and the JSON terminal face (errorCode) end-to-end
    /// pin lives in the dispatch test
    /// `http_failure_numeric_end_to_end_production_chain`; taiji-http's
    /// `error_codes_are_canonical_namespace` pins variant->code, this
    /// test pins the production pairing->table row — a new variant
    /// missing a row surfaces as None (otherwise it would silently fall
    /// back to 1).
    #[test]
    fn http_error_variants_pair_production_kinds_with_table_rows() {
        use taiji_core::session::EngineFailure;
        use taiji_http::error::HttpError;
        let variants: Vec<HttpError> = vec![
            HttpError::BadRange,
            // A newer variant (a download-phase 200 = an explicit
            // capability-drift failure) — added to the sweep at slot 8 to
            // guard the mapping row against regressions.
            HttpError::RangeIgnored,
            // A newer variant (a download-phase 412 = content changed,
            // the If-Match precheck) — the canonical code reuses the
            // bad_range family (8); the Bare sub-kind already has a table
            // row.
            HttpError::PreconditionFailed,
            HttpError::PathConflict,
            HttpError::MirrorMismatch,
            HttpError::NoSource,
            HttpError::UnexpectedResponse { status: 404 },
            HttpError::UnexpectedResponse { status: 403 },
            HttpError::UnexpectedResponse { status: 503 },
            HttpError::RedirectLimit { max: 20 },
            HttpError::RedirectLoop,
            HttpError::InsecureRedirect,
            HttpError::CookieFileTooLarge {
                max_bytes: 1024 * 1024,
            },
            HttpError::CookieFile("io".into()),
            // Two transport-chain-text shapes (DNS/connect refused) —
            // the production pairing is always Bare.
            HttpError::Transport("dns: no record".into()),
            HttpError::Transport("connect refused".into()),
            HttpError::AuthFailed("digest challenge".into()),
            HttpError::ChecksumMismatch {
                expected: "ab".into(),
                got: "cd".into(),
            },
            HttpError::OptionInvalid {
                option: "--http-block-size",
                value: "3MiB".into(),
            },
            HttpError::CoordinatorStopped,
            // Two disk-family shapes (open/read-write) — the production pairing is always Bare.
            HttpError::Disk("open .part".into()),
            HttpError::Disk("fsync .part".into()),
            HttpError::TotalLengthExceeded {
                total: u64::MAX,
                max: 1,
            },
            HttpError::Ftp("read idle timeout".into()),
            HttpError::FtpResumeUnsupported,
        ];
        for err in variants {
            let f = EngineFailure::of_http_error(&err);
            let kind = crate::dispatch::engine_kind(f.kind);
            let n = try_http_numeric_code(&f.code, kind);
            assert!(
                n.is_some(),
                "{} production pairing (kind={kind:?}) lacks a mapping row — it would silently fall back to 1",
                f.code
            );
        }
    }
}
