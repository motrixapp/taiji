//! Parse error surface. The error-code strings
//! (`taiji.metalink.parse_failed` / `taiji.metalink.unsupported_version`)
//! are owned solely by the RPC error mapping table (taiji-rpc); this crate
//! only provides the stable variants for mapping.

/// metalink document parse error (hard error — the whole document is
/// unusable when it occurs).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetalinkError {
    /// Document exceeds the 16MiB cap (rejected before parsing).
    #[error("metalink document too large: {len} bytes (limit {limit})")]
    DocumentTooLarge {
        /// Input byte count.
        len: usize,
        /// Byte cap ([`crate::model::MAX_DOCUMENT_BYTES`]).
        limit: usize,
    },
    /// `<file>` entry count exceeds the cap.
    #[error("too many file entries: {count} (limit {limit})")]
    TooManyFiles {
        /// Actual file entry count.
        count: usize,
        /// Cap ([`crate::model::MAX_FILES`]).
        limit: usize,
    },
    /// `<url>` entry count for one file exceeds the cap.
    #[error("too many urls for file {file:?}: {count} (limit {limit})")]
    TooManyUrls {
        /// File name that hit the cap.
        file: String,
        /// Actual url entry count.
        count: usize,
        /// Cap ([`crate::model::MAX_URLS_PER_FILE`]).
        limit: usize,
    },
    /// `<metaurl>` entry count for one file exceeds the cap (same
    /// parse-limit discipline as urls — mass duplicate entries are a
    /// parse-amplification shape; exceeding is a hard error).
    #[error("too many metaurls for file {file:?}: {count} (limit {limit})")]
    TooManyMetaurls {
        /// File name that hit the cap.
        file: String,
        /// Actual metaurl entry count.
        count: usize,
        /// Cap ([`crate::model::MAX_METAURLS_PER_FILE`]).
        limit: usize,
    },
    /// metalink v3 or an unknown version — explicit downgrade (the default
    /// branch; v3 detection = the `http://www.metalinker.org/` namespace
    /// or a `version="3.0"` attribute).
    #[error("unsupported metalink version: {found}")]
    UnsupportedVersion {
        /// Detected version signal (namespace URI or version attribute
        /// value).
        found: String,
    },
    /// Structural/format errors: non-well-formed XML, DOCTYPE (DTDs
    /// disabled), undefined entities, unknown charset declarations, a root
    /// that is not metalink, unknown namespaces, depth overrun, zero file
    /// entries, and the like.
    #[error("metalink parse failed: {reason}")]
    ParseFailed {
        /// Failure reason (sanitized; only a truncated leading fragment of
        /// document text).
        reason: String,
    },
}
