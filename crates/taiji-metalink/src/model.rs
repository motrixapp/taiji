//! Mirror manifest model (RFC 5854 → Rust types, the "format → model"
//! surface).
//!
//! Naming mirrors upstream aria2 (read-only reference): `Url` ≈
//! `MetalinkResource`, `MetaUrl` ≈ `MetalinkMetaurl`, `PieceSet` ≈
//! `ChunkChecksum` (v4 pieces), `MetalinkFile` ≈ `MetalinkEntry`.
//!
//! Field fidelity policy: text fields keep the document text verbatim
//! (including the name field — path sanitization belongs to the task
//! layer; the model does not make policy decisions for consumers; the
//! parser only drops traversal-named entries outright, same rule as aria2
//! `util::detectDirTraversal`, plus a warning).

use crate::hash::{Hash, HashKind};

/// Document byte cap: 16MiB (rejected before parsing).
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
/// `<file>` entry cap: 10k.
pub const MAX_FILES: usize = 10_000;
/// `<url>` entries per file: 64.
pub const MAX_URLS_PER_FILE: usize = 64;
/// `<metaurl>` entries per file (same value as the url cap; exceeding it
/// is a hard error). After dedup by metaurl URI the expansion yields at
/// most one BT task per file, so the cap only closes the parse-amplification
/// shape of mass duplicate entries.
pub const MAX_METAURLS_PER_FILE: usize = 64;
/// Nesting depth cap (parse-limit discipline; legal metalink nesting is
/// <= 4 levels — guards against deep-stack abuse).
pub const MAX_DEPTH: usize = 256;
/// Default URL/metaurl `priority` = the RFC 5854 upper bound 999999
/// (cross-checked against aria2 `MetalinkResource.h getLowestPriority()` —
/// aria2's default is lowest priority).
pub const DEFAULT_PRIORITY: u32 = 999_999;
/// Legal `priority` domain (RFC 5854 Appendix B: `xsd:positiveInteger
/// maxInclusive=999999`; aria2 validates the same domain in
/// MetalinkParserStateV4Impl.cc).
pub const PRIORITY_MAX: u32 = 999_999;

/// metalink v4 namespace URI (RFC 5854 §1.2).
pub const METALINK4_NS: &str = "urn:ietf:params:xml:ns:metalink";
/// metalink v3 namespace URI (same text as aria2 `METALINK3_NAMESPACE_URI`;
/// a hit yields [`crate::MetalinkError::UnsupportedVersion`]).
pub const METALINK3_NS: &str = "http://www.metalinker.org/";

/// A successfully parsed mirror manifest (the `<metalink>` root).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metalink {
    /// `<file>` entries (RFC: file+; zero entries after parsing is a hard
    /// error, so a successful Metalink never has empty files).
    pub files: Vec<MetalinkFile>,
    /// `<generator>` (document generator identity, informational).
    pub generator: Option<String>,
    /// `<origin>` (original source of a dynamic document).
    pub origin: Option<Origin>,
    /// `<published>` (xsd:dateTime text; format validation is consumer
    /// policy).
    pub published: Option<String>,
    /// `<updated>` (xsd:dateTime text).
    pub updated: Option<String>,
    /// Soft-drop records (the per-element degradation surface matching
    /// aria2 logError: drop the entry and continue, for logging/diff
    /// reporting; hard errors go through [`crate::MetalinkError`]).
    pub warnings: Vec<ParseWarning>,
}

/// `<origin dynamic="…">` (dynamic manifest source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Source IRI text.
    pub uri: String,
    /// `dynamic` attribute (RFC: xsd:boolean; a non-boolean value is None).
    pub dynamic: Option<bool>,
}

/// A soft-drop record (one-to-one with the logError sites of aria2
/// MetalinkParserStateV4Impl; the text is diagnostic only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWarning {
    /// Drop category.
    pub kind: WarningKind,
    /// Diagnostic context (element name / attribute value fragment,
    /// truncated).
    pub context: String,
}

/// Soft-drop categories (aria2 `MetalinkParserStateV4Impl.cc` logError
/// sites).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarningKind {
    /// file@name missing/empty/path traversal — the whole file is dropped.
    BadFileName,
    /// `<size>` malformed — the whole file is dropped (aria2
    /// cancelEntryTransaction, same rule).
    BadSize,
    /// url@priority malformed/out of range — that url is dropped.
    BadUrlPriority,
    /// `<url>` content empty — that url is dropped.
    EmptyUrl,
    /// metaurl@name empty or a traversal path — that metaurl is dropped.
    BadMetaurlName,
    /// metaurl@priority malformed/out of range — that metaurl is dropped.
    BadMetaurlPriority,
    /// metaurl@mediatype missing/empty — that metaurl is dropped.
    MissingMetaurlMediatype,
    /// hash@type missing/empty — that hash is dropped.
    MissingHashType,
    /// hash content is not valid hex (or digest length mismatches the known
    /// type) — that hash is dropped.
    BadHashHex,
    /// pieces@length/@type missing or malformed — the whole pieces group is
    /// dropped.
    BadPieces,
    /// piece hash entry is not valid hex — that entry is dropped.
    BadPieceHashHex,
    /// signature@mediatype missing/empty — the signature is dropped.
    MissingSignatureMediatype,
    /// publisher@name missing/empty — that element is dropped (RFC 5854
    /// §3.1.3 makes name required; aria2 v4 silently skips the element and
    /// has no logError for it — this implementation consumes publisher as a
    /// model-fidelity superset and warns on missing name under the same
    /// drop discipline).
    BadPublisher,
}

/// A `<file>` entry (RFC 5854 §3.1.2; structurally aria2 `MetalinkEntry`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetalinkFile {
    /// `name` attribute text (RFC required; entries with a missing/empty/
    /// traversal name are dropped by the parser — so the name has no
    /// control characters and no `..`/leading `/` traversal shapes, but may
    /// still contain directory separators; basename sanitization before
    /// writing to disk belongs to the task layer).
    pub name: String,
    /// `<size>` in bytes (non-negative integer; malformed = whole entry
    /// dropped, never a half-entry).
    pub size: Option<u64>,
    /// `<identity>`.
    pub identity: Option<String>,
    /// `<version>`.
    pub version: Option<String>,
    /// `<language>` (repeatable, RFC `language*`).
    pub languages: Vec<String>,
    /// `<os>` (repeatable, RFC `os*`).
    pub oses: Vec<String>,
    /// `<description>`.
    pub description: Option<String>,
    /// `<copyright>`.
    pub copyright: Option<String>,
    /// `<logo>` (IRI text).
    pub logo: Option<String>,
    /// `<publisher name=… url=…>`.
    pub publisher: Option<Publisher>,
    /// `<hash>` checksum group (RFC `hash*`).
    pub hashes: Vec<Hash>,
    /// `<url>` mirror group (RFC `url*`; <= [`MAX_URLS_PER_FILE`]).
    pub urls: Vec<Url>,
    /// `<metaurl>` group (RFC `metaurl*`; BT metadata mirrors).
    pub metaurls: Vec<MetaUrl>,
    /// `<pieces>` group (RFC `pieces*`; multiple groups with different hash
    /// types allowed).
    pub pieces: Vec<PieceSet>,
    /// `<signature mediatype=…>` (body kept verbatim).
    pub signature: Option<Signature>,
}

/// `<publisher name=… url=…>` (RFC 5854 §3.1.3: name required, url
/// optional, no child elements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publisher {
    /// `name` attribute text.
    pub name: String,
    /// `url` attribute text.
    pub url: Option<String>,
}

/// A `<url>` mirror entry (structurally aria2 `MetalinkResource`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// Mirror IRI text (scheme detection / protocol filtering belongs to
    /// the task layer).
    pub uri: String,
    /// `location` (suggested values are ISO 3166-1 alpha-2; kept verbatim,
    /// not validated — aria2 does not validate either).
    pub location: Option<String>,
    /// `priority` (1..=999999; default = [`DEFAULT_PRIORITY`]).
    pub priority: u32,
}

/// A `<metaurl>` metadata mirror entry (structurally aria2
/// `MetalinkMetaurl`).
///
/// BT entries (mediatype="torrent") convert directly to BT tasks inside
/// the engine; that orchestration belongs to the RPC/task layer — this
/// crate only delivers the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaUrl {
    /// Metadata IRI text.
    pub uri: String,
    /// `mediatype` (RFC required; aria2 requires non-empty — entries
    /// missing it are dropped by the parser).
    pub mediatype: String,
    /// `priority` (same domain as [`Url::priority`]).
    pub priority: u32,
    /// `name` (path selection within a multi-file torrent, RFC §3.1.4;
    /// traversal-named entries are dropped by the parser).
    pub name: Option<String>,
}

/// A `<pieces length=… type=…>` piece checksum group (structurally aria2 v4
/// `ChunkChecksum`; the mirror-side declaration of piece-level verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceSet {
    /// `length`: bytes per piece (xs:positiveInteger, always > 0).
    pub piece_length: u64,
    /// `type`: piece hash type (shared by the whole group).
    pub kind: HashKind,
    /// Per-piece digest hex in document order (invalid entries are dropped
    /// by the parser).
    pub hashes: Vec<String>,
}

/// `<signature mediatype=…>` (body kept verbatim; signature verification is
/// task-layer policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// `mediatype` attribute text.
    pub mediatype: String,
    /// Signature body (text with leading/trailing whitespace trimmed).
    pub body: String,
}

/// Path traversal name detection (cross-checked against aria2
/// `util::detectDirTraversal`, util.cc: control characters / `.`·`..` /
/// leading `/`·`./`·`../` / embedded `/../`·`/./` / trailing `/`·`/.`·`/..`).
/// file/metaurl entries whose name matches are dropped whole by the parser
/// (same rule as aria2 logError). POSIX backslash names are not in scope
/// (aria2 likewise — Windows semantics belong to the task layer).
pub(crate) fn detect_dir_traversal(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.bytes().any(|c| c <= 0x1f || c == 0x7f) {
        return true;
    }
    s == "."
        || s == ".."
        || s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.contains("/../")
        || s.contains("/./")
        || s.ends_with('/')
        || s.ends_with("/.")
        || s.ends_with("/..")
}

#[cfg(test)]
mod tests {
    use super::detect_dir_traversal;

    /// Cross-checks aria2 `util::detectDirTraversal` (util.cc).
    #[test]
    fn dir_traversal_parity_with_aria2() {
        // Traversal = true.
        assert!(detect_dir_traversal("../evil.iso"));
        assert!(detect_dir_traversal("/abs.iso"));
        assert!(detect_dir_traversal("./rel.iso"));
        assert!(detect_dir_traversal("a/../b.iso"));
        assert!(detect_dir_traversal("a/./b.iso"));
        assert!(detect_dir_traversal("dir/"));
        assert!(detect_dir_traversal("dir/."));
        assert!(detect_dir_traversal("dir/.."));
        assert!(detect_dir_traversal("."));
        assert!(detect_dir_traversal(".."));
        assert!(detect_dir_traversal("bad\u{01}name.iso"));
        assert!(detect_dir_traversal("del\u{7f}.iso"));
        // Legal names = false (including POSIX backslash names — aria2 also
        // does not detect `\`).
        assert!(!detect_dir_traversal("example.ext"));
        assert!(!detect_dir_traversal("..\\..\\example.ext"));
        assert!(!detect_dir_traversal("sub/dir/file.iso"));
        assert!(!detect_dir_traversal("..data.iso"));
        assert!(!detect_dir_traversal("a..b.iso"));
        assert!(!detect_dir_traversal(""));
    }
}
