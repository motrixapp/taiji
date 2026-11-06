//! `taiji-metalink` — Metalink v4 (RFC 5854) parsing and mirror manifest
//! model (pure data layer).
//!
//! Crate boundary: "format → model" only — RFC 5854 document parsing, the
//! mirror manifest model, checksum consumption (md5/sha-1/SHA-2 family),
//! and metaurl extraction. Task orchestration, downloading, and multi-source
//! scheduling all use existing paths; this crate has zero reverse
//! dependencies and consumers gate it behind their own features (the
//! `metalink` feature of `taiji-rpc`, on by default — with it off the RPC
//! layer does not register addMetalink).
//!
//! Modules:
//! - [`model`]: the mirror manifest model (`Metalink`/`MetalinkFile`/
//! mirror URLs/metaurls/piece hashes/signature) and parse-limit constants;
//! - [`hash`]: `<hash>` checksum consumption — type identification (IANA
//! textual names), hex decoding, digest verification over given bytes;
//! - [`parser`]: quick-xml event-machine parse entry
//! [`parse`](parser::parse);
//! - [`error`]: parse errors (error-code strings belong to the RPC mapping
//! layer; this crate only provides the variants).
//!
//! # Parsing discipline
//!
//! - DTDs/entities disabled: quick-xml never resolves external entities
//! (no XXE surface); `DOCTYPE` is a parse error; undefined entity
//! references are parse errors; only the five predefined entities
//! (`&amp;` etc.) expand.
//! - Limits: documents <= 16MiB, `<file>` <= 10k, `<url>`/`<metaurl`
//! <= 64 per file (exceeding any is a hard error, rejected at parse
//! time).
//! - Charset declarations honored from the XML declaration/BOM (UTF-8,
//! ISO-8859-1, and other ASCII-compatible label names; values and
//! attributes decode via encoding_rs; since quick-xml 0.42 the event
//! surface is always UTF-8, so a non-UTF-8 declaration triggers one full
//! transcode + reparse at `Event::Decl`). UTF-16-like inputs (BOM/`<?`
//! byte patterns) are an explicit parse error — 0.42's `DecodingReader`
//! could silently transcode UTF-16, and this parser does not use it.
//! - Namespaces: elements match on (namespace URI, local name) — only
//! elements in the metalink v4 namespace take part in manifest semantics
//! (same rule as aria2 MetalinkParserStateV4Impl.cc `isMetalink4Ns` +
//! findAttr double matching): unprefixed children under a root with no
//! default binding, elements with an unbound prefix, and same-name
//! elements/attributes in foreign namespaces never participate (skipped;
//! no local-name admission).
//! - Character surface: bare control characters outside the XML 1.0 Char
//! production (except Tab/LF/CR) are malformed and rejected at parse
//! time; line-end normalization follows XML 1.0 rules (text goes through
//! `xml10_content` — U+0085/U+2028 are not folded to line breaks).
//!
//! # aria2 behavior mapping (read-only reference)
//!
//! Per-element semantics mirror the upstream aria2 Metalink parsing state
//! machine (`MetalinkParserStateV4Impl.cc` /
//! `MetalinkParserController.cc`): missing/out-of-range/malformed
//! attributes drop that element (or the whole file entry — malformed size
//! and a missing/traversal file@name drop the entry, same rule as
//! `util::detectDirTraversal` in util.cc) and record it in
//! [`Metalink::warnings`] while parsing continues. Document-level
//! structural errors (non-metalink root, unknown namespace, zero file
//! entries) are the hard errors. Unknown/foreign-namespace elements are
//! silently skipped (not fatal, aria2 skipTag). metalink v3 (the
//! `http://www.metalinker.org/` namespace or `version="3.0"`) is an
//! explicit downgrade error [`MetalinkError::UnsupportedVersion`] — the
//! default branch; the executable fixture inventory lives in
//! `tests/v3_adjudication.rs`.
//!
//! The model is a fidelity superset of the aria2 consumption surface:
//! informational elements such as `identity`/`description`/`publisher`
//! (silently skipped by aria2 v4) are kept per RFC 5854; `<hash>`/`<pieces`
//! groups are kept in full (aria2 picks one best group — selection is
//! task-layer policy, the data layer does not decide).
//!
//! Text values have leading/trailing ASCII whitespace (space/tab/CR/LF)
//! trimmed: a pragmatic deviation from RFC 5854 §2.4 "MUST NOT ignore
//! whitespace" — the RFC's own §1.1 example has indented metaurl content
//! and ecosystem documents are widely pretty-printed; only the element
//! content edges are trimmed, internal whitespace is untouched.
//!
//! # Registered deviations
//!
//! - ISO-8859-1 decodes via the WHATWG windows-1252 mapping: encoding_rs
//! maps the `ISO-8859-1` label to windows-1252 (same as the HTML
//! standard), so 0x80-0x9F decode as Cp1252 printables (e.g. 0x85 →
//! U+2026). Strict Latin-1 decoding would produce XML 1.0-illegal C1
//! characters in that range — this deviation is in the lenient
//! (superset-accepting) direction and is pinned in the parser tests.
//!
//! # fuzz
//!
//! The parser entry point is a fuzz target (whole-document byte stream):
//! `fuzz/fuzz_targets/metalink_v4.rs` (separate fuzz workspace).

pub mod error;
pub mod hash;
pub mod model;
pub mod parser;

pub use error::MetalinkError;
pub use hash::{Hash, HashKind, VerifyError};
pub use model::{
    DEFAULT_PRIORITY, MAX_DOCUMENT_BYTES, MAX_FILES, MAX_METAURLS_PER_FILE, MAX_URLS_PER_FILE,
    METALINK3_NS, METALINK4_NS, MetaUrl, Metalink, MetalinkFile, Origin, PRIORITY_MAX,
    ParseWarning, PieceSet, Publisher, Signature, Url, WarningKind,
};
pub use parser::parse;
