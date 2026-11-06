//! RFC 5854 document parser (quick-xml event machine + own namespace
//! stack).
//!
//! Structure: a single-pass event loop with an explicit frame stack (no
//! recursion). A frame = the currently open element plus its accumulated
//! text (mirrors the aria2 ExpatXmlParser character accumulation: entity
//! references split text into multiple events, joined at End).
//!
//! Entities (quick-xml 0.42 event model): references in text arrive as
//! separate GeneralRef events (payload = entity name, `&` and `;`
//! stripped). Only the five predefined entities and numeric character
//! references resolve; anything else is a parse error — custom/external
//! entities have no resolution path, so the XXE/entity-expansion surface
//! is closed. Text is line-end normalized per XML 1.0 via
//! `xml10_content` (quick-xml's `xml11_content`/`xml_content(Explicit1_1)`
//! is XML 1.1 normalization — U+0085/U+2028 folded to line breaks — and
//! is deliberately avoided).
//!
//! Events (0.42): always UTF-8 str (the tokenizer validates each slice);
//! decoding no longer hangs off events/Decoder. UTF-16-like inputs are
//! explicitly rejected at the entry via BOM/`<?` byte patterns; a
//! non-UTF-8 ASCII-compatible declaration (ISO-8859-1 etc.) triggers one
//! full transcode + reparse at `Event::Decl`.
//!
//! Namespaces (same rule as aria2 MetalinkParserStateV4Impl.cc): elements
//! match on (namespace URI, local name) — only elements in the metalink
//! v4 namespace take part in manifest semantics. Elements with an unbound
//! prefix, unprefixed children under a root with no default binding, and
//! same-name elements in foreign namespaces are skipped with their whole
//! subtree (aria2 skipTag); a local-name match alone never admits them.
//! Attributes follow the same rule (aria2 findAttr: local name + v4
//! namespace) — foreign same-name attributes do not shadow.
//!
//! Parsing discipline (see crate docs): DOCTYPE is rejected outright;
//! three-tier size caps + a depth cap are hard errors; bare control
//! characters outside the XML 1.0 Char production are rejected.

use quick_xml::Reader;
use quick_xml::encoding::{DetectedEncoding, decode, detect_encoding};
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;

use crate::error::MetalinkError;
use crate::hash::{Hash, HashKind, is_valid_hex};
use crate::model::{
    DEFAULT_PRIORITY, MAX_DEPTH, MAX_FILES, MAX_METAURLS_PER_FILE, MAX_URLS_PER_FILE, METALINK3_NS,
    METALINK4_NS, MetaUrl, Metalink, MetalinkFile, Origin, PRIORITY_MAX, ParseWarning, PieceSet,
    Publisher, Signature, Url, WarningKind, detect_dir_traversal,
};

/// Namespace binding set: (prefix bytes (empty = default namespace), URI
/// bytes).
type NsBindings = Vec<(Vec<u8>, Vec<u8>)>;
/// Namespace binding stack: (frame depth at push, bindings); popped when
/// the host element closes.
type NsStack = Vec<(usize, NsBindings)>;

/// Parse entry point: a whole document byte stream (the fuzz surface).
///
/// Returns the model or a hard error; per-element soft degradation (same
/// rule as aria2 logError) is recorded in [`Metalink::warnings`].
pub fn parse(input: &[u8]) -> Result<Metalink, MetalinkError> {
    if input.len() > crate::model::MAX_DOCUMENT_BYTES {
        return Err(MetalinkError::DocumentTooLarge {
            len: input.len(),
            limit: crate::model::MAX_DOCUMENT_BYTES,
        });
    }

    // In 0.42 the event surface is always UTF-8 (per-slice `from_utf8` in
    // the tokenizer). UTF-16-like inputs (BOM or `<?` byte patterns) are
    // rejected here explicitly: 0.42's `DecodingReader` silently transcodes
    // UTF-16 and this parser does not use it — no silent misreading. UTF-32
    // has no detection pattern; it falls through to UTF-8 tokenizing and is
    // rejected structurally (NUL never matches a name).
    let detected = detect_encoding(input);
    if matches!(
        detected,
        Some(
            DetectedEncoding::Utf16LeBom
                | DetectedEncoding::Utf16BeBom
                | DetectedEncoding::Utf16LeLike
                | DetectedEncoding::Utf16BeLike
        )
    ) {
        return Err(MetalinkError::ParseFailed {
            reason: "UTF-16 encoding is not supported (explicitly rejected)".to_string(),
        });
    }
    // UTF-8 BOM length (stripped before transcoding — windows-1252 et al.
    // would misread EF BB BF as text; UTF-16 BOMs were rejected above).
    let bom = detected.map_or(0, |d| d.bom_len());
    parse_document(input, bom, true)
}

/// Event loop body (continuation of [`parse`]). `bom` = BOM length
/// detected at entry (stripped when transcoding per the declared charset);
/// `allow_transcode` = whether a full transcode + reparse at `Event::Decl`
/// is allowed (first pass only, prevents recursion).
fn parse_document(
    input: &[u8],
    bom: usize,
    allow_transcode: bool,
) -> Result<Metalink, MetalinkError> {
    let mut reader = Reader::from_reader(input);
    // Well-formedness: start/end tag matching is enforced by the tokenizer
    // (check_end_names defaults on; stated explicitly to pin the contract).
    reader.config_mut().check_end_names = true;

    let mut buf = Vec::with_capacity(4096);
    let mut doc = Metalink::default();
    let mut stack: Vec<Frame> = Vec::new();
    // Whether the root element appeared (the frame stack empties once the
    // root closes, so stack depth cannot identify the root).
    let mut saw_root = false;
    // Root element closed: any element event (Start/Empty) afterwards is
    // rejected (multiple roots / content outside the root = malformed —
    // "<metalink/> + a second complete document" used to be accepted; only
    // Misc — whitespace text/comments/PIs — is allowed).
    let mut root_closed = false;
    // Namespace binding stack: (frame depth at push, bindings); popped when
    // the host element closes.
    let mut ns: NsStack = Vec::new();

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| MetalinkError::ParseFailed {
                reason: e.to_string(),
            })?;
        match event {
            Event::Start(e) => {
                if root_closed {
                    return Err(root_tail_error());
                }
                let (prefix, local) = split_name(e.name());
                let bindings = collect_bindings(&e)?;
                if !bindings.is_empty() {
                    ns.push((stack.len(), bindings));
                }
                let uri = resolve_ns(&ns, prefix, stack.len());
                start_element(&mut doc, &mut stack, uri.as_deref(), local, &e, &ns)?;
                saw_root |= matches!(
                    stack.last(),
                    Some(Frame {
                        kind: FrameKind::Metalink,
                        ..
                    })
                );
            }
            Event::Empty(e) => {
                // <x/> is a full open/close cycle (expat semantics): the
                // frame is pushed and immediately closed (empty text). A
                // self-closing root also counts as "root appeared"
                // (saw_root covers the Empty branch too — without it
                // <metalink/> is not registered as the root and a second
                // complete document would be accepted as the first).
                if root_closed {
                    return Err(root_tail_error());
                }
                let (prefix, local) = split_name(e.name());
                let bindings = collect_bindings(&e)?;
                if !bindings.is_empty() {
                    ns.push((stack.len(), bindings));
                }
                let uri = resolve_ns(&ns, prefix, stack.len());
                start_element(&mut doc, &mut stack, uri.as_deref(), local, &e, &ns)?;
                saw_root |= matches!(
                    stack.last(),
                    Some(Frame {
                        kind: FrameKind::Metalink,
                        ..
                    })
                );
                end_element(&mut doc, &mut stack, &mut ns)?;
                if saw_root && stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::End(_) => {
                end_element(&mut doc, &mut stack, &mut ns)?;
                if saw_root && stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::Text(t) => {
                // XML 1.0 semantics: line-end normalization (xml10_content;
                // 0.42 events are already UTF-8 str, no decode step); bare
                // control characters outside XML 1.0 Char are rejected;
                // text outside the root is allowed only as whitespace (Misc).
                let decoded = t.xml10_content();
                validate_xml10_chars(&decoded)?;
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&decoded);
                } else if !decoded.chars().all(is_xml10_ws) {
                    return Err(MetalinkError::ParseFailed {
                        reason: "character data outside the root element".to_string(),
                    });
                }
            }
            Event::GeneralRef(t) => {
                // Payload = entity name (quick-xml strips `&` and `;`);
                // a reference outside the root is malformed.
                let ch = resolve_entity(t.as_bytes())?;
                if let Some(top) = stack.last_mut() {
                    top.text.push(ch);
                } else {
                    return Err(MetalinkError::ParseFailed {
                        reason: "entity reference outside the root element".to_string(),
                    });
                }
            }
            Event::CData(t) => {
                // CDATA is literal character data: no entity expansion (no
                // double decoding); line-end normalization per XML 1.0 is
                // applied here too (no decode step since 0.42); CDATA
                // outside the root is malformed.
                let decoded = t.xml10_content();
                validate_xml10_chars(&decoded)?;
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&decoded);
                } else {
                    return Err(MetalinkError::ParseFailed {
                        reason: "CDATA outside the root element".to_string(),
                    });
                }
            }
            Event::DocType(_) => {
                // DTDs are disabled: DOCTYPE is rejected outright — entity
                // expansion and external DTDs have no path into this parser.
                return Err(MetalinkError::ParseFailed {
                    reason: "DOCTYPE is not allowed (DTD/entities disabled)".to_string(),
                });
            }
            Event::Decl(e) => {
                // Charset declaration handling: in 0.42 the event surface is
                // always UTF-8, so a non-UTF-8 ASCII-compatible declaration
                // triggers one full transcode + reparse here (the declaration
                // segment is ASCII and transcodes identically under any
                // ASCII-compatible encoding; the BOM is already stripped).
                // Unrecognized encoding = None → stay UTF-8 (non-ASCII bytes
                // are then rejected by UTF-8 validation). UTF-16-like inputs
                // were rejected at the parse() entry and never get here.
                if allow_transcode
                    && let Some(enc) = e.encoder()
                    && enc.name() != "UTF-8"
                {
                    let transcoded =
                        decode(&input[bom..], enc).map_err(|err| MetalinkError::ParseFailed {
                            reason: err.to_string(),
                        })?;
                    return parse_document(transcoded.as_bytes(), 0, false);
                }
            }
            Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
        buf.clear();
    }

    if !saw_root {
        return Err(MetalinkError::ParseFailed {
            reason: "document has no metalink root element".to_string(),
        });
    }
    if !stack.is_empty() {
        return Err(MetalinkError::ParseFailed {
            reason: "unbalanced document (unclosed elements)".to_string(),
        });
    }
    if doc.files.is_empty() {
        // aria2 fails the task on zero entries (same rule on the consumer
        // side, Metalink2RequestGroup).
        return Err(MetalinkError::ParseFailed {
            reason: "document contains no file entries".to_string(),
        });
    }
    Ok(doc)
}

/// Entity reference resolution: the five predefined entities + numeric
/// character references (decimal/hex, XML 1.0 legal range); anything else
/// (including external/custom entities) is a parse error — entity
/// expansion is disabled and the XXE surface is closed.
fn resolve_entity(name: &[u8]) -> Result<char, MetalinkError> {
    let ch = match name {
        b"amp" => '&',
        b"lt" => '<',
        b"gt" => '>',
        b"quot" => '"',
        b"apos" => '\'',
        _ => {
            let parsed = if let Some(hex) = name.strip_prefix(b"#x").or(name.strip_prefix(b"#X")) {
                std::str::from_utf8(hex)
                    .ok()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
            } else if let Some(dec) = name.strip_prefix(b"#") {
                std::str::from_utf8(dec)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
            } else {
                None
            };
            return match parsed.and_then(char::from_u32) {
                Some(c) if !c.is_control() || matches!(c, '\t' | '\n' | '\r') => Ok(c),
                _ => Err(MetalinkError::ParseFailed {
                    reason: "unsupported character reference (entities disabled)".to_string(),
                }),
            };
        }
    };
    Ok(ch)
}

// ---- Character surface (XML 1.0 Char validation) --------------------------

/// XML 1.0 Char production (#x9 | #xA | #xD | [#x20-#xD7FF] |
/// [#xE000-#xFFFD] | [#x10000-#x10FFFF]). The quick-xml tokenizer does not
/// validate character legality — bare control characters (except
/// Tab/LF/CR) would pass through the event stream into model fields; this
/// surface rejects them uniformly at the text/attribute decode points.
fn is_xml10_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{D7FF}').contains(&c)
        || ('\u{E000}'..='\u{FFFD}').contains(&c)
        || ('\u{10000}'..='\u{10FFFF}').contains(&c)
}

/// XML whitespace (the outside-root Misc whitelist: whitespace text,
/// comments and PIs pass).
fn is_xml10_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Character-surface validation for text/attribute values; a violation is
/// a hard malformed error (the reason carries only the code point, never
/// document content).
fn validate_xml10_chars(s: &str) -> Result<(), MetalinkError> {
    match s.chars().find(|c| !is_xml10_char(*c)) {
        None => Ok(()),
        Some(c) => Err(MetalinkError::ParseFailed {
            reason: format!(
                "raw character U+{:04X} is not an XML 1.0 character",
                c as u32
            ),
        }),
    }
}

/// Element content after the root closes = malformed (multiple roots /
/// elements outside the root).
fn root_tail_error() -> MetalinkError {
    MetalinkError::ParseFailed {
        reason: "element content after the metalink root element".to_string(),
    }
}

// ---- Frame stack ----------------------------------------------------------

#[derive(Debug)]
struct Frame {
    kind: FrameKind,
    /// Text accumulated by the open element (after entity expansion +
    /// line-end normalization).
    text: String,
}

#[derive(Debug)]
enum FrameKind {
    /// `<metalink>` root.
    Metalink,
    /// `<file>`; doomed = invalid name or malformed size (aria2 rule: the
    /// entry is not committed, children are consumed normally but their
    /// results are all discarded).
    File {
        file: Box<MetalinkFile>,
        doomed: bool,
    },
    /// `<url>` (attributes validated into pending, text supplies the uri).
    Url { url: Url },
    /// `<metaurl>`.
    MetaUrl { metaurl: MetaUrlPending },
    /// `<hash type=…>`.
    Hash { kind: HashKind },
    /// `<hash>` inside pieces.
    PieceHash,
    /// `<pieces length=… type=…>`.
    Pieces { pending: PiecesPending },
    /// `<signature mediatype=…>`.
    Signature { mediatype: String },
    /// `<origin dynamic=…>`.
    Origin { dynamic: Option<bool> },
    /// Document-level single-value text elements.
    DocText(DocSlot),
    /// file-level text elements (single-value / repeatable).
    FileText(FileSlot, bool),
    /// Unknown/foreign-namespace element — the whole subtree is silently
    /// swallowed (same rule as aria2 skipTag; not fatal).
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocSlot {
    Generator,
    Published,
    Updated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSlot {
    Size,
    Identity,
    Version,
    Description,
    Copyright,
    Logo,
    Language,
    Os,
}

#[derive(Debug)]
struct MetaUrlPending {
    mediatype: String,
    priority: u32,
    name: Option<String>,
}

#[derive(Debug)]
struct PiecesPending {
    piece_length: u64,
    kind: HashKind,
    hashes: Vec<String>,
}

/// Parent frame discriminant (avoids dispatch under a mutable borrow).
enum Parent {
    Metalink,
    FileDoomed,
    FileActive,
    Pieces,
    Container,
}

fn parent_of(stack: &[Frame]) -> Parent {
    match stack.last() {
        Some(Frame {
            kind: FrameKind::Metalink,
            ..
        }) => Parent::Metalink,
        Some(Frame {
            kind: FrameKind::File { doomed, .. },
            ..
        }) => {
            if *doomed {
                Parent::FileDoomed
            } else {
                Parent::FileActive
            }
        }
        Some(Frame {
            kind: FrameKind::Pieces { .. },
            ..
        }) => Parent::Pieces,
        Some(_) => Parent::Container,
        None => Parent::Container,
    }
}

fn start_element(
    doc: &mut Metalink,
    stack: &mut Vec<Frame>,
    ns_uri: Option<&str>,
    local: &[u8],
    e: &BytesStart,
    ns: &NsStack,
) -> Result<(), MetalinkError> {
    if stack.len() >= MAX_DEPTH {
        return Err(MetalinkError::ParseFailed {
            reason: format!("element nesting exceeds depth limit {MAX_DEPTH}"),
        });
    }

    if stack.is_empty() {
        return root_element(stack, ns_uri, local, e, ns);
    }

    // Namespace decision (same rule as the reference implementation,
    // MetalinkParserStateV4Impl.cc isMetalink4Ns + local-name match): only
    // v4-namespace elements take part in manifest semantics — elements with
    // an unbound prefix (the expat unbound-prefix surface), unprefixed
    // children under a root with no default binding (XML Namespaces: no
    // prefix = no namespace), and same-name elements in foreign namespaces
    // are skipped with their subtree; a local-name match never admits them
    // (prevents same-name shadowing, aria2 skipTag).
    if ns_uri != Some(METALINK4_NS) {
        return push_skip(stack);
    }

    match parent_of(stack) {
        Parent::Metalink => match local {
            b"file" => {
                let name = take_attr(e, "name", ns, stack.len())?;
                let valid = name
                    .as_deref()
                    .is_some_and(|n| !n.is_empty() && !detect_dir_traversal(n));
                if valid {
                    let file = match name {
                        Some(name) => MetalinkFile {
                            name,
                            ..MetalinkFile::default()
                        },
                        // Unreachable (valid already checks Some); kept for
                        // structural completeness — no expect/unwrap.
                        None => MetalinkFile::default(),
                    };
                    stack.push(Frame {
                        kind: FrameKind::File {
                            file: Box::new(file),
                            doomed: false,
                        },
                        text: String::new(),
                    });
                } else {
                    // aria2: missing/empty/traversal name → logError, no
                    // entry (MetalinkParserStateV4Impl.cc); children are
                    // all discarded; parsing continues.
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::BadFileName,
                        context: short(name.as_deref().unwrap_or_default()),
                    });
                    stack.push(Frame {
                        kind: FrameKind::File {
                            file: Box::new(MetalinkFile::default()),
                            doomed: true,
                        },
                        text: String::new(),
                    });
                }
                Ok(())
            }
            b"generator" => push(stack, FrameKind::DocText(DocSlot::Generator)),
            b"published" => push(stack, FrameKind::DocText(DocSlot::Published)),
            b"updated" => push(stack, FrameKind::DocText(DocSlot::Updated)),
            b"origin" => {
                let dynamic =
                    take_attr(e, "dynamic", ns, stack.len())?.and_then(|v| parse_bool(&v));
                stack.push(Frame {
                    kind: FrameKind::Origin { dynamic },
                    text: String::new(),
                });
                Ok(())
            }
            // RFC extension elements / foreign-namespace markers: skip the
            // subtree, not fatal.
            _ => push_skip(stack),
        },
        Parent::FileDoomed => push_skip(stack),
        Parent::FileActive => file_child(doc, stack, local, e, ns),
        Parent::Pieces => {
            if local == b"hash" {
                push(stack, FrameKind::PieceHash)
            } else {
                push_skip(stack)
            }
        }
        // Any nesting inside value elements or skip regions: silently
        // skipped (aria2 skipTag).
        Parent::Container => push_skip(stack),
    }
}

/// Child-element dispatch for an active `<file>` frame (attribute
/// validation failure = that child is dropped + warning, same rule as
/// aria2 logError + return).
fn file_child(
    doc: &mut Metalink,
    stack: &mut Vec<Frame>,
    local: &[u8],
    e: &BytesStart,
    ns: &NsStack,
) -> Result<(), MetalinkError> {
    // Attribute lookup depth = stack depth before this element's frame is
    // pushed (its own xmlns bindings are pushed at the same depth in the
    // loop and are visible to its attributes).
    let depth = stack.len();
    match local {
        b"size" => push(stack, FrameKind::FileText(FileSlot::Size, false)),
        b"identity" => push(stack, FrameKind::FileText(FileSlot::Identity, false)),
        b"version" => push(stack, FrameKind::FileText(FileSlot::Version, false)),
        b"description" => push(stack, FrameKind::FileText(FileSlot::Description, false)),
        b"copyright" => push(stack, FrameKind::FileText(FileSlot::Copyright, false)),
        b"logo" => push(stack, FrameKind::FileText(FileSlot::Logo, false)),
        b"language" => push(stack, FrameKind::FileText(FileSlot::Language, true)),
        b"os" => push(stack, FrameKind::FileText(FileSlot::Os, true)),
        b"publisher" => {
            // RFC 5854 §3.1.3: name is required, url is optional, no child
            // elements. aria2 v4 silently skips the whole element; this
            // implementation consumes it into the model (the crate's
            // model-fidelity superset). Missing name = drop + warning
            // (WarningKind::BadPublisher is this surface's own site —
            // aria2 has no matching logError).
            let name = match take_attr(e, "name", ns, depth)? {
                Some(n) if !n.is_empty() => n,
                other => {
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::BadPublisher,
                        context: short(other.as_deref().unwrap_or_default()),
                    });
                    return push_skip(stack);
                }
            };
            let url = take_attr(e, "url", ns, depth)?;
            let file = current_file_mut(stack).ok_or_else(|| MetalinkError::ParseFailed {
                reason: "publisher outside file element".to_string(),
            })?;
            file.publisher = Some(Publisher { name, url });
            // Children/text are swallowed by the Skip frame (the RFC defines
            // no child elements; closes the injection surface).
            push_skip(stack)
        }
        b"url" => {
            let location = take_attr(e, "location", ns, depth)?;
            let priority = match priority_attr(e, WarningKind::BadUrlPriority, ns, depth)? {
                Ok(p) => p,
                Err(kind) => {
                    doc.warnings.push(ParseWarning {
                        kind,
                        context: "url".to_string(),
                    });
                    return push_skip(stack);
                }
            };
            stack.push(Frame {
                kind: FrameKind::Url {
                    url: Url {
                        uri: String::new(),
                        location,
                        priority,
                    },
                },
                text: String::new(),
            });
            Ok(())
        }
        b"metaurl" => {
            let mediatype = match take_attr(e, "mediatype", ns, depth)? {
                Some(m) if !m.is_empty() => m,
                other => {
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::MissingMetaurlMediatype,
                        context: short(other.as_deref().unwrap_or_default()),
                    });
                    return push_skip(stack);
                }
            };
            let name = take_attr(e, "name", ns, depth)?;
            if let Some(n) = &name {
                if n.is_empty() || detect_dir_traversal(n) {
                    // aria2: bad metaurl@name (MetalinkParserStateV4Impl.cc).
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::BadMetaurlName,
                        context: short(n),
                    });
                    return push_skip(stack);
                }
            }
            let priority = match priority_attr(e, WarningKind::BadMetaurlPriority, ns, depth)? {
                Ok(p) => p,
                Err(kind) => {
                    doc.warnings.push(ParseWarning {
                        kind,
                        context: "metaurl".to_string(),
                    });
                    return push_skip(stack);
                }
            };
            stack.push(Frame {
                kind: FrameKind::MetaUrl {
                    metaurl: MetaUrlPending {
                        mediatype,
                        priority,
                        name,
                    },
                },
                text: String::new(),
            });
            Ok(())
        }
        b"hash" => {
            let ty = match take_attr(e, "type", ns, depth)? {
                Some(t) if !t.is_empty() => t,
                other => {
                    // aria2: missing hash@type (MetalinkParserStateV4Impl.cc).
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::MissingHashType,
                        context: short(other.as_deref().unwrap_or_default()),
                    });
                    return push_skip(stack);
                }
            };
            push(
                stack,
                FrameKind::Hash {
                    kind: HashKind::from_type_name(&ty),
                },
            )
        }
        b"pieces" => {
            let length = match take_attr(e, "length", ns, depth)? {
                // xs:positiveInteger; aria2 parses it as uint32
                // (parseUIntNoThrow — overflow = bad pieces@length).
                Some(l) => l,
                None => {
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::BadPieces,
                        context: "missing pieces@length".to_string(),
                    });
                    return push_skip(stack);
                }
            };
            let piece_length = length.parse::<u64>().ok().filter(|l| *l > 0);
            let Some(piece_length) = piece_length else {
                doc.warnings.push(ParseWarning {
                    kind: WarningKind::BadPieces,
                    context: short(&length),
                });
                return push_skip(stack);
            };
            let ty = match take_attr(e, "type", ns, depth)? {
                Some(t) if !t.is_empty() => t,
                other => {
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::BadPieces,
                        context: short(other.as_deref().unwrap_or_default()),
                    });
                    return push_skip(stack);
                }
            };
            stack.push(Frame {
                kind: FrameKind::Pieces {
                    pending: PiecesPending {
                        piece_length,
                        kind: HashKind::from_type_name(&ty),
                        hashes: Vec::new(),
                    },
                },
                text: String::new(),
            });
            Ok(())
        }
        b"signature" => {
            let mediatype = match take_attr(e, "mediatype", ns, depth)? {
                Some(m) if !m.is_empty() => m,
                other => {
                    // aria2: missing signature@mediatype
                    // (MetalinkParserStateV4Impl.cc).
                    doc.warnings.push(ParseWarning {
                        kind: WarningKind::MissingSignatureMediatype,
                        context: short(other.as_deref().unwrap_or_default()),
                    });
                    return push_skip(stack);
                }
            };
            push(stack, FrameKind::Signature { mediatype })
        }
        _ => push_skip(stack),
    }
}

/// Root element: version detection by namespace (explicit v3 downgrade) +
/// push.
fn root_element(
    stack: &mut Vec<Frame>,
    ns_uri: Option<&str>,
    local: &[u8],
    e: &BytesStart,
    ns: &NsStack,
) -> Result<(), MetalinkError> {
    if local != b"metalink" {
        return Err(MetalinkError::ParseFailed {
            reason: format!(
                "root element is not metalink: {}",
                short(&String::from_utf8_lossy(local))
            ),
        });
    }
    // The version attribute takes precedence (RFC 5854 has no such
    // attribute — its presence is an external signal; "3.0" gives a
    // document with an unknown namespace + version declaration the
    // accurate downgrade error too).
    let version = take_attr(e, "version", ns, stack.len())?;
    if version.as_deref() == Some("3.0") {
        return Err(MetalinkError::UnsupportedVersion {
            found: "3.0".to_string(),
        });
    }
    match ns_uri {
        Some(METALINK3_NS) => Err(MetalinkError::UnsupportedVersion {
            found: METALINK3_NS.to_string(),
        }),
        Some(METALINK4_NS) => {
            stack.push(Frame {
                kind: FrameKind::Metalink,
                text: String::new(),
            });
            Ok(())
        }
        other => Err(MetalinkError::ParseFailed {
            reason: format!(
                "metalink root without v4 namespace: {}",
                short(other.unwrap_or("(none)"))
            ),
        }),
    }
}

fn end_element(
    doc: &mut Metalink,
    stack: &mut Vec<Frame>,
    ns: &mut NsStack,
) -> Result<(), MetalinkError> {
    let frame = stack.pop().ok_or_else(|| MetalinkError::ParseFailed {
        reason: "unbalanced end element".to_string(),
    })?;
    // Bindings die with their host element: any binding whose depth >= the
    // post-close frame count belongs to the closed element or deeper.
    let closed = stack.len();
    ns.retain(|(depth, _)| *depth < closed);

    let mut frame = frame;
    let mut value = std::mem::take(&mut frame.text);
    trim_xml_ws(&mut value);

    match frame.kind {
        FrameKind::Metalink | FrameKind::Skip => {}
        FrameKind::File { file, doomed } => {
            if !doomed {
                if doc.files.len() >= MAX_FILES {
                    return Err(MetalinkError::TooManyFiles {
                        count: doc.files.len() + 1,
                        limit: MAX_FILES,
                    });
                }
                doc.files.push(*file);
            }
        }
        FrameKind::Url { mut url } => {
            url.uri = value;
            if url.uri.is_empty() {
                doc.warnings.push(ParseWarning {
                    kind: WarningKind::EmptyUrl,
                    context: "url".to_string(),
                });
            } else {
                let file = current_file_mut(stack).ok_or_else(|| MetalinkError::ParseFailed {
                    reason: "url outside file element".to_string(),
                })?;
                if file.urls.len() >= MAX_URLS_PER_FILE {
                    return Err(MetalinkError::TooManyUrls {
                        file: file.name.clone(),
                        count: file.urls.len() + 1,
                        limit: MAX_URLS_PER_FILE,
                    });
                }
                file.urls.push(url);
            }
        }
        FrameKind::MetaUrl { metaurl } => {
            if value.is_empty() {
                doc.warnings.push(ParseWarning {
                    kind: WarningKind::EmptyUrl,
                    context: "metaurl".to_string(),
                });
            } else {
                let file = current_file_mut(stack).ok_or_else(|| MetalinkError::ParseFailed {
                    reason: "metaurl outside file element".to_string(),
                })?;
                if file.metaurls.len() >= MAX_METAURLS_PER_FILE {
                    return Err(MetalinkError::TooManyMetaurls {
                        file: file.name.clone(),
                        count: file.metaurls.len() + 1,
                        limit: MAX_METAURLS_PER_FILE,
                    });
                }
                file.metaurls.push(MetaUrl {
                    uri: value,
                    mediatype: metaurl.mediatype,
                    priority: metaurl.priority,
                    name: metaurl.name,
                });
            }
        }
        FrameKind::Hash { kind } => match finish_hash(kind, &value) {
            Some(hash) => {
                let file = current_file_mut(stack).ok_or_else(|| MetalinkError::ParseFailed {
                    reason: "hash outside file element".to_string(),
                })?;
                file.hashes.push(hash);
            }
            None => doc.warnings.push(ParseWarning {
                kind: WarningKind::BadHashHex,
                context: short(&value),
            }),
        },
        FrameKind::PieceHash => {
            // Parent frame = pieces: hex validity + known-type digest length
            // are checked here.
            let parent_ok = match stack.last_mut() {
                Some(Frame {
                    kind: FrameKind::Pieces { pending },
                    ..
                }) => {
                    let hex = value.to_ascii_lowercase();
                    let len_ok = pending.kind.digest_len().is_none_or(|n| hex.len() == n * 2);
                    if is_valid_hex(&hex) && len_ok {
                        pending.hashes.push(hex);
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if !parent_ok {
                doc.warnings.push(ParseWarning {
                    kind: WarningKind::BadPieceHashHex,
                    context: short(&value),
                });
            }
        }
        FrameKind::Pieces { pending } => {
            if pending.hashes.is_empty() {
                // RFC metalinkHash+ (at least one); an empty group is dropped.
                doc.warnings.push(ParseWarning {
                    kind: WarningKind::BadPieces,
                    context: "pieces without hash entries".to_string(),
                });
            } else {
                let file = current_file_mut(stack).ok_or_else(|| MetalinkError::ParseFailed {
                    reason: "pieces outside file element".to_string(),
                })?;
                file.pieces.push(PieceSet {
                    piece_length: pending.piece_length,
                    kind: pending.kind,
                    hashes: pending.hashes,
                });
            }
        }
        FrameKind::Signature { mediatype } => {
            let file = current_file_mut(stack).ok_or_else(|| MetalinkError::ParseFailed {
                reason: "signature outside file element".to_string(),
            })?;
            file.signature = Some(Signature {
                mediatype,
                body: value,
            });
        }
        FrameKind::Origin { dynamic } => {
            if !value.is_empty() {
                doc.origin = Some(Origin {
                    uri: value,
                    dynamic,
                });
            }
        }
        FrameKind::DocText(slot) => {
            if !value.is_empty() {
                match slot {
                    DocSlot::Generator => doc.generator = Some(value),
                    DocSlot::Published => doc.published = Some(value),
                    DocSlot::Updated => doc.updated = Some(value),
                }
            }
        }
        FrameKind::FileText(slot, repeatable) => match slot {
            // Malformed size = the whole file entry is dropped (aria2
            // cancelEntryTransaction, MetalinkParserStateV4Impl.cc): the
            // frame is marked doomed — the entry is not committed and later
            // child results are silently discarded with it — plus a warning.
            FileSlot::Size if parse_size(&value).is_none() => {
                if let Some(Frame {
                    kind: FrameKind::File { doomed, .. },
                    ..
                }) = stack.last_mut()
                {
                    *doomed = true;
                }
                doc.warnings.push(ParseWarning {
                    kind: WarningKind::BadSize,
                    context: short(&value),
                });
            }
            _ => {
                let file = current_file_mut(stack).ok_or_else(|| MetalinkError::ParseFailed {
                    reason: "file metadata element outside file".to_string(),
                })?;
                apply_file_text(file, slot, repeatable, &value);
            }
        },
    }
    Ok(())
}

/// file-level text finalize (the size doom path is special-cased at the
/// close site).
fn apply_file_text(file: &mut MetalinkFile, slot: FileSlot, repeatable: bool, value: &str) {
    match slot {
        FileSlot::Size => file.size = parse_size(value),
        FileSlot::Identity => file.identity = Some(value.to_string()),
        FileSlot::Version => file.version = Some(value.to_string()),
        FileSlot::Description => file.description = Some(value.to_string()),
        FileSlot::Copyright => file.copyright = Some(value.to_string()),
        FileSlot::Logo => file.logo = Some(value.to_string()),
        FileSlot::Language => {
            if repeatable && !value.is_empty() {
                file.languages.push(value.to_string());
            }
        }
        FileSlot::Os => {
            if repeatable && !value.is_empty() {
                file.oses.push(value.to_string());
            }
        }
    }
}

/// xs:nonNegativeInteger (a leading + is allowed, RFC 5854 size grammar).
fn parse_size(value: &str) -> Option<u64> {
    value.strip_prefix('+').unwrap_or(value).parse::<u64>().ok()
}

/// hash finalize: hex validation + known-type digest-length validation;
/// invalid = None (the caller records a warning and drops the element).
fn finish_hash(kind: HashKind, value: &str) -> Option<Hash> {
    let hex = value.to_ascii_lowercase();
    if !is_valid_hex(&hex) {
        return None;
    }
    if let Some(len) = kind.digest_len() {
        if hex.len() != len * 2 {
            return None;
        }
    }
    Some(Hash::new(kind, hex))
}

/// Stack top must be an active file frame (close site of file children);
/// a doomed frame returns None — its children's results are silently
/// discarded (mirrors aria2's no-transaction semantics).
fn current_file_mut(stack: &mut [Frame]) -> Option<&mut MetalinkFile> {
    match stack.last_mut() {
        Some(Frame {
            kind: FrameKind::File { file, doomed },
            ..
        }) if !*doomed => Some(file),
        _ => None,
    }
}

fn push(stack: &mut Vec<Frame>, kind: FrameKind) -> Result<(), MetalinkError> {
    stack.push(Frame {
        kind,
        text: String::new(),
    });
    Ok(())
}

fn push_skip(stack: &mut Vec<Frame>) -> Result<(), MetalinkError> {
    push(stack, FrameKind::Skip)
}

// ---- Attribute and text helpers --------------------------------------------

/// First attribute matching by name. XML Namespaces semantics + the
/// reference double match (aria2 MetalinkParserStateImpl.cc findAttr):
/// local name equal **and** attribute namespace empty (unprefixed
/// attribute) or the metalink v4 namespace — foreign same-name attributes
/// do not shadow (`xmlns:e="urn:x" e:name=…` does not match); attributes
/// with an unbound prefix are skipped leniently (expat makes that a hard
/// unbound-prefix error; skipping has the same reject effect). `xmlns`/
/// `xmlns:*` are declarations, not attributes, and never match. Values go
/// through entity expansion + XML 1.0 character validation (since 0.42
/// attribute values are always UTF-8 str, no decode step). `depth` = the
/// host element's namespace-lookup depth (its frame is not pushed yet, but
/// its own xmlns bindings are already on the stack at that depth).
fn take_attr(
    e: &BytesStart,
    name: &str,
    ns: &NsStack,
    depth: usize,
) -> Result<Option<String>, MetalinkError> {
    for attr in e.attributes() {
        let attr = attr.map_err(|err| MetalinkError::ParseFailed {
            reason: err.to_string(),
        })?;
        let key: &[u8] = attr.key.0.as_bytes();
        if key == b"xmlns" {
            continue;
        }
        let (prefix, local) = split_name(attr.key);
        if local != name.as_bytes() {
            continue;
        }
        let matched =
            prefix.is_empty() || resolve_ns(ns, prefix, depth).as_deref() == Some(METALINK4_NS);
        if matched {
            // 0.42 replacement for decode_and_unescape_value: unescaping
            // lives in quick_xml::escape (predefined entities + numeric
            // refs; no attribute-value whitespace normalization, strictly
            // equivalent to the 0.38 behavior — normalized_value would fold
            // literal \t\r\n into spaces, a behavior change not adopted).
            let v = unescape(&attr.value).map_err(|err| MetalinkError::ParseFailed {
                reason: err.to_string(),
            })?;
            validate_xml10_chars(&v)?;
            return Ok(Some(v.into_owned()));
        }
    }
    Ok(None)
}

/// priority attribute (shared by url/metaurl): missing = DEFAULT_PRIORITY;
/// malformed/out of range (outside 1..=999999) = Err(bad) — same rule as
/// aria2, the element is dropped. `bad` is supplied by the caller (the
/// url/metaurl warning variant).
fn priority_attr(
    e: &BytesStart,
    bad: WarningKind,
    ns: &NsStack,
    depth: usize,
) -> Result<Result<u32, WarningKind>, MetalinkError> {
    let raw = take_attr(e, "priority", ns, depth)?;
    let Some(raw) = raw else {
        return Ok(Ok(DEFAULT_PRIORITY));
    };
    match raw.trim().parse::<u32>() {
        Ok(p) if (1..=PRIORITY_MAX).contains(&p) => Ok(Ok(p)),
        _ => Ok(Err(bad)),
    }
}

/// Collect xmlns bindings (default + prefixed; same-name nearest-wins is
/// guaranteed by resolve_ns's reverse lookup). Binding values get the same
/// attribute-value validation (entity expansion + XML 1.0 characters).
fn collect_bindings(e: &BytesStart) -> Result<NsBindings, MetalinkError> {
    let mut out: NsBindings = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|err| MetalinkError::ParseFailed {
            reason: err.to_string(),
        })?;
        let key: &[u8] = attr.key.0.as_bytes();
        if key == b"xmlns" {
            // Unescaping as in take_attr (quick_xml::escape, no whitespace
            // normalization).
            let v = unescape(&attr.value).map_err(|err| MetalinkError::ParseFailed {
                reason: err.to_string(),
            })?;
            validate_xml10_chars(&v)?;
            out.push((Vec::new(), v.into_owned().into_bytes()));
        } else if let Some(prefix) = key.strip_prefix(b"xmlns:") {
            let v = unescape(&attr.value).map_err(|err| MetalinkError::ParseFailed {
                reason: err.to_string(),
            })?;
            validate_xml10_chars(&v)?;
            out.push((prefix.to_vec(), v.into_owned().into_bytes()));
        }
    }
    Ok(out)
}

/// Resolve prefix → namespace URI (nearest binding wins, stack top first).
/// No prefix takes the default binding; unbound = None.
fn resolve_ns(ns: &NsStack, prefix: &[u8], depth: usize) -> Option<String> {
    for (bind_depth, bindings) in ns.iter().rev() {
        if *bind_depth > depth {
            continue;
        }
        for (p, uri) in bindings.iter().rev() {
            if p == prefix {
                return Some(String::from_utf8_lossy(uri).into_owned());
            }
        }
    }
    None
}

/// Raw name → (prefix, local name), at the byte level; the UTF-8 form of
/// an XML Name guarantees both sides of the `:` split are valid UTF-8
/// slices. Since 0.42 the `QName` inner value is `&str`; the byte cut
/// lives here.
fn split_name(name: QName<'_>) -> (&[u8], &[u8]) {
    let raw: &[u8] = name.0.as_bytes();
    match raw.iter().position(|&b| b == b':') {
        Some(i) => (&raw[..i], &raw[i + 1..]),
        None => (&raw[..0], raw),
    }
}

/// Trim XML whitespace (space/tab/CR/LF only — not Unicode whitespace; see
/// the crate's RFC deviation note).
fn trim_xml_ws(s: &mut String) {
    let trimmed = s.trim_matches([' ', '\t', '\r', '\n']);
    if trimmed.len() != s.len() {
        *s = trimmed.to_string();
    }
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// Diagnostic truncation (error/warning context never carries whole
/// document content).
fn short(s: &str) -> String {
    s.chars().take(48).collect()
}

// ---- Unit tests (parsing discipline + aria2 parity) -----------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MAX_DOCUMENT_BYTES;

    fn ok(doc: &[u8]) -> Metalink {
        match parse(doc) {
            Ok(d) => d,
            Err(e) => panic!("parse must succeed: {e}"),
        }
    }

    fn err(doc: &[u8]) -> MetalinkError {
        match parse(doc) {
            Ok(_) => panic!("parse must fail"),
            Err(e) => e,
        }
    }

    const V4: &str = "urn:ietf:params:xml:ns:metalink";

    fn wrap_file(inner: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="{V4}"><file name="a.iso">{inner}</file></metalink>"#
        )
    }

    #[test]
    fn prefixed_namespace_and_default_ns() {
        // Prefixed form (RFC: the prefix is arbitrary; the namespace URI is
        // the identity).
        let doc = ok(
            br#"<?xml version="1.0"?>
<m:metalink xmlns:m="urn:ietf:params:xml:ns:metalink"><m:file name="a.iso"><m:size>1</m:size><m:url>http://a/</m:url></m:file></m:metalink>"#,
        );
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].size, Some(1));
        assert_eq!(doc.files[0].urls.len(), 1);
    }

    #[test]
    fn foreign_namespace_children_skipped() {
        // Foreign-namespace children: silently skipped, never pollute the
        // manifest (RFC §5.3/§14.8).
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><ext:foo xmlns:ext="urn:x">junk</ext:foo><size>7</size></file></metalink>"#,
        );
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].size, Some(7));
        assert!(doc.warnings.is_empty());
    }

    #[test]
    fn doctype_rejected() {
        // XXE surface: DOCTYPE is rejected outright — entity expansion and
        // external DTDs have no path.
        let e = err(
            br#"<?xml version="1.0"?><!DOCTYPE metalink [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><url>&xxe;</url></file></metalink>"#,
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
    }

    #[test]
    fn undefined_entity_rejected() {
        let e = err(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><url>http://a/?x=&undefined;</url></file></metalink>"#,
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
    }

    #[test]
    fn predefined_entities_and_char_refs() {
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a&amp;b.iso"><url>http://a/?x=1&amp;y=2&#38;z=3</url></file></metalink>"#,
        );
        assert_eq!(doc.files[0].name, "a&b.iso");
        assert_eq!(doc.files[0].urls[0].uri, "http://a/?x=1&y=2&z=3");
    }

    #[test]
    fn latin1_charset_declaration_honored() {
        // Charset declaration honored: ISO-8859-1 value decoding (the label
        // sits on the ASCII-compatible surface).
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><metalink xmlns=\"urn:ietf:params:xml:ns:metalink\"><file name=\"caf\xe9.iso\"><size>1</size></file></metalink>";
        let doc = ok(latin1);
        assert_eq!(doc.files[0].name, "café.iso");
    }

    #[test]
    fn utf16_rejected_explicitly() {
        // UTF-16 (quick-xml does not transcode names): explicitly rejected,
        // no silent misreading.
        let mut le: Vec<u8> = vec![0xFF, 0xFE];
        let body: Vec<u8> = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><metalink xmlns=\"urn:ietf:params:xml:ns:metalink\"><file name=\"e.iso\"><size>5</size></file></metalink>"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        le.extend_from_slice(&body);
        assert!(matches!(err(&le), MetalinkError::ParseFailed { .. }));
    }

    #[test]
    fn document_size_cap_enforced() {
        let big = vec![b'x'; MAX_DOCUMENT_BYTES + 1];
        match err(&big) {
            MetalinkError::DocumentTooLarge { len, limit } => {
                assert_eq!(len, MAX_DOCUMENT_BYTES + 1);
                assert_eq!(limit, MAX_DOCUMENT_BYTES);
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn url_cap_per_file_enforced() {
        let mut doc = String::from(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso">"#,
        );
        for i in 0..=MAX_URLS_PER_FILE {
            doc.push_str(&format!("<url>http://m/{i}</url>"));
        }
        doc.push_str("</file></metalink>");
        match err(doc.as_bytes()) {
            MetalinkError::TooManyUrls { file, count, limit } => {
                assert_eq!(file, "a.iso");
                assert_eq!(count, MAX_URLS_PER_FILE + 1);
                assert_eq!(limit, MAX_URLS_PER_FILE);
            }
            other => panic!("wrong error: {other}"),
        }
        // Exactly 64 entries = legal.
        let mut doc = String::from(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso">"#,
        );
        for i in 0..MAX_URLS_PER_FILE {
            doc.push_str(&format!("<url>http://m/{i}</url>"));
        }
        doc.push_str("</file></metalink>");
        assert_eq!(ok(doc.as_bytes()).files[0].urls.len(), MAX_URLS_PER_FILE);
    }

    #[test]
    fn file_cap_enforced() {
        let mut doc = String::from(r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">"#);
        for i in 0..=MAX_FILES {
            doc.push_str(&format!(r#"<file name="f{i}.iso"><size>1</size></file>"#));
        }
        doc.push_str("</metalink>");
        match err(doc.as_bytes()) {
            MetalinkError::TooManyFiles { count, limit } => {
                assert_eq!(count, MAX_FILES + 1);
                assert_eq!(limit, MAX_FILES);
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn depth_cap_enforced() {
        let mut doc = String::from(r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">"#);
        for _ in 0..=MAX_DEPTH {
            doc.push_str("<file name=\"x\"><f>");
        }
        doc.push_str("</metalink>");
        match err(doc.as_bytes()) {
            MetalinkError::ParseFailed { reason } => {
                assert!(reason.contains("depth"), "{reason}");
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn structural_errors() {
        // Not a metalink root.
        assert!(matches!(
            err(br#"<notmetalink xmlns="urn:ietf:params:xml:ns:metalink"/>"#),
            MetalinkError::ParseFailed { .. }
        ));
        // No-namespace root (aria2 skips → empty; here an explicit
        // ParseFailed).
        assert!(matches!(
            err(br#"<metalink><file name="a.iso"/></metalink>"#),
            MetalinkError::ParseFailed { .. }
        ));
        // Zero file entries.
        assert!(matches!(
            err(br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><generator>g</generator></metalink>"#),
            MetalinkError::ParseFailed { .. }
        ));
        // Empty/garbage byte stream.
        assert!(matches!(err(b""), MetalinkError::ParseFailed { .. }));
        assert!(matches!(
            err(b"\x00\x01\x02"),
            MetalinkError::ParseFailed { .. }
        ));
        // Malformed nesting.
        assert!(matches!(
            err(br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><size>1</file></metalink>"#),
            MetalinkError::ParseFailed { .. }
        ));
    }

    #[test]
    fn v3_signals_downgrade() {
        // version attribute only (no v3 namespace).
        assert!(matches!(
            err(br#"<metalink version="3.0" xmlns="urn:ietf:params:xml:ns:metalink"/>"#),
            MetalinkError::UnsupportedVersion { .. }
        ));
        // v3 namespace only.
        assert!(matches!(
            err(br#"<metalink xmlns="http://www.metalinker.org/"><files><file name="a.iso"><resources><url type="http">http://a/</url></resources></file></files></metalink>"#),
            MetalinkError::UnsupportedVersion { .. }
        ));
    }

    #[test]
    fn aria2_parity_bad_size_drops_entry() {
        // aria2: malformed size → cancelEntryTransaction (whole entry
        // dropped) + logError; that entry's url results are discarded with
        // the doomed frame; good entries are unaffected.
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><size>12x</size><url>http://a/</url></file><file name="b.iso"><size>7</size></file></metalink>"#,
        );
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].name, "b.iso");
        assert_eq!(doc.warnings.len(), 1);
        assert_eq!(doc.warnings[0].kind, WarningKind::BadSize);
        // All entries dropped = the zero-entry hard error (aria2 consumer
        // side, same rule).
        assert!(matches!(
            err(
                br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><size>12x</size></file></metalink>"#
            ),
            MetalinkError::ParseFailed { .. }
        ));
    }

    #[test]
    fn aria2_parity_priority_default_and_bad() {
        // Default = 999999 (aria2 MetalinkResource.h).
        let doc = ok(wrap_file("<url>http://a/</url>").as_bytes());
        assert_eq!(doc.files[0].urls[0].priority, DEFAULT_PRIORITY);
        // Malformed/out of range → that url dropped + warning.
        let doc = ok(wrap_file("<url priority=\"0\">http://a/</url><url priority=\"abc\">http://b/</url><url priority=\"1000000\">http://c/</url><url priority=\"5\">http://good/</url>").as_bytes());
        assert_eq!(doc.files[0].urls.len(), 1);
        assert_eq!(doc.files[0].urls[0].uri, "http://good/");
        assert_eq!(doc.warnings.len(), 3);
        assert!(
            doc.warnings
                .iter()
                .all(|w| w.kind == WarningKind::BadUrlPriority)
        );
    }

    #[test]
    fn aria2_parity_bad_name_and_metaurl() {
        // Traversal name → file dropped (same rule as aria2 util.cc).
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="../evil.iso"><url>http://a/</url></file><file name="ok.iso"><size>1</size></file></metalink>"#,
        );
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].name, "ok.iso");
        assert_eq!(doc.warnings.len(), 1);
        assert_eq!(doc.warnings[0].kind, WarningKind::BadFileName);

        // metaurl: missing mediatype / traversal name → that metaurl
        // dropped.
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><metaurl>http://t/</metaurl><metaurl mediatype="torrent" name="../e">http://t/</metaurl><metaurl mediatype="torrent">http://good.torrent</metaurl></file></metalink>"#,
        );
        assert_eq!(doc.files[0].metaurls.len(), 1);
        assert_eq!(doc.files[0].metaurls[0].uri, "http://good.torrent");
        assert_eq!(doc.warnings.len(), 2);
    }

    #[test]
    fn aria2_parity_hash_and_pieces_softness() {
        // hash@type missing → drop; known type with wrong length → drop;
        // unknown type kept.
        let doc = ok(wrap_file(
            "<hash>da39a3ee5e6b4b0d3255bfef95601890afd80709</hash><hash type=\"sha-256\">beef</hash><hash type=\"sha3-512\">cafe</hash><hash type=\"sha-256\">deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef</hash>",
        ).as_bytes());
        let f = &doc.files[0];
        assert_eq!(f.hashes.len(), 2);
        assert_eq!(f.hashes[0].kind(), &HashKind::Other("sha3-512".to_string()));
        assert_eq!(f.hashes[0].hex(), "cafe");
        assert_eq!(f.hashes[1].kind(), &HashKind::Sha256);
        // warnings: 1 MissingHashType + 1 BadHashHex.
        assert_eq!(
            doc.warnings
                .iter()
                .filter(|w| w.kind == WarningKind::MissingHashType)
                .count(),
            1
        );
        assert_eq!(
            doc.warnings
                .iter()
                .filter(|w| w.kind == WarningKind::BadHashHex)
                .count(),
            1
        );

        // pieces: missing length → group dropped; empty hash group →
        // dropped.
        let doc = ok(wrap_file(
            "<pieces type=\"sha-1\"><hash>aa</hash></pieces><pieces length=\"16\" type=\"sha-1\"></pieces><pieces length=\"16\" type=\"sha-1\"><hash>0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33</hash></pieces>",
        ).as_bytes());
        let f = &doc.files[0];
        assert_eq!(f.pieces.len(), 1);
        assert_eq!(f.pieces[0].piece_length, 16);
        assert_eq!(f.pieces[0].hashes.len(), 1);
        assert_eq!(
            doc.warnings
                .iter()
                .filter(|w| w.kind == WarningKind::BadPieces)
                .count(),
            2
        );
    }

    #[test]
    fn signature_and_origin_and_generator() {
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink" ><generator>t</generator><origin dynamic="true">http://o/</origin><file name="a.iso"><size>+42</size><signature mediatype="application/pgp-signature">sig</signature></file></metalink>"#,
        );
        assert_eq!(doc.generator.as_deref(), Some("t"));
        let origin = doc.origin.as_ref().unwrap_or_else(|| panic!("origin"));
        assert_eq!(origin.uri, "http://o/");
        assert_eq!(origin.dynamic, Some(true));
        // xs:nonNegativeInteger leading +.
        assert_eq!(doc.files[0].size, Some(42));
        let sig = doc.files[0]
            .signature
            .as_ref()
            .unwrap_or_else(|| panic!("sig"));
        assert_eq!(sig.body, "sig");
    }

    #[test]
    fn multiple_singleton_elements_last_wins() {
        let doc = ok(wrap_file(
            "<size>1</size><size>2</size><version>1</version><version>2</version>",
        )
        .as_bytes());
        assert_eq!(doc.files[0].size, Some(2));
        assert_eq!(doc.files[0].version.as_deref(), Some("2"));
    }

    #[test]
    fn self_closing_and_whitespace_text() {
        // <url/> empty element → EmptyUrl soft drop (aria2 commits the empty
        // URL and filters on the consumer side; the data surface drops it and
        // warns); other urls unaffected.
        let doc = ok(wrap_file(
            "<url location=\"de\"/><url location=\"fr\" priority=\"2\">  http://a/  </url>",
        )
        .as_bytes());
        assert_eq!(doc.files[0].urls.len(), 1);
        assert_eq!(doc.files[0].urls[0].uri, "http://a/");
        assert_eq!(doc.files[0].urls[0].location.as_deref(), Some("fr"));
        assert_eq!(doc.files[0].urls[0].priority, 2);
        assert_eq!(
            doc.warnings
                .iter()
                .filter(|w| w.kind == WarningKind::EmptyUrl)
                .count(),
            1
        );
    }

    #[test]
    fn cdata_content_is_literal() {
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><url><![CDATA[http://a/?x=&notanentity;]]></url></file></metalink>"#,
        );
        // & inside CDATA is not entity-expanded.
        assert_eq!(doc.files[0].urls[0].uri, "http://a/?x=&notanentity;");
    }

    #[test]
    fn crlf_and_pretty_printed_urls() {
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso">
        <url>
            http://a/path
        </url>
</file></metalink>"#,
        );
        // CRLF normalization + leading/trailing XML whitespace trim.
        assert_eq!(doc.files[0].urls[0].uri, "http://a/path");
    }

    // ---- Strictness batch (expat namespace handling + Char validation
    // parity) ----

    #[test]
    fn unbound_prefix_elements_are_not_local_name_matches() {
        // `<p:file>` with an unbound prefix was previously accepted by local
        // name. Reference behavior (expat namespace processing +
        // MetalinkParserStateV4Impl.cc double match): unbound-prefix
        // elements take no part in manifest semantics — this surface skips
        // the subtree as a foreign element (expat makes unbound prefixes a
        // hard error; skipping yields the same "no entry produced", the
        // only difference being error vs soft drop). The only entry skipped
        // = the zero-entry hard error.
        let e = err(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><p:file name="a.iso"><size>1</size><url>http://a/</url></p:file></metalink>"#,
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
        // Good entries are unaffected by the skip region.
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><p:file name="a.iso"><size>1</size></p:file><file name="b.iso"><size>2</size></file></metalink>"#,
        );
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].name, "b.iso");
    }

    #[test]
    fn unprefixed_children_under_prefixed_root_are_not_metalink_elements() {
        // Prefixed root + unprefixed children: the children have no default
        // binding = no namespace (XML Namespaces); reference skipTag, same
        // rule → all entries dropped (previously admitted by local name) →
        // zero-entry hard error.
        let e = err(
            br#"<m:metalink xmlns:m="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><size>1</size><url>http://a/</url></file></m:metalink>"#,
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
    }

    #[test]
    fn foreign_namespaced_same_name_elements_and_attrs_do_not_shadow() {
        // Foreign-namespace same-name elements/attributes do not shadow:
        // f:name does not replace file@name, f:size does not replace size
        // (the element surface previously admitted by local name).
        let doc = ok(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file xmlns:f="urn:y" f:name="../evil.iso" name="good.iso"><f:size>99</f:size><size>7</size><url>http://a/</url></file></metalink>"#,
        );
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].name, "good.iso");
        assert_eq!(
            doc.files[0].size,
            Some(7),
            "foreign f:size must not shadow size"
        );
        assert!(doc.warnings.is_empty());
    }

    #[test]
    fn attributes_in_v4_namespace_match_reference_findattr() {
        // Reference findAttr (MetalinkParserStateImpl.cc): local name +
        // namespace double match, and "no namespace (unprefixed attribute)"
        // always matches — a prefix bound to the v4 namespace matches too.
        let doc = ok(
            br#"<m:metalink xmlns:m="urn:ietf:params:xml:ns:metalink"><m:file m:name="a.iso"><m:size>3</m:size><m:url m:priority="2">http://a/</m:url></m:file></m:metalink>"#,
        );
        assert_eq!(doc.files[0].name, "a.iso");
        assert_eq!(doc.files[0].size, Some(3));
        assert_eq!(doc.files[0].urls[0].priority, 2);
    }

    #[test]
    fn self_closing_root_registers_and_post_root_content_rejected() {
        // `<metalink/>` followed by a full second document was previously
        // accepted wholesale (saw_root lacked an Empty branch). A
        // self-closing root registers, and element events after the root
        // closes are rejected.
        let e = err(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"/><metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><size>1</size></file></metalink>"#,
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
        // Elements outside a non-self-closing root are likewise rejected.
        let e = err(
            br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><size>1</size></file></metalink><extra/>"#,
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
        // Self-closing zero-entry root: classified as the "zero file
        // entries" hard error (the root did register).
        assert!(matches!(
            err(br#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"/>"#),
            MetalinkError::ParseFailed { .. }
        ));
    }

    #[test]
    fn trailing_misc_after_root_is_allowed() {
        // Misc after the root (whitespace text/comments/PIs) is allowed —
        // the common pretty-printed trailing newline is unaffected.
        let doc = ok(
            b"<metalink xmlns=\"urn:ietf:params:xml:ns:metalink\"><file name=\"a.iso\"><size>1</size></file></metalink>\n<!-- tail --><?pi x?>  ",
        );
        assert_eq!(doc.files.len(), 1);
    }

    #[test]
    fn raw_control_characters_are_rejected() {
        // A raw \x01 inside url.uri previously parsed successfully. Bare
        // control characters outside the XML 1.0 Char production (except
        // Tab/LF/CR) are hard malformed errors.
        let e = err(
            b"<metalink xmlns=\"urn:ietf:params:xml:ns:metalink\"><file name=\"a.iso\"><url>http://a/\x01</url></file></metalink>",
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
        // Attribute values too (a control character in a file name is
        // rejected at the decode point, not via the doom path).
        let e = err(
            b"<metalink xmlns=\"urn:ietf:params:xml:ns:metalink\"><file name=\"a\x02.iso\"><size>1</size></file></metalink>",
        );
        assert!(matches!(e, MetalinkError::ParseFailed { .. }), "{e}");
    }

    #[test]
    fn text_normalization_is_xml10_not_xml11() {
        // quick-xml's xml_content alias = XML 1.1 normalization (U+0085/
        // U+2028 folded to line breaks); this surface pins xml10_content —
        // U+2028 is preserved verbatim (XML 1.0 line ends are only
        // CR/LF/CRLF).
        let doc = ok(
            format!(
                r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso"><url>http://a/{}x</url></file></metalink>"#,
                '\u{2028}'
            )
            .as_bytes(),
        );
        assert_eq!(doc.files[0].urls[0].uri, "http://a/\u{2028}x");
    }

    #[test]
    fn iso8859_1_decodes_via_whatwg_windows1252_mapping() {
        // Registered deviation (crate docs): encoding_rs maps the
        // ISO-8859-1 label to windows-1252 (WHATWG) — 0x85 decodes to
        // U+2026 instead of the C1 U+0085 (strict Latin-1 decoding would
        // yield an XML 1.0-illegal character; this deviation is in the
        // lenient direction, pinned against regressions).
        let mut doc_bytes = Vec::new();
        doc_bytes.extend_from_slice(
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><metalink xmlns=\"urn:ietf:params:xml:ns:metalink\"><file name=\"a.iso\"><description>caf\x85</description></file></metalink>",
        );
        let doc = ok(&doc_bytes);
        assert_eq!(
            doc.files[0].description.as_deref(),
            Some("caf\u{2026}"),
            "0x85 must decode via the WHATWG windows-1252 mapping"
        );
    }

    #[test]
    fn metaurl_cap_per_file_enforced() {
        let mut doc = String::from(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso">"#,
        );
        for i in 0..=MAX_METAURLS_PER_FILE {
            doc.push_str(&format!(
                r#"<metaurl mediatype="torrent">http://t/{i}</metaurl>"#
            ));
        }
        doc.push_str("</file></metalink>");
        match err(doc.as_bytes()) {
            MetalinkError::TooManyMetaurls { file, count, limit } => {
                assert_eq!(file, "a.iso");
                assert_eq!(count, MAX_METAURLS_PER_FILE + 1);
                assert_eq!(limit, MAX_METAURLS_PER_FILE);
            }
            other => panic!("wrong error: {other}"),
        }
        // Exactly 64 entries = legal (the parse-amplification surface of
        // mass duplicate entries closes at the cap).
        let mut doc = String::from(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file name="a.iso">"#,
        );
        for i in 0..MAX_METAURLS_PER_FILE {
            doc.push_str(&format!(
                r#"<metaurl mediatype="torrent">http://t/{i}</metaurl>"#
            ));
        }
        doc.push_str("</file></metalink>");
        assert_eq!(
            ok(doc.as_bytes()).files[0].metaurls.len(),
            MAX_METAURLS_PER_FILE
        );
    }

    #[test]
    fn publisher_name_and_url_are_consumed() {
        // RFC 5854 §3.1.3: name required, url optional; the element enters
        // the model (previously a dead field — silently skipped, always
        // None).
        let doc =
            ok(wrap_file("<size>1</size><publisher name=\"Exa\" url=\"http://p/\"/>").as_bytes());
        let publisher = doc.files[0]
            .publisher
            .as_ref()
            .unwrap_or_else(|| panic!("publisher must be consumed"));
        assert_eq!(publisher.name, "Exa");
        assert_eq!(publisher.url.as_deref(), Some("http://p/"));
        assert_eq!(doc.files[0].size, Some(1));

        // Missing name = drop + warning (BadPublisher).
        let doc = ok(wrap_file("<publisher url=\"http://p/\"></publisher>").as_bytes());
        assert!(doc.files[0].publisher.is_none());
        assert_eq!(doc.warnings.len(), 1);
        assert_eq!(doc.warnings[0].kind, WarningKind::BadPublisher);

        // Children are swallowed by the Skip frame (the RFC defines no child
        // elements — a nested size produces nothing).
        let doc = ok(
            wrap_file("<publisher name=\"P\"><size>9</size></publisher><size>1</size>").as_bytes(),
        );
        let publisher = doc.files[0]
            .publisher
            .as_ref()
            .unwrap_or_else(|| panic!("publisher with children"));
        assert_eq!(publisher.name, "P");
        assert_eq!(doc.files[0].size, Some(1), "nested size must be swallowed");
    }
}
