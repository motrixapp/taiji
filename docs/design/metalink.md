# Metalink design notes (RFC 5854)

Distilled design notes behind `crates/taiji-metalink` (RFC 5854 document
parsing, the mirror manifest model, checksum consumption). The behavioral
reference is upstream aria2, read-only (`MetalinkParserStateV4Impl.cc`,
`MetalinkParserController.cc`, `MetalinkParserStateImpl.cc`, util.cc,
`MetalinkResource.h`).

## Parsing surface discipline

- DTDs and entities are disabled. quick-xml never resolves external
  entities (no XXE surface); a `DOCTYPE` is rejected outright, undefined
  entity references are parse errors, and only the five predefined
  entities plus numeric character references expand. Custom/external
  entities have no resolution path, so entity-expansion bombs cannot
  occur.
- Parse limits, all hard errors: document <= 16MiB, `<file>` <= 10k, per
  file `<url>` <= 64 and `<metaurl>` <= 64, element depth <= 256. The
  metaurl cap mirrors the url cap; after dedup by URI the expansion
  yields at most one BT task per file, so the cap only closes the
  parse-amplification shape of mass duplicate entries.
- Events in quick-xml 0.42 are always UTF-8 str. UTF-16-like inputs
  (BOM or `<?` byte patterns) are explicitly rejected at the entry:
  0.42's `DecodingReader` would silently transcode UTF-16 and this parser
  does not use it (no silent misreading). UTF-32 has no detection pattern
  and is rejected structurally (NUL never matches a name). A non-UTF-8
  ASCII-compatible charset declaration (ISO-8859-1 etc.) triggers one
  full transcode + reparse at `Event::Decl` (first pass only, preventing
  recursion); the declaration segment is ASCII and transcodes identically
  under any ASCII-compatible encoding.
- Namespaces: elements match on (namespace URI, local name) — the aria2
  `isMetalink4Ns` + local-name double match. Elements with an unbound
  prefix, unprefixed children under a root with no default binding (XML
  Namespaces: no prefix = no namespace), and same-name elements in
  foreign namespaces are skipped with their whole subtree (aria2
  skipTag); a local-name match alone never admits them. Attributes match
  the same way (aria2 findAttr): local name + empty or v4 namespace —
  foreign same-name attributes do not shadow. `xmlns`/`xmlns:*` are
  declarations, never matched as attributes.
- Character surface: the quick-xml tokenizer does not validate character
  legality, so bare control characters (except Tab/LF/CR) outside the XML
  1.0 Char production are rejected uniformly at the text/attribute decode
  points (a raw `\x01` inside a url previously parsed successfully).
  Line-end normalization uses `xml10_content`, not quick-xml's
  `xml_content` alias, which is XML 1.1 normalization (U+0085/U+2028
  folded to line breaks) — deliberately avoided.
- Well-formedness rules enforced beyond the tokenizer: after the root
  element closes, any further element event is rejected (`<metalink/>`
  followed by a second complete document used to be accepted); only Misc
  (whitespace text/comments/PIs) may trail the root. Attribute values are
  unescaped without whitespace normalization (quick-xml `unescape`, not
  `normalized_value`, which would fold literal `\t\r\n` into spaces).

## Behavior mapping to aria2

Per-element semantics mirror the aria2 v4 parsing state machine: a
missing/out-of-range/malformed attribute drops that element (with a
`ParseWarning` matching the aria2 logError site) and parsing continues;
malformed `<size>` and a missing/empty/traversal file@name drop the whole
file entry (aria2 cancelEntryTransaction — the entry frame is marked
doomed, children are consumed normally but their results are discarded).
Document-level structural errors are hard errors: non-metalink root,
root without the v4 namespace, unbalanced elements, zero file entries.

The model is a fidelity superset of the aria2 consumption surface:
`identity`, `description`, `publisher` and other informational elements
(silently skipped by aria2 v4) are kept per RFC 5854, and all
`<hash>`/`<pieces>` groups are kept in full — aria2 picks one best group,
which is task-layer policy, not a data-layer decision.

Text values are trimmed of leading/trailing ASCII whitespace
(space/tab/CR/LF only, not Unicode whitespace): a pragmatic deviation
from RFC 5854 §2.4 "MUST NOT ignore whitespace" — the RFC's own §1.1
example carries indented metaurl content and ecosystem documents are
widely pretty-printed. Only the element content edges are trimmed.

## metalink v3 adjudication (downgrade)

metalink v3 documents — detected by the `http://www.metalinker.org/`
namespace (same text as aria2 `METALINK3_NAMESPACE_URI`) or a
`version="3.0"` attribute (RFC 5854 defines no version attribute, so its
presence is an external signal; either signal alone downgrades) — are
rejected explicitly with `MetalinkError::UnsupportedVersion`. The
attribute value is reported verbatim when present, otherwise the v3
namespace URI. Error-code mapping (`taiji.metalink.unsupported_version`)
belongs to the RPC layer.

`tests/v3_adjudication.rs` is the executable reference table for this
decision: 15 distinct v3-only fixture forms taken from the upstream aria2
`test/` directory (`2files.metalink`, `metalink3-dirtraversal.xml`, and
`MetalinkProcessorTest` cases), each asserting that the document parses
to `UnsupportedVersion` with the correct version signal. The inventory
count is pinned by assertion so any change to the table forces the
downgrade conclusion and the diff declaration to be revisited. Should v3
support ever land, this suite going red is the reminder to flip the
conclusion. v3-only traits covered by the table include the
files>file>resources>url@type wrapper structure, verification>
signature@type/@file, url@preference/maxconnections, pieces>hash@piece
indices, and v3's softer bad-size behavior (entry kept with length=0,
where v4 drops the entry).

## Registered deviation: ISO-8859-1 decodes via windows-1252

encoding_rs maps the `ISO-8859-1` label to windows-1252 (WHATWG, same as
the HTML standard), so 0x80-0x9F decode as Cp1252 printables (e.g. 0x85 →
U+2026 instead of C1 U+0085). Strict Latin-1 decoding would produce
XML 1.0-illegal characters in that range, so this deviation is in the
lenient (superset-accepting) direction; it is pinned in the parser tests
against regressions.
