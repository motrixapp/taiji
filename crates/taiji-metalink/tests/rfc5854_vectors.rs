//! RFC 5854 / aria2 ecosystem vector tests (fixture sources noted per
//! test; reference = the upstream aria2 read-only `test/` directory
//! vectors + the RFC 5854 §1.1 sample documents).

use taiji_metalink::{DEFAULT_PRIORITY, HashKind, METALINK3_NS, MetalinkError, WarningKind, parse};

/// Fixture bytes embedded at compile time (the repo-wide convention —
/// cf. the `taiji-io` mse vectors and the `taiji-http` CA mocks). A
/// runtime `fs::read` against `CARGO_MANIFEST_DIR` is not hermetic: a
/// binary built from another checkout keeps the baked path and ENOENTs
/// on every fixture; `include_bytes!` pins the bytes to the source.
fn fixture(name: &str) -> &'static [u8] {
    match name {
        "rfc5854_brief.metalink" => include_bytes!("fixtures/rfc5854_brief.metalink"),
        "rfc5854_twofiles.metalink" => include_bytes!("fixtures/rfc5854_twofiles.metalink"),
        "aria2_metalink4.xml" => include_bytes!("fixtures/aria2_metalink4.xml"),
        "aria2_2files_v3.metalink" => include_bytes!("fixtures/aria2_2files_v3.metalink"),
        "aria2_metalink4_groupbymetaurl.xml" => {
            include_bytes!("fixtures/aria2_metalink4_groupbymetaurl.xml")
        }
        "aria2_metalink4_dosdirtraversal.xml" => {
            include_bytes!("fixtures/aria2_metalink4_dosdirtraversal.xml")
        }
        other => panic!("unknown fixture {other}"),
    }
}

fn must_parse(name: &str) -> taiji_metalink::Metalink {
    match parse(fixture(name)) {
        Ok(doc) => doc,
        Err(e) => panic!("parse {name} must succeed, got {e}"),
    }
}

fn warnings_of(doc: &taiji_metalink::Metalink, kind: WarningKind) -> usize {
    doc.warnings.iter().filter(|w| w.kind == kind).count()
}

/// RFC 5854 §1.1 brief example (single file + a metaurl with indented
/// content — the concrete vector for the text-trimming semantics: the
/// RFC's own sample carries leading/trailing whitespace).
#[test]
fn rfc5854_brief_example() {
    let doc = must_parse("rfc5854_brief.metalink");
    assert_eq!(doc.files.len(), 1);
    let f = &doc.files[0];
    assert_eq!(f.name, "example.ext");
    assert_eq!(f.size, Some(14_471_447));
    assert_eq!(
        f.urls.iter().map(|u| u.uri.as_str()).collect::<Vec<_>>(),
        vec![
            "ftp://ftp.example.com/example.ext",
            "http://example.com/example.ext"
        ]
    );
    // url has no priority attribute → the aria2 default (MetalinkResource.h).
    assert!(f.urls.iter().all(|u| u.priority == DEFAULT_PRIORITY));
    // metaurl content has indented line breaks → trimmed to the bare IRI.
    assert_eq!(f.metaurls.len(), 1);
    assert_eq!(f.metaurls[0].uri, "http://example.com/example.ext.torrent");
    assert_eq!(f.metaurls[0].mediatype, "torrent");
    assert!(doc.warnings.is_empty());
}

/// RFC 5854 §1.1 two-file example (published timestamp / identity /
/// version / language / description / sha-256 / the hash family). The
/// RFC text truncates the hashes with "..."; real digests
/// (sha-256("taiji metalink RFC 5854 vector file N")) are substituted so
/// [`taiji_metalink::Hash::verify`] can close the loop.
#[test]
fn rfc5854_two_files_example() {
    let doc = must_parse("rfc5854_twofiles.metalink");
    assert_eq!(doc.files.len(), 2);
    assert_eq!(doc.published.as_deref(), Some("2009-05-15T12:23:23Z"));

    let (a, b) = (&doc.files[0], &doc.files[1]);
    assert_eq!(a.name, "example.ext");
    assert_eq!(a.identity.as_deref(), Some("Example"));
    assert_eq!(a.version.as_deref(), Some("1.0"));
    assert_eq!(a.languages, vec!["en"]);
    // description is multi-line text: edges trimmed, internal whitespace
    // kept.
    assert_eq!(
        a.description.as_deref(),
        Some("A description of the example file for download.")
    );
    assert_eq!(
        b.description.as_deref(),
        Some("Another description for a second file.")
    );

    // location/priority attribute parsing.
    assert_eq!(a.urls[0].location.as_deref(), Some("de"));
    assert_eq!(a.urls[0].priority, 1);
    assert_eq!(a.urls[1].location.as_deref(), Some("fr"));
    assert_eq!(a.metaurls[0].priority, 2);

    // sha-256 digest verification closed loop (content → digest → matches
    // the document claim).
    let hash = &a.hashes[0];
    assert_eq!(hash.kind(), &HashKind::Sha256);
    assert!(
        hash.verify(b"taiji metalink RFC 5854 vector file 1")
            .unwrap_or(false)
    );
    assert!(!hash.verify(b"other content").unwrap_or(false));
    let hash_b = &b.hashes[0];
    assert!(
        hash_b
            .verify(b"taiji metalink RFC 5854 vector file 2")
            .unwrap_or(false)
    );
    assert!(doc.warnings.is_empty());
}

/// Upstream aria2 `test/metalink4.xml` vector verbatim: md5/sha-1 dual
/// hashes, two pieces groups (sha-1/sha-256), a signature. Note: in this
/// vector the md5 is 31 hex chars ("cbd18db4..."; sha1("foo") is the legal
/// 40-char value) — the invalid entry is dropped with a warning per the
/// aria2 consumer rule; the sha-1 verifies against b"foo".
#[test]
fn aria2_metalink4_vector() {
    let doc = must_parse("aria2_metalink4.xml");
    assert_eq!(doc.files.len(), 1);
    let f = &doc.files[0];
    assert_eq!(f.name, "example.ext");
    assert_eq!(f.size, Some(786_430));
    assert_eq!(f.identity.as_deref(), Some("Example"));
    assert_eq!(f.version.as_deref(), Some("1.0"));
    assert_eq!(f.languages, vec!["en"]);
    assert_eq!(
        f.description.as_deref(),
        Some("A description of the example file for download.")
    );

    // 31-char md5 dropped; 40-char sha-1 kept.
    assert_eq!(warnings_of(&doc, WarningKind::BadHashHex), 1);
    assert_eq!(f.hashes.len(), 1);
    let sha1 = &f.hashes[0];
    assert_eq!(sha1.kind(), &HashKind::Sha1);
    assert_eq!(sha1.hex(), "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33");
    assert!(sha1.verify(b"foo").unwrap_or(false));

    // Both pieces groups kept in full (best-group selection is task-layer
    // policy; the data layer does not decide).
    assert_eq!(f.pieces.len(), 2);
    let p1 = &f.pieces[0];
    assert_eq!(p1.piece_length, 262_144);
    assert_eq!(p1.kind, HashKind::Sha1);
    assert_eq!(p1.hashes.len(), 3);
    let p2 = &f.pieces[1];
    assert_eq!(p2.kind, HashKind::Sha256);
    assert_eq!(p2.hashes.len(), 3);
    assert_eq!(
        p2.hashes[0],
        "0245178074fd042e19b7c3885b360fc21064b30e73f5626c7e3b005d048069c5"
    );

    // urls + metaurl + signature.
    assert_eq!(f.urls.len(), 2);
    assert_eq!(f.urls[0].location.as_deref(), Some("de"));
    assert_eq!(f.urls[0].priority, 1);
    assert_eq!(f.metaurls.len(), 1);
    assert_eq!(f.metaurls[0].priority, 2);
    let sig = f
        .signature
        .as_ref()
        .unwrap_or_else(|| panic!("signature must parse"));
    assert_eq!(sig.mediatype, "application/pgp-signature");
    assert_eq!(sig.body, "a signature");

    // published is document-level (this vector has no generator/origin).
    assert_eq!(doc.published.as_deref(), Some("2009-05-15T12:23:23Z"));
}

/// Upstream aria2 `test/2files.metalink` vector verbatim: a v3 document
/// (version="3.0" + the metalinker.org namespace) → explicit downgrade
/// error (the default branch). Either v3 signal (the version attribute or
/// the namespace) alone triggers the downgrade — this vector carries both.
#[test]
fn aria2_v3_document_downgrades_explicitly() {
    match parse(fixture("aria2_2files_v3.metalink")) {
        Err(MetalinkError::UnsupportedVersion { found }) => {
            assert!(
                found == "3.0" || found == METALINK3_NS,
                "v3 signal, got {found}"
            );
        }
        other => panic!("v3 must downgrade explicitly, got {other:?}"),
    }
}

/// Upstream aria2 `test/metalink4-groupbymetaurl.xml` vector verbatim:
/// multiple files + metaurl@name (the BT multi-file path-selection
/// surface).
#[test]
fn aria2_groupbymetaurl_vector() {
    let doc = must_parse("aria2_metalink4_groupbymetaurl.xml");
    assert_eq!(doc.files.len(), 3);
    let f1 = &doc.files[0];
    assert_eq!(f1.name, "file1");
    assert_eq!(f1.size, Some(1000));
    assert_eq!(f1.urls.len(), 1);
    assert_eq!(f1.metaurls.len(), 1);
    assert_eq!(f1.metaurls[0].name.as_deref(), Some("file1"));
    let f2 = &doc.files[1];
    // A file entry without a metaurl is unaffected by its neighbors.
    assert!(f2.metaurls.is_empty());
    assert_eq!(f2.urls.len(), 1);
}

/// Upstream aria2 `test/metalink4-dosdirtraversal.xml` vector verbatim:
/// backslash names are not traversal under POSIX semantics (aria2
/// detectDirTraversal, same rule — `\` is not detected), so the entries
/// are kept as-is; task-layer basename sanitization handles them
/// separately.
#[test]
fn aria2_dosdirtraversal_vector_backslash_names_kept() {
    let doc = must_parse("aria2_metalink4_dosdirtraversal.xml");
    assert_eq!(doc.files.len(), 3);
    assert_eq!(doc.files[0].name, "..\\..\\example.ext");
    assert_eq!(doc.files[1].name, "..\\..\\file1.ext");
    // metaurl@name = "d/file1.ext": a subdirectory shape, not traversal →
    // kept.
    assert_eq!(
        doc.files[1].metaurls[0].name.as_deref(),
        Some("d/file1.ext")
    );
    assert!(doc.warnings.is_empty());
}
