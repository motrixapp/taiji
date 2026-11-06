//! Executable adjudication table for metalink v3: v4 is the supported
//! format; v3 documents are rejected explicitly with
//! `taiji.metalink.unsupported_version` (the default branch; the decision
//! notes live in docs/design/metalink.md).
//!
//! Each entry of [`V3_FIXTURE_FORMS`] is a real v3 document (sourced from
//! the upstream aria2 `test/` directory, read-only) plus the v3-specific
//! trait it exhibits — 15 distinct semantic forms. Every form must parse
//! to [`MetalinkError::UnsupportedVersion`] with the correct version
//! signal. Malformed-XML forms (testMalformedXML/testMalformedXML2) are
//! version-independent well-formedness negatives and are not counted as
//! v3-specific. If v3 support ever lands, this suite going red is the
//! reminder to flip the downgrade conclusion.

use taiji_metalink::{MetalinkError, parse};

/// v3-only fixture form inventory (the executable reference table):
/// (reference source, v3-specific trait, document). Sources are files in
/// the upstream aria2 `test/` checkout or `MetalinkProcessorTest` case
/// names (read-only reference).
const V3_FIXTURE_FORMS: &[(&str, &str, &str)] = &[
    (
        "test/2files.metalink",
        "files>file>resources>url@type wrapper structure + publisher/description document face",
        r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/">
  <publisher><name>aria2</name><url>http://aria2.sourceforge.net/</url></publisher>
  <description>The high speed download utility</description>
  <files>
    <file name="aria2-5.0.0.tar.bz2"><resources><url type="http">http://localhost/a.tar.bz2</url></resources></file>
  </files>
</metalink>"#,
    ),
    (
        "test/metalink3-dirtraversal.xml",
        "verification>signature@type/@file + traversal-name entry",
        r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/">
  <files>
    <file name="../aria2-0.5.2.tar.bz2">
      <verification><signature type="pgp" file="a.sig">SIG</signature></verification>
      <resources><url type="http">http://example.org/a</url></resources>
    </file>
  </files>
</metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testParseFile（test/test.xml）",
        "all elements: size/version/language/os + verification{hash@type,pieces>hash@piece,\
         signature@type/@file} + resources@maxconnections + url@{type,location,preference,maxconnections}",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/">
  <files>
    <file name="aria2-0.5.2.tar.bz2">
      <size>345689</size><version>0.5.2</version><language>en-US</language><os>Linux-x86</os>
      <verification>
        <hash type="sha1">a96cf3f0266b91d87d5124cf94326422800b627d</hash>
        <pieces length="262144" type="sha1"><hash piece="0">44213f9f4d59b557314fadcd233232eebcac8012</hash></pieces>
        <signature type="pgp" file="a.sig">SIG</signature>
      </verification>
      <resources maxconnections="1">
        <url type="ftp" location="jp" preference="1" maxconnections="1">ftp://ftphost/a</url>
        <url type="http" location="us" preference="1">http://httphost/a</url>
      </resources>
    </file>
  </files>
</metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testBadSize",
        "size=abc -> entry kept (length=0) — a v3-specific softening \
         (v4 drops the entry on the same shape)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="a.tar.bz2"><size>abc</size><version>0.5.2</version></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testBadMaxConn",
        "resources@maxconnections malformed (v4 has no resources wrapper / no such attribute)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="a.tar.bz2"><size>43743838</size><resources maxconnections="abc"/></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testNoName",
        "nameless file entry dropped (name is the v3 required entry attribute)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file><size>1024</size></file>
  <file name="a.tar.bz2"><size>43743838</size></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testBadURLPrefs",
        "url@preference malformed -> lowest preference \
         (v4 names the same-domain attribute priority)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="a.tar.bz2"><size>43743838</size><resources>
    <url type="ftp" maxconnections="1" preference="xyz" location="jp">ftp://mirror/</url>
  </resources></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testBadURLMaxConn",
        "url@maxconnections malformed (per-URL connection hint, absent in v4)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="a.tar.bz2"><size>43743838</size><resources>
    <url maxconnections="xyz" type="ftp" preference="100" location="jp">ftp://mirror/</url>
  </resources></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testUnsupportedType",
        "url@type=magnet -> TYPE_NOT_SUPPORTED kept \
         (type carries a classification, v4 has no type)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="a.tar.bz2"><size>43743838</size><resources>
    <url type="ftp">ftp://mirror/</url>
    <url type="magnet">magnet:xt=XYZ</url>
    <url type="http">http://mirror/</url>
  </resources></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testMultiplePieces",
        "multiple pieces groups, best chosen \
         (sha1 over md5 — consumer-side policy, v3 group form)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="aria2.tar.bz2"><verification>
    <pieces length="1024" type="sha1"></pieces>
    <pieces length="512" type="md5"></pieces>
  </verification></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testBadPieceNo",
        "pieces>hash@piece ordinal attribute (v4 pieces>hash has no attributes)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="aria2.tar.bz2"><verification>
    <pieces length="512" type="sha1">
      <hash piece="0">44213f9f4d59b557314fadcd233232eebcac8012</hash>
      <hash piece="xyz">44213f9f4d59b557314fadcd233232eebcac8012</hash>
    </pieces>
  </verification></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testBadPieceLength",
        "pieces@length malformed -> group dropped + fallback to the alternate group",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="aria2.tar.bz2"><verification>
    <pieces length="xyz" type="sha1"><hash piece="0">44213f9f4d59b557314fadcd233232eebcac8012</hash></pieces>
    <pieces length="1024" type="sha1"><hash piece="0">44213f9f4d59b557314fadcd233232eebcac8012</hash></pieces>
  </verification></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testUnsupportedType_piece",
        "pieces@type unknown -> group skipped",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="aria2.tar.bz2"><verification>
    <pieces length="512" type="ARIA2"><hash piece="0">44213f9f4d59b557314fadcd233232eebcac8012</hash></pieces>
    <pieces length="1024" type="sha1"><hash piece="0">44213f9f4d59b557314fadcd233232eebcac8012</hash></pieces>
  </verification></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testLargeFileSize",
        "size = i64::MAX upper bound (v3 size domain face)",
        r#"<metalink version="3.0" xmlns="http://www.metalinker.org/"><files>
  <file name="dvd.iso"><size>9223372036854775807</size>
    <resources><url type="http">http://mirror/</url></resources></file>
</files></metalink>"#,
    ),
    (
        "MetalinkProcessorTest::testXmlPrefixV3",
        "prefixed namespace form (m: bound to metalinker.org)",
        r#"<m:metalink version="3.0" xmlns:m="http://www.metalinker.org/">
  <m:files><m:file name="dvd.iso">
    <m:size>9223372036854775807</m:size>
    <m:resources><m:url type="http">http://mirror/</m:url></m:resources>
  </m:file></m:files>
</m:metalink>"#,
    ),
];

/// Pins the inventory measurement the downgrade decision rests on: the
/// count and the threshold are asserted together, so growing the table
/// still has to clear the threshold for the downgrade conclusion to stay
/// coherent, and revisiting the decision starts from this assertion.
#[test]
fn v3_fixture_inventory_exceeds_the_do_threshold() {
    assert_eq!(
        V3_FIXTURE_FORMS.len(),
        15,
        "inventory count change = measurement baseline change: \
         sync the decision conclusion and the delta declaration"
    );
    assert!(
        V3_FIXTURE_FORMS.len() > 10,
        "criterion one (fixtures <= 10) not satisfied — \
         the measurement premise of the downgrade conclusion"
    );
}

/// Pins the conclusion: all 15 v3 forms are rejected with
/// UnsupportedVersion. The version signal follows detection order: a
/// `version="3.0"` attribute present in the document is reported verbatim
/// (reference fixtures generally carry it); otherwise the v3 namespace
/// URI is reported. Error-code mapping lives in taiji-rpc
/// (`taiji.metalink.unsupported_version`).
#[test]
fn every_v3_form_declines_with_unsupported_version() {
    for (origin, trait_, doc) in V3_FIXTURE_FORMS {
        let err = match parse(doc.as_bytes()) {
            Err(e) => e,
            Ok(_) => panic!("{origin}: v3 document must not parse"),
        };
        match err {
            MetalinkError::UnsupportedVersion { found } => {
                assert!(
                    found == "3.0" || found == taiji_metalink::METALINK3_NS,
                    "{origin}: version signal must be the attribute or the \
                     v3 namespace ({trait_}), got {found:?}"
                );
            }
            other => panic!("{origin}: expected UnsupportedVersion, got {other}"),
        }
    }
}

/// The other half of the downgrade path: the version attribute alone (a
/// document without the v3 namespace — `version="3.0"` stands on its own)
/// is also rejected explicitly (the parser unit tests cover both signals;
/// this pins that either signal alone downgrades, complementing the
/// namespace forms in the inventory table).
#[test]
fn version_attribute_alone_is_a_downgrade_signal() {
    let doc = r#"<metalink version="3.0" xmlns="urn:ietf:params:xml:ns:metalink"/>"#;
    match parse(doc.as_bytes()) {
        Err(MetalinkError::UnsupportedVersion { found }) => {
            assert_eq!(found, "3.0", "attribute signal is reported verbatim");
        }
        other => panic!("attribute-only v3 signal must decline: {other:?}"),
    }
}
