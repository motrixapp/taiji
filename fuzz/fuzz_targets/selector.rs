#![no_main]

//! fuzz target: the three-layer media selector expression face
//! (the selector rides the RPC surface as
//! a raw client string, so the parser is a hostile-input face).
//! the DASH vectors — the escape hatch's value domain is the
//! DASH Representation `@id` (arbitrary attacker-influenced text from
//! a hostile MPD), so the derived tree alternates `hls`-kind (ordinal
//! ids) and `dash`-kind (rep-id) shapes.
//!
//! Invariants (the expression matrix runs as the committed seed
//! corpus; every input re-asserts the guarantees):
//! 1. `parse_selector` never panics and is deterministic (same
//! expression, same verdict; a parse failure is an explicit
//! error, never a crash);
//! 2. `resolve_selection` against a fuzz-derived format tree never
//! panics; a successful `Selection` names a primary URI that
//! exists in the tree (or the empty audio-only sentinel) and
//! attached URIs that all exist;
//! 3. the default face (`None`) stays the `best` layer.

use libfuzzer_sys::fuzz_target;

use taiji_media::format::{FormatNode, FormatTree};
use taiji_media::selector::{MediaSelector, SelectorLayer, parse_selector, resolve_selection};

/// A small tree whose node fields derive from the fuzz bytes (every
/// string field is attacker-controlled text; the numeric faces cycle
/// a byte-derived domain). Even-length inputs build an `hls`-kind
/// tree (ordinal ids), odd-length a `dash`-kind tree (rep-id-shaped
/// ids — the DASH escape-hatch domain).
fn tree_from(data: &[u8]) -> FormatTree {
    let dash = data.len() % 2 == 1;
    let chunk = |i: usize| {
        if data.is_empty() {
            return String::new();
        }
        let n = data.len();
        let start = (i * 7) % n;
        let end = ((start + 13).min(n)).max(start).max(start + 1).min(n);
        String::from_utf8_lossy(&data[start..end]).to_string()
    };
    let num = |i: usize| u64::from(data.get(i).copied().unwrap_or(0)) * 10_000;
    let node = |i: usize| FormatNode {
        format_id: if dash {
            // A DASH Representation @id: the fuzz text verbatim
            // (empty ids stay honest — unaddressable, never fatal).
            chunk(i * 3)
        } else {
            format!("v{i}")
        },
        protocol: if dash { "dash" } else { "hls" }.to_string(),
        ext: chunk(i * 3 + 1),
        resolution: chunk(i * 3 + 2),
        fps: (data.get(i).copied().unwrap_or(30) % 120) as f64,
        hdr: "SDR".to_string(),
        vcodec: chunk(i * 3 + 1),
        acodec: chunk(i * 3 + 2),
        tbr: num(i),
        abr: num(i + 1),
        vbr: 0,
        filesize: num(i + 2),
        language: chunk(i * 3 + 3),
        has_video: i % 2 == 0,
        has_audio: i % 2 == 1 || i == 3,
        uri: format!("https://tree.test/{i}.m3u8"),
    };
    FormatTree {
        url: "https://tree.test/master.m3u8".to_string(),
        kind: if dash { "dash" } else { "hls" }.to_string(),
        formats: (0..4).map(node).collect(),
    }
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    // 1: parse — no panic, deterministic verdict.
    let parsed = parse_selector(Some(&s));
    let parsed_again = parse_selector(Some(&s));
    assert_eq!(parsed.is_ok(), parsed_again.is_ok(), "deterministic parse");
    if let Ok(sel) = parsed {
        let again = parse_selector(Some(&s));
        assert_eq!(
            again.map(|x| x.layer),
            Ok(sel.layer.clone()),
            "deterministic layer"
        );
        // 2: resolution — no panic; every named URI exists.
        let tree = tree_from(data);
        if let Ok(selection) = resolve_selection(&tree, &sel) {
            if !selection.primary_uri.is_empty() {
                assert!(
                    tree.formats.iter().any(|f| f.uri == selection.primary_uri),
                    "the primary URI comes from the tree: {}",
                    selection.primary_uri
                );
            }
            for uri in &selection.attached_uris {
                assert!(
                    tree.formats.iter().any(|f| f.uri == *uri),
                    "an attached URI comes from the tree: {uri}"
                );
            }
        }
        // Resolution is a pure function of (tree, selector).
        if let Ok(a) = resolve_selection(&tree, &sel) {
            if let Ok(b) = resolve_selection(&tree, &sel) {
                assert_eq!(a, b, "deterministic resolution");
            }
        }
    }

    // 3: the default face stays `best`.
    let default = parse_selector(None).unwrap_or_else(|e| panic!("default parse: {e}"));
    assert!(matches!(default.layer, SelectorLayer::Best));
    let _typed: MediaSelector = default;
});
