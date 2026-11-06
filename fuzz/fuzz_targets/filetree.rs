#![no_main]

//! fuzz target: the file tree parser.
//!
//! Invariants:
//! 1. `bencode::decode` + `filetree::parse` never panic or hang on any
//! input (parse depth bounded by bencode MAX_DEPTH; path sanitization
//! does no indexing/slicing);
//! 2. A successful parse satisfies the parser's own promised invariants
//! (a tripped assertion means a sanitization/validation hole — a
//! crash-level defect):
//! - piece_length is a power of two and >= 16KiB (BEP52);
//! - every entry path contains only Normal components ('.'/'..'/absolute
//! paths are rejected in the sanitization layer);
//! - length == 0 iff no pieces root; non-empty files always have a pieces
//! root;
//! - piece_layer present implies pieces_root present (mounted only after
//! layer validation passes).

use libfuzzer_sys::fuzz_target;

use taiji_bt::{bencode, filetree};
use taiji_store::merkle;

fuzz_target!(|data: &[u8]| {
    let Ok(top) = bencode::decode(data) else {
        return;
    };
    let Ok(files) = filetree::parse(&top) else {
        return;
    };
    assert!(
        files.piece_length.is_power_of_two() && files.piece_length >= merkle::BLOCK_SIZE,
        "parse accepted invalid piece length {}",
        files.piece_length
    );
    for entry in files.files {
        for component in entry.path.components() {
            assert!(
                matches!(component, std::path::Component::Normal(_)),
                "sanitized path must contain only normal components: {:?}",
                entry.path
            );
        }
        assert_eq!(
            entry.length == 0,
            entry.pieces_root.is_none(),
            "length/pieces-root pairing violated for {:?}",
            entry.path
        );
        assert!(
            entry.piece_layer.is_none() || entry.pieces_root.is_some(),
            "layer without root for {:?}",
            entry.path
        );
    }
});
