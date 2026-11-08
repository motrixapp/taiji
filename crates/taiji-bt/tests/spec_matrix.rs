//! SPEC §2 protocol-matrix and source-comment BEP-label consistency
//! assertions.
//!
//! The asserted object is the documentation itself: matrix rows must match
//! what actually landed, deviation notes must be centrally registered, and
//! BEP label typos must be zero. The reference is the BEP text and the
//! corresponding code (anchors in each assertion's comment); documentation
//! drift is a failure — the doc is part of the spec surface.

use std::path::{Path, PathBuf};

fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/taiji-bt -> two levels up is the repo
    // root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    match manifest.parent().and_then(|p| p.parent()) {
        Some(p) => p.to_path_buf(),
        None => panic!("repo root not found from {}", manifest.display()),
    }
}

fn read(rel: &str) -> String {
    ok(
        std::fs::read_to_string(repo_root().join(rel)),
        &format!("read {rel}"),
    )
}

fn spec() -> String {
    read("docs/spec.md")
}

/// Return the matrix row starting `| BEP <n> ` (first match).
fn matrix_row(spec: &str, bep: &str) -> String {
    let prefix = format!("| {bep} ");
    spec.lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("SPEC §2 missing the {bep} row"))
        .to_owned()
}

#[test]
fn matrix_rows_match_landed_battles() {
    let spec = spec();
    // BEP-12: full tier ingestion + the BEP-27 private single-flight gate
    // are landed (metainfo.rs announce_tiers / tracker actor private
    // bit).
    let bep12 = matrix_row(&spec, "BEP 12");
    assert!(
        bep12.contains("full tier ingestion"),
        "BEP12 row must record full tier ingestion: {bep12}"
    );
    assert!(
        bep12.contains("single-in-flight gate"),
        "BEP12 row must record the private single-in-flight gate: {bep12}"
    );
    // BEP-32: KRPC want send/receive + the 1024B whole-reply frame gate
    // (DHT face).
    let bep32 = matrix_row(&spec, "BEP 32");
    assert!(
        bep32.contains("want"),
        "BEP32 row must record the want parameter: {bep32}"
    );
    assert!(
        bep32.contains("1024"),
        "BEP32 row must record the 1024B gate: {bep32}"
    );
    // BEP-7: tracker peers6/dual-stack belongs to BEP-7 (the IPv6 tracker
    // extension), separate from BEP-32 (the DHT IPv6 extension) — the same
    // wording in http.rs/mod.rs.
    let bep7 = matrix_row(&spec, "BEP 7");
    assert!(
        bep7.contains("peers6"),
        "BEP7 row must record peers6: {bep7}"
    );
    // BEP-11: first-message exemption + flags only bit0/bit1
    // (pex/message.rs FLAG_ENCRYPTED/FLAG_SEEDER; 0x04/0x08/0x10
    // unused).
    let bep11 = matrix_row(&spec, "BEP 11");
    assert!(
        bep11.contains("first-message exemption"),
        "BEP11 row must record the first-message exemption: {bep11}"
    );
    assert!(
        bep11.contains("partially implemented"),
        "BEP11 row must record the partial flags implementation: {bep11}"
    );
    // BEP-6: outbound negotiation gate; outbound allowed-fast/suggest
    // stays deferred.
    let bep6 = matrix_row(&spec, "BEP 6");
    assert!(
        bep6.contains("negotiation gate"),
        "BEP6 row must record the outbound negotiation gate: {bep6}"
    );
    assert!(
        bep6.contains("pending items"),
        "BEP6 row must keep the pending items note: {bep6}"
    );
    // BEP-3: v1-only piece length relaxed to any positive integer.
    let bep3 = matrix_row(&spec, "BEP 3");
    assert!(
        bep3.contains("positive integer"),
        "BEP3 row must record the v1 piece length relaxation: {bep3}"
    );
    // BEP-47: symlink = partial support (filetree.rs parses attr 'l' but
    // not `symlink path`, so no link semantics).
    let bep47 = matrix_row(&spec, "BEP 47");
    assert!(
        bep47.contains("symlink"),
        "BEP47 row must record the symlink face: {bep47}"
    );
    assert!(
        bep47.contains("partial support"),
        "BEP47 row must record partial support: {bep47}"
    );
    // BEP-29: LEDBAT as a BEP-29 dialect + the three missing RFC 6817
    // pieces.
    let bep29 = matrix_row(&spec, "BEP 29");
    assert!(
        bep29.contains("dialect"),
        "BEP29 row must record the dialect characterization: {bep29}"
    );
    assert!(
        bep29.contains("RFC 6817"),
        "BEP29 row must record the RFC 6817 absences: {bep29}"
    );
    // the MSE/PE row stays ✅.
    let mse = matrix_row(&spec, "MSE/PE");
    assert!(mse.contains("✅"), "MSE row stays ✅: {mse}");
}

#[test]
fn matrix_new_rows_bep48_55_51() {
    let spec = spec();
    // BEP-48: HTTP scrape (tracker/scrape.rs) + UDP scrape (udp.rs
    // action=2) implemented, beyond aria2 (no scrape face).
    let bep48 = matrix_row(&spec, "BEP 48");
    assert!(
        bep48.contains("scrape") && bep48.contains("aria2"),
        "BEP48 row must record scrape implemented beyond aria2: {bep48}"
    );
    // BEP-55: ut_holepunch implemented and wired (holepunch.rs +
    // peer/engine wiring).
    let bep55 = matrix_row(&spec, "BEP 55");
    assert!(
        bep55.contains("holepunch"),
        "BEP55 row must record the holepunch wiring: {bep55}"
    );
    // BEP-51: an explicit non-goal (indexer role).
    let bep51 = matrix_row(&spec, "BEP 51");
    assert!(
        bep51.contains("non-goal"),
        "BEP51 row must record the explicit non-goal: {bep51}"
    );
}

#[test]
fn deviation_notes_centrally_registered() {
    let spec = spec();
    assert!(
        spec.contains("Deviation notes"),
        "§2 must have a central deviation-notes section"
    );
    // All notes present one by one (anchors: filetree.rs reject-not-
    // sanitize philosophy / the §4.2 missing-layer degradation / udp.rs
    // 5s/10s / token.rs formula / cookies.rs single-label rejection /
    // filetree.rs i64->u32 domain).
    assert!(
        spec.contains("rejection rather than rewriting"),
        "sanitization-philosophy note missing: {spec}"
    );
    assert!(
        spec.contains("non-UTF-8"),
        "non-UTF-8 legacy torrent face note missing"
    );
    assert!(
        spec.contains("hash recovery"),
        "missing piece layers degradation note missing"
    );
    assert!(spec.contains("5s/10s"), "BEP15 retransmit note missing");
    assert!(
        spec.contains("(ip, port)"),
        "DHT token binding note missing"
    );
    assert!(
        spec.contains("single-label"),
        "cookie single-label domain note missing"
    );
    assert!(spec.contains("i64"), "piece length i64 domain note missing");
}

#[test]
fn piece_layers_key_is_binary_32b() {
    let spec = spec();
    // The key = 32B binary pieces root (filetree.rs load matches
    // root.as_slice() by k.len()==32; creator.rs writes root.to_vec()) —
    // a hex-text key was a typo.
    assert!(
        !spec.contains("<root_hex>"),
        "the §4.2 hex-key typo must not reappear"
    );
    assert!(
        spec.contains("32B binary"),
        "§4.2 must note the binary 32B key"
    );
}

#[test]
fn tracker_docs_label_peers6_bep7() {
    // peers6/dual-stack belongs to BEP-7 (the IPv6 tracker extension);
    // BEP-32 is the DHT IPv6 extension (nodes6/want) — tracker-face files
    // must not carry BEP-32 labels.
    for rel in [
        "crates/taiji-bt/src/tracker/mod.rs",
        "crates/taiji-bt/src/tracker/http.rs",
    ] {
        let src = read(rel);
        assert!(
            !src.contains("BEP32"),
            "{rel} still carries a BEP32 label (peers6/dual-stack is BEP7)"
        );
        assert!(src.contains("BEP7"), "{rel} must carry a BEP7 label");
    }
}

#[test]
fn peer_wire_reject_comment_cites_bep6() {
    let src = read("crates/taiji-bt/src/peer_wire.rs");
    // Reject is a BEP-6 fast extension message (BEP-3 has no such
    // message).
    assert!(
        !src.contains("BEP3 fast extension"),
        "peer_wire.rs must not label the fast extension message as BEP3"
    );
    assert!(
        src.contains("BEP-6 fast extension: reject request"),
        "the MessageId::Reject comment must cite BEP6"
    );
}
