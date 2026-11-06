#![no_main]

//! fuzz target: LSD/BEP14 BT-SEARCH packet parsing.
//!
//! Invariant: `lsd::parse_packet` never panics on any byte sequence
//! (header-block lookup, UTF-8 boundaries, 40-hex infohash decoding, and
//! the Port header 0/65535 boundaries are all covered); a successful parse
//! satisfies the parser's own validity contract (Port != 0, infohash
//! exactly 20B — the `LpdMessageReceiver.cc` semantics).

use std::net::SocketAddr;

use taiji_bt::lsd;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let from = SocketAddr::from(([192, 168, 1, 5], 5000));
    if let Some(msg) = lsd::parse_packet(data, from) {
        assert_ne!(msg.peer.port(), 0, "a port=0 packet must be rejected");
        assert_eq!(msg.info_hash.len(), 20, "info_hash is always 20B");
    }
});
