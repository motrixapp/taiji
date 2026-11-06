#![no_main]

//! fuzz target: the UdpDemux classifier.
//!
//! Invariant: `classify` is total and never panics on any inbound
//! first-packet byte sequence (a pure function; strong assertions on rule
//! precedence live in the proptest inside
//! `crates/taiji-io/src/udp_demux.rs`).

use libfuzzer_sys::fuzz_target;

use taiji_io::udp_demux;

fuzz_target!(|data: &[u8]| {
    let _ = udp_demux::classify(data);
});
