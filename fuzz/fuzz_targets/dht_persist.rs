//! fuzz target: the DHT persistence parsing surface.
//!
//! Covers two parsers:
//! - the own routing-table BLOB (`dht_state.routing_table`,
//! `decode_table`);
//! - the aria2 `dht.dat` format (`parse_dht_dat`; header magic 0xa1 0xa2 /
//! format id 0x02 / version 0x02|0x03,
//! `DHTRoutingTableDeserializer.cc`).
//!
//! Assertion: no input panics (whole-function decoders; errors surface as
//! Result).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let family = if sel & 1 == 0 {
        taiji_bt::dht::DhtFamily::V4
    } else {
        taiji_bt::dht::DhtFamily::V6
    };
    // The own BLOB.
    if let Ok(nodes) = taiji_bt::dht::decode_table(rest) {
        // Roundtrip invariant: legal input re-encodes and decodes back to
        // an equal list.
        let re = taiji_bt::dht::encode_table(&nodes);
        assert_eq!(taiji_bt::dht::decode_table(&re).as_deref(), Ok(&nodes[..]));
    }
    // aria2 dht.dat (invariant = no panic; survivors of the skip rules
    // never exceed the record count).
    if let Ok(dat) = taiji_bt::dht::parse_dht_dat(family, rest) {
        // Fixed 56B before the record area (header 8 + timestamp 8 + self
        // 32 + count 8).
        let records = rest.len().saturating_sub(56) / 56;
        assert!(
            dat.nodes.len() <= records,
            "parsed {} nodes from {records} possible records",
            dat.nodes.len()
        );
    }
});
