#![no_main]

//! fuzz target: the µTP v1 packet header + extension chain.
//!
//! Invariants (BEP29 "header format"/"extension"/"Selective ACK"):
//! `packet::decode` is total over any byte sequence (Err/Ok, never
//! panics); extension chains terminate within 32 hops (malformed chains
//! error out instead of looping); the Selective ACK bitmap view never
//! indexes out of bounds for any sequence number query.

use libfuzzer_sys::fuzz_target;

use taiji_io::utp::packet;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = packet::decode(data) {
        let _ = p.header.packet_type;
        let _ = p.header.seq_nr;
        if let Some(sack) = p.sack {
            // Bitmap view queries never panic or go out of bounds for any
            // sequence number.
            let _ = sack.acked(p.header.ack_nr);
            let _ = sack.acked(p.header.ack_nr.wrapping_add(137));
        }
    }
});
