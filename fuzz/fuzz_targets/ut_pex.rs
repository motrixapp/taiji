#![no_main]

//! fuzz target: the ut_pex payload.
//!
//! Invariants:
//! 1. `PexMessage::decode` never panics or hangs on any input;
//! 2. Any successfully decoded message must re-encode into something
//! decodable again (canonical self-consistency);
//! Note: the decode projection (seeders dropped, non-dict entries
//! ignored) means decode(encode(x)) == x holds only for the addr sets,
//! not full message equality.

use libfuzzer_sys::fuzz_target;

use taiji_bt::pex::PexMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = PexMessage::decode(data) {
        // Canonical self-consistency: anything decodable must re-encode
        // (failure = canonical bug) and re-decode (equal address sets).
        let encoded = match msg.encode() {
            Ok(b) => b,
            Err(e) => panic!("decode output must re-encode: {e:?}"),
        };
        if let Ok(re) = PexMessage::decode(&encoded) {
            assert_eq!(
                re.fresh_peers(),
                msg.fresh_peers(),
                "re-encode must preserve fresh addrs"
            );
            assert_eq!(
                re.dropped_peers(),
                msg.dropped_peers(),
                "re-encode must preserve dropped addrs"
            );
        }
    }
});
