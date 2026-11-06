#![no_main]

//! fuzz target: the HTTP Basic authentication header parser (under the
//! "every parser gets a fuzz target" rule).
//!
//! Invariants (for any Authorization header bytes):
//! 1. `BasicAuth::authorize` / `basic_authorized` never panic — parsing
//! uses only `find`/`position` slicing with Option short-circuits, no
//! out-of-bounds indexing;
//! 2. The authentication result is always a plain bool with no partial
//! state leaking out (plaintext credentials live only briefly on the
//! call stack; the tag comparison is constant-time);
//! 3. Without --rpc-user configured (None) the result is always true
//! (HttpServer.cc parity).

use libfuzzer_sys::fuzz_target;

use taiji_rpc::auth::{BasicAuth, basic_authorized};

fuzz_target!(|data: &[u8]| {
    let header = String::from_utf8_lossy(&data);
    // No Basic configured: always true, independent of input.
    assert!(basic_authorized(None, Some(&header)));

    let auth = BasicAuth::new(Some("fuzz-user"), Some("fuzz-pass"));
    if let Some(auth) = auth {
        // For any input the result is only ever a bool, and never panics.
        let _ = auth.authorize(Some(&header));
        // A missing header never passes (when credentials are configured,
        // HttpServer.cc).
        assert!(!auth.authorize(None));
    }
});
