#![no_main]

//! fuzz target for `parse_www_authenticate` (WWW-Authenticate header
//! parsing).
//!
//! Invariant: total over any text (including malformed quoting/comma
//! nesting), never panics.

use libfuzzer_sys::fuzz_target;

use taiji_http::auth::parse_www_authenticate;

fuzz_target!(|data: &[u8]| {
    // The invariant is totality (the Challenge enum's Digest branch fields
    // are constrained by struct-level validation — there is no bare scheme
    // string surface to assert on).
    let s = String::from_utf8_lossy(data);
    let _ = parse_www_authenticate(&s);
});
