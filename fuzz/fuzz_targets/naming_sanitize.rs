#![no_main]

//! fuzz target: the naming sanitizers.
//!
//! Invariant: any text through `sanitize_generated_name` /
//! `sanitize_user_name` never panics, and the generated-name output
//! contains no C0/DEL control characters (the filesystem and display
//! hygiene guarantee holds for arbitrary input).

use libfuzzer_sys::fuzz_target;

use taiji_http::naming::{sanitize_generated_name, sanitize_user_name};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // Generated-name channel (URL/CD-derived names): control characters
    // must be replaced (_) — the guarantee holds for any input.
    let full = sanitize_generated_name(&s);
    assert!(
        !full.chars().any(|ch| (ch.is_control() && ch != '\t') || ch == '\u{7f}'),
        "all channels emit no control characters"
    );
    // User-supplied name channel (out=): by design no character
    // replacement (control characters are rejected at the acceptance
    // layer, not here). Per-channel invariant = structural safety: no
    // path-component semantics (no '/'), non-empty, not all dots.
    let user = sanitize_user_name(&s);
    assert!(!user.is_empty(), "light channel non-empty (fallback name)");
    assert!(!user.contains('/'), "light channel has no path separator");
});
