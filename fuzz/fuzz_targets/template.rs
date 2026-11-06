#![no_main]

//! fuzz target: the output-template expansion + forced-sanitization
//! face (the untrusted-remote-string
//! red line: `{title}/{ext}` carry site-controlled text, whatever
//! they hold, the product name passes the §8.3-equivalent sanitizer).
//!
//! Invariants (the §11 template-injection vector family runs as the
//! committed seed corpus; every input re-asserts the guarantees):
//! 1. `expand_template` never panics (unknown fields / unterminated
//! placeholders are explicit errors, not crashes);
//! 2. a successful expansion fed through `sanitize_output_name`
//! never escapes the output directory: no path separator, no
//! control characters, no leading `-` (the argv face), length
//! clamped on UTF-8 boundaries, never empty;
//! 3. `sanitize_output_name` alone (the raw remote-string posture)
//! holds the same guarantees for arbitrary bytes;
//! 4. both faces are deterministic (same input, same output).

use libfuzzer_sys::fuzz_target;

use taiji_media::template::{
    MAX_OUTPUT_NAME_BYTES, TemplateContext, expand_template, sanitize_output_name,
};

/// The whole input plays every remote field at once (the maximally
/// hostile context — the 0.5 bridge turns all of these into
/// site-controlled strings).
fn hostile_ctx(s: &str) -> TemplateContext {
    TemplateContext {
        title: Some(s.to_string()),
        id: Some(s.to_string()),
        ext: Some(s.to_string()),
        res: Some(s.to_string()),
        lang: Some(s.to_string()),
        playlist_index: Some(s.to_string()),
    }
}

/// The sanitizer's product-name guarantees (§10 #1).
fn assert_product_name(san: &taiji_media::template::SanitizedName) {
    assert!(!san.name.is_empty(), "the product name is never empty");
    assert!(!san.name.contains('/'), "no path separator: {:?}", san.name);
    assert!(
        !san.name.contains('\\'),
        "no path separator: {:?}",
        san.name
    );
    assert!(
        !san.name.chars().any(char::is_control),
        "no control characters: {:?}",
        san.name
    );
    assert!(
        !san.name.starts_with('-'),
        "no leading dash (argv face): {:?}",
        san.name
    );
    assert!(
        san.name.len() <= MAX_OUTPUT_NAME_BYTES,
        "length clamped: {} > {}",
        san.name.len(),
        MAX_OUTPUT_NAME_BYTES
    );
    assert_ne!(san.name, "..", "the dot-dot component never survives");
    assert_ne!(san.name, ".", "the dot component never survives");
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    // 1 + 2: expansion face — the input is the template expression
    // AND every field value.
    let expanded = expand_template(Some(&s), &hostile_ctx(&s));
    let expanded_again = expand_template(Some(&s), &hostile_ctx(&s));
    assert_eq!(
        expanded.is_ok(),
        expanded_again.is_ok(),
        "deterministic expansion verdict"
    );
    if let Ok(name) = expanded {
        let san = sanitize_output_name(&name);
        assert_product_name(&san);
        let san2 = sanitize_output_name(&name);
        assert_eq!(san.name, san2.name, "deterministic sanitization");
    }
    // The default-shape face (None template) over the hostile
    // context: same guarantees.
    if let Ok(name) = expand_template(None, &hostile_ctx(&s)) {
        let san = sanitize_output_name(&name);
        assert_product_name(&san);
    }

    // 3: the raw remote-string posture — the input IS the remote
    // value, no template involved.
    let san = sanitize_output_name(&s);
    assert_product_name(&san);
    let san2 = sanitize_output_name(&s);
    assert_eq!(san.name, san2.name, "deterministic sanitization");
});
