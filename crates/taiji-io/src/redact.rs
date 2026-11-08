//! Unified URL log-redaction face (single source; one policy across
//! protocols).
//!
//! # Policy
//!
//! - **Strip at every level by default (ERROR..TRACE alike)**: PT announce
//!   credentials (`?passkey=…` / `?authkey=…`) and webseed/HTTP pre-signed
//!   tokens all live in the query segment — this prevents the routine
//!   accident of credentials leaking through shared troubleshooting logs.
//!   Deliberately stricter than the references: aria2/libtorrent log the
//!   raw URL at debug. Debug is exactly the "please paste your logs"
//!   sharing mode, so the fullest form must not be a log-level side
//!   effect.
//! - **Explicit verbatim switch** (CLI `--log-verbatim-urls` ->
//!   [`set_url_log_verbatim`]): on = [`redact_url_for_log`] returns the
//!   URL as-is (full query incl. credentials — local deep diagnostics
//!   only; scrub logs before sharing). Orthogonal to log level.
//! - **Functional use bypasses this module**: announce/scrape/dial/pickup
//!   bodies and the RPC `tellStatus` data face keep the raw URL — only
//!   the log face is redacted.
//!
//! # Consumers (cross-protocol)
//!
//! - BT face: tracker announce/webseed (`taiji-bt` tracker actor +
//!   `taiji-engine` dial, re-exported via `taiji_bt::tracker`);
//! - HTTP download face: the `taiji-http` client URL log points (a
//!   verbatim gate above its private `redact` Url form).
//!
//! The `userinfo` form (`scheme://user:pass@…`) has no precedent on any
//! face and is intentionally not covered. Tests serialize on
//! `REDACT_TEST_MUTEX` (guards parallel flips of the in-process global
//! static).

use std::sync::atomic::{AtomicBool, Ordering};

/// Process-level verbatim switch (default off = strip at every level).
static URL_LOG_VERBATIM: AtomicBool = AtomicBool::new(false);

/// Verbatim setter (CLI `--log-verbatim-urls` calls it once before
/// `init_tracing`; the taiji-http verbatim gate reads the same switch).
pub fn set_url_log_verbatim(on: bool) {
    URL_LOG_VERBATIM.store(on, Ordering::SeqCst);
}

/// Verbatim getter (consumed by taiji-http `redact_or_verbatim`).
pub fn url_log_verbatim() -> bool {
    URL_LOG_VERBATIM.load(Ordering::SeqCst)
}

/// URL log form: strip query/fragment (from the first `?` or `#`), keep
/// `scheme://authority/path`; verbatim on = as-is. **CR/LF/NUL and all
/// other C0 control characters are always emitted as `\u{XX}` literals**:
/// malicious announce/metalink URIs are arbitrary bencode/XML text, and a
/// raw CR/LF in a log line forges log events and — persisted via
/// config_json.tiers — replays on every restart. Escaping applies on the
/// verbatim arm too (line integrity over verbatim semantics).
pub fn redact_url_for_log(url: &str) -> String {
    if url_log_verbatim() {
        return escape_control_chars(url);
    }
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    escape_control_chars(&url[..cut])
}

/// Control-character escaping for log lines (single source): C0 (incl.
/// CR/LF/NUL) and DEL -> `\u{xx}` literals. tracing-subscriber 0.3.x's
/// EscapeGuard only covers ESC/BEL/C1 — CR/LF pass through untouched
/// (verified against tracing-subscriber escape.rs); this function fills
/// that gap, shared by the URL face and raw string log points.
pub fn escape_control_chars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        // TAB (0x09) kept: a legal in-field separator; no line-forging surface.
        let ctrl = (ch.is_control() && ch as u32 <= 0x1f && ch != '\t') || ch as u32 == 0x7f;
        if ctrl {
            out.push_str(&format!("\\u{{{:02x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test serialization lock for the global verbatim static (shared by
    /// the decision table and the phase test).
    pub(crate) static REDACT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Decision table: URL log form strips query/fragment — PT passkey
    /// forms (single key / multiple keys / custom key name), a fragment,
    /// no-query passthrough, UDP host:port form kept, empty string, and
    /// the pre-signed token form.
    #[test]
    fn redact_url_for_log_decision_table() {
        let _guard = REDACT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        for (input, want) in [
            (
                "https://t.example/announce?passkey=XYZ",
                "https://t.example/announce",
            ),
            (
                "https://t.example/announce?passkey=XYZ&foo=1",
                "https://t.example/announce",
            ),
            (
                "https://t.example/announce?authkey=abc&secure=1",
                "https://t.example/announce",
            ),
            (
                "https://t.example/announce#frag",
                "https://t.example/announce",
            ),
            ("https://t.example/announce", "https://t.example/announce"),
            (
                "udp://t.example:6969/announce?key=1",
                "udp://t.example:6969/announce",
            ),
            ("", ""),
            (
                "https://cdn.example/file.bin?X-Amz-Signature=deadbeef",
                "https://cdn.example/file.bin",
            ),
        ] {
            assert_eq!(redact_url_for_log(input), want, "input={input}");
        }
    }

    /// Verbatim phase: on = as-is (full query incl. credentials); off =
    /// stripped. Serialized with the decision table via the mutex; reset
    /// at the end (guards against phase pollution).
    #[test]
    fn redact_url_verbatim_phase() {
        let _guard = REDACT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        set_url_log_verbatim(false);
        assert_eq!(
            redact_url_for_log("https://t.example/announce?passkey=X"),
            "https://t.example/announce"
        );
        set_url_log_verbatim(true);
        assert_eq!(
            redact_url_for_log("https://t.example/announce?passkey=X"),
            "https://t.example/announce?passkey=X"
        );
        assert_eq!(
            redact_url_for_log("udp://t.example:6969/announce?key=1"),
            "udp://t.example:6969/announce?key=1"
        );
        set_url_log_verbatim(false);
    }
}

#[cfg(test)]
mod sec_41_tests {
    use super::*;

    /// Decision table: CR/LF/NUL/DEL/SOH -> `\\u{xx}` literals; TAB kept
    /// (legal log separator); multi-byte UTF-8 passes through; orthogonal
    /// composition with query stripping.
    #[test]
    fn control_chars_escaped_for_log_lines() {
        assert_eq!(
            escape_control_chars("a\r\nb"),
            "a\\u{0d}\\u{0a}b",
            "CRLF must be escaped (the log-forgery surface)"
        );
        assert_eq!(escape_control_chars("x\0y"), "x\\u{00}y");
        assert_eq!(escape_control_chars("d\x7fe"), "d\\u{7f}e");
        assert_eq!(escape_control_chars("\u{1}start"), "\\u{01}start");
        assert_eq!(escape_control_chars("tab\tkept"), "tab\tkept");
        assert_eq!(escape_control_chars("café→β"), "café→β");
        // Combined with stripping: a CRLF inside the query goes with the
        // whole query; one in the path is escaped.
        let _g = super::tests::REDACT_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            redact_url_for_log("http://h/a\r\nb?passkey=x"),
            "http://h/a\\u{0d}\\u{0a}b"
        );
        // The verbatim arm escapes too (line integrity first).
        super::set_url_log_verbatim(true);
        assert_eq!(
            redact_url_for_log("http://h/?p\r\n=q"),
            "http://h/?p\\u{0d}\\u{0a}=q"
        );
        super::set_url_log_verbatim(false);
    }
}
