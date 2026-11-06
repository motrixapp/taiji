//! Parser for the ngosang/trackerslist format (global import surface of the
//! three-tier tracker configuration).
//!
//! # Format (ngosang/trackerslist conventions)
//!
//! One tracker URL per line; lines starting with `#` are comments; blank
//! lines (including whitespace-only lines) are skipped. CRLF line endings
//! are tolerated; surrounding whitespace is stripped from URLs.
//!
//! # Resource limits (designed for <= 1 MiB)
//!
//! Per-file input is capped by [`TRACKERSLIST_MAX_BYTES`] (1 MiB). The full
//! ngosang list (trackers_all, roughly 1000-3000 entries at ~60B each) is
//! well under 300KB, so the 1 MiB cap keeps a 3x margin. Oversized input is
//! rejected explicitly — never silently truncated, because a partial import
//! would distort the "global supplement" semantics. Reading the file is
//! blocking disk IO, so callers (actor/CLI) must run [`read_trackerslist`]
//! inside `spawn_blocking`.
//!
//! The pure parser [`parse_trackerslist`] has no allocation-amplification
//! path (output <= input byte count); a cargo-fuzz target covers it
//! synchronously (fuzz/trackerslist).

use std::path::Path;

/// Per-file input byte cap: 1 MiB.
pub const TRACKERSLIST_MAX_BYTES: usize = 1024 * 1024;

/// Import failure surface: callers (actor import seam / CLI startup) warn
/// and degrade on these instead of panicking.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrackerslistError {
    /// File read failed (missing / permissions / IO).
    #[error("trackerslist read failed: {0}")]
    Io(#[from] std::io::Error),
    /// Input exceeds [`TRACKERSLIST_MAX_BYTES`] (explicit rejection, never
    /// silent truncation).
    #[error("trackerslist exceeds {limit} bytes (got {got})")]
    TooLarge { got: u64, limit: u64 },
    /// Not valid UTF-8 (the URL surface is always UTF-8; a leading BOM is
    /// tolerated and stripped by the parser).
    #[error("trackerslist is not valid UTF-8")]
    NotUtf8,
}

/// Parse ngosang/trackerslist text: read line by line, skip `#` comments and
/// blank (whitespace-only) lines, strip surrounding whitespace, and tolerate
/// a leading UTF-8 BOM (common in browser downloads). Returns URLs in import
/// order. Duplicates are NOT removed here — dedup belongs to the import
/// merge layer (union semantics); the parser keeps the single responsibility
/// of pure format reading.
pub fn parse_trackerslist(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.push(t.to_string());
    }
    out
}

/// Read and parse a trackerslist file (blocking disk IO — callers must run
/// this inside `spawn_blocking`). The size cap is checked before the full
/// read via `metadata`, then re-checked on the bytes after reading (TOCTOU
/// tolerance); oversized input is rejected on both checks.
pub fn read_trackerslist(path: &Path) -> Result<Vec<String>, TrackerslistError> {
    let limit = TRACKERSLIST_MAX_BYTES as u64;
    let meta = std::fs::metadata(path)?;
    if meta.len() > limit {
        return Err(TrackerslistError::TooLarge {
            got: meta.len(),
            limit,
        });
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() as u64 > limit {
        return Err(TrackerslistError::TooLarge {
            got: bytes.len() as u64,
            limit,
        });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| TrackerslistError::NotUtf8)?;
    Ok(parse_trackerslist(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic format: per-line URLs, `#` comments, blank-line skipping, CRLF
    /// tolerance, whitespace stripping.
    #[test]
    fn parses_lines_skips_comments_and_blanks() {
        let text = "\u{feff}".to_string()
            + "udp://tracker.a:6969/announce\r\n\
               \n\
               # comment line (ngosang header)\n\
               https://tracker.b/announce  \n\
               \t \n\
               \thttps://tracker.c/announce\n\
               #another comment\n\
               wss://tracker.d/announce";
        let urls = parse_trackerslist(&text);
        assert_eq!(
            urls,
            vec![
                "udp://tracker.a:6969/announce",
                "https://tracker.b/announce",
                "https://tracker.c/announce",
                "wss://tracker.d/announce",
            ]
        );
    }

    /// Empty and comment-only inputs yield an empty list (no error).
    #[test]
    fn empty_and_comment_only_inputs_yield_empty() {
        assert!(parse_trackerslist("").is_empty());
        assert!(parse_trackerslist("\n\n# a\n# b\n").is_empty());
    }

    /// Duplicate lines are kept (dedup belongs to the import merge layer);
    /// `#` that is not at the start of a line is not a comment (the ngosang
    /// format only comments at line start — a URL fragment `#x` is URL
    /// syntax).
    #[test]
    fn duplicates_kept_and_inline_hash_not_a_comment() {
        let text = "udp://a/announce\nudp://a/announce\nhttp://b/announce#frag";
        let urls = parse_trackerslist(text);
        assert_eq!(urls.len(), 3);
        assert_eq!(urls[2], "http://b/announce#frag");
    }

    /// Oversized files are rejected, not truncated (1 MiB cap).
    #[test]
    fn oversized_file_is_rejected_not_truncated() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "bh-trackerslist-big-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        // 1 MiB + 1 byte.
        let blob = vec![b'a'; TRACKERSLIST_MAX_BYTES + 1];
        std::fs::write(&path, &blob).unwrap_or_else(|e| panic!("write fixture: {e}"));
        match read_trackerslist(&path) {
            Err(TrackerslistError::TooLarge { got, limit }) => {
                assert_eq!(got, (TRACKERSLIST_MAX_BYTES + 1) as u64);
                assert_eq!(limit, TRACKERSLIST_MAX_BYTES as u64);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Normal file read roundtrip (with comments and blank lines).
    #[test]
    fn file_read_roundtrip() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "bh-trackerslist-ok-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, b"# list\nudp://x/announce\n\nhttps://y/announce\n")
            .unwrap_or_else(|e| panic!("write fixture: {e}"));
        let urls = read_trackerslist(&path).unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(urls, vec!["udp://x/announce", "https://y/announce"]);
        let _ = std::fs::remove_file(&path);
    }

    /// Acceptance bar: importing 1200 URLs (ngosang trackers_all scale) in
    /// under 1s with output memory under 1 MiB. Memory is measured as the
    /// total output string bytes (the heap growth of a single parse is
    /// bounded by the input, which the 1 MiB cap already clamps); time is
    /// measured over the pure-CPU parse (no IO), and separately over the
    /// full `read_trackerslist` chain including a temp-file read.
    #[test]
    fn import_1200_urls_under_1s_and_1mib() {
        // Build a synthetic 1200-entry list (~50B each, ~62KB total << 1 MiB).
        let mut text = String::from("# ngosang/trackerslist synthetic fixture\n");
        for i in 0..1200 {
            text.push_str(&format!(
                "udp://tracker.synthetic-{i}.example:6969/announce\n"
            ));
        }
        let t0 = std::time::Instant::now();
        let urls = parse_trackerslist(&text);
        let elapsed = t0.elapsed();
        assert_eq!(urls.len(), 1200);
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "importing 1200 entries must take <1s, took {elapsed:?}"
        );
        let bytes: usize = urls.iter().map(|u| u.len()).sum();
        assert!(
            bytes < TRACKERSLIST_MAX_BYTES,
            "imported set memory (total string bytes {bytes}B) must be <1MiB"
        );
        // Full chain (including temp-file IO): same <1s bar.
        let mut path = std::env::temp_dir();
        path.push(format!(
            "bh-trackerslist-perf-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, text.as_bytes()).unwrap_or_else(|e| panic!("write fixture: {e}"));
        let t1 = std::time::Instant::now();
        let urls = read_trackerslist(&path).unwrap_or_else(|e| panic!("read: {e}"));
        let elapsed = t1.elapsed();
        assert_eq!(urls.len(), 1200);
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "importing 1200 entries with full IO must take <1s, took {elapsed:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
